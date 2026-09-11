#!/usr/bin/env python3

import argparse
import csv
import hashlib
import os
import textwrap
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED, TimeoutError as FutureTimeoutError
import html
import ipaddress
import json
import math
import re
import unicodedata
import shutil
import subprocess
import sys
import tempfile
import time
import threading
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, urljoin, urlparse

def _early_requirements_path():
    here = Path(__file__).resolve().parent
    candidates = [
        here / "requirements.txt",
        here.parent / "requirements.txt",
    ]
    return next((path for path in candidates if path.exists()), None)


def _bootstrap_python_dependencies():
    """Instala requirements Python apenas quando um import obrigatório falta."""
    req = _early_requirements_path()
    if req is None:
        raise

    command = [sys.executable, "-m", "pip", "install", "-r", str(req)]
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        command.insert(4, "--break-system-packages")

    print("[*] Preparando dependências Python do L1ght Recon...")
    result = subprocess.run(command, text=True)
    if result.returncode != 0:
        raise SystemExit(result.returncode)

    os.execv(sys.executable, [sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]])


try:
    import requests
    import urllib3
    from bs4 import BeautifulSoup
except ModuleNotFoundError:
    _bootstrap_python_dependencies()
    raise

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ============================================================
# L1ght Recon
# Scanning & Enumeration
# ============================================================

VERSION = "2.2.0"
AUTHOR = "Rafael Ademilton"
HANDLE = "l1ghtr3v3n"

BLUE = "\033[1;34m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
RED = "\033[1;31m"
CYAN = "\033[1;36m"
MAGENTA = "\033[1;35m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

CONSOLE_LOCK = threading.RLock()

COMMAND_TIMEOUT = 0
LOW_NOISE = False
TIMED_OUT_TASKS = []
FFUF_PARTIAL_LOCK = threading.RLock()
FFUF_PARTIAL_RESULTS = defaultdict(list)
DEBUG_LOG_PATH = None
DEBUG_LOG_LOCK = threading.RLock()
DEBUG_SECRETS = set()
NUCLEI_PARTIAL_SEEN = defaultdict(set)
NIKTO_PARTIAL_SEEN = defaultdict(set)
WEB_TOOL_SEMAPHORES = {}
TOOL_BINARIES = {}

DEFAULT_UDP_TOP_PORTS = 200
FULL_UDP_TOP_PORTS = 400
MAX_UDP_TOP_PORTS = 500
UDP_PROGRESS_INTERVAL = 60


DEFAULT_CONTENT_WORDLIST = "/usr/share/wordlists/seclists/Discovery/Web-Content/big.txt"

DEFAULT_VHOST_WORDLIST = (
    "/usr/share/seclists/Discovery/DNS/"
    "subdomains-top1million-5000.txt"
)

UPDATE_MANIFEST_URL = (
    "https://raw.githubusercontent.com/LightReven/"
    "l1ght_recon/main/releases/latest.json"
)
UPDATE_CHECK_TIMEOUT = 2.0
UPDATE_DOWNLOAD_TIMEOUT = 5.0
UPDATE_SKIP_ONCE_ENV = "L1GHT_RECON_SKIP_UPDATE_ONCE"

INTERESTING_WORDS = [
    "admin",
    "administrator",
    "login",
    "signin",
    "auth",
    "authenticate",
    "password",
    "passwd",
    "token",
    "bearer",
    "jwt",
    "secret",
    "apikey",
    "api_key",
    "client_secret",
    "session",
    "phpsessid",
    "api",
    "graphql",
    "swagger",
    "openapi",
    "upload",
    "backup",
    "config",
    "configuration",
    "debug",
    "internal",
    "private",
    "localhost",
    "endpoint",
    "baseurl",
    "base_url",
    "dev",
    "development",
    "test",
    "staging",
]

PARAM_CATEGORIES = {
    "SQLi / IDOR": {
        "id", "uid", "userid", "user_id", "account", "accountid",
        "account_id", "product", "productid", "product_id", "item",
        "itemid", "item_id", "order", "orderid", "order_id", "post",
        "postid", "post_id", "customer", "customerid", "customer_id",
    },
    "XSS": {
        "q", "query", "search", "keyword", "term", "name", "message",
        "comment", "text", "title", "input", "returnmsg",
    },
    "SSRF / Open Redirect": {
        "url", "uri", "redirect", "redirect_uri", "redirect_url", "next",
        "return", "returnurl", "return_url", "continue", "callback",
        "dest", "destination", "domain", "host",
    },
    "LFI / Path Traversal": {
        "file", "filename", "filepath", "path", "page", "template",
        "include", "folder", "directory", "dir", "document",
    },
    "Command Injection": {
        "cmd", "command", "exec", "execute", "ping", "host",
        "hostname", "ip",
    },
}

INTERESTING_PATHS = {
    "Authentication": [
        "login", "signin", "sign-in", "auth", "oauth", "register",
        "signup", "password", "reset",
    ],
    "Administration": [
        "admin", "administrator", "dashboard", "manager", "management",
        "console",
    ],
    "Upload": [
        "upload", "uploads", "attachment", "attachments", "import",
    ],
    "API": [
        "/api/", "/api?", "graphql", "swagger", "openapi", "/rest/",
    ],
    "Backup / Config": [
        "backup", ".bak", ".old", ".zip", ".tar", ".gz", ".sql",
        ".env", "config", "configuration",
    ],
}


# ============================================================
# Atualização automática
# ============================================================

def _version_key(value):
    value = str(value or "").strip().lower().lstrip("v")

    if not re.fullmatch(r"\d+(?:\.\d+){1,3}", value):
        raise ValueError(f"versão inválida: {value!r}")

    parts = [int(part) for part in value.split(".")]

    while len(parts) < 4:
        parts.append(0)

    return tuple(parts[:4])


def _running_script_path():
    try:
        path = Path(__file__).resolve()
        if path.exists():
            return path
    except Exception:
        pass

    return Path(sys.argv[0]).resolve()


def _download_update_manifest():
    response = requests.get(
        UPDATE_MANIFEST_URL,
        timeout=UPDATE_CHECK_TIMEOUT,
        headers={
            "User-Agent": f"L1ght-Recon/{VERSION} updater",
            "Accept": "application/json",
            "Cache-Control": "no-cache",
        },
    )
    response.raise_for_status()

    data = response.json()

    if not isinstance(data, dict):
        raise ValueError("manifesto de atualização inválido")

    required = ("version", "url", "sha256")

    for field in required:
        if not str(data.get(field) or "").strip():
            raise ValueError(
                f"manifesto de atualização sem o campo obrigatório {field!r}"
            )

    url = str(data["url"]).strip()

    if not url.lower().startswith("https://"):
        raise ValueError("URL de atualização deve usar HTTPS")

    digest = str(data["sha256"]).strip().lower()

    if not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ValueError("SHA-256 inválido no manifesto")

    data["version"] = str(data["version"]).strip().lstrip("v")
    data["url"] = url
    data["sha256"] = digest

    _version_key(data["version"])

    return data


def _validate_downloaded_update(content, expected_version, expected_sha256):
    actual_sha256 = hashlib.sha256(content).hexdigest()

    if actual_sha256.lower() != expected_sha256.lower():
        raise ValueError(
            "SHA-256 da atualização não corresponde ao manifesto"
        )

    source = content.decode("utf-8")

    match = re.search(
        r'(?m)^\s*VERSION\s*=\s*["\\\']([^"\\\']+)["\\\']',
        source,
    )

    if not match:
        raise ValueError("arquivo baixado não contém VERSION")

    downloaded_version = match.group(1).strip().lstrip("v")

    if _version_key(downloaded_version) != _version_key(expected_version):
        raise ValueError(
            f"versão do arquivo ({downloaded_version}) difere do manifesto "
            f"({expected_version})"
        )

    compile(
        source,
        f"l1ght_recon_v{expected_version.replace('.', '_')}.py",
        "exec",
    )

    return source


def _install_update(manifest):
    script_path = _running_script_path()
    script_dir = script_path.parent

    if not script_path.exists():
        raise FileNotFoundError(
            f"arquivo em execução não encontrado: {script_path}"
        )

    response = requests.get(
        manifest["url"],
        timeout=UPDATE_DOWNLOAD_TIMEOUT,
        headers={
            "User-Agent": f"L1ght-Recon/{VERSION} updater",
            "Accept": "text/plain, application/octet-stream",
            "Cache-Control": "no-cache",
        },
    )
    response.raise_for_status()

    content = response.content

    _validate_downloaded_update(
        content,
        manifest["version"],
        manifest["sha256"],
    )

    # A atualização já foi validada (HTTPS, SHA-256, VERSION e sintaxe)
    # antes deste ponto. Como os.replace() é atômico no mesmo filesystem,
    # não mantemos .bak persistente no diretório do usuário.
    temp_path = None

    try:
        fd, temp_name = tempfile.mkstemp(
            prefix=".l1ght_recon_update_",
            suffix=".py",
            dir=str(script_dir),
        )
        os.close(fd)
        temp_path = Path(temp_name)
        temp_path.write_bytes(content)

        try:
            os.chmod(temp_path, script_path.stat().st_mode)
        except Exception:
            pass

        os.replace(temp_path, script_path)

    finally:
        if temp_path and temp_path.exists():
            try:
                temp_path.unlink()
            except Exception:
                pass

    return script_path


def cleanup_legacy_update_backups():
    """Remove apenas backups legados criados pelo updater do L1ght Recon."""
    script_path = _running_script_path()
    patterns = (
        f"{script_path.name}.v*.bak",
        f"{script_path.name}.bak",
    )
    removed = []

    for pattern in patterns:
        for candidate in script_path.parent.glob(pattern):
            try:
                if candidate.is_file() or candidate.is_symlink():
                    candidate.unlink()
                    removed.append(candidate)
            except Exception as exc:
                _debug_log("UPDATE_CLEANUP", f"falha removendo {candidate}: {exc}")

    if removed:
        _debug_log(
            "UPDATE_CLEANUP",
            "backups legados removidos: " + ", ".join(str(x) for x in removed),
        )

    return removed


def _restart_after_update(script_path):
    env = dict(os.environ)
    env[UPDATE_SKIP_ONCE_ENV] = "1"

    argv = [
        sys.executable,
        str(script_path),
        *sys.argv[1:],
    ]

    os.execve(sys.executable, argv, env)


def handle_update_check(
    *,
    install=True,
    restart=True,
    verbose=False,
):
    """
    Verifica a versão publicada no manifesto.

    Modo padrão:
      - silencioso quando está atualizado;
      - silencioso quando não há internet/manifesto;
      - só informa algo quando existe atualização real.

    Modo verbose é usado por --check-update e --update. Ambos instalam
    uma versão mais nova quando ela estiver disponível.
    """
    if os.environ.pop(UPDATE_SKIP_ONCE_ENV, None):
        return "skipped"

    try:
        manifest = _download_update_manifest()
    except Exception as exc:
        if verbose:
            print(
                f"{YELLOW}[!]{RESET} Não foi possível consultar atualizações: "
                f"{exc}"
            )
        return "unavailable"

    remote_version = manifest["version"]

    try:
        newer = _version_key(remote_version) > _version_key(VERSION)
    except Exception as exc:
        if verbose:
            print(
                f"{YELLOW}[!]{RESET} Manifesto de atualização inválido: {exc}"
            )
        return "invalid"

    if not newer:
        if verbose:
            print(
                f"{GREEN}[+]{RESET} L1ght Recon v{VERSION} já está atualizado."
            )
        return "current"

    print(
        f"{CYAN}[*]{RESET} Atualização disponível: "
        f"v{VERSION} -> v{remote_version}"
    )

    notes = str(manifest.get("notes") or "").strip()
    if notes and verbose:
        print(f"{DIM}    {notes}{RESET}")

    if not install:
        return "available"

    try:
        script_path = _install_update(manifest)
    except Exception as exc:
        print(
            f"{YELLOW}[!]{RESET} Não foi possível instalar a atualização; "
            f"continuando com v{VERSION}. ({exc})"
        )
        return "failed"

    print(
        f"{GREEN}[+]{RESET} Atualização instalada com sucesso: "
        f"v{VERSION} -> v{remote_version}"
    )

    if restart:
        print(
            f"{CYAN}[*]{RESET} Reiniciando o L1ght Recon com a nova versão..."
        )
        _restart_after_update(script_path)

    return "updated"



# ============================================================
# Runtime bootstrap / debug log
# ============================================================

def _redact_debug_text(value):
    text = _text_value(value)
    for secret in sorted((s for s in DEBUG_SECRETS if s), key=len, reverse=True):
        text = text.replace(secret, "<redacted>")
    text = re.sub(
        r"(?i)(cookie\s*:\s*)[^\r\n]+",
        r"\1<redacted>",
        text,
    )
    return text


def _compact_debug_output(value):
    """Remove apenas ruído visual/progresso; preserva resultados e erros auditáveis."""
    text = _redact_debug_text(value)
    text = re.sub(r"\x1b(?:[@-Z\-_]|\[[0-?]*[ -/]*[@-~])", "", text)
    text = text.replace("\r", "\n")
    kept = []
    dropped = 0
    last = None
    repeats = 0
    for raw in text.splitlines():
        line = raw.rstrip()
        lowered = line.lower()
        if (
            ":: progress:" in lowered
            or ("status:" in lowered and "errors:" in lowered and "duration:" in lowered)
            or re.search(r"\b\d+\s*/\s*\d+\s*\([0-9.]+%\)", line)
        ):
            dropped += 1
            continue
        if line == last:
            repeats += 1
            if repeats > 2:
                dropped += 1
                continue
        else:
            last = line
            repeats = 0
        kept.append(line)
    if dropped:
        kept.append(f"[L1ght Recon] {dropped} frame(s) repetitivo(s) de progresso omitido(s) do debug.log")
    return "\n".join(kept)


def init_debug_log(path, cookie=None):
    global DEBUG_LOG_PATH
    DEBUG_LOG_PATH = Path(path).expanduser().resolve()
    DEBUG_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if cookie:
        DEBUG_SECRETS.add(str(cookie))
    DEBUG_LOG_PATH.write_text(
        f"[{datetime.now().isoformat(timespec='seconds')}] L1ght Recon v{VERSION} debug log\n",
        encoding="utf-8",
    )
    _debug_log("SESSION", f"argv={_redact_debug_text(' '.join(sys.argv))}")


def _debug_log(kind, message):
    if DEBUG_LOG_PATH is None:
        return
    stamp = datetime.now().isoformat(timespec="milliseconds")
    if kind in {"STDOUT", "STDERR"}:
        payload = _compact_debug_output(message)
    else:
        payload = _redact_debug_text(message)
    with DEBUG_LOG_LOCK:
        try:
            with DEBUG_LOG_PATH.open("a", encoding="utf-8") as handle:
                handle.write(f"[{stamp}] [{kind}] {payload}\n")
        except Exception:
            pass


def metric_start(name, **details):
    detail = " ".join(f"{key}={value}" for key, value in details.items())
    _debug_log("PHASE_START", f"{name}{(' ' + detail) if detail else ''}")
    return time.monotonic()


def metric_end(name, started, **details):
    detail = " ".join(f"{key}={value}" for key, value in details.items())
    _debug_log(
        "PHASE_END",
        f"{name} duration={time.monotonic() - started:.3f}s{(' ' + detail) if detail else ''}",
    )


def configure_web_scheduler(full_mode=False):
    global WEB_TOOL_SEMAPHORES
    limits = {
        "ffuf": 2 if full_mode else 1,
        "nuclei": 2 if full_mode else 1,
        "nikto": 1,
    }
    WEB_TOOL_SEMAPHORES = {
        name: threading.BoundedSemaphore(limit)
        for name, limit in limits.items()
    }
    _debug_log(
        "SCHEDULER",
        " ".join(f"{name}_max={limit}" for name, limit in limits.items())
        + f" full={bool(full_mode)}",
    )


def _run_weighted_background(field, fn, *args):
    category = None
    if field in {"ffuf_content", "ffuf_vhosts"}:
        category = "ffuf"
    elif field == "nuclei":
        category = "nuclei"
    elif field == "nikto":
        category = "nikto"
    semaphore = WEB_TOOL_SEMAPHORES.get(category) if category else None
    if semaphore is None:
        return fn(*args)
    started = time.monotonic()
    _debug_log("SCHEDULER_WAIT", f"field={field} category={category}")
    with semaphore:
        _debug_log(
            "SCHEDULER_START",
            f"field={field} category={category} waited={time.monotonic()-started:.3f}s",
        )
        return fn(*args)


def _find_setup_script():
    here = Path(__file__).resolve().parent
    candidates = [here / "setup_tools.sh", here.parent / "setup_tools.sh"]
    return next((path for path in candidates if path.exists()), None)


def ensure_path_command():
    """Registra o comando l1ght_recon sem substituir arquivos regulares existentes."""
    script = Path(__file__).resolve()
    try:
        script.chmod(script.stat().st_mode | 0o111)
    except Exception:
        pass

    if hasattr(os, "geteuid") and os.geteuid() == 0:
        link = Path("/usr/local/bin/l1ght_recon")
    else:
        link = Path.home() / ".local" / "bin" / "l1ght_recon"
        link.parent.mkdir(parents=True, exist_ok=True)

    try:
        if link.is_symlink():
            if link.resolve() != script:
                link.unlink()
                link.symlink_to(script)
        elif not link.exists():
            link.symlink_to(script)
        elif link.resolve() != script:
            _debug_log("PATH", f"não alterado: {link} já existe e não é o script atual")
            return False
        _debug_log("PATH", f"comando disponível em {link} -> {script}")
        return True
    except Exception as exc:
        _debug_log("PATH", f"falha registrando {link}: {exc}")
        return False


def _auto_setup_external_tools(missing):
    if not missing:
        return True
    setup = _find_setup_script()
    if setup is None:
        return False

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        sudo = shutil.which("sudo")
        if not sudo or not sys.stdin.isatty():
            warning(
                "Há ferramentas ausentes. Execute: sudo ./setup_tools.sh "
                "para concluir a instalação."
            )
            return False
        command = [sudo, "bash", str(setup)]
        info(
            "Dependências ausentes detectadas. Solicitando privilégios "
            "administrativos para concluir o setup automático."
        )
    else:
        command = ["bash", str(setup)]
        info(
            "Preparando automaticamente as dependências externas ausentes: "
            + ", ".join(missing)
        )

    stdout, stderr, code = run_command(
        command,
        activity=None,
        timeout=0,
        register_timeout=False,
    )
    if code != 0:
        detail = (stderr or stdout or "").strip().splitlines()
        suffix = f" Última mensagem: {detail[-1]}" if detail else ""
        warning(
            "O setup automático não foi concluído; consulte --log ou execute "
            f"sudo ./setup_tools.sh manualmente.{suffix}"
        )
        return False
    return True


def wait_future_with_progress(future, label, interval=15):
    while True:
        try:
            return future.result(timeout=interval)
        except FutureTimeoutError:
            info(f"{label} continua em execução em segundo plano...")


def preparse_auto_update():
    """
    Faz a checagem automática antes do argparse.

    Isso permite que uma versão antiga se atualize antes de rejeitar um
    parâmetro introduzido por uma versão nova (por exemplo, --log).
    A execução é silenciosa quando não há atualização ou não há Internet.
    """
    raw_args = set(sys.argv[1:])

    if not raw_args:
        return "skipped"

    skip_flags = {
        "-h",
        "--help",
        "--flow",
        "--no-update",
        "--check-update",
        "--update",
    }

    if raw_args.intersection(skip_flags):
        return "skipped"

    return handle_update_check(
        install=True,
        restart=True,
        verbose=False,
    )


# ============================================================
# Visual
# ============================================================

def brand(value="L1ght Recon"):
    return f"{CYAN}{value}{RESET}"


def _center_ansi(text, width, color=""):
    padding = max(0, (width - len(text)) // 2)
    return (" " * padding) + color + text + RESET


def _glitch_intro():
    """
    Animação curta apenas quando a saída é um terminal real.
    Não interfere em pipes, arquivos ou execução automatizada.
    """
    if not sys.stdout.isatty():
        return

    terminal_width = shutil.get_terminal_size((80, 24)).columns

    frames = [
        ("L1GHT // R3C0N", MAGENTA),
        ("L1G_T // RE_C0N", CYAN),
        ("L1GHT // RECON", MAGENTA),
    ]

    for frame, color in frames:
        line = _center_ansi(frame, terminal_width, color)
        print("\r" + line, end="", flush=True)
        time.sleep(0.07)

    print(
        "\r" + (" " * max(1, terminal_width - 1)),
        end="\r",
        flush=True,
    )


def banner():
    _glitch_intro()

    width = 78
    top = "╔" + ("═" * width) + "╗"
    bottom = "╚" + ("═" * width) + "╝"

    logo = [
        "██╗      ██╗ ██████╗ ██╗  ██╗████████╗",
        "██║     ███║██╔════╝ ██║  ██║╚══██╔══╝",
        "██║      ██║██║  ███╗███████║   ██║",
        "██║      ██║██║██╔══██║██╔══██║   ██║",
        "███████╗ ██║╚██████╔╝██║  ██║   ██║",
        "╚══════╝ ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝",
    ]

    # Corrige a quarta linha para manter o desenho visual do "L1GHT".
    logo[3] = "██║      ██║██║   ██║██╔══██║   ██║"

    print(BLUE + top + RESET)
    print(BLUE + "║" + (" " * width) + "║" + RESET)

    for index, line in enumerate(logo):
        logo_color = CYAN if index % 2 == 0 else BLUE
        left = max(0, (width - len(line)) // 2)
        right = max(0, width - len(line) - left)

        print(
            BLUE
            + "║"
            + RESET
            + (" " * left)
            + logo_color
            + line
            + RESET
            + (" " * right)
            + BLUE
            + "║"
            + RESET
        )

    print(BLUE + "║" + (" " * width) + "║" + RESET)

    recon = "R  E  C  O  N"
    left = max(0, (width - len(recon)) // 2)
    right = max(0, width - len(recon) - left)

    print(
        BLUE
        + "║"
        + RESET
        + (" " * left)
        + MAGENTA
        + BOLD
        + recon
        + RESET
        + (" " * right)
        + BLUE
        + "║"
        + RESET
    )

    print(BLUE + "║" + (" " * width) + "║" + RESET)

    subtitle = "Scanning & Enumeration"
    left = max(0, (width - len(subtitle)) // 2)
    right = max(0, width - len(subtitle) - left)

    print(
        BLUE
        + "║"
        + RESET
        + (" " * left)
        + CYAN
        + subtitle
        + RESET
        + (" " * right)
        + BLUE
        + "║"
        + RESET
    )

    signature = f"v{VERSION}  ·  {HANDLE}"
    left = max(0, (width - len(signature)) // 2)
    right = max(0, width - len(signature) - left)

    print(
        BLUE
        + "║"
        + RESET
        + (" " * left)
        + GREEN
        + f"v{VERSION}"
        + RESET
        + "  ·  "
        + MAGENTA
        + HANDLE
        + RESET
        + (" " * right)
        + BLUE
        + "║"
        + RESET
    )

    print(BLUE + "║" + (" " * width) + "║" + RESET)
    print(BLUE + bottom + RESET)

    print(
        f"{YELLOW}[i]{RESET} Para consultar todas as opções e exemplos de uso, "
        f"execute: python3 l1ght_recon.py {GREEN}-h{RESET}"
    )
    print(
        f"{YELLOW}[i]{RESET} Para entender o fluxo e os comandos utilizados, "
        f"execute: python3 l1ght_recon.py {GREEN}--flow{RESET}"
    )
    print()


def print_flow():
    b = brand()
    command = lambda value: f"{GREEN}{value}{RESET}"

    lines = [
        "",
        f"{CYAN}{'=' * 72}{RESET}",
        f"{BOLD}FLUXO DO {b}{RESET}",
        f"{CYAN}{'=' * 72}{RESET}",
        "",
        "1. Coleta silenciosa de rede/DNS quando aplicável",
        "   " + command("dig +short -x IP"),
        "   " + command("dig +short DOMAIN A|AAAA|MX|NS|TXT"),
        "   " + command("dig AXFR DOMAIN @NS"),
        "   " + command("nmap -sn --script dns-brute --script-args dns-brute.domain=DOMAIN DOMAIN"),
        "",
        "2. Nmap TCP - descoberta rápida",
        "   " + command(
            "nmap -sS -p- --open -Pn -n TARGET -T4 --min-rate 1000"
        ),
        "",
        "3. Nmap TCP - detalhamento das portas encontradas",
        "   " + command(
            "nmap -sS -sC -sV -O --osscan-guess -p PORTAS TARGET -T4"
        ),
        "",
        "4. Scan UDP em segundo plano",
        "   " + command(
            f"nmap -sU --open --top-ports {DEFAULT_UDP_TOP_PORTS} -Pn -n TARGET -T4"
        ),
        f"   --full usa {FULL_UDP_TOP_PORTS} portas UDP; --udp-top permite ajuste até {MAX_UDP_TOP_PORTS}.",
        "",
        "5. Enumeração específica dos serviços encontrados",
        "   FTP, SSH, SMTP, DNS, RPC, SMB, SNMP, LDAP, RDP, NFS/mountd,",
        "   bancos, Redis, VNC, Telnet e banner genérico.",
        "   RPC/NFS também usam rpcinfo/showmount/rpcclient quando disponíveis.",
        "",
        "6. Identificação das portas Web",
        "   " + command(
            "httpx -l open_ports_targets.txt -silent -json "
            "-status-code -title -tech-detect -server -content-length -location"
        ),
        "",
        "7. robots.txt, sitemap.xml, redirects e crawling",
        "   robots.txt usa Googlebot.",
        "   " + command(
            "katana -u URL -d DEPTH -jc -kf all -fx -jsonl -silent -nc"
        ),
        "",
        "8. FFUF por porta Web",
        "   " + command(
            "ffuf -w WORDLIST:FUZZ -u URL/FUZZ -recursion "
            "-recursion-depth FFUF_DEPTH -e EXTENSIONS ..."
        ),
        "   Automático: php,html,txt; asp,aspx entram somente em alvo Windows/IIS.",
        "   Os achados são apresentados em blocos durante a execução.",
        "",
        "9. Análise complementar",
        "   " + command("whatweb --color=never --no-errors URL"),
        "   " + command("nuclei -u URL -silent -jsonl ..."),
        "   " + command("nikto -h URL ..."),
        "   " + command("wafw00f -a --no-colors URL"),
        "   " + command("searchsploit --json 'PRODUTO VERSAO'"),
        "",
        "10. Saída",
        "   Resultados rápidos aparecem primeiro.",
        "   Background: WhatWeb -> FFUF -> Nuclei -> Nikto.",
        "   UDP e enumerações extensas são compilados na seção FINAL.",
        "",
        "11. Timeout opcional",
        "   Por padrão NÃO existe timeout.",
        "   Use --timeout SEGUNDOS somente quando quiser impor um limite.",
        "",
        "12. Relatório",
        "   report.html contém detalhes adicionais que não poluem o terminal.",
        "",
        "Observação:",
        "   --low-noise reduz timing, taxas e scripts agressivos,",
        "   mas não transforma a varredura em uma operação furtiva.",
        "",
    ]

    console_block(lines)


def console_block(lines):
    with CONSOLE_LOCK:
        for line in lines:
            print(line)


def info(message):
    with CONSOLE_LOCK:
        print(f"{BLUE}[*]{RESET} {message}")


def success(message):
    with CONSOLE_LOCK:
        print(f"{GREEN}[+]{RESET} {message}")


def warning(message):
    with CONSOLE_LOCK:
        print(f"{YELLOW}[!]{RESET} {message}")


def error(message):
    with CONSOLE_LOCK:
        print(f"{RED}[-]{RESET} {message}")


def section(message):
    _debug_log("SECTION", message)
    with CONSOLE_LOCK:
        print()
        print(f"{CYAN}{'=' * 72}{RESET}")
        print(f"{BOLD}{message}{RESET}")
        print(f"{CYAN}{'=' * 72}{RESET}")


# ============================================================
# Generic helpers
# ============================================================

def _looks_like_projectdiscovery_httpx(path):
    """Evita confundir o httpx da ProjectDiscovery com o CLI do python-httpx."""
    if not path:
        return False
    try:
        result = subprocess.run(
            [str(path), "-h"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=4,
            check=False,
        )
        output = (result.stdout or "").lower()
    except Exception:
        return False

    return (
        "fast and multi-purpose http toolkit" in output
        or (
            "-silent" in output
            and "-status-code" in output
            and ("projectdiscovery" in output or "httpx" in output)
        )
    )


def resolve_tool_binary(command):
    if command == "httpx":
        candidates = []
        for candidate in (
            shutil.which("httpx-toolkit"),
            "/usr/local/bin/httpx" if Path("/usr/local/bin/httpx").exists() else None,
            shutil.which("httpx"),
        ):
            if candidate and candidate not in candidates:
                candidates.append(candidate)

        for candidate in candidates:
            if _looks_like_projectdiscovery_httpx(candidate):
                return str(candidate)
        return None

    return shutil.which(command)


def command_exists(command):
    path = resolve_tool_binary(command)
    if path:
        TOOL_BINARIES[command] = path
        return True
    TOOL_BINARIES.pop(command, None)
    return False


def tool_command(command):
    return TOOL_BINARIES.get(command) or resolve_tool_binary(command) or command


def safe_name(value):
    value = re.sub(r"^https?://", "", value, flags=re.I)
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
    return value.strip("_") or "target"


def normalize_target(value):
    value = value.strip().strip("\"'")

    # Accept accidental Markdown links:
    # [http://10.10.10.10:8080/](http://10.10.10.10:8080/)
    match = re.match(r"^\[(https?://[^\]]+)\]\([^)]+\)$", value)
    if match:
        value = match.group(1)

    return value.rstrip("/")


def target_host(value):
    candidate = value
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
        candidate = "http://" + candidate

    parsed = urlparse(candidate)
    if not parsed.hostname:
        raise ValueError("Não foi possível identificar o host do alvo.")

    return parsed.hostname


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def write_lines(path, lines):
    values = sorted({str(x).strip() for x in lines if str(x).strip()})
    Path(path).write_text(
        "".join(f"{line}\n" for line in values),
        encoding="utf-8",
    )


def redact_file_secret(path, secret):
    if not secret:
        return

    path = Path(path)
    if not path.exists():
        return

    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        if secret in content:
            path.write_text(
                content.replace(secret, "<redacted-session-cookie>"),
                encoding="utf-8",
            )
    except Exception:
        pass


def _text_value(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)


def _register_timeout(command, output_file=None, activity=None, timeout=None):
    TIMED_OUT_TASKS.append(
        {
            "command": [str(item) for item in command],
            "output_file": str(output_file) if output_file else None,
            "activity": activity or str(command[0]),
            "timeout": timeout,
        }
    )


def run_command(
    command,
    output_file=None,
    activity=None,
    timeout=None,
    register_timeout=True,
    heartbeat=None,
    heartbeat_interval=1.0,
):
    if activity:
        info(activity)

    effective_timeout = COMMAND_TIMEOUT if timeout is None else timeout
    if effective_timeout == 0:
        effective_timeout = None

    process = None
    stdout_lines = []
    stderr_lines = []
    started = time.monotonic()
    safe_command = _redact_debug_text(" ".join(str(x) for x in command))
    _debug_log("COMMAND_START", safe_command)

    def _reader(stream, sink):
        try:
            for line in iter(stream.readline, ""):
                sink.append(line)
        except Exception as exc:
            _debug_log("READER_ERROR", str(exc))
        finally:
            try:
                stream.close()
            except Exception:
                pass

    try:
        process = subprocess.Popen(
            [str(x) for x in command],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        stdout_thread = threading.Thread(
            target=_reader,
            args=(process.stdout, stdout_lines),
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=_reader,
            args=(process.stderr, stderr_lines),
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()

        timed_out = False
        last_heartbeat = started
        while process.poll() is None:
            now = time.monotonic()
            if effective_timeout is not None and now - started >= effective_timeout:
                timed_out = True
                process.kill()
                break
            if heartbeat and now - last_heartbeat >= heartbeat_interval:
                try:
                    heartbeat()
                except Exception as exc:
                    _debug_log("HEARTBEAT_ERROR", str(exc))
                last_heartbeat = now
            time.sleep(0.15)

        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()

        stdout_thread.join(timeout=2)
        stderr_thread.join(timeout=2)
        stdout = "".join(stdout_lines)
        stderr = "".join(stderr_lines)
        return_code = process.returncode
        elapsed = time.monotonic() - started

        _debug_log(
            "COMMAND_END",
            f"rc={124 if timed_out else return_code} duration={elapsed:.3f}s cmd={safe_command}",
        )
        if stdout:
            _debug_log("STDOUT", stdout)
        if stderr:
            _debug_log("STDERR", stderr)

        if timed_out:
            if output_file is not None:
                Path(output_file).write_text(stdout, encoding="utf-8")
            warning(
                f"{command[0]} atingiu o limite de {effective_timeout}s; "
                "resultados parciais foram preservados."
            )
            if register_timeout:
                _register_timeout(
                    command,
                    output_file=output_file,
                    activity=activity,
                    timeout=effective_timeout,
                )
            return stdout, stderr, 124

    except KeyboardInterrupt:
        if process is not None and process.poll() is None:
            process.kill()
        _debug_log("INTERRUPT", safe_command)
        warning("Execução interrompida pelo usuário.")
        raise
    except Exception as exc:
        _debug_log("COMMAND_EXCEPTION", f"cmd={safe_command} exc={exc!r}")
        error(f"Falha executando {command[0]}: {exc}")
        return "", "", -1

    if output_file is not None:
        Path(output_file).write_text(stdout or "", encoding="utf-8")

    if return_code != 0 and (stderr or "").strip():
        warning(
            f"{command[0]} retornou código {return_code}: "
            f"{stderr.strip().splitlines()[-1]}"
        )

    return stdout or "", stderr or "", return_code


def offer_continue_timeouts():
    if not TIMED_OUT_TASKS:
        return

    section("VARREDURAS QUE ATINGIRAM O LIMITE DE TEMPO")
    warning(
        f"{len(TIMED_OUT_TASKS)} comando(s) atingiram o limite configurado. "
        "Os resultados obtidos até o momento foram mantidos."
    )

    for index, task in enumerate(TIMED_OUT_TASKS, start=1):
        print(f"  {index}. {task['activity']}")

    if not sys.stdin.isatty():
        print()
        info(
            "Execução não interativa: para repetir sem limite de tempo, "
            "use --timeout 0."
        )
        return

    print()
    answer = input(
        "Deseja continuar executando novamente apenas esses comandos "
        "sem limite de tempo? [s/N]: "
    ).strip().lower()

    if answer not in {"s", "sim", "y", "yes"}:
        return

    pending = list(TIMED_OUT_TASKS)
    TIMED_OUT_TASKS.clear()

    for index, task in enumerate(pending, start=1):
        info(
            f"Continuando [{index}/{len(pending)}] "
            f"{task['activity']} sem limite de tempo..."
        )

        run_command(
            task["command"],
            output_file=task["output_file"],
            activity=None,
            timeout=0,
            register_timeout=False,
        )

    success(
        "Comandos que haviam atingido o limite foram executados novamente."
    )


def html_table(headers, rows):
    if not rows:
        return '<p class="muted">Nenhum resultado.</p>'

    head = "".join(f"<th>{html.escape(str(item))}</th>" for item in headers)
    body = []

    for row in rows:
        cells = "".join(f"<td>{item}</td>" for item in row)
        body.append(f"<tr>{cells}</tr>")

    return (
        '<div class="table-wrap"><table>'
        f"<thead><tr>{head}</tr></thead>"
        f"<tbody>{''.join(body)}</tbody>"
        "</table></div>"
    )


# ============================================================
# Dependency checks
# ============================================================

def check_external_tools(auto_setup=False):
    tools = [
        "nmap", "httpx", "katana", "ffuf", "nikto", "nuclei",
        "whatweb", "wafw00f", "dig", "rpcinfo", "showmount",
        "rpcclient", "smbclient", "snmpwalk", "searchsploit",
    ]
    status = {tool: command_exists(tool) for tool in tools}
    missing = [tool for tool, found in status.items() if not found]

    if missing and auto_setup:
        _debug_log("DEPENDENCIES", "missing before setup: " + ", ".join(missing))
        if _auto_setup_external_tools(missing):
            status = {tool: command_exists(tool) for tool in tools}
            missing = [tool for tool, found in status.items() if not found]

    if missing:
        section("DEPENDÊNCIAS EXTERNAS AUSENTES")
        for tool in missing:
            warning(f"{tool:<8} não encontrado; a etapa correspondente será ignorada.")
    else:
        _debug_log(
            "DEPENDENCIES",
            "all external tools available; "
            + " ".join(
                f"{name}={TOOL_BINARIES.get(name) or resolve_tool_binary(name) or '-'}"
                for name in tools
            ),
        )

    return status


# ============================================================
# Nmap
# ============================================================

def parse_gnmap_open_ports(gnmap_file):
    ports = []

    path = Path(gnmap_file)
    if not path.exists():
        return ports

    for line in path.read_text(
        encoding="utf-8",
        errors="ignore",
    ).splitlines():
        if "Ports:" not in line:
            continue

        ports_part = line.split("Ports:", 1)[1]

        for item in ports_part.split(","):
            fields = item.strip().split("/")
            if len(fields) < 2:
                continue

            if fields[1] != "open":
                continue

            try:
                ports.append(int(fields[0]))
            except ValueError:
                continue

    return sorted(set(ports))


def run_nmap(host, output_dir):
    section("1. NMAP — DESCOBERTA TCP E ENUMERAÇÃO DETALHADA")

    discovery_normal = output_dir / "nmap_discovery.txt"
    discovery_gnmap = output_dir / "nmap_discovery.gnmap"

    timing = "-T2" if LOW_NOISE else "-T4"

    discovery_command = [
        "nmap",
        "-sS",
        "-p-",
        "--open",
        "-Pn",
        "-n",
        host,
        timing,
    ]

    if not LOW_NOISE:
        discovery_command.extend(["--min-rate", "1000"])

    discovery_command.extend(
        [
            "-oN",
            discovery_normal,
            "-oG",
            discovery_gnmap,
        ]
    )

    _, _, discovery_code = run_command(
        discovery_command,
        activity=(
            "Executando Nmap fase 1 — descoberta rápida de portas TCP abertas..."
        ),
    )

    open_port_numbers = parse_gnmap_open_ports(discovery_gnmap)

    if not open_port_numbers:
        # Preserve any visible partial result when Nmap timed out.
        partial_text = ""
        if discovery_normal.exists():
            partial_text = discovery_normal.read_text(
                encoding="utf-8",
                errors="ignore",
            )

        for match in re.findall(
            r"^(\d+)/tcp\s+open\b",
            partial_text,
            flags=re.M,
        ):
            open_port_numbers.append(int(match))

        open_port_numbers = sorted(set(open_port_numbers))

    if not open_port_numbers:
        warning(
            "Nenhuma porta TCP aberta foi identificada na fase de descoberta."
        )
        return []

    success(
        "Nmap fase 1: "
        f"{len(open_port_numbers)} porta(s) TCP aberta(s) identificada(s): "
        + ",".join(str(port) for port in open_port_numbers)
    )

    normal_file = output_dir / "nmap.txt"
    xml_file = output_dir / "nmap.xml"

    ports_arg = ",".join(str(port) for port in open_port_numbers)

    detailed_command = [
        "nmap",
        "-sS",
        "-sV",
        "-v",
        "--open",
        "-Pn",
        "-n",
        "-p",
        ports_arg,
        host,
        timing,
    ]

    if LOW_NOISE:
        detailed_command.append("--version-light")
    else:
        detailed_command.extend(["-sC", "-O", "--osscan-guess"])

    detailed_command.extend(
        [
            "--script-timeout",
            "60s",
            "-oN",
            normal_file,
            "-oX",
            xml_file,
        ]
    )

    _, _, return_code = run_command(
        detailed_command,
        activity=(
            "Executando Nmap fase 2 — serviços, versões e scripts NSE "
            "somente nas portas TCP identificadas..."
        ),
    )

    if not xml_file.exists():
        warning(
            "Não foi possível obter XML detalhado do Nmap; "
            "mantendo apenas as portas descobertas."
        )
        return [
            {
                "port": port,
                "protocol": "tcp",
                "service": "",
                "product": "",
                "version": "",
                "extrainfo": "",
                "tunnel": "",
                "scripts": [],
            }
            for port in open_port_numbers
        ]

    return parse_nmap_xml(xml_file)


def parse_nmap_xml(xml_file, display=True):
    ports = []

    try:
        root = ET.parse(xml_file).getroot()
    except Exception as exc:
        warning(f"Falha ao interpretar XML do Nmap: {exc}")
        return ports

    for host_node in root.findall("host"):
        host_os = [
            node.get("name", "")
            for node in host_node.findall("./os/osmatch")
            if node.get("name")
        ]

        for port_node in host_node.findall("./ports/port"):
            state = port_node.find("state")
            if state is None or state.get("state") != "open":
                continue

            port_id = int(port_node.get("portid"))
            protocol = port_node.get("protocol", "tcp")
            service_node = port_node.find("service")

            service = ""
            product = ""
            version = ""
            extrainfo = ""
            tunnel = ""

            if service_node is not None:
                service = service_node.get("name", "")
                product = service_node.get("product", "")
                version = service_node.get("version", "")
                extrainfo = service_node.get("extrainfo", "")
                tunnel = service_node.get("tunnel", "")

            scripts = []
            for script in port_node.findall("script"):
                scripts.append(
                    {
                        "id": script.get("id", ""),
                        "output": script.get("output", ""),
                    }
                )

            ports.append(
                {
                    "port": port_id,
                    "protocol": protocol,
                    "service": service,
                    "product": product,
                    "version": version,
                    "extrainfo": extrainfo,
                    "tunnel": tunnel,
                    "host_os": host_os,
                    "scripts": scripts,
                }
            )

    ports.sort(key=lambda item: (item["protocol"], item["port"]))
    if display:
        print_ports(ports)
    return ports


def print_ports(ports):
    if not ports:
        warning("Nenhuma porta TCP aberta encontrada.")
        return

    print()
    print(f"{BOLD}{'PORT':<11}{'STATE':<8}{'SERVICE':<18}{'VERSION'}{RESET}")
    print("-" * 92)

    for item in ports:
        description = " ".join(
            x
            for x in [
                item["product"],
                item["version"],
                item["extrainfo"],
            ]
            if x
        )

        port_text = f"{item['port']}/{item['protocol']}"
        print(
            f"{port_text:<11}"
            f"{'open':<8}"
            f"{(item['service'] or 'unknown'):<18}"
            f"{description}"
        )

        for script in item["scripts"]:
            output = (script["output"] or "").strip()
            if not output:
                continue

            print(f"| {script['id']}:")

            for raw_line in output.splitlines():
                cleaned = raw_line.strip()

                if not cleaned:
                    continue

                wrapped = textwrap.wrap(
                    cleaned,
                    width=104,
                    subsequent_indent="",
                ) or [""]

                for line in wrapped:
                    print(f"|   {line}")

            print("|_")

    print()


# ============================================================
# UDP scan and generic service enumeration
# ============================================================

SERVICE_PROFILES = [
    {
        "name": "FTP",
        "ports": {20, 21},
        "names": {"ftp"},
        "base": ["banner", "ftp-anon", "ftp-syst"],
        "extra": ["ftp-vsftpd-backdoor"],
    },
    {
        "name": "SSH",
        "ports": {22},
        "names": {"ssh"},
        "base": [
            "banner",
            "ssh-hostkey",
            "ssh2-enum-algos",
            "ssh-auth-methods",
        ],
        "extra": [],
    },
    {
        "name": "SMTP",
        "ports": {25, 465, 587},
        "names": {"smtp", "smtps"},
        "base": ["banner", "smtp-commands"],
        "extra": [],
    },
    {
        "name": "DNS",
        "ports": {53},
        "names": {"domain"},
        "base": ["dns-nsid"],
        "extra": [],
    },
    {
        "name": "RPC",
        "ports": {111},
        "names": {"rpcbind", "rpc"},
        "base": ["rpcinfo"],
        "extra": [],
    },
    {
        "name": "SMB",
        "ports": {139, 445},
        "names": {"netbios-ssn", "microsoft-ds"},
        "base": [
            "smb-os-discovery",
            "smb-protocols",
            "smb2-security-mode",
            "smb2-time",
            "smb-enum-shares",
        ],
        "extra": [
            "smb-enum-users",
            "smb-vuln-ms17-010",
        ],
    },
    {
        "name": "SNMP",
        "ports": {161, 162},
        "names": {"snmp", "snmptrap"},
        "base": [
            "snmp-info",
            "snmp-sysdescr",
            "snmp-interfaces",
        ],
        "extra": [
            "snmp-netstat",
            "snmp-processes",
        ],
    },
    {
        "name": "LDAP",
        "ports": {389, 636},
        "names": {"ldap", "ldaps"},
        "base": ["ldap-rootdse"],
        "extra": [],
    },
    {
        "name": "RDP",
        "ports": {3389},
        "names": {"ms-wbt-server"},
        "base": [
            "rdp-enum-encryption",
            "rdp-ntlm-info",
        ],
        "extra": ["rdp-vuln-ms12-020"],
    },
    {
        "name": "NFS",
        "ports": {2049},
        "names": {"nfs", "mountd"},
        "base": [
            "nfs-showmount",
            "nfs-ls",
            "nfs-statfs",
        ],
        "extra": [],
    },
    {
        "name": "MySQL",
        "ports": {3306},
        "names": {"mysql"},
        "base": ["mysql-info"],
        "extra": [],
    },
    {
        "name": "MSSQL",
        "ports": {1433},
        "names": {"ms-sql-s"},
        "base": [
            "ms-sql-info",
            "ms-sql-ntlm-info",
        ],
        "extra": [],
    },
    {
        "name": "PostgreSQL",
        "ports": {5432},
        "names": {"postgresql"},
        "base": ["banner"],
        "extra": [],
    },
    {
        "name": "Redis",
        "ports": {6379},
        "names": {"redis"},
        "base": ["redis-info"],
        "extra": [],
    },
    {
        "name": "VNC",
        "ports": {5900, 5901, 5902},
        "names": {"vnc"},
        "base": ["vnc-info"],
        "extra": [],
    },
    {
        "name": "Telnet",
        "ports": {23},
        "names": {"telnet"},
        "base": ["banner", "telnet-encryption"],
        "extra": [],
    },
]


def is_probably_web_port(item):
    service_name = (item.get("service") or "").lower()

    if "http" in service_name:
        return True

    return item.get("port") in {
        80, 443, 8000, 8008, 8080, 8081, 8443, 8888,
        3000, 5000, 7001, 9000, 9090, 28080,
    }


def get_service_profile(item):
    port = item.get("port")
    service_name = (item.get("service") or "").lower()

    for profile in SERVICE_PROFILES:
        if (
            port in profile["ports"]
            or service_name in profile["names"]
        ):
            return profile

    return {
        "name": service_name.upper() if service_name else "GENERIC",
        "ports": {port},
        "names": {service_name} if service_name else set(),
        "base": ["banner"],
        "extra": [],
    }


def looks_like_windows_target(open_ports, web_services=None):
    strong_windows_ports = {135, 3389}
    windows_terms = {
        "windows",
        "microsoft windows",
        "internet information services",
        "iis",
        "asp.net",
        "msrpc",
        "ms-wbt-server",
    }

    for item in open_ports or []:
        if item.get("port") in strong_windows_ports:
            return True

        blob = " ".join(
            [
                str(item.get("service") or ""),
                str(item.get("product") or ""),
                str(item.get("version") or ""),
                str(item.get("extrainfo") or ""),
                " ".join(item.get("host_os") or []),
            ]
        ).lower()

        if any(term in blob for term in windows_terms):
            return True

    for service in web_services or []:
        blob = " ".join(
            [
                str(service.get("server") or ""),
                " ".join(service.get("tech") or []),
                str(service.get("title") or ""),
            ]
        ).lower()

        if any(
            term in blob
            for term in [
                "iis",
                "asp.net",
                "windows",
                "microsoft",
            ]
        ):
            return True

    return False


def resolve_ffuf_extensions(user_value, open_ports, web_services):
    if user_value is not None:
        return normalize_extensions(user_value)

    values = ["php", "html", "txt"]

    if looks_like_windows_target(open_ports, web_services):
        values.extend(["asp", "aspx"])

    return normalize_extensions(",".join(values))


def parse_nmap_udp_states(xml_file):
    values = []
    try:
        root = ET.parse(xml_file).getroot()
    except Exception:
        return values
    for host_node in root.findall("host"):
        for port_node in host_node.findall("./ports/port"):
            if port_node.get("protocol") != "udp":
                continue
            state_node = port_node.find("state")
            state = state_node.get("state", "") if state_node is not None else ""
            if state not in {"open", "open|filtered"}:
                continue
            service_node = port_node.find("service")
            scripts = [
                {"id": node.get("id", ""), "output": node.get("output", "")}
                for node in port_node.findall("script")
            ]
            values.append({
                "port": int(port_node.get("portid")),
                "protocol": "udp",
                "state": state,
                "reason": state_node.get("reason", "") if state_node is not None else "",
                "service": service_node.get("name", "") if service_node is not None else "",
                "product": service_node.get("product", "") if service_node is not None else "",
                "version": service_node.get("version", "") if service_node is not None else "",
                "extrainfo": service_node.get("extrainfo", "") if service_node is not None else "",
                "tunnel": service_node.get("tunnel", "") if service_node is not None else "",
                "scripts": scripts,
            })
    return sorted(values, key=lambda item: item["port"])


def _fallback_udp_states(normal_file):
    values = []
    if not Path(normal_file).exists():
        return values
    content = Path(normal_file).read_text(encoding="utf-8", errors="ignore")
    for match in re.finditer(
        r"^(\d+)/udp\s+(open(?:\|filtered)?)\s+(\S+)?",
        content,
        flags=re.M,
    ):
        values.append({
            "port": int(match.group(1)), "protocol": "udp",
            "state": match.group(2), "reason": "",
            "service": match.group(3) or "", "product": "", "version": "",
            "extrainfo": "", "tunnel": "", "scripts": [],
        })
    return values


def run_udp_scan(host, output_dir, top_ports=DEFAULT_UDP_TOP_PORTS):
    started = metric_start("udp_scan", top_ports=top_ports)
    normal_file = output_dir / "nmap_udp.txt"
    xml_file = output_dir / "nmap_udp.xml"
    timing = "-T2" if LOW_NOISE else "-T4"

    command = [
        "nmap", "-sU", "--open", "--top-ports", str(top_ports),
        "--reason", "-Pn", "-n", host, timing, "--script-timeout", "45s",
        "-oN", normal_file, "-oX", xml_file,
    ]
    run_command(command, activity=None)

    states = parse_nmap_udp_states(xml_file) if xml_file.exists() else []
    if not states:
        states = _fallback_udp_states(normal_file)

    confirmed = {item["port"]: item for item in states if item.get("state") == "open"}
    candidates = {item["port"]: item for item in states if item.get("state") == "open|filtered"}

    if candidates:
        ports_text = ",".join(str(port) for port in sorted(candidates))
        confirm_normal = output_dir / "nmap_udp_confirm.txt"
        confirm_xml = output_dir / "nmap_udp_confirm.xml"
        confirm_command = [
            "nmap", "-sU", "-sV", "--version-light", "--reason",
            "--max-retries", "1", "-Pn", "-n", "-p", ports_text,
            host, timing, "--script-timeout", "30s",
            "-oN", confirm_normal, "-oX", confirm_xml,
        ]
        run_command(confirm_command, activity=None)
        confirmed_states = parse_nmap_udp_states(confirm_xml) if confirm_xml.exists() else []
        if not confirmed_states:
            confirmed_states = _fallback_udp_states(confirm_normal)
        for item in confirmed_states:
            if item.get("state") == "open":
                confirmed[item["port"]] = item
                candidates.pop(item["port"], None)
            elif item.get("state") == "open|filtered":
                candidates[item["port"]] = item

    summary = {
        "top_ports": int(top_ports),
        "open": sorted(confirmed.values(), key=lambda item: item["port"]),
        "open_filtered": sorted(candidates.values(), key=lambda item: item["port"]),
    }
    (output_dir / "udp_state_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    metric_end(
        "udp_scan", started, open=len(summary["open"]),
        open_filtered=len(summary["open_filtered"]),
    )
    return summary


def print_udp_results(udp_ports, use_section=True, udp_candidates=None):
    if use_section:
        section("UDP — RESULTADO DO SCAN EM SEGUNDO PLANO")
    if not udp_ports:
        print("Nenhuma porta UDP confirmada como aberta.")
    else:
        print_ports(udp_ports)
    udp_candidates = udp_candidates or []
    if udp_candidates:
        print(f"{YELLOW}[!]{RESET} {len(udp_candidates)} porta(s) permaneceram open|filtered e não são contadas como abertas.")


def run_one_service_enum(host, item, output_dir):
    profile = get_service_profile(item)
    port = item["port"]
    protocol = item.get("protocol", "tcp")
    service_dir = output_dir / "service_enum"
    service_dir.mkdir(parents=True, exist_ok=True)

    scripts = list(profile["base"])

    if not LOW_NOISE:
        scripts.extend(profile["extra"])

    scripts = list(dict.fromkeys(script for script in scripts if script))

    if not scripts:
        return {
            "profile": profile["name"],
            "port": port,
            "protocol": protocol,
            "service": item.get("service") or "",
            "result": item,
        }

    normal_file = service_dir / f"{protocol}_{port}.txt"
    xml_file = service_dir / f"{protocol}_{port}.xml"

    timing = "-T2" if LOW_NOISE else "-T4"

    command = [
        "nmap",
        "-Pn",
        "-n",
        "-sV",
    ]

    if protocol == "udp":
        command.append("-sU")
    else:
        command.append("-sS")

    command.extend(
        [
            "-p",
            str(port),
            "--script",
            ",".join(scripts),
            "--script-timeout",
            "45s",
            host,
            timing,
            "-oN",
            normal_file,
            "-oX",
            xml_file,
        ]
    )

    run_command(
        command,
        activity=None,
    )

    parsed = parse_nmap_xml(xml_file, display=False) if xml_file.exists() else []

    result_item = parsed[0] if parsed else item

    product = result_item.get("product") or ""
    version = result_item.get("version") or ""

    public_exploits = search_public_exploits(
        product,
        version,
        output_dir,
        f"{protocol}_{port}_{product}_{version}",
    )

    return {
        "profile": profile["name"],
        "port": port,
        "protocol": protocol,
        "service": result_item.get("service") or item.get("service") or "",
        "product": product,
        "version": version,
        "scripts": result_item.get("scripts") or [],
        "public_exploits": public_exploits,
        "raw_file": str(normal_file),
    }


def run_smb_service_enum(host, items, output_dir):
    ports = sorted({int(item["port"]) for item in items})
    profile = get_service_profile(items[0])
    service_dir = output_dir / "service_enum"
    service_dir.mkdir(parents=True, exist_ok=True)
    scripts = list(profile["base"])
    if not LOW_NOISE:
        scripts.extend(profile["extra"])
    scripts = list(dict.fromkeys(s for s in scripts if s))
    normal_file = service_dir / "tcp_smb_139_445.txt"
    xml_file = service_dir / "tcp_smb_139_445.xml"
    timing = "-T2" if LOW_NOISE else "-T4"
    command = [
        "nmap", "-Pn", "-n", "-sV", "-sS", "-p", ",".join(map(str, ports)),
        "--script", ",".join(scripts), "--script-timeout", "45s",
        host, timing, "-oN", normal_file, "-oX", xml_file,
    ]
    run_command(command, activity=None)
    parsed = parse_nmap_xml(xml_file, display=False) if xml_file.exists() else []
    scripts_out = []
    product = ""
    version = ""
    service = "netbios-ssn"
    for item in parsed:
        product = product or item.get("product") or ""
        version = version or item.get("version") or ""
        service = item.get("service") or service
        for script in item.get("scripts") or []:
            scripts_out.append({
                "id": f"{item.get('port')}/{script.get('id') or 'NSE'}",
                "output": script.get("output") or "",
            })
    public_exploits = search_public_exploits(
        product, version, output_dir, f"tcp_smb_{product}_{version}"
    )
    return {
        "profile": "SMB",
        "port": ports[0],
        "ports": ports,
        "protocol": "tcp",
        "service": service,
        "product": product,
        "version": version,
        "scripts": scripts_out,
        "public_exploits": public_exploits,
        "raw_file": str(normal_file),
    }


def _print_service_partial(item):
    ports = item.get("ports") or [item.get("port")]
    port_text = ",".join(str(p) for p in ports if p is not None)
    profile = item.get("profile") or item.get("service") or "Serviço"
    console_block([
        f"{GREEN}[+]{RESET} Enumeração concluída: {profile} — {port_text}/{item.get('protocol', 'tcp')}"
    ])


def run_service_enumeration(host, ports, output_dir, live=False):
    candidates = [
        item
        for item in ports
        if not is_probably_web_port(item)
    ]

    if not candidates:
        return []

    results = []
    smb_items = [
        item for item in candidates
        if item.get("protocol", "tcp") == "tcp" and int(item.get("port", 0)) in {139, 445}
    ]
    regular = [item for item in candidates if item not in smb_items]
    job_count = len(regular) + (1 if smb_items else 0)
    workers = 1 if LOW_NOISE else min(6, max(1, job_count))

    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = {}
        for item in regular:
            future = executor.submit(run_one_service_enum, host, item, output_dir)
            futures[future] = item
        if smb_items:
            future = executor.submit(run_smb_service_enum, host, smb_items, output_dir)
            futures[future] = smb_items[0]

        for future in as_completed(futures):
            try:
                value = future.result()
                results.append(value)
                if live:
                    _print_service_partial(value)
            except Exception as exc:
                item = futures[future]
                warning(
                    f"Falha enumerando serviço em "
                    f"{item['port']}/{item.get('protocol', 'tcp')}: {exc}"
                )

    return sorted(
        results,
        key=lambda item: (item["protocol"], item["port"]),
    )


def print_service_enumeration(results):
    if not results:
        print("Nenhum serviço adicional para enumerar.")
        return

    for item in results:
        profile = item.get("profile") or "Serviço"
        description = " ".join(
            part
            for part in [
                item.get("product") or "",
                item.get("version") or "",
            ]
            if part
        )

        port_text = (
            ",".join(str(port) for port in item.get("ports", []))
            if item.get("ports")
            else str(item.get("port", "-"))
        )

        print()
        print(
            f"{BOLD}{profile} — "
            f"{port_text}/{item.get('protocol', 'tcp')}{RESET}"
        )

        if item.get("service"):
            print(f"  Serviço.................: {item['service']}")

        if description:
            print(f"  Produto / versão........: {description}")

        if item.get("exports"):
            print("  Exports NFS.............:")
            for export in item["exports"]:
                print(f"    - {export}")

        if item.get("users"):
            print(
                "  Usuários RPC............: "
                + ", ".join(item["users"][:20])
            )

        if item.get("share_access"):
            accessible = [entry for entry in item["share_access"] if entry.get("listing_allowed")]
            if accessible:
                print("  Shares acessíveis via -N:")
                for entry in accessible:
                    print(
                        f"    - {entry.get('share')}: listagem permitida "
                        f"({entry.get('recursive_items_count') or len(entry.get('root_items') or [])} item(ns))"
                    )
                    for example in (entry.get("examples") or [])[:8]:
                        print(f"        {example}")

        if item.get("groups"):
            print(
                "  Grupos RPC...............: "
                + ", ".join(item["groups"][:20])
            )

        if item.get("shares"):
            print(
                "  Shares anônimos..........: "
                + ", ".join(item["shares"][:20])
            )

        if item.get("rpc_entries"):
            print("  Programas RPC............:")

            for entry in item["rpc_entries"][:20]:
                print(
                    f"    - {entry.get('service')} "
                    f"{entry.get('protocol')}/{entry.get('port')} "
                    f"(prog {entry.get('program')} v{entry.get('version')})"
                )

        if item.get("anonymous_rpc_allowed"):
            print(
                f"  {GREEN}RPC anônimo aceito; "
                f"vale aprofundar enumeração manual.{RESET}"
            )

        scripts = item.get("scripts") or []

        for script in scripts:
            script_id = script.get("id") or "NSE"
            lines = format_service_script_lines(profile, script)

            print(f"  [{script_id}]")

            for line in lines:
                print(f"    {line}")

        public_exploits = item.get("public_exploits") or []

        if public_exploits:
            print("  Exploits públicos........:")

            for finding in public_exploits[:5]:
                print(f"    - {finding.get('title') or '-'}")

        if item.get("deeper_enum") and not item.get("anonymous_rpc_allowed"):
            print(
                f"  {CYAN}Enumeração adicional aceita/útil; "
                f"há superfície para aprofundar manualmente.{RESET}"
            )


def run_information_gathering(host, target, output_dir):
    """
    Coleta silenciosa, voltada a CTF:
    - reverse DNS para IP;
    - registros DNS para hostname/domínio;
    - tentativa de AXFR somente quando um NS é conhecido.
    """
    result = {
        "reverse_dns": [],
        "dns_records": {},
        "nameservers": [],
        "zone_transfer": {},
        "dns_brute_file": None,
    }

    if not command_exists("dig"):
        return result

    info_dir = output_dir / "information_gathering"
    info_dir.mkdir(parents=True, exist_ok=True)

    if is_ip(host):
        stdout, _, _ = run_command(
            ["dig", "+short", "-x", host],
            activity=None,
        )
        result["reverse_dns"] = [
            line.strip().rstrip(".")
            for line in stdout.splitlines()
            if line.strip()
        ]
    else:
        for record_type in ("A", "AAAA", "MX", "NS", "TXT"):
            stdout, _, _ = run_command(
                ["dig", "+short", host, record_type],
                activity=None,
            )
            values = [
                line.strip()
                for line in stdout.splitlines()
                if line.strip()
            ]
            result["dns_records"][record_type] = values

            if record_type == "NS":
                result["nameservers"] = [
                    value.rstrip(".")
                    for value in values
                ]

        for ns in result["nameservers"][:5]:
            stdout, _, code = run_command(
                ["dig", "AXFR", host, f"@{ns}", "+noall", "+answer"],
                activity=None,
            )

            clean = [
                line.strip()
                for line in stdout.splitlines()
                if line.strip()
                and "Transfer failed" not in line
                and "connection timed out" not in line.lower()
            ]

            if code == 0 and clean:
                result["zone_transfer"][ns] = clean

        if not LOW_NOISE:
            dns_brute_file = info_dir / "dns_brute.txt"

            run_command(
                [
                    "nmap",
                    "-sn",
                    "--script",
                    "dns-brute",
                    "--script-args",
                    f"dns-brute.domain={host}",
                    host,
                    "-oN",
                    dns_brute_file,
                ],
                activity=None,
            )

            if dns_brute_file.exists():
                result["dns_brute_file"] = str(dns_brute_file)

    (info_dir / "information_gathering.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return result


def parse_rpcinfo_output(stdout):
    entries = []

    for raw_line in stdout.splitlines():
        line = raw_line.strip()

        if not line or line.lower().startswith("program"):
            continue

        parts = re.split(r"\s+", line)

        if len(parts) < 5 or not parts[0].isdigit():
            continue

        try:
            entries.append(
                {
                    "program": int(parts[0]),
                    "version": parts[1],
                    "protocol": parts[2],
                    "port": int(parts[3]),
                    "service": parts[4],
                }
            )
        except (ValueError, IndexError):
            continue

    return entries


def run_rpcinfo_enum(host, output_dir):
    result = {"entries": [], "raw": ""}

    if not command_exists("rpcinfo"):
        return result

    service_dir = output_dir / "service_enum"
    service_dir.mkdir(parents=True, exist_ok=True)
    output_file = service_dir / "rpcinfo.txt"

    stdout, _, _ = run_command(
        ["rpcinfo", "-p", host],
        output_file=output_file,
        activity=None,
    )

    result["raw"] = stdout
    result["entries"] = parse_rpcinfo_output(stdout)
    return result


def discover_rpc_ports(rpc_entries, service_names):
    names = {
        value.lower()
        for value in service_names
    }

    return sorted(
        {
            int(item["port"])
            for item in rpc_entries
            if (item.get("service") or "").lower() in names
        }
    )


def run_nfs_deep_enum(host, open_ports, output_dir, rpc_result):
    rpc_entries = (rpc_result or {}).get("entries", [])
    open_numbers = {
        int(item["port"])
        for item in open_ports
    }

    rpc_names = {
        (item.get("service") or "").lower()
        for item in rpc_entries
    }

    should_run = bool(
        2049 in open_numbers
        or {"nfs", "mountd"} & rpc_names
    )

    if not should_run:
        return None

    ports = set()

    if 111 in open_numbers:
        ports.add(111)

    if 2049 in open_numbers:
        ports.add(2049)

    ports.update(
        discover_rpc_ports(
            rpc_entries,
            {"nfs", "mountd"},
        )
    )

    if not ports:
        ports.update({111, 2049})

    service_dir = output_dir / "service_enum"
    service_dir.mkdir(parents=True, exist_ok=True)

    normal_file = service_dir / "nfs_deep.txt"
    xml_file = service_dir / "nfs_deep.xml"

    command = [
        "nmap",
        "-Pn",
        "-n",
        "-sV",
        "-p",
        ",".join(str(port) for port in sorted(ports)),
        "--script",
        "nfs-showmount,nfs-ls,nfs-statfs",
        "--script-timeout",
        "90s",
        host,
        "-T2" if LOW_NOISE else "-T4",
        "-oN",
        normal_file,
        "-oX",
        xml_file,
    ]

    run_command(command, activity=None)

    parsed_ports = (
        parse_nmap_xml(xml_file, display=False)
        if xml_file.exists()
        else []
    )

    scripts = []

    for item in parsed_ports:
        for script in item.get("scripts", []):
            scripts.append(
                {
                    "id": script.get("id") or "NSE",
                    "output": script.get("output") or "",
                    "port": item.get("port"),
                }
            )

    exports = []

    if command_exists("showmount"):
        stdout, _, _ = run_command(
            ["showmount", "-e", host],
            output_file=service_dir / "showmount.txt",
            activity=None,
        )

        for line in stdout.splitlines():
            line = line.strip()

            if line.startswith("/"):
                exports.append(line)

    return {
        "profile": "NFS / mountd",
        "port": min(ports) if ports else 2049,
        "ports": sorted(ports),
        "protocol": "tcp",
        "service": "nfs/mountd",
        "product": "",
        "version": "",
        "scripts": scripts,
        "exports": exports,
        "raw_file": str(normal_file),
        "deeper_enum": bool(scripts or exports),
    }


def run_rpc_anonymous_enum(host, open_ports, output_dir, rpc_result):
    open_numbers = {int(item["port"]) for item in open_ports}
    smb_port = 445 if 445 in open_numbers else 139 if 139 in open_numbers else None
    result = {
        "profile": "RPC / SMB anonymous" if smb_port else "RPC services",
        "port": smb_port or (111 if 111 in open_numbers else 0),
        "protocol": "tcp",
        "service": "rpc/smb" if smb_port else "rpcbind",
        "product": "", "version": "", "scripts": [],
        "users": [], "groups": [], "shares": [], "share_access": [],
        "rpc_entries": list((rpc_result or {}).get("entries", [])),
        "anonymous_rpc_allowed": False, "deeper_enum": False,
    }
    service_dir = output_dir / "service_enum"
    service_dir.mkdir(parents=True, exist_ok=True)

    if {139, 445} & open_numbers and command_exists("rpcclient"):
        stdout, _, code = run_command(
            ["rpcclient", "-U", "", "-N", host, "-c", "querydominfo;enumdomusers;enumdomgroups"],
            output_file=service_dir / "rpcclient_anonymous.txt",
            activity=None,
            timeout=20,
        )
        lower = stdout.lower()
        denied = any(marker in lower for marker in [
            "access_denied", "nt_status_access_denied", "logon failure"
        ])
        result["users"] = sorted(set(re.findall(r"user:\[([^\]]+)\]", stdout, flags=re.I)))
        result["groups"] = sorted(set(re.findall(r"group:\[([^\]]+)\]", stdout, flags=re.I)))
        result["anonymous_rpc_allowed"] = code == 0 and not denied and bool(stdout.strip())

    if {139, 445} & open_numbers and command_exists("smbclient"):
        stdout, _, _ = run_command(
            ["smbclient", "-L", f"//{host}", "-N", "-g"],
            output_file=service_dir / "smbclient_anonymous.txt",
            activity=None,
            timeout=20,
        )
        share_types = {}
        for line in stdout.splitlines():
            parts = line.split("|")
            if len(parts) >= 2 and parts[0] in {"Disk", "IPC", "Printer"}:
                share_types[parts[1]] = parts[0]
        result["shares"] = sorted(share_types)

        for share in result["shares"]:
            if share_types.get(share) != "Disk":
                continue
            safe_share = safe_name(share)
            root_file = service_dir / f"smb_{safe_share}_root.txt"
            recursive_file = service_dir / f"smb_{safe_share}_recursive.txt"
            root_out, root_err, root_code = run_command(
                ["smbclient", f"//{host}/{share}", "-N", "-g", "-c", "ls"],
                output_file=root_file,
                activity=None,
                timeout=15,
            )
            combined = (root_out + "\n" + root_err).lower()
            denied = any(x in combined for x in [
                "nt_status_access_denied", "nt_status_logon_failure", "access denied"
            ])
            allowed = root_code == 0 and not denied
            access = {
                "share": share,
                "listing_allowed": allowed,
                "root_items": [],
                "recursive_items_count": 0,
                "examples": [],
            }
            if allowed:
                root_items = [line.strip() for line in root_out.splitlines() if line.strip()]
                access["root_items"] = root_items[:100]
                rec_out, _, _ = run_command(
                    ["smbclient", f"//{host}/{share}", "-N", "-g", "-c", "recurse;ls"],
                    output_file=recursive_file,
                    activity=None,
                    timeout=25,
                )
                recursive_items = [line.strip() for line in rec_out.splitlines() if line.strip()]
                access["recursive_items_count"] = len(recursive_items)
                access["examples"] = recursive_items[:25] or root_items[:25]
                console_block([
                    f"{GREEN}[+]{RESET} SMB anônimo: //{host}/{share} permite listagem "
                    f"({len(recursive_items) or len(root_items)} item(ns) observado(s), somente leitura)."
                ])
            result["share_access"].append(access)

    result["deeper_enum"] = bool(
        result["anonymous_rpc_allowed"] or result["users"] or result["groups"]
        or result["shares"] or result["share_access"] or (rpc_result or {}).get("entries")
    )
    return result if result["deeper_enum"] else None


def run_snmp_public_enum(host, udp_ports, output_dir):
    if not command_exists("snmpwalk"):
        return None

    if not any(
        item.get("port") == 161
        and item.get("protocol") == "udp"
        for item in udp_ports
    ):
        return None

    service_dir = output_dir / "service_enum"
    service_dir.mkdir(parents=True, exist_ok=True)

    stdout, stderr, code = run_command(
        [
            "snmpwalk",
            "-v2c",
            "-c",
            "public",
            "-t",
            "2",
            "-r",
            "1",
            host,
            "1.3.6.1.2.1.1",
        ],
        output_file=service_dir / "snmp_public_system.txt",
        activity=None,
    )

    combined = (stdout or "") + "\n" + (stderr or "")
    lowered = combined.lower()

    if (
        code != 0
        or not stdout.strip()
        or "timeout" in lowered
        or "no response" in lowered
    ):
        return None

    return {
        "profile": "SNMP public",
        "port": 161,
        "protocol": "udp",
        "service": "snmp",
        "product": "",
        "version": "v2c / community public",
        "scripts": [
            {
                "id": "snmpwalk-system",
                "output": stdout.strip(),
            }
        ],
        "public_exploits": [],
        "deeper_enum": True,
        "raw_file": str(service_dir / "snmp_public_system.txt"),
    }


def search_public_exploits(product, version, output_dir, key):
    if not command_exists("searchsploit"):
        return []

    query = " ".join(
        part
        for part in [product, version]
        if part
    ).strip()

    if not query:
        return []

    vuln_dir = output_dir / "vulnerability_analysis"
    vuln_dir.mkdir(parents=True, exist_ok=True)

    stdout, _, _ = run_command(
        ["searchsploit", "--json", query],
        output_file=vuln_dir / f"{safe_name(key)}.json",
        activity=None,
    )

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []

    findings = []

    for group_name in ("RESULTS_EXPLOIT", "RESULTS_SHELLCODE", "RESULTS_PAPER"):
        for item in data.get(group_name, [])[:10]:
            title = item.get("Title") or item.get("title")
            path = item.get("Path") or item.get("path")

            if title:
                findings.append(
                    {
                        "title": title,
                        "path": path or "",
                        "type": group_name,
                    }
                )

    return findings[:15]


def search_web_public_exploits(service, output_dir):
    findings = []
    seen = set()

    queries = []

    if service.get("server"):
        queries.append(service["server"])

    for tech in service.get("tech") or []:
        if tech:
            queries.append(tech)

    for index, query in enumerate(queries[:6], start=1):
        parts = query.split(None, 1)
        product = parts[0]
        version = parts[1] if len(parts) > 1 else ""

        for finding in search_public_exploits(
            product,
            version,
            output_dir,
            f"web_{service.get('port')}_{index}_{query}",
        ):
            key = (
                finding.get("title"),
                finding.get("path"),
            )

            if key in seen:
                continue

            seen.add(key)
            findings.append(finding)

    return findings[:20]


def summarize_ssh_script(script_id, output):
    lines = [
        line.strip()
        for line in (output or "").splitlines()
        if line.strip()
    ]

    if script_id == "ssh2-enum-algos":
        category_lines = []

        for line in lines:
            lowered = line.lower()

            if any(
                marker in lowered
                for marker in [
                    "kex_algorithms",
                    "server_host_key_algorithms",
                    "encryption_algorithms",
                    "mac_algorithms",
                    "compression_algorithms",
                ]
            ):
                category_lines.append(line)

        return category_lines[:8] or lines[:8]

    if script_id == "ssh-hostkey":
        return lines[:4]

    if script_id == "ssh-auth-methods":
        return lines[:6]

    return lines[:8]


def format_service_script_lines(profile, script):
    script_id = script.get("id") or "NSE"
    output = script.get("output") or ""

    if profile == "SSH":
        lines = summarize_ssh_script(script_id, output)
        omitted = max(
            0,
            len(
                [
                    line
                    for line in output.splitlines()
                    if line.strip()
                ]
            )
            - len(lines),
        )
    else:
        lines = [
            line.rstrip()
            for line in output.splitlines()
            if line.strip()
        ]

        limit = None if profile == "NFS / mountd" else 14

        if limit is not None:
            omitted = max(0, len(lines) - limit)
            lines = lines[:limit]
        else:
            omitted = 0

    if omitted:
        lines.append(f"... {omitted} linha(s) omitida(s)")

    return lines


def normalize_hint_url(service, value):
    value = (value or "").strip().strip("\"'()[]<>.,;")
    if not value:
        return None

    try:
        if value.startswith(("http://", "https://")):
            parsed = urlparse(value)
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            return urljoin(service["url"].rstrip("/") + "/", path)

        if value.startswith("/"):
            return urljoin(service["url"].rstrip("/") + "/", value)
    except Exception:
        return None

    return None


def extract_nmap_web_hints(service, open_ports):
    findings = []
    target_port = service["port"]

    port_data = next(
        (item for item in open_ports if item["port"] == target_port),
        None,
    )

    if not port_data:
        return findings

    for script in port_data.get("scripts", []):
        script_id = (script.get("id") or "").lower()
        output = script.get("output") or ""

        if not script_id.startswith("http"):
            continue

        values = set()

        # Absolute URLs, including:
        # Requested resource was http://host/band/
        for match in re.findall(r"https?://[^\s<>'\"]+", output, flags=re.I):
            values.add(match.rstrip(").,;]"))

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            # robots.txt / sitemap style directives.
            directive = re.search(
                r"(?:Disallow|Allow|Sitemap)\s*:\s*(\S+)",
                line,
                flags=re.I,
            )
            if directive:
                values.add(directive.group(1))

            # http-enum and similar NSE scripts often put the path at
            # the beginning of the line.
            if line.startswith("/"):
                values.add(line.split()[0].rstrip(":,;"))

            # Explicit Nmap wording.
            requested = re.search(
                r"Requested resource was\s+(\S+)",
                line,
                flags=re.I,
            )
            if requested:
                values.add(requested.group(1))

        for value in values:
            normalized = normalize_hint_url(service, value)
            if normalized:
                findings.append(
                    {
                        "source": f"Nmap/{script.get('id') or 'http-nse'}",
                        "url": normalized,
                    }
                )

    unique = {}
    for item in findings:
        unique[(item["source"], item["url"])] = item

    return sorted(
        unique.values(),
        key=lambda item: (item["url"], item["source"]),
    )


def discover_robots_and_sitemap(service, cookie=None):
    findings = []
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": (
                "Googlebot/2.1 (+http://www.google.com/bot.html)"
            )
        }
    )

    if cookie:
        session.headers["Cookie"] = cookie

    robots_url = service["url"].rstrip("/") + "/robots.txt"
    sitemap_url = service["url"].rstrip("/") + "/sitemap.xml"

    try:
        response = session.get(
            robots_url,
            timeout=6,
            verify=False,
            allow_redirects=True,
        )
        if response.status_code < 400:
            findings.append({"source": "robots.txt", "url": robots_url})

            for raw_line in response.text.splitlines():
                line = raw_line.strip()
                match = re.match(
                    r"(?:Allow|Disallow|Sitemap)\s*:\s*(\S+)",
                    line,
                    flags=re.I,
                )
                if not match:
                    continue

                value = match.group(1).strip()
                if not value or value == "-":
                    continue

                normalized = normalize_hint_url(service, value)
                if normalized:
                    findings.append(
                        {"source": "robots.txt", "url": normalized}
                    )
    except requests.RequestException:
        pass

    try:
        response = session.get(
            sitemap_url,
            timeout=6,
            verify=False,
            allow_redirects=True,
        )
        if response.status_code < 400:
            findings.append({"source": "sitemap.xml", "url": sitemap_url})

            locs = re.findall(
                r"<loc>\s*(.*?)\s*</loc>",
                response.text,
                flags=re.I | re.S,
            )

            for value in locs[:200]:
                normalized = normalize_hint_url(service, html.unescape(value))
                if normalized:
                    findings.append(
                        {"source": "sitemap.xml", "url": normalized}
                    )
    except requests.RequestException:
        pass

    unique = {}
    for item in findings:
        unique[(item["source"], item["url"])] = item

    return sorted(
        unique.values(),
        key=lambda item: (item["url"], item["source"]),
    )


def canonicalize_seed_url(url):
    try:
        parsed = urlparse(str(url).strip())
        if not parsed.scheme or not parsed.netloc:
            return str(url).strip()
        path = re.sub(r"/{2,}", "/", parsed.path or "/")
        return parsed._replace(path=path, fragment="").geturl()
    except Exception:
        return str(url).strip()


def build_service_seed_evidence(service, open_ports, cookie=None):
    evidence = []
    evidence.extend(extract_nmap_web_hints(service, open_ports))
    evidence.extend(discover_robots_and_sitemap(service, cookie=cookie))
    evidence.append({"source": "Base", "url": canonicalize_seed_url(service["url"])})

    by_url = {}
    for item in evidence:
        url = canonicalize_seed_url(item["url"])
        if not same_service(url, service["url"]):
            continue
        if url not in by_url:
            by_url[url] = {"url": url, "sources": set()}
        by_url[url]["sources"].add(item["source"])

    result = []
    for url, item in by_url.items():
        result.append({"url": url, "source": ", ".join(sorted(item["sources"]))})
    return sorted(result, key=lambda item: item["url"])


def print_seed_evidence(service_url, evidence):
    useful = [
        item for item in evidence
        if item["url"].rstrip("/") != service_url.rstrip("/")
    ]

    if not useful:
        return

    lines = [
        "",
        f"{BOLD}Caminhos aproveitados automaticamente - {service_url}{RESET}",
    ]

    for item in useful:
        lines.append(f"  - [{item['source']}] {item['url']}")

    console_block(lines)


def is_apache_autoindex_query(query):
    query = (query or "").strip()
    if not query:
        return False

    # Apache mod_autoindex sorting links, e.g. ?C=N;O=D
    return bool(
        re.fullmatch(
            r"(?:C=[NMSD][;&]O=[AD]|O=[AD][;&]C=[NMSD])",
            query,
            flags=re.I,
        )
    )


def is_noise_url(url):
    try:
        return is_apache_autoindex_query(urlparse(url).query)
    except Exception:
        return False


def clean_url_collection(values):
    return sorted(
        {
            value
            for value in values
            if value and not is_noise_url(value)
        }
    )


def ffuf_bases_from_seeds(service, seed_urls, max_bases=12):
    root = canonicalize_seed_url(service["url"])
    parsed_root = urlparse(root)
    root_path = parsed_root.path or "/"
    if not root_path.endswith("/"):
        root_path = root_path.rsplit("/", 1)[0] + "/"
    root_base = f"{parsed_root.scheme}://{parsed_root.netloc}{root_path}"

    bases = {root_base}
    for seed in seed_urls or []:
        seed = canonicalize_seed_url(seed)
        if not same_service(seed, service["url"]):
            continue
        parsed = urlparse(seed)
        path = parsed.path or "/"
        if path.endswith("/"):
            directory = path
        else:
            directory = path.rsplit("/", 1)[0] + "/" if "/" in path else "/"
        bases.add(f"{parsed.scheme}://{parsed.netloc}{directory}")

    ordered = [root_base] + sorted(base for base in bases if base != root_base)
    return ordered[:max(1, int(max_bases))]


def _ffuf_base_covered(base_url, results):
    # Só considera um seed coberto quando o FFUF pai realmente encontrou algo
    # abaixo dele. Encontrar apenas o diretório (301/403/etc.) não basta, pois
    # uma execução explícita naquele caminho ainda pode revelar conteúdo.
    base = canonicalize_seed_url(base_url).rstrip("/")
    prefix = base + "/"
    for item in results or []:
        url = canonicalize_seed_url(item.get("url") or "")
        if url.startswith(prefix):
            return True
    return False


# ============================================================
# Web service discovery with httpx
# ============================================================

def probe_web_services(host, open_ports, output_dir, cookie=None):
    section("2. IDENTIFICAÇÃO DAS PORTAS WEB")

    targets_file = output_dir / "open_ports_targets.txt"
    httpx_file = output_dir / "httpx_web.jsonl"

    targets = [f"{host}:{item['port']}" for item in open_ports]
    write_lines(targets_file, targets)

    if not targets:
        return []

    command = [
        tool_command("httpx"),
        "-l",
        targets_file,
        "-silent",
        "-json",
        "-status-code",
        "-title",
        "-tech-detect",
        "-server",
        "-content-length",
        "-location",
        "-no-color",
    ]

    if cookie:
        command.extend(["-H", f"Cookie: {cookie}"])

    stdout, _, _ = run_command(
        command,
        httpx_file,
        activity=(
            "Executando HTTPX — identificando serviços Web, "
            "status, títulos e tecnologias..."
        ),
    )
    redact_file_secret(httpx_file, cookie)

    services = []

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        url = (
            data.get("url")
            or data.get("final_url")
            or data.get("input")
        )

        if not url or not str(url).startswith(("http://", "https://")):
            continue

        tech = data.get("tech") or data.get("technologies") or []
        if isinstance(tech, str):
            tech = [tech]

        parsed = urlparse(url)

        services.append(
            {
                "url": url.rstrip("/"),
                "scheme": parsed.scheme,
                "host": parsed.hostname or host,
                "port": parsed.port or (443 if parsed.scheme == "https" else 80),
                "status": data.get("status_code"),
                "title": data.get("title") or "",
                "server": data.get("webserver") or data.get("server") or "",
                "tech": tech,
                "content_length": data.get("content_length"),
                "location": data.get("location") or "",
            }
        )

    # Deduplicate by effective URL.
    unique = {}
    for item in services:
        unique[item["url"]] = item

    services = sorted(unique.values(), key=lambda x: (x["port"], x["scheme"]))

    if not services:
        warning("O httpx não confirmou serviços Web nas portas abertas.")
        return []

    print()
    print(f"{BOLD}{'PORTA':<8}{'STATUS':<9}{'URL':<42}{'TÍTULO'}{RESET}")
    print("-" * 100)

    for item in services:
        print(
            f"{item['port']:<8}"
            f"{str(item['status'] or '-'):<9}"
            f"{item['url'][:40]:<42}"
            f"{item['title'][:45]}"
        )

    print()
    success(f"{len(services)} serviço(s) Web identificado(s).")
    return services


# ============================================================
# Katana
# ============================================================

def run_katana(service, service_dir, depth, cookie=None, seed_urls=None, progress_callback=None):
    katana_started = metric_start("katana", service=service["url"], depth=depth)
    output_file = service_dir / "katana.jsonl"
    seeds_file = service_dir / "katana_seeds.txt"

    seeds = {
        canonicalize_seed_url(url)
        for url in ([service["url"]] + list(seed_urls or []))
        if same_service(url, service["url"]) and not is_noise_url(url)
    }
    seeds = sorted(seeds)[:25]
    write_lines(seeds_file, seeds)

    info(
        f"Executando Katana em {service['url']} - coletando links, endpoints, "
        f"JavaScript e formulários a partir de {len(seeds)} semente(s)..."
    )

    command = [
        "katana", "-list", str(seeds_file), "-d", str(depth),
        "-jc", "-kf", "all", "-fx", "-jsonl", "-silent", "-nc",
    ]
    if cookie:
        command.extend(["-H", f"Cookie: {cookie}"])

    def _katana_progress():
        drain_ffuf_partial_blocks()
        if progress_callback:
            progress_callback()

    stdout, _, _ = run_command(
        command,
        activity=None,
        heartbeat=_katana_progress,
        heartbeat_interval=0.8,
    )
    output_file.write_text(stdout or "", encoding="utf-8")
    redact_file_secret(output_file, cookie)

    urls = set(seeds)
    forms = []

    def add_url(candidate):
        if (
            candidate
            and str(candidate).startswith(("http://", "https://"))
            and same_service(str(candidate), service["url"])
            and not is_noise_url(str(candidate))
        ):
            urls.add(str(candidate))

    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            add_url(line)
            continue
        for key in ("request", "response"):
            obj = data.get(key)
            if isinstance(obj, dict):
                add_url(obj.get("endpoint") or obj.get("url"))
        for key in ("url", "endpoint"):
            add_url(data.get(key))
        form = data.get("form")
        if form:
            forms.append(form)

    urls = clean_url_collection(urls)
    write_lines(service_dir / "katana_urls.txt", urls)
    success(f"Katana: {len(urls)} URL(s) coletada(s).")
    metric_end("katana", katana_started, urls=len(urls), forms=len(forms))
    return urls, forms


# ============================================================
# ffuf content discovery
# ============================================================

def normalize_extensions(value):
    """
    Aceita:
      php,html,txt
      .php,.html,.txt
      php html txt

    Retorna:
      .php,.html,.txt

    Use "-" ou valor vazio para não adicionar extensões.
    """
    if value is None:
        return ".php,.html,.txt"

    value = value.strip()

    if not value or value == "-":
        return ""

    parts = re.split(r"[\s,;]+", value)
    normalized = []

    for part in parts:
        part = part.strip()

        if not part:
            continue

        if not part.startswith("."):
            part = "." + part

        if part not in normalized:
            normalized.append(part)

    return ",".join(normalized)


def status_color(status):
    try:
        status = int(status)
    except Exception:
        return RESET

    if 200 <= status < 300:
        return GREEN
    if 300 <= status < 400:
        return YELLOW
    if 400 <= status < 500:
        return CYAN
    if status >= 500:
        return RED
    return RESET


def print_ffuf_live(service_url, item, label="FFUF"):
    status = item.get("status", "-")
    url = item.get("url") or "-"
    length = item.get("length", "-")
    color = status_color(status)

    console_block(
        [
            f"{CYAN}[{label}]{RESET} "
            f"{color}[{status}]{RESET} "
            f"{url}  {BLUE}len={length}{RESET}"
        ]
    )


def queue_ffuf_partial(service_url, item, label="FFUF"):
    key = (service_url, label)

    with FFUF_PARTIAL_LOCK:
        FFUF_PARTIAL_RESULTS[key].append(item)


def drain_ffuf_partial_blocks(block_size=30):
    snapshots = []

    with FFUF_PARTIAL_LOCK:
        for key in list(FFUF_PARTIAL_RESULTS.keys()):
            items = FFUF_PARTIAL_RESULTS.get(key) or []

            if not items:
                continue

            snapshots.append((key, list(items)))
            FFUF_PARTIAL_RESULTS[key].clear()

    total = 0

    for (service_url, label), items in snapshots:
        total += len(items)

        for offset in range(0, len(items), block_size):
            chunk = items[offset:offset + block_size]

            lines = [
                "",
                f"{BOLD}{label} — resultados parciais — {service_url}{RESET}",
            ]

            for item in chunk:
                status = item.get("status", "-")
                url = item.get("url") or "-"
                length = item.get("length", "-")
                redirect = item.get("redirectlocation") or ""

                display_url = url

                try:
                    service_parsed = urlparse(service_url)
                    item_parsed = urlparse(url)

                    if (
                        service_parsed.scheme == item_parsed.scheme
                        and service_parsed.netloc == item_parsed.netloc
                    ):
                        display_url = item_parsed.path or "/"

                        if item_parsed.query:
                            display_url += "?" + item_parsed.query
                except Exception:
                    pass

                line = f"  [{status}] {display_url}  (len: {length})"

                if redirect:
                    display_redirect = redirect

                    try:
                        redirect_parsed = urlparse(redirect)

                        if (
                            service_parsed.scheme == redirect_parsed.scheme
                            and service_parsed.netloc == redirect_parsed.netloc
                        ):
                            display_redirect = redirect_parsed.path or "/"

                            if redirect_parsed.query:
                                display_redirect += "?" + redirect_parsed.query
                    except Exception:
                        pass

                    line += f" -> {display_redirect}"

                lines.append(line)

            console_block(lines)

    return total


def print_ffuf_finished(service_url, results, label="FFUF"):
    console_block(
        [
            "",
            f"{BOLD}{label} — {service_url}{RESET}",
            f"  Finalizado: {len(results)} resultado(s) consolidado(s).",
        ]
    )



def _ffuf_extension_suffixes(extensions):
    suffixes = [""]
    for value in str(extensions or "").split(","):
        value = value.strip()
        if not value:
            continue
        if not value.startswith("."):
            value = "." + value
        if value not in suffixes:
            suffixes.append(value)
    return suffixes


def _ffuf_redirect_is_path_preserving_upgrade(request_url, location):
    if not location:
        return False
    try:
        source = urlparse(request_url)
        target = urlparse(urljoin(request_url, location))
    except Exception:
        return False

    source_path = re.sub(r"/{2,}", "/", source.path or "/")
    target_path = re.sub(r"/{2,}", "/", target.path or "/")
    return (
        source.scheme == "http"
        and target.scheme == "https"
        and (source.hostname or "").lower() == (target.hostname or "").lower()
        and source_path.rstrip("/") == target_path.rstrip("/")
        and (source.query or "") == (target.query or "")
    )


def _ffuf_baseline_profile(base_url, extensions, cookie=None):
    """Cria uma baseline conservadora com canários inexistentes antes do FFUF."""
    suffixes = _ffuf_extension_suffixes(extensions)
    session = requests.Session()
    session.headers.update({
        "User-Agent": f"L1ght-Recon/{VERSION} ffuf-calibration",
        "Cache-Control": "no-cache",
    })
    if cookie:
        session.headers["Cookie"] = cookie

    signatures = {}
    probes_total = 0
    alias_probes = 0

    for suffix in suffixes:
        samples = []
        for index in range(2):
            material = (
                f"{base_url}|{suffix}|{index}|{time.monotonic_ns()}"
            ).encode()
            token = "l1ght-" + hashlib.sha256(material).hexdigest()[:20]
            request_url = base_url.rstrip("/") + "/" + token + suffix
            try:
                response = session.get(
                    request_url,
                    timeout=6,
                    verify=False,
                    allow_redirects=False,
                )
            except requests.RequestException:
                continue

            body = response.text or ""
            location = response.headers.get("Location") or ""
            sample = {
                "status": int(response.status_code),
                "length": len(response.content or b""),
                "words": len(re.findall(r"\\S+", body)),
                "lines": len(body.splitlines()),
                "location": location,
                "upgrade_preserve": _ffuf_redirect_is_path_preserving_upgrade(
                    request_url, location
                ),
            }
            samples.append(sample)
            probes_total += 1
            if sample["upgrade_preserve"] and 300 <= sample["status"] < 400:
                alias_probes += 1

        if len(samples) < 2:
            continue

        comparable = (
            samples[0]["status"],
            samples[0]["length"],
            samples[0]["words"],
            samples[0]["lines"],
            bool(samples[0]["location"]),
        )
        if all(
            (
                item["status"],
                item["length"],
                item["words"],
                item["lines"],
                bool(item["location"]),
            ) == comparable
            for item in samples[1:]
        ):
            signatures[suffix] = {
                "status": samples[0]["status"],
                "length": samples[0]["length"],
                "words": samples[0]["words"],
                "lines": samples[0]["lines"],
                "has_location": bool(samples[0]["location"]),
            }

    redirect_alias = (
        probes_total >= max(2, len(suffixes) * 2)
        and alias_probes == probes_total
    )

    return {
        "base_url": base_url,
        "suffixes": suffixes,
        "signatures": signatures,
        "redirect_alias": redirect_alias,
        "probes": probes_total,
        "rejected": 0,
    }


def _ffuf_item_matches_baseline(item, profile):
    if not isinstance(item, dict) or not profile:
        return False

    try:
        status = int(item.get("status") or 0)
    except Exception:
        status = 0

    if status in {401, 403, 407, 429} or status >= 500:
        return False

    item_url = str(item.get("url") or "")
    redirect = str(item.get("redirectlocation") or "")

    if (
        profile.get("redirect_alias")
        and 300 <= status < 400
        and _ffuf_redirect_is_path_preserving_upgrade(item_url, redirect)
    ):
        return True

    suffix = ""
    try:
        path = urlparse(item_url).path.lower()
    except Exception:
        path = item_url.lower()

    for candidate in sorted(
        (value for value in profile.get("suffixes", []) if value),
        key=len,
        reverse=True,
    ):
        if path.endswith(candidate.lower()):
            suffix = candidate
            break

    signature = (profile.get("signatures") or {}).get(suffix)
    if not signature:
        return False
    if not (200 <= status < 400):
        return False
    if status != int(signature.get("status") or -1):
        return False

    try:
        if int(item.get("length")) != int(signature.get("length")):
            return False
    except Exception:
        return False

    for key in ("words", "lines"):
        if item.get(key) is not None and signature.get(key) is not None:
            try:
                if int(item.get(key)) != int(signature.get(key)):
                    return False
            except Exception:
                return False

    if signature.get("has_location"):
        return bool(redirect)
    return not bool(redirect)


def _load_ffuf_result_file(path):
    path = Path(path)

    if not path.exists():
        return []

    try:
        data = json.loads(
            path.read_text(encoding="utf-8", errors="ignore")
        )
    except Exception:
        return []

    if isinstance(data, dict):
        results = data.get("results", [])
        return results if isinstance(results, list) else []

    if isinstance(data, list):
        return data

    return []


def _run_ffuf_json_stream(
    command,
    service_url,
    label="FFUF",
    result_file=None,
    raw_log_file=None,
    result_filter=None,
):
    results = []
    seen = set()
    raw_lines = []
    non_json_lines = []
    started_at = time.monotonic()

    safe_command = _redact_debug_text(" ".join(str(value) for value in command))
    _debug_log("COMMAND_START", safe_command)
    process = subprocess.Popen(
        [str(value) for value in command],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    def add_item(item, queue=True):
        if not isinstance(item, dict):
            return

        key = (
            item.get("url"),
            item.get("status"),
            item.get("length"),
            json.dumps(item.get("input") or {}, sort_keys=True),
        )

        if key in seen:
            return

        seen.add(key)

        if result_filter is not None:
            try:
                if not result_filter(item):
                    return
            except Exception as exc:
                _debug_log("FFUF_FILTER_ERROR", f"{exc!r}")

        results.append(item)

        if queue:
            queue_ffuf_partial(service_url, item, label=label)

    if process.stdout is not None:
        for raw_line in process.stdout:
            raw_lines.append(raw_line)
            line = raw_line.strip()

            if not line:
                continue

            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                non_json_lines.append(line)
                continue

            add_item(item, queue=True)

    return_code = process.wait()
    elapsed = time.monotonic() - started_at
    _debug_log(
        "COMMAND_END",
        f"rc={return_code} duration={elapsed:.3f}s cmd={safe_command}",
    )
    if raw_lines:
        _debug_log("STDOUT", "".join(raw_lines))

    if raw_log_file:
        try:
            Path(raw_log_file).write_text(
                "".join(raw_lines),
                encoding="utf-8",
            )
        except Exception:
            pass

    if result_file:
        for item in _load_ffuf_result_file(result_file):
            # Algumas versões/combinações do ffuf não entregam os matches
            # em NDJSON no stdout quando -o/-of também são usados. Nesses
            # casos os achados só aparecem no arquivo JSON final. Enfileirar
            # aqui garante que eles também sejam mostrados em blocos na tela.
            add_item(item, queue=True)

    if (
        COMMAND_TIMEOUT
        and COMMAND_TIMEOUT > 0
        and elapsed >= max(1, COMMAND_TIMEOUT - 1)
    ):
        warning(
            f"{label} em {service_url} atingiu aproximadamente "
            f"{COMMAND_TIMEOUT}s; resultados parciais foram preservados."
        )
        _register_timeout(
            command,
            activity=f"{label} em {service_url}",
            timeout=COMMAND_TIMEOUT,
        )

    elif return_code not in (0, 1):
        detail = non_json_lines[-1] if non_json_lines else ""
        suffix = f" Última mensagem: {detail}" if detail else ""
        warning(
            f"{label} em {service_url} finalizou com código "
            f"{return_code}.{suffix}"
        )

    return results


def run_ffuf_content(
    service,
    service_dir,
    wordlist,
    extensions,
    ffuf_depth,
    cookie=None,
    seed_urls=None,
    announce=True,
    full_mode=False,
):
    aggregate_file = service_dir / "ffuf_content.json"
    filter_file = service_dir / "ffuf_filter_summary.json"

    if not Path(wordlist).exists():
        warning(f"Wordlist de conteúdo não encontrada: {wordlist}")
        return []

    max_bases = 24 if full_mode else 12
    fuzz_bases = ffuf_bases_from_seeds(
        service, seed_urls or [service["url"]], max_bases=max_bases
    )
    started = metric_start(
        "ffuf_content", service=service["url"], bases=len(fuzz_bases),
        depth=ffuf_depth, full=bool(full_mode),
    )

    if announce:
        info(
            f"Executando FFUF em {service['url']} - "
            f"validando wildcard/soft-404 e enumerando diretamente até "
            f"{len(fuzz_bases)} caminho(s), profundidade {ffuf_depth}..."
        )

    baseline_cache = {}
    attempted_bases = set()

    def get_baseline(base_url):
        profile = baseline_cache.get(base_url)
        if profile is None:
            profile = _ffuf_baseline_profile(base_url, extensions, cookie=cookie)
            baseline_cache[base_url] = profile
            _debug_log(
                "FFUF_BASELINE",
                f"base={base_url} probes={profile.get('probes', 0)} "
                f"signatures={len(profile.get('signatures') or {})} "
                f"redirect_alias={bool(profile.get('redirect_alias'))}",
            )
        return profile

    def execute_base(base_url, index, auto_calibrate=True, suffix=""):
        profile = get_baseline(base_url)

        if profile.get("redirect_alias"):
            _debug_log(
                "FFUF_SKIP_REDIRECT_ALIAS",
                f"base={base_url} reason=path-preserving-http-to-https",
            )
            if announce and not profile.get("_announced_alias"):
                info(
                    f"FFUF: {base_url} funciona como redirecionador canônico "
                    "HTTP→HTTPS; fuzzing duplicado dessa base foi omitido."
                )
                profile["_announced_alias"] = True
            return []

        attempted_bases.add(base_url)
        fuzz_url = base_url.rstrip("/") + "/FUZZ"
        result_file = service_dir / f"ffuf_run_{index:02d}{suffix}.json"
        raw_log_file = service_dir / f"ffuf_run_{index:02d}{suffix}.stdout.log"

        command = [
            "ffuf", "-w", f"{wordlist}:FUZZ", "-u", fuzz_url,
            "-recursion", "-recursion-depth", str(ffuf_depth),
        ]
        if extensions:
            command.extend(["-e", extensions])
        if cookie:
            command.extend(["-b", cookie])
        if COMMAND_TIMEOUT and COMMAND_TIMEOUT > 0:
            command.extend(["-maxtime", str(COMMAND_TIMEOUT)])
        if LOW_NOISE:
            command.extend(["-rate", "20"])
        command.extend(["-ic", "-fs", "0"])
        if auto_calibrate:
            command.append("-ac")
        command.extend([
            "-mc", "all", "-fc", "404", "-noninteractive", "-json",
            "-of", "json", "-o", str(result_file),
        ])

        def keep_item(item):
            if _ffuf_item_matches_baseline(item, profile):
                profile["rejected"] = int(profile.get("rejected") or 0) + 1
                return False
            return True

        return _run_ffuf_json_stream(
            command,
            service["url"],
            label="FFUF",
            result_file=result_file,
            raw_log_file=raw_log_file,
            result_filter=keep_item,
        )

    def seed_complete_pass(auto_calibrate=True, suffix=""):
        combined = []
        for index, base_url in enumerate(fuzz_bases, start=1):
            try:
                combined.extend(
                    execute_base(base_url, index, auto_calibrate, suffix)
                )
            except Exception as exc:
                warning(f"FFUF falhou no caminho {base_url}: {exc}")
                _debug_log(
                    "FFUF_EXCEPTION",
                    f"base={base_url} index={index} exc={exc!r}",
                )
        _debug_log(
            "FFUF_SEED_PASS",
            f"service={service['url']} bases={len(fuzz_bases)} "
            f"attempted={len(attempted_bases)}",
        )
        return combined

    combined = seed_complete_pass(auto_calibrate=True, suffix="")

    if not combined and attempted_bases:
        warning(
            f"FFUF em {service['url']} não retornou achados após os filtros "
            "conservadores; validando novamente sem -ac..."
        )
        combined.extend(seed_complete_pass(auto_calibrate=False, suffix="_fallback"))

    unique = {}
    for item in combined:
        key = (item.get("url"), item.get("status"), item.get("length"))
        unique[key] = item

    results = sorted(
        unique.values(),
        key=lambda item: (
            str(item.get("url", "")),
            int(item.get("status", 0) or 0),
        ),
    )

    filter_summary = []
    for base_url, profile in baseline_cache.items():
        filter_summary.append({
            "base_url": base_url,
            "probes": profile.get("probes", 0),
            "redirect_alias": bool(profile.get("redirect_alias")),
            "rejected": int(profile.get("rejected") or 0),
            "signatures": profile.get("signatures") or {},
        })

    aggregate_file.write_text(
        json.dumps(
            {"results": results, "filtering": filter_summary},
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    filter_file.write_text(
        json.dumps(filter_summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    redact_file_secret(aggregate_file, cookie)
    redact_file_secret(filter_file, cookie)

    rejected_total = sum(int(item.get("rejected") or 0) for item in filter_summary)
    alias_total = sum(1 for item in filter_summary if item.get("redirect_alias"))

    metric_end(
        "ffuf_content",
        started,
        results=len(results),
        rejected=rejected_total,
        redirect_alias_bases=alias_total,
    )

    if announce:
        if results:
            message = (
                f"FFUF {service['url']}: {len(results)} "
                "diretório(s)/arquivo(s) validado(s)."
            )
            if rejected_total or alias_total:
                message += (
                    f" Filtro: {rejected_total} resposta(s) wildcard/soft-404 "
                    f"descartada(s), {alias_total} base(s) de redirecionamento omitida(s)."
                )
            success(message)
        elif alias_total and not attempted_bases:
            success(
                f"FFUF {service['url']}: serviço identificado como "
                "redirecionador canônico; enumeração de conteúdo duplicada omitida."
            )
        else:
            warning(
                f"FFUF {service['url']}: 0 resultado(s) após validação. "
                "Os JSON/logs brutos continuam preservados nos artefatos."
            )

    return results


def run_ffuf_vhosts(
    service,
    service_dir,
    wordlist,
    vhost_domain,
    cookie=None,
    announce=True,
):
    result_file = service_dir / "ffuf_vhosts.json"

    if not vhost_domain:
        return []

    if not Path(wordlist).exists():
        warning(f"Wordlist de vhost não encontrada: {wordlist}")
        return []

    command = [
        "ffuf",
        "-w",
        f"{wordlist}:FUZZ",
        "-u",
        service["url"] + "/",
        "-H",
        f"Host: FUZZ.{vhost_domain}",
        "-ach",
        "-mc",
        "all",
        "-fc",
        "404",
        "-fs",
        "0",
        "-noninteractive",
        "-s",
        "-json",
    ]

    if COMMAND_TIMEOUT and COMMAND_TIMEOUT > 0:
        command.extend(["-maxtime", str(COMMAND_TIMEOUT)])

    if LOW_NOISE:
        command.extend(["-rate", "20"])

    if cookie:
        command.extend(["-b", cookie])

    if announce:
        info(
            f"Executando FFUF VHosts em {service['url']} - "
            f"buscando hosts virtuais de {vhost_domain}..."
        )

    results = _run_ffuf_json_stream(
        command,
        service["url"],
        label=f"FFUF-VHOST:{service['port']}",
    )

    for item in results:
        fuzz_value = (item.get("input") or {}).get("FUZZ")
        if fuzz_value:
            item["vhost"] = f"{fuzz_value}.{vhost_domain}"

    result_file.write_text(
        json.dumps(
            {"results": results},
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    redact_file_secret(result_file, cookie)

    if announce:
        success(f"FFUF vhost: {len(results)} resultado(s).")

    return results


def parse_ffuf_json(path):
    path = Path(path)
    if not path.exists():
        return []

    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return []

    results = data.get("results", [])
    return results if isinstance(results, list) else []



def _valid_http_url(url):
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _parameter_names_from_query(query):
    query = (query or "").strip()
    if not query or "=" not in query:
        return []

    names = []
    for name, _ in parse_qsl(query, keep_blank_values=True):
        name = (name or "").strip()
        if not name:
            continue
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", name):
            continue
        names.append(name)

    return list(dict.fromkeys(names))


def _katana_noise_url(url):
    lowered = (url or "").lower()

    noise_tokens = (
        "%27", "%22", "settings.image", "getattribute%28",
        "+libraryname+", "'+libraryname+", "%5c%22",
        "javascript:", "\\.js",
    )

    return any(token in lowered for token in noise_tokens)


def _katana_route_signature(url):
    try:
        parsed = urlparse(url)
    except Exception:
        return None

    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None

    path = parsed.path or "/"
    params = _parameter_names_from_query(parsed.query)

    if params:
        return path + "?" + "&".join(f"{name}={{...}}" for name in sorted(params))

    return path


def summarize_katana_urls(service_url, urls):
    signatures = Counter()
    examples = {}
    raw_http = 0
    noise = 0

    assets = Counter()
    route_without_query = Counter()

    for url in urls or []:
        if not _valid_http_url(url):
            noise += 1
            continue

        raw_http += 1

        if _katana_noise_url(url):
            noise += 1
            continue

        sig = _katana_route_signature(url)
        if not sig:
            noise += 1
            continue

        signatures[sig] += 1
        examples.setdefault(sig, url)

        path = urlparse(url).path.lower()
        suffix = Path(path).suffix.lower()

        if suffix in {".js", ".mjs", ".cjs"}:
            assets["JavaScript"] += 1
        elif suffix == ".css":
            assets["CSS"] += 1
        elif suffix in {".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico"}:
            assets["Imagens"] += 1
        elif suffix in {".woff", ".woff2", ".ttf", ".eot"}:
            assets["Fontes"] += 1
        elif suffix and suffix not in {".php", ".asp", ".aspx", ".jsp", ".html", ".htm"}:
            assets["Outros assets"] += 1

        if "?" not in sig and suffix not in {
            ".js", ".mjs", ".cjs", ".css", ".png", ".jpg", ".jpeg",
            ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".eot"
        }:
            route_without_query[sig] += 1

    patterns = [
        {
            "signature": sig,
            "count": count,
            "example": examples.get(sig, ""),
        }
        for sig, count in signatures.most_common()
    ]

    return {
        "raw": len(urls or []),
        "http": raw_http,
        "noise": noise,
        "unique_patterns": len(signatures),
        "patterns": patterns,
        "assets": dict(assets),
        "routes": [item for item, _ in route_without_query.most_common()],
    }


def print_katana_results(service_url, urls):
    summary = summarize_katana_urls(service_url, urls)

    lines = [
        "",
        f"{BOLD}Katana - {service_url}{RESET}",
        f"  URLs coletadas.........: {summary['raw']}",
        f"  Padrões únicos.........: {summary['unique_patterns']}",
    ]

    if summary["assets"]:
        lines.append(
            "  Assets.................: "
            + ", ".join(
                f"{name}={count}"
                for name, count in sorted(summary["assets"].items())
            )
        )

    if summary["noise"]:
        lines.append(f"  Ruído/artefatos ocultos: {summary['noise']}")

    patterns = summary["patterns"]

    if not patterns:
        lines.append("  Nenhum padrão útil de URL identificado.")
    else:
        lines.append("")
        lines.append("  Padrões principais:")

        for item in patterns[:25]:
            prefix = f"{item['count']}x" if item["count"] > 1 else "1x"
            lines.append(f"    {prefix:<6} {item['signature']}")

        if len(patterns) > 25:
            lines.append(
                f"    ... +{len(patterns) - 25} padrão(ões) no relatório/artefatos"
            )

    lines.extend([
        "",
        "  [i] A lista bruta completa continua salva em katana_urls.txt.",
    ])

    console_block(lines)

def print_ffuf_results(service_url, results):
    lines = ["", f"{BOLD}FFUF - {service_url}{RESET}"]

    if not results:
        lines.append("  Nenhum diretório ou arquivo encontrado.")
    else:
        for item in results:
            status = item.get("status", "-")
            length = item.get("length", "-")
            url = item.get("url", "-")
            redirect = item.get("redirectlocation") or ""

            line = f"  [{status}] {url}  (length: {length})"
            if redirect:
                line += f" -> {redirect}"
            lines.append(line)

    console_block(lines)


def print_vhost_results(service_url, results):
    lines = ["", f"{BOLD}FFUF VHosts - {service_url}{RESET}"]

    if not results:
        lines.append("  Nenhum virtual host encontrado.")
    else:
        for item in results:
            vhost = item.get("vhost") or "-"
            status = item.get("status", "-")
            length = item.get("length", "-")
            lines.append(f"  [{status}] {vhost}  (length: {length})")

    console_block(lines)


def _tail_new_lines(path, state):
    path = Path(path)
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            handle.seek(state.get("offset", 0))
            lines = handle.readlines()
            state["offset"] = handle.tell()
        return lines
    except Exception:
        return []


def make_nikto_heartbeat(output_file, service_url):
    state = {"offset": 0}
    def heartbeat():
        new = []
        for raw in _tail_new_lines(output_file, state):
            line = raw.strip()
            if not line.startswith("+"):
                continue
            cleaned = line.lstrip("+ ").strip()
            lowered = cleaned.lower()
            if any(marker in lowered for marker in [
                "target ip", "target hostname", "target port", "start time",
                "end time", "host(s) tested",
            ]):
                continue
            if cleaned in NIKTO_PARTIAL_SEEN[service_url]:
                continue
            NIKTO_PARTIAL_SEEN[service_url].add(cleaned)
            new.append(cleaned)
        if new:
            console_block(["", f"{BOLD}Nikto — parcial — {service_url}{RESET}"] + [f"  - {line}" for line in new[:20]])
    return heartbeat


def make_nuclei_heartbeat(output_file, service_url):
    state = {"offset": 0}
    def heartbeat():
        new = []
        for raw in _tail_new_lines(output_file, state):
            try:
                data = json.loads(raw)
            except Exception:
                continue
            info_obj = data.get("info") or {}
            template_id = data.get("template-id") or data.get("template_id") or ""
            name = info_obj.get("name") or template_id or "finding"
            severity = str(info_obj.get("severity") or "unknown").upper()
            matched = data.get("matched-at") or data.get("matched") or data.get("host") or ""
            tags = info_obj.get("tags") or []
            context = " ".join([template_id, name, " ".join(tags) if isinstance(tags, list) else str(tags)]).lower()
            if re.search(r"\bwaf\b", context) or "web application firewall" in context:
                continue
            key = (severity, name, matched)
            if key in NUCLEI_PARTIAL_SEEN[service_url]:
                continue
            NUCLEI_PARTIAL_SEEN[service_url].add(key)
            new.append(key)
        if new:
            console_block(["", f"{BOLD}Nuclei — parcial — {service_url}{RESET}"] + [f"  [{sev}] {name} -> {matched}" for sev, name, matched in new[:20]])
    return heartbeat


# ============================================================
# Nikto
# ============================================================

def run_nikto(service, service_dir, cookie=None, announce=True):
    output_file = service_dir / "nikto.txt"

    command = [
        "nikto",
        "-h",
        service["url"],
        "-Format",
        "txt",
        "-output",
        output_file,
        "-nointeractive",
    ]

    temp_config = None

    if cookie:
        cookie_parts = [
            part.strip() for part in cookie.split(";")
            if part.strip() and "=" in part
        ]
        static_cookie = ";".join(f'"{part}"' for part in cookie_parts) + ";"

        config_candidates = [
            Path("/etc/nikto.conf"),
            Path("/usr/share/nikto/nikto.conf"),
            Path("/usr/share/nikto/program/nikto.conf"),
            Path("/usr/share/nikto/program/nikto.conf.default"),
        ]
        base_config = "CHECKMETHODS=GET\n@@DEFAULT=@@ALL\n"

        for candidate in config_candidates:
            if candidate.exists():
                try:
                    base_config = candidate.read_text(encoding="utf-8", errors="ignore")
                    break
                except Exception:
                    pass

        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", prefix="l1ght_nikto_",
            suffix=".conf", delete=False
        ) as temp:
            temp.write(base_config.rstrip() + "\n")
            temp.write(f"STATIC-COOKIE={static_cookie}\n")
            temp_config = Path(temp.name)

        command.extend(["-config", temp_config])

    try:
        stdout, _, _ = run_command(
            command,
            activity=(
                f"Executando Nikto em {service['url']} - "
                "verificando configurações e exposições Web..."
                if announce else None
            ),
            heartbeat=make_nikto_heartbeat(output_file, service["url"]),
            heartbeat_interval=2.0,
        )
    finally:
        if temp_config:
            try:
                temp_config.unlink(missing_ok=True)
            except Exception:
                pass

    redact_file_secret(output_file, cookie)

    if not output_file.exists() and stdout:
        output_file.write_text(stdout, encoding="utf-8")

    findings = []

    if output_file.exists():
        for line in output_file.read_text(
            encoding="utf-8", errors="ignore"
        ).splitlines():
            line = line.strip()
            if not line.startswith("+"):
                continue

            if any(
                marker in line.lower()
                for marker in [
                    "target ip",
                    "target hostname",
                    "target port",
                    "start time",
                    "end time",
                    "host(s) tested",
                ]
            ):
                continue

            findings.append(line.lstrip("+ ").strip())

    if announce:
        success(f"Nikto: {len(findings)} linha(s) relevante(s).")
    return findings


# ============================================================
# Nuclei
# ============================================================

def run_nuclei(service, service_dir, cookie=None, announce=True):
    output_file = service_dir / "nuclei.jsonl"

    command = [
        "nuclei",
        "-u",
        service["url"],
        "-silent",
        "-nc",
        "-jsonl",
        "-or",
        "-o",
        output_file,
    ]

    if cookie:
        command.extend(["-H", f"Cookie: {cookie}"])

    if LOW_NOISE:
        command.extend(["-rl", "10"])

    stdout, _, _ = run_command(
        command,
        activity=(
            f"Executando Nuclei em {service['url']} - "
            "executando templates de detecção..."
            if announce else None
        ),
        heartbeat=make_nuclei_heartbeat(output_file, service["url"]),
        heartbeat_interval=2.0,
    )

    redact_file_secret(output_file, cookie)

    # Some versions write only to -o. Preserve stdout if needed.
    if not output_file.exists() and stdout:
        output_file.write_text(stdout, encoding="utf-8")

    redact_file_secret(output_file, cookie)

    findings = []

    if not output_file.exists():
        return findings

    for line in output_file.read_text(
        encoding="utf-8", errors="ignore"
    ).splitlines():
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        info_obj = data.get("info") or {}

        template_id = (
            data.get("template-id")
            or data.get("template_id")
            or ""
        )
        finding_name = info_obj.get("name") or ""
        tags = info_obj.get("tags") or []

        if isinstance(tags, list):
            tags_text = " ".join(str(tag) for tag in tags)
        else:
            tags_text = str(tags)

        waf_context = " ".join(
            [template_id, finding_name, tags_text]
        ).lower()

        if (
            re.search(r"\bwaf\b", waf_context)
            or "web application firewall" in waf_context
        ):
            continue

        findings.append(
            {
                "template_id": template_id,
                "name": finding_name,
                "severity": info_obj.get("severity") or "unknown",
                "matched": data.get("matched-at") or data.get("matched") or "",
                "host": data.get("host") or "",
            }
        )

    if announce:
        success(f"Nuclei: {len(findings)} finding(s).")
    return findings


# ============================================================
# WhatWeb
# ============================================================

def split_whatweb_plugins(value):
    parts = []
    current = []
    depth = 0

    for char in value:
        if char == "[":
            depth += 1
        elif char == "]" and depth > 0:
            depth -= 1

        if char == "," and depth == 0:
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
        else:
            current.append(char)

    part = "".join(current).strip()
    if part:
        parts.append(part)

    return parts


def parse_whatweb_output(stdout):
    records = []

    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        match = re.match(
            r"^(https?://\S+)\s+\[([^\]]+)\]\s*(.*)$",
            line,
        )

        if match:
            url = match.group(1)
            status = match.group(2)
            tail = match.group(3)
        else:
            url = ""
            status = ""
            tail = line

        plugins = []

        for token in split_whatweb_plugins(tail):
            plugin_match = re.match(r"^([^\[]+)((?:\[[^\]]*\])*)$", token)
            if not plugin_match:
                plugins.append(
                    {
                        "name": "Detalhe",
                        "values": [token],
                    }
                )
                continue

            name = plugin_match.group(1).strip()
            values = re.findall(r"\[([^\]]*)\]", plugin_match.group(2))

            plugins.append(
                {
                    "name": name,
                    "values": values or ["detectado"],
                }
            )

        records.append(
            {
                "url": url,
                "status": status,
                "plugins": plugins,
            }
        )

    return records


def run_whatweb(service, service_dir, cookie=None, announce=True):
    output_file = service_dir / "whatweb.txt"
    command = ["whatweb", "--color=never", "--no-errors", service["url"]]

    if cookie:
        command.extend(["-c", cookie])

    stdout, _, _ = run_command(
        command,
        output_file,
        activity=(
            f"Executando WhatWeb em {service['url']} - "
            "identificando tecnologias e características da aplicação..."
            if announce else None
        ),
    )

    redact_file_secret(output_file, cookie)
    return parse_whatweb_output(stdout)


def print_nikto_results(service_url, results):
    seen = NIKTO_PARTIAL_SEEN.get(service_url) or set()
    if seen:
        remaining = [line for line in results if line not in seen]
        lines = ["", f"{BOLD}Nikto - {service_url}{RESET}"]
        lines.append(f"  Finalizado: {len(results)} linha(s) relevante(s); {len(seen)} exibida(s) durante a execução.")
        lines.extend(f"  - {line}" for line in remaining)
        console_block(lines)
        return
    lines = ["", f"{BOLD}Nikto - {service_url}{RESET}"]
    if not results:
        lines.append("  Nenhum resultado relevante.")
    else:
        lines.extend(f"  - {line}" for line in results)
    console_block(lines)


def print_nuclei_results(service_url, results):
    grouped = Counter()
    for item in results:
        severity = str(item.get("severity", "unknown")).upper()
        name = item.get("name") or item.get("template_id") or "finding"
        matched = item.get("matched") or item.get("host") or ""
        grouped[(severity, name, matched)] += 1
    seen = NUCLEI_PARTIAL_SEEN.get(service_url) or set()
    lines = ["", f"{BOLD}Nuclei - {service_url}{RESET}"]
    if not results:
        lines.append("  Nenhum finding encontrado.")
    elif seen:
        lines.append(f"  Finalizado: {len(results)} finding(s); {len(seen)} padrão(ões) exibido(s) durante a execução.")
        for (severity, name, matched), count in grouped.items():
            if (severity, name, matched) in seen:
                continue
            suffix = f"  (x{count})" if count > 1 else ""
            lines.append(f"  [{severity}] {name} -> {matched}{suffix}")
    else:
        for (severity, name, matched), count in grouped.items():
            suffix = f"  (x{count})" if count > 1 else ""
            lines.append(f"  [{severity}] {name} -> {matched}{suffix}")
    console_block(lines)


def print_whatweb_results(service_url, results):
    lines = ["", f"{BOLD}WhatWeb - {service_url}{RESET}"]

    if not results:
        lines.append("  Nenhuma identificação adicional.")
        console_block(lines)
        return

    for index, record in enumerate(results, start=1):
        if index > 1:
            lines.append("")

        if record.get("url"):
            lines.append(f"  URL....: {record['url']}")
        if record.get("status"):
            lines.append(f"  Status.: {record['status']}")

        for plugin in record.get("plugins", []):
            name = plugin.get("name") or "Detalhe"
            values = " | ".join(plugin.get("values") or ["detectado"])
            wrapped = textwrap.wrap(
                f"{name}: {values}",
                width=105,
                subsequent_indent="      ",
            ) or [""]

            lines.append(f"  - {wrapped[0]}")
            lines.extend(f"    {part}" for part in wrapped[1:])

    console_block(lines)


# ============================================================
# WAFW00F
# ============================================================

def run_wafw00f(service, service_dir, cookie=None, announce=True):
    output_file = service_dir / "wafw00f.txt"
    header_file = None

    command = [
        "wafw00f",
        "-a",
        "--no-colors",
    ]

    try:
        if cookie:
            header_file = service_dir / ".wafw00f_headers.txt"
            header_file.write_text(
                f"Cookie: {cookie}\n",
                encoding="utf-8",
            )
            command.extend(["-H", str(header_file)])

        command.append(service["url"])

        stdout, _, _ = run_command(
            command,
            output_file,
            activity=(
                f"Executando WAFW00F em {service['url']} - "
                "verificando presença de WAF..."
                if announce else None
            ),
        )

        redact_file_secret(output_file, cookie)

        meaningful = []
        wafs = []
        detected = False
        requests_count = None

        for raw_line in stdout.splitlines():
            line = raw_line.strip()

            if not line:
                continue

            lowered = line.lower()

            if "number of requests" in lowered:
                requests_count = line.split(":", 1)[-1].strip()
                continue

            match = re.search(
                r"is behind\s+(.+?)\s+WAF",
                line,
                flags=re.I,
            )

            if match:
                detected = True
                waf = match.group(1).strip(" .")
                if waf not in wafs:
                    wafs.append(waf)
                continue

            if (
                "no waf detected" in lowered
                or "does not seem to be behind a waf" in lowered
            ):
                meaningful.append("Nenhum WAF identificado.")
                continue

        if detected:
            meaningful.insert(
                0,
                "WAF identificado: " + ", ".join(wafs),
            )

        if not meaningful and not detected:
            meaningful.append(
                "Nenhum WAF identificado pelo WAFW00F."
            )

        return {
            "detected": detected,
            "wafs": wafs,
            "requests": requests_count,
            "summary": meaningful,
        }

    finally:
        if header_file and header_file.exists():
            try:
                header_file.unlink()
            except OSError:
                pass


def print_wafw00f_results(service_url, result):
    lines = ["", f"{BOLD}WAFW00F - {service_url}{RESET}"]

    if not result:
        lines.append("  Resultado indisponível.")
    elif result.get("detected"):
        lines.append(
            f"  {GREEN}WAF identificado:{RESET} "
            + ", ".join(result.get("wafs") or ["desconhecido"])
        )
    else:
        lines.append(
            f"  {CYAN}Nenhum WAF identificado.{RESET}"
        )

    if result and result.get("requests"):
        lines.append(
            f"  Requisições realizadas: {result['requests']}"
        )

    console_block(lines)


# ============================================================
# Sensitive data analysis
# ============================================================

SENSITIVE_IDENTITY_KEYS = {
    "user", "username", "user_name", "userid", "user_id", "login",
    "email", "account", "account_name", "usuario", "nome_usuario",
    "client_id", "clientid",
    "db_user", "db_username", "database_user",
}

SENSITIVE_PASSWORD_KEYS = {
    "password", "passwd", "pwd", "pass", "senha", "user_password",
    "db_password", "database_password", "mysql_password", "pg_password",
}

SENSITIVE_HASH_KEYS = {
    "hash", "password_hash", "passwd_hash", "pwd_hash", "senha_hash",
    "passhash", "passwordhash", "user_hash", "credential_hash",
}

SENSITIVE_SECRET_KEYS = {
    "secret", "api_key", "apikey", "api_secret", "access_token",
    "auth_token", "token", "bearer", "jwt", "client_secret",
    "private_key", "secret_key", "app_secret", "db_pass", "database_pass",
}

SENSITIVE_ALL_KEYS = (
    SENSITIVE_IDENTITY_KEYS
    | SENSITIVE_PASSWORD_KEYS
    | SENSITIVE_HASH_KEYS
    | SENSITIVE_SECRET_KEYS
)

SENSITIVE_PATH_HINTS = (
    "user", "users", "usuario", "usuarios", "credential", "credentials",
    "creds", "account", "accounts", "login", "auth", "password", "passwd",
    "pwd", "hash", "secret", "token", "config", "configuration", "database",
    "db", "backup", "dump", "debug", "admin", ".env", "shadow", "htpasswd",
)

SENSITIVE_TEXT_EXTENSIONS = {
    ".php", ".phtml", ".php3", ".php4", ".php5", ".phps", ".asp", ".aspx",
    ".jsp", ".jspx", ".js", ".mjs", ".cjs", ".json", ".xml", ".yaml",
    ".yml", ".ini", ".env", ".conf", ".config", ".txt", ".sql", ".log",
    ".csv", ".html", ".htm", ".properties", ".toml",
}

SENSITIVE_PLACEHOLDERS = {
    "", "none", "null", "nil", "undefined", "password", "passwd", "pwd",
    "secret", "token", "changeme", "change_me", "example", "example123",
    "test", "testing", "demo", "default", "your_password", "your_secret",
    "your_token", "<password>", "<secret>", "<token>", "xxxxx", "xxxxxx",
}

SENSITIVE_EXTRA_TEXT_LIMIT = 120


def _normalize_sensitive_key(value):
    raw = unicodedata.normalize("NFKD", str(value or ""))
    raw = "".join(ch for ch in raw if not unicodedata.combining(ch))
    return re.sub(r"[^a-z0-9]+", "_", raw.lower()).strip("_")


def _sensitive_path_score(url):
    try:
        path = urlparse(url).path.lower()
    except Exception:
        path = str(url or "").lower()
    score = sum(1 for hint in SENSITIVE_PATH_HINTS if hint in path)
    suffix = Path(path).suffix.lower()
    if suffix in SENSITIVE_TEXT_EXTENSIONS:
        score += 1
    return score


def _is_priority_sensitive_url(url):
    try:
        path = urlparse(url).path.lower()
    except Exception:
        path = str(url or "").lower()
    return any(hint in path for hint in SENSITIVE_PATH_HINTS)


def _is_textual_candidate_url(url):
    try:
        suffix = Path(urlparse(url).path.lower()).suffix
    except Exception:
        return False
    return suffix in SENSITIVE_TEXT_EXTENSIONS


def _select_source_urls(service_url, urls, limit):
    unique = {url for url in urls if _valid_http_url(url)}
    unique.add(service_url)

    sensitive = sorted(
        (url for url in unique if _is_priority_sensitive_url(url)),
        key=lambda url: (-_sensitive_path_score(url), url),
    )
    sensitive_set = set(sensitive)

    textual = sorted(
        (
            url for url in unique
            if url not in sensitive_set and _is_textual_candidate_url(url)
        ),
        key=lambda url: (-_sensitive_path_score(url), url),
    )[:SENSITIVE_EXTRA_TEXT_LIMIT]
    textual_set = set(textual)

    normal = sorted(
        (
            url for url in unique
            if url not in sensitive_set and url not in textual_set
        ),
        key=lambda url: (url != service_url, url),
    )[:max(1, int(limit or 1))]

    selected = []
    seen = set()
    for url in [service_url, *sensitive, *textual, *normal]:
        if url in seen:
            continue
        seen.add(url)
        selected.append(url)
    return selected


def _is_textual_response(response, url):
    content_type = str(response.headers.get("Content-Type", "")).lower()
    if any(token in content_type for token in (
        "text/", "json", "javascript", "xml", "yaml", "x-www-form-urlencoded"
    )):
        return True
    if _is_textual_candidate_url(url):
        return True
    sample = (response.text or "")[:512].lower()
    return "<html" in sample or "<!doctype" in sample


def _shannon_entropy(value):
    text = str(value or "")
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _looks_concrete_sensitive_value(value):
    text = str(value or "").strip().strip(chr(34) + chr(39))
    if not text:
        return False

    lowered = text.lower()
    if lowered in SENSITIVE_PLACEHOLDERS:
        return False
    if lowered in {
        "true", "false", "!0", "!1", "0", "1", "yes", "no",
        "on", "off", "enabled", "disabled",
    }:
        return False
    if len(text) < 4 or len(text) > 500:
        return False

    non_values = (
        "document.", "window.", "process.env", "getenv(", "env(", "function(",
        "function ", "$" + "{", "{{", "}}", "$_post", "$_get", "$_server",
        "password_hash(", "hash(", "md5(", "sha1(", "sha256(", "bcrypt(",
        ".concat(", "=>", "return ", "require(", "import(",
    )
    if any(token in lowered for token in non_values):
        return False

    if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_.$-]*", text) and lowered.endswith(
        ("value", "field", "input", "variable", "var", "element")
    ):
        return False

    return True


def _classify_hash_value(value):
    text = str(value or "").strip()
    if re.fullmatch(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}", text):
        return "bcrypt"
    if text.startswith("$argon2"):
        return "Argon2"
    if text.startswith(("$P$", "$H$")):
        return "phpass"
    if text.startswith("$1$"):
        return "Unix crypt MD5"
    if text.startswith("$5$"):
        return "Unix crypt SHA-256"
    if text.startswith("$6$"):
        return "Unix crypt SHA-512"
    if text.lower().startswith("$pbkdf2"):
        return "PBKDF2"
    if re.fullmatch(r"[A-Fa-f0-9]+", text):
        labels = {
            32: "hash hexadecimal de 128 bits (ex.: MD5/NTLM)",
            40: "hash hexadecimal de 160 bits (ex.: SHA-1)",
            64: "hash hexadecimal de 256 bits (ex.: SHA-256)",
            96: "hash hexadecimal de 384 bits (ex.: SHA-384)",
            128: "hash hexadecimal de 512 bits (ex.: SHA-512)",
        }
        if len(text) in labels:
            return labels[len(text)]
    return None


def _confidence_from_score(score):
    if score >= 8:
        return "alta"
    if score >= 5:
        return "média"
    return "informação"


def _line_is_comment(line):
    stripped = str(line or "").lstrip().lower()
    return stripped.startswith(("#", "//", "/*", "*", "<!--", ";"))


def _sensitive_kv_regex():
    keys = sorted(SENSITIVE_ALL_KEYS, key=len, reverse=True)
    pattern = "|".join(re.escape(key) for key in keys)
    return re.compile(
        rf'''(?ix)
        ["']?(?P<key>{pattern})["']?\s*(?:=>|=|:)\s*
        (?:
            "(?P<dq>[^"\r\n]{{1,500}})"
            |
            '(?P<sq>[^'\r\n]{{1,500}})'
            |
            (?P<bare>[^\s,;}}\]\r\n]{{1,500}})
        )
        '''
    )


SENSITIVE_KV_RE = _sensitive_kv_regex()

SENSITIVE_STRUCTURED_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 7),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,255}\b"), 7),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,255}\b"), 7),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), 6),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), 9),
]


def _is_minified_javascript(url, text):
    try:
        path = urlparse(url).path.lower()
    except Exception:
        path = str(url or "").lower()

    if not path.endswith((".js", ".mjs", ".cjs")):
        return False

    content = str(text or "")
    lines = content.splitlines() or [content]
    average = sum(len(line) for line in lines) / max(1, len(lines))
    return (
        path.endswith(".min.js")
        or "/vendor/" in path
        or "/plugins/" in path
        or "/node_modules/" in path
        or average > 900
    )


def _sensitive_field_allowed_in_minified(key, value):
    hash_type = _classify_hash_value(value)
    if hash_type:
        return True
    if key in SENSITIVE_HASH_KEYS:
        return len(value) >= 20
    if key in SENSITIVE_PASSWORD_KEYS | SENSITIVE_SECRET_KEYS:
        return len(value) >= 12 and _shannon_entropy(value) >= 3.0
    return False


def _detect_sensitive_data(url, text):
    lines = str(text or "").splitlines()
    parsed_lines = []
    minified_js = _is_minified_javascript(url, text)

    for index, line in enumerate(lines, start=1):
        fields = []
        for match in SENSITIVE_KV_RE.finditer(line):
            key = _normalize_sensitive_key(match.group("key"))
            value = next(
                (group for group in (match.group("dq"), match.group("sq"), match.group("bare")) if group is not None),
                "",
            ).strip()
            if not _looks_concrete_sensitive_value(value):
                continue
            if minified_js and not _sensitive_field_allowed_in_minified(key, value):
                continue
            fields.append({"key": key, "value": value, "span": match.span()})
        parsed_lines.append({"number": index, "text": line, "fields": fields})

    paired_secret_members = set()
    findings = []
    seen = set()
    path_bonus = 2 if _is_priority_sensitive_url(url) else 0

    identity_records = []
    secret_records = []
    for row in parsed_lines:
        for field in row["fields"]:
            record = (row["number"], field["key"], field["value"])
            if field["key"] in SENSITIVE_IDENTITY_KEYS:
                identity_records.append(record)
            elif field["key"] in (SENSITIVE_PASSWORD_KEYS | SENSITIVE_HASH_KEYS | SENSITIVE_SECRET_KEYS):
                secret_records.append(record)

    for pos, identity in enumerate(identity_records):
        if minified_js:
            break
        next_identity_line = (
            identity_records[pos + 1][0]
            if pos + 1 < len(identity_records)
            else None
        )
        candidates = [
            secret for secret in secret_records
            if secret[0] >= identity[0]
            and secret[0] <= identity[0] + 2
            and (next_identity_line is None or secret[0] < next_identity_line or secret[0] == identity[0])
        ]
        if not candidates:
            continue
        secret = min(candidates, key=lambda record: (abs(record[0] - identity[0]), record[0]))
        pair_key = (url, identity[1], identity[2], secret[1], secret[2])
        if pair_key in seen:
            continue
        seen.add(pair_key)
        paired_secret_members.add(secret)
        hash_type = _classify_hash_value(secret[2]) if secret[1] in SENSITIVE_HASH_KEYS else None
        entropy = _shannon_entropy(secret[2])
        score = 8 + path_bonus
        if hash_type:
            score += 2
        if len(secret[2]) >= 20 and entropy >= 3.5:
            score += 2
        context_start = max(1, min(identity[0], secret[0]))
        context_end = min(len(parsed_lines), max(identity[0], secret[0]) + 1)
        context_lines = [
            parsed_lines[line_no - 1]["text"]
            for line_no in range(context_start, context_end + 1)
            if parsed_lines[line_no - 1]["text"].strip()
        ]
        if any(_line_is_comment(row) for row in context_lines):
            score -= 1
        findings.append({
            "kind": "credential_pair",
            "confidence": _confidence_from_score(score),
            "score": score,
            "url": url,
            "line": identity[0],
            "identity_key": identity[1],
            "identity_value": identity[2],
            "secret_key": secret[1],
            "secret_value": secret[2],
            "classification": hash_type or ("credencial em texto" if secret[1] in SENSITIVE_PASSWORD_KEYS else "segredo/token"),
            "context": "\n".join(context_lines)[:1200],
        })

    for item in parsed_lines:
        for field in item["fields"]:
            key = field["key"]
            member = (item["number"], key, field["value"])
            if member in paired_secret_members or key in SENSITIVE_IDENTITY_KEYS:
                continue
            if key not in (SENSITIVE_PASSWORD_KEYS | SENSITIVE_HASH_KEYS | SENSITIVE_SECRET_KEYS):
                continue
            value = field["value"]
            hash_type = _classify_hash_value(value) if key in SENSITIVE_HASH_KEYS else None
            entropy = _shannon_entropy(value)
            score = 3 + path_bonus
            if hash_type:
                score += 2
            if len(value) >= 20 and entropy >= 3.5:
                score += 2
            if _line_is_comment(item["text"]):
                score -= 1
            finding_key = (url, "direct", key, value, item["number"])
            if finding_key in seen:
                continue
            seen.add(finding_key)
            findings.append({
                "kind": "hash" if key in SENSITIVE_HASH_KEYS else ("password" if key in SENSITIVE_PASSWORD_KEYS else "secret"),
                "confidence": _confidence_from_score(score),
                "score": score,
                "url": url,
                "line": item["number"],
                "key": key,
                "value": value,
                "classification": hash_type or ("valor sensível atribuído" if key in SENSITIVE_PASSWORD_KEYS else "segredo/token atribuído"),
                "context": item["text"][:1200],
            })

    for label, pattern, base_score in SENSITIVE_STRUCTURED_PATTERNS:
        for match in pattern.finditer(str(text or "")):
            line_no = str(text or "")[:match.start()].count("\n") + 1
            line = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
            value = match.group(0)
            finding_key = (url, label, value, line_no)
            if finding_key in seen:
                continue
            seen.add(finding_key)
            score = base_score + path_bonus - (1 if _line_is_comment(line) else 0)
            findings.append({
                "kind": "structured_secret",
                "confidence": _confidence_from_score(score),
                "score": score,
                "url": url,
                "line": line_no,
                "key": label,
                "value": value,
                "classification": label,
                "context": line[:1200],
            })

    findings.sort(key=lambda item: (-int(item.get("score") or 0), item.get("url") or "", int(item.get("line") or 0)))
    return findings


def _deduplicate_sensitive_findings(findings):
    unique = {}
    for item in findings or []:
        if item.get("kind") == "credential_pair":
            key = (
                item.get("kind"), item.get("url"), item.get("identity_key"),
                item.get("identity_value"), item.get("secret_key"), item.get("secret_value"),
            )
        else:
            key = (item.get("kind"), item.get("url"), item.get("key"), item.get("value"))
        current = unique.get(key)
        if current is None or int(item.get("score") or 0) > int(current.get("score") or 0):
            unique[key] = item
    return sorted(
        unique.values(),
        key=lambda item: (-int(item.get("score") or 0), item.get("url") or "", int(item.get("line") or 0)),
    )


def print_sensitive_findings(service_url, findings):
    findings = findings or []
    if not findings:
        return
    grouped = defaultdict(list)
    for item in findings:
        grouped[item.get("url") or service_url].append(item)

    lines = ["", f"{BOLD}Possíveis credenciais e segredos - {service_url}{RESET}"]
    for url, items in sorted(
        grouped.items(),
        key=lambda pair: (-max(int(x.get("score") or 0) for x in pair[1]), pair[0]),
    )[:12]:
        high = sum(1 for item in items if item.get("confidence") == "alta")
        medium = sum(1 for item in items if item.get("confidence") == "média")
        pairs = sum(1 for item in items if item.get("kind") == "credential_pair")
        details = []
        if pairs:
            details.append(f"{pairs} par(es) de credencial")
        if high:
            details.append(f"{high} alta confiança")
        if medium:
            details.append(f"{medium} média confiança")
        lines.append(f"  [!] {url}")
        lines.append(f"      {', '.join(details) or str(len(items)) + ' achado(s)'}")
    if len(grouped) > 12:
        lines.append(f"  ... +{len(grouped) - 12} recurso(s) no relatório HTML.")
    lines.append("  [i] Valores e contexto completos estão no HTML e em sensitive_findings.json.")
    console_block(lines)

# ============================================================
# HTTP source / forms / headers / cookies
# ============================================================

def same_service(url, service_url):
    try:
        return urlparse(url).netloc == urlparse(service_url).netloc
    except Exception:
        return False


def analyze_source(service, candidate_urls, ffuf_results, limit=25, cookie=None, response_cache=None):
    analysis_started = metric_start("analyze_source", service=service["url"], limit=limit)
    all_urls = {service["url"]}

    for url in candidate_urls:
        if same_service(url, service["url"]):
            all_urls.add(url)

    for item in ffuf_results:
        url = item.get("url")
        if url and same_service(url, service["url"]):
            all_urls.add(url)

    urls = _select_source_urls(service["url"], all_urls, limit)
    priority_count = sum(1 for url in urls if _is_priority_sensitive_url(url))
    _debug_log(
        "SOURCE_SELECTION",
        f"service={service['url']} discovered={len(all_urls)} selected={len(urls)} "
        f"priority_sensitive={priority_count} normal_limit={limit}",
    )

    summary = {
        "headers": {},
        "cookies": [],
        "forms": [],
        "hrefs": set(),
        "srcs": set(),
        "domains": set(),
        "api_endpoints": set(),
        "interesting_words": Counter(),
        "sensitive_findings": [],
        "get_parameters": defaultdict(set),
        "post_parameters": defaultdict(set),
        "source_urls_checked": [],
    }

    response_cache = response_cache if isinstance(response_cache, dict) else {}
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) "
                f"AppleWebKit/537.36 L1ght-Recon/{VERSION}"
            )
        }
    )

    if cookie:
        session.headers["Cookie"] = cookie

    def _fetch_source(url):
        cached = response_cache.get(url)
        if cached is not None:
            return url, cached, True
        try:
            response = session.get(
                url,
                timeout=8,
                verify=False,
                allow_redirects=True,
            )
            return url, response, False
        except requests.RequestException:
            return url, None, False

    workers = 1 if LOW_NOISE else min(8, max(1, len(urls)))
    fetched = []
    cache_hits = 0
    with ThreadPoolExecutor(max_workers=workers) as source_executor:
        futures = {source_executor.submit(_fetch_source, url): url for url in urls}
        for future in as_completed(futures):
            url, response, cached = future.result()
            if response is not None and not cached:
                response_cache[url] = response
            if cached:
                cache_hits += 1
            fetched.append((url, response))

    fetched.sort(key=lambda pair: (pair[0] != service["url"], -_sensitive_path_score(pair[0]), pair[0]))
    _debug_log(
        "SOURCE_FETCH",
        f"service={service['url']} fetched={len(fetched)} cache_hits={cache_hits}",
    )

    for index, (url, response) in enumerate(fetched):
        if response is None:
            continue

        summary["source_urls_checked"].append(url)

        if index == 0 or url == service["url"]:
            summary["headers"] = dict(response.headers)

        for response_cookie in response.cookies:
            summary["cookies"].append(
                {
                    "name": response_cookie.name,
                    "value": response_cookie.value,
                    "domain": response_cookie.domain or "",
                    "path": response_cookie.path or "",
                }
            )

        parsed = urlparse(response.url)
        if not is_apache_autoindex_query(parsed.query):
            for name, _ in parse_qsl(parsed.query, keep_blank_values=True):
                summary["get_parameters"][response.url].add(name)

        content_type = response.headers.get("Content-Type", "").lower()
        text = response.text or ""
        lowered = text.lower()

        for word in INTERESTING_WORDS:
            count = len(re.findall(rf"\b{re.escape(word)}\b", lowered))
            if count:
                summary["interesting_words"][word] += count

        if _is_textual_response(response, url):
            findings = _detect_sensitive_data(response.url or url, text)
            if findings:
                summary["sensitive_findings"].extend(findings)
                _debug_log(
                    "SENSITIVE_SCAN",
                    f"url={response.url or url} findings={len(findings)} "
                    f"high={sum(1 for item in findings if item.get('confidence') == 'alta')}",
                )

        for match in re.findall(
            r"https?://[A-Za-z0-9._:-]+(?:/[^\s\"'<>]*)?",
            text,
            flags=re.I,
        ):
            parsed_match = urlparse(match)
            if parsed_match.hostname:
                summary["domains"].add(parsed_match.hostname)

        api_patterns = [
            r'''["'](\/api(?:\/[^"'<> ]*)?)["']''',
            r'''["'](\/graphql[^"'<> ]*)["']''',
            r'''["'](\/rest(?:\/[^"'<> ]*)?)["']''',
            r'''["'](\/swagger[^"'<> ]*)["']''',
            r'''["'](\/openapi[^"'<> ]*)["']''',
        ]

        for pattern in api_patterns:
            for endpoint in re.findall(pattern, text, flags=re.I):
                summary["api_endpoints"].add(urljoin(response.url, endpoint))

        if "html" not in content_type and "<html" not in lowered:
            continue

        soup = BeautifulSoup(text, "html.parser")

        for tag in soup.find_all(href=True):
            absolute = urljoin(response.url, tag.get("href"))
            if not is_noise_url(absolute):
                summary["hrefs"].add(absolute)

        for tag in soup.find_all(src=True):
            absolute = urljoin(response.url, tag.get("src"))
            if not is_noise_url(absolute):
                summary["srcs"].add(absolute)

        for form in soup.find_all("form"):
            method = (form.get("method") or "GET").upper()
            action = urljoin(response.url, form.get("action") or response.url)
            fields = []

            for field in form.find_all(["input", "textarea", "select"]):
                name = field.get("name")
                field_type = field.get("type") or field.name

                if name:
                    fields.append({"name": name, "type": field_type})
                    if method == "POST":
                        summary["post_parameters"][action].add(name)
                    else:
                        summary["get_parameters"][action].add(name)

            summary["forms"].append(
                {
                    "source": response.url,
                    "method": method,
                    "action": action,
                    "fields": fields,
                }
            )

    cookie_map = {}
    for cookie_item in summary["cookies"]:
        key = (cookie_item["name"], cookie_item["domain"], cookie_item["path"])
        cookie_map[key] = cookie_item
    summary["cookies"] = list(cookie_map.values())

    summary["hrefs"] = sorted(summary["hrefs"])
    summary["srcs"] = sorted(summary["srcs"])
    summary["domains"] = sorted(summary["domains"])
    summary["api_endpoints"] = sorted(summary["api_endpoints"])
    summary["interesting_words"] = dict(summary["interesting_words"])
    summary["sensitive_findings"] = _deduplicate_sensitive_findings(summary["sensitive_findings"])
    summary["get_parameters"] = {
        key: sorted(value) for key, value in summary["get_parameters"].items()
    }
    summary["post_parameters"] = {
        key: sorted(value) for key, value in summary["post_parameters"].items()
    }

    metric_end(
        "analyze_source", analysis_started, urls=len(urls),
        forms=len(summary.get("forms") or []), hrefs=len(summary.get("hrefs") or []),
        sensitive=len(summary.get("sensitive_findings") or []), cache_hits=cache_hits,
    )
    return summary


# ============================================================
# Triage
# ============================================================


def classify_parameter(name):
    lowered = name.lower().strip()
    tokens = {
        token
        for token in re.split(r"[^a-z0-9]+", lowered)
        if token
    }
    categories = set()

    identifier_names = {
        "id", "uid", "uuid", "pk", "userid", "user_id",
        "accountid", "account_id", "productid", "product_id",
        "itemid", "item_id", "orderid", "order_id",
        "postid", "post_id", "customerid", "customer_id",
        "prod", "mprod", "cat", "subcat", "category", "pid",
        "pedido", "pedfin",
    }

    sql_names = identifier_names | {
        "user", "username", "email", "account", "product",
        "item", "order", "filter", "sort", "search", "query",
        "pag", "page", "offset", "limit",
    }

    if lowered in sql_names or lowered.endswith("_id"):
        categories.add("Possível SQLi")

    if lowered in identifier_names or lowered.endswith("_id"):
        categories.add("Possível IDOR")

    if lowered in {
        "file", "filename", "filepath", "path", "page",
        "include", "template", "folder", "directory", "dir",
        "document",
    } or tokens & {
        "file", "filepath", "path", "page", "include",
        "folder", "directory", "document",
    }:
        categories.add("Possível LFI / Path Traversal")

    if lowered in {
        "url", "uri", "redirect", "redirect_uri", "redirect_url",
        "callback", "return", "returnurl", "return_url", "next",
        "dest", "destination", "host", "domain", "endpoint",
    } or tokens & {
        "url", "uri", "redirect", "callback", "return", "next",
        "dest", "destination", "host", "domain", "endpoint",
    }:
        categories.add("Possível SSRF / Open Redirect")

    if lowered in {
        "cmd", "command", "exec", "execute", "ping",
        "hostname", "shell",
    } or tokens & {
        "cmd", "command", "exec", "execute", "ping",
        "hostname", "shell",
    }:
        categories.add("Possível Command Injection")

    if lowered in {
        "template", "render", "renderer", "view", "engine",
    }:
        categories.add("Possível SSTI")

    if lowered in {
        "q", "query", "search", "keyword", "term", "name",
        "message", "comment", "text", "title", "input",
        "busca", "mensagem", "nome",
    }:
        categories.add("Possível XSS")

    return sorted(categories)


def print_parameter_results(service_url, records, title="Parâmetros identificados"):
    lines = [
        "",
        f"{BOLD}{title} - {service_url}{RESET}",
    ]

    if not records:
        lines.append("  Nenhum parâmetro GET/POST relevante identificado.")
        console_block(lines)
        return

    prioritized = [r for r in records if r.get("vectors")]
    neutral = [r for r in records if not r.get("vectors")]

    ordered = prioritized + neutral

    for record in ordered[:30]:
        params = ", ".join(record.get("parameters") or [])
        vectors = ", ".join(record.get("vectors") or []) or "sem heurística"
        count = int(record.get("count") or 1)
        route = record.get("route") or record.get("url") or "-"
        suffix = f"  ({count} variações)" if count > 1 else ""

        lines.append(
            f"  [{record.get('method', '-')}] "
            f"{route} | {params} -> {vectors}{suffix}"
        )

    if len(ordered) > 30:
        lines.append(
            f"  ... +{len(ordered) - 30} padrão(ões) de parâmetros no relatório."
        )

    console_block(lines)


def collect_parameter_records(urls, source_summary):
    grouped = {}

    def add_record(method, url, params):
        method = (method or "GET").upper()
        params = [
            value for value in (params or [])
            if value and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", value)
        ]

        if not params:
            return

        try:
            parsed = urlparse(url)
        except Exception:
            return

        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return

        if is_apache_autoindex_query(parsed.query):
            return

        route = parsed.path or "/"
        param_tuple = tuple(sorted(set(params)))
        key = (method, route, param_tuple)

        vectors = sorted(
            {
                vector
                for parameter in param_tuple
                for vector in classify_parameter(parameter)
            }
        )

        record = grouped.setdefault(
            key,
            {
                "url": url,
                "route": route,
                "method": method,
                "parameters": list(param_tuple),
                "vectors": vectors,
                "count": 0,
                "examples": [],
            },
        )

        record["count"] += 1

        if url not in record["examples"] and len(record["examples"]) < 3:
            record["examples"].append(url)

    for url in urls or []:
        if not _valid_http_url(url):
            continue

        try:
            parsed = urlparse(url)
        except Exception:
            continue

        params = _parameter_names_from_query(parsed.query)
        if params:
            add_record("GET", url, params)

    for url, params in (source_summary.get("get_parameters") or {}).items():
        add_record("GET", url, params)

    for url, params in (source_summary.get("post_parameters") or {}).items():
        add_record("POST", url, params)

    return sorted(
        grouped.values(),
        key=lambda record: (
            0 if record.get("vectors") else 1,
            record.get("method", ""),
            record.get("route", ""),
            record.get("parameters", []),
        ),
    )

def collect_javascript_files(urls, source_summary):
    candidates = set(urls)
    candidates.update(source_summary.get("hrefs", []))
    candidates.update(source_summary.get("srcs", []))

    javascript = set()
    for url in candidates:
        try:
            path = urlparse(url).path.lower()
        except Exception:
            continue
        if path.endswith((".js", ".mjs", ".cjs")):
            javascript.add(url)

    return sorted(javascript)


def analyze_interesting_paths(urls):
    results = []

    for url in sorted(set(urls)):
        lowered = url.lower()
        categories = []

        for category, keywords in INTERESTING_PATHS.items():
            if any(keyword in lowered for keyword in keywords):
                categories.append(category)

        if categories:
            results.append(
                {
                    "url": url,
                    "categories": categories,
                }
            )

    return results


def build_vector_summary(parameter_records, source_summary, interesting_paths, vhosts, nuclei):
    vectors = Counter()

    for record in parameter_records:
        for vector in record["vectors"]:
            vectors[vector] += 1

    for item in interesting_paths:
        for category in item["categories"]:
            vectors[category] += 1

    for form in source_summary["forms"]:
        if form["method"] == "POST":
            vectors["POST Form"] += 1

        if any(field["type"].lower() == "file" for field in form["fields"]):
            vectors["File Upload"] += 1

    if source_summary["api_endpoints"]:
        vectors["API"] += len(source_summary["api_endpoints"])

    if vhosts:
        vectors["Virtual Hosts"] += len(vhosts)

    for finding in nuclei:
        severity = str(finding["severity"]).capitalize()
        vectors[f"Nuclei: {severity}"] += 1

    return vectors


# ============================================================
# CSV output
# ============================================================


def write_parameter_csv(path, records):
    with Path(path).open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(
            [
                "Method",
                "Route",
                "Parameters",
                "Potential vectors",
                "Occurrences",
                "Example",
            ]
        )

        for record in records:
            writer.writerow(
                [
                    record["method"],
                    record.get("route") or record["url"],
                    ", ".join(record["parameters"]),
                    ", ".join(record["vectors"]),
                    record.get("count", 1),
                    (record.get("examples") or [record["url"]])[0],
                ]
            )


# ============================================================
# HTML report
# ============================================================

def generate_report(
    target,
    host,
    output_dir,
    open_ports,
    web_results,
    missing_tools,
    udp_ports=None,
    udp_candidates=None,
    service_results=None,
):
    report_file = output_dir / "report.html"

    udp_ports = udp_ports or []
    udp_candidates = udp_candidates or []
    service_results = service_results or []

    port_rows = []
    for item in open_ports:
        description = " ".join(
            x for x in [item["product"], item["version"], item["extrainfo"]] if x
        )
        nse = "<br>".join(
            f"<strong>{html.escape(script['id'])}</strong>: {html.escape(script['output'])}"
            for script in item["scripts"]
        ) or "-"
        port_rows.append([
            html.escape(f"{item['port']}/{item['protocol']}"),
            html.escape(item["service"] or "-"),
            html.escape(description or "-"),
            nse,
        ])

    udp_rows = []
    for item in udp_ports:
        description = " ".join(
            x
            for x in [
                item.get("product") or "",
                item.get("version") or "",
                item.get("extrainfo") or "",
            ]
            if x
        )
        nse = "<br>".join(
            f"<strong>{html.escape(script.get('id') or 'NSE')}</strong>: "
            f"{html.escape(script.get('output') or '')}"
            for script in item.get("scripts", [])
        ) or "-"

        udp_rows.append([
            html.escape(f"{item['port']}/{item.get('protocol', 'udp')}"),
            html.escape(item.get("service") or "-"),
            html.escape(description or "-"),
            nse,
        ])

    udp_candidate_rows = []
    for item in udp_candidates:
        description = " ".join(
            x for x in [item.get("product") or "", item.get("version") or "", item.get("extrainfo") or ""] if x
        )
        udp_candidate_rows.append([
            html.escape(f"{item['port']}/{item.get('protocol', 'udp')}"),
            html.escape(item.get("state") or "open|filtered"),
            html.escape(item.get("service") or "-"),
            html.escape(description or "-"),
            html.escape(item.get("reason") or "-"),
        ])

    service_enum_rows = []
    for item in service_results:
        scripts_text = "<br><br>".join(
            f"<strong>{html.escape(script.get('id') or 'NSE')}</strong>:<br>"
            f"{html.escape(script.get('output') or '').replace(chr(10), '<br>')}"
            for script in item.get("scripts", [])
        ) or "-"

        description = " ".join(
            part
            for part in [
                item.get("product") or "",
                item.get("version") or "",
            ]
            if part
        )

        detail_parts = []

        if item.get("exports"):
            detail_parts.append(
                "<strong>Exports:</strong><br>"
                + "<br>".join(
                    html.escape(value)
                    for value in item["exports"]
                )
            )

        if item.get("users"):
            detail_parts.append(
                "<strong>Usuários:</strong> "
                + html.escape(", ".join(item["users"]))
            )

        if item.get("groups"):
            detail_parts.append(
                "<strong>Grupos:</strong> "
                + html.escape(", ".join(item["groups"]))
            )

        if item.get("shares"):
            detail_parts.append(
                "<strong>Shares:</strong> "
                + html.escape(", ".join(item["shares"]))
            )

        if item.get("share_access"):
            access_lines = []
            for entry in item["share_access"]:
                status = "listagem anônima permitida" if entry.get("listing_allowed") else "sem listagem anônima"
                count = entry.get("recursive_items_count") or len(entry.get("root_items") or [])
                access_lines.append(
                    f"<strong>{html.escape(entry.get('share') or '-')}</strong>: "
                    f"{html.escape(status)} ({count} item(ns))"
                )
                examples = entry.get("examples") or []
                if examples:
                    access_lines.extend(
                        "&nbsp;&nbsp;" + html.escape(example)
                        for example in examples[:25]
                    )
            if access_lines:
                detail_parts.append(
                    "<strong>Acesso SMB via -N (somente leitura):</strong><br>"
                    + "<br>".join(access_lines)
                )

        if item.get("rpc_entries"):
            detail_parts.append(
                "<strong>Programas RPC:</strong><br>"
                + "<br>".join(
                    html.escape(
                        f"{entry.get('service')} "
                        f"{entry.get('protocol')}/{entry.get('port')} "
                        f"(prog {entry.get('program')} v{entry.get('version')})"
                    )
                    for entry in item["rpc_entries"][:30]
                )
            )

        if item.get("anonymous_rpc_allowed"):
            detail_parts.append(
                "<strong>RPC anônimo:</strong> aceito; "
                "enumeração manual adicional recomendada."
            )

        public_exploits = item.get("public_exploits") or []

        if public_exploits:
            detail_parts.append(
                "<strong>Exploits públicos localizados:</strong><br>"
                + "<br>".join(
                    html.escape(finding.get("title") or "-")
                    for finding in public_exploits[:10]
                )
            )

        ports_display = (
            ",".join(str(port) for port in item.get("ports", []))
            if item.get("ports")
            else str(item.get("port", "-"))
        )

        service_enum_rows.append([
            html.escape(item.get("profile") or "-"),
            html.escape(
                f"{ports_display}/{item.get('protocol', '-')}"
            ),
            html.escape(item.get("service") or "-"),
            html.escape(description or "-"),
            scripts_text,
            "<br><br>".join(detail_parts) or "-",
        ])

    service_sections = []

    for result in web_results:
        service = result["service"]
        source = result["source"]
        parameters = result["parameters"]
        javascript = result.get("javascript", [])
        ffuf_content = result["ffuf_content"]
        ffuf_vhosts = result["ffuf_vhosts"]
        nuclei = result["nuclei"]
        nikto = result["nikto"]
        whatweb = result.get("whatweb", [])
        wafw00f = result.get("wafw00f") or {}
        katana_urls = result["katana_urls"]

        fingerprint_rows = [
            ["URL", html.escape(service["url"])],
            ["Porta", html.escape(str(service["port"]))],
            ["Status", html.escape(str(service["status"] or "-"))],
            ["Título", html.escape(service["title"] or "-")],
            ["Servidor", html.escape(service["server"] or "-")],
            ["Tecnologias", html.escape(", ".join(service["tech"]) or "-")],
            ["Content-Length", html.escape(str(service["content_length"] or "-"))],
            ["Redirect", html.escape(service["location"] or "-")],
        ]

        header_rows = [[html.escape(k), html.escape(str(v))] for k, v in source["headers"].items()]
        cookie_rows = [[
            html.escape(item["name"]),
            "&lt;redacted&gt;" if item.get("value") else "-",
            html.escape(item["domain"] or "-"),
            html.escape(item["path"] or "-"),
        ] for item in source["cookies"]]

        form_rows = []
        for form in source["forms"]:
            fields = ", ".join(f"{field['name']} ({field['type']})" for field in form["fields"]) or "-"
            form_rows.append([
                f'<span class="method-cell">{html.escape(form["method"])}</span>',
                html.escape(form["action"]),
                html.escape(fields),
                html.escape(form["source"]),
            ])

        parameter_rows = [[
            f'<span class="method-cell">{html.escape(record["method"])}</span>',
            html.escape(record.get("route") or record["url"]),
            html.escape(", ".join(record["parameters"])),
            html.escape(", ".join(record["vectors"]) or "-"),
            html.escape(str(record.get("count", 1))),
            html.escape((record.get("examples") or [record["url"]])[0]),
        ] for record in parameters]

        javascript_rows = [[html.escape(url)] for url in javascript]
        api_rows = [[html.escape(url)] for url in source["api_endpoints"]]
        domain_rows = [[html.escape(domain)] for domain in source["domains"]]
        href_rows = [[html.escape(url)] for url in source["hrefs"][:150]]
        src_rows = [[html.escape(url)] for url in source["srcs"][:150]]

        katana_summary = summarize_katana_urls(service["url"], katana_urls)
        katana_rows = [[
            html.escape(str(item["count"])),
            html.escape(item["signature"]),
            html.escape(item["example"] or "-"),
        ] for item in katana_summary["patterns"][:100]]
        source_word_rows = [[html.escape(word), html.escape(str(count))] for word, count in sorted(
            source["interesting_words"].items(), key=lambda pair: (-pair[1], pair[0])
        )]
        sensitive_rows = []
        for item in source.get("sensitive_findings") or []:
            if item.get("kind") == "credential_pair":
                key_text = f"{item.get('identity_key')} + {item.get('secret_key')}"
                value_text = f"{item.get('identity_key')}={item.get('identity_value')} | {item.get('secret_key')}={item.get('secret_value')}"
            else:
                key_text = item.get("key") or item.get("kind") or "-"
                value_text = item.get("value") or "-"
            sensitive_rows.append([
                html.escape(str(item.get("confidence") or "-")),
                html.escape(str(item.get("score") or "-")),
                html.escape(str(item.get("kind") or "-")),
                html.escape(str(item.get("url") or "-")),
                html.escape(str(item.get("line") or "-")),
                html.escape(str(key_text)),
                html.escape(str(value_text)),
                html.escape(str(item.get("classification") or "-")),
                html.escape(str(item.get("context") or "-")),
            ])
        ffuf_rows = [[
            html.escape(str(item.get("status", "-"))),
            html.escape(item.get("url", "-")),
            html.escape(str(item.get("length", "-"))),
            html.escape(item.get("redirectlocation") or "-"),
        ] for item in ffuf_content]
        vhost_rows = [[
            html.escape(item.get("vhost") or "-"),
            html.escape(str(item.get("status", "-"))),
            html.escape(str(item.get("length", "-"))),
        ] for item in ffuf_vhosts]
        nuclei_grouped = Counter(
            (
                str(item.get("severity") or "unknown"),
                item.get("template_id") or "-",
                item.get("name") or "-",
                item.get("matched") or item.get("host") or "-",
            )
            for item in nuclei
        )
        nuclei_rows = [[
            html.escape(str(severity)),
            html.escape(template_id),
            html.escape(name),
            html.escape(matched),
            html.escape(str(count)),
        ] for (severity, template_id, name, matched), count in nuclei_grouped.items()]
        nikto_rows = [[html.escape(line)] for line in nikto]
        whatweb_rows = []
        for record in whatweb:
            details = []
            for plugin in record.get("plugins", []):
                values = " | ".join(plugin.get("values") or ["detectado"])
                details.append(
                    f"<div><strong>{html.escape(plugin.get('name') or 'Detalhe')}:</strong> "
                    f"{html.escape(values)}</div>"
                )

            whatweb_rows.append([
                html.escape(record.get("url") or "-"),
                html.escape(record.get("status") or "-"),
                "".join(details) or "-",
            ])

        seed_rows = [[
            html.escape(item.get("source") or "-"),
            html.escape(item.get("url") or "-"),
        ] for item in result.get("seed_evidence", [])]

        wafw00f_rows = [
            ["Detectado", "Sim" if wafw00f.get("detected") else "Não"],
            [
                "Produto(s)",
                html.escape(", ".join(wafw00f.get("wafs") or []) or "-"),
            ],
            [
                "Requisições",
                html.escape(str(wafw00f.get("requests") or "-")),
            ],
        ]

        service_sections.append(f"""
<section class="service">
<h2>{html.escape(service['url'])}</h2>

<h3>Resumo / Fingerprint</h3>
{html_table(["Campo", "Valor"], fingerprint_rows)}

<h3>WhatWeb - identificação</h3>
{html_table(["URL", "Status", "Identificações"], whatweb_rows)}

<h3>WAFW00F - identificação de WAF</h3>
{html_table(["Campo", "Resultado"], wafw00f_rows)}

<h3>Caminhos descobertos automaticamente</h3>
<p class="muted">Sementes obtidas do Nmap, robots.txt e sitemap.xml e reaproveitadas na enumeração.</p>
{html_table(["Origem", "URL"], seed_rows)}

<h3>Headers HTTP</h3>
{html_table(["Header", "Valor"], header_rows)}

<h3>Cookies observados</h3>
{html_table(["Nome", "Valor", "Domínio", "Path"], cookie_rows)}

<h3>Formulários</h3>
{html_table(["Método", "Action", "Campos", "Origem"], form_rows)}

<h3>Parâmetros</h3>
<p class="muted">Entradas equivalentes são agrupadas por método, rota e conjunto de parâmetros. A coluna de possíveis testes é heurística e serve apenas para priorização manual.</p>
{html_table(["Método", "Rota", "Parâmetros", "Possíveis testes relacionados", "Ocorrências", "Exemplo"], parameter_rows)}

<h3>Arquivos JavaScript</h3>
{html_table(["Arquivo .js / .mjs / .cjs"], javascript_rows)}

<h3>APIs encontradas</h3>
{html_table(["Endpoint"], api_rows)}

<h3>Palavras interessantes no código-fonte</h3>
{html_table(["Palavra", "Ocorrências"], source_word_rows)}

<h3>Possíveis credenciais e segredos</h3>
<p class="muted">Detecção heurística contextual. Pares de identidade/segredo, hashes, tokens e chaves são priorizados por score; a classificação não confirma por si só a validade da credencial.</p>
{html_table(["Confiança", "Score", "Tipo", "URL", "Linha", "Campo(s)", "Valor(es)", "Classificação", "Contexto"], sensitive_rows)}

<h3>Domínios encontrados no código-fonte</h3>
{html_table(["Domínio"], domain_rows)}

<h3>FFUF - diretórios e arquivos</h3>
{html_table(["Status", "URL", "Length", "Redirect"], ffuf_rows)}

<h3>FFUF - virtual hosts</h3>
{html_table(["VHost", "Status", "Length"], vhost_rows)}

<h3>Nuclei</h3>
{html_table(["Severidade", "Template", "Finding", "Match", "Ocorrências"], nuclei_rows)}

<h3>Nikto</h3>
{html_table(["Resultado"], nikto_rows)}

<details>
<summary>Katana - resumo ({len(katana_urls)} URLs brutas → {katana_summary["unique_patterns"]} padrões)</summary>
<p class="muted">A lista bruta completa permanece no arquivo katana_urls.txt. Aqui as variações de valores de query string são consolidadas.</p>
{html_table(["Ocorrências", "Padrão", "Exemplo"], katana_rows)}
</details>

<details>
<summary>Links href encontrados ({len(source['hrefs'])})</summary>
{html_table(["href"], href_rows)}
</details>

<details>
<summary>Assets src encontrados ({len(source['srcs'])})</summary>
{html_table(["src"], src_rows)}
</details>
</section>
""")

    missing_html = ", ".join(html.escape(tool) for tool in missing_tools) if missing_tools else "Nenhuma"
    sensitive_total = sum(len((result.get("source") or {}).get("sensitive_findings") or []) for result in web_results)

    body = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>L1ght Recon - {html.escape(target)}</title>
<style>
body {{ margin:0; background:#0f172a; color:#e5e7eb; font-family:Arial,Helvetica,sans-serif; }}
main {{ max-width:1450px; margin:0 auto; padding:32px; }}
h1,h2,h3 {{ color:#93c5fd; }}
.subtitle,.muted {{ color:#94a3b8; }}
.summary {{ display:flex; flex-wrap:wrap; gap:12px; margin:24px 0; }}
.card {{ background:#1e293b; border:1px solid #334155; border-radius:8px; padding:16px; min-width:160px; }}
.card .number {{ display:block; margin-top:6px; font-size:28px; font-weight:bold; }}
.service {{ margin-top:38px; padding:24px; background:#111827; border:1px solid #334155; border-radius:10px; }}
.table-wrap {{ overflow-x:auto; margin-bottom:24px; }}
.method-cell {{ white-space:nowrap; min-width:64px; display:inline-block; }}
td {{ overflow-wrap:anywhere; }}
table {{ width:100%; border-collapse:collapse; background:#1e293b; }}
th,td {{ border-bottom:1px solid #334155; padding:9px 10px; text-align:left; vertical-align:top; word-break:break-word; }}
th {{ background:#334155; }}
.notice {{ background:#312e81; border-radius:8px; padding:14px; margin:16px 0; }}
details {{ margin:18px 0; }}
summary {{ cursor:pointer; color:#bfdbfe; font-weight:bold; }}
</style>
</head>
<body>
<main>
<h1>L1ght Recon</h1>
<div class="subtitle">Scanning &amp; Enumeration - versão {VERSION}</div>

<p><strong>Alvo:</strong> {html.escape(target)}</p>
<p><strong>Host:</strong> {html.escape(host)}</p>
<p><strong>Execução:</strong> {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}</p>
<p><strong>Ferramentas ausentes:</strong> {missing_html}</p>
<div class="notice">As associações feitas na seção de parâmetros são apenas heurísticas para orientar testes manuais e não confirmam vulnerabilidades.</div>
<div class="summary">
<div class="card">TCP abertas<span class="number">{len(open_ports)}</span></div>
<div class="card">UDP abertas<span class="number">{len(udp_ports)}</span></div>
<div class="card">UDP open|filtered<span class="number">{len(udp_candidates)}</span></div>
<div class="card">Serviços enumerados<span class="number">{len(service_results)}</span></div>
<div class="card">Serviços Web<span class="number">{len(web_results)}</span></div>
<div class="card">Possíveis segredos<span class="number">{sensitive_total}</span></div>
</div>

<h2>Portas TCP, serviços e resultados NSE</h2>
{html_table(["Porta", "Serviço", "Produto / versão", "NSE"], port_rows)}

<h2>Portas UDP confirmadas como abertas</h2>
{html_table(["Porta", "Serviço", "Produto / versão", "NSE"], udp_rows)}

<h2>Portas UDP open|filtered (não confirmadas)</h2>
<div class="notice">Essas portas permaneceram ambíguas após a confirmação direcionada e não são contadas como abertas.</div>
{html_table(["Porta", "Estado", "Serviço provável", "Produto / versão", "Razão"], udp_candidate_rows)}

<h2>Enumeração automática dos serviços</h2>
{html_table(["Perfil", "Porta", "Serviço", "Produto / versão", "NSE", "Detalhes"], service_enum_rows)}

{''.join(service_sections)}
<div class="report-footer">
    {html.escape(HANDLE)} · Rafael Ademilton
</div>

</main>
</body>
</html>
"""
    report_file.write_text(body, encoding="utf-8")
    return report_file


def print_final_port_table(title, ports):
    print()
    print(f"{BOLD}{title}{RESET}")

    if not ports:
        print("  Nenhum resultado.")
        return

    print(f"  {'PORTA':<12}{'SERVIÇO':<20}PRODUTO / VERSÃO")
    print("  " + "-" * 72)

    for item in ports:
        port_text = f"{item.get('port')}/{item.get('protocol', 'tcp')}"
        description = " ".join(
            value
            for value in [
                item.get("product") or "",
                item.get("version") or "",
                item.get("extrainfo") or "",
            ]
            if value
        )

        print(
            f"  {port_text:<12}"
            f"{(item.get('service') or 'unknown'):<20}"
            f"{description}"
        )


def print_final_web_summary(all_results):
    print()
    print(f"{BOLD}SERVIÇOS WEB{RESET}")

    if not all_results:
        print("  Nenhum serviço Web confirmado.")
        return

    for result in all_results:
        service = result["service"]
        source = result["source"]
        waf = result.get("wafw00f") or {}

        print()
        print(f"  {BOLD}{service['url']}{RESET}")
        print(f"    Status.................: {service.get('status') or '-'}")
        print(f"    Título.................: {service.get('title') or '-'}")
        print(
            "    Tecnologias............: "
            + (", ".join(service.get("tech") or []) or "-")
        )
        print(f"    Katana URLs............: {len(result.get('katana_urls') or [])}")
        print(f"    FFUF conteúdo..........: {len(result.get('ffuf_content') or [])}")
        print(f"    FFUF vhosts............: {len(result.get('ffuf_vhosts') or [])}")
        print(f"    Formulários............: {len(source.get('forms') or [])}")
        print(f"    Padrões de parâmetros..: {len(result.get('parameters') or [])}")
        print(f"    APIs...................: {len(source.get('api_endpoints') or [])}")
        print(f"    JavaScript.............: {len(result.get('javascript') or [])}")
        print(
            "    WAFW00F................: "
            + (
                "WAF detectado: " + ", ".join(waf.get("wafs") or [])
                if waf.get("detected")
                else "sem WAF detectado"
            )
        )
        print(f"    Nuclei.................: {len(result.get('nuclei') or [])}")
        print(f"    Nikto..................: {len(result.get('nikto') or [])}")

        parameters = result.get("parameters") or []

        if parameters:
            print("    Parâmetros priorizados.:")

            for record in parameters[:10]:
                vectors = ", ".join(record.get("vectors") or []) or "sem heurística"
                params = ", ".join(record.get("parameters") or [])
                count = int(record.get("count") or 1)
                route = record.get("route") or record.get("url") or "-"
                suffix = f" ({count} variações)" if count > 1 else ""
                print(
                    f"      [{record.get('method')}] {route} | "
                    f"{params} -> {vectors}{suffix}"
                )

            if len(parameters) > 10:
                print(
                    f"      ... +{len(parameters) - 10} padrão(ões) no relatório"
                )


def format_execution_time(seconds):
    total = max(0, int(round(float(seconds or 0))))
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours:02d}h {minutes:02d}m {secs:02d}s"
    if minutes:
        return f"{minutes:02d}m {secs:02d}s"
    return f"{secs}s"


def print_final_compilation(
    target,
    open_ports,
    udp_ports,
    udp_candidates,
    service_results,
    all_results,
    web_services,
    args,
    extensions,
    cookie,
    output_dir,
    html_report,
    elapsed_seconds,
):
    section("FINAL")

    print(f"Alvo.....................: {target}")
    print(f"Portas TCP abertas.......: {len(open_ports)}")
    print(f"Portas UDP abertas.......: {len(udp_ports)}")
    print(f"UDP open|filtered........: {len(udp_candidates)}")
    print(f"Perfil...................: {'full' if args.full else 'padrão'}")
    print(f"UDP top ports............: {args.udp_top}")
    print(f"Serviços enumerados......: {len(service_results)}")
    print(f"Serviços Web.............: {len(web_services)}")
    print(f"Wordlist FFUF............: {args.wordlist}")
    print(
        f"Extensões FFUF...........: "
        f"{extensions if extensions else 'sem extensões adicionais'}"
    )
    print(f"Depth Katana.............: {args.depth}")
    print(f"Depth FFUF...............: {args.ffuf_depth}")
    print(f"Sessão autenticada.......: {'sim' if cookie else 'não'}")
    print(f"Low-noise................: {'sim' if LOW_NOISE else 'não'}")
    print(
        f"Timeout por comando......: "
        f"{'desabilitado' if COMMAND_TIMEOUT == 0 else str(COMMAND_TIMEOUT) + 's'}"
    )

    print_final_port_table("PORTAS TCP", open_ports)
    print_final_port_table("PORTAS UDP — CONFIRMADAS OPEN", udp_ports)
    if udp_candidates:
        print()
        print(f"{BOLD}PORTAS UDP — OPEN|FILTERED (NÃO CONFIRMADAS){RESET}")
        print(f"  {'PORTA':<12}{'SERVIÇO':<20}{'RAZÃO'}")
        print("  " + "-" * 72)
        for item in udp_candidates:
            print(
                f"  {str(item.get('port')) + '/udp':<12}"
                f"{(item.get('service') or 'unknown'):<20}"
                f"{item.get('reason') or '-'}"
            )

    print()
    print(f"{BOLD}ENUMERAÇÃO DOS SERVIÇOS{RESET}")

    if service_results:
        print_service_enumeration(service_results)
    else:
        print("  Nenhum resultado adicional.")

    print_final_web_summary(all_results)

    print()
    print(f"{BOLD}ARTEFATOS{RESET}")
    print(f"  Diretório...............: {output_dir}")
    print(f"  Relatório HTML..........: {html_report}")
    if DEBUG_LOG_PATH is not None:
        print(f"  Log detalhado...........: {DEBUG_LOG_PATH}")
    print(f"  {DIM}O HTML contém detalhes adicionais que não são exibidos no terminal.{RESET}")

    print()
    print(f"{DIM}Tempo de execução: {format_execution_time(elapsed_seconds)}{RESET}")
    success(f"{brand()} finalizado.")
    print(f"{DIM}{HANDLE} · Rafael Ademilton{RESET}")

    print()
    print("Abra o relatório com:\n")
    print(f"  firefox '{html_report}'")
    print()


# ============================================================
# Main
# ============================================================

def main():
    # Limpa backups legados antes de qualquer early-return (--check-update, -h etc.).
    cleanup_legacy_update_backups()

    # Antes do argparse: uma versão antiga pode se atualizar e reiniciar
    # antes de rejeitar flags novas ainda desconhecidas localmente.
    preparse_auto_update()

    examples = """
Exemplos:
  python3 l1ght_recon.py -t 192.168.92.206
  python3 l1ght_recon.py -t 192.168.92.206:28080
  python3 l1ght_recon.py -t http://192.168.92.206:28080/
  python3 l1ght_recon.py -t rollback.cige
  python3 l1ght_recon.py -t 192.168.92.206 --vhost-domain rollback.cige
  python3 l1ght_recon.py -t 192.168.92.206 --wordlist /caminho/wordlist.txt
  python3 l1ght_recon.py -t 192.168.92.206 -e php,html,txt,js
  python3 l1ght_recon.py -t 192.168.92.206 --depth 4 --ffuf-depth 2
  python3 l1ght_recon.py -t 192.168.92.206 -c 'PHPSESSID=abc123; role=user'
  python3 l1ght_recon.py -t 192.168.92.206 --low-noise
  python3 l1ght_recon.py -t 192.168.92.206 --timeout 900
  python3 l1ght_recon.py -t 192.168.92.206 --log
  python3 l1ght_recon.py -t 192.168.92.206 --full
  python3 l1ght_recon.py -t 192.168.92.206 --udp-top 300
  python3 l1ght_recon.py --check-update
  python3 l1ght_recon.py --update
  python3 l1ght_recon.py -t 192.168.92.206 --no-update

Fluxo:
  1. Coleta de rede/DNS quando aplicável.
  2. Nmap TCP rápido -> detalhamento somente das portas abertas.
  3. Scan UDP e enumeração de serviços em segundo plano.
  4. HTTPX/Katana e análise Web.
  5. Resultados de background são exibidos assim que cada ferramenta termina.
  6. NFS/mountd, RPC, SNMP e demais serviços são aprofundados.
  7. Seção FINAL compila os resultados e gera HTML.
"""

    parser = argparse.ArgumentParser(
        prog="l1ght_recon.py",
        description=(
            f"{brand()} - Scanning & Enumeration.\n"
            "Ferramenta de scanning e enumeração para laboratórios e CTFs."
        ),
        epilog=examples,
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "--flow",
        action="store_true",
        help=(
            "Exibe um resumo do fluxo interno e os comandos utilizados "
            "pela ferramenta, sem executar a enumeração."
        ),
    )
    parser.add_argument(
        "-t",
        "--target",
        required=False,
        help=(
            "Alvo da enumeração. Aceita IP, hostname, IP:porta ou URL.\n"
            "Ex.: 192.168.92.206 | 192.168.92.206:8080 | http://alvo:8080/"
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        help=(
            "Diretório de saída.\n"
            "Padrão: recon_<host>_<data_hora>"
        ),
    )
    parser.add_argument(
        "--log",
        nargs="?",
        const="AUTO",
        default=None,
        metavar="ARQUIVO",
        help=(
            "Registra log detalhado de auditoria. Sem ARQUIVO, usa debug.log "
            "no diretório da execução."
        ),
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help=(
            "Modo completo para quem prioriza cobertura em vez de tempo.\n"
            "Aumenta Katana, FFUF, análise de fonte e UDP para um perfil mais profundo,\n"
            "mantendo o UDP limitado a um valor razoável (400 portas por padrão)."
        ),
    )
    parser.add_argument(
        "--udp-top",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Quantidade de portas UDP mais frequentes a testar.\n"
            f"Padrão: {DEFAULT_UDP_TOP_PORTS}; --full: {FULL_UDP_TOP_PORTS}; máximo: {MAX_UDP_TOP_PORTS}."
        ),
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=3,
        help=(
            "Profundidade máxima do crawling do Katana.\n"
            "Padrão: 3"
        ),
    )
    parser.add_argument(
        "--ffuf-depth",
        type=int,
        default=1,
        help=(
            "Profundidade máxima de recursão do FFUF.\n"
            "Equivale ao parâmetro -recursion-depth do FFUF.\n"
            "Padrão: 1"
        ),
    )
    parser.add_argument(
        "-w",
        "--wordlist",
        default=DEFAULT_CONTENT_WORDLIST,
        help=(
            "Wordlist usada pelo FFUF para diretórios e arquivos.\n"
            f"Padrão: {DEFAULT_CONTENT_WORDLIST}"
        ),
    )
    parser.add_argument(
        "-e",
        "--extensions",
        default=None,
        help=(
            "Extensões usadas pelo FFUF no content discovery.\n"
            "Ex.: php,html,txt,js ou .php,.html,.txt\n"
            "Use '-' para não adicionar extensões.\n"
            "Automático: php,html,txt; acrescenta asp,aspx quando Windows/IIS é identificado."
        ),
    )
    parser.add_argument(
        "--vhost-wordlist",
        default=DEFAULT_VHOST_WORDLIST,
        help=(
            "Wordlist usada pelo FFUF para virtual hosts.\n"
            f"Padrão: {DEFAULT_VHOST_WORDLIST}"
        ),
    )
    parser.add_argument(
        "--vhost-domain",
        help=(
            "Domínio-base usado na enumeração de virtual hosts.\n"
            "Ex.: --vhost-domain rollback.cige\n"
            "Quando o alvo é apenas IP e este parâmetro não é informado,\n"
            "a enumeração de vhosts é ignorada."
        ),
    )
    parser.add_argument(
        "-c",
        "--cookie",
        help=(
            "Cookie de sessão para enumeração autenticada.\n"
            "Ex.: -c 'PHPSESSID=abc123; role=user'\n"
            "O valor não é exibido no relatório nem no terminal."
        ),
    )
    parser.add_argument(
        "--source-limit",
        type=int,
        default=25,
        help=(
            "Máximo de páginas gerais por serviço Web para análise de fonte.\n"
            "Recursos textuais sensíveis priorizados não consomem esse limite.\n"
            "Padrão: 25"
        ),
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=0,
        help=(
            "Limite de tempo em segundos por comando externo.\n"
            "Resultados parciais são preservados. Use 0 para desabilitar.\n"
            "Padrão: desabilitado (0)"
        ),
    )
    parser.add_argument(
        "--low-noise",
        action="store_true",
        help=(
            "Reduz agressividade do scanning: Nmap T2/--version-light sem -sC global, limita taxa do FFUF/Nuclei "
            "e evita scripts NSE de vulnerabilidade na enumeração de serviços. "
            "Não garante furtividade."
        ),
    )
    parser.add_argument(
        "--skip-udp",
        action="store_true",
        help="Não executa o scan UDP em segundo plano.",
    )
    parser.add_argument(
        "--skip-service-enum",
        action="store_true",
        help="Não executa a enumeração automática dos serviços.",
    )
    parser.add_argument(
        "--skip-ffuf",
        action="store_true",
        help="Não executa FFUF de conteúdo nem de virtual hosts.",
    )
    parser.add_argument(
        "--skip-nikto",
        action="store_true",
        help="Não executa Nikto.",
    )
    parser.add_argument(
        "--skip-nuclei",
        action="store_true",
        help="Não executa Nuclei.",
    )
    parser.add_argument(
        "--skip-whatweb",
        action="store_true",
        help="Não executa WhatWeb.",
    )
    parser.add_argument(
        "--skip-wafw00f",
        action="store_true",
        help="Não executa WAFW00F.",
    )

    update_group = parser.add_mutually_exclusive_group()
    update_group.add_argument(
        "--check-update",
        action="store_true",
        help=(
            "Verifica e instala automaticamente uma versão mais nova, "
            "se existir, e encerra."
        ),
    )
    update_group.add_argument(
        "--update",
        action="store_true",
        help=(
            "Força a verificação e instala uma versão mais nova, se existir. "
            "Sem -t/--target, encerra após a operação."
        ),
    )
    update_group.add_argument(
        "--no-update",
        action="store_true",
        help=(
            "Não consulta o servidor de atualização nesta execução."
        ),
    )

    args = parser.parse_args()

    global COMMAND_TIMEOUT, LOW_NOISE
    COMMAND_TIMEOUT = args.timeout
    LOW_NOISE = args.low_noise

    if args.udp_top is not None and not (1 <= args.udp_top <= MAX_UDP_TOP_PORTS):
        parser.error(f"--udp-top deve ficar entre 1 e {MAX_UDP_TOP_PORTS}.")
    if args.udp_top is None:
        args.udp_top = FULL_UDP_TOP_PORTS if args.full else DEFAULT_UDP_TOP_PORTS
    if args.full:
        args.depth = max(args.depth, 5)
        args.ffuf_depth = max(args.ffuf_depth, 2)
        args.source_limit = max(args.source_limit, 60)
        info(
            f"Modo full habilitado: Katana depth={args.depth}, FFUF depth={args.ffuf_depth}, "
            f"source-limit={args.source_limit}, UDP top {args.udp_top}."
        )
    configure_web_scheduler(full_mode=args.full)

    if args.check_update:
        handle_update_check(
            install=True,
            restart=False,
            verbose=True,
        )
        return

    if args.update:
        handle_update_check(
            install=True,
            restart=bool(args.target),
            verbose=True,
        )

        if not args.target:
            return

    # A checagem automática das execuções normais já ocorreu antes do argparse.
    banner()

    if args.flow:
        print_flow()
        return

    if not args.target:
        parser.error(
            "o parâmetro -t/--target é obrigatório, exceto com "
            "--flow, --check-update ou --update."
        )

    execution_started = time.monotonic()

    extensions = None

    if args.ffuf_depth < 1:
        parser.error("--ffuf-depth deve ser igual ou maior que 1.")

    if args.timeout < 0:
        parser.error("--timeout deve ser igual ou maior que 0.")

    cookie = args.cookie.strip() if args.cookie else None

    if cookie:
        info("Cookie de sessão fornecido; enumeração autenticada habilitada.")

    if LOW_NOISE:
        info(
            "Modo low-noise habilitado: temporização e taxas reduzidas. "
            "Isso não torna a varredura furtiva."
        )

    target = normalize_target(args.target)

    try:
        host = target_host(target)
    except ValueError as exc:
        error(str(exc))
        sys.exit(1)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(
        args.output
        or f"recon_{safe_name(host)}_{timestamp}"
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.log is not None:
        log_path = output_dir / "debug.log" if args.log == "AUTO" else Path(args.log)
        init_debug_log(log_path, cookie=cookie)
        info(f"Log detalhado habilitado: {DEBUG_LOG_PATH}")

    ensure_path_command()
    tools = check_external_tools(auto_setup=True)

    if not tools["nmap"]:
        error(f"Nmap é necessário para o fluxo principal do {brand()}.")
        sys.exit(1)

    auxiliary_executor = ThreadPoolExecutor(max_workers=3 if LOW_NOISE else 4)
    udp_future = None
    service_future = None
    smb_anonymous_future = None
    info_future = auxiliary_executor.submit(
        run_information_gathering,
        host,
        target,
        output_dir,
    )

    if not args.skip_udp:
        info(
            "Iniciando scan UDP em segundo plano; "
            "o resultado será apresentado somente no final."
        )
        udp_future = auxiliary_executor.submit(
            run_udp_scan,
            host,
            output_dir,
            args.udp_top,
        )

    nmap_started = metric_start("nmap_tcp")
    open_ports = run_nmap(host, output_dir)
    metric_end("nmap_tcp", nmap_started, open_ports=len(open_ports))

    if not open_ports:
        warning(
            "Nenhuma porta TCP aberta foi identificada. "
            "O fluxo continuará para considerar resultados UDP."
        )

    if open_ports and not args.skip_service_enum:
        info(
            "Iniciando enumeração básica dos serviços em segundo plano."
        )
        service_future = auxiliary_executor.submit(
            run_service_enumeration,
            host,
            open_ports,
            output_dir,
            True,
        )
        if any(int(item.get("port", 0)) in {139, 445} for item in open_ports):
            smb_anonymous_future = auxiliary_executor.submit(
                run_rpc_anonymous_enum,
                host,
                open_ports,
                output_dir,
                {"entries": [], "raw": ""},
            )

    web_services = []

    if open_ports and tools["httpx"]:
        httpx_started = metric_start("httpx_probe")
        web_services = probe_web_services(
            host,
            open_ports,
            output_dir,
            cookie=cookie,
        )
        metric_end("httpx_probe", httpx_started, services=len(web_services))
    elif open_ports and not tools["httpx"]:
        warning(
            "HTTPX não está disponível; a identificação automática "
            "de serviços Web será ignorada."
        )

    if not web_services:
        warning(
            "Nenhum serviço Web foi confirmado; "
            "a enumeração de serviços e UDP continuará normalmente."
        )

    extensions = resolve_ffuf_extensions(
        args.extensions,
        open_ports,
        web_services,
    )

    vhost_domain = args.vhost_domain

    if not vhost_domain and not is_ip(host):
        vhost_domain = host

    if web_services and not vhost_domain and is_ip(host):
        warning(
            "Alvo é IP e --vhost-domain não foi informado; "
            "enumeração de virtual hosts será ignorada."
        )

    if web_services:
        section("3. ENUMERAÇÃO WEB POR SERVIÇO")

    # Prepare service folders and result objects first.
    result_by_key = {}

    for service in web_services:
        key = (service["port"], service["scheme"])
        service_dir = output_dir / f"web_{service['port']}_{service['scheme']}"
        service_dir.mkdir(parents=True, exist_ok=True)

        result_by_key[key] = {
            "service": service,
            "service_dir": service_dir,
            "seed_evidence": build_service_seed_evidence(
                service,
                open_ports,
                cookie=cookie,
            ),
            "katana_urls": [service["url"]],
            "katana_forms": [],
            "ffuf_content": [],
            "ffuf_vhosts": [],
            "source": None,
            "source_cache": {},
            "parameters": [],
            "javascript": [],
            "nikto": [],
            "nuclei": [],
            "whatweb": [],
            "wafw00f": {},
            "public_exploits": [],
            "preliminary_parameters": [],
        }

    # Start the slower tools immediately and let them run while Katana/source
    # analysis continues.
    background_jobs = {}
    max_workers = (
        2
        if LOW_NOISE
        else max(1, min(16, len(web_services) * 6))
    )

    executor = ThreadPoolExecutor(max_workers=max_workers)

    def submit_background(fn, key, field, *fn_args):
        future = executor.submit(_run_weighted_background, field, fn, *fn_args)
        background_jobs[future] = (key, field)
        return future

    processed_background = set()
    background_section_started = False
    foreground_complete = False

    def ensure_background_section():
        nonlocal background_section_started
        if background_section_started:
            return
        background_section_started = True
        section("4. RESULTADOS DAS VARREDURAS EM SEGUNDO PLANO")
        info(
            "As varreduras demoradas continuam em segundo plano. "
            "Cada resultado é exibido assim que fica pronto, em blocos atômicos."
        )

    def consume_background_future(future, display=True):
        if future in processed_background:
            return None
        processed_background.add(future)
        key, field = background_jobs[future]
        service_url = result_by_key[key]["service"]["url"]
        try:
            value = future.result()
            result_by_key[key][field] = value
        except Exception as exc:
            value = [] if field != "wafw00f" else {}
            result_by_key[key][field] = value
            warning(f"Falha na tarefa {field} de {service_url}: {exc}")
            _debug_log("BACKGROUND_EXCEPTION", f"field={field} service={service_url} exc={exc!r}")
        if display and field not in {"wafw00f", "public_exploits"}:
            if foreground_complete:
                ensure_background_section()
            if field == "whatweb":
                print_whatweb_results(service_url, value)
            elif field == "ffuf_content":
                drain_ffuf_partial_blocks()
                print_ffuf_finished(service_url, value, label="FFUF")
            elif field == "ffuf_vhosts":
                print_vhost_results(service_url, value)
            elif field == "nuclei":
                print_nuclei_results(service_url, value)
            elif field == "nikto":
                print_nikto_results(service_url, value)
        return service_url, field, value

    def drain_ready_background():
        drain_ffuf_partial_blocks()
        for future in list(background_jobs):
            if future not in processed_background and future.done():
                consume_background_future(future, display=True)


    try:
        for service in web_services:
            key = (service["port"], service["scheme"])
            service_dir = result_by_key[key]["service_dir"]

            seed_urls = [
                item["url"]
                for item in result_by_key[key]["seed_evidence"]
            ]

            print_seed_evidence(
                service["url"],
                result_by_key[key]["seed_evidence"],
            )

            if tools["ffuf"] and not args.skip_ffuf:
                info(
                    f"Iniciando FFUF em {service['url']} - "
                    "diretórios e arquivos em segundo plano."
                )
                submit_background(
                    run_ffuf_content,
                    key,
                    "ffuf_content",
                    service,
                    service_dir,
                    args.wordlist,
                    extensions,
                    args.ffuf_depth,
                    cookie,
                    seed_urls,
                    False,
                    args.full,
                )

                if vhost_domain:
                    info(
                        f"Iniciando FFUF VHosts em {service['url']} "
                        f"para {vhost_domain}."
                    )
                    submit_background(
                        run_ffuf_vhosts,
                        key,
                        "ffuf_vhosts",
                        service,
                        service_dir,
                        args.vhost_wordlist,
                        vhost_domain,
                        cookie,
                        False,
                    )

            if tools["nikto"] and not args.skip_nikto:
                info(
                    f"Iniciando Nikto em {service['url']} "
                    "em segundo plano."
                )
                submit_background(
                    run_nikto,
                    key,
                    "nikto",
                    service,
                    service_dir,
                    cookie,
                    False,
                )

            if tools["nuclei"] and not args.skip_nuclei:
                info(
                    f"Iniciando Nuclei em {service['url']} "
                    "em segundo plano."
                )
                submit_background(
                    run_nuclei,
                    key,
                    "nuclei",
                    service,
                    service_dir,
                    cookie,
                    False,
                )

            if tools["whatweb"] and not args.skip_whatweb:
                info(
                    f"Iniciando WhatWeb em {service['url']} "
                    "em segundo plano."
                )
                submit_background(
                    run_whatweb,
                    key,
                    "whatweb",
                    service,
                    service_dir,
                    cookie,
                    False,
                )

            if tools["wafw00f"] and not args.skip_wafw00f:
                info(
                    f"Iniciando WAFW00F em {service['url']} "
                    "em segundo plano."
                )
                submit_background(
                    run_wafw00f,
                    key,
                    "wafw00f",
                    service,
                    service_dir,
                    cookie,
                    False,
                )

            if tools.get("searchsploit"):
                submit_background(
                    search_web_public_exploits,
                    key,
                    "public_exploits",
                    service,
                    output_dir,
                )

        if background_jobs:
            print()
            success(
                f"{len(background_jobs)} varredura(s) complementar(es) "
                "iniciada(s) em segundo plano."
            )

        # Foreground work: Katana and source analysis on every Web service.
        for index, service in enumerate(web_services, start=1):
            key = (service["port"], service["scheme"])
            result = result_by_key[key]
            service_dir = result["service_dir"]

            print()
            print(
                f"{BOLD}[{index}/{len(web_services)}] "
                f"{service['url']}{RESET}"
            )

            if tools["katana"]:
                katana_urls, katana_forms = run_katana(
                    service,
                    service_dir,
                    args.depth,
                    cookie=cookie,
                    seed_urls=[
                        item["url"]
                        for item in result["seed_evidence"]
                    ],
                    progress_callback=drain_ready_background,
                )
            else:
                katana_urls = [service["url"]]
                katana_forms = []

            result["katana_urls"] = katana_urls
            result["katana_forms"] = katana_forms

            print_katana_results(
                service["url"],
                katana_urls,
            )
            drain_ffuf_partial_blocks()

            if katana_forms:
                (service_dir / "katana_forms.json").write_text(
                    json.dumps(
                        katana_forms,
                        indent=2,
                        ensure_ascii=False,
                    ),
                    encoding="utf-8",
                )

            info(
                f"Analisando {service['url']} — headers, cookies, "
                "formulários, parâmetros, APIs e código-fonte..."
            )

            result["source"] = analyze_source(
                service,
                katana_urls
                + [
                    item["url"]
                    for item in result["seed_evidence"]
                ],
                [],
                limit=args.source_limit,
                cookie=cookie,
                response_cache=result["source_cache"],
            )

            preliminary_urls = set(katana_urls)
            preliminary_urls.update(
                item["url"]
                for item in result["seed_evidence"]
            )
            preliminary_urls.update(result["source"]["hrefs"])
            preliminary_urls.update(result["source"]["srcs"])
            preliminary_urls.update(result["source"]["api_endpoints"])
            preliminary_urls = {
                url
                for url in preliminary_urls
                if not is_noise_url(url)
            }

            preliminary_parameters = collect_parameter_records(
                preliminary_urls,
                result["source"],
            )
            result["preliminary_parameters"] = preliminary_parameters

            print_parameter_results(
                service["url"],
                preliminary_parameters,
            )
            drain_ready_background()

        foreground_complete = True
        if background_jobs:
            pending = set(background_jobs) - processed_background
            if pending:
                ensure_background_section()
            background_wait_started = metric_start("web_background_wait", jobs=len(pending))
            while pending:
                drain_ffuf_partial_blocks()
                done, pending = wait(pending, timeout=1.0, return_when=FIRST_COMPLETED)
                for future in done:
                    consume_background_future(future, display=True)
            drain_ffuf_partial_blocks()
            metric_end("web_background_wait", background_wait_started)

    finally:
        executor.shutdown(wait=True, cancel_futures=False)

    # Consolidate each service only after every background result is ready.
    all_results = []

    for service in web_services:
        key = (service["port"], service["scheme"])
        result = result_by_key[key]
        service_dir = result["service_dir"]

        # Reanalisa as páginas agora que o FFUF também terminou, para incluir
        # conteúdo descoberto fora do crawling do Katana.
        source = analyze_source(
            service,
            result["katana_urls"]
            + [
                item["url"]
                for item in result["seed_evidence"]
            ],
            result["ffuf_content"],
            limit=args.source_limit,
            cookie=cookie,
            response_cache=result["source_cache"],
        )
        result["source"] = source
        sensitive_findings = source.get("sensitive_findings") or []
        (service_dir / "sensitive_findings.json").write_text(
            json.dumps(sensitive_findings, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print_sensitive_findings(service["url"], sensitive_findings)

        discovered_urls = set(result["katana_urls"])
        discovered_urls.add(service["url"])
        discovered_urls.update(
            item["url"]
            for item in result["seed_evidence"]
        )

        for item in result["ffuf_content"]:
            url = item.get("url")
            if url:
                discovered_urls.add(url)

        discovered_urls.update(source["hrefs"])
        discovered_urls.update(source["srcs"])
        discovered_urls.update(source["api_endpoints"])
        discovered_urls = {
            url
            for url in discovered_urls
            if not is_noise_url(url)
        }

        write_lines(
            service_dir / "all_urls.txt",
            discovered_urls,
        )

        parameter_records = collect_parameter_records(
            discovered_urls,
            source,
        )

        write_parameter_csv(
            service_dir / "parameters.csv",
            parameter_records,
        )

        javascript = collect_javascript_files(discovered_urls, source)
        result["parameters"] = parameter_records
        result["javascript"] = javascript

        preliminary_keys = {
            (
                item.get("method"),
                item.get("url"),
                tuple(item.get("parameters") or []),
            )
            for item in result.get("preliminary_parameters", [])
        }

        new_parameter_records = [
            item
            for item in parameter_records
            if (
                item.get("method"),
                item.get("url"),
                tuple(item.get("parameters") or []),
            )
            not in preliminary_keys
        ]

        if new_parameter_records:
            print_parameter_results(
                service["url"],
                new_parameter_records,
                title="Novos parâmetros após a enumeração complementar",
            )

        # Remove internal-only field before HTML generation.
        result.pop("service_dir", None)
        result.pop("katana_forms", None)
        result.pop("preliminary_parameters", None)
        result.pop("source_cache", None)
        all_results.append(result)

    service_results = []
    udp_ports = []
    udp_candidates = []

    if service_future is not None:
        try:
            service_results.extend(
                wait_future_with_progress(service_future, "Enumeração de serviços")
            )
        except Exception as exc:
            warning(f"Falha consolidando enumeração de serviços TCP: {exc}")

    early_smb_anonymous = None
    if smb_anonymous_future is not None:
        try:
            early_smb_anonymous = wait_future_with_progress(
                smb_anonymous_future, "Enumeração SMB anônima"
            )
            if early_smb_anonymous:
                service_results.append(early_smb_anonymous)
        except Exception as exc:
            warning(f"Falha consolidando enumeração SMB anônima: {exc}")

    if udp_future is not None:
        try:
            udp_result = wait_future_with_progress(
                udp_future, "Scan UDP", interval=UDP_PROGRESS_INTERVAL
            )
            if isinstance(udp_result, dict):
                udp_ports = udp_result.get("open") or []
                udp_candidates = udp_result.get("open_filtered") or []
            else:
                udp_ports = udp_result or []
            if udp_candidates:
                info(
                    f"UDP: {len(udp_ports)} porta(s) confirmada(s) como open; "
                    f"{len(udp_candidates)} permaneceram open|filtered e não serão contadas como abertas."
                )
        except Exception as exc:
            warning(f"Falha consolidando scan UDP: {exc}")
            udp_ports = []
            udp_candidates = []

    # Se o UDP revelou serviços importantes (SNMP, DNS, etc.),
    # também executa a enumeração específica antes dos relatórios.
    if udp_ports and not args.skip_service_enum:
        try:
            udp_service_results = run_service_enumeration(
                host,
                udp_ports,
                output_dir,
            )
            service_results.extend(udp_service_results)
        except Exception as exc:
            warning(f"Falha enumerando serviços UDP: {exc}")

    information_gathering = {}

    if info_future is not None:
        try:
            information_gathering = info_future.result()
        except Exception:
            information_gathering = {}

    auxiliary_executor.shutdown(wait=True, cancel_futures=False)

    rpc_result = {"entries": [], "raw": ""}

    rpc_candidates = list(open_ports) + list(udp_ports)

    if (
        any(item.get("port") == 111 for item in rpc_candidates)
        or any(item.get("service") == "rpcbind" for item in rpc_candidates)
    ):
        rpc_result = run_rpcinfo_enum(host, output_dir)

    if not args.skip_service_enum:
        nfs_deep = run_nfs_deep_enum(
            host,
            open_ports + udp_ports,
            output_dir,
            rpc_result,
        )

        if nfs_deep:
            service_results.append(nfs_deep)

        rpc_anonymous = None
        if smb_anonymous_future is None:
            rpc_anonymous = run_rpc_anonymous_enum(
                host,
                open_ports,
                output_dir,
                rpc_result,
            )

        if rpc_anonymous:
            service_results.append(rpc_anonymous)

        snmp_public = run_snmp_public_enum(
            host,
            udp_ports,
            output_dir,
        )

        if snmp_public:
            service_results.append(snmp_public)

    # Remove duplicatas de enumeração especializada.
    unique_service_results = []
    seen_service_keys = set()

    for item in service_results:
        key = (
            item.get("profile"),
            item.get("protocol"),
            tuple(item.get("ports") or [item.get("port")]),
        )

        if key in seen_service_keys:
            continue

        seen_service_keys.add(key)
        unique_service_results.append(item)

    service_results = unique_service_results

    # Resultados parciais já foram preservados. Se algo excedeu o limite,
    # oferece uma nova execução sem timeout somente no final.
    offer_continue_timeouts()

    missing_tools = [
        name
        for name, present in tools.items()
        if not present
    ]

    report_started = metric_start("html_report")
    html_report = generate_report(
        target,
        host,
        output_dir,
        open_ports,
        all_results,
        missing_tools,
        udp_ports=udp_ports,
        udp_candidates=udp_candidates,
        service_results=service_results,
    )
    metric_end("html_report", report_started, file=html_report)
    elapsed_seconds = time.monotonic() - execution_started
    _debug_log("EXECUTION", f"total_duration={elapsed_seconds:.3f}s")
    print_final_compilation(
        target,
        open_ports,
        udp_ports,
        udp_candidates,
        service_results,
        all_results,
        web_services,
        args,
        extensions,
        cookie,
        output_dir,
        html_report,
        elapsed_seconds,
    )



if __name__ == "__main__":
    main()

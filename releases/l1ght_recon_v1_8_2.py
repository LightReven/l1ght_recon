#!/usr/bin/env python3

import argparse
import csv
import hashlib
import os
import textwrap
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
import html
import ipaddress
import json
import re
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

import requests
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ============================================================
# L1ght Recon
# Scanning & Enumeration
# ============================================================

VERSION = "1.8.2"
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

    backup_path = script_path.with_name(
        f"{script_path.name}.v{VERSION}.bak"
    )

    try:
        shutil.copy2(script_path, backup_path)
    except Exception as exc:
        raise RuntimeError(
            f"não foi possível criar o backup em {backup_path}: {exc}"
        ) from exc

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

    return script_path, backup_path


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

    Modo verbose é usado por --check-update e --update.
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
        script_path, backup_path = _install_update(manifest)
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

    if verbose:
        print(f"{DIM}    Backup: {backup_path}{RESET}")

    if restart:
        print(
            f"{CYAN}[*]{RESET} Reiniciando o L1ght Recon com a nova versão..."
        )
        _restart_after_update(script_path)

    return "updated"



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
        "4. UDP top 1000 em segundo plano",
        "   " + command(
            "nmap -sU --open --top-ports 1000 -Pn -n TARGET -T4"
        ),
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
        "12. Relatórios",
        "   report.html e report.pdf (gerador PDF interno).",
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
    with CONSOLE_LOCK:
        print()
        print(f"{CYAN}{'=' * 72}{RESET}")
        print(f"{BOLD}{message}{RESET}")
        print(f"{CYAN}{'=' * 72}{RESET}")


# ============================================================
# Generic helpers
# ============================================================

def command_exists(command):
    return shutil.which(command) is not None


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
):
    if activity:
        info(activity)

    effective_timeout = COMMAND_TIMEOUT if timeout is None else timeout
    if effective_timeout == 0:
        effective_timeout = None

    process = None
    stdout_lines = []
    stderr_lines = []

    def _reader(stream, sink):
        try:
            for line in iter(stream.readline, ""):
                sink.append(line)
        except Exception:
            pass
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

        try:
            process.wait(timeout=effective_timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()

            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass

        stdout_thread.join(timeout=2)
        stderr_thread.join(timeout=2)

        stdout = "".join(stdout_lines)
        stderr = "".join(stderr_lines)
        return_code = process.returncode

        if timed_out:
            if output_file is not None:
                Path(output_file).write_text(
                    stdout,
                    encoding="utf-8",
                )

            warning(
                f"{command[0]} atingiu o limite de "
                f"{effective_timeout}s; resultados parciais foram preservados."
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

        warning("Execução interrompida pelo usuário.")
        raise

    except Exception as exc:
        error(f"Falha executando {command[0]}: {exc}")
        return "", "", -1

    if output_file is not None:
        Path(output_file).write_text(
            stdout or "",
            encoding="utf-8",
        )

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

def check_external_tools():
    tools = [
        "nmap", "httpx", "katana", "ffuf", "nikto", "nuclei",
        "whatweb", "wafw00f", "dig", "rpcinfo", "showmount",
        "rpcclient", "smbclient", "snmpwalk", "searchsploit",
    ]
    status = {tool: command_exists(tool) for tool in tools}

    missing = [tool for tool, found in status.items() if not found]

    if missing:
        section("DEPENDÊNCIAS EXTERNAS AUSENTES")
        for tool in missing:
            warning(
                f"{tool:<8} não encontrado; "
                "a etapa correspondente será ignorada."
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


def run_udp_scan(host, output_dir):
    normal_file = output_dir / "nmap_udp.txt"
    xml_file = output_dir / "nmap_udp.xml"

    timing = "-T2" if LOW_NOISE else "-T4"

    command = [
        "nmap",
        "-sU",
        "--open",
        "--top-ports",
        "1000",
        "-Pn",
        "-n",
        host,
        timing,
        "--script-timeout",
        "45s",
        "-oN",
        normal_file,
        "-oX",
        xml_file,
    ]

    run_command(
        command,
        activity=None,
    )

    if xml_file.exists():
        parsed = parse_nmap_xml(xml_file, display=False)
        if parsed:
            return parsed

    # Fallback para XML incompleto/timeout: aproveita linhas já gravadas
    # no formato normal do Nmap.
    partial = []

    if normal_file.exists():
        content = normal_file.read_text(
            encoding="utf-8",
            errors="ignore",
        )

        for match in re.finditer(
            r"^(\d+)/udp\s+open(?:\|filtered)?\s+(\S+)?",
            content,
            flags=re.M,
        ):
            partial.append(
                {
                    "port": int(match.group(1)),
                    "protocol": "udp",
                    "service": match.group(2) or "",
                    "product": "",
                    "version": "",
                    "extrainfo": "",
                    "tunnel": "",
                    "scripts": [],
                }
            )

    return partial


def print_udp_results(udp_ports, use_section=True):
    if use_section:
        section("UDP — RESULTADO DO SCAN EM SEGUNDO PLANO")

    if not udp_ports:
        print("Nenhuma porta UDP aberta identificada entre as top 1000.")
        return

    print_ports(udp_ports)


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


def run_service_enumeration(host, ports, output_dir):
    candidates = [
        item
        for item in ports
        if not is_probably_web_port(item)
    ]

    if not candidates:
        return []

    results = []
    workers = 1 if LOW_NOISE else min(4, len(candidates))

    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = {
            executor.submit(
                run_one_service_enum,
                host,
                item,
                output_dir,
            ): item
            for item in candidates
        }

        for future in as_completed(futures):
            try:
                results.append(future.result())
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
    open_numbers = {
        int(item["port"])
        for item in open_ports
    }

    smb_port = (
        445
        if 445 in open_numbers
        else 139
        if 139 in open_numbers
        else None
    )

    result = {
        "profile": (
            "RPC / SMB anonymous"
            if smb_port
            else "RPC services"
        ),
        "port": smb_port or (111 if 111 in open_numbers else 0),
        "protocol": "tcp",
        "service": "rpc/smb" if smb_port else "rpcbind",
        "product": "",
        "version": "",
        "scripts": [],
        "users": [],
        "groups": [],
        "shares": [],
        "rpc_entries": list((rpc_result or {}).get("entries", [])),
        "anonymous_rpc_allowed": False,
        "deeper_enum": False,
    }

    service_dir = output_dir / "service_enum"
    service_dir.mkdir(parents=True, exist_ok=True)

    if {139, 445} & open_numbers and command_exists("rpcclient"):
        stdout, _, code = run_command(
            [
                "rpcclient",
                "-U",
                "",
                "-N",
                host,
                "-c",
                "querydominfo;enumdomusers;enumdomgroups",
            ],
            output_file=service_dir / "rpcclient_anonymous.txt",
            activity=None,
        )

        lower = stdout.lower()

        denied = any(
            marker in lower
            for marker in [
                "access_denied",
                "nt_status_access_denied",
                "logon failure",
            ]
        )

        result["users"] = sorted(
            set(
                re.findall(
                    r"user:\[([^\]]+)\]",
                    stdout,
                    flags=re.I,
                )
            )
        )

        result["groups"] = sorted(
            set(
                re.findall(
                    r"group:\[([^\]]+)\]",
                    stdout,
                    flags=re.I,
                )
            )
        )

        result["anonymous_rpc_allowed"] = (
            code == 0
            and not denied
            and bool(stdout.strip())
        )

    if {139, 445} & open_numbers and command_exists("smbclient"):
        stdout, _, _ = run_command(
            ["smbclient", "-L", f"//{host}", "-N", "-g"],
            output_file=service_dir / "smbclient_anonymous.txt",
            activity=None,
        )

        for line in stdout.splitlines():
            parts = line.split("|")

            if len(parts) >= 2 and parts[0] in {"Disk", "IPC", "Printer"}:
                result["shares"].append(parts[1])

        result["shares"] = sorted(set(result["shares"]))

    result["deeper_enum"] = bool(
        result["anonymous_rpc_allowed"]
        or result["users"]
        or result["groups"]
        or result["shares"]
        or (rpc_result or {}).get("entries")
    )

    if not result["deeper_enum"]:
        return None

    return result


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


def build_service_seed_evidence(service, open_ports, cookie=None):
    evidence = []
    evidence.extend(extract_nmap_web_hints(service, open_ports))
    evidence.extend(discover_robots_and_sitemap(service, cookie=cookie))

    # Always include the service root as the primary seed.
    evidence.append({"source": "Base", "url": service["url"]})

    by_url = {}
    for item in evidence:
        url = item["url"]
        if not same_service(url, service["url"]):
            continue

        if url not in by_url:
            by_url[url] = {
                "url": url,
                "sources": set(),
            }
        by_url[url]["sources"].add(item["source"])

    result = []
    for url, item in by_url.items():
        result.append(
            {
                "url": url,
                "source": ", ".join(sorted(item["sources"])),
            }
        )

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


def ffuf_bases_from_seeds(service, seed_urls):
    bases = {service["url"].rstrip("/") + "/"}

    for seed in seed_urls or []:
        if not same_service(seed, service["url"]):
            continue

        parsed = urlparse(seed)
        path = parsed.path or "/"

        if path.endswith("/"):
            directory = path
        else:
            if "/" in path:
                directory = path.rsplit("/", 1)[0] + "/"
            else:
                directory = "/"

        origin = f"{parsed.scheme}://{parsed.netloc}"
        bases.add(origin + directory)

    # Avoid turning a long sitemap into hundreds of FFUF jobs.
    return sorted(bases)[:12]


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
        "httpx",
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

def run_katana(service, service_dir, depth, cookie=None, seed_urls=None):
    output_file = service_dir / "katana.jsonl"

    seeds = {
        url
        for url in ([service["url"]] + list(seed_urls or []))
        if same_service(url, service["url"]) and not is_noise_url(url)
    }
    seeds = sorted(seeds)[:25]

    info(
        f"Executando Katana em {service['url']} - "
        f"coletando links, endpoints, JavaScript e formulários "
        f"a partir de {len(seeds)} semente(s)..."
    )

    combined_output = []
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

    for seed in seeds:
        command = [
            "katana",
            "-u",
            seed,
            "-d",
            str(depth),
            "-jc",
            "-kf",
            "all",
            "-fx",
            "-jsonl",
            "-silent",
            "-nc",
        ]

        if cookie:
            command.extend(["-H", f"Cookie: {cookie}"])

        stdout, _, _ = run_command(command, activity=None)

        if stdout:
            combined_output.append(stdout)

        for line in stdout.splitlines():
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

    output_file.write_text(
        "\n".join(combined_output),
        encoding="utf-8",
    )
    redact_file_secret(output_file, cookie)

    urls = clean_url_collection(urls)
    write_lines(service_dir / "katana_urls.txt", urls)

    success(f"Katana: {len(urls)} URL(s) coletada(s).")
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
):
    results = []
    seen = set()
    raw_lines = []
    non_json_lines = []
    started_at = time.monotonic()

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
):
    aggregate_file = service_dir / "ffuf_content.json"

    if not Path(wordlist).exists():
        warning(f"Wordlist de conteúdo não encontrada: {wordlist}")
        return []

    fuzz_bases = ffuf_bases_from_seeds(
        service,
        seed_urls or [service["url"]],
    )

    if announce:
        info(
            f"Executando FFUF em {service['url']} - "
            f"buscando diretórios e arquivos em {len(fuzz_bases)} caminho(s) "
            f"com profundidade {ffuf_depth}..."
        )

    def execute_base(base_url, index, auto_calibrate=True, suffix=""):
        fuzz_url = base_url.rstrip("/") + "/FUZZ"
        result_file = service_dir / f"ffuf_run_{index:02d}{suffix}.json"
        raw_log_file = (
            service_dir / f"ffuf_run_{index:02d}{suffix}.stdout.log"
        )

        command = [
            "ffuf",
            "-w",
            f"{wordlist}:FUZZ",
            "-u",
            fuzz_url,
            "-recursion",
            "-recursion-depth",
            str(ffuf_depth),
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

        command.extend(
            [
                "-mc",
                "all",
                "-fc",
                "404",
                "-noninteractive",
                "-json",
                "-of",
                "json",
                "-o",
                str(result_file),
            ]
        )

        return _run_ffuf_json_stream(
            command,
            service["url"],
            label="FFUF",
            result_file=result_file,
            raw_log_file=raw_log_file,
        )

    combined = []

    for index, base_url in enumerate(fuzz_bases, start=1):
        combined.extend(
            execute_base(
                base_url,
                index,
                auto_calibrate=True,
            )
        )

    if not combined and fuzz_bases:
        warning(
            f"FFUF em {service['url']} não retornou achados na passagem "
            "com auto-calibração; validando novamente sem -ac..."
        )

        fallback_bases = fuzz_bases[:3]

        for index, base_url in enumerate(fallback_bases, start=1):
            combined.extend(
                execute_base(
                    base_url,
                    index,
                    auto_calibrate=False,
                    suffix="_fallback",
                )
            )

    unique = {}

    for item in combined:
        key = (
            item.get("url"),
            item.get("status"),
            item.get("length"),
        )
        unique[key] = item

    results = sorted(
        unique.values(),
        key=lambda item: (
            str(item.get("url", "")),
            int(item.get("status", 0) or 0),
        ),
    )

    aggregate_file.write_text(
        json.dumps(
            {"results": results},
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    redact_file_secret(aggregate_file, cookie)

    if announce:
        if results:
            success(
                f"FFUF {service['url']}: "
                f"{len(results)} diretório(s)/arquivo(s) encontrado(s)."
            )
        else:
            warning(
                f"FFUF {service['url']}: 0 resultado(s) após validação. "
                "Os logs ffuf_run_*.stdout.log foram preservados."
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
    lines = ["", f"{BOLD}Nikto - {service_url}{RESET}"]

    if not results:
        lines.append("  Nenhum resultado relevante.")
    else:
        lines.extend(f"  - {line}" for line in results)

    console_block(lines)



def print_nuclei_results(service_url, results):
    lines = ["", f"{BOLD}Nuclei - {service_url}{RESET}"]

    if not results:
        lines.append("  Nenhum finding encontrado.")
    else:
        grouped = Counter()

        for item in results:
            severity = str(item.get("severity", "unknown")).upper()
            name = item.get("name") or item.get("template_id") or "finding"
            matched = item.get("matched") or item.get("host") or ""
            grouped[(severity, name, matched)] += 1

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
# HTTP source / forms / headers / cookies
# ============================================================

def same_service(url, service_url):
    try:
        return urlparse(url).netloc == urlparse(service_url).netloc
    except Exception:
        return False


def analyze_source(service, candidate_urls, ffuf_results, limit=25, cookie=None):
    urls = {service["url"]}

    for url in candidate_urls:
        if same_service(url, service["url"]):
            urls.add(url)

    for item in ffuf_results:
        url = item.get("url")
        if url and same_service(url, service["url"]):
            urls.add(url)

    urls = sorted(urls)[:limit]

    summary = {
        "headers": {},
        "cookies": [],
        "forms": [],
        "hrefs": set(),
        "srcs": set(),
        "domains": set(),
        "api_endpoints": set(),
        "interesting_words": Counter(),
        "get_parameters": defaultdict(set),
        "post_parameters": defaultdict(set),
        "source_urls_checked": [],
    }

    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 L1ght-Recon/1.0"
            )
        }
    )

    if cookie:
        session.headers["Cookie"] = cookie

    for index, url in enumerate(urls):
        try:
            response = session.get(
                url,
                timeout=8,
                verify=False,
                allow_redirects=True,
            )
        except requests.RequestException:
            continue

        summary["source_urls_checked"].append(url)

        if index == 0:
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

        # Análise textual simples em HTML, JavaScript e outros recursos textuais.
        for word in INTERESTING_WORDS:
            count = len(re.findall(rf"\b{re.escape(word)}\b", lowered))
            if count:
                summary["interesting_words"][word] += count

        for match in re.findall(
            r"https?://[A-Za-z0-9._:-]+(?:/[^\s\"'<>]*)?",
            text,
            flags=re.I,
        ):
            parsed_match = urlparse(match)
            if parsed_match.hostname:
                summary["domains"].add(parsed_match.hostname)

        api_patterns = [
            r"""["'](\/api(?:\/[^"'<> ]*)?)["']""",
            r"""["'](\/graphql[^"'<> ]*)["']""",
            r"""["'](\/rest(?:\/[^"'<> ]*)?)["']""",
            r"""["'](\/swagger[^"'<> ]*)["']""",
            r"""["'](\/openapi[^"'<> ]*)["']""",
        ]

        for pattern in api_patterns:
            for endpoint in re.findall(pattern, text, flags=re.I):
                summary["api_endpoints"].add(urljoin(response.url, endpoint))

        # Formulários, href e src dependem de HTML.
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
                    fields.append(
                        {
                            "name": name,
                            "type": field_type,
                        }
                    )

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


    # Deduplicate cookies.
    cookie_map = {}
    for cookie in summary["cookies"]:
        key = (cookie["name"], cookie["domain"], cookie["path"])
        cookie_map[key] = cookie
    summary["cookies"] = list(cookie_map.values())

    summary["hrefs"] = sorted(summary["hrefs"])
    summary["srcs"] = sorted(summary["srcs"])
    summary["domains"] = sorted(summary["domains"])
    summary["api_endpoints"] = sorted(summary["api_endpoints"])
    summary["interesting_words"] = dict(summary["interesting_words"])
    summary["get_parameters"] = {
        key: sorted(value) for key, value in summary["get_parameters"].items()
    }
    summary["post_parameters"] = {
        key: sorted(value) for key, value in summary["post_parameters"].items()
    }

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
    service_results=None,
):
    report_file = output_dir / "report.html"

    udp_ports = udp_ports or []
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
<div class="card">Serviços enumerados<span class="number">{len(service_results)}</span></div>
<div class="card">Serviços Web<span class="number">{len(web_results)}</span></div>
</div>

<h2>Portas TCP, serviços e resultados NSE</h2>
{html_table(["Porta", "Serviço", "Produto / versão", "NSE"], port_rows)}

<h2>Portas UDP — top 1000</h2>
{html_table(["Porta", "Serviço", "Produto / versão", "NSE"], udp_rows)}

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


def _pdf_escape_text(value):
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )


def _write_builtin_text_pdf(report_file, lines):
    """
    Fallback PDF generator with no third-party dependency.
    It creates a readable multi-page text report using Helvetica.
    """
    page_width = 842
    page_height = 595
    left = 34
    top = 560
    line_height = 11
    max_lines = 45
    wrap_width = 125

    wrapped_lines = []

    for line in lines:
        if line == "":
            wrapped_lines.append("")
            continue

        pieces = textwrap.wrap(
            str(line),
            width=wrap_width,
            replace_whitespace=False,
            drop_whitespace=False,
        ) or [""]

        wrapped_lines.extend(pieces)

    pages = [
        wrapped_lines[index:index + max_lines]
        for index in range(0, len(wrapped_lines), max_lines)
    ] or [[]]

    objects = {}
    next_id = 1

    catalog_id = next_id
    next_id += 1
    pages_id = next_id
    next_id += 1
    font_id = next_id
    next_id += 1

    page_ids = []
    content_ids = []

    for _ in pages:
        page_ids.append(next_id)
        next_id += 1
        content_ids.append(next_id)
        next_id += 1

    objects[font_id] = (
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
        b"/Encoding /WinAnsiEncoding >>"
    )

    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    objects[pages_id] = (
        f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>"
    ).encode("ascii")

    objects[catalog_id] = (
        f"<< /Type /Catalog /Pages {pages_id} 0 R >>"
    ).encode("ascii")

    for page_id, content_id, page_lines in zip(
        page_ids,
        content_ids,
        pages,
    ):
        operators = [
            "BT",
            "/F1 8.5 Tf",
            f"{left} {top} Td",
            f"{line_height} TL",
        ]

        for line in page_lines:
            safe = _pdf_escape_text(line)
            operators.append(f"({safe}) Tj")
            operators.append("T*")

        operators.append("ET")

        stream_text = "\n".join(operators)
        stream_bytes = stream_text.encode("cp1252", errors="replace")

        objects[content_id] = (
            f"<< /Length {len(stream_bytes)} >>\nstream\n".encode("ascii")
            + stream_bytes
            + b"\nendstream"
        )

        objects[page_id] = (
            f"<< /Type /Page /Parent {pages_id} 0 R "
            f"/MediaBox [0 0 {page_width} {page_height}] "
            f"/Resources << /Font << /F1 {font_id} 0 R >> >> "
            f"/Contents {content_id} 0 R >>"
        ).encode("ascii")

    max_id = max(objects)
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0] * (max_id + 1)

    for object_id in range(1, max_id + 1):
        offsets[object_id] = len(output)
        output.extend(f"{object_id} 0 obj\n".encode("ascii"))
        output.extend(objects[object_id])
        output.extend(b"\nendobj\n")

    xref_offset = len(output)
    output.extend(
        f"xref\n0 {max_id + 1}\n".encode("ascii")
    )
    output.extend(b"0000000000 65535 f \n")

    for object_id in range(1, max_id + 1):
        output.extend(
            f"{offsets[object_id]:010d} 00000 n \n".encode("ascii")
        )

    output.extend(
        (
            f"trailer\n<< /Size {max_id + 1} /Root {catalog_id} 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode("ascii")
    )

    report_file.write_bytes(output)
    return report_file


def _plain_report_lines(target, host, open_ports, web_results, udp_ports=None, service_results=None):
    udp_ports = udp_ports or []
    service_results = service_results or []

    lines = [
        "L1ght Recon",
        "Scanning & Enumeration",
        "",
        f"Alvo: {target}",
        f"Host: {host}",
        f"Execucao: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
        f"Handle: {HANDLE}",
        "",
        "PORTAS, SERVICOS E NSE",
    ]

    for item in open_ports:
        description = " ".join(
            x for x in [
                item["product"],
                item["version"],
                item["extrainfo"],
            ]
            if x
        )
        lines.append(
            f"{item['port']}/{item['protocol']} "
            f"{item['service'] or '-'} {description or '-'}"
        )

        for script in item.get("scripts", []):
            lines.append(
                f"  NSE {script.get('id') or '-'}: "
                f"{script.get('output') or '-'}"
            )

    lines.extend(["", "PORTAS UDP - TOP 1000"])

    for item in udp_ports:
        description = " ".join(
            part
            for part in [
                item.get("product") or "",
                item.get("version") or "",
                item.get("extrainfo") or "",
            ]
            if part
        )
        lines.append(
            f"{item.get('port')}/{item.get('protocol', 'udp')} "
            f"{item.get('service') or '-'} {description or '-'}"
        )

    lines.extend(["", "ENUMERACAO AUTOMATICA DOS SERVICOS"])

    for item in service_results:
        description = " ".join(
            part
            for part in [
                item.get("product") or "",
                item.get("version") or "",
            ]
            if part
        )

        ports_display = (
            ",".join(str(port) for port in item.get("ports", []))
            if item.get("ports")
            else str(item.get("port"))
        )

        lines.append(
            f"{item.get('profile') or '-'} "
            f"{ports_display}/{item.get('protocol')} "
            f"{item.get('service') or '-'} {description or '-'}"
        )

        if item.get("exports"):
            lines.append("  Exports NFS:")
            lines.extend(
                f"    {value}"
                for value in item["exports"]
            )

        if item.get("users"):
            lines.append(
                "  Usuarios RPC: " + ", ".join(item["users"])
            )

        if item.get("groups"):
            lines.append(
                "  Grupos RPC: " + ", ".join(item["groups"])
            )

        if item.get("shares"):
            lines.append(
                "  Shares anonimos: " + ", ".join(item["shares"])
            )

        if item.get("rpc_entries"):
            lines.append("  Programas RPC:")

            for entry in item["rpc_entries"][:30]:
                lines.append(
                    f"    {entry.get('service')} "
                    f"{entry.get('protocol')}/{entry.get('port')} "
                    f"(prog {entry.get('program')} v{entry.get('version')})"
                )

        if item.get("anonymous_rpc_allowed"):
            lines.append(
                "  RPC anonimo aceito; aprofundamento manual recomendado."
            )

        for script in item.get("scripts", []):
            lines.append(
                f"  {script.get('id') or 'NSE'}:"
            )

            for raw_line in (script.get("output") or "-").splitlines():
                lines.append(f"    {raw_line}")

        for finding in item.get("public_exploits") or []:
            lines.append(
                f"  Exploit publico: {finding.get('title') or '-'}"
            )

    for result in web_results:
        service = result["service"]
        source = result["source"]

        lines.extend(
            [
                "",
                "=" * 70,
                f"WEB: {service['url']}",
                "=" * 70,
                f"Status: {service['status'] or '-'}",
                f"Titulo: {service['title'] or '-'}",
                f"Servidor: {service['server'] or '-'}",
                f"Tecnologias: {', '.join(service['tech']) or '-'}",
                "",
                "CAMINHOS DESCOBERTOS AUTOMATICAMENTE",
            ]
        )

        for item in result.get("seed_evidence", []):
            lines.append(
                f"  [{item.get('source') or '-'}] {item.get('url') or '-'}"
            )

        lines.append("")
        lines.append("WHATWEB")
        for record in result.get("whatweb", []):
            lines.append(
                f"  {record.get('url') or '-'} [{record.get('status') or '-'}]"
            )
            for plugin in record.get("plugins", []):
                values = " | ".join(plugin.get("values") or ["detectado"])
                lines.append(
                    f"    {plugin.get('name') or 'Detalhe'}: {values}"
                )

        waf_result = result.get("wafw00f") or {}
        lines.extend(["", "WAFW00F"])
        lines.append(
            "  Detectado: "
            + ("sim" if waf_result.get("detected") else "nao")
        )
        if waf_result.get("wafs"):
            lines.append(
                "  Produtos: " + ", ".join(waf_result["wafs"])
            )

        lines.extend(["", "FORMULARIOS"])
        for form in source["forms"]:
            fields = ", ".join(
                f"{field['name']} ({field['type']})"
                for field in form["fields"]
            ) or "-"
            lines.append(
                f"  {form['method']} {form['action']} | {fields}"
            )

        lines.extend(["", "PARAMETROS - PADROES AGRUPADOS"])
        for rec in result["parameters"]:
            count = int(rec.get("count") or 1)
            route = rec.get("route") or rec.get("url") or "-"
            suffix = f" | {count} variacoes" if count > 1 else ""
            lines.append(
                f"  {rec['method']} {route} | "
                f"{', '.join(rec['parameters'])} | "
                f"{', '.join(rec['vectors']) or '-'}"
                f"{suffix}"
            )

        lines.extend(["", "ARQUIVOS JAVASCRIPT"])
        lines.extend(f"  {url}" for url in result.get("javascript", []))

        lines.extend(["", "APIS"])
        lines.extend(f"  {url}" for url in source["api_endpoints"])

        lines.extend(["", "PALAVRAS INTERESSANTES"])
        for word, count in sorted(
            source["interesting_words"].items(),
            key=lambda item: (-item[1], item[0]),
        ):
            lines.append(f"  {word}: {count}")

        lines.extend(["", "FFUF"])
        for item in result["ffuf_content"]:
            lines.append(
                f"  [{item.get('status', '-')}] "
                f"{item.get('url', '-')} "
                f"(length {item.get('length', '-')})"
            )

        lines.extend(["", "NUCLEI"])
        for item in result["nuclei"]:
            lines.append(
                f"  [{item['severity']}] "
                f"{item['name'] or item['template_id'] or '-'} -> "
                f"{item['matched'] or item['host'] or '-'}"
            )

        lines.extend(["", "NIKTO"])
        lines.extend(f"  {line}" for line in result["nikto"])

        lines.extend(["", "KATANA - RESUMO"])
        katana_summary = summarize_katana_urls(
            result["service"]["url"],
            result["katana_urls"],
        )
        lines.append(
            f"  URLs brutas: {katana_summary['raw']} | "
            f"Padroes unicos: {katana_summary['unique_patterns']}"
        )
        for item in katana_summary["patterns"][:40]:
            lines.append(
                f"  {item['count']}x {item['signature']}"
            )
        if len(katana_summary["patterns"]) > 40:
            lines.append(
                f"  ... +{len(katana_summary['patterns']) - 40} padroes"
            )

    lines.extend(
        [
            "",
            "-" * 70,
            f"{HANDLE} · Rafael Ademilton",
        ]
    )

    return lines


def generate_pdf_report(
    target,
    host,
    output_dir,
    open_ports,
    web_results,
    udp_ports=None,
    service_results=None,
):
    report_file = output_dir / "report.pdf"

    return _write_builtin_text_pdf(
        report_file,
        _plain_report_lines(
            target,
            host,
            open_ports,
            web_results,
            udp_ports=udp_ports or [],
            service_results=service_results or [],
        ),
    )


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


def print_final_compilation(
    target,
    open_ports,
    udp_ports,
    service_results,
    all_results,
    web_services,
    args,
    extensions,
    cookie,
    output_dir,
    html_report,
    pdf_report,
):
    section("FINAL")

    print(f"Alvo.....................: {target}")
    print(f"Portas TCP abertas.......: {len(open_ports)}")
    print(f"Portas UDP abertas.......: {len(udp_ports)}")
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
    print_final_port_table("PORTAS UDP — TOP 1000", udp_ports)

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
    print(f"  Relatório PDF...........: {pdf_report}")

    print()
    success(f"{brand()} finalizado.")
    print(f"{DIM}{HANDLE} · Rafael Ademilton{RESET}")

    print()
    print("Abra os relatórios com:\n")
    print(f"  firefox '{html_report}'")
    print(f"  xdg-open '{pdf_report}'")
    print()


# ============================================================
# Main
# ============================================================

def main():
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
  python3 l1ght_recon.py --check-update
  python3 l1ght_recon.py --update
  python3 l1ght_recon.py -t 192.168.92.206 --no-update

Fluxo:
  1. Coleta de rede/DNS quando aplicável.
  2. Nmap TCP rápido -> detalhamento somente das portas abertas.
  3. UDP top 1000 e enumeração de serviços em segundo plano.
  4. HTTPX/Katana e análise Web.
  5. Background exibido em ordem: WhatWeb -> FFUF -> Nuclei -> Nikto.
  6. NFS/mountd, RPC, SNMP e demais serviços são aprofundados.
  7. Seção FINAL compila os resultados e gera HTML/PDF.
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
            "Máximo de páginas por serviço Web para análise simples do HTML.\n"
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
        help="Não executa o scan UDP top 1000 em segundo plano.",
    )
    parser.add_argument(
        "--skip-service-enum",
        action="store_true",
        help="Não executa a enumeração automática dos serviços não Web.",
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
            "Verifica se existe uma versão mais nova e encerra. "
            "Não instala a atualização."
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

    if args.check_update:
        handle_update_check(
            install=False,
            restart=False,
            verbose=True,
        )
        return

    if args.update:
        update_status = handle_update_check(
            install=True,
            restart=bool(args.target),
            verbose=True,
        )

        if not args.target:
            return

    elif not args.no_update and not args.flow:
        # Checagem automática deliberadamente silenciosa:
        # sem internet, manifesto ausente ou versão atual não poluem a saída.
        handle_update_check(
            install=True,
            restart=True,
            verbose=False,
        )

    banner()

    if args.flow:
        print_flow()
        return

    if not args.target:
        parser.error(
            "o parâmetro -t/--target é obrigatório, exceto com "
            "--flow, --check-update ou --update."
        )

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

    tools = check_external_tools()

    if not tools["nmap"]:
        error(f"Nmap é necessário para o fluxo principal do {brand()}.")
        sys.exit(1)

    auxiliary_executor = ThreadPoolExecutor(max_workers=2 if LOW_NOISE else 3)
    udp_future = None
    service_future = None
    info_future = auxiliary_executor.submit(
        run_information_gathering,
        host,
        target,
        output_dir,
    )

    if not args.skip_udp:
        info(
            "Iniciando scan UDP top 1000 em segundo plano; "
            "o resultado será apresentado somente no final."
        )
        udp_future = auxiliary_executor.submit(
            run_udp_scan,
            host,
            output_dir,
        )

    open_ports = run_nmap(host, output_dir)

    if not open_ports:
        warning(
            "Nenhuma porta TCP aberta foi identificada. "
            "O fluxo continuará para considerar resultados UDP."
        )

    if open_ports and not args.skip_service_enum:
        info(
            "Iniciando enumeração básica dos serviços não Web "
            "em segundo plano."
        )
        service_future = auxiliary_executor.submit(
            run_service_enumeration,
            host,
            open_ports,
            output_dir,
        )

    web_services = []

    if open_ports and tools["httpx"]:
        web_services = probe_web_services(
            host,
            open_ports,
            output_dir,
            cookie=cookie,
        )
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

    if not vhost_domain and is_ip(host):
        warning(
            "Alvo é IP e --vhost-domain não foi informado; "
            "enumeração de virtual hosts será ignorada."
        )

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
        future = executor.submit(fn, *fn_args)
        background_jobs[future] = (key, field)
        return future


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

        if background_jobs:
            section("4. RESULTADOS DAS VARREDURAS EM SEGUNDO PLANO")
            info(
                "As varreduras demoradas continuam em segundo plano. "
                "Os resultados são exibidos em blocos, sem misturar as ferramentas."
            )

            jobs_by_field = defaultdict(list)

            for future, metadata in background_jobs.items():
                jobs_by_field[metadata[1]].append(future)

            def store_background_result(future):
                key, field = background_jobs[future]
                service_url = result_by_key[key]["service"]["url"]

                try:
                    value = future.result()
                    result_by_key[key][field] = value
                    return service_url, field, value

                except Exception as exc:
                    result_by_key[key][field] = [] if field != "wafw00f" else {}
                    warning(
                        f"Falha na tarefa {field} de {service_url}: {exc}"
                    )
                    return service_url, field, result_by_key[key][field]

            # 1) WhatWeb: geralmente rápido e útil para orientar o restante.
            for future in as_completed(jobs_by_field.get("whatweb", [])):
                service_url, _, value = store_background_result(future)
                print_whatweb_results(service_url, value)

            # WAFW00F é processado agora, mas fica resumido no FINAL.
            for future in as_completed(jobs_by_field.get("wafw00f", [])):
                store_background_result(future)

            # 2) FFUF: enquanto ainda executa, drena achados em blocos parciais.
            ffuf_futures = set(
                jobs_by_field.get("ffuf_content", [])
                + jobs_by_field.get("ffuf_vhosts", [])
            )

            while ffuf_futures:
                drain_ffuf_partial_blocks()

                done, ffuf_futures = wait(
                    ffuf_futures,
                    timeout=1.0,
                    return_when=FIRST_COMPLETED,
                )

                for future in done:
                    service_url, field, value = store_background_result(future)

                    drain_ffuf_partial_blocks()

                    if field == "ffuf_content":
                        print_ffuf_finished(
                            service_url,
                            value,
                            label="FFUF",
                        )
                    else:
                        print_vhost_results(service_url, value)

            drain_ffuf_partial_blocks()

            # 3) Nuclei.
            for future in as_completed(jobs_by_field.get("nuclei", [])):
                service_url, _, value = store_background_result(future)
                print_nuclei_results(service_url, value)

            # 4) Nikto.
            for future in as_completed(jobs_by_field.get("nikto", [])):
                service_url, _, value = store_background_result(future)
                print_nikto_results(service_url, value)

            # Pesquisa local de exploits públicos: processada sem poluir a tela.
            for future in as_completed(jobs_by_field.get("public_exploits", [])):
                store_background_result(future)

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
        )
        result["source"] = source

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
        all_results.append(result)

    service_results = []
    udp_ports = []

    if service_future is not None:
        try:
            service_results.extend(service_future.result())
        except Exception as exc:
            warning(f"Falha consolidando enumeração de serviços TCP: {exc}")

    if udp_future is not None:
        try:
            udp_ports = udp_future.result()
        except Exception as exc:
            warning(f"Falha consolidando scan UDP: {exc}")
            udp_ports = []

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

    html_report = generate_report(
        target,
        host,
        output_dir,
        open_ports,
        all_results,
        missing_tools,
        udp_ports=udp_ports,
        service_results=service_results,
    )
    pdf_report = generate_pdf_report(
        target,
        host,
        output_dir,
        open_ports,
        all_results,
        udp_ports=udp_ports,
        service_results=service_results,
    )

    print_final_compilation(
        target,
        open_ports,
        udp_ports,
        service_results,
        all_results,
        web_services,
        args,
        extensions,
        cookie,
        output_dir,
        html_report,
        pdf_report,
    )



if __name__ == "__main__":
    main()

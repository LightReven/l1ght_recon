#!/usr/bin/env bash
set -uo pipefail

info() { printf '[*] %s\n' "$*"; }
ok()   { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
fail() { printf '[-] %s\n' "$*" >&2; exit 1; }

if [[ "${EUID}" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
        exec sudo -E bash "$0" "$@"
    fi
    fail "O setup precisa de privilégios administrativos (root/sudo)."
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_PATH="${SCRIPT_DIR}/l1ght_recon.py"
REQ_FILE="${SCRIPT_DIR}/requirements.txt"

if [[ ! -r /etc/os-release ]]; then
    fail "Não foi possível identificar a distribuição Linux."
fi

# shellcheck disable=SC1091
. /etc/os-release
DISTRO_ID="${ID:-unknown}"
DISTRO_LIKE="${ID_LIKE:-}"
ARCH_RAW="$(uname -m)"
case "${ARCH_RAW}" in
    x86_64|amd64) PD_ARCH="amd64" ;;
    aarch64|arm64) PD_ARCH="arm64" ;;
    *)
        fail "Arquitetura não suportada pelo instalador automático: ${ARCH_RAW}. Suportadas: x86_64/amd64 e arm64/aarch64."
        ;;
esac

command -v apt-get >/dev/null 2>&1 ||     fail "O instalador automático suporta Kali/Debian/Ubuntu e derivados com apt."

export DEBIAN_FRONTEND=noninteractive

apt_has() {
    apt-cache show "$1" >/dev/null 2>&1
}

apt_install_if_available() {
    local pkg="$1"
    if dpkg -s "${pkg}" >/dev/null 2>&1; then
        return 0
    fi
    if ! apt_has "${pkg}"; then
        return 2
    fi
    info "Instalando pacote: ${pkg}"
    apt-get install -y "${pkg}"
}

retry() {
    local attempts="$1"
    shift
    local n=1
    until "$@"; do
        if (( n >= attempts )); then
            return 1
        fi
        warn "Tentativa ${n} falhou; tentando novamente..."
        n=$((n + 1))
        sleep 2
    done
}

info "Atualizando índice APT..."
retry 2 apt-get update || fail "apt-get update falhou. Verifique rede, DNS e repositórios."

# Instala cada pacote isoladamente. Assim um pacote ausente em uma distro
# não impede a instalação dos demais.
BASE_PACKAGES=(
    ca-certificates curl unzip tar git
    python3 python3-pip
    nmap ffuf nikto whatweb
    dnsutils rpcbind nfs-common smbclient samba-common-bin snmp
    perl ruby
)

for pkg in "${BASE_PACKAGES[@]}"; do
    if ! apt_install_if_available "${pkg}"; then
        rc=$?
        if [[ "${rc}" -eq 2 ]]; then
            warn "Pacote APT não disponível nesta distribuição: ${pkg}"
        else
            warn "Falha ao instalar ${pkg}; o setup continuará e tentará validar/fazer fallback no final."
        fi
    fi
done

# Dependências opcionais do Kali.
for pkg in wafw00f seclists exploitdb; do
    if ! apt_install_if_available "${pkg}"; then
        true
    fi
done

install_python_requirements() {
    [[ -f "${REQ_FILE}" ]] || return 0
    info "Instalando dependências Python..."
    if python3 -m pip install --help 2>/dev/null | grep -q -- '--break-system-packages'; then
        python3 -m pip install --break-system-packages -U -r "${REQ_FILE}"
    else
        python3 -m pip install -U -r "${REQ_FILE}"
    fi
}

retry 2 install_python_requirements || fail "Falha ao instalar requirements.txt."

is_pd_httpx() {
    local bin="${1:-}"
    [[ -n "${bin}" && -x "${bin}" ]] || return 1
    "${bin}" -h 2>&1 | grep -qi 'fast and multi-purpose HTTP toolkit'
}

normalize_httpx_command() {
    # Kali empacota a ferramenta da ProjectDiscovery como httpx-toolkit
    # porque /usr/bin/httpx pode pertencer ao pacote python3-httpx.
    if command -v httpx-toolkit >/dev/null 2>&1; then
        local toolkit
        toolkit="$(command -v httpx-toolkit)"
        if is_pd_httpx "${toolkit}"; then
            ln -sfn "${toolkit}" /usr/local/bin/httpx
            return 0
        fi
    fi
    if [[ -x /usr/local/bin/httpx ]] && is_pd_httpx /usr/local/bin/httpx; then
        return 0
    fi
    if command -v httpx >/dev/null 2>&1 && is_pd_httpx "$(command -v httpx)"; then
        return 0
    fi
    return 1
}

github_latest_binary() {
    local tool="$1"
    local repo="$2"
    local binary="$3"
    local tmpdir asset_url archive

    tmpdir="$(mktemp -d)"
    trap 'rm -rf "${tmpdir:-}"' RETURN

    asset_url="$(
        TOOL_REPO="${repo}" TOOL_ARCH="${PD_ARCH}" python3 - <<'PY'
import json
import os
import re
import sys
import urllib.request

repo = os.environ["TOOL_REPO"]
arch = os.environ["TOOL_ARCH"]
request = urllib.request.Request(
    f"https://api.github.com/repos/{repo}/releases/latest",
    headers={
        "User-Agent": "L1ght-Recon-Installer",
        "Accept": "application/vnd.github+json",
    },
)
try:
    with urllib.request.urlopen(request, timeout=20) as response:
        data = json.load(response)
except Exception as exc:
    print(f"GitHub API: {exc}", file=sys.stderr)
    raise SystemExit(1)

patterns = [
    re.compile(rf"linux[_-]{re.escape(arch)}.*\.zip$", re.I),
    re.compile(rf"linux[_-]{re.escape(arch)}.*\.tar\.gz$", re.I),
    re.compile(rf"linux[_-]{re.escape(arch)}.*\.tgz$", re.I),
]
for pattern in patterns:
    for asset in data.get("assets", []):
        name = asset.get("name") or ""
        if pattern.search(name):
            print(asset["browser_download_url"])
            raise SystemExit(0)
raise SystemExit(2)
PY
    )" || return 1

    archive="${tmpdir}/asset"
    info "Baixando binário oficial de ${tool} para linux/${PD_ARCH}..."
    retry 3 curl -fL --connect-timeout 15 --max-time 180         --retry 2 --retry-delay 2 "${asset_url}" -o "${archive}" || return 1

    if [[ "${asset_url}" == *.zip ]]; then
        unzip -q "${archive}" -d "${tmpdir}/extract" || return 1
    else
        mkdir -p "${tmpdir}/extract"
        tar -xzf "${archive}" -C "${tmpdir}/extract" || return 1
    fi

    local found
    found="$(find "${tmpdir}/extract" -type f -name "${binary}" -print -quit)"
    [[ -n "${found}" ]] || return 1
    install -m 0755 "${found}" "/usr/local/bin/${binary}"
    return 0
}

install_projectdiscovery_tool() {
    local logical="$1"
    local apt_pkg="$2"
    local repo="$3"
    local binary="$4"

    if [[ "${logical}" == "httpx" ]]; then
        normalize_httpx_command && return 0
    elif command -v "${binary}" >/dev/null 2>&1; then
        return 0
    fi

    if apt_has "${apt_pkg}"; then
        info "Instalando ${logical} pelo pacote oficial da distribuição (${apt_pkg})..."
        if apt-get install -y "${apt_pkg}"; then
            if [[ "${logical}" == "httpx" ]]; then
                normalize_httpx_command && return 0
            elif command -v "${binary}" >/dev/null 2>&1; then
                return 0
            fi
        fi
    fi

    warn "${logical}: pacote da distribuição indisponível/inadequado; usando release binária oficial."
    github_latest_binary "${logical}" "${repo}" "${binary}" || return 1

    if [[ "${logical}" == "httpx" ]]; then
        normalize_httpx_command
    else
        command -v "${binary}" >/dev/null 2>&1
    fi
}

# Preferimos pacotes da distro. No Kali atual:
#   httpx-toolkit -> ProjectDiscovery httpx
#   katana        -> ProjectDiscovery Katana
#   nuclei        -> ProjectDiscovery Nuclei
# Se qualquer pacote não existir, usamos o binário pré-compilado oficial;
# não dependemos mais de "go install @latest".
install_projectdiscovery_tool     httpx httpx-toolkit projectdiscovery/httpx httpx ||     fail "Não foi possível instalar o httpx da ProjectDiscovery."

install_projectdiscovery_tool     katana katana projectdiscovery/katana katana ||     fail "Não foi possível instalar o Katana."

install_projectdiscovery_tool     nuclei nuclei projectdiscovery/nuclei nuclei ||     fail "Não foi possível instalar o Nuclei."

# WAFW00F: fallback via PyPI quando o pacote APT não existe.
if ! command -v wafw00f >/dev/null 2>&1; then
    info "Instalando WAFW00F via pip..."
    if python3 -m pip install --help 2>/dev/null | grep -q -- '--break-system-packages'; then
        python3 -m pip install --break-system-packages -U wafw00f || true
    else
        python3 -m pip install -U wafw00f || true
    fi
fi

# SecLists: garante os dois diretórios usados pelos defaults do L1ght Recon.
if [[ ! -d /usr/share/seclists ]]; then
    info "SecLists não está disponível via APT; baixando apenas Discovery/Web-Content e Discovery/DNS..."
    git clone --depth 1 --filter=blob:none --sparse         https://github.com/danielmiessler/SecLists.git /usr/share/seclists || true
    if [[ -d /usr/share/seclists/.git ]]; then
        git -C /usr/share/seclists sparse-checkout set             Discovery/Web-Content Discovery/DNS || true
    fi
fi
mkdir -p /usr/share/wordlists
if [[ -d /usr/share/seclists ]]; then
    ln -sfn /usr/share/seclists /usr/share/wordlists/seclists
fi

# Fall back de FFUF por release binária, útil em Debian/Ubuntu mínimos.
if ! command -v ffuf >/dev/null 2>&1; then
    github_latest_binary ffuf ffuf/ffuf ffuf ||         fail "Não foi possível instalar o FFUF."
fi

# Nikto/WhatWeb: apt normalmente resolve em Kali/Debian/Ubuntu.
# Mantemos mensagens explícitas quando a distro não oferece o pacote.
if ! command -v nikto >/dev/null 2>&1; then
    warn "Nikto continua ausente. Verifique se os repositórios da distribuição estão habilitados."
fi
if ! command -v whatweb >/dev/null 2>&1; then
    warn "WhatWeb continua ausente. Verifique se os repositórios da distribuição estão habilitados."
fi

if command -v nuclei >/dev/null 2>&1; then
    info "Atualizando templates do Nuclei..."
    nuclei -ut >/dev/null 2>&1 || nuclei -update-templates >/dev/null 2>&1 || true
fi

if [[ -f "${SCRIPT_PATH}" ]]; then
    chmod +x "${SCRIPT_PATH}"
    ln -sfn "${SCRIPT_PATH}" /usr/local/bin/l1ght_recon
fi

# Validação final. httpx é validado pela assinatura do CLI da ProjectDiscovery,
# não apenas pelo nome do executável.
REQUIRED=(nmap katana ffuf nikto nuclei whatweb wafw00f)
OPTIONAL=(dig rpcinfo showmount rpcclient smbclient snmpwalk searchsploit)

missing_required=0
if ! normalize_httpx_command; then
    warn "httpx da ProjectDiscovery ausente ou foi confundido com python-httpx."
    missing_required=1
else
    ok "httpx -> $(readlink -f "$(command -v httpx)")"
fi

for tool in "${REQUIRED[@]}"; do
    if command -v "${tool}" >/dev/null 2>&1; then
        ok "${tool} -> $(command -v "${tool}")"
    else
        warn "${tool} ausente"
        missing_required=1
    fi
done

for tool in "${OPTIONAL[@]}"; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        warn "${tool} ausente; apenas a enumeração específica correspondente ficará indisponível."
    fi
done

if [[ ! -f /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt ]]; then
    warn "Wordlist big.txt não localizada no caminho padrão."
    missing_required=1
fi

if [[ "${missing_required}" -ne 0 ]]; then
    fail "Setup terminou com dependências obrigatórias ausentes."
fi

ok "Ambiente do L1ght Recon pronto."
ok "Comando: l1ght_recon"

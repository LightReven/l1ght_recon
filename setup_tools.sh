#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "[!] Execute como root no Kali/Debian para o setup automático."
    exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_PATH="${SCRIPT_DIR}/l1ght_recon.py"

apt-get update
apt-get install -y \
    nmap \
    ffuf \
    nikto \
    whatweb \
    wafw00f \
    seclists \
    dnsutils \
    rpcbind \
    nfs-common \
    smbclient \
    snmp \
    exploitdb \
    golang-go \
    python3-pip

python3 -m pip install --break-system-packages -U -r "${SCRIPT_DIR}/requirements.txt"

GOBIN=/usr/local/bin go install github.com/projectdiscovery/httpx/cmd/httpx@latest
GOBIN=/usr/local/bin go install github.com/projectdiscovery/katana/cmd/katana@latest
GOBIN=/usr/local/bin go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

if command -v nuclei >/dev/null 2>&1; then
    nuclei -ut || true
fi

if [[ -f "${SCRIPT_PATH}" ]]; then
    chmod +x "${SCRIPT_PATH}"
    ln -sfn "${SCRIPT_PATH}" /usr/local/bin/l1ght_recon
fi

TOOLS=(
    nmap httpx katana ffuf nikto nuclei whatweb wafw00f
    dig rpcinfo showmount rpcclient smbclient snmpwalk searchsploit
)

missing=0
for tool in "${TOOLS[@]}"; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        printf '[!!] %s ausente\n' "${tool}"
        missing=1
    fi
done

if [[ "${missing}" -eq 0 ]]; then
    echo "[+] Ambiente do L1ght Recon pronto. Comando: l1ght_recon"
else
    echo "[!] Setup concluído com dependências ainda ausentes."
fi

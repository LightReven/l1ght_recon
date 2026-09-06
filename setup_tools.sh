#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "[!] Execute como root no Kali."
    exit 1
fi

echo "[*] Atualizando índices APT..."
apt-get update

echo "[*] Instalando/atualizando ferramentas do repositório Kali..."
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

echo "[*] Atualizando dependências Python..."
python3 -m pip install \
    --break-system-packages \
    -U \
    requests \
    beautifulsoup4

echo "[*] Instalando/atualizando ferramentas ProjectDiscovery..."
GOBIN=/usr/local/bin go install github.com/projectdiscovery/httpx/cmd/httpx@latest
GOBIN=/usr/local/bin go install github.com/projectdiscovery/katana/cmd/katana@latest
GOBIN=/usr/local/bin go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

echo "[*] Atualizando templates do Nuclei..."
if command -v nuclei >/dev/null 2>&1; then
    nuclei -ut || true
fi

echo "[*] Verificando ferramentas..."
TOOLS=(
    nmap
    httpx
    katana
    ffuf
    nikto
    nuclei
    whatweb
    wafw00f
    dig
    rpcinfo
    showmount
    rpcclient
    smbclient
    snmpwalk
    searchsploit
)

missing=0

for tool in "${TOOLS[@]}"; do
    if command -v "${tool}" >/dev/null 2>&1; then
        printf "  [OK] %-12s %s\n" "${tool}" "$(command -v "${tool}")"
    else
        printf "  [!!] %-12s ausente\n" "${tool}"
        missing=1
    fi
done

echo
if [[ "${missing}" -eq 0 ]]; then
    echo "[+] Ambiente do L1ght Recon pronto."
else
    echo "[!] Setup concluído, mas há ferramentas ausentes. Revise as mensagens acima."
fi

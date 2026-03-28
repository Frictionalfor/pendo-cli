#!/usr/bin/env bash
# check.sh - Dependency checker + auto install

echo "[*] Pendo CLI - Dependency Check"

MISSING=0

check_cmd() {
    if command -v "$1" &>/dev/null; then
        echo "[+] $1 found: $(command -v $1)"
    else
        echo "[!] $1 NOT found"
        MISSING=1
    fi
}

check_pip_pkg() {
    if python3 -c "import $1" &>/dev/null; then
        echo "[+] Python package '$1' installed"
    else
        echo "[!] Python package '$1' missing - installing..."
        pip3 install "$2" --quiet
    fi
}

check_cmd python3
check_cmd pip3

check_pip_pkg requests requests
check_pip_pkg bs4 beautifulsoup4
check_pip_pkg urllib3 urllib3

if [ $MISSING -eq 1 ]; then
    echo ""
    echo "[!] Some system dependencies are missing."
    echo "    On Kali/Debian: sudo apt install python3 python3-pip"
    echo "    On Termux:      pkg install python"
    exit 1
fi

echo ""
echo "[+] All dependencies satisfied. Pendo CLI is ready."

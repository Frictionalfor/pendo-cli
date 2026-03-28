#!/usr/bin/env bash
# setup.sh - Pendo CLI installer for Linux (Kali/Debian)
set -e

echo "[*] Pendo CLI - Setup"
echo "[*] Checking Python..."
python3 --version || { echo "[!] Python3 not found. Install it first."; exit 1; }

echo "[*] Installing dependencies..."
pip3 install -r requirements.txt --quiet

echo "[*] Making pendo.py executable..."
chmod +x pendo.py

PENDO_PATH="$(pwd)/pendo.py"
WRAPPER="$HOME/.local/bin/pendo"

mkdir -p "$HOME/.local/bin"
printf '#!/usr/bin/env bash\nexport PYTHONDONTWRITEBYTECODE=1\nexec python3 -B "%s" "$@"\n' "$PENDO_PATH" > "$WRAPPER"
chmod +x "$WRAPPER"

echo "[+] Installed: pendo -> $WRAPPER"

# Check PATH
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo "[!] Add this to your ~/.bashrc or ~/.zshrc:"
    echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

echo "[+] Setup complete. Run: pendo -h"

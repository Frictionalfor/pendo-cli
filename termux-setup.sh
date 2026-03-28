#!/usr/bin/env bash
# termux-setup.sh - Pendo CLI installer for Termux (Android, no root required)
set -e

echo "[*] Pendo CLI - Termux Setup"
echo "[*] Updating package lists..."
pkg update -y -o Dpkg::Options::="--force-confnew" 2>/dev/null || pkg update -y

echo "[*] Installing Python..."
pkg install python -y

echo "[*] Installing pip dependencies..."
pip install --quiet requests beautifulsoup4 urllib3

echo "[*] Making pendo.py executable..."
chmod +x pendo.py

# Create global command in Termux PREFIX bin
PENDO_PATH="$(pwd)/pendo.py"
WRAPPER="$PREFIX/bin/pendo"

printf '#!/usr/bin/env bash\nexport PYTHONDONTWRITEBYTECODE=1\nexec python3 -B "%s" "$@"\n' "$PENDO_PATH" > "$WRAPPER"
chmod +x "$WRAPPER"

echo "[+] Installed: pendo -> $WRAPPER"
echo "[+] Setup complete."
echo ""
echo "    Usage:"
echo "      pendo -h"
echo "      pendo scan https://example.com"
echo "      pendo probe https://example.com --payloads sqli"

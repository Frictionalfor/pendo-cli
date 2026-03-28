#!/usr/bin/env bash
# update.sh - One-command updater
set -e

echo "[*] Pendo CLI - Updater"

if [ -d ".git" ]; then
    echo "[*] Pulling latest changes..."
    git pull origin main
else
    echo "[!] Not a git repo. Download the latest release manually."
    exit 1
fi

echo "[*] Updating dependencies..."
pip3 install -r requirements.txt --quiet --upgrade

echo "[+] Update complete. Version: $(cat version.txt)"

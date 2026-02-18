#!/usr/bin/env bash
# =============================================================================
# setup.sh — One-time environment setup for shamir-secret-sharing
# =============================================================================
# Run once after cloning the repo:
#   chmod +x setup.sh && ./setup.sh

set -euo pipefail

echo ""
echo "============================================="
echo "  Shamir Secret Sharing — Environment Setup"
echo "============================================="
echo ""

# Check Python version
PYTHON_MIN="3.8"
PYTHON_CMD=""

for cmd in python3 python3.12 python3.11 python3.10 python3.9 python3.8; do
    if command -v "$cmd" &>/dev/null; then
        VERSION=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        MAJOR=$(echo "$VERSION" | cut -d. -f1)
        MINOR=$(echo "$VERSION" | cut -d. -f2)
        if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 8 ]; then
            PYTHON_CMD="$cmd"
            echo "[OK] Found Python $VERSION at $(command -v $cmd)"
            break
        fi
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    echo "[ERROR] Python 3.8+ is required but not found."
    echo "  macOS:   brew install python3"
    echo "  Ubuntu:  sudo apt install python3"
    echo "  Windows: https://www.python.org/downloads/"
    exit 1
fi

# Create virtual environment
VENV_DIR=".venv"
if [ -d "$VENV_DIR" ]; then
    echo "[INFO] Virtual environment already exists at .venv — skipping creation."
    echo "  To recreate: rm -rf .venv && ./setup.sh"
else
    echo "[INFO] Creating virtual environment..."
    "$PYTHON_CMD" -m venv "$VENV_DIR"
    echo "[OK] Virtual environment created at .venv"
fi

# Activate and install
echo "[INFO] Installing dependencies..."
source "$VENV_DIR/bin/activate"
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
echo "[OK] Dependencies installed."

# Make run script executable
chmod +x run.sh 2>/dev/null || true

echo ""
echo "============================================="
echo "  Setup complete!"
echo ""
echo "  To run the tool:  ./run.sh"
echo "  (Do NOT run shamir_key.py directly — use"
echo "   run.sh for shell history protection)"
echo "============================================="
echo ""

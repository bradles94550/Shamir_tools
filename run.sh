#!/usr/bin/env bash
# =============================================================================
# run.sh — Hardened launcher for the Shamir Secret Sharing toolkit
#
# Security measures applied:
#   1. Disables bash/zsh history for this shell session immediately
#   2. Activates the virtual environment
#   3. Offers choice: prepare a new secret OR go straight to shamir_key.py
#   4. Clears the screen on exit to prevent visual residue
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# 1. Disable shell history BEFORE any further input is read
# ---------------------------------------------------------------------------
unset HISTFILE
set +o history          2>/dev/null || true
export HISTSIZE=0
export HISTFILESIZE=0
unset SAVEHIST          2>/dev/null || true   # zsh (macOS default)
unset HISTDUP           2>/dev/null || true   # zsh duplicate suppression

# ---------------------------------------------------------------------------
# 2. Check venv exists
# ---------------------------------------------------------------------------
VENV_DIR=".venv"
if [ ! -d "$VENV_DIR" ]; then
    echo ""
    echo "[ERROR] Virtual environment not found."
    echo "  Please run setup first:  chmod +x setup.sh && ./setup.sh"
    echo ""
    exit 1
fi

source "$VENV_DIR/bin/activate"

# ---------------------------------------------------------------------------
# 3. Menu
# ---------------------------------------------------------------------------
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Shamir Secret Sharing Toolkit"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "  [INFO] Shell history is disabled for this session."
echo ""
echo "  What would you like to do?"
echo "  1. Password only — enter your 64-char password, split into shares"
echo "     (passkey field set to 'none'; each user manages their own auth)"
echo ""
echo "  2. Passkey + password — enter both, split into shares"
echo "     (full guided entry via prepare_secret.py)"
echo ""
echo "  3. Advanced / reconstruct — go straight to shamir_key.py"
echo "     (paste a JSON string you already have, or reconstruct from shares)"
echo ""
printf "  Enter 1, 2, or 3: "
read -r CHOICE
echo ""

case "$CHOICE" in
    1)
        python3 run_password_only.py
        ;;
    2)
        python3 prepare_secret.py
        ;;
    3)
        python3 shamir_key.py
        ;;
    *)
        echo "  Invalid choice. Exiting."
        exit 1
        ;;
esac

EXIT_CODE=$?

# ---------------------------------------------------------------------------
# 4. Clear screen on exit
# ---------------------------------------------------------------------------
echo ""
echo "  [INFO] Clearing screen in 3 seconds..."
sleep 3
clear

echo ""
echo "  Session ended. Terminal cleared."
echo "  Reminder: securely delete any output files (shares.txt, secret.json)"
echo "  once you have distributed or stored them appropriately."
echo ""

exit $EXIT_CODE

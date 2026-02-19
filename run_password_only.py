#!/usr/bin/env python3
"""
run_password_only.py — Password-only entry point for shamir_key.py

Use this when each custodian or user will manage their own passkey/authenticator
separately. This script only asks for the 64-character password, wraps it in
the required JSON format (passkey field set to "none"), and hands off directly
to shamir_key.py.

Usage:
    python3 run_password_only.py        # normal use
    ./run.sh                            # recommended (history suppressed)
"""

import sys
import os
import json
import pty
import termios
import tty
import select
import time
from getpass import getpass

# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------
def _supports_colour():
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if _supports_colour() else text

OK   = lambda t: _c("32", t)
ERR  = lambda t: _c("31", t)
INFO = lambda t: _c("36", t)
WARN = lambda t: _c("33", t)
BOLD = lambda t: _c("1",  t)

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
ALLOWED_CHARS = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "!@#$%^&*()-_=+[]{}|;:,.<>?/`~"
)

def validate_password(pw: str) -> list:
    errors = []
    if len(pw) != 64:
        errors.append(f"Must be exactly 64 characters (got {len(pw)})")
    bad = [c for c in pw if c not in ALLOWED_CHARS]
    if bad:
        errors.append(f"Contains disallowed characters: {list(dict.fromkeys(bad))}")
    return errors

# ---------------------------------------------------------------------------
# Collect password and optional TOTP seed
# ---------------------------------------------------------------------------
def collect_password() -> str:
    print()
    print("═" * 60)
    print(BOLD("  Password-Only Secret Entry"))
    print("═" * 60)
    print(f"""
{INFO('Note:')} The passkey/authenticator field is managed separately
  per user. This script captures your 64-character password and
  optionally your TOTP seed, wraps them in the required format,
  and passes everything directly to shamir_key.py.

  Password requirements:
    • Exactly 64 characters
    • Allowed: a-z  A-Z  0-9  and common special characters
    • Input is hidden (no echo) and confirmed by re-entry
""")

    while True:
        pw = getpass("  Password (hidden): ").strip()
        errors = validate_password(pw)
        if errors:
            for e in errors:
                print(ERR(f"  [ERROR] {e}"))
            print()
            continue

        pw2 = getpass("  Confirm password:  ").strip()
        if pw != pw2:
            print(ERR("  [ERROR] Passwords do not match. Please try again.\n"))
            continue

        print(OK("  [OK] Password accepted — 64 characters, valid.\n"))
        return pw


def collect_totp_seed() -> str:
    """Prompt for optional TOTP seed. Returns empty string if skipped."""
    print("─" * 60)
    print(BOLD("  TOTP SEED (optional)"))
    print(f"""
  {INFO('Do you have a TOTP seed to include? (e.g. AWS MFA seed)')}
  Expected format: 64-character Base32 string (A-Z and 2-7).
  This will be stored alongside the password in the secret JSON.
  Press Enter with no value to skip.
""")

    seed = getpass("  TOTP seed (hidden, or Enter to skip): ").strip()
    if not seed:
        print(INFO("  [SKIP] No TOTP seed provided.\n"))
        return ""

    seed2 = getpass("  Confirm TOTP seed: ").strip()
    if seed != seed2:
        print(ERR("  [ERROR] TOTP seeds do not match."))
        print(WARN("  [WARN] Skipping TOTP seed to avoid storing a mistyped value.\n"))
        return ""

    print(OK(f"  [OK] TOTP seed accepted ({len(seed)} characters, Base32).\n"))
    return seed

# ---------------------------------------------------------------------------
# Launch shamir_key.py via pty, injecting mode + JSON
# ---------------------------------------------------------------------------
def launch_shamir(json_string: str):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    shamir_path = os.path.join(script_dir, "shamir_key.py")

    if not os.path.exists(shamir_path):
        print(ERR(f"\n[ERROR] shamir_key.py not found at: {shamir_path}"))
        print("  Ensure run_password_only.py and shamir_key.py are in the same directory.")
        sys.exit(1)

    print("─" * 60)
    print(INFO("  Handing off to shamir_key.py..."))
    print(INFO("  Your password JSON has been prepared in memory only."))
    print("─" * 60)
    print()

    # Use pty so shamir_key.py behaves fully interactively after our injections
    try:
        master_fd, slave_fd = pty.openpty()
    except AttributeError:
        _fallback(json_string)
        return

    pid = os.fork()

    if pid == 0:
        # Child — become shamir_key.py
        os.setsid()
        import fcntl
        fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
        os.dup2(slave_fd, sys.stdin.fileno())
        os.dup2(slave_fd, sys.stdout.fileno())
        os.dup2(slave_fd, sys.stderr.fileno())
        os.close(master_fd)
        os.close(slave_fd)
        os.execv(sys.executable, [sys.executable, shamir_path])

    # Parent — bridge I/O, injecting the two lines first
    os.close(slave_fd)

    inject_lines = [b"1\n", (json_string + "\n").encode()]
    inject_idx = 0
    inject_delay = 0.15
    last_inject = time.time()
    inject_done = False

    real_in  = sys.stdin.fileno()
    real_out = sys.stdout.fileno()

    try:
        old_settings = termios.tcgetattr(real_in)
        tty.setraw(real_in)
        raw_mode = True
    except termios.error:
        raw_mode = False
        old_settings = None

    try:
        while True:
            result = os.waitpid(pid, os.WNOHANG)
            if result[0] != 0:
                break

            watch = [master_fd] + ([real_in] if inject_done else [])
            try:
                r, _, _ = select.select(watch, [], [], 0.05)
            except (select.error, ValueError):
                break

            if master_fd in r:
                try:
                    data = os.read(master_fd, 4096)
                    if data:
                        os.write(real_out, data)
                        sys.stdout.flush()
                except OSError:
                    break

            if not inject_done and inject_idx < len(inject_lines):
                if time.time() - last_inject >= inject_delay:
                    try:
                        os.write(master_fd, inject_lines[inject_idx])
                        inject_idx += 1
                        last_inject = time.time()
                        if inject_idx >= len(inject_lines):
                            inject_done = True
                    except OSError:
                        break

            if inject_done and real_in in r:
                try:
                    data = os.read(real_in, 1024)
                    if data:
                        os.write(master_fd, data)
                except OSError:
                    break
    finally:
        if raw_mode and old_settings:
            try:
                termios.tcsetattr(real_in, termios.TCSADRAIN, old_settings)
            except termios.error:
                pass
        try:
            os.close(master_fd)
        except OSError:
            pass

    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass


def _fallback(json_string: str):
    """Windows / non-pty fallback: print JSON and instruct manual paste."""
    print()
    print(WARN("  [INFO] Auto-launch not supported on this platform (no pty)."))
    print("  Copy the JSON below, then run: python3 shamir_key.py")
    print("  Paste it when prompted for the secret JSON.\n")
    print(f"  {json_string}\n")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    try:
        password = collect_password()
        totp_seed = collect_totp_seed()
    except KeyboardInterrupt:
        print("\n\n  Aborted.")
        sys.exit(0)

    # Build JSON — passkey is "none" as explicit placeholder
    secret = {"passkey": "none", "password": password}
    if totp_seed:
        secret["totp_seed"] = totp_seed
    payload = json.dumps(secret, separators=(",", ":"))

    # Scrub sensitive locals immediately
    del password
    del totp_seed
    del secret

    try:
        launch_shamir(payload)
    except KeyboardInterrupt:
        print("\n\n  Aborted.")
        sys.exit(0)


if __name__ == "__main__":
    main()

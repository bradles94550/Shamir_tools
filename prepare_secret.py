#!/usr/bin/env python3
"""
prepare_secret.py — Interactive helper to build the secret JSON and launch shamir_key.py

Usage:
    python3 prepare_secret.py          # interactive mode, launches shamir_key.py automatically
    python3 prepare_secret.py --print  # print JSON to stdout only (advanced/pipe use)
"""

import sys
import os
import json
import subprocess
import argparse
from getpass import getpass

# ---------------------------------------------------------------------------
# ANSI colour helpers (gracefully disabled if terminal doesn't support them)
# ---------------------------------------------------------------------------
def _supports_colour():
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if _supports_colour() else text

OK   = lambda t: _c("32", t)   # green
ERR  = lambda t: _c("31", t)   # red
INFO = lambda t: _c("36", t)   # cyan
WARN = lambda t: _c("33", t)   # yellow
BOLD = lambda t: _c("1",  t)   # bold

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

ALLOWED_PASSWORD_CHARS = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "!@#$%^&*()-_=+[]{}|;:,.<>?/`~"
)

def validate_password(pw: str) -> list[str]:
    """Return a list of validation error strings (empty = valid)."""
    errors = []
    if len(pw) != 64:
        errors.append(f"Must be exactly 64 characters (got {len(pw)})")
    bad = [c for c in pw if c not in ALLOWED_PASSWORD_CHARS]
    if bad:
        unique_bad = list(dict.fromkeys(bad))
        errors.append(f"Contains disallowed characters: {unique_bad}")
    return errors


def validate_passkey(pk: str) -> list[str]:
    errors = []
    if not pk:
        errors.append("Passkey cannot be empty")
    if len(pk) > 512:
        errors.append("Passkey is unusually long (>512 chars) — double-check this is correct")
    return errors


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------

def prompt_secret(label: str, confirm: bool = False) -> str:
    """Prompt for a secret value using getpass (no echo)."""
    while True:
        val = getpass(f"  {label}: ").strip()
        if not val:
            print(ERR("  [ERROR] Value cannot be empty. Please try again."))
            continue
        if confirm:
            val2 = getpass(f"  Confirm {label}: ").strip()
            if val != val2:
                print(ERR("  [ERROR] Values do not match. Please try again."))
                continue
        return val


def prompt_visible(label: str) -> str:
    """Prompt for a non-secret value with visible input."""
    while True:
        val = input(f"  {label}: ").strip()
        if val:
            return val
        print(ERR("  [ERROR] Value cannot be empty. Please try again."))


def separator(char="─", width=60):
    print(char * width)


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------

def collect_secret() -> dict:
    """Interactively collect and validate the passkey and password."""

    separator("═")
    print(BOLD("  Secret Preparation — Step 1 of 2"))
    print("  Build your secret JSON before splitting into shares")
    separator("═")

    print(f"""
{INFO('What this script does:')}
  1. Prompts you for your passkey and 64-character password
  2. Validates both inputs
  3. Builds the JSON string
  4. Passes it directly to shamir_key.py — it is never written to disk here

{WARN('Security note:')} Input is collected via hidden prompt (no echo).
  Use ./run.sh to ensure shell history is suppressed for the full session.
""")

    # --- Passkey ---
    separator()
    print(BOLD("  PASSKEY"))
    print("  This is your passkey / passphrase / account identifier.")
    print("  It can be any non-empty string (no length restriction).")
    separator()
    print()

    while True:
        passkey = prompt_secret("Passkey (hidden input)", confirm=True)
        errs = validate_passkey(passkey)
        if errs:
            for e in errs:
                print(WARN(f"  [WARN] {e}"))
            print("  Proceed anyway? (y/n): ", end="")
            if input().strip().lower() != "y":
                continue
        print(OK("  [OK] Passkey accepted."))
        break

    # --- Password ---
    print()
    separator()
    print(BOLD("  64-CHARACTER PASSWORD"))
    print("  Must be exactly 64 characters.")
    print("  Allowed: a-z A-Z 0-9 and common special characters")
    separator()
    print()

    while True:
        password = prompt_secret("Password (hidden input)", confirm=True)
        errs = validate_password(password)
        if errs:
            for e in errs:
                print(ERR(f"  [ERROR] {e}"))
            print()
            print("  Would you like to try again? (y/n): ", end="")
            if input().strip().lower() == "y":
                continue
            else:
                print(ERR("\n  Aborted by user."))
                sys.exit(1)
        print(OK("  [OK] Password accepted — 64 characters, all valid."))
        break

    return {"passkey": passkey, "password": password}


def build_json(secret: dict) -> str:
    return json.dumps(secret, separators=(",", ":"))


def launch_shamir(json_string: str):
    """Launch shamir_key.py, feeding the JSON string as the first input."""

    script_dir = os.path.dirname(os.path.abspath(__file__))
    shamir_path = os.path.join(script_dir, "shamir_key.py")

    if not os.path.exists(shamir_path):
        print(ERR(f"\n[ERROR] shamir_key.py not found at: {shamir_path}"))
        print("  Make sure prepare_secret.py and shamir_key.py are in the same directory.")
        sys.exit(1)

    print()
    separator("═")
    print(BOLD("  Launching shamir_key.py — Step 2 of 2"))
    separator("═")
    print()
    print(INFO("  [INFO] Your secret JSON has been prepared and will be passed"))
    print(INFO("         directly to shamir_key.py. It is not stored on disk."))
    print()

    # We need to inject the JSON string as input to shamir_key.py's first prompt.
    # Strategy: pipe "1\n{json}\n" as the start of stdin, then hand control back
    # to the user for the remaining interactive prompts.
    #
    # We use a wrapper: write the preamble to a temp FIFO / pty-style approach.
    # Simplest portable method: use a shell heredoc via subprocess with stdin=PIPE
    # for the JSON line only, then re-attach to the real tty for subsequent input.

    import pty
    import termios
    import tty

    # Check if we're on a platform that supports pty (Unix/macOS/Linux)
    try:
        # Create a pseudo-terminal so shamir_key.py behaves interactively
        master_fd, slave_fd = pty.openpty()
    except AttributeError:
        # Fallback for platforms without pty (e.g. some Windows environments)
        _launch_fallback(json_string, shamir_path)
        return

    # We'll run shamir_key.py as a child process connected to the pty slave,
    # then manually inject the mode selection ("1") and the JSON line,
    # then bridge the master_fd <-> real stdin/stdout for the rest.

    pid = os.fork()

    if pid == 0:
        # --- Child: be the shamir_key.py process ---
        os.setsid()
        import fcntl
        fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
        os.dup2(slave_fd, sys.stdin.fileno())
        os.dup2(slave_fd, sys.stdout.fileno())
        os.dup2(slave_fd, sys.stderr.fileno())
        os.close(master_fd)
        os.close(slave_fd)
        os.execv(sys.executable, [sys.executable, shamir_path])
        # execv replaces the process; we never reach here

    # --- Parent: orchestrate I/O ---
    os.close(slave_fd)

    import select
    import time

    real_stdin_fd = sys.stdin.fileno()
    real_stdout_fd = sys.stdout.fileno()

    # Try to set raw mode on stdin so keypresses pass through cleanly
    try:
        old_settings = termios.tcgetattr(real_stdin_fd)
        tty.setraw(real_stdin_fd)
        raw_mode = True
    except termios.error:
        raw_mode = False
        old_settings = None

    # Lines to auto-inject: mode selection then the JSON
    inject_lines = [b"1\n", (json_string + "\n").encode()]
    inject_idx = 0
    inject_delay = 0.15  # seconds between injections (wait for prompt)
    last_inject_time = time.time()
    inject_done = False

    try:
        while True:
            # Check if child exited
            result = os.waitpid(pid, os.WNOHANG)
            if result[0] != 0:
                break

            rlist = [master_fd]
            if inject_done:
                rlist.append(real_stdin_fd)

            try:
                r, _, _ = select.select(rlist, [], [], 0.05)
            except (select.error, ValueError):
                break

            # Forward child output to real stdout
            if master_fd in r:
                try:
                    data = os.read(master_fd, 4096)
                    if data:
                        os.write(real_stdout_fd, data)
                        sys.stdout.flush()
                except OSError:
                    break

            # Auto-inject lines at appropriate timing
            if not inject_done and inject_idx < len(inject_lines):
                now = time.time()
                if now - last_inject_time >= inject_delay:
                    try:
                        os.write(master_fd, inject_lines[inject_idx])
                        inject_idx += 1
                        last_inject_time = now
                        if inject_idx >= len(inject_lines):
                            inject_done = True
                    except OSError:
                        break

            # Forward real user input to child
            if inject_done and real_stdin_fd in r:
                try:
                    data = os.read(real_stdin_fd, 1024)
                    if data:
                        os.write(master_fd, data)
                except OSError:
                    break

    finally:
        if raw_mode and old_settings:
            try:
                termios.tcsetattr(real_stdin_fd, termios.TCSADRAIN, old_settings)
            except termios.error:
                pass
        try:
            os.close(master_fd)
        except OSError:
            pass

    # Final waitpid to reap child
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass


def _launch_fallback(json_string: str, shamir_path: str):
    """
    Fallback for environments without pty (e.g. Windows native, some CI).
    Prints the JSON and instructions instead of auto-injecting.
    """
    print()
    print(WARN("  [INFO] Auto-launch not supported on this platform."))
    print("  Please copy the JSON below and paste it when shamir_key.py asks")
    print("  for your secret JSON.\n")
    print(f"  {json_string}\n")
    print("  Then run:  python3 shamir_key.py")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Prepare secret JSON and launch shamir_key.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./run.sh prepare          # Use the combined launcher (recommended)
  python3 prepare_secret.py # Run directly (ensure shell history is suppressed)
  python3 prepare_secret.py --print  # Print JSON only, don't launch shamir_key.py
        """
    )
    parser.add_argument(
        "--print",
        action="store_true",
        help="Print the JSON string to stdout instead of launching shamir_key.py (for piping/testing)"
    )
    args = parser.parse_args()

    try:
        secret = collect_secret()
    except KeyboardInterrupt:
        print("\n\n  Aborted.")
        sys.exit(0)

    json_string = build_json(secret)

    if args.print:
        # Just emit the JSON — useful for piping or manual review
        print()
        print(json_string)
        sys.exit(0)

    try:
        launch_shamir(json_string)
    except KeyboardInterrupt:
        print("\n\n  Aborted.")
        sys.exit(0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Shamir's Secret Sharing - Portable Key Split/Reconstruct Tool
Requires only Python 3.6+ standard library + one common package: cryptography

Install dependency:
    pip install cryptography

Usage:
    python3 shamir_key.py
"""

import sys
import os
import json
import base64
import hashlib
import secrets
import itertools
from getpass import getpass

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("\n[ERROR] Missing dependency. Please run:\n    pip install cryptography\n")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Shamir's Secret Sharing over GF(2^8)  — pure Python, no extra libs
# ---------------------------------------------------------------------------

PRIME = 257  # smallest prime > 255; all byte values 0-255 are valid field elements


def _eval_poly(coeffs, x):
    result = 0
    for c in reversed(coeffs):
        result = (result * x + c) % PRIME
    return result


def _mod_inverse(a, p):
    if a == 0:
        raise ValueError("0 has no inverse")
    lm, hm = 1, 0
    low, high = a % p, p
    while low > 1:
        ratio = high // low
        lm, hm = hm - lm * ratio, lm
        low, high = high - low * ratio, low
    return lm % p


def _lagrange_interpolate(x, x_s, y_s):
    k = len(x_s)
    total = 0
    for i in range(k):
        num = den = 1
        for j in range(k):
            if i == j:
                continue
            num = (num * (x - x_s[j])) % PRIME
            den = (den * (x_s[i] - x_s[j])) % PRIME
        lagrange = num * _mod_inverse(den, PRIME) % PRIME
        total = (total + y_s[i] * lagrange) % PRIME
    return total


def _pack_values(values):
    """Pack list of ints (0-256) as 2-bytes-each big-endian bytes."""
    out = bytearray()
    for v in values:
        out.extend(v.to_bytes(2, "big"))
    return bytes(out)


def _unpack_values(data):
    """Unpack 2-bytes-each big-endian bytes to list of ints."""
    return [int.from_bytes(data[i:i+2], "big") for i in range(0, len(data), 2)]


def split_secret(secret_bytes, n, k):
    """Split secret_bytes into n shares, k required to reconstruct."""
    raw_shares = [(i, []) for i in range(1, n + 1)]
    for byte_val in secret_bytes:
        coeffs = [byte_val] + [secrets.randbelow(PRIME) for _ in range(k - 1)]
        for x, share_list in raw_shares:
            share_list.append(_eval_poly(coeffs, x))
    # Pack values (each 0-256) into 2-byte encoding
    return [(x, _pack_values(vals)) for x, vals in raw_shares]


def reconstruct_secret(shares):
    """Reconstruct secret from list of (x, packed_share_bytes) tuples."""
    if not shares:
        raise ValueError("No shares provided")
    unpacked = [(x, _unpack_values(data)) for x, data in shares]
    length = len(unpacked[0][1])
    x_s = [s[0] for s in unpacked]
    result = []
    for i in range(length):
        y_s = [s[1][i] for s in unpacked]
        result.append(_lagrange_interpolate(0, x_s, y_s))
    return bytes(result)


# ---------------------------------------------------------------------------
# Encryption helpers (AES-256-GCM)
# ---------------------------------------------------------------------------

def derive_key(password: str) -> bytes:
    """Derive a 32-byte AES key from a password using SHA-256."""
    return hashlib.sha256(password.encode()).digest()


def encrypt_payload(plaintext: str, password: str) -> bytes:
    """Encrypt plaintext string with AES-256-GCM, return raw ciphertext bundle."""
    key = derive_key(password)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce + ct  # prepend nonce


def decrypt_payload(ciphertext_bundle: bytes, password: str) -> str:
    """Decrypt ciphertext bundle, return plaintext string."""
    key = derive_key(password)
    aesgcm = AESGCM(key)
    nonce, ct = ciphertext_bundle[:12], ciphertext_bundle[12:]
    return aesgcm.decrypt(nonce, ct, None).decode()


# ---------------------------------------------------------------------------
# Share encoding / decoding for human-friendly transport
# ---------------------------------------------------------------------------

def encode_share(x: int, share_bytes: bytes) -> str:
    """Encode a share as a base64 string prefixed with its index."""
    payload = bytes([x]) + share_bytes  # x stored as first byte (supports up to 255 shares)
    return base64.b85encode(payload).decode()


def decode_share(share_str: str) -> tuple[int, bytes]:
    """Decode an encoded share string back to (x, share_bytes)."""
    payload = base64.b85decode(share_str.strip())
    x = payload[0]
    return x, payload[1:]


# ---------------------------------------------------------------------------
# Verification helper
# ---------------------------------------------------------------------------

def verify_all_combinations(shares: list[tuple[int, bytes]], k: int, master: bytes) -> bool:
    """Test every k-combination of shares to verify they all reconstruct master."""
    print(f"\n  Verifying all C({len(shares)},{k}) = {len(list(itertools.combinations(shares, k)))} combinations...")
    failed = 0
    for combo in itertools.combinations(shares, k):
        result = reconstruct_secret(list(combo))
        if result != master:
            failed += 1
            print(f"  [FAIL] Combination {[s[0] for s in combo]} did not reconstruct correctly!")
    if failed == 0:
        print(f"  [OK] All combinations verified successfully.\n")
        return True
    else:
        print(f"  [ERROR] {failed} combinations failed verification!\n")
        return False


# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------

def separator(char="─", width=60):
    print(char * width)


def prompt_int(prompt: str, min_val: int, max_val: int) -> int:
    while True:
        try:
            val = int(input(prompt).strip())
            if min_val <= val <= max_val:
                return val
            print(f"  Please enter a number between {min_val} and {max_val}.")
        except ValueError:
            print("  Invalid input. Please enter a number.")


# ---------------------------------------------------------------------------
# Create flow
# ---------------------------------------------------------------------------

def flow_create():
    separator()
    print("  CREATE — Split a secret into Shamir shares")
    separator()

    print("""
You will be asked to provide a JSON string containing your secret data.
Example format (password only):
    {"passkey":"none","password":"your-64-char-password-here"}

Example format (with optional TOTP seed):
    {"passkey":"none","password":"your-64-char-password-here","totp_seed":"your-seed-here"}
""")

    # Collect the secret JSON
    print("Paste your secret JSON (single line), then press Enter:")
    raw_json = input("> ").strip()

    # Validate JSON
    try:
        parsed = json.loads(raw_json)
        assert "passkey" in parsed and "password" in parsed, "JSON must contain 'passkey' and 'password' fields"
        assert len(parsed["password"]) == 64, f"'password' must be exactly 64 characters (got {len(parsed['password'])})"
        # totp_seed is optional — no length/format constraint, store as-is
        if "totp_seed" in parsed:
            assert isinstance(parsed["totp_seed"], str) and parsed["totp_seed"], "'totp_seed' must be a non-empty string"
    except (json.JSONDecodeError, AssertionError) as e:
        print(f"\n[ERROR] Invalid input: {e}")
        sys.exit(1)

    # Optional: encrypt the secret before splitting
    print("\nWould you like to encrypt the secret with a passphrase before splitting? (y/n)")
    use_encryption = input("> ").strip().lower() == "y"
    
    if use_encryption:
        passphrase = getpass("Enter encryption passphrase: ")
        passphrase_confirm = getpass("Confirm passphrase: ")
        if passphrase != passphrase_confirm:
            print("[ERROR] Passphrases do not match.")
            sys.exit(1)
        payload = encrypt_payload(raw_json, passphrase)
        print("  [OK] Secret encrypted.")
    else:
        payload = raw_json.encode()

    # Split parameters
    print()
    n = prompt_int("How many total shares to generate? (2-20): ", 2, 20)
    k = prompt_int(f"How many shares required to reconstruct? (2-{n}): ", 2, n)

    # Perform the split
    print(f"\n  Splitting into {n} shares, requiring {k} to reconstruct...")
    raw_shares = split_secret(payload, n, k)

    # Verify
    ok = verify_all_combinations(raw_shares, k, payload)
    if not ok:
        print("[CRITICAL] Verification failed. Do NOT distribute these shares.")
        sys.exit(1)

    # Display shares
    separator()
    print("  YOUR SHARES — Distribute each to a separate trusted holder")
    separator()
    encoded_shares = []
    for x, share_bytes in raw_shares:
        encoded = encode_share(x, share_bytes)
        encoded_shares.append(encoded)
        print(f"\n  Share #{x}:\n  {encoded}")
    
    print(f"""
{separator.__doc__ and '' or ''}{"─"*60}
  IMPORTANT NOTES:
  • You need any {k} of these {n} shares to reconstruct the secret.
  • Store each share separately and securely.
  • Anyone with {k} or more shares can reconstruct the secret.
{"─"*60}
""")

    # Optionally save to file
    print("Save shares to a text file? (y/n)")
    if input("> ").strip().lower() == "y":
        fname = input("Filename (default: shares.txt): ").strip() or "shares.txt"
        with open(fname, "w") as f:
            f.write(f"Shamir Secret Sharing — {n} shares, {k} required\n")
            f.write("=" * 60 + "\n\n")
            for i, enc in enumerate(encoded_shares, 1):
                f.write(f"Share #{i}:\n{enc}\n\n")
            f.write(f"\nNOTE: Any {k} of these {n} shares reconstructs the secret.\n")
        print(f"  Saved to {fname}")


# ---------------------------------------------------------------------------
# Reconstruct flow
# ---------------------------------------------------------------------------

def flow_reconstruct():
    separator()
    print("  RECONSTRUCT — Combine shares to recover the secret")
    separator()

    k = prompt_int("\nHow many shares are you providing? (2-20): ", 2, 20)

    shares = []
    for i in range(1, k + 1):
        while True:
            raw = input(f"\nPaste share #{i}: ").strip()
            try:
                x, share_bytes = decode_share(raw)
                shares.append((x, share_bytes))
                print(f"  [OK] Share index {x} accepted.")
                break
            except Exception as e:
                print(f"  [ERROR] Could not decode share: {e}. Please try again.")

    print("\n  Reconstructing secret...")
    try:
        payload = reconstruct_secret(shares)
    except Exception as e:
        print(f"[ERROR] Reconstruction failed: {e}")
        sys.exit(1)

    # Try to decode as plain JSON first; if that fails, try decryption
    try:
        secret_str = payload.decode("utf-8")
        json.loads(secret_str)  # validate
        print("  [OK] Secret reconstructed (no encryption detected).\n")
    except (UnicodeDecodeError, json.JSONDecodeError):
        # Likely encrypted
        print("  Secret appears to be encrypted.")
        passphrase = getpass("Enter decryption passphrase: ")
        try:
            secret_str = decrypt_payload(payload, passphrase)
            json.loads(secret_str)  # validate
            print("  [OK] Secret decrypted successfully.\n")
        except Exception:
            print("[ERROR] Decryption failed. Wrong passphrase or corrupted shares.")
            sys.exit(1)

    separator()
    print("  RECONSTRUCTED SECRET")
    separator()
    parsed = json.loads(secret_str)
    print(f"\n  passkey   : {parsed.get('passkey', '<not found>')}")
    print(f"  password  : {parsed.get('password', '<not found>')}")
    if "totp_seed" in parsed:
        print(f"  totp_seed : {parsed.get('totp_seed')}  (Base32, {len(parsed['totp_seed'])} chars)")
    print()

    # Optionally save to file
    print("Save reconstructed secret to a file? (y/n)")
    if input("> ").strip().lower() == "y":
        fname = input("Filename (default: secret.json): ").strip() or "secret.json"
        with open(fname, "w") as f:
            json.dump(parsed, f, indent=2)
        print(f"  Saved to {fname}")
        print("  WARNING: Delete this file securely after use.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print()
    separator("═")
    print("  Shamir's Secret Sharing Tool")
    print("  Portable | AES-256-GCM Encryption | Self-verifying")
    separator("═")
    print("""
  This tool splits a secret (JSON with passkey + 64-char password)
  into N shares using Shamir's Secret Sharing scheme.
  Any K shares reconstruct the original. Fewer than K reveal nothing.
""")

    print("What would you like to do?")
    print("  1. Create — Split a secret into shares")
    print("  2. Decode — Reconstruct a secret from shares")
    print()

    choice = input("Enter 1 or 2: ").strip()
    print()

    if choice == "1":
        flow_create()
    elif choice == "2":
        flow_reconstruct()
    else:
        print("[ERROR] Invalid choice.")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Aborted.")
        sys.exit(0)

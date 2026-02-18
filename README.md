# Shamir Secret Sharing — Portable Key Split Tool

A self-contained Python tool for splitting sensitive secrets (passkeys, passwords) into **N shares** using [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing), where any **K shares** can reconstruct the original. Fewer than K shares reveal **nothing** about the secret — this is information-theoretically proven, not just computationally assumed.

Designed for practical operational security: air-gap friendly, no cloud dependencies, fully auditable, and ships with a hardened launcher that suppresses shell history.

---

## Why Shamir's Secret Sharing?

Standard backup strategies for high-value secrets (master passwords, recovery keys, API credentials) force an uncomfortable tradeoff:

| Strategy | Risk |
|---|---|
| Single copy with one person | Single point of failure — loss or compromise ends you |
| Multiple copies with multiple people | Each copy is a full compromise risk |
| Encrypted + stored centrally | Vault becomes the single point of failure |

Shamir's Secret Sharing eliminates this tradeoff. A 3-of-5 scheme means:

- **Any 3 custodians** can reconstruct the secret independently
- **Any 2 custodians colluding** learn provably nothing — not even partial information
- **Losing 2 custodians** does not break recoverability
- **No single custodian** can act alone

This is mathematically guaranteed by polynomial interpolation over a finite field, not by policy or trust.

---

## Contents

```
shamir-secret-sharing/
├── shamir_key.py      # Core tool — Shamir splitting and reconstruction
├── prepare_secret.py  # Helper — guided passkey+password entry, auto-launches shamir_key.py
├── requirements.txt   # cryptography>=41.0.0
├── setup.sh           # One-time venv setup
├── run.sh             # Hardened launcher (suppresses shell history, menu, clears screen)
└── README.md          # This file
```

---

## Requirements

- **Python 3.8+** (standard library only, plus one package)
- **`cryptography` package** — for AES-256-GCM envelope encryption (installed automatically by setup)
- Runs on macOS, Linux, Windows (WSL recommended on Windows)

---

## Quick Start

### 1. Clone and set up

```bash
git clone https://github.com/YOUR_USERNAME/shamir-secret-sharing.git
cd shamir-secret-sharing
chmod +x setup.sh run.sh
./setup.sh
```

### 2. Run

```bash
./run.sh
```

> **Always use `run.sh`**, not `python3 shamir_key.py` directly.  
> `run.sh` disables shell history before the tool starts.

---

## Setup Details

### What `setup.sh` does

1. Detects a suitable Python 3.8+ interpreter
2. Creates an isolated virtual environment at `.venv/`
3. Installs `cryptography` (pinned to ≥41.0.0 for modern AES-GCM support)
4. Makes `run.sh` executable

### Recreating the environment

```bash
rm -rf .venv
./setup.sh
```

---

## Security Hardening

### Shell history suppression (`run.sh`)

When you paste a secret or share into a terminal, it can be written to your shell's history file (e.g., `~/.bash_history`, `~/.zsh_history`) and recovered later — even after the session ends.

`run.sh` mitigates this with four layers:

| Measure | What it does |
|---|---|
| `unset HISTFILE` | Prevents bash from writing *any* history to disk for this session |
| `set +o history` | Disables in-memory history capture |
| `HISTSIZE=0` / `HISTFILESIZE=0` | Zero-size history buffers |
| `unset SAVEHIST` | zsh equivalent (macOS default shell) |

> **These measures apply only to the subshell launched by `run.sh`.** Your main terminal's history is unaffected by commands typed *before* running `./run.sh`.

### Screen clearing on exit

After the tool finishes, `run.sh` waits a few seconds and then clears the terminal. This prevents share strings from remaining visible if you step away from your machine.

### Additional hardening recommendations

**OS level:**

```bash
# Verify your shell history file is not capturing this session
# (run inside the ./run.sh session to confirm)
echo $HISTFILE   # Should be empty
echo $HISTSIZE   # Should be 0
```

**For high-assurance use:**

- Run on an **air-gapped machine** — one that has never been and will never be connected to a network. A Raspberry Pi running offline Raspberry Pi OS is ideal for this.
- If air-gapping is not possible, boot from a **live USB** (e.g., Tails OS) so no persistent state survives the session.
- **Disable swap** before running: `sudo swapoff -a` on Linux. Swap can page memory contents to disk, potentially including your secret.
- Use **full-disk encryption** (FileVault on macOS, BitLocker on Windows, LUKS on Linux) on any machine where shares may be saved to disk.
- After generating shares, **immediately shred** any output files before deleting:

```bash
# Linux
shred -vuz shares.txt

# macOS (no shred; use srm or overwrite manually)
rm -P shares.txt
```

**Network:**

- Never transmit shares over the same channel you use to transmit the secret.
- Never email all shares to the same person or store multiple shares in the same vault.

---

## Usage

### Recommended flow: `./run.sh`

`run.sh` is the single entry point for all operations. After disabling shell history it presents a menu:

```
  What would you like to do?
  1. Prepare a new secret and split into shares
     (guided: enter passkey + password → auto-launches split tool)

  2. Go straight to shamir_key.py
     (for splitting a JSON string you already have, or reconstructing)
```

---

### Option 1 — Prepare and split (new secret)

Choose **1** to launch `prepare_secret.py`. This walks you through:

1. **Passkey entry** — hidden input (no echo), confirmed by re-entry
2. **64-character password entry** — hidden input, validated for length and character set, confirmed by re-entry
3. **Automatic handoff** — the JSON string is built in memory and injected directly into `shamir_key.py`. It is never written to disk by this step.

```
  PASSKEY
  Passkey (hidden input): ••••••••••••
  Confirm Passkey: ••••••••••••
  [OK] Passkey accepted.

  64-CHARACTER PASSWORD
  Password (hidden input): ••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••
  Confirm Password: ••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••
  [OK] Password accepted — 64 characters, all valid.

  Launching shamir_key.py — Step 2 of 2
```

`shamir_key.py` then takes over with the standard splitting prompts (encryption passphrase, N, K).

---

### Option 2 — Direct access to `shamir_key.py`

Choose **2** to go straight to `shamir_key.py`. Use this when:

- You are **reconstructing** a secret from shares
- You already have a JSON string prepared and want to split it manually

```
What would you like to do?
  1. Create — Split a secret into shares
  2. Decode — Reconstruct a secret from shares
```

---

### Creating shares (inside `shamir_key.py`)

When creating, you will be prompted to:

1. **Paste your secret as a single-line JSON string** (if not coming from `prepare_secret.py`):
   ```json
   {"passkey": "your-passkey-here", "password": "your-exactly-64-character-password-here-padded-ok"}
   ```
   The `password` field must be exactly 64 characters.

2. **Optionally encrypt the JSON with a passphrase** (AES-256-GCM) before splitting. Custodians with K shares still cannot reconstruct the secret without also knowing this passphrase — a second independent layer of protection.

3. **Choose N** (total shares, 2–20) and **K** (shares required to reconstruct, 2–N)

The tool then verifies **every possible K-subset** before displaying anything, then prints shares as base85-encoded strings.

---

### Reconstructing the secret

Choose option **2** from the `run.sh` menu, then option **2** inside `shamir_key.py`:

```
How many shares are you providing?: 3

Paste share #1: 0RVdd4*(Ycf&i8PbO5*j...
  [OK] Share index 1 accepted.

Paste share #2: 0sz4PumG$8TL8}hHUO3Y...
  [OK] Share index 2 accepted.

Paste share #3: 0{~0_0{|@m?EoDBx&Q?L...
  [OK] Share index 3 accepted.

  passkey  : your-passkey-here
  password : your-64-character-password-here...
```

---

## How it works

### Mathematical foundation

The secret is split **byte by byte**. For each byte value `s` (0–255):

1. A random polynomial `f(x) = s + a₁x + a₂x² + ... + a_{k-1}x^{k-1}` is constructed where `s` is the constant term (the secret) and `a₁...a_{k-1}` are random coefficients.
2. The polynomial is evaluated at points `x = 1, 2, ..., N` to generate N share values.
3. Any K of these points are sufficient to uniquely determine the polynomial via **Lagrange interpolation**, recovering `s = f(0)`.

All arithmetic is performed modulo the prime **257** (the smallest prime larger than 255), which ensures every byte value is a valid field element. Share values can be 0–256, so each is encoded as 2 bytes.

This scheme has **perfect secrecy**: any set of fewer than K shares is statistically independent of the secret.

### Envelope encryption (optional)

If you choose to add a passphrase:
- The JSON secret is encrypted with **AES-256-GCM** using a key derived from your passphrase via SHA-256.
- A random 96-bit nonce is prepended to the ciphertext.
- The resulting binary blob is what gets split into shares — not the plaintext JSON.
- Reconstruction yields the encrypted blob, which then requires the passphrase to decrypt.

### Self-verification

After generating shares, the tool uses Python's `itertools.combinations` to test **every possible K-subset** of the N shares:

- C(5, 3) = 10 combinations for a 3-of-5 scheme
- C(10, 4) = 210 combinations for a 4-of-10 scheme

Each combination is reconstructed and compared to the original master. If any fail, the tool aborts and refuses to display shares. This catches any implementation bugs or entropy failures before you distribute anything you cannot undo.

---

## Operational checklist

Use this checklist each time you generate a set of shares:

### Before generating

- [ ] Machine is dedicated / air-gapped, or you accept the risk model
- [ ] Disk encryption is enabled
- [ ] Swap is disabled (`sudo swapoff -a`)
- [ ] You are using `./run.sh`, not running the script directly
- [ ] You have identified your N custodians and a secure channel to each

### During generation

- [ ] You are alone or in a trusted, private location (no cameras, no shoulder-surfers)
- [ ] The screen clear timeout in `run.sh` is acceptable for your environment
- [ ] You have written down or transmitted each share to its custodian immediately after generation

### After generation

- [ ] Shares have been delivered via your established out-of-band process
- [ ] You have confirmed receipt with each custodian
- [ ] Any intermediate files (`shares.txt`) have been securely deleted
- [ ] You have tested reconstruction with at least K custodians before the session ends

---

## Threat model

This tool addresses the following threats:

| Threat | Mitigation |
|---|---|
| Single custodian compromise | Attacker has fewer than K shares → learns nothing |
| Custodian loss / unavailability | N−K redundant shares accommodate loss |
| Shell history disclosure | `run.sh` disables history before first input |
| Screen shoulder-surfing | Auto-clear on exit |
| Implementation bug in share generation | Exhaustive combination verification before output |
| Brute force on encrypted secret | AES-256-GCM; computationally infeasible |
| Share forgery | AES-GCM authentication tag detects tampering during decryption |

This tool does **not** address:

| Threat | Notes |
|---|---|
| Custodian coercion | Social/legal problem, not cryptographic |
| Compromised runtime environment (keylogger, malware) | Use air-gapped hardware for high-assurance use |
| Side-channel attacks (timing, power) | Pure Python is not constant-time |
| Quantum adversaries | AES-256 has reasonable post-quantum security; Shamir's scheme is information-theoretically secure and unaffected by quantum computers |

---

## Dependency audit

The tool has exactly **one third-party dependency**:

| Package | Version | Purpose | Audit |
|---|---|---|---|
| `cryptography` | ≥41.0.0 | AES-256-GCM via `AESGCM` | [PyPI](https://pypi.org/project/cryptography/) / [GitHub](https://github.com/pyf/cryptography) — maintained by the Python Cryptographic Authority (PyCA); widely audited |

Everything else — Shamir's polynomial math, Lagrange interpolation, base85 encoding, all I/O — uses the Python standard library only.

To verify the installed version:

```bash
source .venv/bin/activate
pip show cryptography
```

---

## Platform notes

### macOS

- Default shell since Catalina is **zsh**. `run.sh` handles both bash and zsh history suppression.
- `rm -P filename` for secure deletion (no `shred` by default).
- If running on Apple Silicon (M1/M2/M3): works natively with Python 3.8+.

### Linux

- Tested on Ubuntu 22.04+, Debian 12, Raspberry Pi OS (bookworm).
- `shred -vuz filename` for secure deletion.
- Disable swap: `sudo swapoff -a` (temporary) or remove swap from `/etc/fstab` (permanent).

### Windows

- **WSL2 (Windows Subsystem for Linux)** is strongly recommended.
- Native Windows (PowerShell/CMD): `setup.sh` and `run.sh` will not work directly.  
  Use instead:
  ```powershell
  python -m venv .venv
  .venv\Scripts\activate
  pip install -r requirements.txt
  python shamir_key.py
  ```
  Note: Shell history suppression is not implemented for PowerShell/CMD. Consider WSL2.

---

## License

MIT License. See [LICENSE](LICENSE).

---

## Contributing

Pull requests welcome. Areas of particular interest:

- Windows native launcher (`run.ps1`) with PowerShell history suppression
- Additional input formats beyond the current JSON schema
- PBKDF2/Argon2 key derivation for the optional encryption passphrase (currently SHA-256)
- Test suite

Please do not add dependencies beyond the Python standard library and `cryptography`.

---

## References

- Shamir, A. (1979). "How to share a secret." *Communications of the ACM*, 22(11), 612–613.
- [Wikipedia: Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing)
- [Python Cryptographic Authority — cryptography library](https://cryptography.io)
- [NIST SP 800-38D — AES-GCM specification](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)

# CipherShield -- Post-Quantum Cryptography Lab

An educational desktop app for exploring classical vs. post-quantum public-key
cryptography. **This is not an antivirus** -- it doesn't scan files or detect
malware. It's a hands-on lab for encryption, digital signatures, and why
NIST's post-quantum standards exist.

## What changed from the original version

The original `main.py` had an algorithm dropdown (RSA/ECC/Kyber/Dilithium)
that didn't actually do anything -- every choice silently used the same
Fernet encryption underneath. The "Run Quantum Attack" button didn't attack
anything; it was a timer plus a hardcoded if-statement. And `graph.py`
plotted four made-up numbers labeled `# Example performance scores` in the
comments.

This version replaces all of that with the real thing:

| Area | Before | Now |
|---|---|---|
| RSA / ECC / Kyber | Dropdown was cosmetic; always used Fernet | Genuine RSA-OAEP and ECIES hybrid encryption, and genuine Kyber (ML-KEM-768) key encapsulation -- each wrapping a real AES-256-GCM payload |
| Dilithium | Treated as another "encryption" option (it isn't one -- it's a signature scheme) | Moved to a proper **Sign / Verify** tab alongside RSA-PSS and ECDSA, with real sign/verify and tamper detection |
| "Quantum Attack" | Implied a real crack had happened, with a fake "breach time" | Relabeled **Quantum Threat Simulator**, clearly marked as an educational simulation with a disclaimer, explaining the real reason (Shor's algorithm vs. lattice-based hardness) |
| Benchmark chart | Four hardcoded "security scores" with no basis | Real measured keygen/operation timing and real ciphertext/signature sizes, charted live in-app and exportable to JSON |
| UI | Single window, one output box, froze during the attack simulation | Tabbed layout, persistent activity log, threaded background work (no freezing), copy/export buttons, per-algorithm info panels |

## Setup

```bash
pip install -r requirements.txt
python3 main.py
```

`pqcrypto` (which provides Kyber and Dilithium) ships prebuilt wheels for
common platforms, but it's optional -- if it fails to install or you'd
rather skip it, everything else in the app (RSA, ECC, RSA-PSS, ECDSA) works
fine without it; Kyber/Dilithium options will just show an "install
pqcrypto" message instead of crashing.

**Note for Linux users:** if you get `ModuleNotFoundError: No module named
'tkinter'`, install it via your package manager, e.g. `sudo apt install
python3-tk`. macOS's python.org installer and Homebrew's `python-tk` both
include it already.

## Files

- `main.py` -- the app (tabs: Encrypt/Decrypt, Sign/Verify, Quantum Threat
  Simulator, Benchmark & Compare, About)
- `crypto_backends.py` -- the actual cryptographic engines, importable and
  testable on their own
- `graph.py` -- standalone chart generator; reads a `benchmark_results.json`
  exported from the app's Benchmark tab and renders a PNG, useful for
  reports outside the app: `python3 graph.py benchmark_results.json`
- `requirements.txt`

## Honesty notes (worth knowing before you present this anywhere)

- RSA and ECC are used the way they're actually used in the real world:
  hybrid encryption, not raw. Raw RSA can only encrypt a payload smaller
  than its key, and raw ECC can't "encrypt" a message at all -- it only
  produces a shared secret. Pretending otherwise is a common mistake in
  student crypto demos.
- Dilithium is a signature algorithm. There's no such thing as "Dilithium
  encryption" -- if you see a tool that claims to encrypt with it, that
  tool is misusing the algorithm.
- The Quantum Threat Simulator does not run a real attack. No computer
  capable of breaking 2048-bit RSA via Shor's algorithm exists yet. The
  outcome shown is the established theoretical result from the
  cryptography literature, and the app says so on-screen.

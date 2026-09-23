# Architecture and trust boundaries

## Purpose

CipherShield keeps user-interface concerns separate from primitive adapters and
experiment metadata. This makes the cryptographic behavior testable without
launching the desktop interface. It does not make the application a production
security boundary.

## Components

### `main.py`

Owns the Tkinter interface, background workers, in-memory keys, educational
threat explanations, and benchmark orchestration. Keys exist only for the
lifetime of the process and are not persisted.

### `crypto_backends.py`

Provides a small common shape for encryption and signature engines:

- classical primitives come from the `cryptography` package;
- ML-KEM-768 and ML-DSA-65 come from `pqcrypto`;
- bulk encryption uses AES-256-GCM;
- ECDH and ML-KEM shared values are passed through HKDF-SHA-256;
- `EncryptedPayload` serializes binary fields with Base64.

This module composes library primitives; it does not implement lattice
arithmetic, AES, RSA, or elliptic-curve arithmetic itself.

### `experiment.py`

Builds a versioned benchmark record containing the iteration count, UTC
timestamp, platform, Python version, and dependency versions. Keeping this
logic outside the GUI makes the record schema directly testable.

### `graph.py`

Consumes an exported benchmark record and creates a two-panel PNG. It is a
presentation layer and performs no cryptographic operation.

## Data flow

### Hybrid encryption

1. The selected engine creates or receives an asymmetric key pair.
2. RSA wraps a random AES key, while ECDH or ML-KEM establishes key material
   that is derived with HKDF-SHA-256.
3. AES-256-GCM encrypts and authenticates the message with a fresh 96-bit
   nonce.
4. The payload contains an algorithm label, wrapped key or KEM ciphertext,
   nonce, and authenticated ciphertext.
5. Decryption recovers the symmetric key and fails if AES-GCM authentication
   detects modification.

The algorithm label is descriptive metadata; it is not authenticated as
additional data and must not be treated as a protocol negotiation mechanism.

### Signatures

1. The selected engine generates a key pair.
2. The private key signs the exact message bytes.
3. Verification returns a Boolean after checking the same message and public
   key.

The application does not attach identities or certificates to public keys.

## Trust boundaries

The laboratory trusts the local Python process, dependency implementations,
operating-system entropy, and machine running the experiment. It intentionally
does not solve secret storage, process isolation, dependency provenance,
side-channel resistance, remote communication, or user authentication.

## Failure behavior

- AES-GCM authentication failures propagate as `InvalidTag`.
- Classical signature verification returns `False` for an invalid signature.
- ML-DSA verification converts the backend's invalid-signature exception to
  `False`.
- Missing `pqcrypto` support raises a clear `RuntimeError`; the GUI skips those
  algorithms during a benchmark.
- Malformed imported dictionaries raise the corresponding decoding or key
  error. They are not a trusted external file format.

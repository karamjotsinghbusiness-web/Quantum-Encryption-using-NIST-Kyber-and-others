# Experimental methodology

## Scope

CipherShield's built-in benchmark is an exploratory comparison performed
inside a Python desktop application. It helps generate hypotheses and observe
rough engineering trade-offs. It is not a cryptographic security evaluation
and is not rigorous enough, by itself, for a universal performance claim.

## What the current benchmark measures

Each selected algorithm is run for the iteration count entered in the UI
(default: five). Timing uses `time.perf_counter()` and the export records the
arithmetic mean.

| Category | `keygen_ms` | `op_ms` | `size_bytes` |
|---|---|---|---|
| RSA, ECDH, ML-KEM encryption rows | Key-pair generation | Decryption only | Wrapped key or KEM ciphertext plus AES-GCM ciphertext; nonce excluded |
| RSA-PSS, ECDSA, ML-DSA signature rows | Key-pair generation | Signing plus verification | Signature length |

The fixed payload is a short ASCII message. Encryption time is not included in
the encryption-row `op_ms`, whereas both signing and verification are included
in signature-row `op_ms`. For that reason, operation times across categories
are not directly comparable.

## Recorded metadata

Exported JSON uses schema version 1 and records:

- a UTC generation timestamp;
- iterations per algorithm;
- the timing clock and aggregation rule;
- Python, operating-system, and dependency versions;
- algorithm name, category, quantum-safety label, timing, and output size.

Keep the original JSON with any chart or written conclusion. A PNG without its
source record is not adequate experimental evidence.

## Known sources of bias and noise

- interpreter, library, compiler, and CPU differences;
- CPU frequency scaling, thermal throttling, and other processes;
- first-run and cache effects; there is no warm-up phase;
- a small default sample count and arithmetic mean without variance;
- Python and GUI orchestration overhead;
- asymmetric operation definitions between encryption and signature rows;
- a single small message size;
- backend implementation choices rather than algorithm theory alone.

## Recommended protocol for a serious comparison

1. State a narrow hypothesis before collecting results.
2. Fix the hardware, power mode, OS, Python, and dependency versions.
3. Close unrelated workloads and record relevant hardware details.
4. Separate key generation, encapsulation/encryption, decapsulation/decryption,
   signing, and verification into distinct measurements.
5. Use multiple message sizes and at least 30 measured repetitions after a
   documented warm-up phase.
6. Repeat the full experiment in multiple fresh processes.
7. Report median, dispersion, outliers, and raw samples—not only a mean.
8. Avoid comparing signature bytes directly with ciphertext bytes as if they
   provide the same function.
9. Publish the raw machine-readable results and the exact commit hash.
10. Reproduce the result on a second machine before making a general claim.

## Interpretation rules

- A faster measurement means only that the tested implementation was faster
  under the recorded conditions.
- Larger keys or signatures do not automatically imply stronger security.
- “Post-quantum” means designed around problems without a known efficient
  quantum solution; it does not mean mathematically proven unbreakable.
- Passing round-trip tests establishes functional behavior for tested cases,
  not resistance to cryptanalysis or side channels.

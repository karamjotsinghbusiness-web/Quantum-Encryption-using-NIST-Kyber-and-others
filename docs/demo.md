# CipherShield guided demonstration

This walkthrough demonstrates the repository's implemented behavior with
synthetic data. It does not demonstrate production readiness, certification,
or resistance to every attack.

## 1. Install and verify

```bash
git clone https://github.com/karamjotsinghbusiness-web/Quantum-Encryption-using-NIST-Kyber-and-others.git
cd Quantum-Encryption-using-NIST-Kyber-and-others
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

On Windows, activate the environment with `.venv\Scripts\activate`. A passing
suite shows that the tested round trips and tamper checks work in that
environment. It is not a cryptographic security proof.

## 2. Launch the laboratory

```bash
python main.py
```

The desktop interface runs locally. Use a synthetic message such as:

```text
CipherShield demonstration message — no sensitive data.
```

## 3. Compare encryption constructions

1. Generate a key pair for RSA-2048, P-256, or ML-KEM-768.
2. Encrypt the synthetic message.
3. Decrypt the result and confirm that it matches the original.
4. Change one byte of an exported ciphertext and attempt decryption again.

RSA and P-256 are represented as classical constructions. ML-KEM-768 is a
post-quantum key-encapsulation mechanism paired with HKDF-SHA-256 and
AES-256-GCM; the lab does not claim that ML-KEM directly encrypts a file.
AES-GCM should reject a modified authenticated ciphertext.

## 4. Compare signature constructions

1. Generate a key pair for RSA-PSS-2048, ECDSA P-256, or ML-DSA-65.
2. Sign the synthetic message and verify the signature.
3. Modify the message and verify the same signature again.

The changed message should fail verification. ML-DSA-65 is a signature
algorithm, not an encryption algorithm.

## 5. Export a benchmark record

Use the **Benchmark & Compare** tab, then export the result as JSON. The record
contains the timestamp, iteration count, timing clock, aggregation method,
runtime platform, Python version, dependency versions, and measured results.

Render the exported measurements:

```bash
python graph.py benchmark_results.json
```

Read the [methodology](methodology.md) before interpreting the chart. Results
from different machines or environments are not directly comparable without
controlling those differences.

## 6. Useful follow-up questions

- How do key and ciphertext sizes differ between the represented algorithms?
- Which operations are being timed, and are those operations comparable?
- What failures do the tamper tests catch?
- Which security properties remain outside this lab's threat model?

Use [GitHub Discussions](https://github.com/karamjotsinghbusiness-web/Quantum-Encryption-using-NIST-Kyber-and-others/discussions)
for questions about the demonstration and
[GitHub Issues](https://github.com/karamjotsinghbusiness-web/Quantum-Encryption-using-NIST-Kyber-and-others/issues)
for reproducible bugs or documentation errors.

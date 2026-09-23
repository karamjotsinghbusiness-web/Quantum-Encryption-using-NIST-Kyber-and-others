"""
crypto_backends.py
===================
Real cryptographic implementations backing the CipherShield demo app.

Design notes (read this before assuming anything is fake):

- RSA and ECC below are *genuine* hybrid encryption schemes (this is how RSA
  and ECC are actually used in the real world -- raw RSA can only encrypt a
  tiny payload smaller than the key, and raw ECC does not "encrypt" a message
  at all, it only produces a shared secret). Both wrap a random AES-256 key
  and use AES-256-GCM to do the bulk work, exactly like TLS does.

- Kyber (standardized by NIST as ML-KEM-768) is a Key Encapsulation
  Mechanism, not a message-encryption algorithm. It is used here the same
  way: encapsulate a shared secret, then use it as an AES-256-GCM key.

- Dilithium (standardized by NIST as ML-DSA-65) is a *signature* algorithm.
  It cannot encrypt anything -- there is no such thing as "Dilithium
  encryption." It is used here for message signing/verification, alongside
  classical RSA-PSS and ECDSA for comparison. Any tool that claims to
  "encrypt a message with Dilithium" is misusing the algorithm.

- Kyber/Dilithium require the optional `pqcrypto` package
  (`pip install pqcrypto`). If it is not installed, PQCRYPTO_AVAILABLE is
  False and calling those engines raises a clear RuntimeError instead of
  crashing the app.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

try:
    from pqcrypto.kem import ml_kem_768 as _kyber
    from pqcrypto.sign import ml_dsa_65 as _dilithium
    from pqcrypto import InvalidSignatureError as _PQInvalidSignature
    PQCRYPTO_AVAILABLE = True
except ImportError:
    _kyber = None
    _dilithium = None
    _PQInvalidSignature = Exception
    PQCRYPTO_AVAILABLE = False


AES_KEY_LEN = 32  # AES-256


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _hkdf_derive(shared_secret: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_LEN,
        salt=None,
        info=info,
    ).derive(shared_secret)


def _aes_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce, ct


def _aes_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, None)


@dataclass
class EncryptedPayload:
    """Container for a hybrid-encrypted message, algorithm-agnostic."""
    algorithm: str
    wrapped_key: bytes   # RSA ciphertext of AES key / ECC ephemeral pubkey / Kyber KEM ciphertext
    nonce: bytes
    ciphertext: bytes

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "wrapped_key": b64(self.wrapped_key),
            "nonce": b64(self.nonce),
            "ciphertext": b64(self.ciphertext),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EncryptedPayload":
        """Restore a payload exported by :meth:`to_dict`."""
        return cls(
            algorithm=data["algorithm"],
            wrapped_key=unb64(data["wrapped_key"]),
            nonce=unb64(data["nonce"]),
            ciphertext=unb64(data["ciphertext"]),
        )


# ---------------------------------------------------------------------------
# RSA-OAEP + AES-256-GCM hybrid encryption
# ---------------------------------------------------------------------------
class RSAEngine:
    name = "RSA-2048 (hybrid w/ AES-256-GCM)"
    quantum_safe = False

    def __init__(self):
        self.private_key: Optional[rsa.RSAPrivateKey] = None
        self.public_key: Optional[rsa.RSAPublicKey] = None

    def generate_keypair(self) -> float:
        import time
        t0 = time.perf_counter()
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        return time.perf_counter() - t0

    def key_sizes(self) -> dict:
        pub = self.public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        priv = self.private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return {"public_key_bytes": len(pub), "private_key_bytes": len(priv)}

    def encrypt(self, plaintext: bytes) -> EncryptedPayload:
        aes_key = os.urandom(AES_KEY_LEN)
        wrapped = self.public_key.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
        nonce, ct = _aes_encrypt(aes_key, plaintext)
        return EncryptedPayload(self.name, wrapped, nonce, ct)

    def decrypt(self, payload: EncryptedPayload) -> bytes:
        aes_key = self.private_key.decrypt(
            payload.wrapped_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
        return _aes_decrypt(aes_key, payload.nonce, payload.ciphertext)


# ---------------------------------------------------------------------------
# ECC (ECIES-style: ephemeral ECDH P-256 + HKDF + AES-256-GCM)
# ---------------------------------------------------------------------------
class ECCEngine:
    name = "ECC P-256 (ECIES w/ AES-256-GCM)"
    quantum_safe = False
    _INFO = b"ciphershield-ecies-v1"

    def __init__(self):
        self.private_key: Optional[ec.EllipticCurvePrivateKey] = None
        self.public_key: Optional[ec.EllipticCurvePublicKey] = None

    def generate_keypair(self) -> float:
        import time
        t0 = time.perf_counter()
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        return time.perf_counter() - t0

    def key_sizes(self) -> dict:
        pub = self.public_key.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        priv = self.private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return {"public_key_bytes": len(pub), "private_key_bytes": len(priv)}

    def encrypt(self, plaintext: bytes) -> EncryptedPayload:
        ephemeral_private = ec.generate_private_key(ec.SECP256R1())
        shared = ephemeral_private.exchange(ec.ECDH(), self.public_key)
        aes_key = _hkdf_derive(shared, self._INFO)
        ephemeral_pub_bytes = ephemeral_private.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        nonce, ct = _aes_encrypt(aes_key, plaintext)
        return EncryptedPayload(self.name, ephemeral_pub_bytes, nonce, ct)

    def decrypt(self, payload: EncryptedPayload) -> bytes:
        ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), payload.wrapped_key
        )
        shared = self.private_key.exchange(ec.ECDH(), ephemeral_public)
        aes_key = _hkdf_derive(shared, self._INFO)
        return _aes_decrypt(aes_key, payload.nonce, payload.ciphertext)


# ---------------------------------------------------------------------------
# Kyber / ML-KEM-768 (post-quantum KEM) + AES-256-GCM
# ---------------------------------------------------------------------------
class KyberEngine:
    name = "Kyber / ML-KEM-768 (post-quantum, hybrid w/ AES-256-GCM)"
    quantum_safe = True
    _INFO = b"ciphershield-kyber-v1"

    def __init__(self):
        self.public_key: Optional[bytes] = None
        self.secret_key: Optional[bytes] = None

    def _require(self):
        if not PQCRYPTO_AVAILABLE:
            raise RuntimeError(
                "Kyber requires the 'pqcrypto' package. Install it with:\n\n    pip install pqcrypto"
            )

    def generate_keypair(self) -> float:
        import time
        self._require()
        t0 = time.perf_counter()
        self.public_key, self.secret_key = _kyber.keygen()
        return time.perf_counter() - t0

    def key_sizes(self) -> dict:
        return {"public_key_bytes": len(self.public_key), "private_key_bytes": len(self.secret_key)}

    def encrypt(self, plaintext: bytes) -> EncryptedPayload:
        self._require()
        kem_ct, shared_secret = _kyber.encaps(self.public_key)
        aes_key = _hkdf_derive(shared_secret, self._INFO)
        nonce, ct = _aes_encrypt(aes_key, plaintext)
        return EncryptedPayload(self.name, kem_ct, nonce, ct)

    def decrypt(self, payload: EncryptedPayload) -> bytes:
        self._require()
        shared_secret = _kyber.decaps(self.secret_key, payload.wrapped_key)
        aes_key = _hkdf_derive(shared_secret, self._INFO)
        return _aes_decrypt(aes_key, payload.nonce, payload.ciphertext)


# ---------------------------------------------------------------------------
# Signature engines: RSA-PSS, ECDSA, Dilithium / ML-DSA-65 (post-quantum)
# ---------------------------------------------------------------------------
class RSASignEngine:
    name = "RSA-PSS-2048"
    quantum_safe = False

    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keypair(self) -> float:
        import time
        t0 = time.perf_counter()
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        return time.perf_counter() - t0

    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self.public_key.verify(
                signature,
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            return True
        except InvalidSignature:
            return False


class ECDSAEngine:
    name = "ECDSA P-256"
    quantum_safe = False

    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keypair(self) -> float:
        import time
        t0 = time.perf_counter()
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        return time.perf_counter() - t0

    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self.public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False


class DilithiumEngine:
    name = "Dilithium / ML-DSA-65 (post-quantum)"
    quantum_safe = True

    def __init__(self):
        self.public_key: Optional[bytes] = None
        self.secret_key: Optional[bytes] = None

    def _require(self):
        if not PQCRYPTO_AVAILABLE:
            raise RuntimeError(
                "Dilithium requires the 'pqcrypto' package. Install it with:\n\n    pip install pqcrypto"
            )

    def generate_keypair(self) -> float:
        import time
        self._require()
        t0 = time.perf_counter()
        self.public_key, self.secret_key = _dilithium.keygen()
        return time.perf_counter() - t0

    def sign(self, message: bytes) -> bytes:
        self._require()
        return _dilithium.sign(self.secret_key, message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        self._require()
        try:
            _dilithium.verify(self.public_key, message, signature)
            return True
        except _PQInvalidSignature:
            return False

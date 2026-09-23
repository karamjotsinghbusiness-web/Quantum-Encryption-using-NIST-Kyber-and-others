import unittest

from cryptography.exceptions import InvalidTag

from crypto_backends import (
    DilithiumEngine,
    ECCEngine,
    ECDSAEngine,
    EncryptedPayload,
    KyberEngine,
    PQCRYPTO_AVAILABLE,
    RSAEngine,
    RSASignEngine,
)


MESSAGE = b"CipherShield reproducibility test\x00\xff"


class PayloadSerializationTests(unittest.TestCase):
    def test_payload_dictionary_round_trip_preserves_binary_fields(self):
        payload = EncryptedPayload(
            algorithm="test",
            wrapped_key=b"wrapped\x00key",
            nonce=b"0123456789ab",
            ciphertext=b"ciphertext\xff",
        )

        restored = EncryptedPayload.from_dict(payload.to_dict())

        self.assertEqual(restored, payload)


class EncryptionEngineTests(unittest.TestCase):
    def assert_round_trip(self, engine):
        engine.generate_keypair()
        payload = engine.encrypt(MESSAGE)
        self.assertEqual(engine.decrypt(payload), MESSAGE)

    def assert_tamper_rejected(self, engine):
        engine.generate_keypair()
        payload = engine.encrypt(MESSAGE)
        tampered = EncryptedPayload(
            algorithm=payload.algorithm,
            wrapped_key=payload.wrapped_key,
            nonce=payload.nonce,
            ciphertext=payload.ciphertext[:-1] + bytes([payload.ciphertext[-1] ^ 1]),
        )
        with self.assertRaises(InvalidTag):
            engine.decrypt(tampered)

    def test_rsa_hybrid_encryption_round_trip(self):
        self.assert_round_trip(RSAEngine())

    def test_rsa_hybrid_encryption_rejects_tampering(self):
        self.assert_tamper_rejected(RSAEngine())

    def test_ecc_hybrid_encryption_round_trip(self):
        self.assert_round_trip(ECCEngine())

    def test_ecc_hybrid_encryption_rejects_tampering(self):
        self.assert_tamper_rejected(ECCEngine())

    @unittest.skipUnless(PQCRYPTO_AVAILABLE, "pqcrypto is not installed")
    def test_ml_kem_hybrid_encryption_round_trip(self):
        self.assert_round_trip(KyberEngine())

    @unittest.skipUnless(PQCRYPTO_AVAILABLE, "pqcrypto is not installed")
    def test_ml_kem_hybrid_encryption_rejects_tampering(self):
        self.assert_tamper_rejected(KyberEngine())


class SignatureEngineTests(unittest.TestCase):
    def assert_signature_behavior(self, engine):
        engine.generate_keypair()
        signature = engine.sign(MESSAGE)
        self.assertTrue(engine.verify(MESSAGE, signature))
        self.assertFalse(engine.verify(MESSAGE + b"tampered", signature))

    def test_rsa_pss_signatures_detect_message_tampering(self):
        self.assert_signature_behavior(RSASignEngine())

    def test_ecdsa_signatures_detect_message_tampering(self):
        self.assert_signature_behavior(ECDSAEngine())

    @unittest.skipUnless(PQCRYPTO_AVAILABLE, "pqcrypto is not installed")
    def test_ml_dsa_signatures_detect_message_tampering(self):
        self.assert_signature_behavior(DilithiumEngine())


if __name__ == "__main__":
    unittest.main()

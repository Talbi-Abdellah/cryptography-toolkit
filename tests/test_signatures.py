"""Unit tests for digital signature modules."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest
from signatures.elgamal_signature import ElGamalSigner


class TestElGamalSignature(unittest.TestCase):
    def setUp(self):
        self.priv = ElGamalSigner.generate_keypair(256)
        self.pub = self.priv.public_key

    def test_sign_verify_roundtrip(self):
        msg = b"Test message for ElGamal signing"
        r, s = ElGamalSigner.sign(msg, self.priv)
        self.assertTrue(ElGamalSigner.verify(msg, r, s, self.pub))

    def test_tampered_message_fails(self):
        msg = b"Original message"
        r, s = ElGamalSigner.sign(msg, self.priv)
        self.assertFalse(ElGamalSigner.verify(b"Tampered message", r, s, self.pub))

    def test_wrong_signature_fails(self):
        msg = b"Test message"
        ElGamalSigner.sign(msg, self.priv)
        # Use wrong r/s values
        self.assertFalse(ElGamalSigner.verify(msg, 1, 1, self.pub))

    def test_nonce_reuse_attack(self):
        result = ElGamalSigner.nonce_reuse_attack_demo(256)
        self.assertTrue(result["attack_succeeded"])

    def test_different_messages_different_sigs(self):
        msg1, msg2 = b"Message 1", b"Message 2"
        r1, s1 = ElGamalSigner.sign(msg1, self.priv)
        r2, s2 = ElGamalSigner.sign(msg2, self.priv)
        # With high probability, signatures will differ
        self.assertFalse((r1 == r2 and s1 == s2))


class TestRSASignature(unittest.TestCase):
    def setUp(self):
        try:
            from signatures.rsa_signature import RSASigner
            self.RSASigner = RSASigner
        except ImportError:
            self.skipTest("pycryptodome not installed")

    def test_sign_verify_roundtrip(self):
        signer = self.RSASigner(1024)
        msg = b"Sign this message"
        sig = signer.sign(msg)
        self.assertTrue(signer.verify(msg, sig))

    def test_tampered_fails(self):
        signer = self.RSASigner(1024)
        msg = b"Original"
        sig = signer.sign(msg)
        self.assertFalse(signer.verify(b"TAMPERED", sig))

    def test_wrong_key_fails(self):
        signer1 = self.RSASigner(1024)
        signer2 = self.RSASigner(1024)
        msg = b"Test"
        sig = signer1.sign(msg)
        # Verify against signer2's key — should fail
        self.assertFalse(signer2.verify(msg, sig))

    def test_pem_export(self):
        signer = self.RSASigner(1024)
        self.assertIn("BEGIN", signer.public_pem)
        self.assertIn("BEGIN", signer.private_pem)


class TestDSA(unittest.TestCase):
    def setUp(self):
        try:
            from signatures.dsa_ecdsa import DSASigner
            self.DSASigner = DSASigner
        except ImportError:
            self.skipTest("cryptography library not installed")

    def test_sign_verify(self):
        signer = self.DSASigner(2048)
        msg = b"DSA test message"
        sig = signer.sign(msg)
        self.assertTrue(signer.verify(msg, sig))

    def test_tampered_fails(self):
        signer = self.DSASigner(2048)
        msg = b"Original"
        sig = signer.sign(msg)
        self.assertFalse(signer.verify(b"Tampered", sig))


class TestECDSA(unittest.TestCase):
    def setUp(self):
        try:
            from signatures.dsa_ecdsa import ECDSASigner
            self.ECDSASigner = ECDSASigner
        except ImportError:
            self.skipTest("cryptography library not installed")

    def test_p256_roundtrip(self):
        signer = self.ECDSASigner("p256")
        msg = b"ECDSA test message"
        sig = signer.sign(msg)
        self.assertTrue(signer.verify(msg, sig))

    def test_secp256k1_roundtrip(self):
        signer = self.ECDSASigner("secp256k1")
        msg = b"Bitcoin curve test"
        sig = signer.sign(msg)
        self.assertTrue(signer.verify(msg, sig))

    def test_tampered_fails(self):
        signer = self.ECDSASigner("p256")
        sig = signer.sign(b"original")
        self.assertFalse(signer.verify(b"tampered", sig))

    def test_unknown_curve_raises(self):
        with self.assertRaises(ValueError):
            self.ECDSASigner("invalid_curve_xyz")

    def test_get_raw_signature(self):
        signer = self.ECDSASigner("p256")
        r, s = signer.get_raw_signature(b"test")
        self.assertIsInstance(r, int)
        self.assertIsInstance(s, int)
        self.assertGreater(r, 0)
        self.assertGreater(s, 0)


class TestAuthenticityVerifier(unittest.TestCase):
    def setUp(self):
        try:
            from signatures.verify import AuthenticityVerifier, DocumentSigner
            self.verifier = AuthenticityVerifier()
            self.signer = DocumentSigner()
        except ImportError:
            self.skipTest("Required libraries not installed")

    def test_rsa_document_verifies(self):
        doc, _ = self.signer.sign_rsa(b"important document", "Alice", key_size=1024)
        self.assertTrue(self.verifier.verify(doc))

    def test_ecdsa_document_verifies(self):
        doc, _ = self.signer.sign_ecdsa(b"ECDSA document", "Bob")
        self.assertTrue(self.verifier.verify(doc))

    def test_tampered_document_fails(self):
        doc, _ = self.signer.sign_rsa(b"original content", "Alice", key_size=1024)
        # Tamper with content
        import dataclasses
        tampered = dataclasses.replace(doc, content=b"tampered content")
        self.assertFalse(self.verifier.verify(tampered))


if __name__ == "__main__":
    unittest.main()

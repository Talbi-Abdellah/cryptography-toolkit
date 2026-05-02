"""Unit tests for symmetric cryptography modules."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest
from symmetric.rc4 import RC4Cipher


class TestRC4(unittest.TestCase):
    def test_roundtrip(self):
        key = b"Secret"
        msg = b"Hello, World!"
        self.assertEqual(RC4Cipher.decrypt(key, RC4Cipher.encrypt(key, msg)), msg)

    def test_known_vector(self):
        # RC4("Key", "Plaintext") from Wikipedia test vector
        key = b"Key"
        pt = b"Plaintext"
        ct = RC4Cipher.encrypt(key, pt)
        self.assertEqual(ct, bytes([0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]))

    def test_empty_message(self):
        self.assertEqual(RC4Cipher.encrypt(b"key", b""), b"")

    def test_different_keys_give_different_output(self):
        msg = b"test message"
        ct1 = RC4Cipher.encrypt(b"key1", msg)
        ct2 = RC4Cipher.encrypt(b"key2", msg)
        self.assertNotEqual(ct1, ct2)

    def test_ksa_produces_permutation(self):
        S = RC4Cipher.ksa(b"testkey")
        self.assertEqual(sorted(S), list(range(256)))

    def test_bias_demo_runs(self):
        result = RC4Cipher.bias_demo(num_trials=1000)
        self.assertIn("byte0_value0_probability", result)
        self.assertGreater(result["trials"], 0)


class TestAES(unittest.TestCase):
    def setUp(self):
        try:
            from symmetric.aes_cipher import AESCipher
            self.AESCipher = AESCipher
        except ImportError:
            self.skipTest("pycryptodome not installed")

    def test_cbc_roundtrip_128(self):
        key = b"0123456789abcdef"
        cipher = self.AESCipher(key)
        msg = b"Test message for AES-CBC"
        iv, ct = cipher.encrypt_cbc(msg)
        self.assertEqual(cipher.decrypt_cbc(ct, iv), msg)

    def test_cbc_roundtrip_256(self):
        key = b"01234567890abcdef01234567890abcd"
        cipher = self.AESCipher(key[:32])
        msg = b"256-bit AES key test"
        iv, ct = cipher.encrypt_cbc(msg)
        self.assertEqual(cipher.decrypt_cbc(ct, iv), msg)

    def test_ctr_roundtrip(self):
        key = b"0123456789abcdef"
        cipher = self.AESCipher(key)
        msg = b"CTR mode test message!"
        nonce, ct = cipher.encrypt_ctr(msg)
        self.assertEqual(cipher.decrypt_ctr(ct, nonce), msg)

    def test_ecb_roundtrip(self):
        key = b"0123456789abcdef"
        cipher = self.AESCipher(key)
        msg = b"ECB test message"
        ct = cipher.encrypt_ecb(msg)
        self.assertEqual(cipher.decrypt_ecb(ct), msg)

    def test_nonce_reuse_attack(self):
        result = self.AESCipher.nonce_reuse_attack_demo()
        self.assertTrue(result["attack_succeeded"])

    def test_invalid_key_size(self):
        with self.assertRaises(ValueError):
            self.AESCipher(b"shortkey")

    def test_cbc_different_ivs_give_different_ct(self):
        import os
        key = b"0123456789abcdef"
        cipher = self.AESCipher(key)
        msg = b"same message"
        _, ct1 = cipher.encrypt_cbc(msg, os.urandom(16))
        _, ct2 = cipher.encrypt_cbc(msg, os.urandom(16))
        self.assertNotEqual(ct1, ct2)


class TestDES(unittest.TestCase):
    def setUp(self):
        try:
            from symmetric.des_cipher import DESCipher, TripleDESCipher
            self.DESCipher = DESCipher
            self.TripleDESCipher = TripleDESCipher
        except ImportError:
            self.skipTest("pycryptodome not installed")

    def test_des_ecb_roundtrip(self):
        key = b"8bytekey"
        des = self.DESCipher(key)
        msg = b"Test DES message"
        self.assertEqual(des.decrypt_ecb(des.encrypt_ecb(msg)), msg)

    def test_des_cbc_roundtrip(self):
        key = b"8bytekey"
        des = self.DESCipher(key)
        msg = b"CBC DES message"
        iv, ct = des.encrypt_cbc(msg)
        self.assertEqual(des.decrypt_cbc(ct, iv), msg)

    def test_3des_cbc_roundtrip(self):
        key = b"24bytetripleDESkey!!!!!"
        des3 = self.TripleDESCipher(key)
        msg = b"Triple DES test message"
        iv, ct = des3.encrypt_cbc(msg)
        self.assertEqual(des3.decrypt_cbc(ct, iv), msg)

    def test_wrong_key_size_raises(self):
        with self.assertRaises(ValueError):
            self.DESCipher(b"tooshort")


if __name__ == "__main__":
    unittest.main()

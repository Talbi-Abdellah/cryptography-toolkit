"""Unit tests for classical cryptography modules."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest
from classical.caesar import CaesarCipher
from classical.vigenere import VigenereCipher
from classical.hill import HillCipher
from classical.otp import OneTimePad


class TestCaesar(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        for shift in [0, 1, 13, 25]:
            ct = CaesarCipher.encrypt("Hello, World!", shift)
            pt = CaesarCipher.decrypt(ct, shift)
            self.assertEqual(pt, "Hello, World!")

    def test_shift_wraps(self):
        self.assertEqual(CaesarCipher.encrypt("Z", 1), "A")
        self.assertEqual(CaesarCipher.encrypt("z", 1), "a")

    def test_non_alpha_unchanged(self):
        ct = CaesarCipher.encrypt("Hello, World! 123", 5)
        self.assertIn(",", ct)
        self.assertIn(" ", ct)
        self.assertIn("!", ct)

    def test_rot13_is_own_inverse(self):
        text = "ThequickbrownFox"
        self.assertEqual(CaesarCipher.decrypt(CaesarCipher.encrypt(text, 13), 13), text)

    def test_brute_force_finds_shift(self):
        original_shift = 7
        ct = CaesarCipher.encrypt("The quick brown fox jumps over the lazy dog", original_shift)
        results = CaesarCipher.brute_force(ct)
        guessed = results[0][0]
        self.assertEqual(guessed, original_shift)

    def test_index_of_coincidence_english(self):
        # Long English text should have IC ≈ 0.065
        text = "The quick brown fox jumps over the lazy dog" * 20
        ic = CaesarCipher.index_of_coincidence(text)
        self.assertAlmostEqual(ic, 0.065, delta=0.015)

    def test_ic_empty(self):
        self.assertEqual(CaesarCipher.index_of_coincidence(""), 0.0)


class TestVigenere(unittest.TestCase):
    PLAINTEXT = "ATTACKATDAWN"
    KEY = "LEMON"
    CIPHERTEXT = "LXFOPVEFRNHR"

    def test_known_vector(self):
        ct = VigenereCipher.encrypt(self.PLAINTEXT, self.KEY)
        self.assertEqual(ct, self.CIPHERTEXT)

    def test_decrypt_known_vector(self):
        pt = VigenereCipher.decrypt(self.CIPHERTEXT, self.KEY)
        self.assertEqual(pt, self.PLAINTEXT)

    def test_roundtrip(self):
        for text in ["HELLO", "CRYPTOGRAPHY", "ABCDEFGHIJ"]:
            for key in ["KEY", "SECRET", "VIGENERE"]:
                ct = VigenereCipher.encrypt(text, key)
                pt = VigenereCipher.decrypt(ct, key)
                self.assertEqual(pt, text)

    def test_ic_attack_finds_key_length(self):
        # Generate a long ciphertext with a known key
        import string, random
        key = "SECRET"
        plain = "".join(random.choices(string.ascii_uppercase, k=600))
        ct = VigenereCipher.encrypt(plain, key)
        guessed_len = VigenereCipher.ic_attack(ct, max_key_len=12)
        # Allow small multiples of the actual key length
        self.assertIn(guessed_len, [len(key), len(key) * 2, len(key) * 3])

    def test_crack_short_key(self):
        key = "KEY"
        plain = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG " * 10
        ct = VigenereCipher.encrypt(plain, key)
        recovered_key, recovered_plain = VigenereCipher.crack(ct, max_key_len=10)
        self.assertEqual(recovered_key, key)


class TestHill(unittest.TestCase):
    KEY_2x2 = [[3, 3], [2, 5]]
    KEY_3x3 = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]

    def test_2x2_roundtrip(self):
        h = HillCipher(self.KEY_2x2)
        pt = "HELPME"
        self.assertEqual(h.decrypt(h.encrypt(pt)), pt)

    def test_3x3_roundtrip(self):
        h = HillCipher(self.KEY_3x3)
        pt = "ACTMAN"
        self.assertEqual(h.decrypt(h.encrypt(pt)), pt)

    def test_invalid_key_singular(self):
        # [[1,0],[0,0]] is singular
        with self.assertRaises(ValueError):
            HillCipher([[2, 4], [3, 6]])

    def test_known_plaintext_attack(self):
        key = self.KEY_2x2
        h = HillCipher(key)
        # Use two known plaintext blocks
        p_blocks = ["HE", "LP"]
        c_blocks = [h.encrypt("HE"), h.encrypt("LP")]
        # Attack recovers the original key
        recovered = HillCipher.known_plaintext_attack(p_blocks, c_blocks, n=2)
        self.assertIsNotNone(recovered)
        flat_orig = [v % 26 for row in key for v in row]
        flat_rec = [v for row in recovered for v in row]
        self.assertEqual(flat_orig, flat_rec)


class TestOTP(unittest.TestCase):
    def test_roundtrip(self):
        msg = b"Top secret message"
        key = OneTimePad.generate_key(len(msg))
        self.assertEqual(OneTimePad.decrypt(OneTimePad.encrypt(msg, key), key), msg)

    def test_key_too_short_raises(self):
        with self.assertRaises(ValueError):
            OneTimePad.encrypt(b"long message", b"key")

    def test_key_reuse_reveals_xor(self):
        m1 = b"Hello World!"
        m2 = b"Secret Text!"
        c1, c2, xor_ct, xor_pt = OneTimePad.key_reuse_attack_demo(m1, m2)
        self.assertEqual(xor_ct, xor_pt)

    def test_crib_drag_finds_matches(self):
        xor_data = bytes(a ^ b for a, b in zip(b"Hello World", b"Lorem ipsum"))
        results = OneTimePad.crib_drag(xor_data, "Lorem")
        # There should be at least one printable match at offset 0
        self.assertTrue(any(off == 0 for off, _ in results))


if __name__ == "__main__":
    unittest.main()

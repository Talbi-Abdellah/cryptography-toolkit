"""Unit tests for asymmetric cryptography modules."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest
from utils.math_utils import (
    extended_gcd, mod_inverse, is_prime_miller_rabin,
    generate_prime, mod_matrix_inverse, matrix_multiply_mod,
)


class TestMathUtils(unittest.TestCase):
    def test_extended_gcd(self):
        for a, b in [(3, 11), (17, 31), (100, 37)]:
            g, x, y = extended_gcd(a, b)
            self.assertEqual(g, a * x + b * y)

    def test_mod_inverse(self):
        self.assertEqual(mod_inverse(3, 11), 4)
        self.assertEqual(mod_inverse(7, 26), 15)
        self.assertIsNone(mod_inverse(2, 4))  # gcd(2,4)=2≠1

    def test_miller_rabin_primes(self):
        for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 97, 997, 7919]:
            self.assertTrue(is_prime_miller_rabin(p), f"{p} should be prime")

    def test_miller_rabin_composites(self):
        for n in [1, 4, 6, 8, 9, 10, 100, 1000]:
            self.assertFalse(is_prime_miller_rabin(n), f"{n} should be composite")

    def test_generate_prime_bit_length(self):
        for bits in [64, 128, 256]:
            p = generate_prime(bits)
            self.assertTrue(is_prime_miller_rabin(p))
            self.assertGreaterEqual(p.bit_length(), bits - 1)
            self.assertLessEqual(p.bit_length(), bits)

    def test_matrix_inverse_2x2(self):
        M = [[3, 3], [2, 5]]
        inv = mod_matrix_inverse(M, 26)
        self.assertIsNotNone(inv)
        # M * inv = I mod 26
        prod = matrix_multiply_mod(M, inv, 26)
        self.assertEqual(prod[0][0], 1)
        self.assertEqual(prod[1][1], 1)
        self.assertEqual(prod[0][1], 0)
        self.assertEqual(prod[1][0], 0)

    def test_matrix_inverse_singular(self):
        # [[2,4],[3,6]] det=0
        M = [[2, 4], [3, 6]]
        self.assertIsNone(mod_matrix_inverse(M, 26))


class TestDiffieHellman(unittest.TestCase):
    def test_key_exchange(self):
        from asymmetric.diffie_hellman import DiffieHellman
        r = DiffieHellman.key_exchange_demo(bits=512)
        self.assertTrue(r["secrets_match"])

    def test_mitm_attack(self):
        from asymmetric.diffie_hellman import DiffieHellman
        r = DiffieHellman.mitm_attack_demo(bits=512)
        self.assertFalse(r["alice_knows_real_bob_secret"])

    def test_dh_party_public_key_matches(self):
        from asymmetric.diffie_hellman import DHParty, DiffieHellman
        p, g = DiffieHellman.generate_parameters(512)
        party = DHParty(p, g)
        expected = pow(g, party.private_key, p)
        self.assertEqual(party.public_key, expected)


class TestRSA(unittest.TestCase):
    def setUp(self):
        try:
            from asymmetric.rsa_cipher import RSACipher
            self.RSACipher = RSACipher
        except ImportError:
            self.skipTest("pycryptodome not installed")

    def test_keygen(self):
        priv = self.RSACipher.generate_keypair(512)
        self.assertGreater(priv.n.bit_length(), 256)
        self.assertEqual(priv.e, 65537)

    def test_textbook_roundtrip(self):
        priv = self.RSACipher.generate_keypair(512)
        msg = 12345
        ct = self.RSACipher.encrypt_textbook(msg, priv.public_key)
        pt = self.RSACipher.decrypt_textbook(ct, priv)
        self.assertEqual(pt, msg)

    def test_hybrid_roundtrip(self):
        priv = self.RSACipher.generate_keypair(1024)
        msg = b"Hybrid encryption test message!"
        enc_key, iv, ct = self.RSACipher.hybrid_encrypt(msg, priv.public_key)
        pt = self.RSACipher.hybrid_decrypt(enc_key, iv, ct, priv)
        self.assertEqual(pt, msg)

    def test_message_too_large_raises(self):
        priv = self.RSACipher.generate_keypair(512)
        with self.assertRaises(ValueError):
            self.RSACipher.encrypt_textbook(priv.n + 1, priv.public_key)


class TestElGamal(unittest.TestCase):
    def test_roundtrip(self):
        from asymmetric.elgamal import ElGamal
        priv = ElGamal.generate_keypair(256)
        for msg in [1, 42, 999, 12345]:
            c1, c2 = ElGamal.encrypt(msg, priv.public_key)
            self.assertEqual(ElGamal.decrypt(c1, c2, priv), msg)

    def test_malleability(self):
        from asymmetric.elgamal import ElGamal
        r = ElGamal.malleability_demo(256)
        self.assertTrue(r["attack_succeeded"])


class TestECC(unittest.TestCase):
    def test_demo_curve_point_addition(self):
        from asymmetric.ecc import DEMO_CURVE, ECPoint
        G = DEMO_CURVE.G
        # 2G via doubling
        twoG = DEMO_CURVE.add(G, G)
        # 2G via multiplication
        twoG_mul = DEMO_CURVE.multiply(G, 2)
        self.assertEqual(twoG, twoG_mul)

    def test_point_at_infinity(self):
        from asymmetric.ecc import DEMO_CURVE, ECPoint
        G = DEMO_CURVE.G
        neg_G = DEMO_CURVE.negate(G)
        result = DEMO_CURVE.add(G, neg_G)
        self.assertTrue(result.is_infinity)

    def test_ecdh_key_exchange(self):
        from asymmetric.ecc import ECDH, SECP256K1
        r = ECDH(SECP256K1).key_exchange_demo()
        self.assertTrue(r["secrets_match"])

    def test_ecies_roundtrip(self):
        from asymmetric.ecc import ECIES, ECDH, SECP256K1
        ecies = ECIES(SECP256K1)
        ecdh = ECDH(SECP256K1)
        priv, pub = ecdh.generate_keypair()
        msg = b"ECIES test message"
        r_pub, iv, ct = ecies.encrypt(msg, pub)
        pt = ecies.decrypt(r_pub, iv, ct, priv)
        self.assertEqual(pt, msg)

    def test_point_on_curve(self):
        from asymmetric.ecc import SECP256K1
        self.assertTrue(SECP256K1.is_on_curve(SECP256K1.G))


if __name__ == "__main__":
    unittest.main()

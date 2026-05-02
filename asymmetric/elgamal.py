"""ElGamal public-key encryption with malleability demonstration."""
import hashlib
import secrets
from dataclasses import dataclass
from typing import Tuple

from utils.math_utils import generate_prime, primitive_root, mod_inverse
from utils.logger import get_logger

log = get_logger("elgamal")


@dataclass
class ElGamalPublicKey:
    p: int   # prime modulus
    g: int   # generator
    y: int   # y = g^x mod p


@dataclass
class ElGamalPrivateKey:
    p: int
    g: int
    x: int   # secret exponent

    @property
    def public_key(self) -> ElGamalPublicKey:
        return ElGamalPublicKey(p=self.p, g=self.g, y=pow(self.g, self.x, self.p))


class ElGamal:
    """
    ElGamal encryption over Z_p*.

    Security note: uses textbook (no padding), appropriate for educational
    demonstration only. Real implementations require ECIES or hybrid schemes.
    """

    @staticmethod
    def generate_keypair(bits: int = 512) -> ElGamalPrivateKey:
        """Generate an ElGamal keypair of `bits` prime size."""
        p = generate_prime(bits)
        g = primitive_root(p)
        x = secrets.randbelow(p - 2) + 2  # 2 ≤ x ≤ p-2
        log.info("ElGamal keygen: p_bits=%d", p.bit_length())
        return ElGamalPrivateKey(p=p, g=g, x=x)

    @staticmethod
    def encrypt(message: int, pub: ElGamalPublicKey) -> Tuple[int, int]:
        """
        Encrypt integer `message` (must be < p).
        Returns (c1, c2) where:
            c1 = g^k mod p
            c2 = m * y^k mod p
        k is a fresh ephemeral random value.
        """
        if message >= pub.p:
            raise ValueError("Message must be less than p")
        k = secrets.randbelow(pub.p - 2) + 2
        c1 = pow(pub.g, k, pub.p)
        c2 = (message * pow(pub.y, k, pub.p)) % pub.p
        log.debug("ElGamal encrypt: msg_bits=%d", message.bit_length())
        return c1, c2

    @staticmethod
    def decrypt(c1: int, c2: int, priv: ElGamalPrivateKey) -> int:
        """
        Decrypt (c1, c2):
            s = c1^x mod p
            m = c2 * s^{-1} mod p
        """
        s = pow(c1, priv.x, priv.p)
        s_inv = mod_inverse(s, priv.p)
        if s_inv is None:
            raise ValueError("Decryption failed: s has no inverse mod p")
        m = (c2 * s_inv) % priv.p
        log.debug("ElGamal decrypt: m_bits=%d", m.bit_length())
        return m

    @staticmethod
    def encrypt_bytes(message: bytes, pub: ElGamalPublicKey) -> Tuple[int, int]:
        """Convenience wrapper: encode bytes as integer then encrypt."""
        m_int = int.from_bytes(message, "big")
        if m_int >= pub.p:
            raise ValueError("Message too long for key size")
        return ElGamal.encrypt(m_int, pub)

    @staticmethod
    def decrypt_bytes(c1: int, c2: int, priv: ElGamalPrivateKey, length: int) -> bytes:
        """Convenience wrapper: decrypt then decode integer to bytes."""
        m_int = ElGamal.decrypt(c1, c2, priv)
        return m_int.to_bytes(length, "big")

    # ── Malleability Demonstration ────────────────────────────────────────────

    @staticmethod
    def malleability_demo(bits: int = 256) -> dict:
        """
        Demonstrate ElGamal's multiplicative malleability.

        Given a ciphertext (c1, c2) encrypting m, an attacker can produce
        a valid ciphertext (c1, c2 * k mod p) that decrypts to m*k without
        knowing the private key or m.

        This makes textbook ElGamal malleable and unsuitable for direct use
        without integrity protection (MAC or authenticated encryption).
        """
        priv = ElGamal.generate_keypair(bits)
        pub = priv.public_key

        message = 42
        c1, c2 = ElGamal.encrypt(message, pub)

        # Attacker multiplies c2 by a known factor `factor`
        factor = 7
        c2_modified = (c2 * factor) % pub.p

        # Decryption now yields message * factor
        m_modified = ElGamal.decrypt(c1, c2_modified, priv)

        log.warning("ElGamal malleability demo: original=%d recovered=%d factor=%d", message, m_modified, factor)
        return {
            "original_message": message,
            "factor_applied_by_attacker": factor,
            "expected_modified_message": (message * factor) % pub.p,
            "actual_decrypted_message": m_modified,
            "attack_succeeded": m_modified == (message * factor) % pub.p,
            "explanation": (
                "ElGamal is multiplicatively malleable: "
                "modifying c2 → c2*k causes decryption to yield m*k. "
                "Mitigation: use authenticated encryption (e.g. ECIES)."
            ),
        }

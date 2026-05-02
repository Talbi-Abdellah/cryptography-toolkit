"""ElGamal digital signature scheme."""
import hashlib
import secrets
from dataclasses import dataclass
from typing import Tuple

from utils.math_utils import generate_prime, primitive_root, mod_inverse
from utils.logger import get_logger

log = get_logger("elgamal_sig")


@dataclass
class ElGamalSigPublicKey:
    p: int
    g: int
    y: int  # y = g^x mod p


@dataclass
class ElGamalSigPrivateKey:
    p: int
    g: int
    x: int

    @property
    def public_key(self) -> ElGamalSigPublicKey:
        return ElGamalSigPublicKey(p=self.p, g=self.g, y=pow(self.g, self.x, self.p))


class ElGamalSigner:
    """
    ElGamal signature scheme.

    Signature (r, s) for message m:
        k  = random in (0, p-1), gcd(k, p-1) = 1
        r  = g^k mod p
        s  = k^{-1} * (H(m) - x*r) mod (p-1)

    Verification:
        g^{H(m)} ≡ y^r * r^s (mod p)
    """

    @staticmethod
    def generate_keypair(bits: int = 512) -> ElGamalSigPrivateKey:
        p = generate_prime(bits)
        g = primitive_root(p)
        x = secrets.randbelow(p - 2) + 2
        log.info("ElGamal signature keygen: p_bits=%d", p.bit_length())
        return ElGamalSigPrivateKey(p=p, g=g, x=x)

    @staticmethod
    def _hash_message(message: bytes, p: int) -> int:
        """SHA-256 digest of message reduced modulo p-1."""
        h = hashlib.sha256(message).digest()
        return int.from_bytes(h, "big") % (p - 1)

    @staticmethod
    def sign(message: bytes, priv: ElGamalSigPrivateKey) -> Tuple[int, int]:
        """Sign `message`. Returns (r, s)."""
        p = priv.p
        phi = p - 1
        h = ElGamalSigner._hash_message(message, p)

        # Choose ephemeral k coprime to p-1
        while True:
            k = secrets.randbelow(phi - 2) + 2
            from math import gcd
            if gcd(k, phi) == 1:
                break

        r = pow(priv.g, k, p)
        k_inv = mod_inverse(k, phi)
        s = (k_inv * (h - priv.x * r)) % phi

        log.debug("ElGamal sign: r_bits=%d s_bits=%d", r.bit_length(), s.bit_length())
        return r, s

    @staticmethod
    def verify(message: bytes, r: int, s: int, pub: ElGamalSigPublicKey) -> bool:
        """
        Verify signature (r, s) on `message`.
        Returns True if valid.
        """
        p = pub.p
        if not (0 < r < p):
            return False

        h = ElGamalSigner._hash_message(message, p)

        # g^H(m) ≡ y^r * r^s (mod p)
        lhs = pow(pub.g, h, p)
        rhs = (pow(pub.y, r, p) * pow(r, s, p)) % p

        valid = lhs == rhs
        log.debug("ElGamal verify: %s", "OK" if valid else "FAIL")
        return valid

    @staticmethod
    def nonce_reuse_attack_demo(bits: int = 256) -> dict:
        """
        Demonstrate that reusing k in ElGamal signatures leaks the private key.

        If k is reused for two signatures on different messages m1, m2:
            s1 = k^{-1} * (H(m1) - x*r) mod (p-1)
            s2 = k^{-1} * (H(m2) - x*r) mod (p-1)
            s1 - s2 = k^{-1} * (H(m1) - H(m2)) mod (p-1)
            k = (H(m1) - H(m2)) * (s1 - s2)^{-1} mod (p-1)
            x = r^{-1} * (H(m1) - k*s1) mod (p-1)
        """
        priv = ElGamalSigner.generate_keypair(bits)
        p = priv.p
        phi = p - 1
        from math import gcd

        msg1 = b"First message"
        msg2 = b"Second message"

        # Deliberately reuse k
        while True:
            k = secrets.randbelow(phi - 2) + 2
            if gcd(k, phi) == 1:
                break

        h1 = ElGamalSigner._hash_message(msg1, p)
        h2 = ElGamalSigner._hash_message(msg2, p)
        r = pow(priv.g, k, p)
        k_inv = mod_inverse(k, phi)
        s1 = (k_inv * (h1 - priv.x * r)) % phi
        s2 = (k_inv * (h2 - priv.x * r)) % phi

        # Recover k
        ds = (s1 - s2) % phi
        ds_inv = mod_inverse(ds, phi)
        recovered_k = ((h1 - h2) * ds_inv) % phi if ds_inv else None

        recovered_x = None
        if recovered_k is not None:
            r_inv = mod_inverse(r, phi)
            if r_inv is not None:
                recovered_x = (r_inv * (h1 - recovered_k * s1)) % phi

        log.warning("ElGamal nonce-reuse attack: recovered_x=%s", recovered_x == priv.x)
        return {
            "original_private_key_x": priv.x,
            "recovered_k": recovered_k,
            "recovered_private_key_x": recovered_x,
            "attack_succeeded": recovered_x == priv.x,
            "explanation": (
                "Reusing the ephemeral nonce k in ElGamal signatures allows "
                "an attacker to recover the long-term private key x. "
                "Always use a fresh random k per signature."
            ),
        }

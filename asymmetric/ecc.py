"""
Elliptic Curve Cryptography — point arithmetic, ECDH, ECIES (simplified).

Uses secp256k1 parameters by default (the Bitcoin curve).
"""
from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass, field
from typing import Optional, Tuple

from utils.logger import get_logger

log = get_logger("ecc")

# ── secp256k1 curve parameters ────────────────────────────────────────────────
_P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_A  = 0
_B  = 7
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _mod_inv(a: int, m: int) -> int:
    """Modular inverse via Fermat's little theorem (m must be prime)."""
    return pow(a, m - 2, m)


@dataclass(frozen=True)
class ECPoint:
    """A point on an elliptic curve, or the point at infinity (x=None, y=None)."""
    x: Optional[int]
    y: Optional[int]

    @property
    def is_infinity(self) -> bool:
        return self.x is None and self.y is None

    @classmethod
    def infinity(cls) -> ECPoint:
        return cls(None, None)

    def __repr__(self) -> str:
        if self.is_infinity:
            return "ECPoint(∞)"
        return f"ECPoint(x=0x{self.x:x}, y=0x{self.y:x})"


class EllipticCurve:
    """Weierstrass curve y² = x³ + ax + b over F_p."""

    def __init__(
        self, p: int, a: int, b: int,
        Gx: int, Gy: int, n: int,
        name: str = "custom",
    ) -> None:
        self.p = p
        self.a = a
        self.b = b
        self.G = ECPoint(Gx, Gy)
        self.n = n  # order of G
        self.name = name

    def is_on_curve(self, P: ECPoint) -> bool:
        if P.is_infinity:
            return True
        return (P.y ** 2 - P.x ** 3 - self.a * P.x - self.b) % self.p == 0

    def add(self, P: ECPoint, Q: ECPoint) -> ECPoint:
        """Elliptic curve point addition."""
        if P.is_infinity:
            return Q
        if Q.is_infinity:
            return P

        if P.x == Q.x:
            if (P.y + Q.y) % self.p == 0:
                return ECPoint.infinity()  # P + (-P) = ∞
            # Point doubling
            lam = (3 * P.x ** 2 + self.a) * _mod_inv(2 * P.y, self.p) % self.p
        else:
            lam = (Q.y - P.y) * _mod_inv(Q.x - P.x, self.p) % self.p

        x3 = (lam ** 2 - P.x - Q.x) % self.p
        y3 = (lam * (P.x - x3) - P.y) % self.p
        return ECPoint(x3, y3)

    def multiply(self, P: ECPoint, k: int) -> ECPoint:
        """Scalar multiplication k*P via double-and-add."""
        k = k % self.n
        result = ECPoint.infinity()
        addend = P
        while k:
            if k & 1:
                result = self.add(result, addend)
            addend = self.add(addend, addend)
            k >>= 1
        return result

    def negate(self, P: ECPoint) -> ECPoint:
        if P.is_infinity:
            return P
        return ECPoint(P.x, (-P.y) % self.p)


# Singleton secp256k1 instance
SECP256K1 = EllipticCurve(_P, _A, _B, _Gx, _Gy, _N, name="secp256k1")

# Small demo curve for fast tests: y² = x³ + 2x + 3 over F(97)
DEMO_CURVE = EllipticCurve(
    p=97, a=2, b=3,
    Gx=3, Gy=6,
    n=5,
    name="demo(p=97)",
)


class ECDH:
    """Elliptic-Curve Diffie-Hellman key exchange."""

    def __init__(self, curve: EllipticCurve = SECP256K1) -> None:
        self.curve = curve

    def generate_keypair(self) -> Tuple[int, ECPoint]:
        """Returns (private_key, public_key_point)."""
        priv = secrets.randbelow(self.curve.n - 1) + 1
        pub = self.curve.multiply(self.curve.G, priv)
        return priv, pub

    def compute_shared_secret(self, my_private: int, their_public: ECPoint) -> int:
        """
        Compute the shared secret x-coordinate of my_private * their_public.
        Both parties derive the same value.
        """
        shared_point = self.curve.multiply(their_public, my_private)
        if shared_point.is_infinity:
            raise ValueError("Shared point is the point at infinity — invalid keys")
        return shared_point.x

    def key_exchange_demo(self) -> dict:
        alice_priv, alice_pub = self.generate_keypair()
        bob_priv, bob_pub = self.generate_keypair()

        alice_shared = self.compute_shared_secret(alice_priv, bob_pub)
        bob_shared = self.compute_shared_secret(bob_priv, alice_pub)

        assert alice_shared == bob_shared
        log.info("ECDH exchange succeeded on curve %s", self.curve.name)
        return {
            "curve": self.curve.name,
            "alice_public_x": alice_pub.x,
            "alice_public_y": alice_pub.y,
            "bob_public_x": bob_pub.x,
            "bob_public_y": bob_pub.y,
            "shared_secret": alice_shared,
            "secrets_match": alice_shared == bob_shared,
        }


class ECIES:
    """
    Simplified ECIES (Elliptic Curve Integrated Encryption Scheme).

    Uses ECDH for key agreement, SHA-256 as KDF, and AES-CBC for encryption.
    """

    def __init__(self, curve: EllipticCurve = SECP256K1) -> None:
        self.ecdh = ECDH(curve)

    def _kdf(self, shared_x: int) -> bytes:
        """SHA-256 of the shared x-coordinate as a 32-byte AES key."""
        return hashlib.sha256(shared_x.to_bytes(32, "big")).digest()

    def encrypt(self, plaintext: bytes, recipient_pub: ECPoint) -> Tuple[ECPoint, bytes, bytes]:
        """
        Returns (ephemeral_pub, iv, ciphertext).
        Encrypt plaintext for the owner of recipient_pub.
        """
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
        except ImportError:
            raise ImportError("Install pycryptodome: pip install pycryptodome")

        r_priv, r_pub = self.ecdh.generate_keypair()
        shared_x = self.ecdh.compute_shared_secret(r_priv, recipient_pub)
        aes_key = self._kdf(shared_x)

        iv = os.urandom(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(plaintext, AES.block_size))
        log.debug("ECIES encrypt: plaintext_len=%d", len(plaintext))
        return r_pub, iv, ct

    def decrypt(
        self, ephemeral_pub: ECPoint, iv: bytes, ciphertext: bytes, priv: int
    ) -> bytes:
        """Decrypt using the recipient's private key."""
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import unpad
        except ImportError:
            raise ImportError("Install pycryptodome: pip install pycryptodome")

        shared_x = self.ecdh.compute_shared_secret(priv, ephemeral_pub)
        aes_key = self._kdf(shared_x)

        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size)

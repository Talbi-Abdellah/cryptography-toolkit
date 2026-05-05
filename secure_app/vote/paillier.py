"""Simple Paillier cryptosystem for a pedagogical voting demo.

The goal is to show additive homomorphism:
- encrypt(0) and encrypt(1) represent individual votes
- multiplying ciphertexts modulo n^2 adds the underlying plaintexts

This is intentionally compact and educational, not production hardened.
"""
from __future__ import annotations

import math
import secrets
from dataclasses import dataclass

from utils.math_utils import generate_prime, mod_inverse


@dataclass(frozen=True)
class PaillierPublicKey:
    n: int
    g: int

    @property
    def n_square(self) -> int:
        return self.n * self.n


@dataclass(frozen=True)
class PaillierPrivateKey:
    lambda_param: int
    mu: int


def _l_function(u: int, n: int) -> int:
    return (u - 1) // n


def _lcm(a: int, b: int) -> int:
    return abs(a * b) // math.gcd(a, b)


def generate_keypair(bits: int = 512) -> tuple[PaillierPublicKey, PaillierPrivateKey]:
    """Generate a simple Paillier keypair.

    The default size is kept moderate for a TP/demo.
    """
    if bits < 128:
        raise ValueError("Paillier bit size should be at least 128")

    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        if p == q:
            continue

        n = p * q
        g = n + 1
        lambda_param = _lcm(p - 1, q - 1)
        n_square = n * n

        # For g = n + 1, L(g^lambda mod n^2) usually equals lambda mod n.
        u = pow(g, lambda_param, n_square)
        l_value = _l_function(u, n)
        mu = mod_inverse(l_value % n, n)
        if mu is None:
            continue

        return PaillierPublicKey(n=n, g=g), PaillierPrivateKey(lambda_param=lambda_param, mu=mu)


def encrypt(m: int, public_key: PaillierPublicKey) -> int:
    """Encrypt a plaintext integer m where 0 <= m < n."""
    if m not in (0, 1) and m < 0:
        raise ValueError("Vote must be 0 or 1")
    if m >= public_key.n:
        raise ValueError("Plaintext must be smaller than n")

    n = public_key.n
    n_square = public_key.n_square

    while True:
        r = secrets.randbelow(n - 1) + 1
        if math.gcd(r, n) == 1:
            break

    return (pow(public_key.g, m, n_square) * pow(r, n, n_square)) % n_square


def decrypt(c: int, private_key: PaillierPrivateKey, public_key: PaillierPublicKey) -> int:
    """Decrypt a Paillier ciphertext."""
    n = public_key.n
    n_square = public_key.n_square
    u = pow(c, private_key.lambda_param, n_square)
    l_value = _l_function(u, n)
    return (l_value * private_key.mu) % n


def homomorphic_add(c1: int, c2: int, public_key: PaillierPublicKey) -> int:
    """Combine two ciphertexts so that decryption yields the sum of plaintexts."""
    return (c1 * c2) % public_key.n_square

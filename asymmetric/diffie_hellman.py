"""Diffie-Hellman key exchange with MITM attack simulation."""
import secrets
from dataclasses import dataclass, field
from typing import Optional, Tuple

from utils.math_utils import generate_prime, primitive_root, is_prime_miller_rabin
from utils.logger import get_logger

log = get_logger("dh")

# Well-known 2048-bit MODP group (RFC 3526) for production use
RFC3526_2048_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
RFC3526_2048_G = 2


@dataclass
class DHParty:
    """One side of a Diffie-Hellman exchange."""
    p: int
    g: int
    private_key: int = field(default=0)
    public_key: int = field(default=0)

    def __post_init__(self) -> None:
        if self.private_key == 0:
            self.private_key = secrets.randbelow(self.p - 2) + 2
        self.public_key = pow(self.g, self.private_key, self.p)

    def compute_shared_secret(self, other_public: int) -> int:
        return pow(other_public, self.private_key, self.p)


class DiffieHellman:
    """Diffie-Hellman key exchange with full MITM simulation."""

    @staticmethod
    def generate_parameters(bits: int = 512) -> Tuple[int, int]:
        """
        Generate a fresh (p, g) pair.
        For `bits` ≤ 1024 we generate on-the-fly; for 2048 we return RFC 3526.
        """
        if bits >= 2048:
            log.info("DH: using RFC 3526 2048-bit group")
            return RFC3526_2048_P, RFC3526_2048_G
        p = generate_prime(bits)
        g = primitive_root(p)
        log.info("DH: generated %d-bit prime", bits)
        return p, g

    @staticmethod
    def key_exchange_demo(bits: int = 512) -> dict:
        """Simulate a complete honest DH exchange."""
        p, g = DiffieHellman.generate_parameters(bits)

        alice = DHParty(p, g)
        bob = DHParty(p, g)

        alice_secret = alice.compute_shared_secret(bob.public_key)
        bob_secret = bob.compute_shared_secret(alice.public_key)

        assert alice_secret == bob_secret, "DH shared secret mismatch"

        log.info("DH key exchange succeeded: shared_secret_bits=%d", alice_secret.bit_length())
        return {
            "prime_bits": p.bit_length(),
            "generator": g,
            "alice_public": alice.public_key,
            "bob_public": bob.public_key,
            "shared_secret": alice_secret,
            "secrets_match": alice_secret == bob_secret,
        }

    @staticmethod
    def mitm_attack_demo(bits: int = 512) -> dict:
        """
        Man-in-the-Middle attack on unauthenticated DH.

        Mallory intercepts Alice↔Bob and substitutes her own public keys.
        Alice thinks she shares a secret with Bob; Bob thinks he shares one
        with Alice — both are actually sharing separate secrets with Mallory.
        """
        p, g = DiffieHellman.generate_parameters(bits)

        # Legitimate parties
        alice = DHParty(p, g)
        bob = DHParty(p, g)

        # Mallory generates two ephemeral keys — one for each side
        mallory_for_alice = DHParty(p, g)
        mallory_for_bob = DHParty(p, g)

        # Alice sends her public key; Mallory intercepts and sends her own to Bob
        # Bob replies; Mallory intercepts and sends her own to Alice

        alice_mallory_secret = alice.compute_shared_secret(mallory_for_alice.public_key)
        mallory_alice_secret = mallory_for_alice.compute_shared_secret(alice.public_key)

        bob_mallory_secret = bob.compute_shared_secret(mallory_for_bob.public_key)
        mallory_bob_secret = mallory_for_bob.compute_shared_secret(bob.public_key)

        # Both pairs must agree
        assert alice_mallory_secret == mallory_alice_secret
        assert bob_mallory_secret == mallory_bob_secret

        log.warning("DH MITM attack demo: Mallory can decrypt all traffic")
        return {
            "prime_bits": p.bit_length(),
            "alice_public": alice.public_key,
            "bob_public": bob.public_key,
            "mallory_public_to_alice": mallory_for_alice.public_key,
            "mallory_public_to_bob": mallory_for_bob.public_key,
            "alice_mallory_shared_secret": alice_mallory_secret,
            "bob_mallory_shared_secret": bob_mallory_secret,
            "alice_knows_real_bob_secret": False,
            "mitigation": (
                "Authenticate public keys via digital signatures or PKI. "
                "Unauthenticated DH is vulnerable to MITM."
            ),
        }

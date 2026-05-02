"""RSA cipher — keygen, textbook RSA, hybrid encryption (RSA + AES)."""
import os
import secrets
from dataclasses import dataclass
from typing import Tuple

from utils.math_utils import generate_prime, mod_inverse
from utils.logger import get_logger

log = get_logger("rsa")

try:
    from Crypto.PublicKey import RSA as _PycryptoRSA
    from Crypto.Cipher import PKCS1_OAEP, AES as _AES
    from Crypto.Util.Padding import pad, unpad
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


@dataclass
class RSAPublicKey:
    n: int
    e: int

    def encrypt_raw(self, m: int) -> int:
        """Textbook RSA: c = m^e mod n. Message must be < n."""
        if m >= self.n:
            raise ValueError("Message too large for key size")
        return pow(m, self.e, self.n)


@dataclass
class RSAPrivateKey:
    n: int
    e: int
    d: int
    p: int
    q: int

    @property
    def public_key(self) -> RSAPublicKey:
        return RSAPublicKey(self.n, self.e)

    def decrypt_raw(self, c: int) -> int:
        """Textbook RSA: m = c^d mod n."""
        return pow(c, self.d, self.n)


class RSACipher:
    """RSA with textbook operations, OAEP hybrid encryption, and keygen."""

    # Common public exponent
    E = 65537

    @staticmethod
    def generate_keypair(bits: int = 2048) -> RSAPrivateKey:
        """
        Generate an RSA keypair of `bits` total modulus size.
        bits must be ≥ 512. Recommended ≥ 2048 for real use.
        """
        if bits < 512:
            raise ValueError("RSA modulus must be at least 512 bits")
        half = bits // 2
        e = RSACipher.E

        while True:
            p = generate_prime(half)
            q = generate_prime(half)
            if p == q:
                continue
            n = p * q
            phi = (p - 1) * (q - 1)
            d = mod_inverse(e, phi)
            if d is not None and n.bit_length() >= bits - 1:
                break

        log.info("RSA keygen: bits=%d p_bits=%d q_bits=%d", bits, p.bit_length(), q.bit_length())
        return RSAPrivateKey(n=n, e=e, d=d, p=p, q=q)

    @staticmethod
    def encrypt_textbook(message: int, pub: RSAPublicKey) -> int:
        """Raw textbook encryption — for educational use only (no padding)."""
        return pub.encrypt_raw(message)

    @staticmethod
    def decrypt_textbook(ciphertext: int, priv: RSAPrivateKey) -> int:
        """Raw textbook decryption."""
        return priv.decrypt_raw(ciphertext)

    # ── Hybrid Encryption (RSA-OAEP + AES-CBC) ───────────────────────────────

    @staticmethod
    def hybrid_encrypt(plaintext: bytes, pub: RSAPublicKey) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt `plaintext` using hybrid RSA+AES:
          1. Generate a random 256-bit AES key.
          2. Encrypt the AES key with RSA-OAEP.
          3. Encrypt plaintext with AES-CBC.
        Returns (encrypted_aes_key, iv, aes_ciphertext).
        """
        if not _HAS_CRYPTO:
            raise ImportError("Install pycryptodome: pip install pycryptodome")

        # Export our custom key to pycryptodome format
        rsa_key = _PycryptoRSA.construct((pub.n, pub.e))
        rsa_cipher = PKCS1_OAEP.new(rsa_key)

        aes_key = os.urandom(32)
        encrypted_aes_key = rsa_cipher.encrypt(aes_key)

        iv = os.urandom(16)
        aes_cipher = _AES.new(aes_key, _AES.MODE_CBC, iv)
        ct = aes_cipher.encrypt(pad(plaintext, _AES.block_size))

        log.debug("RSA hybrid encrypt: plaintext_len=%d", len(plaintext))
        return encrypted_aes_key, iv, ct

    @staticmethod
    def hybrid_decrypt(
        encrypted_aes_key: bytes, iv: bytes, ciphertext: bytes, priv: RSAPrivateKey
    ) -> bytes:
        """Decrypt a hybrid-encrypted message."""
        if not _HAS_CRYPTO:
            raise ImportError("Install pycryptodome: pip install pycryptodome")

        rsa_key = _PycryptoRSA.construct((priv.n, priv.e, priv.d, priv.p, priv.q))
        rsa_cipher = PKCS1_OAEP.new(rsa_key)
        aes_key = rsa_cipher.decrypt(encrypted_aes_key)

        aes_cipher = _AES.new(aes_key, _AES.MODE_CBC, iv)
        plaintext = unpad(aes_cipher.decrypt(ciphertext), _AES.block_size)
        log.debug("RSA hybrid decrypt: plaintext_len=%d", len(plaintext))
        return plaintext

    @staticmethod
    def export_public_pem(priv: RSAPrivateKey) -> str:
        """Export RSA public key as PEM string (requires pycryptodome)."""
        if not _HAS_CRYPTO:
            raise ImportError("Install pycryptodome")
        key = _PycryptoRSA.construct((priv.n, priv.e))
        return key.export_key("PEM").decode()

    @staticmethod
    def export_private_pem(priv: RSAPrivateKey) -> str:
        """Export RSA private key as PEM string (requires pycryptodome)."""
        if not _HAS_CRYPTO:
            raise ImportError("Install pycryptodome")
        key = _PycryptoRSA.construct((priv.n, priv.e, priv.d, priv.p, priv.q))
        return key.export_key("PEM").decode()

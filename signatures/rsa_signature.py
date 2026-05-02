"""RSA digital signatures using PSS padding."""
from typing import Optional

from utils.logger import get_logger

log = get_logger("rsa_sig")

try:
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pss
    from Crypto.Hash import SHA256, SHA512
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False
    log.warning("pycryptodome not installed — RSA signatures unavailable")


def _require_crypto() -> None:
    if not _HAS_CRYPTO:
        raise ImportError("Install pycryptodome: pip install pycryptodome")


class RSASigner:
    """RSA-PSS digital signatures (PKCS #1 v2.2)."""

    def __init__(self, key_size: int = 2048) -> None:
        _require_crypto()
        if key_size not in (512, 1024, 2048, 4096):
            raise ValueError("key_size must be 512, 1024, 2048, or 4096")
        self._key = RSA.generate(key_size)
        log.info("RSASigner: generated %d-bit keypair", key_size)

    @classmethod
    def from_pem(cls, private_pem: str) -> "RSASigner":
        """Load an existing RSA private key from PEM string."""
        _require_crypto()
        obj = cls.__new__(cls)
        obj._key = RSA.import_key(private_pem.encode())
        return obj

    @property
    def private_pem(self) -> str:
        return self._key.export_key("PEM").decode()

    @property
    def public_pem(self) -> str:
        return self._key.publickey().export_key("PEM").decode()

    def sign(self, message: bytes, hash_algo: str = "sha256") -> bytes:
        """Sign `message` with RSA-PSS. Returns raw signature bytes."""
        h = self._make_hash(message, hash_algo)
        signer = pss.new(self._key)
        sig = signer.sign(h)
        log.debug("RSA-PSS sign: msg_len=%d sig_len=%d", len(message), len(sig))
        return sig

    def verify(self, message: bytes, signature: bytes, hash_algo: str = "sha256") -> bool:
        """Verify RSA-PSS signature. Returns True if valid."""
        pub_key = self._key.publickey()
        h = self._make_hash(message, hash_algo)
        verifier = pss.new(pub_key)
        try:
            verifier.verify(h, signature)
            log.debug("RSA-PSS verify: OK")
            return True
        except (ValueError, TypeError):
            log.warning("RSA-PSS verify: FAILED")
            return False

    def verify_with_public_pem(
        self, message: bytes, signature: bytes, public_pem: str, hash_algo: str = "sha256"
    ) -> bool:
        """Verify using an externally provided PEM public key."""
        pub_key = RSA.import_key(public_pem.encode())
        h = self._make_hash(message, hash_algo)
        verifier = pss.new(pub_key)
        try:
            verifier.verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _make_hash(data: bytes, algo: str):
        algo = algo.lower().replace("-", "")
        if algo == "sha256":
            return SHA256.new(data)
        if algo == "sha512":
            return SHA512.new(data)
        raise ValueError(f"Unsupported hash algorithm: {algo}")

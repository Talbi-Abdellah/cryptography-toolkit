"""DSA and ECDSA signatures using the cryptography library."""
from utils.logger import get_logger

log = get_logger("dsa_ecdsa")

try:
    from cryptography.hazmat.primitives.asymmetric import dsa, ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature, encode_dss_signature,
    )
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.exceptions import InvalidSignature
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False
    log.warning("cryptography library not installed — DSA/ECDSA unavailable")


def _require() -> None:
    if not _HAS_CRYPTOGRAPHY:
        raise ImportError("Install cryptography: pip install cryptography")


class DSASigner:
    """DSA (Digital Signature Algorithm) using the cryptography library."""

    def __init__(self, key_size: int = 2048) -> None:
        _require()
        if key_size not in (1024, 2048, 3072):
            raise ValueError("DSA key size must be 1024, 2048, or 3072")
        self._private_key = dsa.generate_private_key(key_size=key_size)
        self._public_key = self._private_key.public_key()
        log.info("DSA keygen: key_size=%d", key_size)

    @property
    def private_pem(self) -> str:
        return self._private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

    @property
    def public_pem(self) -> str:
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def sign(self, message: bytes) -> bytes:
        """Sign `message`. Returns DER-encoded (r, s) signature."""
        sig = self._private_key.sign(message, hashes.SHA256())
        log.debug("DSA sign: msg_len=%d sig_len=%d", len(message), len(sig))
        return sig

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify DSA signature. Returns True if valid."""
        try:
            self._public_key.verify(signature, message, hashes.SHA256())
            return True
        except InvalidSignature:
            return False

    def verify_with_public_pem(self, message: bytes, signature: bytes, public_pem: str) -> bool:
        """Verify against an external PEM public key."""
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        pub = load_pem_public_key(public_pem.encode())
        try:
            pub.verify(signature, message, hashes.SHA256())
            return True
        except InvalidSignature:
            return False


class ECDSASigner:
    """ECDSA (Elliptic Curve Digital Signature Algorithm)."""

    CURVES = {
        "p256":   ec.SECP256R1(),
        "p384":   ec.SECP384R1(),
        "p521":   ec.SECP521R1(),
        "secp256k1": ec.SECP256K1(),
    }

    def __init__(self, curve: str = "p256") -> None:
        _require()
        curve_obj = self.CURVES.get(curve.lower())
        if curve_obj is None:
            raise ValueError(f"Unknown curve '{curve}'. Choose: {list(self.CURVES)}")
        self._private_key = ec.generate_private_key(curve_obj)
        self._public_key = self._private_key.public_key()
        self.curve_name = curve
        log.info("ECDSA keygen: curve=%s", curve)

    @property
    def private_pem(self) -> str:
        return self._private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

    @property
    def public_pem(self) -> str:
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def sign(self, message: bytes, hash_algo: str = "sha256") -> bytes:
        """Sign `message` with ECDSA. Returns DER-encoded signature."""
        h = self._select_hash(hash_algo)
        sig = self._private_key.sign(message, ec.ECDSA(h))
        log.debug("ECDSA sign: curve=%s msg_len=%d", self.curve_name, len(message))
        return sig

    def verify(self, message: bytes, signature: bytes, hash_algo: str = "sha256") -> bool:
        """Verify ECDSA signature."""
        h = self._select_hash(hash_algo)
        try:
            self._public_key.verify(signature, message, ec.ECDSA(h))
            return True
        except InvalidSignature:
            return False

    def get_raw_signature(self, message: bytes) -> tuple[int, int]:
        """Return raw (r, s) integers from a DER-encoded signature."""
        sig = self.sign(message)
        return decode_dss_signature(sig)

    @staticmethod
    def _select_hash(algo: str) -> hashes.HashAlgorithm:
        algo = algo.lower().replace("-", "")
        mapping = {
            "sha256": hashes.SHA256(),
            "sha384": hashes.SHA384(),
            "sha512": hashes.SHA512(),
        }
        if algo not in mapping:
            raise ValueError(f"Unsupported hash: {algo}")
        return mapping[algo]

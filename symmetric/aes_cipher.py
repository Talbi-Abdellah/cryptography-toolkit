"""AES cipher — ECB and CBC modes using pycryptodome."""
import os

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    raise ImportError("pycryptodome is required: pip install pycryptodome")

BLOCK_SIZE = 16  # AES block is always 128 bits


def _validate_key(key: bytes) -> None:
    if len(key) not in (16, 24, 32):
        raise ValueError(
            f"AES key must be 16, 24, or 32 bytes (got {len(key)})."
        )


# ── ECB ───────────────────────────────────────────────────────────────────────

def encrypt_ecb(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt with AES-ECB. Pads plaintext automatically."""
    _validate_key(key)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, BLOCK_SIZE))


def decrypt_ecb(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt with AES-ECB. Removes padding automatically."""
    _validate_key(key)
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)


# ── CBC ───────────────────────────────────────────────────────────────────────

def encrypt_cbc(key: bytes, plaintext: bytes, iv: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Encrypt with AES-CBC.
    Generates a random IV if none is provided.
    Returns (iv, ciphertext).
    """
    _validate_key(key)
    if iv is None:
        iv = os.urandom(BLOCK_SIZE)
    elif len(iv) != BLOCK_SIZE:
        raise ValueError(f"IV must be {BLOCK_SIZE} bytes.")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv, cipher.encrypt(pad(plaintext, BLOCK_SIZE))


def decrypt_cbc(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    """Decrypt with AES-CBC."""
    _validate_key(key)
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"IV must be {BLOCK_SIZE} bytes.")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)

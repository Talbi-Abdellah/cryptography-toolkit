"""One-Time Pad — basic XOR encryption."""
import secrets


def generate_key(length: int) -> bytes:
    """Generate a cryptographically random key of `length` bytes."""
    return secrets.token_bytes(length)


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """XOR every byte of plaintext with the corresponding key byte."""
    if len(key) < len(plaintext):
        raise ValueError(
            f"Key ({len(key)} bytes) must be at least as long as the plaintext ({len(plaintext)} bytes)."
        )
    return bytes(p ^ k for p, k in zip(plaintext, key))


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """XOR is its own inverse — decryption is identical to encryption."""
    return encrypt(ciphertext, key)

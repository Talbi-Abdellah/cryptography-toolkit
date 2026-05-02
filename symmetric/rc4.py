"""RC4 stream cipher — manual KSA + PRGA implementation."""


def _ksa(key: bytes) -> list[int]:
    """Key Scheduling Algorithm — builds the initial state array S."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def _prga(S: list[int], length: int) -> bytes:
    """Pseudo-Random Generation Algorithm — produces `length` keystream bytes."""
    S = list(S)  # work on a copy so the original S is not mutated
    i = j = 0
    keystream = []
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        keystream.append(S[(S[i] + S[j]) % 256])
    return bytes(keystream)


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext by XORing with the RC4 keystream."""
    if not key:
        raise ValueError("Key must not be empty.")
    S = _ksa(key)
    keystream = _prga(S, len(plaintext))
    return bytes(p ^ k for p, k in zip(plaintext, keystream))


def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt — RC4 is symmetric, so decryption is the same operation."""
    return encrypt(key, ciphertext)

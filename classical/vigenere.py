"""Vigenère cipher — encrypt and decrypt."""


def _clean_key(key: str) -> str:
    """Keep only letters, uppercase."""
    cleaned = ''.join(c.upper() for c in key if c.isalpha())
    if not cleaned:
        raise ValueError("Key must contain at least one letter.")
    return cleaned


def encrypt(plaintext: str, key: str) -> str:
    """Encrypt plaintext with the Vigenère key."""
    key = _clean_key(key)
    result = []
    key_index = 0
    for ch in plaintext:
        if ch.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
            key_index += 1
        else:
            result.append(ch)
    return ''.join(result)


def decrypt(ciphertext: str, key: str) -> str:
    """Decrypt ciphertext with the Vigenère key."""
    key = _clean_key(key)
    # Build inverse key: each shift becomes (26 - shift) % 26
    inv_key = ''.join(chr((26 - (ord(c) - ord('A'))) % 26 + ord('A')) for c in key)
    return encrypt(ciphertext, inv_key)

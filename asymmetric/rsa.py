"""RSA key generation, encryption, and decryption."""

import secrets


def _is_prime(n: int, rounds: int = 8) -> bool:
    if n < 2 or n % 2 == 0:
        return n == 2
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)


def _modinv(a: int, m: int) -> int:
    original_m = m
    x0, x1 = 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += original_m
    return x1


def _generate_prime(bits: int) -> int:
    if bits < 16:
        raise ValueError("Bit length must be at least 16")
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(candidate):
            return candidate


def generate_keypair(bits: int = 1024) -> tuple[int, int, int]:
    if bits < 512:
        raise ValueError("RSA bit size should be at least 512")
    half = bits // 2
    p = _generate_prime(half)
    q = _generate_prime(half)
    while q == p:
        q = _generate_prime(half)

    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if _gcd(e, phi) != 1:
        raise ValueError("Failed to find a valid public exponent")

    d = _modinv(e, phi)
    return n, e, d


def encrypt_text(message: str, n: int, e: int) -> str:
    data = message.encode("utf-8")
    if len(data) == 0:
        return "0"
    max_size = (n.bit_length() - 1) // 8
    if len(data) > max_size:
        raise ValueError(f"Message too long for key size ({len(data)} > {max_size} bytes)")
    m = int.from_bytes(data, "big")
    c = pow(m, e, n)
    return format(c, "x")


def decrypt_text(cipher_hex: str, n: int, d: int) -> str:
    if cipher_hex == "0":
        return ""
    c = int(cipher_hex, 16)
    m = pow(c, d, n)
    byte_length = (m.bit_length() + 7) // 8
    if byte_length == 0:
        return ""
    plaintext = m.to_bytes(byte_length, "big")
    return plaintext.decode("utf-8", errors="replace")

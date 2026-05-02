"""Mathematical primitives for cryptographic operations."""
import random
import math
from typing import Optional, Tuple, List


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Returns (gcd, x, y) satisfying a*x + b*y = gcd."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    return gcd, y1 - (b // a) * x1, x1


def mod_inverse(a: int, m: int) -> Optional[int]:
    """Modular inverse of a mod m. Returns None if gcd(a,m) != 1."""
    gcd, x, _ = extended_gcd(a % m, m)
    if gcd != 1:
        return None
    return x % m


def is_prime_miller_rabin(n: int, k: int = 20) -> bool:
    """Miller-Rabin probabilistic primality test with k rounds."""
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    if n in small_primes:
        return True
    if any(n % p == 0 for p in small_primes):
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """Generate a random probable prime of the given bit length."""
    while True:
        n = random.getrandbits(bits)
        n |= (1 << (bits - 1)) | 1  # set MSB and LSB
        if is_prime_miller_rabin(n):
            return n


def generate_safe_prime(bits: int) -> Tuple[int, int]:
    """Generate safe prime p = 2q+1 where q is also prime. Returns (p, q)."""
    while True:
        q = generate_prime(bits - 1)
        p = 2 * q + 1
        if is_prime_miller_rabin(p):
            return p, q


def primitive_root(p: int) -> int:
    """Find the smallest primitive root modulo prime p."""
    if p == 2:
        return 1
    phi = p - 1
    factors: set[int] = set()
    n = phi
    d = 2
    while d * d <= n:
        if n % d == 0:
            factors.add(d)
            while n % d == 0:
                n //= d
        d += 1
    if n > 1:
        factors.add(n)

    for g in range(2, p):
        if all(pow(g, phi // f, p) != 1 for f in factors):
            return g
    return -1


def mod_matrix_inverse(matrix: List[List[int]], mod: int) -> Optional[List[List[int]]]:
    """Compute the modular inverse of a 2×2 or 3×3 integer matrix mod `mod`."""
    n = len(matrix)
    if n == 2:
        a, b = matrix[0][0], matrix[0][1]
        c, d = matrix[1][0], matrix[1][1]
        det = (a * d - b * c) % mod
        inv = mod_inverse(det, mod)
        if inv is None:
            return None
        return [
            [(d * inv) % mod, (-b * inv) % mod],
            [(-c * inv) % mod, (a * inv) % mod],
        ]
    elif n == 3:
        # Cofactor expansion along first row to compute det and cofactor matrix
        def minor_det2(M: List[List[int]], row: int, col: int) -> int:
            rows = [r for r in range(3) if r != row]
            cols = [c for c in range(3) if c != col]
            return M[rows[0]][cols[0]] * M[rows[1]][cols[1]] - M[rows[0]][cols[1]] * M[rows[1]][cols[0]]

        cofactors = [[0] * 3 for _ in range(3)]
        for i in range(3):
            for j in range(3):
                cofactors[i][j] = ((-1) ** (i + j) * minor_det2(matrix, i, j)) % mod

        det = sum(matrix[0][j] * cofactors[0][j] for j in range(3)) % mod
        inv = mod_inverse(det % mod, mod)
        if inv is None:
            return None
        # Adjugate = transpose of cofactor matrix
        return [[(cofactors[j][i] * inv) % mod for j in range(3)] for i in range(3)]
    raise ValueError("Only 2×2 and 3×3 matrices supported")


def matrix_multiply_mod(A: List[List[int]], B: List[List[int]], mod: int) -> List[List[int]]:
    """Matrix multiplication A @ B (mod `mod`)."""
    rows_A, cols_A = len(A), len(A[0])
    cols_B = len(B[0])
    result = [[0] * cols_B for _ in range(rows_A)]
    for i in range(rows_A):
        for j in range(cols_B):
            result[i][j] = sum(A[i][k] * B[k][j] for k in range(cols_A)) % mod
    return result


def matrix_det_mod(M: List[List[int]], mod: int) -> int:
    """Determinant of a square matrix mod `mod` (2×2 or 3×3)."""
    n = len(M)
    if n == 2:
        return (M[0][0] * M[1][1] - M[0][1] * M[1][0]) % mod
    elif n == 3:
        d = (
            M[0][0] * (M[1][1] * M[2][2] - M[1][2] * M[2][1])
            - M[0][1] * (M[1][0] * M[2][2] - M[1][2] * M[2][0])
            + M[0][2] * (M[1][0] * M[2][1] - M[1][1] * M[2][0])
        )
        return d % mod
    raise ValueError("Only 2×2 and 3×3 matrices supported")

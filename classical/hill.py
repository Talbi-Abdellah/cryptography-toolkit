"""Hill cipher — 2×2 matrix, encrypt and decrypt."""


# ── Modular arithmetic helpers ─────────────────────────────────────────────────

def _mod_inverse(a: int, m: int) -> int:
    """Extended Euclidean algorithm — returns x such that a*x ≡ 1 (mod m)."""
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError(f"{a} has no inverse mod {m}")


def _matrix_inverse_2x2(mat: list[list[int]]) -> list[list[int]]:
    """Inverse of a 2×2 integer matrix mod 26."""
    a, b = mat[0]
    c, d = mat[1]
    det = (a * d - b * c) % 26
    det_inv = _mod_inverse(det, 26)
    return [
        [(d * det_inv) % 26, (-b * det_inv) % 26],
        [(-c * det_inv) % 26, (a * det_inv) % 26],
    ]


def _mat_vec_mul(mat: list[list[int]], vec: list[int]) -> list[int]:
    """Multiply 2×2 matrix by 2×1 column vector, mod 26."""
    return [
        (mat[0][0] * vec[0] + mat[0][1] * vec[1]) % 26,
        (mat[1][0] * vec[0] + mat[1][1] * vec[1]) % 26,
    ]


def _text_to_nums(text: str) -> list[int]:
    return [ord(c.upper()) - ord('A') for c in text if c.isalpha()]


def _nums_to_text(nums: list[int]) -> str:
    return ''.join(chr(n % 26 + ord('A')) for n in nums)


# ── Public API ─────────────────────────────────────────────────────────────────

def validate_key(key_matrix: list[list[int]]) -> None:
    """Raise ValueError if the 2×2 key matrix is not invertible mod 26."""
    a, b = key_matrix[0]
    c, d = key_matrix[1]
    det = (a * d - b * c) % 26
    try:
        _mod_inverse(det, 26)
    except ValueError:
        raise ValueError(
            f"Key matrix determinant {det} is not invertible mod 26. "
            "Choose a matrix whose determinant is coprime to 26."
        )


def encrypt(plaintext: str, key_matrix: list[list[int]]) -> str:
    """
    Encrypt plaintext with a 2×2 Hill key matrix.
    Non-alpha characters are ignored. Text is padded with 'X' if odd length.
    """
    validate_key(key_matrix)
    nums = _text_to_nums(plaintext)
    if len(nums) % 2 != 0:
        nums.append(23)  # pad with 'X'

    result = []
    for i in range(0, len(nums), 2):
        block = [nums[i], nums[i + 1]]
        enc = _mat_vec_mul(key_matrix, block)
        result.extend(enc)
    return _nums_to_text(result)


def decrypt(ciphertext: str, key_matrix: list[list[int]]) -> str:
    """Decrypt ciphertext using the inverse of the 2×2 key matrix."""
    validate_key(key_matrix)
    inv = _matrix_inverse_2x2(key_matrix)
    nums = _text_to_nums(ciphertext)
    if len(nums) % 2 != 0:
        nums.append(23)

    result = []
    for i in range(0, len(nums), 2):
        block = [nums[i], nums[i + 1]]
        dec = _mat_vec_mul(inv, block)
        result.extend(dec)
    return _nums_to_text(result)

"""Caesar cipher — encrypt, decrypt, brute force."""

ENGLISH_FREQ = "etaoinshrdlcumwfgypbvkjxqz"


def encrypt(plaintext: str, shift: int) -> str:
    """Shift each letter by `shift` positions (0-25)."""
    result = []
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return ''.join(result)


def decrypt(ciphertext: str, shift: int) -> str:
    """Reverse the Caesar shift."""
    return encrypt(ciphertext, -shift)


def brute_force(ciphertext: str) -> list[tuple[int, str]]:
    """
    Try all 26 shifts. Returns list of (shift, plaintext) pairs sorted
    by likelihood (scored against English letter frequency).
    """
    def score(text: str) -> int:
        text = text.lower()
        return sum(ENGLISH_FREQ.index(c) for c in text if c in ENGLISH_FREQ)

    results = []
    for shift in range(26):
        candidate = decrypt(ciphertext, shift)
        results.append((shift, candidate, score(candidate)))

    # Lower score = more common letters = more likely English
    results.sort(key=lambda x: x[2])
    return [(shift, text) for shift, text, _ in results]

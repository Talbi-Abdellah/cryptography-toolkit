"""DES and 3DES cipher wrappers with image encryption demo."""
import os
from pathlib import Path
from typing import Optional, Tuple

from utils.logger import get_logger

log = get_logger("des")

try:
    from Crypto.Cipher import DES, DES3
    from Crypto.Util.Padding import pad, unpad
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False
    log.warning("pycryptodome not installed — DES/3DES will be unavailable")


def _require_crypto() -> None:
    if not _HAS_CRYPTO:
        raise ImportError("Install pycryptodome: pip install pycryptodome")


class DESCipher:
    """DES (56-bit effective key) in ECB and CBC modes."""

    KEY_SIZE = 8   # 8 bytes (64 bits, 56 effective)
    BLOCK_SIZE = 8

    def __init__(self, key: bytes) -> None:
        _require_crypto()
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"DES key must be exactly {self.KEY_SIZE} bytes")
        self.key = key

    # ── ECB ───────────────────────────────────────────────────────────────────

    def encrypt_ecb(self, plaintext: bytes) -> bytes:
        cipher = DES.new(self.key, DES.MODE_ECB)
        padded = pad(plaintext, self.BLOCK_SIZE)
        ct = cipher.encrypt(padded)
        log.debug("DES-ECB encrypt: len=%d", len(plaintext))
        return ct

    def decrypt_ecb(self, ciphertext: bytes) -> bytes:
        cipher = DES.new(self.key, DES.MODE_ECB)
        return unpad(cipher.decrypt(ciphertext), self.BLOCK_SIZE)

    # ── CBC ───────────────────────────────────────────────────────────────────

    def encrypt_cbc(self, plaintext: bytes, iv: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Returns (iv, ciphertext)."""
        if iv is None:
            iv = os.urandom(self.BLOCK_SIZE)
        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(plaintext, self.BLOCK_SIZE))
        log.debug("DES-CBC encrypt: len=%d", len(plaintext))
        return iv, ct

    def decrypt_cbc(self, ciphertext: bytes, iv: bytes) -> bytes:
        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), self.BLOCK_SIZE)

    # ── Image Encryption Demo ─────────────────────────────────────────────────

    def encrypt_image_ecb(self, input_path: str, output_path: str) -> None:
        """
        Encrypt a BMP image pixel-by-pixel in ECB mode.
        ECB preserves pixel patterns — the image structure remains visible
        even after encryption, demonstrating ECB's fundamental weakness.
        """
        try:
            from PIL import Image
        except ImportError:
            raise ImportError("Install Pillow: pip install Pillow")

        img = Image.open(input_path).convert("RGB")
        pixels = list(img.getdata())
        raw = bytes(v for px in pixels for v in px)

        cipher = DES.new(self.key, DES.MODE_ECB)
        padded = pad(raw, self.BLOCK_SIZE)
        enc = cipher.encrypt(padded)

        # Reconstruct image from encrypted bytes (trim to original size)
        enc_pixels = [
            (enc[i], enc[i + 1] if i + 1 < len(enc) else 0,
             enc[i + 2] if i + 2 < len(enc) else 0)
            for i in range(0, len(pixels) * 3, 3)
        ]
        out_img = Image.new("RGB", img.size)
        out_img.putdata(enc_pixels)
        out_img.save(output_path)
        log.info("DES-ECB image encrypt: %s -> %s", input_path, output_path)

    def encrypt_image_cbc(
        self, input_path: str, output_path: str, iv: Optional[bytes] = None
    ) -> bytes:
        """Encrypt image in CBC mode — output looks like random noise. Returns IV."""
        try:
            from PIL import Image
        except ImportError:
            raise ImportError("Install Pillow: pip install Pillow")

        if iv is None:
            iv = os.urandom(self.BLOCK_SIZE)
        img = Image.open(input_path).convert("RGB")
        pixels = list(img.getdata())
        raw = bytes(v for px in pixels for v in px)

        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        enc = cipher.encrypt(pad(raw, self.BLOCK_SIZE))

        enc_pixels = [
            (enc[i], enc[i + 1] if i + 1 < len(enc) else 0,
             enc[i + 2] if i + 2 < len(enc) else 0)
            for i in range(0, len(pixels) * 3, 3)
        ]
        out_img = Image.new("RGB", img.size)
        out_img.putdata(enc_pixels)
        out_img.save(output_path)
        log.info("DES-CBC image encrypt: %s -> %s", input_path, output_path)
        return iv


class TripleDESCipher:
    """3DES (Triple DES) — 16- or 24-byte key in ECB and CBC modes."""

    def __init__(self, key: bytes) -> None:
        _require_crypto()
        if len(key) not in (16, 24):
            raise ValueError("3DES key must be 16 or 24 bytes")
        self.key = key

    def encrypt_ecb(self, plaintext: bytes) -> bytes:
        cipher = DES3.new(self.key, DES3.MODE_ECB)
        return cipher.encrypt(pad(plaintext, DES3.block_size))

    def decrypt_ecb(self, ciphertext: bytes) -> bytes:
        cipher = DES3.new(self.key, DES3.MODE_ECB)
        return unpad(cipher.decrypt(ciphertext), DES3.block_size)

    def encrypt_cbc(self, plaintext: bytes, iv: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Returns (iv, ciphertext)."""
        if iv is None:
            iv = os.urandom(DES3.block_size)
        cipher = DES3.new(self.key, DES3.MODE_CBC, iv)
        return iv, cipher.encrypt(pad(plaintext, DES3.block_size))

    def decrypt_cbc(self, ciphertext: bytes, iv: bytes) -> bytes:
        cipher = DES3.new(self.key, DES3.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), DES3.block_size)

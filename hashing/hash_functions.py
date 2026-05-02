"""Hashing utilities — MD5, SHA-256, SHA-512, avalanche effect."""
import hashlib
import string
from typing import Callable, List, Tuple

from utils.logger import get_logger

log = get_logger("hashing")


class HashFunctions:
    """Collection of hash operations and measurement tools."""

    ALGORITHMS = {
        "md5":    hashlib.md5,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
    }

    @staticmethod
    def digest(data: bytes, algorithm: str = "sha256") -> bytes:
        """Compute raw digest bytes."""
        algo = algorithm.lower().replace("-", "")
        if algo not in HashFunctions.ALGORITHMS:
            raise ValueError(f"Unknown algorithm '{algorithm}'. Choose: {list(HashFunctions.ALGORITHMS)}")
        return HashFunctions.ALGORITHMS[algo](data).digest()

    @staticmethod
    def hexdigest(data: bytes, algorithm: str = "sha256") -> str:
        """Compute hex-encoded digest."""
        algo = algorithm.lower().replace("-", "")
        if algo not in HashFunctions.ALGORITHMS:
            raise ValueError(f"Unknown algorithm '{algorithm}'")
        return HashFunctions.ALGORITHMS[algo](data).hexdigest()

    @staticmethod
    def md5(data: bytes) -> str:
        return hashlib.md5(data).hexdigest()

    @staticmethod
    def sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def sha512(data: bytes) -> str:
        return hashlib.sha512(data).hexdigest()

    # ── Avalanche Effect ──────────────────────────────────────────────────────

    @staticmethod
    def hamming_distance(b1: bytes, b2: bytes) -> int:
        """Bit-level Hamming distance between two equal-length byte strings."""
        if len(b1) != len(b2):
            raise ValueError("Byte strings must be the same length")
        dist = 0
        for x, y in zip(b1, b2):
            diff = x ^ y
            dist += bin(diff).count('1')
        return dist

    @staticmethod
    def avalanche_effect(
        data: bytes,
        algorithm: str = "sha256",
        num_flips: int = 32,
    ) -> dict:
        """
        Measure the avalanche effect for `algorithm` on `data`.

        For each of `num_flips` randomly chosen bit positions, flip one bit
        in `data`, hash both original and modified inputs, and measure the
        fraction of output bits that differ.

        A good hash function exhibits ~50% bit change per single-bit input change.
        """
        import random

        original_hash = HashFunctions.digest(data, algorithm)
        hash_bits = len(original_hash) * 8

        bit_differences: List[float] = []
        for _ in range(num_flips):
            bit_pos = random.randrange(len(data) * 8)
            byte_idx = bit_pos // 8
            bit_idx = bit_pos % 8

            modified = bytearray(data)
            modified[byte_idx] ^= (1 << bit_idx)

            modified_hash = HashFunctions.digest(bytes(modified), algorithm)
            dist = HashFunctions.hamming_distance(original_hash, modified_hash)
            bit_differences.append(dist / hash_bits)

        avg_avalanche = sum(bit_differences) / len(bit_differences)
        log.info("Avalanche effect (%s): avg=%.2f%%", algorithm, avg_avalanche * 100)
        return {
            "algorithm": algorithm,
            "data_preview": data[:20].decode(errors="replace"),
            "original_hash": original_hash.hex(),
            "num_flips_tested": num_flips,
            "average_bit_change_pct": round(avg_avalanche * 100, 2),
            "min_bit_change_pct": round(min(bit_differences) * 100, 2),
            "max_bit_change_pct": round(max(bit_differences) * 100, 2),
            "ideal_pct": 50.0,
        }

    @staticmethod
    def compare_all(data: bytes) -> List[Tuple[str, str, int]]:
        """
        Hash `data` with MD5, SHA-256, SHA-512.
        Returns list of (algorithm, hex_digest, digest_bits).
        """
        results = []
        for name in ["md5", "sha256", "sha512"]:
            h = HashFunctions.hexdigest(data, name)
            results.append((name, h, len(h) * 4))
        return results

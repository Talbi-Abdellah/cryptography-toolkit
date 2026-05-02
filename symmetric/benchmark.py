"""Symmetric cipher performance comparison."""
import os
import time
from typing import List, Dict

from utils.logger import get_logger

log = get_logger("sym_bench")


def benchmark_symmetric(data_size_mb: float = 5.0) -> List[Dict]:
    """
    Benchmark RC4, DES-CBC, 3DES-CBC, AES-128-CBC, AES-256-CBC.
    Returns list of result dicts sortable by throughput.
    """
    data = os.urandom(int(data_size_mb * 1024 * 1024))
    results = []

    # ── RC4 ──────────────────────────────────────────────────────────────────
    try:
        from symmetric.rc4 import RC4Cipher
        key = os.urandom(16)
        t0 = time.perf_counter()
        RC4Cipher.encrypt(key, data)
        elapsed = time.perf_counter() - t0
        results.append({
            "cipher": "RC4",
            "key_bits": 128,
            "mode": "Stream",
            "data_MB": data_size_mb,
            "time_s": round(elapsed, 4),
            "throughput_MB_s": round(data_size_mb / elapsed, 2),
        })
    except Exception as e:
        log.warning("RC4 benchmark failed: %s", e)

    # ── DES-CBC ──────────────────────────────────────────────────────────────
    try:
        from symmetric.des_cipher import DESCipher
        key = os.urandom(8)
        iv = os.urandom(8)
        cipher = DESCipher(key)
        t0 = time.perf_counter()
        cipher.encrypt_cbc(data, iv)
        elapsed = time.perf_counter() - t0
        results.append({
            "cipher": "DES",
            "key_bits": 56,
            "mode": "CBC",
            "data_MB": data_size_mb,
            "time_s": round(elapsed, 4),
            "throughput_MB_s": round(data_size_mb / elapsed, 2),
        })
    except Exception as e:
        log.warning("DES benchmark failed: %s", e)

    # ── 3DES-CBC ─────────────────────────────────────────────────────────────
    try:
        from symmetric.des_cipher import TripleDESCipher
        key = os.urandom(24)
        iv = os.urandom(8)
        cipher = TripleDESCipher(key)
        t0 = time.perf_counter()
        cipher.encrypt_cbc(data, iv)
        elapsed = time.perf_counter() - t0
        results.append({
            "cipher": "3DES",
            "key_bits": 168,
            "mode": "CBC",
            "data_MB": data_size_mb,
            "time_s": round(elapsed, 4),
            "throughput_MB_s": round(data_size_mb / elapsed, 2),
        })
    except Exception as e:
        log.warning("3DES benchmark failed: %s", e)

    # ── AES variants ─────────────────────────────────────────────────────────
    try:
        from symmetric.aes_cipher import AESCipher
        for bits, key_len in [(128, 16), (192, 24), (256, 32)]:
            key = os.urandom(key_len)
            iv = os.urandom(16)
            cipher = AESCipher(key)
            t0 = time.perf_counter()
            cipher.encrypt_cbc(data, iv)
            elapsed = time.perf_counter() - t0
            results.append({
                "cipher": f"AES-{bits}",
                "key_bits": bits,
                "mode": "CBC",
                "data_MB": data_size_mb,
                "time_s": round(elapsed, 4),
                "throughput_MB_s": round(data_size_mb / elapsed, 2),
            })
    except Exception as e:
        log.warning("AES benchmark failed: %s", e)

    results.sort(key=lambda r: -r["throughput_MB_s"])
    return results

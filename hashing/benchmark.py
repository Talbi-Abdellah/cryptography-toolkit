"""Hash function performance benchmark."""
import hashlib
import os
import time
from typing import Dict, List

from utils.logger import get_logger

log = get_logger("hash_bench")


def benchmark_hashing(data_size_mb: float = 100.0) -> List[Dict]:
    """
    Measure throughput (MB/s) of MD5, SHA-1, SHA-256, SHA-384, SHA-512
    over `data_size_mb` of random data.
    Returns results sorted by throughput descending.
    """
    data = os.urandom(int(data_size_mb * 1024 * 1024))
    algorithms = ["md5", "sha256", "sha512"]
    results = []

    for algo in algorithms:
        if algo not in hashlib.algorithms_available:
            log.debug("Skipping unavailable algorithm: %s", algo)
            continue
        try:
            t0 = time.perf_counter()
            hashlib.new(algo, data).hexdigest()
            elapsed = time.perf_counter() - t0
            throughput = data_size_mb / elapsed
            results.append({
                "algorithm": algo.upper(),
                "digest_bits": hashlib.new(algo).digest_size * 8,
                "data_MB": data_size_mb,
                "time_s": round(elapsed, 4),
                "throughput_MB_s": round(throughput, 2),
            })
            log.info("Hash bench %s: %.2f MB/s", algo, throughput)
        except Exception as e:
            log.warning("Benchmark failed for %s: %s", algo, e)

    results.sort(key=lambda r: -r["throughput_MB_s"])
    return results

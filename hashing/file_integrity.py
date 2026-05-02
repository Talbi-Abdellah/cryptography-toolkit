"""File integrity checker — hash files, create manifests, verify."""
import hashlib
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from utils.logger import get_logger

log = get_logger("file_integrity")


class FileIntegrity:
    """Hash-based file integrity checking."""

    DEFAULT_ALGORITHM = "sha256"

    @staticmethod
    def hash_file(path: str, algorithm: str = "sha256") -> str:
        """
        Compute the hex digest of a file's contents.
        Uses streaming reads to handle large files without loading them fully.
        """
        algo = algorithm.lower().replace("-", "")
        if algo not in hashlib.algorithms_available:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        h = hashlib.new(algo)
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        digest = h.hexdigest()
        log.debug("file hash: %s %s=%s", path, algo, digest[:16])
        return digest

    @staticmethod
    def verify_file(path: str, expected_hash: str, algorithm: str = "sha256") -> bool:
        """Return True if the file's hash matches `expected_hash`."""
        actual = FileIntegrity.hash_file(path, algorithm)
        match = actual.lower() == expected_hash.lower()
        if match:
            log.info("Integrity OK: %s", path)
        else:
            log.warning("Integrity FAIL: %s (expected %s, got %s)", path, expected_hash[:16], actual[:16])
        return match

    @staticmethod
    def create_manifest(
        directory: str,
        algorithm: str = "sha256",
        extensions: Optional[List[str]] = None,
    ) -> Dict[str, str]:
        """
        Hash every file in `directory` (recursively).
        Returns a dict mapping relative path → hex digest.
        Optionally filter by file extensions (e.g. ['.py', '.txt']).
        """
        root = Path(directory)
        manifest: Dict[str, str] = {}

        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if extensions and path.suffix.lower() not in extensions:
                continue
            rel = str(path.relative_to(root))
            manifest[rel] = FileIntegrity.hash_file(str(path), algorithm)

        log.info("Manifest created: dir=%s files=%d algo=%s", directory, len(manifest), algorithm)
        return manifest

    @staticmethod
    def save_manifest(manifest: Dict[str, str], output_path: str, algorithm: str = "sha256") -> None:
        """Persist a manifest to JSON."""
        data = {"algorithm": algorithm, "files": manifest}
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        log.info("Manifest saved: %s (%d entries)", output_path, len(manifest))

    @staticmethod
    def load_manifest(path: str) -> Tuple[str, Dict[str, str]]:
        """Load a manifest JSON. Returns (algorithm, file_dict)."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data["algorithm"], data["files"]

    @staticmethod
    def verify_manifest(
        directory: str, manifest: Dict[str, str], algorithm: str = "sha256"
    ) -> Dict[str, str]:
        """
        Compare current directory state against a previously created manifest.
        Returns a dict of {relative_path: status} where status ∈:
            'OK'      — file matches
            'CHANGED' — hash differs
            'MISSING' — file was deleted
            'NEW'     — file not in manifest
        """
        root = Path(directory)
        results: Dict[str, str] = {}

        current_files = {
            str(p.relative_to(root)): str(p)
            for p in root.rglob("*") if p.is_file()
        }

        for rel_path, expected_hash in manifest.items():
            if rel_path not in current_files:
                results[rel_path] = "MISSING"
            else:
                actual = FileIntegrity.hash_file(current_files[rel_path], algorithm)
                results[rel_path] = "OK" if actual == expected_hash else "CHANGED"

        for rel_path in current_files:
            if rel_path not in manifest:
                results[rel_path] = "NEW"

        changed = sum(1 for s in results.values() if s != "OK")
        log.info("Manifest verify: total=%d issues=%d", len(results), changed)
        return results

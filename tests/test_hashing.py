"""Unit tests for hashing modules."""
import sys, os, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest
from hashing.hash_functions import HashFunctions
from hashing.file_integrity import FileIntegrity


class TestHashFunctions(unittest.TestCase):
    DATA = b"The quick brown fox jumps over the lazy dog"

    def test_md5_known_value(self):
        # Well-known MD5 of this string
        self.assertEqual(
            HashFunctions.md5(self.DATA),
            "9e107d9d372bb6826bd81d3542a419d6",
        )

    def test_sha256_known_value(self):
        self.assertEqual(
            HashFunctions.sha256(self.DATA),
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        )

    def test_sha512_length(self):
        h = HashFunctions.sha512(self.DATA)
        self.assertEqual(len(h), 128)  # 512 bits = 128 hex chars

    def test_unknown_algorithm_raises(self):
        with self.assertRaises(ValueError):
            HashFunctions.hexdigest(self.DATA, "md4_unknown")

    def test_avalanche_effect_near_50pct(self):
        result = HashFunctions.avalanche_effect(self.DATA * 5, "sha256", num_flips=50)
        avg = result["average_bit_change_pct"]
        # A good hash should change roughly 40–60% of bits per single input bit flip
        self.assertGreater(avg, 35.0)
        self.assertLess(avg, 65.0)

    def test_compare_all_returns_three(self):
        results = HashFunctions.compare_all(self.DATA)
        self.assertEqual(len(results), 3)
        algos = [r[0] for r in results]
        self.assertIn("md5", algos)
        self.assertIn("sha256", algos)
        self.assertIn("sha512", algos)

    def test_hamming_distance_same(self):
        b = b"test"
        self.assertEqual(HashFunctions.hamming_distance(b, b), 0)

    def test_hamming_distance_all_different(self):
        self.assertEqual(HashFunctions.hamming_distance(b"\x00", b"\xFF"), 8)


class TestFileIntegrity(unittest.TestCase):
    def _make_tmp(self, content: bytes = b"hello world") -> str:
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as f:
            f.write(content)
        return path

    def test_hash_file(self):
        import hashlib
        path = self._make_tmp(b"test content")
        expected = hashlib.sha256(b"test content").hexdigest()
        self.assertEqual(FileIntegrity.hash_file(path, "sha256"), expected)
        os.unlink(path)

    def test_verify_file_ok(self):
        path = self._make_tmp(b"verified content")
        import hashlib
        h = hashlib.sha256(b"verified content").hexdigest()
        self.assertTrue(FileIntegrity.verify_file(path, h))
        os.unlink(path)

    def test_verify_file_fail(self):
        path = self._make_tmp(b"original")
        self.assertFalse(FileIntegrity.verify_file(path, "0" * 64))
        os.unlink(path)

    def test_manifest_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a few files
            for i in range(3):
                with open(os.path.join(tmpdir, f"file{i}.txt"), "wb") as f:
                    f.write(f"content{i}".encode())

            manifest = FileIntegrity.create_manifest(tmpdir)
            self.assertEqual(len(manifest), 3)

            results = FileIntegrity.verify_manifest(tmpdir, manifest)
            self.assertTrue(all(s == "OK" for s in results.values()))

    def test_manifest_detects_change(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "file.txt")
            with open(path, "wb") as f:
                f.write(b"original")

            manifest = FileIntegrity.create_manifest(tmpdir)

            # Modify the file
            with open(path, "wb") as f:
                f.write(b"modified")

            results = FileIntegrity.verify_manifest(tmpdir, manifest)
            self.assertIn("CHANGED", results.values())

    def test_manifest_detects_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "file.txt")
            with open(path, "wb") as f:
                f.write(b"to be deleted")

            manifest = FileIntegrity.create_manifest(tmpdir)
            os.unlink(path)

            results = FileIntegrity.verify_manifest(tmpdir, manifest)
            self.assertIn("MISSING", results.values())


if __name__ == "__main__":
    unittest.main()

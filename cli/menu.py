"""Main CLI menu system for CryptoSuite Pro."""
import os
import sys

from utils.display import Display
from cli.helpers import (
    prompt, prompt_int, prompt_choice, prompt_bytes, prompt_key_bytes,
    prompt_file, confirm, show_result, show_bytes, pause,
)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. CLASSICAL CRYPTO
# ═══════════════════════════════════════════════════════════════════════════════

def menu_caesar() -> None:
    from classical.caesar import CaesarCipher
    options = ["Encrypt", "Decrypt", "Brute Force", "Frequency Analysis", "Index of Coincidence"]
    while True:
        Display.menu("Caesar Cipher", options)
        choice = prompt_choice(options)
        if choice == 0:
            return
        if choice == 1:
            text = prompt("Plaintext")
            shift = prompt_int("Shift (0-25)", 0, 25, 3)
            ct = CaesarCipher.encrypt(text, shift)
            show_result("Ciphertext", ct)
        elif choice == 2:
            text = prompt("Ciphertext")
            shift = prompt_int("Shift (0-25)", 0, 25, 3)
            pt = CaesarCipher.decrypt(text, shift)
            show_result("Plaintext", pt)
        elif choice == 3:
            text = prompt("Ciphertext")
            results = CaesarCipher.brute_force(text)
            Display.header("Brute Force Results (sorted by chi-squared score)")
            rows = [(s, f"{chi2:.4f}", pt[:60]) for s, chi2, pt in results[:10]]
            Display.table(["Shift", "Chi²", "Plaintext preview"], rows)
        elif choice == 4:
            text = prompt("Text")
            report = CaesarCipher.frequency_analysis_report(text)
            rows = [(ch.upper(), f"{obs:.4f}", f"{eng:.4f}") for ch, obs, eng in report[:10]]
            Display.table(["Letter", "Observed", "English"], rows, "Frequency Analysis")
        elif choice == 5:
            text = prompt("Text")
            ic = CaesarCipher.index_of_coincidence(text)
            show_result("IC", f"{ic:.4f}")
            show_result("English IC", "0.0667")
            show_result("Verdict", "Likely English" if abs(ic - 0.0667) < 0.01 else "Not typical English")
        pause()


def menu_vigenere() -> None:
    from classical.vigenere import VigenereCipher
    options = ["Encrypt", "Decrypt", "Kasiski Test", "IC Attack (auto-crack)"]
    while True:
        Display.menu("Vigenère Cipher", options)
        choice = prompt_choice(options)
        if choice == 0:
            return
        if choice == 1:
            text = prompt("Plaintext")
            key = prompt("Key (letters only)")
            ct = VigenereCipher.encrypt(text, key)
            show_result("Ciphertext", ct)
        elif choice == 2:
            text = prompt("Ciphertext")
            key = prompt("Key (letters only)")
            pt = VigenereCipher.decrypt(text, key)
            show_result("Plaintext", pt)
        elif choice == 3:
            text = prompt("Ciphertext")
            results = VigenereCipher.kasiski_test(text)[:8]
            rows = [(kl, cnt) for kl, cnt in results]
            Display.table(["Key Length Candidate", "Score"], rows, "Kasiski Test")
        elif choice == 4:
            text = prompt("Ciphertext")
            max_kl = prompt_int("Max key length to try", 2, 30, 20)
            Display.info("Running IC attack…")
            key, plain = VigenereCipher.crack(text, max_kl)
            show_result("Recovered Key", key)
            show_result("Decrypted Text", plain[:200])
        pause()


def menu_hill() -> None:
    from classical.hill import HillCipher
    options = ["Encrypt (2×2)", "Decrypt (2×2)", "Encrypt (3×3)", "Decrypt (3×3)", "Known-Plaintext Attack (2×2)"]
    while True:
        Display.menu("Hill Cipher", options)
        choice = prompt_choice(options)
        if choice == 0:
            return
        try:
            if choice in (1, 2):
                Display.info("Enter 2×2 key matrix (row by row, space-separated, values 0-25)")
                row0 = list(map(int, prompt("Row 0 (e.g. 3 3)").split()))
                row1 = list(map(int, prompt("Row 1 (e.g. 2 5)").split()))
                h = HillCipher([row0, row1])
                text = prompt("Text (letters only)")
                out = h.encrypt(text) if choice == 1 else h.decrypt(text)
                show_result("Output", out)
            elif choice in (3, 4):
                Display.info("Enter 3×3 key matrix (row by row)")
                rows = [list(map(int, prompt(f"Row {i}").split())) for i in range(3)]
                h = HillCipher(rows)
                text = prompt("Text")
                out = h.encrypt(text) if choice == 3 else h.decrypt(text)
                show_result("Output", out)
            elif choice == 5:
                Display.info("Known-Plaintext Attack — provide 2 plaintext/ciphertext pairs (2-letter blocks)")
                p1 = prompt("Plaintext block 1 (2 letters)")
                c1 = prompt("Ciphertext block 1 (2 letters)")
                p2 = prompt("Plaintext block 2 (2 letters)")
                c2 = prompt("Ciphertext block 2 (2 letters)")
                key = HillCipher.known_plaintext_attack([p1, p2], [c1, c2], n=2)
                if key:
                    show_result("Recovered key matrix", key)
                else:
                    Display.error("Attack failed — plaintext matrix is singular mod 26")
        except Exception as exc:
            Display.error(str(exc))
        pause()


def menu_otp() -> None:
    from classical.otp import OneTimePad
    options = ["Encrypt", "Decrypt", "Key-Reuse Attack Demo", "Crib Dragging"]
    while True:
        Display.menu("One-Time Pad", options)
        choice = prompt_choice(options)
        if choice == 0:
            return
        if choice == 1:
            text = prompt("Plaintext")
            data = text.encode()
            key = OneTimePad.generate_key(len(data))
            ct = OneTimePad.encrypt(data, key)
            show_bytes("Ciphertext", ct)
            show_bytes("Key (save this!)", key)
        elif choice == 2:
            ct_hex = prompt("Ciphertext (hex)")
            key_hex = prompt("Key (hex)")
            try:
                ct = bytes.fromhex(ct_hex)
                key = bytes.fromhex(key_hex)
                pt = OneTimePad.decrypt(ct, key)
                show_result("Plaintext", pt.decode(errors="replace"))
            except Exception as e:
                Display.error(str(e))
        elif choice == 3:
            Display.info("Demonstrating why key reuse destroys OTP security…")
            m1 = b"Attack at dawn, send reinforcements!"
            m2 = b"Retreat at night, no more supplies. "
            c1, c2, xor_ct, xor_pt = OneTimePad.key_reuse_attack_demo(m1, m2)
            show_result("Message 1", m1.decode())
            show_result("Message 2", m2.decode())
            show_bytes("C1 XOR C2", xor_ct)
            show_bytes("M1 XOR M2", xor_pt)
            show_result("Equal?", xor_ct == xor_pt)
            Display.warn("C1 XOR C2 = M1 XOR M2 — key is gone! Crib-drag to recover messages.")
        elif choice == 4:
            xor_hex = prompt("XOR of two ciphertexts (hex)")
            crib = prompt("Crib word to drag")
            try:
                xor_data = bytes.fromhex(xor_hex)
                results = OneTimePad.crib_drag(xor_data, crib)
                if results:
                    rows = [(off, frag.decode(errors="replace")) for off, frag in results[:15]]
                    Display.table(["Offset", "Fragment from other message"], rows)
                else:
                    Display.warn("No printable matches found")
            except Exception as e:
                Display.error(str(e))
        pause()


def menu_classical() -> None:
    options = ["Caesar Cipher", "Vigenère Cipher", "Hill Cipher", "One-Time Pad"]
    while True:
        Display.menu("Classical Cryptography", options)
        choice = prompt_choice(options)
        if choice == 0:
            return
        [menu_caesar, menu_vigenere, menu_hill, menu_otp][choice - 1]()


# ═══════════════════════════════════════════════════════════════════════════════
# 2. SYMMETRIC CRYPTO
# ═══════════════════════════════════════════════════════════════════════════════

def menu_rc4() -> None:
    from symmetric.rc4 import RC4Cipher
    options = ["Encrypt / Decrypt", "Bias Demo"]
    while True:
        Display.menu("RC4 Stream Cipher", options)
        choice = prompt_choice(options)
        if choice == 0:
            return
        if choice == 1:
            key = prompt_key_bytes("Key")
            text = prompt_bytes("Text")
            ct = RC4Cipher.encrypt(key, text)
            show_bytes("Output", ct)
            show_result("Keystream len", f"{len(ct)} bytes")
        elif choice == 2:
            Display.info("Running bias analysis (100 000 trials)…")
            result = RC4Cipher.bias_demo()
            Display.table(
                ["Metric", "Value"],
                [
                    ["Trials", result["trials"]],
                    ["Uniform P(byte=0)", f"{result['uniform_probability']:.4f}"],
                    ["Actual P(byte0=0)", f"{result['byte0_value0_probability']:.4f}"],
                    ["Bias ratio", f"{result['byte0_bias_ratio']:.2f}x"],
                    ["Top biased (byte 0)", str(result["top_biased_byte0"][:3])],
                ],
                "RC4 Byte-0 Bias",
            )
        pause()


def menu_des() -> None:
    from symmetric.des_cipher import DESCipher, TripleDESCipher
    options = ["DES-ECB Encrypt", "DES-ECB Decrypt", "DES-CBC Encrypt", "DES-CBC Decrypt",
               "3DES-CBC Encrypt", "3DES-CBC Decrypt"]
    while True:
        Display.menu("DES / 3DES", options)
        choice = prompt_choice(options)
        if choice == 0:
            return
        try:
            if choice in (1, 2, 3, 4):
                key = prompt_key_bytes("DES Key", required_sizes=[8])
                des = DESCipher(key)
                if choice == 1:
                    ct = des.encrypt_ecb(prompt_bytes("Plaintext"))
                    show_bytes("Ciphertext", ct)
                elif choice == 2:
                    ct = bytes.fromhex(prompt("Ciphertext (hex)"))
                    show_result("Plaintext", des.decrypt_ecb(ct).decode(errors="replace"))
                elif choice == 3:
                    iv, ct = des.encrypt_cbc(prompt_bytes("Plaintext"))
                    show_bytes("IV", iv)
                    show_bytes("Ciphertext", ct)
                elif choice == 4:
                    iv = bytes.fromhex(prompt("IV (hex)"))
                    ct = bytes.fromhex(prompt("Ciphertext (hex)"))
                    show_result("Plaintext", des.decrypt_cbc(ct, iv).decode(errors="replace"))
            elif choice in (5, 6):
                key = prompt_key_bytes("3DES Key", required_sizes=[16, 24])
                des3 = TripleDESCipher(key)
                if choice == 5:
                    iv, ct = des3.encrypt_cbc(prompt_bytes("Plaintext"))
                    show_bytes("IV", iv)
                    show_bytes("Ciphertext", ct)
                elif choice == 6:
                    iv = bytes.fromhex(prompt("IV (hex)"))
                    ct = bytes.fromhex(prompt("Ciphertext (hex)"))
                    show_result("Plaintext", des3.decrypt_cbc(ct, iv).decode(errors="replace"))
        except Exception as e:
            Display.error(str(e))
        pause()


def menu_aes() -> None:
    from symmetric.aes_cipher import AESCipher
    options = ["AES-CBC Encrypt", "AES-CBC Decrypt", "AES-CTR Encrypt", "AES-CTR Decrypt",
               "Nonce-Reuse Attack Demo", "Key-Size Benchmark"]
    while True:
        Display.menu("AES Cipher", options)
        choice = prompt_choice(options)
        if choice == 0:
            return
        try:
            if choice == 1:
                key = prompt_key_bytes("AES Key", required_sizes=[16, 24, 32])
                iv, ct = AESCipher(key).encrypt_cbc(prompt_bytes("Plaintext"))
                show_bytes("IV", iv); show_bytes("Ciphertext", ct)
            elif choice == 2:
                key = prompt_key_bytes("AES Key", required_sizes=[16, 24, 32])
                iv = bytes.fromhex(prompt("IV (hex)"))
                ct = bytes.fromhex(prompt("Ciphertext (hex)"))
                pt = AESCipher(key).decrypt_cbc(ct, iv)
                show_result("Plaintext", pt.decode(errors="replace"))
            elif choice == 3:
                key = prompt_key_bytes("AES Key", required_sizes=[16, 24, 32])
                nonce, ct = AESCipher(key).encrypt_ctr(prompt_bytes("Plaintext"))
                show_bytes("Nonce", nonce); show_bytes("Ciphertext", ct)
            elif choice == 4:
                key = prompt_key_bytes("AES Key", required_sizes=[16, 24, 32])
                nonce = bytes.fromhex(prompt("Nonce (hex, 8 bytes)"))
                ct = bytes.fromhex(prompt("Ciphertext (hex)"))
                pt = AESCipher(key).decrypt_ctr(ct, nonce)
                show_result("Plaintext", pt.decode(errors="replace"))
            elif choice == 5:
                result = AESCipher.nonce_reuse_attack_demo()
                Display.table(
                    ["Field", "Value"],
                    [(k, str(v)[:80]) for k, v in result.items()],
                    "AES-CTR Nonce Reuse Attack",
                )
            elif choice == 6:
                size = float(prompt("Data size in MB", "10"))
                Display.info(f"Benchmarking AES variants on {size} MB…")
                results = AESCipher.benchmark_key_sizes(size)
                Display.table(
                    ["Variant", "Key Bytes", "Time (s)", "Throughput (MB/s)"],
                    [(r["variant"], r["key_bytes"], r["time_s"], r["throughput_MB_s"]) for r in results],
                )
        except Exception as e:
            Display.error(str(e))
        pause()


def menu_sym_bench() -> None:
    from symmetric.benchmark import benchmark_symmetric
    size = float(prompt("Data size in MB", "5"))
    Display.info(f"Benchmarking symmetric ciphers on {size} MB…")
    results = benchmark_symmetric(size)
    Display.table(
        ["Cipher", "Key bits", "Mode", "Time (s)", "MB/s"],
        [(r["cipher"], r["key_bits"], r["mode"], r["time_s"], r["throughput_MB_s"]) for r in results],
        "Symmetric Cipher Benchmark",
    )
    pause()


def menu_symmetric() -> None:
    options = ["RC4 Stream Cipher", "DES / 3DES", "AES Cipher", "Benchmark All"]
    while True:
        Display.menu("Symmetric Cryptography", options)
        choice = prompt_choice(options)
        if choice == 0:
            return
        [menu_rc4, menu_des, menu_aes, menu_sym_bench][choice - 1]()


# ═══════════════════════════════════════════════════════════════════════════════
# 3. ASYMMETRIC CRYPTO
# ═══════════════════════════════════════════════════════════════════════════════

def menu_dh() -> None:
    from asymmetric.diffie_hellman import DiffieHellman
    options = ["Key Exchange Demo", "MITM Attack Demo"]
    while True:
        Display.menu("Diffie-Hellman", options)
        choice = prompt_choice(options)
        if choice == 0:
            return
        bits = prompt_int("Prime size (bits)", 256, 4096, 512)
        Display.info(f"Using {bits}-bit prime…")
        try:
            if choice == 1:
                r = DiffieHellman.key_exchange_demo(bits)
            else:
                r = DiffieHellman.mitm_attack_demo(bits)
            Display.table(["Field", "Value"],
                          [(k, str(v)[:80]) for k, v in r.items()])
        except Exception as e:
            Display.error(str(e))
        pause()


def menu_rsa() -> None:
    from asymmetric.rsa_cipher import RSACipher
    options = ["Generate Keypair", "Encrypt (textbook)", "Decrypt (textbook)",
               "Hybrid Encrypt (RSA+AES)", "Hybrid Decrypt"]
    _state: dict = {}
    while True:
        Display.menu("RSA Cipher", options)
        choice = prompt_choice(options)
        if choice == 0:
            return
        try:
            if choice == 1:
                bits = prompt_int("Key size (bits)", 512, 4096, 2048)
                Display.info(f"Generating {bits}-bit RSA keypair…")
                priv = RSACipher.generate_keypair(bits)
                _state["priv"] = priv
                show_result("Modulus bits", priv.n.bit_length())
                show_result("Public exponent e", priv.e)
                Display.success("Keypair stored in session memory")
            elif choice == 2:
                if "priv" not in _state:
                    Display.error("Generate a keypair first"); continue
                msg_int = int(prompt("Message as integer"))
                ct = RSACipher.encrypt_textbook(msg_int, _state["priv"].public_key)
                show_result("Ciphertext", str(ct)[:80])
                _state["last_ct_int"] = ct
            elif choice == 3:
                if "priv" not in _state:
                    Display.error("Generate a keypair first"); continue
                ct_int = int(prompt("Ciphertext integer"))
                pt = RSACipher.decrypt_textbook(ct_int, _state["priv"])
                show_result("Plaintext", pt)
            elif choice == 4:
                if "priv" not in _state:
                    Display.error("Generate a keypair first"); continue
                msg = prompt_bytes("Plaintext")
                enc_key, iv, ct = RSACipher.hybrid_encrypt(msg, _state["priv"].public_key)
                show_bytes("Encrypted AES key", enc_key)
                show_bytes("IV", iv)
                show_bytes("Ciphertext", ct)
                _state.update({"enc_key": enc_key, "iv": iv, "ct": ct})
                Display.success("Stored in session for decryption")
            elif choice == 5:
                if not all(k in _state for k in ("priv", "enc_key", "iv", "ct")):
                    Display.error("Perform Hybrid Encrypt first"); continue
                pt = RSACipher.hybrid_decrypt(
                    _state["enc_key"], _state["iv"], _state["ct"], _state["priv"]
                )
                show_result("Plaintext", pt.decode(errors="replace"))
        except Exception as e:
            Display.error(str(e))
        pause()


def menu_elgamal() -> None:
    from asymmetric.elgamal import ElGamal
    options = ["Generate Keypair", "Encrypt", "Decrypt", "Malleability Demo"]
    _state: dict = {}
    while True:
        Display.menu("ElGamal Encryption", options)
        choice = prompt_choice(options)
        if choice == 0:
            return
        try:
            if choice == 1:
                bits = prompt_int("Prime size (bits)", 256, 2048, 512)
                Display.info("Generating keypair…")
                priv = ElGamal.generate_keypair(bits)
                _state["priv"] = priv
                pub = priv.public_key
                show_result("p bits", pub.p.bit_length())
                Display.success("Keypair stored")
            elif choice == 2:
                if "priv" not in _state:
                    Display.error("Generate keypair first"); continue
                msg_int = int(prompt("Message as integer"))
                c1, c2 = ElGamal.encrypt(msg_int, _state["priv"].public_key)
                show_result("c1", str(c1)[:80])
                show_result("c2", str(c2)[:80])
                _state.update({"c1": c1, "c2": c2})
            elif choice == 3:
                if "priv" not in _state:
                    Display.error("Generate keypair first"); continue
                c1 = int(prompt("c1"))
                c2 = int(prompt("c2"))
                m = ElGamal.decrypt(c1, c2, _state["priv"])
                show_result("Plaintext", m)
            elif choice == 4:
                bits = prompt_int("Prime size (bits)", 128, 512, 256)
                Display.info("Running malleability demo…")
                r = ElGamal.malleability_demo(bits)
                Display.table(["Field", "Value"], [(k, str(v)[:80]) for k, v in r.items()])
        except Exception as e:
            Display.error(str(e))
        pause()


def menu_ecc() -> None:
    from asymmetric.ecc import ECDH, ECIES, SECP256K1, DEMO_CURVE
    options = ["ECDH Key Exchange Demo (secp256k1)", "ECIES Encrypt/Decrypt", "Demo Curve Point Operations"]
    while True:
        Display.menu("Elliptic Curve Cryptography", options)
        choice = prompt_choice(options)
        if choice == 0:
            return
        try:
            if choice == 1:
                Display.info("Running ECDH on secp256k1…")
                r = ECDH(SECP256K1).key_exchange_demo()
                Display.table(["Field", "Value"],
                              [(k, str(v)[:80]) for k, v in r.items()])
            elif choice == 2:
                ecies = ECIES(SECP256K1)
                priv, pub = ECDH(SECP256K1).generate_keypair()
                msg = prompt_bytes("Plaintext to encrypt")
                Display.info("Encrypting with ECIES…")
                r_pub, iv, ct = ecies.encrypt(msg, pub)
                Display.success(f"Encrypted: {len(ct)} bytes")
                pt = ecies.decrypt(r_pub, iv, ct, priv)
                show_result("Decrypted", pt.decode(errors="replace"))
                show_result("Round-trip OK", pt == msg)
            elif choice == 3:
                Display.info("Demo curve: y² = x³ + 2x + 3 over F(97)")
                curve = DEMO_CURVE
                G = curve.G
                show_result("Generator G", f"({G.x}, {G.y})")
                for k in range(1, 6):
                    P = curve.multiply(G, k)
                    show_result(f"{k}G", f"({P.x}, {P.y})" if not P.is_infinity else "∞")
        except Exception as e:
            Display.error(str(e))
        pause()


def menu_asymmetric() -> None:
    options = ["Diffie-Hellman", "RSA Cipher", "ElGamal", "Elliptic Curve Crypto"]
    while True:
        Display.menu("Asymmetric Cryptography", options)
        choice = prompt_choice(options)
        if choice == 0:
            return
        [menu_dh, menu_rsa, menu_elgamal, menu_ecc][choice - 1]()


# ═══════════════════════════════════════════════════════════════════════════════
# 4. HASHING
# ═══════════════════════════════════════════════════════════════════════════════

def menu_hashing() -> None:
    from hashing.hash_functions import HashFunctions
    from hashing.file_integrity import FileIntegrity
    from hashing.benchmark import benchmark_hashing

    options = ["Hash Text", "Hash File", "Avalanche Effect Demo",
               "Compare Algorithms", "File Integrity Checker", "Benchmark"]
    while True:
        Display.menu("Hashing", options)
        choice = prompt_choice(options)
        if choice == 0:
            return
        try:
            if choice == 1:
                text = prompt_bytes("Text")
                algo = prompt("Algorithm [md5/sha256/sha512]", "sha256")
                show_result(algo.upper(), HashFunctions.hexdigest(text, algo))
            elif choice == 2:
                path = prompt_file("File path")
                algo = prompt("Algorithm", "sha256")
                show_result(algo.upper(), FileIntegrity.hash_file(path, algo))
            elif choice == 3:
                text = prompt_bytes("Text")
                algo = prompt("Algorithm", "sha256")
                n = prompt_int("Number of bit-flips to test", 4, 256, 32)
                r = HashFunctions.avalanche_effect(text, algo, n)
                Display.table(["Metric", "Value"],
                              [(k, str(v)) for k, v in r.items()], "Avalanche Effect")
            elif choice == 4:
                text = prompt_bytes("Text")
                rows = [(a, h[:40] + "…", f"{b} bits")
                        for a, h, b in HashFunctions.compare_all(text)]
                Display.table(["Algorithm", "Digest (truncated)", "Size"], rows)
            elif choice == 5:
                path = prompt_file("File path")
                expected = prompt("Expected hash (hex)")
                algo = prompt("Algorithm", "sha256")
                ok = FileIntegrity.verify_file(path, expected, algo)
                (Display.success if ok else Display.error)(
                    "File integrity: " + ("PASS ✔" if ok else "FAIL ✖")
                )
            elif choice == 6:
                size = float(prompt("Data size in MB", "50"))
                Display.info(f"Benchmarking hash algorithms on {size} MB…")
                results = benchmark_hashing(size)
                Display.table(
                    ["Algorithm", "Digest bits", "Time (s)", "MB/s"],
                    [(r["algorithm"], r["digest_bits"], r["time_s"], r["throughput_MB_s"])
                     for r in results],
                )
        except Exception as e:
            Display.error(str(e))
        pause()


# ═══════════════════════════════════════════════════════════════════════════════
# 5. DIGITAL SIGNATURES
# ═══════════════════════════════════════════════════════════════════════════════

def menu_signatures() -> None:
    from signatures.rsa_signature import RSASigner
    from signatures.elgamal_signature import ElGamalSigner
    from signatures.dsa_ecdsa import DSASigner, ECDSASigner
    from signatures.verify import AuthenticityVerifier, DocumentSigner, SigAlgorithm, SignedDocument

    options = ["RSA-PSS Sign & Verify", "ElGamal Sign & Verify",
               "DSA Sign & Verify", "ECDSA Sign & Verify",
               "ElGamal Nonce-Reuse Attack Demo", "Authenticity Verifier Demo"]
    _state: dict = {}

    while True:
        Display.menu("Digital Signatures", options)
        choice = prompt_choice(options)
        if choice == 0:
            return
        try:
            if choice == 1:
                bits = prompt_int("RSA key size", 512, 4096, 2048)
                Display.info(f"Generating {bits}-bit RSA keypair…")
                signer = RSASigner(bits)
                msg = prompt_bytes("Message to sign")
                sig = signer.sign(msg)
                show_bytes("Signature", sig)
                ok = signer.verify(msg, sig)
                (Display.success if ok else Display.error)("Verification: " + ("PASS" if ok else "FAIL"))
                # Tamper test
                tampered = msg + b"X"
                bad = signer.verify(tampered, sig)
                Display.info(f"Tampered message verify: {'PASS (unexpected!)' if bad else 'FAIL (expected)'}")

            elif choice == 2:
                bits = prompt_int("Prime size (bits)", 256, 1024, 512)
                Display.info("Generating ElGamal keypair…")
                import pickle
                priv = ElGamalSigner.generate_keypair(bits)
                pub = priv.public_key
                msg = prompt_bytes("Message")
                r, s = ElGamalSigner.sign(msg, priv)
                show_result("r", str(r)[:60])
                show_result("s", str(s)[:60])
                ok = ElGamalSigner.verify(msg, r, s, pub)
                (Display.success if ok else Display.error)("Verification: " + ("PASS" if ok else "FAIL"))

            elif choice == 3:
                Display.info("Generating DSA keypair…")
                signer = DSASigner(2048)
                msg = prompt_bytes("Message")
                sig = signer.sign(msg)
                show_bytes("Signature", sig)
                ok = signer.verify(msg, sig)
                (Display.success if ok else Display.error)("Verification: " + ("PASS" if ok else "FAIL"))

            elif choice == 4:
                curves = ["p256", "p384", "p521", "secp256k1"]
                Display.info("Curves: " + ", ".join(curves))
                curve = prompt("Curve", "p256")
                signer = ECDSASigner(curve)
                msg = prompt_bytes("Message")
                sig = signer.sign(msg)
                show_bytes("Signature", sig)
                ok = signer.verify(msg, sig)
                (Display.success if ok else Display.error)("Verification: " + ("PASS" if ok else "FAIL"))

            elif choice == 5:
                bits = prompt_int("Prime size (bits)", 128, 512, 256)
                Display.info("Running nonce-reuse attack demo…")
                r = ElGamalSigner.nonce_reuse_attack_demo(bits)
                Display.table(["Field", "Value"], [(k, str(v)[:80]) for k, v in r.items()])

            elif choice == 6:
                ds = DocumentSigner()
                msg = prompt_bytes("Document content")
                Display.info("Signing with RSA-PSS and ECDSA…")
                rsa_doc, _ = ds.sign_rsa(msg, "Alice")
                ecdsa_doc, _ = ds.sign_ecdsa(msg, "Bob")
                verifier = AuthenticityVerifier()
                for doc in [rsa_doc, ecdsa_doc]:
                    ok = verifier.verify(doc)
                    (Display.success if ok else Display.error)(
                        f"{doc.algorithm.value} — signer '{doc.signer_id}': {'AUTHENTIC' if ok else 'INVALID'}"
                    )
        except Exception as e:
            Display.error(str(e))
        pause()


# ═══════════════════════════════════════════════════════════════════════════════
# 6. SECURE APP
# ═══════════════════════════════════════════════════════════════════════════════

def menu_secure_app() -> None:
    options = ["Start Server (background thread)", "Connect Client & Send Message",
               "Protocol Spec Info"]
    _state: dict = {}
    while True:
        Display.menu("Secure Communication", options)
        choice = prompt_choice(options)
        if choice == 0:
            return
        try:
            if choice == 1:
                import threading
                from secure_app.server import SecureServer
                host = prompt("Host", "127.0.0.1")
                port = prompt_int("Port", 1024, 65535, 9999)
                Display.info("Generating RSA keypair for server (2048-bit)…")
                srv = SecureServer(host, port, rsa_bits=2048)
                t = threading.Thread(target=srv.serve_forever, daemon=True)
                t.start()
                Display.success(f"Server started on {host}:{port} (background thread)")
                _state["server"] = srv
            elif choice == 2:
                from secure_app.client import SecureClient
                host = prompt("Server host", "127.0.0.1")
                port = prompt_int("Server port", 1024, 65535, 9999)
                client = SecureClient()
                Display.info(f"Connecting to {host}:{port}…")
                client.connect(host, port)
                Display.success("Handshake complete — channel is secure")
                msg = prompt_bytes("Message to send")
                client.send(msg)
                reply = client.recv()
                show_result("Server reply", reply.decode(errors="replace"))
                client.close()
            elif choice == 3:
                Display.header("Secure Protocol Specification")
                Display.info("Wire format: MAGIC(5) | VERSION(1) | TYPE(1) | LENGTH(4) | PAYLOAD(N)")
                Display.info("Key exchange: RSA-OAEP (2048-bit) wraps AES-256 session key")
                Display.info("Data channel: AES-256-CBC with fresh IV per message")
                Display.info("Message types: HELLO, KEY_EXCHANGE, HANDSHAKE_DONE, DATA, CHAT, ERROR")
        except Exception as e:
            Display.error(str(e))
        pause()


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN MENU
# ═══════════════════════════════════════════════════════════════════════════════

class MainMenu:
    """Top-level CLI controller."""

    OPTIONS = [
        "Classical Cryptography",
        "Symmetric Cryptography",
        "Asymmetric Cryptography",
        "Hashing",
        "Digital Signatures",
        "Secure Communication App",
    ]

    HANDLERS = [
        menu_classical,
        menu_symmetric,
        menu_asymmetric,
        menu_hashing,
        menu_signatures,
        menu_secure_app,
    ]

    def run(self) -> None:
        Display.banner()
        while True:
            Display.menu("Main Menu", self.OPTIONS, back_label="Exit")
            choice = prompt_choice(self.OPTIONS)
            if choice == 0:
                Display.info("Goodbye!")
                sys.exit(0)
            try:
                self.HANDLERS[choice - 1]()
            except KeyboardInterrupt:
                print()  # newline after ^C

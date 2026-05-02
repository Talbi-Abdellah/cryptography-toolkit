"""CryptoSuite — Classical + Symmetric Cryptography CLI."""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from colorama import Fore, Style, init as colorama_init
from tabulate import tabulate
from utils.logger import get_logger

from classical import caesar, vigenere, hill, otp
from symmetric import rc4, aes_cipher
from symmetric.benchmark import benchmark_symmetric
from asymmetric import diffie_hellman, ecc, elgamal, rsa
from hashing import FileIntegrity, HashFunctions, benchmark_hashing
from signatures import RSASigner, ECDSASigner
from secure_app import SecureClient, SecureServer

colorama_init(autoreset=True)
log = get_logger("main")


# ── Display helpers ────────────────────────────────────────────────────────────

def clear():
    os.system("cls" if os.name == "nt" else "clear")


def header(title: str) -> None:
    print(f"\n{'=' * 50}")
    print(f"  {title}")
    print(f"{'=' * 50}")


def show(label: str, value) -> None:
    print(f"  {label:<20}: {value}")


def print_error(message: str) -> None:
    print(Fore.RED + f"  Error: {message}" + Style.RESET_ALL)


def _preview_hex(value: int, limit: int = 64) -> str:
    text = hex(value)[2:]
    return text if len(text) <= limit else text[:limit] + "..."


def _preview_bytes(data: bytes, limit: int = 80) -> str:
    text = data.hex()
    return text if len(text) <= limit else text[:limit] + "..."


def ask(prompt: str) -> str:
    return input(f"  {prompt}: ").strip()


def pause() -> None:
    input("\n  Press Enter to continue...")


# ── Caesar menu ───────────────────────────────────────────────────────────────

def menu_caesar() -> None:
    while True:
        header("Caesar Cipher")
        print("  [1] Encrypt")
        print("  [2] Decrypt")
        print("  [3] Brute Force")
        print("  [0] Back")

        choice = ask("Choice")

        if choice == "0":
            return

        elif choice == "1":
            text = ask("Plaintext")
            shift = int(ask("Shift (0-25)"))
            result = caesar.encrypt(text, shift)
            show("Ciphertext", result)

        elif choice == "2":
            text = ask("Ciphertext")
            shift = int(ask("Shift (0-25)"))
            result = caesar.decrypt(text, shift)
            show("Plaintext", result)

        elif choice == "3":
            text = ask("Ciphertext")
            results = caesar.brute_force(text)
            print("\n  Top 5 most likely decryptions:")
            print(f"  {'Shift':<8} {'Plaintext'}")
            print("  " + "-" * 45)
            for shift, plaintext in results[:5]:
                print(f"  {shift:<8} {plaintext[:40]}")

        pause()


# ── Vigenère menu ─────────────────────────────────────────────────────────────

def menu_vigenere() -> None:
    while True:
        header("Vigenere Cipher")
        print("  [1] Encrypt")
        print("  [2] Decrypt")
        print("  [0] Back")

        choice = ask("Choice")

        if choice == "0":
            return

        elif choice == "1":
            text = ask("Plaintext")
            key = ask("Key (letters only)")
            try:
                result = vigenere.encrypt(text, key)
                show("Ciphertext", result)
            except ValueError as e:
                print(f"  Error: {e}")

        elif choice == "2":
            text = ask("Ciphertext")
            key = ask("Key (letters only)")
            try:
                result = vigenere.decrypt(text, key)
                show("Plaintext", result)
            except ValueError as e:
                print(f"  Error: {e}")

        pause()


# ── Hill menu ─────────────────────────────────────────────────────────────────

def _read_key_matrix() -> list[list[int]] | None:
    """Prompt the user for a 2x2 key matrix. Returns None on bad input."""
    print("  Enter the 2x2 key matrix (values 0-25).")
    try:
        row0 = list(map(int, ask("Row 0 — two numbers (e.g. 3 3)").split()))
        row1 = list(map(int, ask("Row 1 — two numbers (e.g. 2 5)").split()))
        if len(row0) != 2 or len(row1) != 2:
            print("  Error: each row must have exactly 2 numbers.")
            return None
        matrix = [row0, row1]
        hill.validate_key(matrix)
        return matrix
    except ValueError as e:
        print(f"  Error: {e}")
        return None


def menu_hill() -> None:
    while True:
        header("Hill Cipher (2x2)")
        print("  [1] Encrypt")
        print("  [2] Decrypt")
        print("  [0] Back")

        choice = ask("Choice")

        if choice == "0":
            return

        elif choice in ("1", "2"):
            matrix = _read_key_matrix()
            if matrix is None:
                pause()
                continue

            text = ask("Text (letters only)")

            if choice == "1":
                result = hill.encrypt(text, matrix)
                show("Ciphertext", result)
            else:
                result = hill.decrypt(text, matrix)
                show("Plaintext", result)

        pause()


# ── OTP menu ──────────────────────────────────────────────────────────────────

def menu_otp() -> None:
    while True:
        header("One-Time Pad")
        print("  [1] Encrypt (generate key automatically)")
        print("  [2] Decrypt")
        print("  [0] Back")

        choice = ask("Choice")

        if choice == "0":
            return

        elif choice == "1":
            text = ask("Plaintext (text)")
            data = text.encode()
            key = otp.generate_key(len(data))
            ciphertext = otp.encrypt(data, key)
            show("Ciphertext (hex)", ciphertext.hex())
            show("Key (hex)", key.hex())
            print("\n  ** Save the key — you need it to decrypt! **")

        elif choice == "2":
            try:
                ct_hex = ask("Ciphertext (hex)")
                key_hex = ask("Key (hex)")
                ciphertext = bytes.fromhex(ct_hex)
                key = bytes.fromhex(key_hex)
                plaintext = otp.decrypt(ciphertext, key)
                show("Plaintext", plaintext.decode(errors="replace"))
            except ValueError as e:
                print(f"  Error: {e}")

        pause()


# ── Classical sub-menu ────────────────────────────────────────────────────────

def menu_classical() -> None:
    while True:
        header("Classical Cryptography")
        print("  [1] Caesar Cipher")
        print("  [2] Vigenere Cipher")
        print("  [3] Hill Cipher (2x2)")
        print("  [4] One-Time Pad (OTP)")
        print("  [0] Back")

        choice = ask("Choice")

        if choice == "0":
            return
        elif choice == "1":
            menu_caesar()
        elif choice == "2":
            menu_vigenere()
        elif choice == "3":
            menu_hill()
        elif choice == "4":
            menu_otp()


# ── RC4 menu ──────────────────────────────────────────────────────────────────

def menu_rc4() -> None:
    while True:
        header("RC4 Stream Cipher")
        print("  [1] Encrypt")
        print("  [2] Decrypt")
        print("  [0] Back")

        choice = ask("Choice")

        if choice == "0":
            return

        elif choice in ("1", "2"):
            try:
                key_input = ask("Key (text or hex with 0x prefix)")
                if key_input.startswith("0x"):
                    key = bytes.fromhex(key_input[2:])
                else:
                    key = key_input.encode()

                if choice == "1":
                    text = ask("Plaintext (text)")
                    data = text.encode()
                    ciphertext = rc4.encrypt(key, data)
                    show("Ciphertext (hex)", ciphertext.hex())
                    show("Key (hex)", key.hex())
                else:
                    ct_hex = ask("Ciphertext (hex)")
                    ciphertext = bytes.fromhex(ct_hex)
                    plaintext = rc4.decrypt(key, ciphertext)
                    show("Plaintext", plaintext.decode(errors="replace"))

            except ValueError as e:
                print(f"  Error: {e}")

        pause()


# ── AES menu ──────────────────────────────────────────────────────────────────

def _read_aes_key() -> bytes | None:
    """Prompt for an AES key (text or hex). Returns None on bad input."""
    raw = ask("Key (text or hex with 0x prefix)")
    try:
        key = bytes.fromhex(raw[2:]) if raw.startswith("0x") else raw.encode()
        # Pad or truncate to nearest valid AES key size
        if len(key) <= 16:
            key = key.ljust(16, b'\x00')
        elif len(key) <= 24:
            key = key.ljust(24, b'\x00')
        else:
            key = key.ljust(32, b'\x00')[:32]
        show("Key used (hex)", key.hex())
        show("Key size", f"{len(key) * 8} bits (AES-{len(key) * 8})")
        return key
    except ValueError as e:
        print(f"  Error: {e}")
        return None


def menu_aes() -> None:
    while True:
        header("AES Cipher")
        print("  [1] ECB — Encrypt")
        print("  [2] ECB — Decrypt")
        print("  [3] CBC — Encrypt")
        print("  [4] CBC — Decrypt")
        print("  [0] Back")

        choice = ask("Choice")

        if choice == "0":
            return

        try:
            if choice == "1":
                key = _read_aes_key()
                if key is None:
                    pause()
                    continue
                text = ask("Plaintext (text)")
                ct = aes_cipher.encrypt_ecb(key, text.encode())
                show("Ciphertext (hex)", ct.hex())

            elif choice == "2":
                key = _read_aes_key()
                if key is None:
                    pause()
                    continue
                ct_hex = ask("Ciphertext (hex)")
                pt = aes_cipher.decrypt_ecb(key, bytes.fromhex(ct_hex))
                show("Plaintext", pt.decode(errors="replace"))

            elif choice == "3":
                key = _read_aes_key()
                if key is None:
                    pause()
                    continue
                text = ask("Plaintext (text)")
                iv, ct = aes_cipher.encrypt_cbc(key, text.encode())
                show("IV (hex)", iv.hex())
                show("Ciphertext (hex)", ct.hex())

            elif choice == "4":
                key = _read_aes_key()
                if key is None:
                    pause()
                    continue
                iv_hex = ask("IV (hex)")
                ct_hex = ask("Ciphertext (hex)")
                pt = aes_cipher.decrypt_cbc(key, bytes.fromhex(ct_hex), bytes.fromhex(iv_hex))
                show("Plaintext", pt.decode(errors="replace"))

        except (ValueError, KeyError) as e:
            print(f"  Error: {e}")

        pause()


def menu_symmetric() -> None:
    while True:
        header("Symmetric Cryptography")
        print("  [1] RC4")
        print("  [2] AES")
        print("  [0] Back")

        choice = ask("Choice")

        if choice == "0":
            return
        elif choice == "1":
            menu_rc4()
        elif choice == "2":
            menu_aes()


def menu_hashing() -> None:
    while True:
        header("Hashing")
        print("  [1] Compare MD5 / SHA-256 / SHA-512")
        print("  [2] Avalanche effect")
        print("  [3] File integrity checker")
        print("  [4] Benchmark hash speed")
        print("  [0] Back")

        choice = ask("Choice")

        if choice == "0":
            return

        elif choice == "1":
            text = ask("Input text")
            data = text.encode("utf-8")
            results = HashFunctions.compare_all(data)
            for name, digest, bits in results:
                show(f"{name.upper()} ({bits} bits)", digest)

        elif choice == "2":
            algorithm = ask("Algorithm (md5 / sha256 / sha512)") or "sha256"
            algorithm = algorithm.lower().replace("-", "")
            if algorithm not in {"md5", "sha256", "sha512"}:
                print_error("Invalid algorithm.")
                pause()
                continue
            text = ask("Text to test")
            data = text.encode("utf-8")
            result = HashFunctions.avalanche_effect(data, algorithm, num_flips=20)
            show("Algorithm", result["algorithm"])
            show("Input preview", result["data_preview"])
            show("Original hash", result["original_hash"])
            show("Average bit change", f"{result['average_bit_change_pct']} %")
            show("Min bit change", f"{result['min_bit_change_pct']} %")
            show("Max bit change", f"{result['max_bit_change_pct']} %")
            show("Ideal", f"{result['ideal_pct']} %")

        elif choice == "3":
            while True:
                header("File Integrity Checker")
                print("  [1] Compute file hash")
                print("  [2] Verify file hash")
                print("  [0] Back")
                sub = ask("Choice")
                if sub == "0":
                    break
                if sub == "1":
                    path = ask("File path")
                    algorithm = ask("Algorithm (md5 / sha256 / sha512, default sha256)") or "sha256"
                    try:
                        digest = FileIntegrity.hash_file(path, algorithm)
                        show("File hash", digest)
                    except Exception as exc:
                        print_error(str(exc))
                elif sub == "2":
                    path = ask("File path")
                    expected = ask("Expected hash")
                    algorithm = ask("Algorithm (md5 / sha256 / sha512, default sha256)") or "sha256"
                    try:
                        valid = FileIntegrity.verify_file(path, expected, algorithm)
                        show("Match", valid)
                    except Exception as exc:
                        print_error(str(exc))
                else:
                    print("  Invalid choice.")
                pause()

        elif choice == "4":
            size_input = ask("Benchmark size in MB (default 10)")
            try:
                size_mb = float(size_input) if size_input else 10.0
            except ValueError:
                size_mb = 10.0

            print("\n  Running hashing benchmark...")
            results = benchmark_hashing(size_mb)
            if results:
                rows = [
                    [row["algorithm"], row["digest_bits"], row["data_MB"], row["time_s"], row["throughput_MB_s"]]
                    for row in results
                ]
                print(tabulate(rows, headers=["Algorithm", "Bits", "Size MB", "Time s", "MB/s"], tablefmt="grid"))
            else:
                print_error("No benchmark results available.")

        else:
            print_error("Invalid choice.")

        pause()


def menu_benchmarks() -> None:
    while True:
        header("Performance Benchmarks")
        print("  [1] Symmetric cipher benchmark")
        print("  [2] Hash algorithm benchmark")
        print("  [0] Back")

        choice = ask("Choice")

        if choice == "0":
            return

        elif choice == "1":
            size_input = ask("Benchmark size in MB (default 5)")
            try:
                size_mb = float(size_input) if size_input else 5.0
            except ValueError:
                size_mb = 5.0

            print("\n  Running symmetric cipher benchmark...")
            results = benchmark_symmetric(size_mb)
            if results:
                rows = [
                    [row["cipher"], row["key_bits"], row["mode"], row["data_MB"], row["time_s"], row["throughput_MB_s"]]
                    for row in results
                ]
                print(tabulate(rows, headers=["Cipher", "Key bits", "Mode", "Size MB", "Time s", "MB/s"], tablefmt="grid"))
            else:
                print_error("No benchmark results available.")

        elif choice == "2":
            size_input = ask("Benchmark size in MB (default 10)")
            try:
                size_mb = float(size_input) if size_input else 10.0
            except ValueError:
                size_mb = 10.0

            print("\n  Running hashing benchmark...")
            results = benchmark_hashing(size_mb)
            if results:
                rows = [
                    [row["algorithm"], row["digest_bits"], row["data_MB"], row["time_s"], row["throughput_MB_s"]]
                    for row in results
                ]
                print(tabulate(rows, headers=["Algorithm", "Bits", "Size MB", "Time s", "MB/s"], tablefmt="grid"))
            else:
                print_error("No benchmark results available.")

        else:
            print_error("Invalid choice.")

        pause()


def menu_signatures() -> None:
    while True:
        header("Digital Signatures")
        print("  [1] RSA signature")
        print("  [2] ECDSA signature")
        print("  [0] Back")

        choice = ask("Choice")

        if choice == "0":
            return

        elif choice == "1":
            bits_input = ask("RSA key size in bits (1024 or 2048, default 2048)")
            bits = int(bits_input) if bits_input else 2048
            print("\n  Generating RSA signing key...")
            signer = RSASigner(bits)
            message = ask("Message to sign").encode("utf-8")
            signature = signer.sign(message)
            show("Signature (hex)", _preview_bytes(signature))
            show("Public key PEM", signer.public_pem.splitlines()[0] + "...")
            valid = signer.verify(message, signature)
            show("Signature valid", valid)

            tampered_sig = bytearray(signature)
            tampered_sig[0] ^= 1
            invalid = signer.verify(message, bytes(tampered_sig))
            show("Tampered signature valid", invalid)

            altered_message = message + b"!"
            wrong_message = signer.verify(altered_message, signature)
            show("Wrong-message valid", wrong_message)

        elif choice == "2":
            curve = ask("Curve (p256 / p384 / p521 / secp256k1, default p256)") or "p256"
            print(f"\n  Generating ECDSA key on curve {curve}...")
            signer = ECDSASigner(curve)
            message = ask("Message to sign").encode("utf-8")
            signature = signer.sign(message)
            show("Signature (hex)", _preview_bytes(signature))
            show("Public key PEM", signer.public_pem.splitlines()[0] + "...")
            valid = signer.verify(message, signature)
            show("Signature valid", valid)

            tampered_sig = bytearray(signature)
            tampered_sig[0] ^= 1
            invalid = signer.verify(message, bytes(tampered_sig))
            show("Tampered signature valid", invalid)

            altered_message = message + b"!"
            wrong_message = signer.verify(altered_message, signature)
            show("Wrong-message valid", wrong_message)

        else:
            print("  Invalid choice.")

        pause()


def menu_secure_app() -> None:
    while True:
        header("Secure Application")
        print("  [1] Start secure server")
        print("  [2] Start secure client chat")
        print("  [0] Back")

        choice = ask("Choice")

        if choice == "0":
            return

        elif choice == "1":
            host = ask("Server host (default 127.0.0.1)") or "127.0.0.1"
            port_input = ask("Server port (default 9999)")
            port = int(port_input) if port_input else 9999
            bits_input = ask("RSA key size in bits (1024 or 2048, default 2048)")
            bits = int(bits_input) if bits_input else 2048
            print("\n  Starting secure server (Ctrl+C to stop)...")
            try:
                server = SecureServer(host, port, bits)
                server.serve_forever()
            except KeyboardInterrupt:
                print("\n  Server stopped.")
            except Exception as exc:
                print(f"  Error: {exc}")

        elif choice == "2":
            host = ask("Server host (default 127.0.0.1)") or "127.0.0.1"
            port_input = ask("Server port (default 9999)")
            port = int(port_input) if port_input else 9999
            print("\n  Starting secure client chat...")
            try:
                with SecureClient() as client:
                    client.connect(host, port)
                    print(f"[Client] Connected to {host}:{port}. Type messages, 'quit' to exit.")
                    while True:
                        msg = ask("Message")
                        if not msg:
                            continue
                        client.send(msg.encode("utf-8"))
                        if msg == "quit":
                            break
                        reply = client.recv()
                        print(f"Server> {reply.decode(errors='replace')}")
            except Exception as exc:
                print(f"  Error: {exc}")

        else:
            print("  Invalid choice.")

        pause()


def menu_asymmetric() -> None:
    while True:
        header("Asymmetric Cryptography")
        print("  [1] Diffie-Hellman simulation")
        print("  [2] RSA test")
        print("  [3] ElGamal test")
        print("  [4] ElGamal malleability demo")
        print("  [5] ECC point math and ECDH")
        print("  [0] Back")

        choice = ask("Choice")

        if choice == "0":
            return

        elif choice == "1":
            bits_input = ask("Prime size in bits (default 1024)")
            bits = int(bits_input) if bits_input else 1024
            print("\n  Running Diffie-Hellman key exchange between A and B...")
            dh_result = diffie_hellman.DiffieHellman.key_exchange_demo(bits)
            show("Prime size", f"{dh_result['prime_bits']} bits")
            show("Generator", dh_result["generator"])
            show("A public key", _preview_hex(dh_result["alice_public"]))
            show("B public key", _preview_hex(dh_result["bob_public"]))
            show("Shared secret", _preview_hex(dh_result["shared_secret"]))
            show("A and B agree", dh_result["secrets_match"])

            print("\n  Simulating a man-in-the-middle attack...")
            mitm_result = diffie_hellman.DiffieHellman.mitm_attack_demo(bits)
            show("A public key", _preview_hex(mitm_result["alice_public"]))
            show("B public key", _preview_hex(mitm_result["bob_public"]))
            show("Mallory → A", _preview_hex(mitm_result["mallory_public_to_alice"]))
            show("Mallory → B", _preview_hex(mitm_result["mallory_public_to_bob"]))
            show("A–Mallory secret", _preview_hex(mitm_result["alice_mallory_shared_secret"]))
            show("B–Mallory secret", _preview_hex(mitm_result["bob_mallory_shared_secret"]))
            print("  Note: A and B do not share the same secret when Mallory intercepts the exchange.")

        elif choice == "2":
            bits_input = ask("RSA key size in bits (1024 or 2048, default 1024)")
            bits = int(bits_input) if bits_input else 1024
            print("\n  Generating RSA keypair... this may take a moment")
            n, e, d = rsa.generate_keypair(bits)
            show("Modulus size", f"{n.bit_length()} bits")
            show("Public exponent", e)
            show("Max plaintext bytes", (n.bit_length() - 1) // 8)

            plaintext = ask("Plaintext to encrypt")
            try:
                ciphertext = rsa.encrypt_text(plaintext, n, e)
                show("Ciphertext (hex)", ciphertext)
                decrypted = rsa.decrypt_text(ciphertext, n, d)
                show("Decrypted text", decrypted)
            except ValueError as exc:
                print(f"  Error: {exc}")

        elif choice == "3":
            bits_input = ask("Prime size in bits (default 512)")
            bits = int(bits_input) if bits_input else 512
            print("\n  Generating ElGamal keypair... this may take a moment")
            priv = elgamal.ElGamal.generate_keypair(bits)
            pub = priv.public_key
            show("Prime size", f"{pub.p.bit_length()} bits")
            show("Generator", pub.g)
            show("Public key y", _preview_hex(pub.y))

            plaintext = ask("Plaintext to encrypt")
            message_bytes = plaintext.encode("utf-8")
            try:
                c1a, c2a = elgamal.ElGamal.encrypt_bytes(message_bytes, pub)
                c1b, c2b = elgamal.ElGamal.encrypt_bytes(message_bytes, pub)
                show("Ciphertext #1 c1", _preview_hex(c1a))
                show("Ciphertext #1 c2", _preview_hex(c2a))
                show("Ciphertext #2 c1", _preview_hex(c1b))
                show("Ciphertext #2 c2", _preview_hex(c2b))
                show("Different ciphertexts?", (c1a, c2a) != (c1b, c2b))

                decrypted = elgamal.ElGamal.decrypt_bytes(c1a, c2a, priv, len(message_bytes))
                show("Decrypted text", decrypted.decode("utf-8", errors="replace"))
            except ValueError as exc:
                print(f"  Error: {exc}")

        elif choice == "4":
            print("\n  Demonstrating ElGamal malleability...")
            result = elgamal.ElGamal.malleability_demo()
            show("Original message", result["original_message"])
            show("Factor", result["factor_applied_by_attacker"])
            show("Modified plaintext", result["actual_decrypted_message"])
            show("Attack succeeded", result["attack_succeeded"])
            print(f"\n  Explanation: {result['explanation']}")

        elif choice == "5":
            curve = ecc.DEMO_CURVE
            header("ECC Point Operations")
            show("Curve", curve.name)
            show("Generator G", f"x=0x{curve.G.x:x}, y=0x{curve.G.y:x}")

            sum_point = curve.add(curve.G, curve.G)
            show("G + G", f"x=0x{sum_point.x:x}, y=0x{sum_point.y:x}")

            scalar = 7
            scaled = curve.multiply(curve.G, scalar)
            show(f"{scalar} * G", f"x=0x{scaled.x:x}, y=0x{scaled.y:x}")

            header("ECDH Key Exchange")
            ecdh = ecc.ECDH(curve)
            demo = ecdh.key_exchange_demo()
            show("A public", f"x=0x{demo['alice_public_x']:x}, y=0x{demo['alice_public_y']:x}")
            show("B public", f"x=0x{demo['bob_public_x']:x}, y=0x{demo['bob_public_y']:x}")
            show("Shared secret", _preview_hex(demo["shared_secret"]))
            show("A and B agree", demo["secrets_match"])

        else:
            print("  Invalid choice.")

        pause()


# ── Main menu ─────────────────────────────────────────────────────────────────

def main() -> None:
    while True:
        clear()
        print("""
  ================================
    CryptoSuite Pro
  ================================
  [1] Classical Cryptography
  [2] Symmetric Cryptography
  [3] Asymmetric Cryptography
  [4] Hashing
  [5] Digital Signatures
  [6] Secure Application
  [7] Performance Benchmarks
  [0] Exit
        """)

        choice = ask("Choice")

        if choice == "0":
            print("\n  Goodbye!\n")
            sys.exit(0)
        elif choice == "1":
            menu_classical()
        elif choice == "2":
            menu_symmetric()
        elif choice == "3":
            menu_asymmetric()
        elif choice == "4":
            menu_hashing()
        elif choice == "5":
            menu_signatures()
        elif choice == "6":
            menu_secure_app()
        elif choice == "7":
            menu_benchmarks()
        else:
            print_error("Invalid choice.")
            pause()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n  Interrupted by user. Goodbye!\n")
        log.info("Application interrupted by user.")
        sys.exit(0)
    except Exception as exc:
        log.exception("Unhandled exception")
        print_error(f"Unexpected error: {exc}")
        sys.exit(1)

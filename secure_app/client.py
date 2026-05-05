"""
Secure TCP client — RSA key exchange + AES-CBC encrypted channel + SHA-256 hash + RSA signature.

Usage (standalone):
    python -m secure_app.client --host 127.0.0.1 --port 9999
"""
import os
import socket
import json

from utils.logger import get_logger
from secure_app.protocol import (
    SecureProtocol, MessageType, send_frame, recv_frame, compute_sha256, verify_sha256, Frame,
)

log = get_logger("client")

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.PublicKey import RSA as _RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Hash import SHA256
    from Crypto.Signature import pkcs1_15
    from asymmetric.rsa_cipher import RSACipher
    _HAS_CRYPTO = True
except Exception as _crypto_err:
    import sys, traceback
    print("[DEBUG] Crypto import failed in secure_app.client:", _crypto_err, file=sys.stderr)
    traceback.print_exc()
    _HAS_CRYPTO = False


class SecureClient:
    """
    TCP client with RSA+AES secure channel + SHA-256 integrity + RSA signatures.

    Connects to a SecureServer, performs the key exchange handshake,
    then sends and receives encrypted messages with integrity protection.
    """

    def __init__(self, rsa_bits: int = 2048) -> None:
        if not _HAS_CRYPTO:
            raise ImportError("Install pycryptodome: pip install pycryptodome")
        self._sock: socket.socket | None = None
        self._aes_key: bytes | None = None
        
        # Generate client's RSA keypair for signing
        log.info(f"Client: generating {rsa_bits}-bit RSA keypair for signing…")
        priv = RSACipher.generate_keypair(rsa_bits)
        self._rsa_priv_sign = _RSA.construct((priv.n, priv.e, priv.d, priv.p, priv.q))
        self._rsa_pub_pem_sign = RSACipher.export_public_pem(priv)
        self._server_rsa_pub_exchange: _RSA.RsaKey | None = None  # Will receive from server
        self._server_rsa_pub_sign: _RSA.RsaKey | None = None      # Will receive from server
        log.info("Client: RSA keypair for signing ready")

    def connect(self, host: str = "127.0.0.1", port: int = 9999) -> None:
        """Connect and perform the RSA+AES key exchange handshake."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.connect((host, port))
        log.info(f"[SECURE] Connected to {host}:{port}")
        self._do_handshake()

    def _do_handshake(self) -> None:
        # Step 1: Receive server's RSA public keys (key exchange + signing)
        frame = recv_frame(self._sock)
        if frame.msg_type != MessageType.HANDSHAKE_HELLO:
            raise ValueError("Expected HANDSHAKE_HELLO from server")
        
        payload = json.loads(frame.payload.decode())
        key_exchange_pem = payload["key_exchange_pub"]
        signing_pem = payload["signing_pub"]
        
        self._server_rsa_pub_exchange = _RSA.import_key(key_exchange_pem.encode())
        self._server_rsa_pub_sign = _RSA.import_key(signing_pem.encode())
        
        log.info(f"Client: received server's RSA public keys "
                f"(key_exchange={self._server_rsa_pub_exchange.n.bit_length()} bits, "
                f"signing={self._server_rsa_pub_sign.n.bit_length()} bits)")

        # Step 2: Generate AES key and encrypt with server's RSA public key
        self._aes_key = os.urandom(32)  # AES-256
        rsa_cipher = PKCS1_OAEP.new(self._server_rsa_pub_exchange)
        encrypted_aes_key = rsa_cipher.encrypt(self._aes_key)

        iv = os.urandom(16)
        
        # Send encrypted AES key + client's signing public key
        payload = {
            "enc_key": encrypted_aes_key.hex(),
            "iv": iv.hex(),
            "client_signing_pub": self._rsa_pub_pem_sign,
        }
        send_frame(self._sock, Frame(MessageType.HANDSHAKE_KEY, json.dumps(payload).encode()))

        # Step 3: Wait for confirmation
        frame = recv_frame(self._sock)
        if frame.msg_type != MessageType.HANDSHAKE_DONE:
            raise ValueError("Handshake failed — unexpected server response")
        log.info(f"Client: handshake complete, AES key={self._aes_key.hex()[:16]}…")

    def send(self, plaintext: bytes) -> None:
        """Encrypt, hash, sign and send a message to the server."""
        if not self._sock or not self._aes_key:
            raise RuntimeError("Not connected")
        
        # Compute SHA-256 hash of plaintext
        plaintext_hash = compute_sha256(plaintext)
        
        # Sign the hash (sign the raw hash bytes) with client's private key
        hash_obj = SHA256.new(bytes.fromhex(plaintext_hash))
        signer = pkcs1_15.new(self._rsa_priv_sign)
        signature_bytes = signer.sign(hash_obj)
        signature_hex = signature_bytes.hex()
        
        # Encrypt with AES
        iv = os.urandom(16)
        cipher = AES.new(self._aes_key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(plaintext, AES.block_size))
        
        # Create and send frame with hash and signature
        send_frame(self._sock, SecureProtocol.make_data(iv, ct, plaintext_hash, signature_hex))
        log.debug(f"Client: sent {len(plaintext)} bytes, hash={plaintext_hash[:16]}..., sig={signature_hex[:16]}...")

    def _recv_with_status(self) -> tuple[bytes, bool, bool]:
        """Internal: receive and return plaintext with explicit hash/signature status."""
        if not self._sock or not self._aes_key or not self._server_rsa_pub_sign:
            raise RuntimeError("Not connected")

        frame = recv_frame(self._sock)

        if frame.msg_type == MessageType.ERROR:
            raise ConnectionError(f"Server error: {frame.payload.decode()}")
        if frame.msg_type not in (MessageType.DATA, MessageType.CHAT):
            raise ValueError(f"Unexpected frame: {frame.msg_type}")

        if frame.msg_type == MessageType.DATA:
            iv, ct, plaintext_hash, signature_hex = SecureProtocol.parse_data(frame)
        else:
            _, iv, ct, plaintext_hash, signature_hex = SecureProtocol.parse_chat(frame)

        # Decrypt
        cipher = AES.new(self._aes_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ct), AES.block_size)

        # Verify SHA-256 hash
        computed_hash = compute_sha256(plaintext)
        hash_ok = (computed_hash == plaintext_hash)
        if not hash_ok:
            log.warning(f"Client: HASH MISMATCH! expected={plaintext_hash[:16]}..., got={computed_hash[:16]}...")
        else:
            log.debug(f"Client: hash verified ✓")

        # Verify RSA signature
        sig_ok = False
        if signature_hex:
            try:
                hash_obj = SHA256.new(bytes.fromhex(plaintext_hash))
                verifier = pkcs1_15.new(self._server_rsa_pub_sign)
                signature_bytes = bytes.fromhex(signature_hex)
                verifier.verify(hash_obj, signature_bytes)
                sig_ok = True
                log.debug(f"Client: signature verified ✓")
            except (ValueError, TypeError):
                log.warning(f"Client: SIGNATURE INVALID!")
                sig_ok = False
            except Exception as e:
                log.error(f"Client: signature verification error: {e}")
                sig_ok = False

        return plaintext, hash_ok, sig_ok

    def recv(self) -> bytes:
        """Backward-compatible recv: returns plaintext bytes only (legacy callers expect raw reply)."""
        plaintext, _, _ = self._recv_with_status()
        return plaintext

    def recv_with_status(self) -> tuple[bytes, bool, bool]:
        """Public API to get explicit verification statuses: (plaintext, hash_ok, sig_ok)."""
        return self._recv_with_status()

    def close(self) -> None:
        if self._sock:
            self._sock.close()
            self._sock = None

    def __enter__(self) -> "SecureClient":
        return self

    def __exit__(self, *_) -> None:
        self.close()


def interactive_chat(host: str = "127.0.0.1", port: int = 9999) -> None:
    """Interactive chat client with menu and clear feedback messages."""
    client = SecureClient()
    client.connect(host, port)
    log.info(f"Client: connected and handshake complete")
    
    print(f"\n{'='*60}")
    print(f"[SECURE] Connected to {host}:{port}")
    print(f"{'='*60}\n")
    
    try:
        while True:
            print("\n--- MENU ---")
            print("1) Send a message")
            print("2) Quit")
            choice = input("Choose an option (1-2): ").strip()
            
            if choice == "1":
                msg = input("Enter message: ").strip()
                if not msg:
                    print("❌ Empty message, try again.")
                    continue
                
                try:
                    client.send(msg.encode())
                    print("[SECURE] Message sent")
                    
                    reply, hash_ok, sig_ok = client.recv_with_status()

                    if hash_ok and sig_ok:
                        print(f"[SECURE] Message received [HASH OK] [SIGNATURE OK]")
                    else:
                        status = []
                        status.append("HASH OK" if hash_ok else "HASH FAIL")
                        status.append("SIGNATURE OK" if sig_ok else "SIGNATURE FAIL")
                        print(f"[SECURE] Message received [{status[0]}] [{status[1]}]")
                    print(f"Server: {reply.decode(errors='replace')}")
                    
                    if msg == "quit":
                        break
                        
                except Exception as e:
                    log.error(f"Client: communication error: {e}")
                    print(f"❌ Error: {e}")
                    break
                    
            elif choice == "2":
                print("Goodbye!")
                break
            else:
                print("❌ Invalid option, try again.")
                
    except (KeyboardInterrupt, EOFError):
        print("\n\nInterrupted by user.")
    finally:
        client.close()
        log.info("Client: disconnected")
        print("[SECURE] Disconnected.")


if __name__ == "__main__":
    import argparse
    import sys
    import pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
    
    parser = argparse.ArgumentParser(description="SecureCipher Secure Client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument("--bits", type=int, default=2048)
    args = parser.parse_args()
    
    interactive_chat(args.host, args.port)


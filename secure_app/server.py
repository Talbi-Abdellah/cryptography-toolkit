"""
Secure TCP server — RSA key exchange + AES-CBC encrypted channel.

Usage (standalone):
    python -m secure_app.server --port 9999

Protocol:
    1. Server generates RSA keypair, sends public key to client (HELLO).
    2. Client generates AES-256 key, encrypts it with RSA-OAEP, sends KEY_EXCHANGE.
    3. Server decrypts AES key, sends HANDSHAKE_DONE.
    4. Both sides exchange DATA/CHAT frames encrypted with the shared AES key.
"""
import os
import json
import socket
import threading
from typing import Optional

from utils.logger import get_logger
from asymmetric.rsa_cipher import RSACipher
from secure_app.protocol import (
    SecureProtocol, MessageType, send_frame, recv_frame, compute_sha256,
)

log = get_logger("server")

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.PublicKey import RSA as _RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Hash import SHA256
    from Crypto.Signature import pkcs1_15
    _HAS_CRYPTO = True
except Exception as _crypto_err:
    import sys, traceback
    print("[DEBUG] Crypto import failed in secure_app.server:", _crypto_err, file=sys.stderr)
    traceback.print_exc()
    _HAS_CRYPTO = False


class SecureSession:
    """Represents one connected client session.

    Holds server signing private key and client's signing public key
    to perform signatures and verifications on messages.
    """

    def __init__(self, conn: socket.socket, addr, aes_key: bytes, session_id: int, server_sign_priv=None, client_sign_pub=None) -> None:
        self.conn = conn
        self.addr = addr
        self.aes_key = aes_key
        self.session_id = session_id
        self._server_sign_priv = server_sign_priv
        self._client_sign_pub = client_sign_pub

    def send_message(self, plaintext: bytes) -> None:
        """Encrypt, sign and send a DATA frame."""
        # Compute hash and signature
        plaintext_hash = compute_sha256(plaintext)
        signature_hex = None
        if self._server_sign_priv is not None:
            hash_obj = SHA256.new(bytes.fromhex(plaintext_hash))
            signer = pkcs1_15.new(self._server_sign_priv)
            signature_hex = signer.sign(hash_obj).hex()

        iv = os.urandom(16)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(plaintext, AES.block_size))
        send_frame(self.conn, SecureProtocol.make_data(iv, ct, plaintext_hash, signature_hex))

    def recv_message(self) -> tuple[bytes, bool, bool]:
        """Receive, decrypt, verify hash and signature.

        Returns: (plaintext, hash_ok, sig_ok)
        """
        frame = recv_frame(self.conn)
        if frame.msg_type == MessageType.DATA:
            iv, ct, plaintext_hash, signature_hex = SecureProtocol.parse_data(frame)
        elif frame.msg_type == MessageType.CHAT:
            _, iv, ct, plaintext_hash, signature_hex = SecureProtocol.parse_chat(frame)
        else:
            raise ValueError(f"Unexpected frame type: {frame.msg_type}")

        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ct), AES.block_size)

        # Verify hash
        computed_hash = compute_sha256(plaintext)
        hash_ok = (computed_hash == (plaintext_hash or ""))

        # Verify signature
        sig_ok = False
        if signature_hex and self._client_sign_pub is not None:
            try:
                hash_obj = SHA256.new(bytes.fromhex(plaintext_hash or ""))
                verifier = pkcs1_15.new(self._client_sign_pub)
                # pkcs1_15.verify raises ValueError on failure
                verifier.verify(hash_obj, bytes.fromhex(signature_hex))
                sig_ok = True
            except (ValueError, TypeError):
                sig_ok = False

        return plaintext, hash_ok, sig_ok

    def close(self) -> None:
        try:
            self.conn.close()
        except OSError:
            pass


class SecureServer:
    """
    TCP server with RSA+AES secure channel.

    The server generates a fresh RSA keypair at startup.
    Each client connection performs a full key exchange handshake,
    then data is exchanged using the negotiated AES-256-CBC key.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 9999, rsa_bits: int = 2048) -> None:
        if not _HAS_CRYPTO:
            raise ImportError("Install pycryptodome: pip install pycryptodome")
        self.host = host
        self.port = port
        self._session_counter = 0
        self._lock = threading.Lock()
        self.sessions: list[SecureSession] = []

        log.info("Server: generating %d-bit RSA keypairs (exchange + signing)…", rsa_bits)
        priv_ex = RSACipher.generate_keypair(rsa_bits)
        self._rsa_priv_exchange = _RSA.construct((priv_ex.n, priv_ex.e, priv_ex.d, priv_ex.p, priv_ex.q))
        self._public_pem_exchange = RSACipher.export_public_pem(priv_ex)

        priv_sign = RSACipher.generate_keypair(rsa_bits)
        self._rsa_priv_sign = _RSA.construct((priv_sign.n, priv_sign.e, priv_sign.d, priv_sign.p, priv_sign.q))
        self._public_pem_sign = RSACipher.export_public_pem(priv_sign)
        log.info("Server: RSA keypairs ready")

    def _do_handshake(self, conn: socket.socket) -> tuple[bytes, Optional[_RSA.RsaKey]]:
        """Perform RSA key exchange. Returns the negotiated AES key and client's signing public key (RSA object or None)."""
        # Step 1: Send RSA public keys (exchange + signing)
        hello_payload = json.dumps({
            "key_exchange_pub": self._public_pem_exchange,
            "signing_pub": self._public_pem_sign,
        })
        send_frame(conn, SecureProtocol.make_hello(hello_payload))

        # Step 2: Receive encrypted AES key + client's signing pub
        frame = recv_frame(conn)
        if frame.msg_type != MessageType.HANDSHAKE_KEY:
            raise ValueError("Expected HANDSHAKE_KEY frame")
        enc_key_hex, iv_hex, client_sign_pub = SecureProtocol.parse_key_exchange(frame)

        rsa_cipher = PKCS1_OAEP.new(self._rsa_priv_exchange)
        aes_key = rsa_cipher.decrypt(enc_key_hex)

        client_sign_rsa = None
        if client_sign_pub:
            try:
                client_sign_rsa = _RSA.import_key(client_sign_pub.encode())
            except Exception:
                client_sign_rsa = None

        # Step 3: Confirm
        send_frame(conn, SecureProtocol.make_handshake_done())
        log.info("Server: handshake complete, AES key=%s…", aes_key.hex()[:16])
        return aes_key, client_sign_rsa

    def _handle_client(self, conn: socket.socket, addr) -> None:
        log.info("Server: connection from %s", addr)
        try:
            aes_key, client_sign_rsa = self._do_handshake(conn)
            with self._lock:
                sid = self._session_counter
                self._session_counter += 1
            session = SecureSession(conn, addr, aes_key, sid, server_sign_priv=self._rsa_priv_sign, client_sign_pub=client_sign_rsa)
            with self._lock:
                self.sessions.append(session)

            # Echo loop for demo purposes
            while True:
                try:
                    plaintext, hash_ok, sig_ok = session.recv_message()
                    log.info("Server [session %d]: received %d bytes (hash_ok=%s sig_ok=%s)", sid, len(plaintext), hash_ok, sig_ok)
                    if not hash_ok:
                        log.error("Server [session %d]: HASH verification failed", sid)
                        send_frame(conn, SecureProtocol.make_error("Integrity check failed"))
                        continue
                    if not sig_ok:
                        log.error("Server [session %d]: SIGNATURE verification failed", sid)
                        send_frame(conn, SecureProtocol.make_error("Signature verification failed"))
                        continue

                    # Echo back (signed by server)
                    session.send_message(b"ACK: " + plaintext)
                    if plaintext == b"quit":
                        break
                except (ConnectionError, EOFError):
                    break
        except Exception as exc:
            log.error("Server: client error: %s", exc)
            try:
                send_frame(conn, SecureProtocol.make_error(str(exc)))
            except Exception:
                pass
        finally:
            conn.close()
            log.info("Server: connection closed %s", addr)

    def serve_forever(self, max_clients: int = 5) -> None:
        """Start blocking server loop."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(max_clients)
            log.info("Server: listening on %s:%d", self.host, self.port)
            print(f"[Server] Listening on {self.host}:{self.port}  (Ctrl+C to stop)")
            while True:
                conn, addr = srv.accept()
                t = threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True)
                t.start()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SecureCipher Secure Server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument("--bits", type=int, default=2048)
    args = parser.parse_args()

    import sys, pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
    SecureServer(args.host, args.port, args.bits).serve_forever()

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
import socket
import threading
from typing import Optional

from utils.logger import get_logger
from asymmetric.rsa_cipher import RSACipher
from secure_app.protocol import (
    SecureProtocol, MessageType, send_frame, recv_frame,
)

log = get_logger("server")

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.PublicKey import RSA as _RSA
    from Crypto.Cipher import PKCS1_OAEP
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


class SecureSession:
    """Represents one connected client session."""

    def __init__(self, conn: socket.socket, addr, aes_key: bytes, session_id: int) -> None:
        self.conn = conn
        self.addr = addr
        self.aes_key = aes_key
        self.session_id = session_id

    def send_message(self, plaintext: bytes) -> None:
        """Encrypt and send a DATA frame."""
        iv = os.urandom(16)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(plaintext, AES.block_size))
        send_frame(self.conn, SecureProtocol.make_data(iv, ct))

    def recv_message(self) -> bytes:
        """Receive and decrypt a DATA or CHAT frame."""
        frame = recv_frame(self.conn)
        if frame.msg_type == MessageType.DATA:
            iv, ct = SecureProtocol.parse_data(frame)
        elif frame.msg_type == MessageType.CHAT:
            _, iv, ct = SecureProtocol.parse_chat(frame)
        else:
            raise ValueError(f"Unexpected frame type: {frame.msg_type}")
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size)

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

        log.info("Server: generating %d-bit RSA keypair…", rsa_bits)
        priv = RSACipher.generate_keypair(rsa_bits)
        self._rsa_priv = _RSA.construct((priv.n, priv.e, priv.d, priv.p, priv.q))
        self._public_pem = RSACipher.export_public_pem(priv)
        log.info("Server: RSA keypair ready")

    def _do_handshake(self, conn: socket.socket) -> bytes:
        """Perform RSA key exchange. Returns the negotiated AES key."""
        # Step 1: Send RSA public key
        send_frame(conn, SecureProtocol.make_hello(self._public_pem))

        # Step 2: Receive encrypted AES key
        frame = recv_frame(conn)
        if frame.msg_type != MessageType.HANDSHAKE_KEY:
            raise ValueError("Expected HANDSHAKE_KEY frame")
        enc_key_hex, iv_hex = SecureProtocol.parse_key_exchange(frame)

        rsa_cipher = PKCS1_OAEP.new(self._rsa_priv)
        aes_key = rsa_cipher.decrypt(enc_key_hex)

        # Step 3: Confirm
        send_frame(conn, SecureProtocol.make_handshake_done())
        log.info("Server: handshake complete, AES key=%s…", aes_key.hex()[:16])
        return aes_key

    def _handle_client(self, conn: socket.socket, addr) -> None:
        log.info("Server: connection from %s", addr)
        try:
            aes_key = self._do_handshake(conn)
            with self._lock:
                sid = self._session_counter
                self._session_counter += 1
            session = SecureSession(conn, addr, aes_key, sid)
            with self._lock:
                self.sessions.append(session)

            # Echo loop for demo purposes
            while True:
                try:
                    data = session.recv_message()
                    log.info("Server [session %d]: received %d bytes", sid, len(data))
                    # Echo back
                    session.send_message(b"ACK: " + data)
                    if data == b"quit":
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
    parser = argparse.ArgumentParser(description="CryptoSuite Secure Server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument("--bits", type=int, default=2048)
    args = parser.parse_args()

    import sys, pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
    SecureServer(args.host, args.port, args.bits).serve_forever()

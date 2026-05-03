"""
Secure TCP client — RSA key exchange + AES-CBC encrypted channel.

Usage (standalone):
    python -m secure_app.client --host 127.0.0.1 --port 9999
"""
import os
import socket

from utils.logger import get_logger
from secure_app.protocol import (
    SecureProtocol, MessageType, send_frame, recv_frame,
)

log = get_logger("client")

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.PublicKey import RSA as _RSA
    from Crypto.Cipher import PKCS1_OAEP
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


class SecureClient:
    """
    TCP client with RSA+AES secure channel.

    Connects to a SecureServer, performs the key exchange handshake,
    then sends and receives encrypted messages.
    """

    def __init__(self) -> None:
        if not _HAS_CRYPTO:
            raise ImportError("Install pycryptodome: pip install pycryptodome")
        self._sock: socket.socket | None = None
        self._aes_key: bytes | None = None

    def connect(self, host: str = "127.0.0.1", port: int = 9999) -> None:
        """Connect and perform the RSA+AES key exchange handshake."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.connect((host, port))
        log.info("Client: connected to %s:%d", host, port)
        self._do_handshake()

    def _do_handshake(self) -> None:
        # Step 1: Receive server's RSA public key
        frame = recv_frame(self._sock)
        if frame.msg_type != MessageType.HANDSHAKE_HELLO:
            raise ValueError("Expected HANDSHAKE_HELLO from server")
        public_pem = frame.payload.decode()
        server_pub = _RSA.import_key(public_pem.encode())
        log.info("Client: received %d-bit RSA public key", server_pub.n.bit_length())

        # Step 2: Generate AES key and encrypt with server's RSA public key
        self._aes_key = os.urandom(32)  # AES-256
        rsa_cipher = PKCS1_OAEP.new(server_pub)
        encrypted_aes_key = rsa_cipher.encrypt(self._aes_key)

        iv = os.urandom(16)
        send_frame(self._sock, SecureProtocol.make_key_exchange(encrypted_aes_key, iv))

        # Step 3: Wait for confirmation
        frame = recv_frame(self._sock)
        if frame.msg_type != MessageType.HANDSHAKE_DONE:
            raise ValueError("Handshake failed — unexpected server response")
        log.info("Client: handshake complete, AES key=%s…", self._aes_key.hex()[:16])

    def send(self, plaintext: bytes) -> None:
        """Encrypt and send a message to the server."""
        if not self._sock or not self._aes_key:
            raise RuntimeError("Not connected")
        iv = os.urandom(16)
        cipher = AES.new(self._aes_key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(plaintext, AES.block_size))
        send_frame(self._sock, SecureProtocol.make_data(iv, ct))

    def recv(self) -> bytes:
        """Receive and decrypt a message from the server."""
        if not self._sock or not self._aes_key:
            raise RuntimeError("Not connected")
        frame = recv_frame(self._sock)
        if frame.msg_type == MessageType.ERROR:
            raise ConnectionError(f"Server error: {frame.payload.decode()}")
        if frame.msg_type not in (MessageType.DATA, MessageType.CHAT):
            raise ValueError(f"Unexpected frame: {frame.msg_type}")
        if frame.msg_type == MessageType.DATA:
            iv, ct = SecureProtocol.parse_data(frame)
        else:
            _, iv, ct = SecureProtocol.parse_chat(frame)
        cipher = AES.new(self._aes_key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size)

    def close(self) -> None:
        if self._sock:
            self._sock.close()
            self._sock = None

    def __enter__(self) -> "SecureClient":
        return self

    def __exit__(self, *_) -> None:
        self.close()


def interactive_chat(host: str = "127.0.0.1", port: int = 9999) -> None:
    """Simple interactive chat client (blocking readline loop)."""
    client = SecureClient()
    client.connect(host, port)
    print(f"[Client] Connected to {host}:{port}. Type messages, 'quit' to exit.")
    try:
        while True:
            msg = input("You> ").strip()
            if not msg:
                continue
            client.send(msg.encode())
            if msg == "quit":
                break
            reply = client.recv()
            print(f"Server> {reply.decode(errors='replace')}")
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        client.close()
        print("[Client] Disconnected.")


if __name__ == "__main__":
    import argparse, sys, pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
    parser = argparse.ArgumentParser(description="SecureCipher Secure Client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9999)
    args = parser.parse_args()
    interactive_chat(args.host, args.port)

"""UDP-based secure chat client (Wi‑Fi / LAN).

Simple CLI to perform a secure handshake over UDP and exchange messages.

Limitations:
- UDP does not guarantee delivery or ordering. This client implements
  a simple request/response pattern with timeouts and minimal retries.
"""
import json
import os
import socket
from typing import Optional

from utils.logger import get_logger
from asymmetric.rsa_cipher import RSACipher
from secure_app.protocol import SecureProtocol, MessageType, Frame, compute_sha256

log = get_logger("udp_client")

SERVER_PORT = 9998
BUF_SIZE = 65535

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.PublicKey import RSA as _RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Hash import SHA256
    from Crypto.Signature import pkcs1_15
    _HAS_CRYPTO = True
except Exception as e:
    log.error("PyCryptodome unavailable: %s", e)
    _HAS_CRYPTO = False


def send_udp_frame(sock: socket.socket, frame: Frame, addr) -> None:
    sock.sendto(frame.to_bytes(), addr)


def recv_udp_frame(sock: socket.socket, timeout: float = 5.0) -> tuple[Frame, tuple]:
    sock.settimeout(timeout)
    data, addr = sock.recvfrom(BUF_SIZE)
    return Frame.from_bytes(data), addr


class UDPClient:
    def __init__(self, server_host: str, server_port: int = SERVER_PORT):
        if not _HAS_CRYPTO:
            raise ImportError("PyCryptodome requis: pip install pycryptodome")
        self.server = (server_host, server_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._aes_key: Optional[bytes] = None
        self._server_rsa_pub_exchange = None
        self._server_rsa_pub_sign = None

        priv = RSACipher.generate_keypair(2048)
        self._rsa_priv_sign = _RSA.construct((priv.n, priv.e, priv.d, priv.p, priv.q))
        self._rsa_pub_pem_sign = RSACipher.export_public_pem(priv)

    def handshake(self, retries: int = 3, timeout: float = 3.0) -> bool:
        # send HELLO
        send_udp_frame(self.sock, SecureProtocol.make_hello("client-hello"), self.server)
        try:
            frame, addr = recv_udp_frame(self.sock, timeout=timeout)
        except Exception as e:
            log.error("No HELLO reply from server: %s", e)
            return False

        if frame.msg_type != MessageType.HANDSHAKE_HELLO:
            log.error("Unexpected frame during handshake: %s", frame.msg_type)
            return False

        payload = json.loads(frame.payload.decode())
        key_exchange_pem = payload.get("key_exchange_pub")
        signing_pem = payload.get("signing_pub")
        self._server_rsa_pub_exchange = _RSA.import_key(key_exchange_pem.encode())
        self._server_rsa_pub_sign = _RSA.import_key(signing_pem.encode())

        # generate AES and encrypt
        self._aes_key = os.urandom(32)
        rsa_cipher = PKCS1_OAEP.new(self._server_rsa_pub_exchange)
        encrypted_aes_key = rsa_cipher.encrypt(self._aes_key)

        payload = {
            "enc_key": encrypted_aes_key.hex(),
            "iv": os.urandom(16).hex(),
            "client_signing_pub": self._rsa_pub_pem_sign,
        }
        # send HANDSHAKE_KEY
        send_udp_frame(self.sock, Frame(MessageType.HANDSHAKE_KEY, json.dumps(payload).encode()), self.server)

        try:
            frame2, _ = recv_udp_frame(self.sock, timeout=timeout)
        except Exception as e:
            log.error("No HANDSHAKE_DONE from server: %s", e)
            return False

        if frame2.msg_type != MessageType.HANDSHAKE_DONE:
            log.error("Unexpected frame after key exchange: %s", frame2.msg_type)
            return False

        log.info("Handshake complete with server %s:%d", *self.server)
        return True

    def send(self, plaintext: bytes, timeout: float = 3.0) -> tuple[bool, Optional[bytes], bool, bool]:
        # returns (sent_ok, reply_plaintext_or_None, hash_ok, sig_ok)
        if not self._aes_key:
            raise RuntimeError("Handshake not completed")

        plaintext_hash = compute_sha256(plaintext)
        h = SHA256.new(bytes.fromhex(plaintext_hash))
        signer = pkcs1_15.new(self._rsa_priv_sign)
        sig = signer.sign(h).hex()

        iv = os.urandom(16)
        cipher = AES.new(self._aes_key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(plaintext, AES.block_size))

        send_udp_frame(self.sock, SecureProtocol.make_data(iv, ct, plaintext_hash, sig), self.server)

        # wait for reply with timeout (ACK)
        try:
            frame, addr = recv_udp_frame(self.sock, timeout=timeout)
        except Exception as e:
            log.warning("No reply (possible packet loss): %s", e)
            return False, None, False, False

        if frame.msg_type == MessageType.ERROR:
            log.error("Server error: %s", frame.payload.decode())
            return False, None, False, False

        iv2, ct2, plaintext_hash2, sig2 = SecureProtocol.parse_data(frame)
        cipher2 = AES.new(self._aes_key, AES.MODE_CBC, iv2)
        try:
            reply = unpad(cipher2.decrypt(ct2), AES.block_size)
        except Exception as e:
            log.error("Failed to decrypt server reply: %s", e)
            return False, None, False, False

        computed = compute_sha256(reply)
        hash_ok = (computed == plaintext_hash2)

        sig_ok = False
        if sig2 and self._server_rsa_pub_sign is not None:
            try:
                h2 = SHA256.new(bytes.fromhex(plaintext_hash2))
                verifier = pkcs1_15.new(self._server_rsa_pub_sign)
                verifier.verify(h2, bytes.fromhex(sig2))
                sig_ok = True
            except Exception:
                sig_ok = False

        return True, reply, hash_ok, sig_ok

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


def interactive_cli():
    host = input("Server host (IP): ").strip() or "127.0.0.1"
    client = UDPClient(host)
    if not client.handshake():
        print("Handshake failed — check server or network. UDP is unreliable.")
        return

    print("[SECURE] Connected (handshake complete).")
    try:
        while True:
            print('\n--- MENU ---')
            print('1) Send a message')
            print('2) Quit')
            c = input('Choice (1-2): ').strip()
            if c == '1':
                msg = input('Enter message: ').strip()
                if not msg:
                    continue
                ok, reply, hash_ok, sig_ok = client.send(msg.encode())
                if not ok:
                    print('No reply (possible packet loss).')
                    continue
                status = f"[HASH {'OK' if hash_ok else 'FAIL'}] [SIGNATURE {'OK' if sig_ok else 'FAIL'}]"
                print(f"Server reply: {reply.decode(errors='replace')} {status}")
                if msg == 'quit':
                    break
            elif c == '2':
                break
            else:
                print('Invalid choice')
    finally:
        client.close()


if __name__ == '__main__':
    interactive_cli()

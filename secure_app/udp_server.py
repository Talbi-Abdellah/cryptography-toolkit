"""UDP-based secure chat server (Wi‑Fi / LAN).

This module implements a simple secure handshake and message exchange
over UDP using the same primitives as the TCP implementation:
- RSA-OAEP for exchanging an AES-256 session key
- AES-256-CBC for encrypting messages
- SHA-256 for integrity
- RSA signatures (PKCS#1 v1.5 via pkcs1_15) for authenticity

Notes:
- UDP is connectionless and unreliable: packets may be lost or arrive
  out-of-order. This implementation adds simple timeouts and retries
  but does not provide reliability or ordering guarantees.
- On Windows, raw UDP sockets are supported but behaviour depends on
  the network stack; test on your target environment.
"""
import json
import os
import socket
import time
from typing import Optional

from utils.logger import get_logger
from asymmetric.rsa_cipher import RSACipher
from secure_app.protocol import SecureProtocol, MessageType, Frame, compute_sha256

log = get_logger("udp_server")

PORT = 9998
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
    raw = frame.to_bytes()
    sock.sendto(raw, addr)


def recv_udp_frame(sock: socket.socket, timeout: Optional[float] = None) -> tuple[Frame, tuple]:
    old = sock.gettimeout()
    try:
        sock.settimeout(timeout)
        data, addr = sock.recvfrom(BUF_SIZE)
        frame = Frame.from_bytes(data)
        return frame, addr
    finally:
        sock.settimeout(old)


def run_server(host: str = "0.0.0.0", port: int = PORT) -> None:
    if not _HAS_CRYPTO:
        raise ImportError("PyCryptodome requis: pip install pycryptodome")

    # prepare RSA keypairs (exchange + signing)
    priv_ex = RSACipher.generate_keypair(2048)
    rsa_priv_ex = _RSA.construct((priv_ex.n, priv_ex.e, priv_ex.d, priv_ex.p, priv_ex.q))
    pub_ex_pem = RSACipher.export_public_pem(priv_ex)

    priv_sign = RSACipher.generate_keypair(2048)
    rsa_priv_sign = _RSA.construct((priv_sign.n, priv_sign.e, priv_sign.d, priv_sign.p, priv_sign.q))
    pub_sign_pem = RSACipher.export_public_pem(priv_sign)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as srv:
        srv.bind((host, port))
        log.info("UDP server listening on %s:%d", host, port)
        print(f"[UDP Server] Listening on {host}:{port}")

        clients = {}

        while True:
            try:
                frame, addr = recv_udp_frame(srv, timeout=None)
            except Exception as e:
                log.error("Error receiving UDP frame: %s", e)
                continue

            try:
                if frame.msg_type == MessageType.HANDSHAKE_HELLO:
                    # Client is initiating handshake
                    log.info("Received HELLO from %s", addr)
                    hello_payload = json.dumps({"key_exchange_pub": pub_ex_pem, "signing_pub": pub_sign_pem})
                    send_udp_frame(srv, SecureProtocol.make_hello(hello_payload), addr)
                    log.info("Sent HELLO (pubkeys) to %s", addr)
                    continue

                if frame.msg_type == MessageType.HANDSHAKE_KEY:
                    # client sent encrypted AES key
                    enc_key_hex, iv_hex, client_sign_pub = SecureProtocol.parse_key_exchange(frame)
                    rsa_cipher = PKCS1_OAEP.new(rsa_priv_ex)
                    try:
                        aes_key = rsa_cipher.decrypt(enc_key_hex)
                    except Exception as e:
                        log.error("Failed to decrypt AES key from %s: %s", addr, e)
                        send_udp_frame(srv, SecureProtocol.make_error("Key exchange failed"), addr)
                        continue

                    client_sign_rsa = None
                    if client_sign_pub:
                        try:
                            client_sign_rsa = _RSA.import_key(client_sign_pub.encode())
                        except Exception:
                            client_sign_rsa = None

                    clients[addr] = {
                        "aes_key": aes_key,
                        "client_sign": client_sign_rsa,
                        "server_sign": rsa_priv_sign,
                    }

                    send_udp_frame(srv, SecureProtocol.make_handshake_done(), addr)
                    log.info("Handshake done with %s (AES key established)", addr)
                    continue

                if frame.msg_type == MessageType.DATA:
                    if addr not in clients:
                        log.warning("Received DATA from unknown client %s", addr)
                        send_udp_frame(srv, SecureProtocol.make_error("Not handshaken"), addr)
                        continue

                    aes_key = clients[addr]["aes_key"]
                    client_sign = clients[addr]["client_sign"]
                    iv, ct, plaintext_hash, sig_hex = SecureProtocol.parse_data(frame)

                    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                    try:
                        plaintext = unpad(cipher.decrypt(ct), AES.block_size)
                    except Exception as e:
                        log.error("Decryption error from %s: %s", addr, e)
                        send_udp_frame(srv, SecureProtocol.make_error("Decryption failed"), addr)
                        continue

                    computed = compute_sha256(plaintext)
                    hash_ok = (computed == plaintext_hash)

                    sig_ok = False
                    if sig_hex and client_sign is not None:
                        try:
                            h = SHA256.new(bytes.fromhex(plaintext_hash or ""))
                            verifier = pkcs1_15.new(client_sign)
                            verifier.verify(h, bytes.fromhex(sig_hex))
                            sig_ok = True
                        except Exception:
                            sig_ok = False

                    log.info("Received message from %s: %d bytes (hash_ok=%s sig_ok=%s)", addr, len(plaintext), hash_ok, sig_ok)

                    if not hash_ok:
                        send_udp_frame(srv, SecureProtocol.make_error("Integrity check failed"), addr)
                        continue
                    if not sig_ok:
                        send_udp_frame(srv, SecureProtocol.make_error("Signature verification failed"), addr)
                        continue

                    # send ACK (signed/encrypted)
                    session = clients[addr]
                    # build ACK message
                    ack_text = b"ACK"
                    iv2 = os.urandom(16)
                    cipher2 = AES.new(session["aes_key"], AES.MODE_CBC, iv2)
                    ct2 = cipher2.encrypt(pad(ack_text, AES.block_size))
                    plaintext_hash2 = compute_sha256(ack_text)
                    h2 = SHA256.new(bytes.fromhex(plaintext_hash2))
                    signer = pkcs1_15.new(session["server_sign"])
                    sig2 = signer.sign(h2).hex()
                    send_udp_frame(srv, SecureProtocol.make_data(iv2, ct2, plaintext_hash2, sig2), addr)
                    continue

                # other frames
                log.debug("Unhandled frame %s from %s", frame.msg_type, addr)

            except Exception as e:
                log.error("Server loop error: %s", e)
                continue


if __name__ == "__main__":
    run_server()

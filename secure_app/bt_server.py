"""Bluetooth RFCOMM secure server — wrapper around existing TCP security.

Notes:
- Uses PyBluez (bluetooth) to open an RFCOMM server and advertise
  service "CryptoSuiteSecureBT". This may not work on Windows or when
  Bluetooth hardware/stack is not available. In that case a clear
  message is shown and the TCP implementation should be used instead.

This module reuses the RSA/AES/SHA-256/signature logic from the TCP
implementation (secure_app.protocol and asymmetric.rsa_cipher).
"""
import json
import os
import sys
from typing import Optional

from utils.logger import get_logger
from asymmetric.rsa_cipher import RSACipher
from secure_app.protocol import SecureProtocol, MessageType, send_frame, recv_frame, compute_sha256

log = get_logger("bt_server")

try:
    from bluetooth import (
        BluetoothSocket,
        RFCOMM,
        PORT_ANY,
        advertise_service,
        SERIAL_PORT_CLASS,
        SERIAL_PORT_PROFILE,
        find_service,
    )
    _HAS_BT = True
except Exception as e:
    print("Bluetooth RFCOMM nécessite PyBluez et un environnement compatible. Utilisez la version TCP si indisponible.")
    log.error("Bluetooth not available: %s", e)
    _HAS_BT = False

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


class BTSession:
    def __init__(self, client_sock, addr, aes_key: bytes, server_sign_priv=None, client_sign_pub=None):
        self.sock = client_sock
        self.addr = addr
        self.aes_key = aes_key
        self._server_sign_priv = server_sign_priv
        self._client_sign_pub = client_sign_pub

    def send_message(self, plaintext: bytes) -> None:
        iv = os.urandom(16)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(plaintext, AES.block_size))

        # compute hash and signature
        plaintext_hash = compute_sha256(plaintext)
        sig_hex = None
        if self._server_sign_priv is not None:
            h = SHA256.new(bytes.fromhex(plaintext_hash))
            signer = pkcs1_15.new(self._server_sign_priv)
            sig_hex = signer.sign(h).hex()

        send_frame(self.sock, SecureProtocol.make_data(iv, ct, plaintext_hash, sig_hex))

    def recv_message(self) -> tuple[bytes, bool, bool]:
        frame = recv_frame(self.sock)
        if frame.msg_type == MessageType.DATA:
            iv, ct, plaintext_hash, sig_hex = SecureProtocol.parse_data(frame)
        else:
            raise ValueError("Unexpected frame type")

        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ct), AES.block_size)

        # verify hash
        computed = compute_sha256(plaintext)
        hash_ok = (computed == plaintext_hash)

        # verify signature
        sig_ok = False
        if sig_hex and self._client_sign_pub is not None:
            try:
                h = SHA256.new(bytes.fromhex(plaintext_hash or ""))
                verifier = pkcs1_15.new(self._client_sign_pub)
                verifier.verify(h, bytes.fromhex(sig_hex))
                sig_ok = True
            except Exception:
                sig_ok = False

        return plaintext, hash_ok, sig_ok


def run_server(uuid_name: str = "CryptoSuiteSecureBT") -> None:
    if not _HAS_BT:
        print("Bluetooth RFCOMM nécessite PyBluez et un environnement compatible. Utilisez la version TCP si indisponible.")
        return
    if not _HAS_CRYPTO:
        raise ImportError("PyCryptodome requis: pip install pycryptodome")

    # generate RSA keys (exchange + signing)
    priv_ex = RSACipher.generate_keypair(2048)
    rsa_priv_ex = _RSA.construct((priv_ex.n, priv_ex.e, priv_ex.d, priv_ex.p, priv_ex.q))
    pub_ex_pem = RSACipher.export_public_pem(priv_ex)

    priv_sign = RSACipher.generate_keypair(2048)
    rsa_priv_sign = _RSA.construct((priv_sign.n, priv_sign.e, priv_sign.d, priv_sign.p, priv_sign.q))
    pub_sign_pem = RSACipher.export_public_pem(priv_sign)

    server_sock = BluetoothSocket(RFCOMM)
    server_sock.bind(("", PORT_ANY))
    server_sock.listen(1)

    port = server_sock.getsockname()[1]
    advertise_service(server_sock, uuid_name, service_classes=[SERIAL_PORT_CLASS], profiles=[SERIAL_PORT_PROFILE])
    log.info("BT server listening on RFCOMM channel %s", port)
    print(f"[BT Server] Listening on RFCOMM channel {port}")

    try:
        client_sock, client_info = server_sock.accept()
        log.info("BT: connection from %s", client_info)

        # handshake: send HELLO with both public keys
        hello = json.dumps({"key_exchange_pub": pub_ex_pem, "signing_pub": pub_sign_pem})
        send_frame(client_sock, SecureProtocol.make_hello(hello))

        # receive key exchange
        frame = recv_frame(client_sock)
        if frame.msg_type != MessageType.HANDSHAKE_KEY:
            raise ValueError("Expected HANDSHAKE_KEY")
        enc_key_hex, iv_hex, client_sign_pub = SecureProtocol.parse_key_exchange(frame)

        rsa_cipher = PKCS1_OAEP.new(rsa_priv_ex)
        aes_key = rsa_cipher.decrypt(enc_key_hex)

        client_sign_rsa = None
        if client_sign_pub:
            try:
                client_sign_rsa = _RSA.import_key(client_sign_pub.encode())
            except Exception:
                client_sign_rsa = None

        send_frame(client_sock, SecureProtocol.make_handshake_done())
        log.info("BT: handshake complete, AES key=%s…", aes_key.hex()[:16])

        session = BTSession(client_sock, client_info, aes_key, server_sign_priv=rsa_priv_sign, client_sign_pub=client_sign_rsa)

        # message loop
        while True:
            try:
                plaintext, hash_ok, sig_ok = session.recv_message()
                log.info("BT: received %d bytes (hash_ok=%s sig_ok=%s)", len(plaintext), hash_ok, sig_ok)
                if not hash_ok:
                    send_frame(client_sock, SecureProtocol.make_error("Integrity check failed"))
                    continue
                if not sig_ok:
                    send_frame(client_sock, SecureProtocol.make_error("Signature verification failed"))
                    continue

                # echo
                session.send_message(b"ACK: " + plaintext)
                if plaintext == b"quit":
                    break
            except Exception as e:
                log.error("BT server error: %s", e)
                break

    finally:
        try:
            server_sock.close()
        except Exception:
            pass


if __name__ == "__main__":
    run_server()

"""Bluetooth RFCOMM secure client — discovery + connect + secured chat.

CLI:
 1) Discover devices
 2) Connect to a MAC
 3) Send a message
 4) Quit

If PyBluez is not available or Bluetooth is not supported on the OS,
the client prints a clear message and exits.
"""
import json
import os
import sys
from typing import Optional

from utils.logger import get_logger
from asymmetric.rsa_cipher import RSACipher
from secure_app.protocol import SecureProtocol, MessageType, send_frame, recv_frame, compute_sha256

log = get_logger("bt_client")

try:
    from bluetooth import (
        BluetoothSocket,
        RFCOMM,
        discover_devices,
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


class BTClient:
    def __init__(self):
        if not _HAS_BT:
            raise RuntimeError("Bluetooth RFCOMM non disponible")
        if not _HAS_CRYPTO:
            raise RuntimeError("PyCryptodome requis")

        # generate signing keypair
        priv = RSACipher.generate_keypair(2048)
        self._rsa_priv_sign = _RSA.construct((priv.n, priv.e, priv.d, priv.p, priv.q))
        self._rsa_pub_pem_sign = RSACipher.export_public_pem(priv)

        self._sock: Optional[object] = None
        self._aes_key: Optional[bytes] = None
        self._server_rsa_pub_exchange = None
        self._server_rsa_pub_sign = None

    def discover(self, duration: int = 8):
        return discover_devices(duration=duration, lookup_names=True)

    def connect(self, mac: str) -> None:
        # try to find RFCOMM service
        services = find_service(address=mac)
        port = None
        for s in services:
            if s.get("protocol") == "RFCOMM" or s.get("name") == "CryptoSuiteSecureBT":
                port = s.get("port")
                break
        if port is None:
            port = 1  # fallback

        sock = BluetoothSocket(RFCOMM)
        sock.connect((mac, port))
        self._sock = sock
        log.info("BT: connected to %s:%s", mac, port)

        # handshake
        frame = recv_frame(self._sock)
        if frame.msg_type != MessageType.HANDSHAKE_HELLO:
            raise ValueError("Expected HANDSHAKE_HELLO from server")
        payload = json.loads(frame.payload.decode())
        key_exchange_pem = payload.get("key_exchange_pub")
        signing_pem = payload.get("signing_pub")

        self._server_rsa_pub_exchange = _RSA.import_key(key_exchange_pem.encode())
        self._server_rsa_pub_sign = _RSA.import_key(signing_pem.encode())

        # generate AES key and send encrypted key + our signing pub
        self._aes_key = os.urandom(32)
        rsa_cipher = PKCS1_OAEP.new(self._server_rsa_pub_exchange)
        encrypted_aes_key = rsa_cipher.encrypt(self._aes_key)

        payload = {"enc_key": encrypted_aes_key.hex(), "iv": os.urandom(16).hex(), "client_signing_pub": self._rsa_pub_pem_sign}
        send_frame(self._sock, SecureProtocol.make_key_exchange(bytes.fromhex(payload["enc_key"]), bytes.fromhex(payload["iv"]), self._rsa_pub_pem_sign))

        frame = recv_frame(self._sock)
        if frame.msg_type != MessageType.HANDSHAKE_DONE:
            raise ValueError("Handshake failed — unexpected server response")
        log.info("BT: handshake complete, AES key=%s…", self._aes_key.hex()[:16])

    def send(self, plaintext: bytes) -> None:
        if not self._sock or not self._aes_key:
            raise RuntimeError("Not connected")

        plaintext_hash = compute_sha256(plaintext)
        h = SHA256.new(bytes.fromhex(plaintext_hash))
        signer = pkcs1_15.new(self._rsa_priv_sign)
        sig = signer.sign(h).hex()

        iv = os.urandom(16)
        cipher = AES.new(self._aes_key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(plaintext, AES.block_size))
        send_frame(self._sock, SecureProtocol.make_data(iv, ct, plaintext_hash, sig))

    def recv_with_status(self):
        frame = recv_frame(self._sock)
        if frame.msg_type == MessageType.ERROR:
            raise ConnectionError(frame.payload.decode())
        iv, ct, plaintext_hash, sig_hex = SecureProtocol.parse_data(frame)
        cipher = AES.new(self._aes_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ct), AES.block_size)

        computed = compute_sha256(plaintext)
        hash_ok = (computed == plaintext_hash)
        sig_ok = False
        if sig_hex and self._server_rsa_pub_sign is not None:
            try:
                h = SHA256.new(bytes.fromhex(plaintext_hash))
                verifier = pkcs1_15.new(self._server_rsa_pub_sign)
                verifier.verify(h, bytes.fromhex(sig_hex))
                sig_ok = True
            except Exception:
                sig_ok = False

        return plaintext, hash_ok, sig_ok

    def close(self):
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass


def interactive_cli():
    if not _HAS_BT:
        print("Bluetooth RFCOMM nécessite PyBluez et un environnement compatible. Utilisez la version TCP si indisponible.")
        return
    client = BTClient()
    connected = False
    try:
        while True:
            print('\n--- BT MENU ---')
            print('1) Discover devices')
            print('2) Connect to MAC')
            print('3) Send a message')
            print('4) Quit')
            c = input('Choice (1-4): ').strip()
            if c == '1':
                devs = client.discover()
                if not devs:
                    print('No devices found')
                else:
                    for i, (addr, name) in enumerate(devs, 1):
                        print(f"{i}) {addr} — {name}")
            elif c == '2':
                mac = input('Enter MAC address: ').strip()
                if not mac:
                    print('Invalid MAC')
                    continue
                try:
                    client.connect(mac)
                    connected = True
                    print('[SECURE] Connected via Bluetooth')
                except Exception as e:
                    print('Connection failed:', e)
            elif c == '3':
                if not connected:
                    print('Not connected')
                    continue
                msg = input('Enter message: ').strip()
                if not msg:
                    continue
                client.send(msg.encode())
                reply, hash_ok, sig_ok = client.recv_with_status()
                status = f"[HASH {'OK' if hash_ok else 'FAIL'}] [SIGNATURE {'OK' if sig_ok else 'FAIL'}]"
                print(f"Server reply: {reply.decode(errors='replace')} {status}")
                if msg == 'quit':
                    break
            elif c == '4':
                break
            else:
                print('Invalid choice')
    finally:
        client.close()


if __name__ == '__main__':
    interactive_cli()

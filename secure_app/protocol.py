"""Secure communication protocol — message framing and serialization."""
import json
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, Optional

MAGIC = b"CSPRO"   # 5-byte protocol magic
VERSION = 1


class MessageType(IntEnum):
    HANDSHAKE_HELLO  = 0x01  # Server → Client: public key
    HANDSHAKE_KEY    = 0x02  # Client → Server: AES key encrypted with RSA
    HANDSHAKE_DONE   = 0x03  # Server → Client: confirmation
    DATA             = 0x10  # Encrypted application data
    CHAT             = 0x11  # Encrypted chat message
    FILE_SEND        = 0x12  # File transfer
    ERROR            = 0xFF  # Error frame


@dataclass
class Frame:
    """
    Wire format:
        MAGIC   (5 bytes)
        VERSION (1 byte)
        TYPE    (1 byte)
        LENGTH  (4 bytes, big-endian) — length of PAYLOAD
        PAYLOAD (LENGTH bytes)
    """
    msg_type: MessageType
    payload: bytes

    HEADER_SIZE = len(MAGIC) + 1 + 1 + 4  # 11 bytes

    def to_bytes(self) -> bytes:
        header = MAGIC + bytes([VERSION, int(self.msg_type)]) + struct.pack(">I", len(self.payload))
        return header + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> "Frame":
        if len(data) < cls.HEADER_SIZE:
            raise ValueError("Frame too short")
        if not data.startswith(MAGIC):
            raise ValueError("Bad magic bytes")
        ver = data[5]
        if ver != VERSION:
            raise ValueError(f"Unsupported protocol version {ver}")
        msg_type = MessageType(data[6])
        length = struct.unpack(">I", data[7:11])[0]
        payload = data[11:11 + length]
        if len(payload) != length:
            raise ValueError("Incomplete frame payload")
        return cls(msg_type=msg_type, payload=payload)


class SecureProtocol:
    """Helpers for building specific frame types."""

    @staticmethod
    def make_hello(rsa_public_pem: str) -> Frame:
        return Frame(MessageType.HANDSHAKE_HELLO, rsa_public_pem.encode())

    @staticmethod
    def make_key_exchange(encrypted_aes_key: bytes, iv: bytes) -> Frame:
        payload = json.dumps({
            "enc_key": encrypted_aes_key.hex(),
            "iv": iv.hex(),
        }).encode()
        return Frame(MessageType.HANDSHAKE_KEY, payload)

    @staticmethod
    def parse_key_exchange(frame: Frame) -> tuple[bytes, bytes]:
        data = json.loads(frame.payload.decode())
        return bytes.fromhex(data["enc_key"]), bytes.fromhex(data["iv"])

    @staticmethod
    def make_handshake_done() -> Frame:
        return Frame(MessageType.HANDSHAKE_DONE, b"OK")

    @staticmethod
    def make_data(iv: bytes, ciphertext: bytes) -> Frame:
        payload = json.dumps({
            "iv": iv.hex(),
            "ct": ciphertext.hex(),
        }).encode()
        return Frame(MessageType.DATA, payload)

    @staticmethod
    def parse_data(frame: Frame) -> tuple[bytes, bytes]:
        data = json.loads(frame.payload.decode())
        return bytes.fromhex(data["iv"]), bytes.fromhex(data["ct"])

    @staticmethod
    def make_chat(iv: bytes, ciphertext: bytes, sender: str = "anon") -> Frame:
        payload = json.dumps({
            "sender": sender,
            "iv": iv.hex(),
            "ct": ciphertext.hex(),
        }).encode()
        return Frame(MessageType.CHAT, payload)

    @staticmethod
    def parse_chat(frame: Frame) -> tuple[str, bytes, bytes]:
        data = json.loads(frame.payload.decode())
        return data["sender"], bytes.fromhex(data["iv"]), bytes.fromhex(data["ct"])

    @staticmethod
    def make_error(message: str) -> Frame:
        return Frame(MessageType.ERROR, message.encode())


def send_frame(sock, frame: Frame) -> None:
    """Send a complete frame over a socket."""
    raw = frame.to_bytes()
    total = len(raw)
    sent = 0
    while sent < total:
        n = sock.send(raw[sent:])
        if n == 0:
            raise ConnectionError("Socket connection broken during send")
        sent += n


def recv_frame(sock) -> Frame:
    """Receive one complete frame from a socket (blocking)."""
    header = _recv_exact(sock, Frame.HEADER_SIZE)
    length = struct.unpack(">I", header[7:11])[0]
    payload = _recv_exact(sock, length)
    return Frame.from_bytes(header + payload)


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed before receiving all bytes")
        buf += chunk
    return buf

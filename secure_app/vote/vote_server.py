"""Pedagogical secure voting server using Paillier homomorphic encryption.

The server receives encrypted votes (0/1) from several voters, combines the
ciphertexts without decrypting them, and decrypts only the final total.

This is a simple TP-style demo, not a full election system.
"""
from __future__ import annotations

import argparse
import json
import socket
from typing import Optional

from utils.logger import get_logger
from secure_app.vote.paillier import (
    PaillierPrivateKey,
    PaillierPublicKey,
    decrypt,
    generate_keypair,
    homomorphic_add,
)

log = get_logger("vote_server")


def _send_json(conn: socket.socket, payload: dict) -> None:
    data = (json.dumps(payload) + "\n").encode("utf-8")
    conn.sendall(data)


def _recv_json(conn: socket.socket) -> dict:
    buffer = b""
    while not buffer.endswith(b"\n"):
        chunk = conn.recv(4096)
        if not chunk:
            raise ConnectionError("Connection closed")
        buffer += chunk
    return json.loads(buffer.decode("utf-8").strip())


class VoteServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 10000, expected_voters: int = 3, bits: int = 512) -> None:
        self.host = host
        self.port = port
        self.expected_voters = expected_voters
        self.public_key, self.private_key = generate_keypair(bits)
        self._aggregate = 1
        self._votes_received = 0

    def serve_forever(self) -> None:
        print("[VOTE] Public key ready:")
        print(f"  n = {self.public_key.n}")
        print(f"  g = {self.public_key.g}")
        print("[VOTE] Waiting for encrypted votes...")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(self.expected_voters)
            log.info("Vote server listening on %s:%d", self.host, self.port)

            while self._votes_received < self.expected_voters:
                conn, addr = server_socket.accept()
                with conn:
                    log.info("Connection from %s", addr)
                    print(f"[VOTE] Client connected: {addr[0]}:{addr[1]}")

                    _send_json(conn, {
                        "type": "public_key",
                        "n": str(self.public_key.n),
                        "g": str(self.public_key.g),
                    })

                    conn.settimeout(10.0)
                    try:
                        message = _recv_json(conn)
                    except socket.timeout:
                        log.warning("Timeout waiting for vote from %s", addr)
                        continue

                    if message.get("type") != "vote":
                        log.warning("Invalid message type from %s: %s", addr, message.get("type"))
                        _send_json(conn, {"type": "error", "message": "Invalid vote message"})
                        continue

                    try:
                        ciphertext = int(message["ciphertext"])
                    except (KeyError, ValueError, TypeError):
                        log.warning("Invalid ciphertext format from %s", addr)
                        _send_json(conn, {"type": "error", "message": "Invalid ciphertext"})
                        continue

                    self._aggregate = homomorphic_add(self._aggregate, ciphertext, self.public_key)
                    self._votes_received += 1
                    log.info("Vote accepted from %s (%d/%d)", addr, self._votes_received, self.expected_voters)
                    print(f"[VOTE] Vote accepted ({self._votes_received}/{self.expected_voters})")
                    _send_json(conn, {"type": "ack", "message": "Vote received"})

        total_yes = decrypt(self._aggregate, self.private_key, self.public_key)
        print("[VOTE] End of ballot")
        print(f"[VOTE] Total votes for Oui: {total_yes}")
        log.info("Final tally: yes_votes=%d", total_yes)


def main() -> None:
    parser = argparse.ArgumentParser(description="Secure voting server with Paillier")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=10000)
    parser.add_argument("--expected-voters", type=int, default=3)
    parser.add_argument("--bits", type=int, default=512)
    args = parser.parse_args()

    server = VoteServer(host=args.host, port=args.port, expected_voters=args.expected_voters, bits=args.bits)
    server.serve_forever()


if __name__ == "__main__":
    main()

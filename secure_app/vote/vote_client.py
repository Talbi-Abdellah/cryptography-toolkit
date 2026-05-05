"""Pedagogical secure voting client using Paillier encryption.

The client asks the user to vote 1 (Oui) or 0 (Non), encrypts that value
with the public Paillier key from the server, and sends only the ciphertext.
The clear vote is never shown again after encryption.
"""
from __future__ import annotations

import argparse
import json
import socket

from utils.logger import get_logger
from secure_app.vote.paillier import PaillierPublicKey, encrypt

log = get_logger("vote_client")


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


class VoteClient:
    def __init__(self, host: str = "127.0.0.1", port: int = 10000) -> None:
        self.host = host
        self.port = port

    def vote_once(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
            conn.connect((self.host, self.port))
            log.info("Connected to voting server at %s:%d", self.host, self.port)

            hello = _recv_json(conn)
            if hello.get("type") != "public_key":
                raise ValueError("Server did not send a public key")

            public_key = PaillierPublicKey(n=int(hello["n"]), g=int(hello["g"]))

            print("[VOTE] Choisissez votre vote:")
            print("  1) Oui")
            print("  0) Non")

            choice = input("Votre vote (0 ou 1): ").strip()
            while choice not in {"0", "1"}:
                print("[VOTE] Erreur: entrez uniquement 0 ou 1.")
                choice = input("Votre vote (0 ou 1): ").strip()

            vote = int(choice)
            ciphertext = encrypt(vote, public_key)
            _send_json(conn, {
                "type": "vote",
                "ciphertext": str(ciphertext),
            })

            # Ne pas réafficher le vote en clair ici.
            print("[SECURE] Vote chiffré et envoyé.")

            response = _recv_json(conn)
            if response.get("type") == "ack":
                print(f"[SECURE] {response.get('message', 'Vote reçu')}")
            else:
                print(f"[ERROR] {response.get('message', 'Réponse inattendue')}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Secure voting client with Paillier")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=10000)
    args = parser.parse_args()

    client = VoteClient(host=args.host, port=args.port)
    client.vote_once()


if __name__ == "__main__":
    main()

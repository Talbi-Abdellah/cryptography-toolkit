"""Multi-algorithm authenticity verification system."""
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from utils.logger import get_logger

log = get_logger("verify")


class SigAlgorithm(str, Enum):
    RSA_PSS  = "rsa_pss"
    ELGAMAL  = "elgamal"
    DSA      = "dsa"
    ECDSA    = "ecdsa"


@dataclass
class SignedDocument:
    """A document paired with its signature and algorithm identifier."""
    content: bytes
    signature: bytes
    algorithm: SigAlgorithm
    signer_id: str
    # Algorithm-specific public material (PEM string or custom structure)
    public_key_material: object


class AuthenticityVerifier:
    """Unified verifier that dispatches to the appropriate signature backend."""

    def verify(self, doc: SignedDocument) -> bool:
        """Verify the document's signature. Returns True if authentic."""
        try:
            if doc.algorithm == SigAlgorithm.RSA_PSS:
                return self._verify_rsa_pss(doc)
            elif doc.algorithm == SigAlgorithm.ELGAMAL:
                return self._verify_elgamal(doc)
            elif doc.algorithm == SigAlgorithm.DSA:
                return self._verify_dsa(doc)
            elif doc.algorithm == SigAlgorithm.ECDSA:
                return self._verify_ecdsa(doc)
            else:
                raise ValueError(f"Unknown algorithm: {doc.algorithm}")
        except Exception as exc:
            log.error("Verification error for signer '%s': %s", doc.signer_id, exc)
            return False

    def _verify_rsa_pss(self, doc: SignedDocument) -> bool:
        from signatures.rsa_signature import RSASigner
        signer = RSASigner.__new__(RSASigner)
        from Crypto.PublicKey import RSA as _RSA
        signer._key = _RSA.import_key(doc.public_key_material.encode())
        result = signer.verify(doc.content, doc.signature)
        log.info("RSA-PSS verify for '%s': %s", doc.signer_id, "OK" if result else "FAIL")
        return result

    def _verify_elgamal(self, doc: SignedDocument) -> bool:
        from signatures.elgamal_signature import ElGamalSigner, ElGamalSigPublicKey
        import pickle
        pub = pickle.loads(doc.public_key_material)
        r, s = pickle.loads(doc.signature)
        result = ElGamalSigner.verify(doc.content, r, s, pub)
        log.info("ElGamal verify for '%s': %s", doc.signer_id, "OK" if result else "FAIL")
        return result

    def _verify_dsa(self, doc: SignedDocument) -> bool:
        from signatures.dsa_ecdsa import DSASigner
        signer = DSASigner.__new__(DSASigner)
        result = signer.verify_with_public_pem(doc.content, doc.signature, doc.public_key_material)
        log.info("DSA verify for '%s': %s", doc.signer_id, "OK" if result else "FAIL")
        return result

    def _verify_ecdsa(self, doc: SignedDocument) -> bool:
        from signatures.dsa_ecdsa import ECDSASigner
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
        from cryptography.exceptions import InvalidSignature

        pub = load_pem_public_key(doc.public_key_material.encode())
        try:
            pub.verify(doc.signature, doc.content, ec.ECDSA(hashes.SHA256()))
            log.info("ECDSA verify for '%s': OK", doc.signer_id)
            return True
        except InvalidSignature:
            log.warning("ECDSA verify for '%s': FAIL", doc.signer_id)
            return False


class DocumentSigner:
    """High-level signer that creates SignedDocument objects."""

    def sign_rsa(self, content: bytes, signer_id: str, key_size: int = 2048) -> tuple:
        """Returns (SignedDocument, private_pem)."""
        from signatures.rsa_signature import RSASigner
        signer = RSASigner(key_size)
        sig = signer.sign(content)
        doc = SignedDocument(
            content=content,
            signature=sig,
            algorithm=SigAlgorithm.RSA_PSS,
            signer_id=signer_id,
            public_key_material=signer.public_pem,
        )
        return doc, signer.private_pem

    def sign_ecdsa(self, content: bytes, signer_id: str, curve: str = "p256") -> tuple:
        """Returns (SignedDocument, private_pem)."""
        from signatures.dsa_ecdsa import ECDSASigner
        signer = ECDSASigner(curve)
        sig = signer.sign(content)
        doc = SignedDocument(
            content=content,
            signature=sig,
            algorithm=SigAlgorithm.ECDSA,
            signer_id=signer_id,
            public_key_material=signer.public_pem,
        )
        return doc, signer.private_pem

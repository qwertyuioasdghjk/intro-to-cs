"""
Integrity Verifier module — verifies data authenticity using
hash comparison, Merkle proofs, and storage proofs.
"""

from .verifier import IntegrityVerifier, VerificationResult

__all__ = ["IntegrityVerifier", "VerificationResult"]

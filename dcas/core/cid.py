"""
Content Identifier (CID) generation module.

Generates unique, self-describing content identifiers inspired by IPFS CIDs.
Each CID encodes the hash algorithm, content type, and the hash digest.
"""

import json
import base64
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timezone

from .hashing import HashEngine, HashAlgorithm


@dataclass
class ContentIdentifier:
    """
    A self-describing content identifier for a piece of data.

    Attributes:
        hash_digest: The hex-encoded hash of the content.
        algorithm:   The hash algorithm used.
        version:     CID version (1 = current).
        codec:       The content codec / type description.
        size:        Size of the original content in bytes.
        created_at:  Timestamp when the CID was created.
    """
    hash_digest: str
    algorithm: str
    version: int = 1
    codec: str = "raw"
    size: int = 0
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def cid_string(self) -> str:
        """
        Generate a human-readable CID string.

        Format: dcas-v{version}-{algorithm}-{short_hash}
        Example: dcas-v1-sha256-a1b2c3d4e5f6

        Returns:
            A compact, unique content identifier string.
        """
        short_hash = self.hash_digest[:24]
        return f"dcas-v{self.version}-{self.algorithm}-{short_hash}"

    def to_dict(self) -> dict:
        """Serialize the CID to a dictionary."""
        return {
            "cid": self.cid_string,
            "hash_digest": self.hash_digest,
            "algorithm": self.algorithm,
            "version": self.version,
            "codec": self.codec,
            "size": self.size,
            "created_at": self.created_at,
        }

    def to_json(self) -> str:
        """Serialize the CID to a JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict) -> "ContentIdentifier":
        """Deserialize a CID from a dictionary."""
        return cls(
            hash_digest=data["hash_digest"],
            algorithm=data["algorithm"],
            version=data.get("version", 1),
            codec=data.get("codec", "raw"),
            size=data.get("size", 0),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "ContentIdentifier":
        """Deserialize a CID from a JSON string."""
        return cls.from_dict(json.loads(json_str))


class CIDGenerator:
    """
    Factory for generating Content Identifiers from data.

    Example:
        >>> gen = CIDGenerator()
        >>> cid = gen.generate(b"Hello, World!")
        >>> print(cid.cid_string)
        dcas-v1-sha256-dffd6021bb2bd5b0af67
    """

    def __init__(self, algorithm: HashAlgorithm = HashAlgorithm.SHA256):
        self.engine = HashEngine(algorithm)
        self.algorithm = algorithm

    def generate(self, data: bytes, codec: str = "raw") -> ContentIdentifier:
        """
        Generate a CID for raw bytes.

        Args:
            data:  The content bytes to identify.
            codec: A label for the content type (e.g., "raw", "dag-pb").

        Returns:
            A ContentIdentifier with the computed hash.
        """
        hash_digest = self.engine.hash_bytes(data)
        return ContentIdentifier(
            hash_digest=hash_digest,
            algorithm=self.algorithm.value,
            codec=codec,
            size=len(data),
        )

    def generate_from_file(self, filepath: str, codec: str = "raw") -> ContentIdentifier:
        """
        Generate a CID for a file on disk.

        Args:
            filepath: Path to the file.
            codec:    A label for the content type.

        Returns:
            A ContentIdentifier with the computed hash.
        """
        import os

        hash_digest = self.engine.hash_file(filepath)
        file_size = os.path.getsize(filepath)
        return ContentIdentifier(
            hash_digest=hash_digest,
            algorithm=self.algorithm.value,
            codec=codec,
            size=file_size,
        )

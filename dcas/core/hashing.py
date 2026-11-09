"""
Cryptographic hashing engine supporting multiple hash algorithms.
Provides SHA-256, SHA-512, and SHA3-256 for content fingerprinting.
"""

import hashlib
from enum import Enum
from typing import BinaryIO


class HashAlgorithm(Enum):
    """Supported hash algorithms for content addressing."""
    SHA256 = "sha256"
    SHA512 = "sha512"
    SHA3_256 = "sha3_256"


class HashEngine:
    """
    Engine for computing cryptographic hashes of data.

    Supports streaming hashing for large files and
    multiple algorithm choices.

    Example:
        >>> engine = HashEngine(HashAlgorithm.SHA256)
        >>> engine.hash_bytes(b"Hello, World!")
        'dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f'
    """

    # Chunk size for streaming hash computation (64 KB)
    STREAM_CHUNK_SIZE = 65536

    def __init__(self, algorithm: HashAlgorithm = HashAlgorithm.SHA256):
        self.algorithm = algorithm

    def _create_hasher(self):
        """Create a new hasher instance for the configured algorithm."""
        return hashlib.new(self.algorithm.value)

    def hash_bytes(self, data: bytes) -> str:
        """
        Compute the hash of raw bytes.

        Args:
            data: The bytes to hash.

        Returns:
            The hex-encoded hash digest.
        """
        hasher = self._create_hasher()
        hasher.update(data)
        return hasher.hexdigest()

    def hash_stream(self, stream: BinaryIO) -> str:
        """
        Compute the hash of a file-like binary stream.
        Reads the stream in chunks to handle large files efficiently.

        Args:
            stream: A file-like object opened in binary mode.

        Returns:
            The hex-encoded hash digest.
        """
        hasher = self._create_hasher()
        while True:
            chunk = stream.read(self.STREAM_CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
        return hasher.hexdigest()

    def hash_file(self, filepath: str) -> str:
        """
        Compute the hash of a file on disk.

        Args:
            filepath: Path to the file to hash.

        Returns:
            The hex-encoded hash digest.
        """
        with open(filepath, "rb") as f:
            return self.hash_stream(f)

    def verify_bytes(self, data: bytes, expected_hash: str) -> bool:
        """
        Verify that data matches an expected hash.

        Args:
            data: The bytes to verify.
            expected_hash: The expected hex-encoded hash.

        Returns:
            True if the hash matches, False otherwise.
        """
        return self.hash_bytes(data) == expected_hash

    def verify_file(self, filepath: str, expected_hash: str) -> bool:
        """
        Verify that a file matches an expected hash.

        Args:
            filepath: Path to the file to verify.
            expected_hash: The expected hex-encoded hash.

        Returns:
            True if the hash matches, False otherwise.
        """
        return self.hash_file(filepath) == expected_hash

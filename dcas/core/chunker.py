"""
File chunking module.

Splits files into fixed-size chunks for distributed storage.
Each chunk receives its own content hash for individual verification.
"""

import os
from dataclasses import dataclass
from typing import Generator

from .hashing import HashEngine, HashAlgorithm


@dataclass
class Chunk:
    """
    A single chunk of a file.

    Attributes:
        index:      The chunk's position in the file (0-based).
        data:       The raw bytes of this chunk.
        hash:       The SHA-256 hash of this chunk's data.
        offset:     Byte offset in the original file.
        size:       Size of this chunk in bytes.
    """
    index: int
    data: bytes
    hash: str
    offset: int
    size: int

    def to_dict(self) -> dict:
        """Serialize chunk metadata (without data) to a dictionary."""
        return {
            "index": self.index,
            "hash": self.hash,
            "offset": self.offset,
            "size": self.size,
        }


class FileChunker:
    """
    Splits files into fixed-size chunks for distributed storage.

    The default chunk size is 256 KB, which balances network transfer
    efficiency with storage granularity.

    Example:
        >>> chunker = FileChunker(chunk_size=1024)
        >>> chunks = chunker.chunk_bytes(b"A" * 3000)
        >>> len(chunks)  # 3 chunks: 1024 + 1024 + 952
        3
    """

    # Default chunk size: 256 KB
    DEFAULT_CHUNK_SIZE = 256 * 1024

    def __init__(
        self,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        algorithm: HashAlgorithm = HashAlgorithm.SHA256,
    ):
        if chunk_size <= 0:
            raise ValueError("Chunk size must be positive.")
        self.chunk_size = chunk_size
        self.engine = HashEngine(algorithm)

    def chunk_bytes(self, data: bytes) -> list[Chunk]:
        """
        Split raw bytes into chunks.

        Args:
            data: The raw bytes to split.

        Returns:
            A list of Chunk objects.
        """
        chunks = []
        offset = 0
        index = 0

        while offset < len(data):
            chunk_data = data[offset : offset + self.chunk_size]
            chunk_hash = self.engine.hash_bytes(chunk_data)
            chunks.append(
                Chunk(
                    index=index,
                    data=chunk_data,
                    hash=chunk_hash,
                    offset=offset,
                    size=len(chunk_data),
                )
            )
            offset += self.chunk_size
            index += 1

        return chunks

    def chunk_file(self, filepath: str) -> list[Chunk]:
        """
        Split a file into chunks.

        Args:
            filepath: Path to the file to chunk.

        Returns:
            A list of Chunk objects.
        """
        with open(filepath, "rb") as f:
            data = f.read()
        return self.chunk_bytes(data)

    def chunk_file_streaming(self, filepath: str) -> Generator[Chunk, None, None]:
        """
        Stream chunks from a file without loading it entirely into memory.

        Args:
            filepath: Path to the file to chunk.

        Yields:
            Chunk objects one at a time.
        """
        offset = 0
        index = 0
        with open(filepath, "rb") as f:
            while True:
                chunk_data = f.read(self.chunk_size)
                if not chunk_data:
                    break
                chunk_hash = self.engine.hash_bytes(chunk_data)
                yield Chunk(
                    index=index,
                    data=chunk_data,
                    hash=chunk_hash,
                    offset=offset,
                    size=len(chunk_data),
                )
                offset += len(chunk_data)
                index += 1

    @staticmethod
    def reassemble(chunks: list[Chunk]) -> bytes:
        """
        Reassemble data from an ordered list of chunks.

        Args:
            chunks: List of Chunk objects sorted by index.

        Returns:
            The reassembled bytes.
        """
        sorted_chunks = sorted(chunks, key=lambda c: c.index)
        return b"".join(c.data for c in sorted_chunks)

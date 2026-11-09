"""
Core module for the Decentralized Content-Addressed Storage system.
Provides hashing, CID generation, Merkle tree, and chunking utilities.
"""

from .hashing import HashEngine
from .cid import ContentIdentifier, CIDGenerator
from .merkle import MerkleTree, MerkleProof
from .chunker import FileChunker, Chunk

__all__ = [
    "HashEngine",
    "ContentIdentifier",
    "CIDGenerator",
    "MerkleTree",
    "MerkleProof",
    "FileChunker",
    "Chunk",
]

"""
Individual storage node in the decentralized network.

Each node stores content-addressed chunks in a local directory,
identified by their hash. A node can store, retrieve, delete,
and list the chunks it holds.
"""

import os
import json
import shutil
from datetime import datetime, timezone
from typing import Optional


class StorageNode:
    """
    A simulated decentralized storage node.

    Each node has an ID and a local directory where chunks are stored
    as individual files named by their hash digest.

    Attributes:
        node_id:      Unique identifier for this node.
        storage_dir:  Directory path where chunks are stored.
        capacity:     Maximum storage in bytes (0 = unlimited).
        is_online:    Whether the node is currently reachable.
    """

    def __init__(
        self,
        node_id: str,
        storage_dir: str,
        capacity: int = 0,
        is_online: bool = True,
    ):
        self.node_id = node_id
        self.storage_dir = storage_dir
        self.capacity = capacity
        self.is_online = is_online
        self._metadata: dict[str, dict] = {}

        os.makedirs(self.storage_dir, exist_ok=True)
        self._load_metadata()

    # ── Metadata persistence ────────────────────────────────────────

    @property
    def _metadata_path(self) -> str:
        return os.path.join(self.storage_dir, "_metadata.json")

    def _load_metadata(self):
        if os.path.exists(self._metadata_path):
            with open(self._metadata_path, "r") as f:
                self._metadata = json.load(f)
        else:
            self._metadata = {}

    def _save_metadata(self):
        with open(self._metadata_path, "w") as f:
            json.dump(self._metadata, f, indent=2)

    # ── Storage operations ──────────────────────────────────────────

    def store_chunk(self, chunk_hash: str, data: bytes) -> bool:
        """
        Store a chunk on this node.

        Args:
            chunk_hash: The content hash serving as the chunk's identifier.
            data:       The raw chunk bytes.

        Returns:
            True if stored successfully, False if the node is offline
            or has insufficient capacity.
        """
        if not self.is_online:
            return False

        existing_size = self._metadata.get(chunk_hash, {}).get("size", 0)
        if self.capacity > 0 and self.used_space - existing_size + len(data) > self.capacity:
            return False

        chunk_path = os.path.join(self.storage_dir, chunk_hash)
        with open(chunk_path, "wb") as f:
            f.write(data)

        self._metadata[chunk_hash] = {
            "size": len(data),
            "stored_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save_metadata()
        return True

    def retrieve_chunk(self, chunk_hash: str) -> Optional[bytes]:
        """
        Retrieve a chunk by its hash.

        Args:
            chunk_hash: The content hash of the chunk.

        Returns:
            The raw bytes, or None if not found or node is offline.
        """
        if not self.is_online:
            return None

        chunk_path = os.path.join(self.storage_dir, chunk_hash)
        if not os.path.exists(chunk_path):
            return None

        with open(chunk_path, "rb") as f:
            return f.read()

    def has_chunk(self, chunk_hash: str) -> bool:
        """Check whether this node holds a specific chunk."""
        if not self.is_online:
            return False
        return os.path.exists(os.path.join(self.storage_dir, chunk_hash))

    def delete_chunk(self, chunk_hash: str) -> bool:
        """
        Delete a chunk from this node.

        Returns:
            True if deleted, False if not found.
        """
        chunk_path = os.path.join(self.storage_dir, chunk_hash)
        if os.path.exists(chunk_path):
            os.remove(chunk_path)
            self._metadata.pop(chunk_hash, None)
            self._save_metadata()
            return True
        return False

    def list_chunks(self) -> list[str]:
        """Return a list of all chunk hashes stored on this node."""
        return [
            name
            for name in os.listdir(self.storage_dir)
            if name != "_metadata.json"
        ]

    @property
    def used_space(self) -> int:
        """Total bytes used on this node."""
        return sum(
            info.get("size", 0) for info in self._metadata.values()
        )

    @property
    def chunk_count(self) -> int:
        """Number of chunks stored on this node."""
        return len(self._metadata)

    def get_status(self) -> dict:
        """Return the node's status as a dictionary."""
        return {
            "node_id": self.node_id,
            "is_online": self.is_online,
            "chunk_count": self.chunk_count,
            "used_space_bytes": self.used_space,
            "capacity_bytes": self.capacity,
            "storage_dir": self.storage_dir,
        }

    def clear(self):
        """Remove all chunks from this node."""
        for name in self.list_chunks():
            os.remove(os.path.join(self.storage_dir, name))
        self._metadata = {}
        self._save_metadata()

    def __repr__(self) -> str:
        status = "online" if self.is_online else "offline"
        return f"StorageNode({self.node_id!r}, {status}, chunks={self.chunk_count})"

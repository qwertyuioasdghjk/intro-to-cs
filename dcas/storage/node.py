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

from .pdp import StoragePDP


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

        chunk_metadata = self._metadata.setdefault(chunk_hash, {})
        chunk_metadata["size"] = len(data)
        chunk_metadata["stored_at"] = datetime.now(timezone.utc).isoformat()
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

    def store_merkle_proof(
        self,
        chunk_hash: str,
        merkle_root: str,
        proof: dict,
    ) -> bool:
        """Persist a Merkle inclusion path for a chunk; return whether it was new."""
        if not self.has_chunk(chunk_hash):
            return False

        root_proofs = self._metadata[chunk_hash].setdefault("merkle_proofs", {})
        index = str(proof["leaf_index"])
        existing = root_proofs.setdefault(merkle_root, {}).get(index)
        if existing is not None:
            if existing != proof:
                raise ValueError("Conflicting Merkle proof already stored for this chunk.")
            return False

        root_proofs[merkle_root][index] = proof
        self._save_metadata()
        return True

    def remove_merkle_proof(self, chunk_hash: str, merkle_root: str, leaf_index: int):
        """Remove a newly added Merkle proof when a storage operation rolls back."""
        chunk_metadata = self._metadata.get(chunk_hash)
        if chunk_metadata is None:
            return

        root_proofs = chunk_metadata.get("merkle_proofs", {})
        proofs = root_proofs.get(merkle_root, {})
        proofs.pop(str(leaf_index), None)
        if not proofs:
            root_proofs.pop(merkle_root, None)
        if not root_proofs:
            chunk_metadata.pop("merkle_proofs", None)
        self._save_metadata()

    def retrieve_chunk_with_proof(
        self,
        chunk_hash: str,
        merkle_root: str,
        leaf_index: int,
    ) -> Optional[tuple[bytes, dict]]:
        """Return stored chunk bytes and its inclusion path for a specific file root."""
        chunk_data = self.retrieve_chunk(chunk_hash)
        if chunk_data is None:
            return None

        proof = (
            self._metadata.get(chunk_hash, {})
            .get("merkle_proofs", {})
            .get(merkle_root, {})
            .get(str(leaf_index))
        )
        if proof is None:
            return None
        return chunk_data, proof

    def store_pdp_tag(
        self,
        chunk_hash: str,
        file_id: str,
        sector_index: int,
        tag: str,
    ) -> bool:
        """Persist a homomorphic authenticator for one file sector."""
        if not self.has_chunk(chunk_hash):
            return False

        tags = self._metadata[chunk_hash].setdefault("pdp_tags", {})
        file_tags = tags.setdefault(file_id, {})
        index = str(sector_index)
        existing = file_tags.get(index)
        if existing is not None:
            if existing != tag:
                raise ValueError("Conflicting PDP tag already stored for this sector.")
            return False

        file_tags[index] = tag
        self._save_metadata()
        return True

    def remove_pdp_tag(self, chunk_hash: str, file_id: str, sector_index: int):
        """Remove a newly added PDP tag when a storage operation rolls back."""
        chunk_metadata = self._metadata.get(chunk_hash)
        if chunk_metadata is None:
            return

        tags = chunk_metadata.get("pdp_tags", {})
        file_tags = tags.get(file_id, {})
        file_tags.pop(str(sector_index), None)
        if not file_tags:
            tags.pop(file_id, None)
        if not tags:
            chunk_metadata.pop("pdp_tags", None)
        self._save_metadata()

    def respond_to_pdp_challenge(self, payload: dict) -> Optional[dict]:
        """Return a compact RSA-PDP aggregate proof without returning sector bytes."""
        if not self.is_online:
            return None

        file_id = payload["file_id"]
        nonce_hex = payload["nonce_hex"]
        modulus = int(payload["n"], 16)
        sectors = payload["sectors"]
        if not isinstance(sectors, list) or not 1 <= len(sectors) <= 64:
            raise ValueError("A PDP challenge must include between 1 and 64 sectors.")

        sigma = 1
        mu = 0
        seen_indices = set()
        for item in sectors:
            sector_index = item["sector_index"]
            coefficient = int(item["coefficient_hex"], 16)
            chunk_offset = item["chunk_offset"]
            length = item["length"]
            if (
                not isinstance(sector_index, int)
                or isinstance(sector_index, bool)
                or sector_index < 0
                or sector_index in seen_indices
                or not isinstance(chunk_offset, int)
                or isinstance(chunk_offset, bool)
                or chunk_offset < 0
                or not isinstance(length, int)
                or isinstance(length, bool)
                or not 0 <= length <= StoragePDP.SECTOR_SIZE
                or not 1 <= coefficient < 2 ** StoragePDP.COEFFICIENT_BITS
            ):
                raise ValueError("Invalid PDP challenge sector.")
            seen_indices.add(sector_index)

            chunk_hash = item["chunk_hash"]
            chunk_data = self.retrieve_chunk(chunk_hash)
            tag = (
                self._metadata.get(chunk_hash, {})
                .get("pdp_tags", {})
                .get(file_id, {})
                .get(str(sector_index))
            )
            if chunk_data is None or tag is None:
                return None

            sector_data = chunk_data[chunk_offset:chunk_offset + length]
            if len(sector_data) != length:
                return None
            tag_value = int(tag, 16)
            if not 1 <= tag_value < modulus:
                return None

            sigma = sigma * pow(tag_value, coefficient, modulus) % modulus
            mu += coefficient * StoragePDP.message_value(sector_data)

        return {
            "nonce_hex": nonce_hex,
            "sector_count": len(sectors),
            "sigma_hex": format(sigma, "x"),
            "mu_hex": format(mu, "x"),
        }

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

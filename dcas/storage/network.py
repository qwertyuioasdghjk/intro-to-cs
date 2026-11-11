"""
Decentralized storage network.

Manages a collection of StorageNode instances, distributes chunks
across nodes with configurable replication, and retrieves content
from any node that holds it.
"""

import os
import random
from typing import Optional

from .node import StorageNode
from ..core.chunker import Chunk, FileChunker
from ..core.cid import CIDGenerator, ContentIdentifier
from ..core.merkle import MerkleTree
from ..core.hashing import HashAlgorithm


class StorageNetwork:
    """
    A simulated decentralized storage network.

    Manages multiple StorageNode instances, distributes data chunks
    across nodes, and provides retrieval with automatic failover.

    Attributes:
        nodes:              Registered storage nodes.
        replication_factor: How many nodes should store each chunk.
    """

    def __init__(
        self,
        base_dir: str = "./dcas_network",
        num_nodes: int = 4,
        replication_factor: int = 2,
        algorithm: HashAlgorithm = HashAlgorithm.SHA256,
    ):
        self.base_dir = os.path.abspath(base_dir)
        self.replication_factor = replication_factor
        self.algorithm = algorithm
        self.nodes: list[StorageNode] = []
        self.cid_generator = CIDGenerator(algorithm)
        self.chunker = FileChunker(algorithm=algorithm)
        self.merkle_tree = MerkleTree(algorithm)

        # Create nodes
        for i in range(num_nodes):
            node_id = f"node-{i:03d}"
            node_dir = os.path.join(self.base_dir, node_id)
            node = StorageNode(node_id=node_id, storage_dir=node_dir)
            self.nodes.append(node)

    def add_node(self, node_id: str, capacity: int = 0) -> StorageNode:
        """Add a new node to the network."""
        node_dir = os.path.join(self.base_dir, node_id)
        node = StorageNode(node_id=node_id, storage_dir=node_dir, capacity=capacity)
        self.nodes.append(node)
        return node

    def remove_node(self, node_id: str) -> bool:
        """Remove a node from the network (does not delete stored data)."""
        for i, node in enumerate(self.nodes):
            if node.node_id == node_id:
                self.nodes.pop(i)
                return True
        return False

    def get_online_nodes(self) -> list[StorageNode]:
        """Return all nodes that are currently online."""
        return [n for n in self.nodes if n.is_online]

    def _select_nodes_for_storage(self, count: int) -> list[StorageNode]:
        """Select nodes for storing a chunk, preferring nodes with less data."""
        online = self.get_online_nodes()
        if not online:
            raise RuntimeError("No online nodes available in the network.")
        # Sort by used space (ascending) and pick the lightest-loaded nodes
        online.sort(key=lambda n: n.used_space)
        return online[: min(count, len(online))]

    # ── File operations ─────────────────────────────────────────────

    def store_file(self, filepath: str) -> dict:
        """
        Store a file in the decentralized network.

        Steps:
        1. Read and chunk the file.
        2. Build a Merkle tree from the chunks.
        3. Distribute each chunk to multiple nodes (replication).
        4. Generate a CID for the whole file.

        Args:
            filepath: Path to the file to store.

        Returns:
            A manifest dict containing the CID, Merkle root,
            chunk info, and node placements.
        """
        # Read file
        with open(filepath, "rb") as f:
            file_data = f.read()

        return self.store_bytes(
            file_data,
            filename=os.path.basename(filepath),
        )

    def store_bytes(self, data: bytes, filename: str = "unnamed") -> dict:
        """
        Store raw bytes in the decentralized network.

        Args:
            data:     The bytes to store.
            filename: A human-readable filename label.

        Returns:
            A manifest dict.
        """
        # 1. Generate CID
        cid = self.cid_generator.generate(data)

        # 2. Chunk the data
        chunks = self.chunker.chunk_bytes(data)

        # 3. Build Merkle tree
        chunk_data_list = [c.data for c in chunks]
        merkle_root = self.merkle_tree.build(chunk_data_list)

        # 4. Distribute chunks across nodes
        placements: list[dict] = []
        for chunk in chunks:
            target_nodes = self._select_nodes_for_storage(self.replication_factor)
            stored_on = []
            for node in target_nodes:
                if node.store_chunk(chunk.hash, chunk.data):
                    stored_on.append(node.node_id)
            placements.append({
                "chunk_index": chunk.index,
                "chunk_hash": chunk.hash,
                "chunk_size": chunk.size,
                "stored_on": stored_on,
            })

        manifest = {
            "cid": cid.to_dict(),
            "filename": filename,
            "total_size": len(data),
            "chunk_count": len(chunks),
            "merkle_root": merkle_root,
            "replication_factor": self.replication_factor,
            "placements": placements,
        }

        return manifest

    def retrieve_file(self, manifest: dict) -> Optional[bytes]:
        """
        Retrieve a file from the network using its manifest.

        Tries each node that stores a chunk until one succeeds.

        Args:
            manifest: The manifest dict returned by store_file().

        Returns:
            The reassembled file bytes, or None if any chunk is unrecoverable.
        """
        chunks: list[Chunk] = []

        for placement in manifest["placements"]:
            chunk_hash = placement["chunk_hash"]
            chunk_data = None

            # Try each node that stores this chunk
            for node_id in placement["stored_on"]:
                node = self._get_node(node_id)
                if node:
                    chunk_data = node.retrieve_chunk(chunk_hash)
                    if chunk_data is not None:
                        break

            # Fallback: try all online nodes
            if chunk_data is None:
                for node in self.get_online_nodes():
                    chunk_data = node.retrieve_chunk(chunk_hash)
                    if chunk_data is not None:
                        break

            if chunk_data is None:
                return None  # Chunk is unrecoverable

            chunks.append(Chunk(
                index=placement["chunk_index"],
                data=chunk_data,
                hash=chunk_hash,
                offset=0,
                size=placement["chunk_size"],
            ))

        return FileChunker.reassemble(chunks)

    def delete_file_chunks(
        self,
        manifest: dict,
        referenced_chunk_hashes: set[str] | None = None,
    ) -> int:
        """Delete this file's chunks unless another stored file references them."""
        referenced_chunk_hashes = referenced_chunk_hashes or set()
        chunk_hashes = {
            placement["chunk_hash"]
            for placement in manifest["placements"]
            if placement["chunk_hash"] not in referenced_chunk_hashes
        }
        deleted_copies = 0
        for node in self.nodes:
            for chunk_hash in chunk_hashes:
                deleted_copies += node.delete_chunk(chunk_hash)
        return deleted_copies

    def _get_node(self, node_id: str) -> Optional[StorageNode]:
        """Get a node by its ID."""
        for node in self.nodes:
            if node.node_id == node_id:
                return node
        return None

    # ── Network status ──────────────────────────────────────────────

    def get_network_status(self) -> dict:
        """Return a summary of the network status."""
        online = self.get_online_nodes()
        total_used = sum(n.used_space for n in self.nodes)
        total_chunks = sum(n.chunk_count for n in self.nodes)
        return {
            "total_nodes": len(self.nodes),
            "online_nodes": len(online),
            "offline_nodes": len(self.nodes) - len(online),
            "total_chunks_stored": total_chunks,
            "total_used_bytes": total_used,
            "replication_factor": self.replication_factor,
            "nodes": [n.get_status() for n in self.nodes],
        }

    def simulate_node_failure(self, node_id: str):
        """Take a node offline to simulate a failure."""
        node = self._get_node(node_id)
        if node:
            node.is_online = False

    def simulate_node_recovery(self, node_id: str):
        """Bring a node back online."""
        node = self._get_node(node_id)
        if node:
            node.is_online = True

    def cleanup(self):
        """Remove all network data from disk."""
        import shutil
        if os.path.exists(self.base_dir):
            shutil.rmtree(self.base_dir)

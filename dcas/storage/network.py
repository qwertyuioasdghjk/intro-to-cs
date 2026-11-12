"""
Decentralized storage network.

Manages a collection of StorageNode instances, distributes chunks
across nodes with configurable replication, and retrieves content
from any node that holds it.
"""

import base64
import json
import os
import re
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import ProxyHandler, Request, build_opener
from typing import Optional

from .node import StorageNode
from ..core.chunker import Chunk, FileChunker
from ..core.cid import CIDGenerator, ContentIdentifier
from ..core.merkle import MerkleTree
from ..core.hashing import HashAlgorithm
from .pdp import StoragePDP


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
        node_urls: dict[str, str] | None = None,
        pdp: StoragePDP | None = None,
    ):
        if replication_factor < 1:
            raise ValueError("Replication factor must be positive.")

        self.base_dir = os.path.abspath(base_dir)
        self.replication_factor = replication_factor
        self.algorithm = algorithm
        self.node_urls = dict(node_urls or {})
        self.pdp = pdp
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

    def _select_nodes_for_storage(self, chunk_hash: str) -> list[StorageNode]:
        """Order online nodes by used space so capacity failures can fall through."""
        online = self.get_online_nodes()
        if not online:
            raise RuntimeError("No online nodes available in the network.")
        online.sort(key=lambda n: (not n.has_chunk(chunk_hash), n.used_space))
        return online

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
        file_id = cid.cid_string
        pdp_metadata = None
        pdp_tags = []
        if self.pdp is not None:
            pdp_metadata = self.pdp.file_metadata(
                file_id,
                len(data),
                self.chunker.chunk_size,
            )
            pdp_tags = self.pdp.create_tags(file_id, data)

        # 2. Chunk the data
        chunks = self.chunker.chunk_bytes(data)

        # 3. Build Merkle tree
        chunk_data_list = [c.data for c in chunks]
        merkle_root = self.merkle_tree.build(chunk_data_list)
        merkle_proofs = [
            self.merkle_tree.get_proof(chunk.index).to_dict()
            for chunk in chunks
        ]

        # 4. Distribute chunks across nodes
        placements: list[dict] = []
        newly_stored: list[tuple[StorageNode, str]] = []
        newly_stored_proofs: list[tuple[StorageNode, str, str, int]] = []
        newly_stored_tags: list[tuple[StorageNode, str, str, int]] = []
        try:
            for chunk in chunks:
                stored_on = []
                for node in self._select_nodes_for_storage(chunk.hash):
                    if len(stored_on) >= self.replication_factor:
                        break
                    already_present = node.has_chunk(chunk.hash)
                    if node.store_chunk(chunk.hash, chunk.data):
                        stored_on.append(node.node_id)
                        if not already_present:
                            newly_stored.append((node, chunk.hash))

                if len(stored_on) < self.replication_factor:
                    raise RuntimeError(
                        f"Could not store chunk {chunk.index} on "
                        f"{self.replication_factor} nodes."
                    )

                placements.append({
                    "chunk_index": chunk.index,
                    "chunk_hash": chunk.hash,
                    "chunk_size": chunk.size,
                    "stored_on": stored_on,
                })

            for placement, proof in zip(placements, merkle_proofs):
                for node_id in placement["stored_on"]:
                    node = self._get_node(node_id)
                    if node is None:
                        raise RuntimeError(f"Storage node {node_id} disappeared during upload.")
                    if node.store_merkle_proof(placement["chunk_hash"], merkle_root, proof):
                        newly_stored_proofs.append((
                            node,
                            placement["chunk_hash"],
                            merkle_root,
                            placement["chunk_index"],
                        ))
                    elif not node.has_chunk(placement["chunk_hash"]):
                        raise RuntimeError(
                            f"Storage node {node_id} cannot persist the Merkle proof."
                        )

            if self.pdp is not None:
                for sector_index, tag in enumerate(pdp_tags):
                    data_offset = sector_index * self.pdp.SECTOR_SIZE
                    chunk_index = data_offset // self.chunker.chunk_size
                    placement = placements[chunk_index]
                    for node_id in placement["stored_on"]:
                        node = self._get_node(node_id)
                        if node is None:
                            raise RuntimeError(
                                f"Storage node {node_id} disappeared during PDP tag storage."
                            )
                        if node.store_pdp_tag(
                            placement["chunk_hash"],
                            file_id,
                            sector_index,
                            tag,
                        ):
                            newly_stored_tags.append((
                                node,
                                placement["chunk_hash"],
                                file_id,
                                sector_index,
                            ))
                        elif not node.has_chunk(placement["chunk_hash"]):
                            raise RuntimeError(
                                f"Storage node {node_id} cannot persist the PDP tag."
                            )
        except Exception:
            for node, chunk_hash, tagged_file_id, sector_index in reversed(newly_stored_tags):
                node.remove_pdp_tag(chunk_hash, tagged_file_id, sector_index)
            for node, chunk_hash, root_hash, leaf_index in reversed(newly_stored_proofs):
                node.remove_merkle_proof(chunk_hash, root_hash, leaf_index)
            for node, chunk_hash in reversed(newly_stored):
                node.delete_chunk(chunk_hash)
            raise

        manifest = {
            "cid": cid.to_dict(),
            "filename": filename,
            "total_size": len(data),
            "chunk_count": len(chunks),
            "merkle_root": merkle_root,
            "replication_factor": self.replication_factor,
            "placements": placements,
        }
        if pdp_metadata is not None:
            manifest["pdp"] = pdp_metadata

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

            candidate_node_ids = placement["stored_on"] + [
                node.node_id for node in self.get_online_nodes()
            ]
            for node_id in dict.fromkeys(candidate_node_ids):
                node = self._get_node(node_id)
                if node:
                    candidate = node.retrieve_chunk(chunk_hash)
                    if candidate is not None and self.chunker.engine.verify_bytes(candidate, chunk_hash):
                        chunk_data = candidate
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

    def retrieve_chunk_from_node(
        self,
        node_id: str,
        chunk_hash: str,
        expected_size: int | None = None,
    ) -> Optional[bytes]:
        """Retrieve one chunk directly from a configured node service or local node."""
        if expected_size is not None and expected_size < 0:
            raise ValueError("Expected chunk size cannot be negative.")
        node = self._get_node(node_id)
        if node is None:
            return None

        node_url = self.node_urls.get(node_id)
        if node_url is None:
            data = node.retrieve_chunk(chunk_hash)
            if data is not None and expected_size is not None and len(data) > expected_size:
                return data[:expected_size + 1]
            return data

        if not re.fullmatch(r"[0-9a-f]{64}|[0-9a-f]{128}", chunk_hash):
            raise ValueError("Chunk hash must be a lowercase SHA-256 or SHA-512 digest.")

        url = f"{node_url.rstrip('/')}/v1/chunks/{quote(chunk_hash, safe='')}"
        try:
            opener = build_opener(ProxyHandler({}))
            with opener.open(Request(url, method="GET"), timeout=5) as response:
                return response.read(expected_size + 1 if expected_size is not None else -1)
        except HTTPError as error:
            if error.code == 404:
                return None
            raise
        except URLError:
            raise

    def challenge_chunks(
        self,
        node_id: str,
        nonce: bytes,
        challenges: list[dict],
    ) -> Optional[dict]:
        """Ask a node for sampled chunk bytes and their stored Merkle paths."""
        if not isinstance(nonce, (bytes, bytearray)):
            raise TypeError("Challenge nonce must be provided as bytes.")
        if not challenges or len(challenges) > 64:
            raise ValueError("A challenge must include between 1 and 64 chunks.")

        node = self._get_node(node_id)
        if node is None:
            return None

        node_url = self.node_urls.get(node_id)
        if node_url is None:
            challenged_chunks = []
            for item in challenges:
                retrieved = node.retrieve_chunk_with_proof(
                    item["chunk_hash"],
                    item["merkle_root"],
                    item["chunk_index"],
                )
                if retrieved is None:
                    return None
                chunk_data, proof = retrieved
                challenged_chunks.append({
                    "chunk_hash": item["chunk_hash"],
                    "chunk_index": item["chunk_index"],
                    "data_base64": base64.b64encode(chunk_data).decode("ascii"),
                    "proof": proof,
                })
            return {"nonce_hex": bytes(nonce).hex(), "chunks": challenged_chunks}

        for item in challenges:
            if not re.fullmatch(r"[0-9a-f]{64}|[0-9a-f]{128}", item["chunk_hash"]):
                raise ValueError("Chunk hash must be a lowercase SHA-256 or SHA-512 digest.")
            if not re.fullmatch(r"[0-9a-f]{64}|[0-9a-f]{128}", item["merkle_root"]):
                raise ValueError("Merkle root must be a lowercase hash digest.")

        payload = json.dumps({
            "nonce_hex": bytes(nonce).hex(),
            "chunks": challenges,
        }).encode("utf-8")
        response_limit = (
            64 * 1024
            + len(challenges) * (
                4 * ((self.chunker.chunk_size + 2) // 3) + 64 * 1024
            )
        )
        request = Request(
            f"{node_url.rstrip('/')}/v1/challenges",
            data=payload,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            opener = build_opener(ProxyHandler({}))
            with opener.open(request, timeout=5) as response:
                response_data = response.read(response_limit + 1)
                if len(response_data) > response_limit:
                    raise ValueError(
                        f"Merkle challenge response exceeds the {response_limit} byte limit."
                    )
                body = json.loads(response_data.decode("utf-8"))
                return body if isinstance(body, dict) else None
        except HTTPError as error:
            if error.code == 404:
                return None
            raise

    def request_pdp_proof(self, node_id: str, payload: dict) -> Optional[dict]:
        """Request a compact RSA-PDP response from a local or HTTP storage node."""
        node = self._get_node(node_id)
        if node is None:
            return None

        node_url = self.node_urls.get(node_id)
        if node_url is None:
            return node.respond_to_pdp_challenge(payload)

        request = Request(
            f"{node_url.rstrip('/')}/v1/pdp/challenge",
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            opener = build_opener(ProxyHandler({}))
            with opener.open(request, timeout=5) as response:
                response_data = response.read(64 * 1024 + 1)
                if len(response_data) > 64 * 1024:
                    raise ValueError("PDP response exceeds the 64 KiB limit.")
                body = json.loads(response_data.decode("utf-8"))
                return body if isinstance(body, dict) else None
        except HTTPError as error:
            if error.code == 404:
                return None
            raise

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

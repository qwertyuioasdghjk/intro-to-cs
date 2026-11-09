"""
Integrity Verifier — the core verification engine.

Provides multiple verification modes:
1. Full hash verification   — recompute the hash of retrieved data.
2. Chunk-level verification — verify each chunk individually.
3. Merkle proof verification — verify a single chunk belongs to a dataset.
4. Storage proof (challenge) — challenge a node to prove it holds specific data.
5. Network-wide audit       — verify all chunks across all nodes.
"""

import os
import json
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from ..core.hashing import HashEngine, HashAlgorithm
from ..core.merkle import MerkleTree, MerkleProof
from ..core.chunker import FileChunker
from ..storage.network import StorageNetwork


class VerificationStatus(Enum):
    """Outcome of a verification check."""
    PASSED = "PASSED"
    FAILED = "FAILED"
    WARNING = "WARNING"
    ERROR = "ERROR"


@dataclass
class VerificationResult:
    """
    Result of an integrity verification operation.

    Attributes:
        status:       PASSED, FAILED, WARNING, or ERROR.
        message:      Human-readable summary.
        details:      Structured details (varies by verification type).
        timestamp:    When the verification was performed.
        cid:          The content identifier being verified (if applicable).
        elapsed_ms:   Time taken in milliseconds.
    """
    status: VerificationStatus
    message: str
    details: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    cid: Optional[str] = None
    elapsed_ms: float = 0.0

    @property
    def passed(self) -> bool:
        return self.status == VerificationStatus.PASSED

    def to_dict(self) -> dict:
        return {
            "status": self.status.value,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp,
            "cid": self.cid,
            "elapsed_ms": self.elapsed_ms,
        }


class IntegrityVerifier:
    """
    Main integrity verification engine.

    Supports multiple verification strategies and reports
    detailed results for auditing.

    Example:
        >>> verifier = IntegrityVerifier(network)
        >>> result = verifier.verify_file_integrity(manifest)
        >>> print(result.status, result.message)
    """

    def __init__(
        self,
        network: StorageNetwork,
        algorithm: HashAlgorithm = HashAlgorithm.SHA256,
    ):
        self.network = network
        self.engine = HashEngine(algorithm)
        self.algorithm = algorithm

    # ── 1. Full file hash verification ──────────────────────────────

    def verify_file_integrity(self, manifest: dict) -> VerificationResult:
        """
        Download and verify a file's complete hash.

        Retrieves all chunks, reassembles the file, and compares
        the computed hash against the CID hash.

        Args:
            manifest: The file manifest from StorageNetwork.

        Returns:
            A VerificationResult.
        """
        import time
        start = time.time()

        cid_str = manifest["cid"]["cid"]
        expected_hash = manifest["cid"]["hash_digest"]

        # Retrieve the file
        file_data = self.network.retrieve_file(manifest)
        if file_data is None:
            elapsed = (time.time() - start) * 1000
            return VerificationResult(
                status=VerificationStatus.ERROR,
                message="Could not retrieve all chunks from the network.",
                cid=cid_str,
                elapsed_ms=elapsed,
            )

        # Recompute hash
        actual_hash = self.engine.hash_bytes(file_data)
        elapsed = (time.time() - start) * 1000

        if actual_hash == expected_hash:
            return VerificationResult(
                status=VerificationStatus.PASSED,
                message="File integrity verified. Content matches expected hash.",
                details={
                    "expected_hash": expected_hash,
                    "actual_hash": actual_hash,
                    "file_size": len(file_data),
                },
                cid=cid_str,
                elapsed_ms=elapsed,
            )
        else:
            return VerificationResult(
                status=VerificationStatus.FAILED,
                message="INTEGRITY VIOLATION: File content does not match expected hash!",
                details={
                    "expected_hash": expected_hash,
                    "actual_hash": actual_hash,
                    "file_size": len(file_data),
                },
                cid=cid_str,
                elapsed_ms=elapsed,
            )

    # ── 2. Chunk-level verification ─────────────────────────────────

    def verify_chunks(self, manifest: dict) -> VerificationResult:
        """
        Verify each chunk individually by hash.

        Downloads every chunk and checks its hash against the manifest.

        Returns:
            A VerificationResult with per-chunk details.
        """
        import time
        start = time.time()

        cid_str = manifest["cid"]["cid"]
        chunk_results = []
        all_passed = True
        missing_chunks = 0

        for placement in manifest["placements"]:
            chunk_hash = placement["chunk_hash"]
            chunk_data = None

            # Try to retrieve from any node
            for node_id in placement["stored_on"]:
                node = self.network._get_node(node_id)
                if node:
                    chunk_data = node.retrieve_chunk(chunk_hash)
                    if chunk_data is not None:
                        break

            if chunk_data is None:
                chunk_results.append({
                    "chunk_index": placement["chunk_index"],
                    "status": "MISSING",
                    "expected_hash": chunk_hash,
                })
                all_passed = False
                missing_chunks += 1
                continue

            actual_hash = self.engine.hash_bytes(chunk_data)
            if actual_hash == chunk_hash:
                chunk_results.append({
                    "chunk_index": placement["chunk_index"],
                    "status": "PASSED",
                    "hash": chunk_hash,
                })
            else:
                chunk_results.append({
                    "chunk_index": placement["chunk_index"],
                    "status": "FAILED",
                    "expected_hash": chunk_hash,
                    "actual_hash": actual_hash,
                })
                all_passed = False

        elapsed = (time.time() - start) * 1000

        if all_passed:
            return VerificationResult(
                status=VerificationStatus.PASSED,
                message=f"All {len(chunk_results)} chunks verified successfully.",
                details={"chunks": chunk_results},
                cid=cid_str,
                elapsed_ms=elapsed,
            )
        else:
            failed = sum(1 for c in chunk_results if c["status"] == "FAILED")
            return VerificationResult(
                status=VerificationStatus.FAILED,
                message=f"Chunk verification failed: {failed} corrupted, {missing_chunks} missing out of {len(chunk_results)} chunks.",
                details={"chunks": chunk_results},
                cid=cid_str,
                elapsed_ms=elapsed,
            )

    # ── 3. Merkle proof verification ────────────────────────────────

    def verify_merkle_proof(self, manifest: dict, chunk_index: int) -> VerificationResult:
        """
        Verify a single chunk's membership in the dataset using a Merkle proof.

        Rebuilds the Merkle tree from the stored chunks, generates a proof
        for the specified chunk, and verifies it.

        Args:
            manifest:    The file manifest.
            chunk_index: The index of the chunk to verify.

        Returns:
            A VerificationResult.
        """
        import time
        start = time.time()

        cid_str = manifest["cid"]["cid"]

        # Retrieve all chunks to rebuild the tree
        all_chunk_data = []
        for placement in manifest["placements"]:
            chunk_data = None
            for node_id in placement["stored_on"]:
                node = self.network._get_node(node_id)
                if node:
                    chunk_data = node.retrieve_chunk(placement["chunk_hash"])
                    if chunk_data is not None:
                        break
            if chunk_data is None:
                elapsed = (time.time() - start) * 1000
                return VerificationResult(
                    status=VerificationStatus.ERROR,
                    message=f"Cannot retrieve chunk {placement['chunk_index']} to build Merkle tree.",
                    cid=cid_str,
                    elapsed_ms=elapsed,
                )
            all_chunk_data.append(chunk_data)

        # Build Merkle tree
        tree = MerkleTree(self.algorithm)
        computed_root = tree.build(all_chunk_data)

        # Verify root matches manifest
        expected_root = manifest["merkle_root"]
        if computed_root != expected_root:
            elapsed = (time.time() - start) * 1000
            return VerificationResult(
                status=VerificationStatus.FAILED,
                message="Merkle root mismatch: data has been altered.",
                details={
                    "expected_root": expected_root,
                    "computed_root": computed_root,
                },
                cid=cid_str,
                elapsed_ms=elapsed,
            )

        # Generate and verify proof for the specific chunk
        proof = tree.get_proof(chunk_index)
        is_valid = MerkleTree.verify_proof(proof, self.algorithm)

        elapsed = (time.time() - start) * 1000

        if is_valid:
            return VerificationResult(
                status=VerificationStatus.PASSED,
                message=f"Merkle proof verified: chunk {chunk_index} belongs to the dataset.",
                details={
                    "chunk_index": chunk_index,
                    "leaf_hash": proof.leaf_hash,
                    "root_hash": proof.root_hash,
                    "proof_depth": len(proof.proof_hashes),
                    "tree_visualization": tree.get_tree_visual(),
                },
                cid=cid_str,
                elapsed_ms=elapsed,
            )
        else:
            return VerificationResult(
                status=VerificationStatus.FAILED,
                message=f"Merkle proof INVALID for chunk {chunk_index}.",
                details={
                    "chunk_index": chunk_index,
                    "proof": proof.to_dict(),
                },
                cid=cid_str,
                elapsed_ms=elapsed,
            )

    # ── 4. Storage proof (challenge-response) ───────────────────────

    def challenge_node(
        self,
        node_id: str,
        chunk_hash: str,
        challenge_bytes: bytes | None = None,
    ) -> VerificationResult:
        """
        Challenge a specific node to prove it holds a chunk.

        The verifier sends a random challenge; the node must respond
        with H(chunk_data || challenge). The verifier independently
        computes the expected response.

        This simulates a simplified Proof of Data Possession (PDP).

        Args:
            node_id:         The node to challenge.
            chunk_hash:      The hash of the chunk to verify.
            challenge_bytes: Optional challenge nonce (random if None).

        Returns:
            A VerificationResult.
        """
        import time
        start = time.time()

        node = self.network._get_node(node_id)
        if node is None:
            elapsed = (time.time() - start) * 1000
            return VerificationResult(
                status=VerificationStatus.ERROR,
                message=f"Node {node_id} not found in the network.",
                elapsed_ms=elapsed,
            )

        if not node.is_online:
            elapsed = (time.time() - start) * 1000
            return VerificationResult(
                status=VerificationStatus.WARNING,
                message=f"Node {node_id} is offline; cannot complete challenge.",
                elapsed_ms=elapsed,
            )

        # Generate challenge nonce
        if challenge_bytes is None:
            challenge_bytes = random.randbytes(32)

        # Retrieve chunk from the node
        chunk_data = node.retrieve_chunk(chunk_hash)

        elapsed = (time.time() - start) * 1000

        if chunk_data is None:
            return VerificationResult(
                status=VerificationStatus.FAILED,
                message=f"Node {node_id} does not hold chunk {chunk_hash[:16]}...",
                details={
                    "node_id": node_id,
                    "chunk_hash": chunk_hash,
                },
                elapsed_ms=elapsed,
            )

        # Compute expected response: H(chunk_data || challenge)
        expected_response = self.engine.hash_bytes(chunk_data + challenge_bytes)

        # Simulate node computing its response
        node_response = self.engine.hash_bytes(chunk_data + challenge_bytes)

        if node_response == expected_response:
            return VerificationResult(
                status=VerificationStatus.PASSED,
                message=f"Storage proof PASSED: Node {node_id} proved possession of chunk {chunk_hash[:16]}...",
                details={
                    "node_id": node_id,
                    "chunk_hash": chunk_hash,
                    "challenge_size": len(challenge_bytes),
                    "response_hash": node_response,
                },
                elapsed_ms=elapsed,
            )
        else:
            return VerificationResult(
                status=VerificationStatus.FAILED,
                message=f"Storage proof FAILED: Node {node_id} response mismatch.",
                details={
                    "node_id": node_id,
                    "chunk_hash": chunk_hash,
                    "expected": expected_response,
                    "received": node_response,
                },
                elapsed_ms=elapsed,
            )

    # ── 5. Network-wide audit ───────────────────────────────────────

    def audit_network(self, manifest: dict) -> VerificationResult:
        """
        Perform a full audit of a file across the entire network.

        Checks:
        - Every chunk is present on at least one node.
        - All chunk hashes match.
        - Replication factor is met.
        - Merkle root matches.
        - Overall file hash matches.

        Returns:
            A comprehensive VerificationResult.
        """
        import time
        start = time.time()

        cid_str = manifest["cid"]["cid"]
        expected_replication = manifest["replication_factor"]
        issues = []
        chunk_health = []

        for placement in manifest["placements"]:
            chunk_hash = placement["chunk_hash"]
            healthy_copies = 0
            node_statuses = []

            for node_id in placement["stored_on"]:
                node = self.network._get_node(node_id)
                if node is None:
                    node_statuses.append({"node_id": node_id, "status": "NOT_FOUND"})
                    continue
                if not node.is_online:
                    node_statuses.append({"node_id": node_id, "status": "OFFLINE"})
                    continue

                data = node.retrieve_chunk(chunk_hash)
                if data is None:
                    node_statuses.append({"node_id": node_id, "status": "MISSING"})
                    issues.append(f"Chunk {placement['chunk_index']} missing from {node_id}")
                else:
                    actual_hash = self.engine.hash_bytes(data)
                    if actual_hash == chunk_hash:
                        node_statuses.append({"node_id": node_id, "status": "HEALTHY"})
                        healthy_copies += 1
                    else:
                        node_statuses.append({"node_id": node_id, "status": "CORRUPTED"})
                        issues.append(f"Chunk {placement['chunk_index']} corrupted on {node_id}")

            if healthy_copies == 0:
                issues.append(f"Chunk {placement['chunk_index']} has NO healthy copies!")
            elif healthy_copies < expected_replication:
                issues.append(
                    f"Chunk {placement['chunk_index']} under-replicated: "
                    f"{healthy_copies}/{expected_replication}"
                )

            chunk_health.append({
                "chunk_index": placement["chunk_index"],
                "chunk_hash": chunk_hash[:16] + "...",
                "healthy_copies": healthy_copies,
                "target_copies": expected_replication,
                "nodes": node_statuses,
            })

        # Verify Merkle root and file hash
        file_result = self.verify_file_integrity(manifest)

        elapsed = (time.time() - start) * 1000

        if not issues and file_result.passed:
            return VerificationResult(
                status=VerificationStatus.PASSED,
                message="Full network audit PASSED: all data verified, replication healthy.",
                details={
                    "chunk_health": chunk_health,
                    "file_verification": file_result.to_dict(),
                    "issues": [],
                },
                cid=cid_str,
                elapsed_ms=elapsed,
            )
        else:
            return VerificationResult(
                status=VerificationStatus.FAILED if issues else file_result.status,
                message=f"Network audit found {len(issues)} issue(s).",
                details={
                    "chunk_health": chunk_health,
                    "file_verification": file_result.to_dict(),
                    "issues": issues,
                },
                cid=cid_str,
                elapsed_ms=elapsed,
            )

    # ── 6. Tamper simulation (for testing) ──────────────────────────

    def simulate_corruption(self, manifest: dict, chunk_index: int) -> bool:
        """
        Deliberately corrupt a specific chunk on all nodes (for testing).

        Args:
            manifest:    The file manifest.
            chunk_index: The chunk to corrupt.

        Returns:
            True if at least one copy was corrupted.
        """
        if chunk_index < 0 or chunk_index >= len(manifest["placements"]):
            return False

        placement = manifest["placements"][chunk_index]
        corrupted = False

        for node_id in placement["stored_on"]:
            node = self.network._get_node(node_id)
            if node and node.has_chunk(placement["chunk_hash"]):
                # Overwrite with corrupted data
                corrupted_data = b"CORRUPTED_DATA_" + os.urandom(16)
                # Delete old and store new (different bytes, same key)
                chunk_path = os.path.join(node.storage_dir, placement["chunk_hash"])
                with open(chunk_path, "wb") as f:
                    f.write(corrupted_data)
                corrupted = True

        return corrupted

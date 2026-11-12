"""
Integrity Verifier — the core verification engine.

Provides multiple verification modes:
1. Full hash verification   — recompute the hash of retrieved data.
2. Chunk-level verification — verify each chunk individually.
3. Merkle proof verification — verify a single chunk belongs to a dataset.
4. Retrievability check — request a chunk from a node and verify its committed hash.
5. Sampled Merkle challenge — verify selected chunks against the committed root.
6. RSA-PDP challenge — verify possession of random sectors without downloading them.
7. Network-wide audit — verify all chunks across all nodes.
"""

import os
import json
import base64
import secrets
import binascii
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from urllib.error import URLError

from ..core.hashing import HashEngine, HashAlgorithm
from ..core.merkle import MerkleTree, MerkleProof
from ..core.chunker import FileChunker
from ..storage.network import StorageNetwork
from ..storage.encryption import StorageEncryptor, StorageEncryptionError
from ..storage.pdp import StoragePDP


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

    DEFAULT_PDP_SAMPLE_COUNT = 32

    def __init__(
        self,
        network: StorageNetwork,
        algorithm: HashAlgorithm = HashAlgorithm.SHA256,
        storage_encryptor: StorageEncryptor | None = None,
    ):
        self.network = network
        self.engine = HashEngine(algorithm)
        self.algorithm = algorithm
        self.storage_encryptor = storage_encryptor

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
            chunk_result = self.verify_chunks(manifest)
            has_corruption = any(
                chunk["status"] == "FAILED"
                for chunk in chunk_result.details.get("chunks", [])
            )
            return VerificationResult(
                status=VerificationStatus.FAILED if has_corruption else VerificationStatus.ERROR,
                message=(
                    "INTEGRITY VIOLATION: Stored chunk data does not match expected hashes."
                    if has_corruption
                    else "Could not retrieve all chunks from the network."
                ),
                details=chunk_result.details,
                cid=cid_str,
                elapsed_ms=elapsed,
            )

        if manifest.get("cid_hash_is_client_content"):
            if self.storage_encryptor is None:
                return VerificationResult(
                    status=VerificationStatus.ERROR,
                    message="Cannot verify migrated shared content without the storage key.",
                    cid=cid_str,
                    elapsed_ms=(time.time() - start) * 1000,
                )
            try:
                file_data = self.storage_encryptor.decrypt(file_data)
            except StorageEncryptionError:
                return VerificationResult(
                    status=VerificationStatus.FAILED,
                    message="Stored shared content failed its encryption authentication check.",
                    cid=cid_str,
                    elapsed_ms=(time.time() - start) * 1000,
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
            actual_hash = None

            # Prefer any healthy copy over corrupted replicas.
            for node_id in placement["stored_on"]:
                node = self.network._get_node(node_id)
                if node:
                    candidate = node.retrieve_chunk(chunk_hash)
                    if candidate is None:
                        continue
                    candidate_hash = self.engine.hash_bytes(candidate)
                    if candidate_hash == chunk_hash:
                        chunk_data = candidate
                        break
                    actual_hash = candidate_hash

            if chunk_data is None:
                if actual_hash is None:
                    chunk_results.append({
                        "chunk_index": placement["chunk_index"],
                        "status": "MISSING",
                        "expected_hash": chunk_hash,
                    })
                else:
                    chunk_results.append({
                        "chunk_index": placement["chunk_index"],
                        "status": "FAILED",
                        "expected_hash": chunk_hash,
                        "actual_hash": actual_hash,
                    })
                all_passed = False
                if actual_hash is None:
                    missing_chunks += 1
                continue

            chunk_results.append({
                "chunk_index": placement["chunk_index"],
                "status": "PASSED",
                "hash": chunk_hash,
            })

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

    # ── 4. Node retrievability ──────────────────────────────────────

    def check_node_retrievability(
        self,
        node_id: str,
        manifest: dict,
        sample_count: int = 1,
    ) -> VerificationResult:
        """
        Sample chunks assigned to one node and verify their committed hashes.

        Sampled chunks are downloaded in full from the node's HTTP service when
        configured, or directly from the local node in simulation mode. This is
        a probabilistic availability check, not a cryptographic proof of
        possession or long-term storage.

        Args:
            node_id:     The node to check.
            manifest:    The manifest whose placements define chunks for this node.
            sample_count: Number of random chunks to retrieve and verify.

        Returns:
            A VerificationResult.
        """
        import time
        start = time.time()
        if (
            not isinstance(sample_count, int)
            or isinstance(sample_count, bool)
            or sample_count < 1
        ):
            raise ValueError("Sample count must be a positive integer.")

        node = self.network._get_node(node_id)
        if node is None:
            elapsed = (time.time() - start) * 1000
            return VerificationResult(
                status=VerificationStatus.ERROR,
                message=f"Node {node_id} not found in the network.",
                elapsed_ms=elapsed,
            )

        if node_id not in self.network.node_urls and not node.is_online:
            elapsed = (time.time() - start) * 1000
            return VerificationResult(
                status=VerificationStatus.WARNING,
                message=f"Node {node_id} is offline; retrievability cannot be checked.",
                elapsed_ms=elapsed,
            )

        eligible = [
            placement for placement in manifest["placements"]
            if node_id in placement["stored_on"]
        ]
        if not eligible:
            return VerificationResult(
                status=VerificationStatus.ERROR,
                message=f"Manifest has no chunks assigned to node {node_id}.",
                cid=manifest["cid"]["cid"],
                elapsed_ms=(time.time() - start) * 1000,
            )
        if sample_count > len(eligible):
            raise ValueError(
                f"Sample count {sample_count} exceeds the {len(eligible)} chunks "
                f"assigned to node {node_id}."
            )

        samples = secrets.SystemRandom().sample(eligible, sample_count)
        chunk_results = []
        all_passed = True
        for placement in samples:
            chunk_hash = placement["chunk_hash"]
            try:
                chunk_data = self.network.retrieve_chunk_from_node(
                    node_id,
                    chunk_hash,
                    expected_size=placement["chunk_size"],
                )
            except (URLError, TimeoutError, OSError) as error:
                return VerificationResult(
                    status=VerificationStatus.WARNING,
                    message=f"Could not reach node {node_id} retrieval service: {error}",
                    details={
                        "node_id": node_id,
                        "samples_checked": chunk_results,
                    },
                    cid=manifest["cid"]["cid"],
                    elapsed_ms=(time.time() - start) * 1000,
                )

            actual_hash = self.engine.hash_bytes(chunk_data) if chunk_data is not None else None
            passed = actual_hash == chunk_hash
            all_passed = all_passed and passed
            chunk_results.append({
                "chunk_index": placement["chunk_index"],
                "chunk_hash": chunk_hash,
                "actual_hash": actual_hash,
                "bytes_returned": len(chunk_data) if chunk_data is not None else 0,
                "status": "PASSED" if passed else "FAILED",
            })

        elapsed = (time.time() - start) * 1000
        if all_passed:
            return VerificationResult(
                status=VerificationStatus.PASSED,
                message=(
                    f"Sampled retrievability check PASSED: Node {node_id} returned "
                    f"{sample_count} chunk(s) matching their committed hashes."
                ),
                details={
                    "node_id": node_id,
                    "sample_count": sample_count,
                    "samples_checked": chunk_results,
                },
                cid=manifest["cid"]["cid"],
                elapsed_ms=elapsed,
            )
        else:
            return VerificationResult(
                status=VerificationStatus.FAILED,
                message=(
                    f"Sampled retrievability check FAILED: Node {node_id} could not "
                    "return one or more sampled chunks matching their committed hashes."
                ),
                details={
                    "node_id": node_id,
                    "sample_count": sample_count,
                    "samples_checked": chunk_results,
                },
                cid=manifest["cid"]["cid"],
                elapsed_ms=elapsed,
            )

    # ── 5. Sampled Merkle challenge ─────────────────────────────────

    def challenge_node(
        self,
        node_id: str,
        manifest: dict,
        sample_count: int = 1,
    ) -> VerificationResult:
        """
        Ask a node for random chunks and their Merkle paths, then verify them.

        This is a sampled retrievability challenge, not a formal PDP/PoR proof.
        """
        import time
        start = time.time()

        if (
            not isinstance(sample_count, int)
            or isinstance(sample_count, bool)
            or not 1 <= sample_count <= 64
        ):
            raise ValueError("Sample count must be an integer from 1 to 64.")

        node = self.network._get_node(node_id)
        if node is None:
            return VerificationResult(
                status=VerificationStatus.ERROR,
                message=f"Node {node_id} not found in the network.",
                cid=manifest.get("cid", {}).get("cid"),
                elapsed_ms=(time.time() - start) * 1000,
            )

        if node_id not in self.network.node_urls and not node.is_online:
            return VerificationResult(
                status=VerificationStatus.WARNING,
                message=f"Node {node_id} is offline; cannot complete the challenge.",
                cid=manifest.get("cid", {}).get("cid"),
                elapsed_ms=(time.time() - start) * 1000,
            )

        eligible = [
            placement for placement in manifest.get("placements", [])
            if node_id in placement.get("stored_on", [])
        ]
        if not eligible:
            return VerificationResult(
                status=VerificationStatus.ERROR,
                message=f"Manifest has no chunks assigned to node {node_id}.",
                cid=manifest.get("cid", {}).get("cid"),
                elapsed_ms=(time.time() - start) * 1000,
            )
        if sample_count > len(eligible):
            raise ValueError(
                f"Sample count {sample_count} exceeds the {len(eligible)} chunks "
                f"assigned to node {node_id}."
            )

        nonce = secrets.token_bytes(32)
        root_hash = manifest.get("merkle_root")
        challenges = [
            {
                "chunk_hash": placement["chunk_hash"],
                "chunk_index": placement["chunk_index"],
                "merkle_root": root_hash,
            }
            for placement in secrets.SystemRandom().sample(eligible, sample_count)
        ]

        try:
            response = self.network.challenge_chunks(node_id, nonce, challenges)
        except (URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as error:
            return VerificationResult(
                status=VerificationStatus.WARNING,
                message=f"Could not complete the challenge with node {node_id}: {error}",
                details={
                    "node_id": node_id,
                    "sample_count": sample_count,
                },
                cid=manifest.get("cid", {}).get("cid"),
                elapsed_ms=(time.time() - start) * 1000,
            )

        sample_results = []
        valid = (
            isinstance(response, dict)
            and response.get("nonce_hex") == nonce.hex()
            and isinstance(response.get("chunks"), list)
            and len(response["chunks"]) == len(challenges)
        )

        if valid:
            for challenge, returned in zip(challenges, response["chunks"]):
                result = {
                    "chunk_index": challenge["chunk_index"],
                    "chunk_hash": challenge["chunk_hash"],
                    "status": "FAILED",
                }
                proof_depth = 0
                if (
                    not isinstance(returned, dict)
                    or returned.get("chunk_hash") != challenge["chunk_hash"]
                    or not isinstance(returned.get("chunk_index"), int)
                    or isinstance(returned.get("chunk_index"), bool)
                    or returned.get("chunk_index") != challenge["chunk_index"]
                    or not isinstance(returned.get("data_base64"), str)
                ):
                    sample_results.append(result)
                    valid = False
                    continue

                try:
                    chunk_data = base64.b64decode(returned["data_base64"], validate=True)
                    proof_data = returned["proof"]
                    proof = MerkleProof.from_dict(proof_data)
                    proof_depth = len(proof.proof_hashes)
                    hash_matches = (
                        len(chunk_data) == next(
                            placement["chunk_size"]
                            for placement in eligible
                            if placement["chunk_index"] == challenge["chunk_index"]
                        )
                        and self.engine.hash_bytes(chunk_data) == challenge["chunk_hash"]
                    )
                    proof_valid = (
                        proof.leaf_index == challenge["chunk_index"]
                        and proof.leaf_hash == challenge["chunk_hash"]
                        and proof.root_hash == root_hash
                        and MerkleTree.verify_proof(proof, self.algorithm)
                    )
                except (KeyError, StopIteration, TypeError, ValueError, binascii.Error):
                    hash_matches = False
                    proof_valid = False

                result["proof_depth"] = proof_depth
                result["status"] = "PASSED" if hash_matches and proof_valid else "FAILED"
                sample_results.append(result)
                valid = valid and hash_matches and proof_valid
        else:
            valid = False

        elapsed = (time.time() - start) * 1000
        status = VerificationStatus.PASSED if valid else VerificationStatus.FAILED
        return VerificationResult(
            status=status,
            message=(
                f"Sampled Merkle challenge {'PASSED' if valid else 'FAILED'}: "
                f"Node {node_id} returned {len(sample_results)}/{sample_count} "
                "chunks with valid inclusion proofs."
            ),
            details={
                "node_id": node_id,
                "sample_count": sample_count,
                "nonce_hex": nonce.hex(),
                "merkle_root": root_hash,
                "samples_checked": sample_results,
            },
            cid=manifest.get("cid", {}).get("cid"),
            elapsed_ms=elapsed,
        )

    # ── 6. RSA proof-of-data-possession ──────────────────────────────

    def prove_node_possession(
        self,
        node_id: str,
        manifest: dict,
        sample_count: int | None = None,
    ) -> VerificationResult:
        """Verify an RSA-PDP aggregate proof without downloading challenged sectors."""
        import time
        start = time.time()
        cid_str = manifest.get("cid", {}).get("cid")
        pdp_metadata = manifest.get("pdp")

        if not isinstance(pdp_metadata, dict) or pdp_metadata.get("scheme") != StoragePDP.SCHEME:
            return VerificationResult(
                status=VerificationStatus.ERROR,
                message="This file has no RSA-PDP tags; upload it again to enable PDP challenges.",
                cid=cid_str,
                elapsed_ms=(time.time() - start) * 1000,
            )
        if (
            sample_count is not None
            and (
                not isinstance(sample_count, int)
                or isinstance(sample_count, bool)
                or not 1 <= sample_count <= 64
            )
        ):
            raise ValueError("Sample count must be an integer from 1 to 64.")

        node = self.network._get_node(node_id)
        if node is None:
            return VerificationResult(
                status=VerificationStatus.ERROR,
                message=f"Node {node_id} not found in the network.",
                cid=cid_str,
                elapsed_ms=(time.time() - start) * 1000,
            )
        if node_id not in self.network.node_urls and not node.is_online:
            return VerificationResult(
                status=VerificationStatus.WARNING,
                message=f"Node {node_id} is offline; cannot complete the PDP challenge.",
                cid=cid_str,
                elapsed_ms=(time.time() - start) * 1000,
            )

        file_id = cid_str
        total_size = manifest.get("total_size")
        sector_size = pdp_metadata.get("sector_size")
        chunk_size = pdp_metadata.get("storage_chunk_size")
        sector_count = pdp_metadata.get("sector_count")
        if (
            not isinstance(file_id, str)
            or not file_id
            or pdp_metadata.get("file_id") != file_id
            or not isinstance(total_size, int)
            or isinstance(total_size, bool)
            or total_size < 0
            or sector_size != StoragePDP.SECTOR_SIZE
            or not isinstance(chunk_size, int)
            or isinstance(chunk_size, bool)
            or chunk_size <= 0
            or chunk_size % sector_size
            or sector_count != StoragePDP.block_count(total_size)
            or not isinstance(pdp_metadata.get("n"), str)
            or not re.fullmatch(r"[0-9a-f]{512,1024}", pdp_metadata["n"])
            or not isinstance(pdp_metadata.get("e"), str)
            or not re.fullmatch(r"[0-9a-f]{1,8}", pdp_metadata["e"])
            or not isinstance(pdp_metadata.get("u"), str)
            or not re.fullmatch(r"[0-9a-f]{1,1024}", pdp_metadata["u"])
        ):
            return VerificationResult(
                status=VerificationStatus.ERROR,
                message="Manifest contains invalid RSA-PDP parameters.",
                cid=cid_str,
                elapsed_ms=(time.time() - start) * 1000,
            )

        placements = {
            placement["chunk_index"]: placement
            for placement in manifest.get("placements", [])
        }
        eligible = []
        for index in range(sector_count):
            data_offset = index * sector_size
            chunk_index = data_offset // chunk_size
            placement = placements.get(chunk_index)
            if placement is None or node_id not in placement.get("stored_on", []):
                continue
            eligible.append({
                "sector_index": index,
                "chunk_hash": placement["chunk_hash"],
                "chunk_offset": data_offset - chunk_index * chunk_size,
                "length": min(sector_size, max(0, total_size - data_offset)),
            })

        if not eligible:
            return VerificationResult(
                status=VerificationStatus.ERROR,
                message=f"Manifest has no PDP sectors assigned to node {node_id}.",
                cid=cid_str,
                elapsed_ms=(time.time() - start) * 1000,
            )
        if sample_count is None:
            sample_count = min(self.DEFAULT_PDP_SAMPLE_COUNT, len(eligible))
        if sample_count > len(eligible):
            raise ValueError(
                f"Sample count {sample_count} exceeds the {len(eligible)} sectors "
                f"assigned to node {node_id}."
            )

        nonce = secrets.token_hex(32)
        selected = secrets.SystemRandom().sample(eligible, sample_count)
        challenges = [
            {
                **sector,
                "coefficient_hex": format(
                    secrets.randbits(StoragePDP.COEFFICIENT_BITS) or 1,
                    "x",
                ),
            }
            for sector in selected
        ]
        public_challenges = [
            {
                "sector_index": item["sector_index"],
                "coefficient": int(item["coefficient_hex"], 16),
            }
            for item in challenges
        ]
        payload = {
            "file_id": file_id,
            "nonce_hex": nonce,
            "n": pdp_metadata.get("n"),
            "sectors": challenges,
        }

        try:
            response = self.network.request_pdp_proof(node_id, payload)
        except (URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as error:
            return VerificationResult(
                status=VerificationStatus.WARNING,
                message=f"Could not complete the PDP challenge with node {node_id}: {error}",
                details={"node_id": node_id, "sample_count": sample_count},
                cid=cid_str,
                elapsed_ms=(time.time() - start) * 1000,
            )

        proof_valid = False
        if (
            isinstance(response, dict)
            and response.get("nonce_hex") == nonce
            and isinstance(response.get("sector_count"), int)
            and not isinstance(response.get("sector_count"), bool)
            and response.get("sector_count") == sample_count
            and isinstance(response.get("sigma_hex"), str)
            and isinstance(response.get("mu_hex"), str)
            and re.fullmatch(r"[0-9a-f]{1,1024}", response["sigma_hex"])
            and re.fullmatch(r"[0-9a-f]{1,296}", response["mu_hex"])
        ):
            try:
                sigma = int(response["sigma_hex"], 16)
                mu = int(response["mu_hex"], 16)
            except ValueError:
                sigma = mu = -1
            proof_valid = StoragePDP.verify_aggregate_proof(
                file_id,
                public_challenges,
                sigma,
                mu,
                pdp_metadata,
            )

        elapsed = (time.time() - start) * 1000
        status = VerificationStatus.PASSED if proof_valid else VerificationStatus.FAILED
        return VerificationResult(
            status=status,
            message=(
                f"RSA-PDP challenge {'PASSED' if proof_valid else 'FAILED'}: "
                f"Node {node_id} returned an aggregate proof for "
                f"{sample_count} sector(s)."
            ),
            details={
                "node_id": node_id,
                "scheme": StoragePDP.SCHEME,
                "sample_count": sample_count,
                "sector_indices": [item["sector_index"] for item in challenges],
                "nonce_hex": nonce,
                "proof_valid": proof_valid,
                "data_bytes_returned": 0,
            },
            cid=cid_str,
            elapsed_ms=elapsed,
        )

    # ── 7. Network-wide audit ───────────────────────────────────────

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

    # ── 8. Tamper simulation (for testing) ──────────────────────────

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

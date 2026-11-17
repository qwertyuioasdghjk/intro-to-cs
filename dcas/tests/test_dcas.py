"""
Comprehensive test suite for the DCAS system.

Tests all core components: hashing, CID generation, chunking,
Merkle trees, storage network, integrity verification, and metadata.
"""

import io
import os
import sys
import json
import shutil
import subprocess
import tempfile
import threading
import unittest
from contextlib import ExitStack
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import urlsplit

from py_ecc.optimized_bls12_381 import G1, add, multiply

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dcas.core.hashing import HashEngine, HashAlgorithm
from dcas.core.cid import CIDGenerator, ContentIdentifier
from dcas.core.chunker import FileChunker, Chunk
from dcas.core.merkle import MerkleTree, MerkleProof
from dcas.storage.node import StorageNode
from dcas.storage.network import StorageNetwork
from dcas.storage.node_server import create_node_app
from dcas.storage.pdp import StoragePDP
from dcas.storage.encryption import StorageEncryptor
from dcas.storage.erasure import XorErasureCode
import dcas.storage.por as por_module
from dcas.storage.por import PairingPoR
from dcas.verifier.verifier import IntegrityVerifier, VerificationStatus
from dcas.database.metadata import MetadataStore
from dcas.database.mongo_metadata import MongoMetadataStore
from dcas.database.protocols import MetadataStoreProtocol

NODE_AUTH_TOKEN = "test-node-auth-token-that-is-at-least-32-chars"


class TestHashEngine(unittest.TestCase):
    """Tests for the cryptographic hashing engine."""

    def setUp(self):
        self.engine = HashEngine(HashAlgorithm.SHA256)

    def test_hash_deterministic(self):
        """Same input always produces the same hash."""
        data = b"Hello, World!"
        h1 = self.engine.hash_bytes(data)
        h2 = self.engine.hash_bytes(data)
        self.assertEqual(h1, h2)

    def test_hash_different_inputs(self):
        """Different inputs produce different hashes."""
        h1 = self.engine.hash_bytes(b"Hello")
        h2 = self.engine.hash_bytes(b"Hello!")
        self.assertNotEqual(h1, h2)

    def test_hash_empty(self):
        """Empty input produces a valid hash."""
        h = self.engine.hash_bytes(b"")
        self.assertEqual(len(h), 64)  # SHA-256 = 64 hex chars

    def test_verify_bytes_pass(self):
        """Verification succeeds for matching data."""
        data = b"Test data"
        h = self.engine.hash_bytes(data)
        self.assertTrue(self.engine.verify_bytes(data, h))

    def test_verify_bytes_fail(self):
        """Verification fails for non-matching data."""
        data = b"Test data"
        h = self.engine.hash_bytes(data)
        self.assertFalse(self.engine.verify_bytes(b"Wrong data", h))

    def test_hash_file(self):
        """Hash a file on disk."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"File content for hashing")
            filepath = f.name
        try:
            h = self.engine.hash_file(filepath)
            expected = self.engine.hash_bytes(b"File content for hashing")
            self.assertEqual(h, expected)
        finally:
            os.unlink(filepath)

    def test_multiple_algorithms(self):
        """Different algorithms produce different hashes."""
        data = b"Multi-algorithm test"
        h256 = HashEngine(HashAlgorithm.SHA256).hash_bytes(data)
        h512 = HashEngine(HashAlgorithm.SHA512).hash_bytes(data)
        h3 = HashEngine(HashAlgorithm.SHA3_256).hash_bytes(data)
        # All should be different from each other
        self.assertNotEqual(h256, h512)
        self.assertNotEqual(h256, h3)
        self.assertNotEqual(h512, h3)


class TestCIDGenerator(unittest.TestCase):
    """Tests for Content Identifier generation."""

    def setUp(self):
        self.gen = CIDGenerator(HashAlgorithm.SHA256)

    def test_generate_cid(self):
        """Generate a CID from bytes."""
        cid = self.gen.generate(b"Test data")
        self.assertIn("dcas-v1-sha256", cid.cid_string)
        self.assertEqual(cid.size, 9)
        self.assertEqual(cid.algorithm, "sha256")

    def test_cid_same_content(self):
        """Same content produces the same CID hash."""
        cid1 = self.gen.generate(b"Same")
        cid2 = self.gen.generate(b"Same")
        self.assertEqual(cid1.hash_digest, cid2.hash_digest)

    def test_cid_different_content(self):
        """Different content produces different CID hashes."""
        cid1 = self.gen.generate(b"One")
        cid2 = self.gen.generate(b"Two")
        self.assertNotEqual(cid1.hash_digest, cid2.hash_digest)

    def test_cid_serialization(self):
        """CID can be serialized and deserialized."""
        cid = self.gen.generate(b"Serialization test")
        json_str = cid.to_json()
        restored = ContentIdentifier.from_json(json_str)
        self.assertEqual(cid.hash_digest, restored.hash_digest)
        self.assertEqual(cid.algorithm, restored.algorithm)
        self.assertEqual(cid.size, restored.size)

    def test_cid_from_file(self):
        """Generate CID from a file."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"File CID test")
            filepath = f.name
        try:
            cid = self.gen.generate_from_file(filepath)
            expected = self.gen.generate(b"File CID test")
            self.assertEqual(cid.hash_digest, expected.hash_digest)
        finally:
            os.unlink(filepath)


class TestFileChunker(unittest.TestCase):
    """Tests for file chunking."""

    def test_chunk_small_data(self):
        """Data smaller than chunk size → 1 chunk."""
        chunker = FileChunker(chunk_size=1024)
        chunks = chunker.chunk_bytes(b"Small data")
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0].data, b"Small data")

    def test_chunk_empty_data(self):
        """Empty data is represented by one empty chunk."""
        chunker = FileChunker(chunk_size=1024)
        chunks = chunker.chunk_bytes(b"")
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0].data, b"")
        self.assertEqual(chunks[0].size, 0)

    def test_chunk_exact_multiple(self):
        """Data that's an exact multiple of chunk size."""
        chunker = FileChunker(chunk_size=10)
        chunks = chunker.chunk_bytes(b"A" * 30)
        self.assertEqual(len(chunks), 3)
        for c in chunks:
            self.assertEqual(c.size, 10)

    def test_chunk_with_remainder(self):
        """Data with a remainder after chunking."""
        chunker = FileChunker(chunk_size=10)
        chunks = chunker.chunk_bytes(b"A" * 25)
        self.assertEqual(len(chunks), 3)
        self.assertEqual(chunks[-1].size, 5)

    def test_reassembly(self):
        """Chunks can be reassembled to original data."""
        data = b"Hello, this is a test of chunking and reassembly!"
        chunker = FileChunker(chunk_size=10)
        chunks = chunker.chunk_bytes(data)
        reassembled = FileChunker.reassemble(chunks)
        self.assertEqual(reassembled, data)

    def test_chunk_hashes_unique(self):
        """Different chunks have different hashes."""
        chunker = FileChunker(chunk_size=10)
        chunks = chunker.chunk_bytes(b"A" * 10 + b"B" * 10)
        self.assertNotEqual(chunks[0].hash, chunks[1].hash)

    def test_chunk_offsets(self):
        """Chunk offsets are correct."""
        chunker = FileChunker(chunk_size=10)
        chunks = chunker.chunk_bytes(b"X" * 35)
        self.assertEqual(chunks[0].offset, 0)
        self.assertEqual(chunks[1].offset, 10)
        self.assertEqual(chunks[2].offset, 20)
        self.assertEqual(chunks[3].offset, 30)


class TestMerkleTree(unittest.TestCase):
    """Tests for Merkle tree construction and verification."""

    def test_build_tree(self):
        """Build a Merkle tree and get a root hash."""
        tree = MerkleTree()
        root = tree.build([b"A", b"B", b"C", b"D"])
        self.assertIsNotNone(root)
        self.assertEqual(tree.leaf_count, 4)

    def test_deterministic_root(self):
        """Same data → same root hash."""
        tree1 = MerkleTree()
        tree2 = MerkleTree()
        root1 = tree1.build([b"X", b"Y", b"Z"])
        root2 = tree2.build([b"X", b"Y", b"Z"])
        self.assertEqual(root1, root2)

    def test_different_data_different_root(self):
        """Different data → different root hash."""
        tree1 = MerkleTree()
        tree2 = MerkleTree()
        root1 = tree1.build([b"A", b"B"])
        root2 = tree2.build([b"A", b"C"])
        self.assertNotEqual(root1, root2)

    def test_proof_valid(self):
        """Valid proof verifies correctly."""
        tree = MerkleTree()
        tree.build([b"Block0", b"Block1", b"Block2", b"Block3"])
        for i in range(4):
            proof = tree.get_proof(i)
            self.assertTrue(MerkleTree.verify_proof(proof))

    def test_proof_invalid_after_tamper(self):
        """Proof fails if the leaf hash is altered."""
        tree = MerkleTree()
        tree.build([b"Block0", b"Block1", b"Block2", b"Block3"])
        proof = tree.get_proof(0)
        # Tamper with the leaf hash
        proof.leaf_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        self.assertFalse(MerkleTree.verify_proof(proof))

    def test_single_block(self):
        """Tree with a single block works."""
        tree = MerkleTree()
        root = tree.build([b"OnlyBlock"])
        self.assertIsNotNone(root)
        proof = tree.get_proof(0)
        self.assertTrue(MerkleTree.verify_proof(proof))

    def test_odd_number_of_blocks(self):
        """Tree with odd number of blocks (padding)."""
        tree = MerkleTree()
        root = tree.build([b"A", b"B", b"C"])
        self.assertIsNotNone(root)
        for i in range(3):
            proof = tree.get_proof(i)
            self.assertTrue(MerkleTree.verify_proof(proof))

    def test_tree_visualization(self):
        """Tree visualization produces output."""
        tree = MerkleTree()
        tree.build([b"A", b"B", b"C", b"D"])
        vis = tree.get_tree_visual()
        self.assertIn("Root:", vis)
        self.assertIn("leaf", vis)

    def test_empty_tree_raises(self):
        """Building with no blocks raises ValueError."""
        tree = MerkleTree()
        with self.assertRaises(ValueError):
            tree.build([])


class TestStorageNode(unittest.TestCase):
    """Tests for individual storage nodes."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.node = StorageNode("test-node", os.path.join(self.test_dir, "node"))

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_store_and_retrieve(self):
        """Store and retrieve a chunk."""
        self.assertTrue(self.node.store_chunk("hash1", b"data1"))
        self.assertEqual(self.node.retrieve_chunk("hash1"), b"data1")

    def test_retrieve_missing(self):
        """Retrieving a non-existent chunk returns None."""
        self.assertIsNone(self.node.retrieve_chunk("nonexistent"))

    def test_has_chunk(self):
        """has_chunk reports correctly."""
        self.node.store_chunk("hash1", b"data")
        self.assertTrue(self.node.has_chunk("hash1"))
        self.assertFalse(self.node.has_chunk("hash2"))

    def test_delete_chunk(self):
        """Deleting a chunk removes it."""
        self.node.store_chunk("hash1", b"data")
        self.assertTrue(self.node.delete_chunk("hash1"))
        self.assertFalse(self.node.has_chunk("hash1"))

    def test_offline_node(self):
        """Offline node refuses operations."""
        self.node.is_online = False
        self.assertFalse(self.node.store_chunk("h", b"d"))
        self.assertIsNone(self.node.retrieve_chunk("h"))
        self.assertFalse(self.node.has_chunk("h"))

    def test_capacity_limit(self):
        """Node with capacity refuses when full."""
        node = StorageNode("limited", os.path.join(self.test_dir, "limited"), capacity=10)
        self.assertTrue(node.store_chunk("h1", b"12345"))
        self.assertFalse(node.store_chunk("h2", b"123456"))  # Would exceed 10 bytes

    def test_used_space_tracks_store_replace_delete_and_reload(self):
        self.node.store_chunk("first", b"12345")
        self.node.store_chunk("second", b"abc")
        self.assertEqual(self.node.used_space, 8)

        self.node.store_chunk("first", b"12")
        self.assertEqual(self.node.used_space, 5)

        reloaded = StorageNode("test-node", self.node.storage_dir)
        self.assertEqual(reloaded.used_space, 5)
        self.assertTrue(reloaded.delete_chunk("second"))
        self.assertEqual(reloaded.used_space, 2)

    def test_chunk_stores_batch_metadata_persistence(self):
        with patch.object(
            self.node,
            "_save_metadata",
            wraps=self.node._save_metadata,
        ) as save_metadata:
            with self.node.batch_metadata_writes():
                self.assertTrue(self.node.store_chunk("first", b"one"))
                self.assertTrue(self.node.store_chunk("second", b"two"))
                save_metadata.assert_not_called()
            save_metadata.assert_called_once()

        reloaded = StorageNode("test-node", self.node.storage_dir)
        self.assertEqual(reloaded.chunk_count, 2)
        self.assertEqual(reloaded.used_space, 6)

    def test_por_tags_are_batched_and_conflicts_do_not_partially_write(self):
        self.node.store_chunk("por-hash", b"shard")
        tags = {0: "tag-0", 1: "tag-1"}
        with patch.object(self.node, "_save_metadata") as save_metadata:
            self.assertEqual(
                self.node.store_por_tags(
                    "por-hash", "file", self.node.node_id, 0, tags
                ),
                [0, 1],
            )
            save_metadata.assert_called_once()

            save_metadata.reset_mock()
            self.assertEqual(
                self.node.store_por_tags(
                    "por-hash", "file", self.node.node_id, 0, tags
                ),
                [],
            )
            save_metadata.assert_not_called()

            with self.assertRaisesRegex(ValueError, "Conflicting PoR tag"):
                self.node.store_por_tags(
                    "por-hash",
                    "file",
                    self.node.node_id,
                    0,
                    {2: "new-tag", 1: "conflicting-tag"},
                )
            save_metadata.assert_not_called()
            self.assertNotIn(
                "2",
                self.node._metadata["por-hash"]["por_tags"]["file"][
                    self.node.node_id
                ]["0"],
            )

    def test_list_chunks(self):
        """List stored chunks."""
        self.node.store_chunk("h1", b"d1")
        self.node.store_chunk("h2", b"d2")
        chunks = self.node.list_chunks()
        self.assertIn("h1", chunks)
        self.assertIn("h2", chunks)

    def test_clear(self):
        """Clear all chunks."""
        self.node.store_chunk("h1", b"d1")
        self.node.store_chunk("h2", b"d2")
        self.node.clear()
        self.assertEqual(self.node.chunk_count, 0)


class TestStorageNetwork(unittest.TestCase):
    """Tests for the decentralized storage network."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.network = StorageNetwork(
            base_dir=os.path.join(self.test_dir, "net"),
            num_nodes=4,
            replication_factor=2,
        )

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_network_creation(self):
        """Network has the expected number of nodes."""
        self.assertEqual(len(self.network.nodes), 4)

    def test_store_and_retrieve(self):
        """Store and retrieve data through the network."""
        data = b"Network test data"
        manifest = self.network.store_bytes(data, filename="test.txt")
        retrieved = self.network.retrieve_file(manifest)
        self.assertEqual(retrieved, data)

    def test_bulk_store_batches_node_metadata_writes(self):
        self.network.chunker.chunk_size = 2
        with ExitStack() as stack:
            save_metadata = [
                stack.enter_context(
                    patch.object(
                        node,
                        "_save_metadata",
                        wraps=node._save_metadata,
                    )
                )
                for node in self.network.nodes
            ]
            manifest = self.network.store_bytes(b"0123456789")

        self.assertEqual(manifest["chunk_count"], 5)
        self.assertGreater(sum(mock.call_count for mock in save_metadata), 0)
        self.assertLessEqual(
            sum(mock.call_count for mock in save_metadata),
            2 * len(self.network.nodes),
        )

    def test_empty_data_round_trip(self):
        """Empty content can be stored and retrieved."""
        manifest = self.network.store_bytes(b"")
        self.assertEqual(self.network.retrieve_file(manifest), b"")

    def test_retrieve_uses_healthy_replica_after_corruption(self):
        """A corrupted replica is skipped when another copy is healthy."""
        data = b"Replicated data"
        manifest = self.network.store_bytes(data)
        placement = manifest["placements"][0]
        first_node = self.network._get_node(placement["stored_on"][0])
        self.assertIsNotNone(first_node)
        first_node.store_chunk(placement["chunk_hash"], b"corrupted data")

        self.assertEqual(self.network.retrieve_file(manifest), data)
        result = IntegrityVerifier(self.network).verify_file_integrity(manifest)
        self.assertEqual(result.status, VerificationStatus.PASSED)

    def test_insufficient_replication_rolls_back_new_chunks(self):
        """Failed replication leaves no partial chunks on the nodes."""
        self.network.chunker.chunk_size = 4
        for node in self.network.nodes:
            node.capacity = 4

        with self.assertRaises(RuntimeError):
            self.network.store_bytes(b"123456789012")

        for node in self.network.nodes:
            self.assertEqual(node.list_chunks(), [])

    def test_repeated_chunk_does_not_consume_capacity_twice(self):
        """Identical content-addressed chunks reuse their stored bytes."""
        self.network.chunker.chunk_size = 4
        for node in self.network.nodes:
            node.capacity = 4

        manifest = self.network.store_bytes(b"abcdabcd")

        self.assertEqual(self.network.retrieve_file(manifest), b"abcdabcd")
        self.assertEqual([node.used_space for node in self.network.nodes], [4, 4, 0, 0])

    def test_manifest_structure(self):
        """Manifest has required fields."""
        manifest = self.network.store_bytes(b"Test", filename="f.txt")
        self.assertIn("cid", manifest)
        self.assertIn("filename", manifest)
        self.assertIn("merkle_root", manifest)
        self.assertIn("placements", manifest)
        self.assertEqual(manifest["filename"], "f.txt")

    def test_replication(self):
        """Each chunk is stored on multiple nodes."""
        manifest = self.network.store_bytes(b"Replicated data")
        for p in manifest["placements"]:
            self.assertGreaterEqual(len(p["stored_on"]), 2)

    def test_node_failure_recovery(self):
        """Data is still retrievable after a node failure."""
        data = b"Resilient data"
        manifest = self.network.store_bytes(data)
        # Fail one node
        self.network.simulate_node_failure("node-000")
        retrieved = self.network.retrieve_file(manifest)
        self.assertEqual(retrieved, data)
        # Recover
        self.network.simulate_node_recovery("node-000")

    def test_add_and_remove_node(self):
        """Add and remove nodes dynamically."""
        node = self.network.add_node("node-extra")
        self.assertEqual(len(self.network.nodes), 5)
        self.network.remove_node("node-extra")
        self.assertEqual(len(self.network.nodes), 4)

    def test_network_status(self):
        """Network status reports correctly."""
        status = self.network.get_network_status()
        self.assertEqual(status["total_nodes"], 4)
        self.assertEqual(status["online_nodes"], 4)


class TestIntegrityVerifier(unittest.TestCase):
    """Tests for the integrity verification engine."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.network = StorageNetwork(
            base_dir=os.path.join(self.test_dir, "net"),
            num_nodes=4,
            replication_factor=2,
        )
        self.verifier = IntegrityVerifier(self.network)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_verify_intact_file(self):
        """Verification passes for unaltered file."""
        manifest = self.network.store_bytes(b"Intact data")
        result = self.verifier.verify_file_integrity(manifest)
        self.assertEqual(result.status, VerificationStatus.PASSED)

    def test_verify_corrupted_file(self):
        """Verification fails for corrupted file."""
        manifest = self.network.store_bytes(b"Original data")
        self.verifier.simulate_corruption(manifest, 0)
        result = self.verifier.verify_file_integrity(manifest)
        self.assertEqual(result.status, VerificationStatus.FAILED)

    def test_verify_chunks(self):
        """Chunk-level verification passes for intact data."""
        manifest = self.network.store_bytes(b"Chunk test data " * 100)
        result = self.verifier.verify_chunks(manifest)
        self.assertEqual(result.status, VerificationStatus.PASSED)

    def test_verify_chunks_corrupted(self):
        """Chunk-level verification detects corruption."""
        manifest = self.network.store_bytes(b"Chunk corruption test")
        self.verifier.simulate_corruption(manifest, 0)
        result = self.verifier.verify_chunks(manifest)
        self.assertEqual(result.status, VerificationStatus.FAILED)

    def test_merkle_proof_verification(self):
        """Merkle proof verification passes."""
        data = b"Block " * 200  # Multiple chunks
        manifest = self.network.store_bytes(data)
        result = self.verifier.verify_merkle_proof(manifest, 0)
        self.assertEqual(result.status, VerificationStatus.PASSED)

    def test_node_retrievability_check_passes_for_intact_chunk(self):
        """A node returns a random sampled chunk matching its committed hash."""
        manifest = self.network.store_bytes(b"Challenge test")
        node_id = manifest["placements"][0]["stored_on"][0]
        result = self.verifier.check_node_retrievability(node_id, manifest)
        self.assertEqual(result.status, VerificationStatus.PASSED)
        self.assertEqual(result.details["sample_count"], 1)
        self.assertEqual(len(result.details["samples_checked"]), 1)

    def test_node_retrievability_check_detects_corrupted_chunk(self):
        """A node returning altered bytes fails the committed hash check."""
        manifest = self.network.store_bytes(b"Corrupted challenge test")
        node_id = manifest["placements"][0]["stored_on"][0]
        self.verifier.simulate_corruption(manifest, 0)

        result = self.verifier.check_node_retrievability(node_id, manifest)

        self.assertEqual(result.status, VerificationStatus.FAILED)
        self.assertEqual(result.details["samples_checked"][0]["status"], "FAILED")

    def test_node_retrievability_check_uses_remote_service(self):
        manifest = self.network.store_bytes(b"Remote node sample")
        node_id = manifest["placements"][0]["stored_on"][0]
        node = self.network._get_node(node_id)
        self.assertIsNotNone(node)

        node_client = create_node_app(
            node_id,
            node.storage_dir,
            auth_token=NODE_AUTH_TOKEN,
        ).test_client()
        node_headers = {"Authorization": f"Bearer {NODE_AUTH_TOKEN}"}
        self.assertEqual(node_client.get("/v1/chunks/not-a-hash").status_code, 401)
        self.assertEqual(
            node_client.get(
                "/v1/chunks/not-a-hash",
                headers=node_headers,
            ).status_code,
            400,
        )
        self.assertEqual(
            node_client.get(
                f"/v1/chunks/{'0' * 64}",
                headers=node_headers,
            ).status_code,
            404,
        )

        class InMemoryNodeHTTP:
            def open(opener, request, timeout):
                self.assertEqual(request.method, "GET")
                self.assertEqual(timeout, 5)
                self.assertEqual(
                    request.get_header("Authorization"),
                    f"Bearer {NODE_AUTH_TOKEN}",
                )
                response = node_client.get(
                    urlsplit(request.full_url).path,
                    headers={"Authorization": request.get_header("Authorization")},
                )
                if response.status_code == 404:
                    raise HTTPError(request.full_url, 404, "Not found", {}, None)
                if response.status_code != 200:
                    raise AssertionError(f"Node service returned {response.status_code}")
                return io.BytesIO(response.data)

        self.network.node_auth_token = NODE_AUTH_TOKEN
        self.network.node_urls[node_id] = "https://node-service.test"
        with patch("dcas.storage.network.build_opener", return_value=InMemoryNodeHTTP()):
            result = self.verifier.check_node_retrievability(node_id, manifest)

        self.assertEqual(result.status, VerificationStatus.PASSED)
        self.assertEqual(result.details["samples_checked"][0]["status"], "PASSED")

    def test_node_retrievability_check_offline_node(self):
        """Checking an offline node returns WARNING."""
        manifest = self.network.store_bytes(b"Offline test")
        node_id = manifest["placements"][0]["stored_on"][0]
        self.network.simulate_node_failure(node_id)
        result = self.verifier.check_node_retrievability(node_id, manifest)
        self.assertEqual(result.status, VerificationStatus.WARNING)
        self.network.simulate_node_recovery(node_id)

    def test_node_retrievability_check_rejects_invalid_sample_count(self):
        manifest = self.network.store_bytes(b"Sample count")
        node_id = manifest["placements"][0]["stored_on"][0]

        with self.assertRaises(ValueError):
            self.verifier.check_node_retrievability(node_id, manifest, sample_count=0)

        with self.assertRaises(ValueError):
            self.verifier.check_node_retrievability(node_id, manifest, sample_count=2)

    def test_challenge_node_verifies_sampled_merkle_proofs(self):
        """A node's sampled chunk bytes and stored Merkle paths verify."""
        manifest = self.network.store_bytes(b"Challenge proof test " * 40000)
        node_counts = {
            node.node_id: sum(
                node.node_id in placement["stored_on"]
                for placement in manifest["placements"]
            )
            for node in self.network.nodes
        }
        node_id = max(node_counts, key=node_counts.get)

        result = self.verifier.challenge_node(node_id, manifest, sample_count=2)

        self.assertEqual(result.status, VerificationStatus.PASSED)
        self.assertEqual(result.details["sample_count"], 2)
        self.assertEqual(len(result.details["nonce_hex"]), 64)
        self.assertTrue(all(
            sample["status"] == "PASSED"
            for sample in result.details["samples_checked"]
        ))

    def test_challenge_node_fails_on_invalid_merkle_path(self):
        """A chunk hash alone is insufficient without its committed Merkle path."""
        manifest = self.network.store_bytes(b"Challenge mismatch test " * 40000)
        node_id = manifest["placements"][0]["stored_on"][0]
        node = self.network._get_node(node_id)
        for placement in manifest["placements"]:
            if node_id not in placement["stored_on"]:
                continue
            proof = node._metadata[placement["chunk_hash"]]["merkle_proofs"][
                manifest["merkle_root"]
            ][str(placement["chunk_index"])]
            proof["proof_hashes"] = []

        result = self.verifier.challenge_node(node_id, manifest)

        self.assertEqual(result.status, VerificationStatus.FAILED)
        self.assertEqual(result.details["samples_checked"][0]["status"], "FAILED")

    def test_challenge_node_uses_remote_merkle_challenge_service(self):
        manifest = self.network.store_bytes(b"Remote Merkle challenge " * 30000)
        node_id = manifest["placements"][0]["stored_on"][0]
        node = self.network._get_node(node_id)
        node_client = create_node_app(
            node_id,
            node.storage_dir,
            auth_token=NODE_AUTH_TOKEN,
        ).test_client()

        class InMemoryNodeHTTP:
            def open(inner_self, request, timeout):
                self.assertEqual(request.method, "POST")
                self.assertEqual(timeout, 5)
                self.assertEqual(
                    request.get_header("Authorization"),
                    f"Bearer {NODE_AUTH_TOKEN}",
                )
                response = node_client.post(
                    urlsplit(request.full_url).path,
                    data=request.data,
                    content_type="application/json",
                    headers={"Authorization": request.get_header("Authorization")},
                )
                if response.status_code == 404:
                    raise HTTPError(request.full_url, 404, "Not found", {}, None)
                if response.status_code != 200:
                    raise AssertionError(f"Node service returned {response.status_code}")
                return io.BytesIO(response.data)

        self.network.node_auth_token = NODE_AUTH_TOKEN
        self.network.node_urls[node_id] = "https://node-service.test"
        with patch("dcas.storage.network.build_opener", return_value=InMemoryNodeHTTP()):
            result = self.verifier.challenge_node(node_id, manifest)

        self.assertEqual(result.status, VerificationStatus.PASSED)
        self.assertEqual(result.details["samples_checked"][0]["status"], "PASSED")

    def test_full_audit_pass(self):
        """Full network audit passes for healthy data."""
        manifest = self.network.store_bytes(b"Audit test data")
        result = self.verifier.audit_network(manifest)
        self.assertEqual(result.status, VerificationStatus.PASSED)

    def test_full_audit_fail_after_corruption(self):
        """Full network audit detects corruption."""
        manifest = self.network.store_bytes(b"Audit corruption test")
        self.verifier.simulate_corruption(manifest, 0)
        result = self.verifier.audit_network(manifest)
        self.assertEqual(result.status, VerificationStatus.FAILED)


class TestStorageNodeServiceAuth(unittest.TestCase):
    """Node HTTP endpoints require a configured shared bearer secret."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.node = StorageNode("node-auth", self.test_dir)
        self.chunk_data = b"private stored chunk"
        self.chunk_hash = HashEngine().hash_bytes(self.chunk_data)
        self.node.store_chunk(self.chunk_hash, self.chunk_data)
        self.client = create_node_app(
            self.node.node_id,
            self.test_dir,
            auth_token=NODE_AUTH_TOKEN,
        ).test_client()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_all_node_endpoints_reject_missing_or_invalid_authentication(self):
        chunk_url = f"/v1/chunks/{self.chunk_hash}"
        self.assertEqual(self.client.get(chunk_url).status_code, 401)
        self.assertEqual(
            self.client.get(
                chunk_url,
                headers={"Authorization": "Bearer invalid-token"},
            ).status_code,
            401,
        )
        self.assertEqual(
            self.client.post("/v1/pdp/challenge", json={}).status_code,
            401,
        )
        self.assertEqual(
            self.client.post("/v1/por/challenge", json={}).status_code,
            401,
        )

        authorized = self.client.get(
            chunk_url,
            headers={"Authorization": f"Bearer {NODE_AUTH_TOKEN}"},
        )
        self.assertEqual(authorized.status_code, 200)
        self.assertEqual(authorized.data, self.chunk_data)

    def test_node_service_requires_a_strong_token_and_blocks_single_sector(self):
        with self.assertRaisesRegex(ValueError, "DCAS_NODE_AUTH_TOKEN"):
            create_node_app(self.node.node_id, self.test_dir, auth_token="short")

        authorized = {"Authorization": f"Bearer {NODE_AUTH_TOKEN}"}
        response = self.client.post(
            "/v1/pdp/challenge",
            json={
                "file_id": "file",
                "nonce_hex": "00" * 32,
                "n": "f" * 512,
                "sectors": [{}],
            },
            headers=authorized,
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("between 2 and 64", response.get_json()["error"])
        por_response = self.client.post(
            "/v1/por/challenge",
            json={
                "file_id": "file",
                "node_id": self.node.node_id,
                "shard_index": 0,
                "scheme": PairingPoR.SCHEME,
                "sector_size": XorErasureCode.SECTOR_SIZE,
                "field_elements_per_sector": PairingPoR.FIELD_ELEMENTS_PER_SECTOR,
                "nonce_hex": "00" * 32,
                "sectors": [{}],
            },
            headers=authorized,
        )
        self.assertEqual(por_response.status_code, 400)
        self.assertIn("between 2 and 64", por_response.get_json()["error"])

    def test_remote_node_requires_authentication_and_secure_transport(self):
        with self.assertRaisesRegex(ValueError, "DCAS_NODE_AUTH_TOKEN"):
            StorageNetwork(
                base_dir=os.path.join(self.test_dir, "no-token"),
                node_urls={"node-000": "https://node.example"},
            )
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            StorageNetwork(
                base_dir=os.path.join(self.test_dir, "insecure"),
                node_urls={"node-000": "http://node.example"},
                node_auth_token=NODE_AUTH_TOKEN,
            )


class TestStoragePDP(unittest.TestCase):
    """Tests for the educational RSA proof-of-data-possession protocol."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.pdp = StoragePDP.from_config(self.test_dir)
        self.encryptor = StorageEncryptor.from_config(self.test_dir)
        self.network = StorageNetwork(
            base_dir=os.path.join(self.test_dir, "network"),
            num_nodes=3,
            replication_factor=2,
            pdp=self.pdp,
        )
        self.verifier = IntegrityVerifier(
            self.network,
            storage_encryptor=self.encryptor,
        )

    def store_encrypted(self, data: bytes) -> dict:
        manifest = self.network.store_bytes(self.encryptor.encrypt(data))
        manifest["storage_encrypted"] = True
        return manifest

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_pdp_verifies_aggregate_without_returning_file_blocks(self):
        data = bytes(range(256)) * 2
        manifest = self.store_encrypted(data)
        node_id = manifest["placements"][0]["stored_on"][0]

        result = self.verifier.prove_node_possession(node_id, manifest, sample_count=2)

        self.assertEqual(result.status, VerificationStatus.PASSED)
        self.assertEqual(result.details["data_bytes_returned"], 0)
        self.assertNotIn("data_base64", result.details)
        self.assertEqual(result.details["scheme"], StoragePDP.SCHEME)

    def test_pdp_handles_empty_files_and_repeated_uploads(self):
        encrypted_empty = self.encryptor.encrypt(b"")
        manifest = self.network.store_bytes(encrypted_empty)
        repeated_manifest = self.network.store_bytes(encrypted_empty)
        manifest["storage_encrypted"] = True
        repeated_manifest["storage_encrypted"] = True
        node_id = repeated_manifest["placements"][0]["stored_on"][0]

        self.assertEqual(manifest["cid"]["cid"], repeated_manifest["cid"]["cid"])
        with self.assertRaisesRegex(ValueError, "At least two sectors"):
            self.verifier.prove_node_possession(node_id, repeated_manifest)

    def test_pdp_rejects_tampered_authenticator(self):
        manifest = self.store_encrypted(b"Tamper PDP authenticator " * 20)
        node_id = manifest["placements"][0]["stored_on"][0]
        for placement in manifest["placements"]:
            if node_id not in placement["stored_on"]:
                continue
            node = self.network._get_node(node_id)
            node._metadata[placement["chunk_hash"]]["pdp_tags"][
                manifest["pdp"]["file_id"]
            ] = {
                index: "1"
                for index in node._metadata[placement["chunk_hash"]]["pdp_tags"][
                    manifest["pdp"]["file_id"]
                ]
            }

        result = self.verifier.prove_node_possession(node_id, manifest)

        self.assertEqual(result.status, VerificationStatus.FAILED)

    def test_pdp_requires_upload_time_tags(self):
        legacy_network = StorageNetwork(
            base_dir=os.path.join(self.test_dir, "legacy"),
            num_nodes=2,
            replication_factor=1,
        )
        manifest = legacy_network.store_bytes(
            self.encryptor.encrypt(b"Legacy file without PDP tags")
        )
        manifest["storage_encrypted"] = True

        result = self.verifier.prove_node_possession(
            manifest["placements"][0]["stored_on"][0],
            manifest,
        )

        self.assertEqual(result.status, VerificationStatus.ERROR)
        self.assertIn("no RSA-PDP tags", result.message)

    def test_pdp_refuses_legacy_unencrypted_content(self):
        manifest = self.network.store_bytes(b"legacy plaintext " * 20)
        node_id = manifest["placements"][0]["stored_on"][0]

        result = self.verifier.prove_node_possession(node_id, manifest)

        self.assertEqual(result.status, VerificationStatus.ERROR)
        self.assertIn("not encrypted before storage", result.message)

    def test_pdp_survives_node_service_reload(self):
        manifest = self.store_encrypted(b"Remote PDP challenge " * 20)
        node_id = manifest["placements"][0]["stored_on"][0]
        node = self.network._get_node(node_id)
        node_client = create_node_app(
            node_id,
            node.storage_dir,
            auth_token=NODE_AUTH_TOKEN,
        ).test_client()

        class InMemoryNodeHTTP:
            def open(inner_self, request, timeout):
                self.assertEqual(request.method, "POST")
                self.assertEqual(timeout, 5)
                self.assertEqual(
                    request.get_header("Authorization"),
                    f"Bearer {NODE_AUTH_TOKEN}",
                )
                response = node_client.post(
                    urlsplit(request.full_url).path,
                    data=request.data,
                    content_type="application/json",
                    headers={"Authorization": request.get_header("Authorization")},
                )
                if response.status_code == 404:
                    raise HTTPError(request.full_url, 404, "Not found", {}, None)
                if response.status_code != 200:
                    raise AssertionError(f"Node service returned {response.status_code}")
                return io.BytesIO(response.data)

        self.network.node_auth_token = NODE_AUTH_TOKEN
        self.network.node_urls[node_id] = "https://node-service.test"
        with patch("dcas.storage.network.build_opener", return_value=InMemoryNodeHTTP()):
            result = self.verifier.prove_node_possession(node_id, manifest)

        self.assertEqual(result.status, VerificationStatus.PASSED)

    def test_pdp_key_is_stable_across_restarts(self):
        reloaded = StoragePDP.from_config(self.test_dir)
        self.assertEqual(reloaded.public_parameters, self.pdp.public_parameters)

    @unittest.skipIf(os.name == "nt", "Windows ACLs use icacls rather than POSIX mode bits")
    def test_existing_signing_key_permissions_are_restricted_on_load(self):
        key_path = os.path.join(self.test_dir, ".dcas-pdp-private-key.pem")
        os.chmod(key_path, 0o644)

        StoragePDP.from_config(self.test_dir)

        self.assertEqual(os.stat(key_path).st_mode & 0o777, 0o600)

    @unittest.skipUnless(os.name == "nt", "Windows ACL regression test")
    def test_existing_signing_key_acl_removes_other_users(self):
        key_path = os.path.join(self.test_dir, ".dcas-pdp-private-key.pem")
        subprocess.run(["icacls", key_path, "/grant", "*S-1-1-0:(R)"], check=True)

        StoragePDP.from_config(self.test_dir)

        acl = subprocess.run(
            ["icacls", key_path],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        self.assertIn("NT AUTHORITY\\SYSTEM:(F)", acl)
        self.assertNotIn("*S-1-1-0", acl)
        self.assertNotIn("(I)", acl)


class TestPairingPoR(unittest.TestCase):
    """Tests the educational pairing PoR and 2-of-3 coded storage path."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.por = PairingPoR(17)
        self.network = StorageNetwork(
            base_dir=os.path.join(self.test_dir, "network"),
            num_nodes=3,
            replication_factor=1,
            pairing_por=self.por,
        )
        self.verifier = IntegrityVerifier(
            self.network,
            pairing_por_required=True,
        )

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_por_key_is_stable_across_restarts(self):
        first = PairingPoR.from_config(self.test_dir)
        second = PairingPoR.from_config(self.test_dir)
        first_metadata = first.file_metadata("file", 248, 248, 124)
        second_metadata = second.file_metadata("file", 248, 248, 124)
        self.assertEqual(
            first_metadata["public_key_g2_hex"],
            second_metadata["public_key_g2_hex"],
        )

    @unittest.skipIf(os.name == "nt", "Windows ACLs use icacls rather than POSIX mode bits")
    def test_existing_por_and_encryption_keys_are_restricted_on_load(self):
        por_path = os.path.join(self.test_dir, ".dcas-por-private-key.hex")
        storage_path = os.path.join(self.test_dir, ".dcas-storage-key")
        PairingPoR.from_config(self.test_dir)
        StorageEncryptor.from_config(self.test_dir)
        os.chmod(por_path, 0o644)
        os.chmod(storage_path, 0o644)

        PairingPoR.from_config(self.test_dir)
        StorageEncryptor.from_config(self.test_dir)

        self.assertEqual(os.stat(por_path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(storage_path).st_mode & 0o777, 0o600)

    def test_xor_code_reconstructs_from_every_pair(self):
        original = bytes(range(251)) * 3
        shards, _ = XorErasureCode.encode(original)

        for pair in ((0, 1), (0, 2), (1, 2), (2, 0), (2, 1)):
            with self.subTest(pair=pair):
                recovered = XorErasureCode.decode(
                    {index: shards[index] for index in pair},
                    len(original),
                )
                self.assertEqual(recovered, original)

    @unittest.skipUnless(
        PairingPoR.NATIVE_BACKEND_AVAILABLE,
        "The optional native BLS12-381 backend is not installed.",
    )
    def test_native_tags_match_py_ecc_reference(self):
        data = bytes(range(248))
        parameters = self.por.file_metadata(
            "native-backend-file",
            len(data),
            len(data),
            XorErasureCode.SECTOR_SIZE,
        )
        native_tags = self.por.create_tags(
            "native-backend-file",
            "node-000",
            0,
            data,
            parameters,
        )
        with patch.object(por_module, "_arkworks", None):
            python_tags = self.por.create_tags(
                "native-backend-file",
                "node-000",
                0,
                data,
                parameters,
            )

        self.assertEqual(native_tags, python_tags)

    def test_por_shard_writes_are_concurrent(self):
        chunk_barrier = threading.Barrier(XorErasureCode.TOTAL_SHARDS)
        tag_barrier = threading.Barrier(XorErasureCode.TOTAL_SHARDS)
        for node in self.network.nodes:
            store_chunk = node.store_chunk
            store_por_tags = node.store_por_tags

            def wait_for_all_chunk_writes(
                *args,
                store_chunk=store_chunk,
                **kwargs,
            ):
                chunk_barrier.wait(timeout=5)
                return store_chunk(*args, **kwargs)

            def wait_for_all_tag_writes(
                *args,
                store_por_tags=store_por_tags,
                **kwargs,
            ):
                tag_barrier.wait(timeout=5)
                return store_por_tags(*args, **kwargs)

            node.store_chunk = wait_for_all_chunk_writes
            node.store_por_tags = wait_for_all_tag_writes

        with patch.object(self.por, "create_tags", return_value=["tag-0", "tag-1"]):
            manifest = self.network.store_por_bytes(b"concurrent metadata test")

        self.assertEqual(len(manifest["placements"]), XorErasureCode.TOTAL_SHARDS)

    def test_dynamic_sector_calculator_enforces_minimum_and_maximum(self):
        self.assertEqual(XorErasureCode.calculate_sector_size(0), 1)
        self.assertEqual(XorErasureCode.calculate_sector_size(4), 1)
        self.assertEqual(XorErasureCode.calculate_sector_size(5), 2)
        self.assertEqual(XorErasureCode.calculate_sector_size(16_384), 4096)
        self.assertEqual(XorErasureCode.calculate_sector_size(100_000), 4096)
        for invalid_size in (-1, 1.5, True):
            with self.subTest(invalid_size=invalid_size):
                with self.assertRaises(ValueError):
                    XorErasureCode.calculate_sector_size(invalid_size)

    def test_small_upload_uses_dynamic_sector_size_and_minimum_sector_count(self):
        payload = b"small file"
        manifest = self.network.store_por_bytes(payload)
        sector_size = manifest["por"]["sector_size"]

        self.assertEqual(sector_size, 3)
        self.assertEqual(manifest["erasure_coding"]["sector_size"], sector_size)
        self.assertEqual(manifest["por"]["sector_count_per_shard"], 2)
        self.assertTrue(all(
            placement["chunk_size"] == 2 * sector_size
            for placement in manifest["placements"]
        ))
        self.assertEqual(self.network.retrieve_file(manifest), payload)

        manifest["storage_encrypted"] = True
        node_id = manifest["placements"][0]["stored_on"][0]
        proof = self.verifier.prove_node_possession(node_id, manifest, sample_count=2)
        self.assertEqual(proof.status, VerificationStatus.PASSED)

    def test_large_upload_uses_capped_sector_size_and_verifies(self):
        manifest = self.network.store_por_bytes(b"l" * 16_384)

        self.assertEqual(manifest["por"]["sector_size"], XorErasureCode.MAX_SECTOR_SIZE)
        self.assertEqual(manifest["por"]["field_elements_per_sector"], 133)
        self.assertEqual(manifest["por"]["sector_count_per_shard"], 2)

        manifest["storage_encrypted"] = True
        node_id = manifest["placements"][0]["stored_on"][0]
        proof = self.verifier.prove_node_possession(node_id, manifest, sample_count=2)
        self.assertEqual(proof.status, VerificationStatus.PASSED)

        malformed = dict(manifest)
        malformed["por"] = dict(manifest["por"])
        malformed["por"]["sector_size"] -= 1
        rejected = self.verifier.prove_node_possession(node_id, malformed, sample_count=2)
        self.assertEqual(rejected.status, VerificationStatus.ERROR)

    def test_legacy_fixed_sector_proof_remains_verifiable(self):
        file_id = "legacy-file"
        node_id = "node-legacy"
        shard_index = 0
        sector_size = XorErasureCode.SECTOR_SIZE
        metadata = self.por.file_metadata(
            file_id,
            248,
            248,
            sector_size,
        )
        metadata["scheme"] = PairingPoR.LEGACY_SCHEME
        sectors = [b"a" * sector_size, b"b" * sector_size]
        tagged_sectors = []
        challenges = []
        for index, (sector, coefficient) in enumerate(zip(sectors, (7, 11))):
            tag_point = PairingPoR._hash_sector(
                file_id,
                node_id,
                shard_index,
                index,
                sector_size,
                PairingPoR.LEGACY_SCHEME,
            )
            for base_hex, value in zip(
                metadata["u_g1_hex"],
                PairingPoR._sector_values(sector, sector_size),
            ):
                tag_point = add(
                    tag_point,
                    multiply(PairingPoR._decode_g1(base_hex), value),
                )
            tag_hex = PairingPoR._encode_g1(
                multiply(tag_point, self.por._private_scalar)
            )
            tagged_sectors.append((tag_hex, sector, coefficient))
            challenges.append({
                "sector_index": index,
                "coefficient": coefficient,
            })

        sigma, mu = PairingPoR.aggregate_response(tagged_sectors, sector_size)
        self.assertTrue(PairingPoR.verify_aggregate_proof(
            file_id,
            node_id,
            shard_index,
            challenges,
            sigma,
            mu,
            metadata,
        ))

    def test_network_retrieves_from_any_two_live_shards(self):
        for unavailable_index in range(XorErasureCode.TOTAL_SHARDS):
            payload = bytes([unavailable_index + 1]) * 600
            manifest = self.network.store_por_bytes(payload)
            unavailable = self.network._get_node(
                manifest["placements"][unavailable_index]["stored_on"][0]
            )
            unavailable.is_online = False

            try:
                self.assertEqual(self.network.retrieve_file(manifest), payload)
                audit = self.verifier.audit_network(manifest)
                self.assertEqual(audit.status, VerificationStatus.WARNING)
                self.assertEqual(audit.details["healthy_shards"], 2)
            finally:
                unavailable.is_online = True

    def test_network_recovers_when_one_shard_is_corrupted(self):
        payload = b"recoverable encrypted content " * 32
        manifest = self.network.store_por_bytes(payload)
        placement = manifest["placements"][0]
        node = self.network._get_node(placement["stored_on"][0])
        node.store_chunk(
            placement["chunk_hash"],
            b"x" * placement["chunk_size"],
        )

        self.assertEqual(self.network.retrieve_file(manifest), payload)
        audit = self.verifier.audit_network(manifest)
        self.assertEqual(audit.status, VerificationStatus.WARNING)
        self.assertEqual(audit.details["healthy_shards"], 2)

    def test_node_proof_is_bound_to_node_and_shard(self):
        payload = b"encrypted storage fixture " * 40
        manifest = self.network.store_por_bytes(payload)
        placement = manifest["placements"][0]
        node_id = placement["stored_on"][0]
        node = self.network._get_node(node_id)
        nonce = "ab" * 32
        sectors = [
            {
                "sector_index": index,
                "chunk_hash": placement["chunk_hash"],
                "chunk_offset": index * manifest["por"]["sector_size"],
                "coefficient_hex": format(index + 11, "x"),
            }
            for index in (0, 1)
        ]
        response = self.network.request_por_proof(
            node_id,
            {
                "file_id": manifest["cid"]["cid"],
                "node_id": node_id,
                "shard_index": placement["shard_index"],
                "scheme": manifest["por"]["scheme"],
                "sector_size": manifest["por"]["sector_size"],
                "field_elements_per_sector": manifest["por"]["field_elements_per_sector"],
                "nonce_hex": nonce,
                "sectors": sectors,
            },
        )
        challenges = [
            {
                "sector_index": item["sector_index"],
                "coefficient": int(item["coefficient_hex"], 16),
            }
            for item in sectors
        ]

        self.assertIsNotNone(response)
        self.assertTrue(PairingPoR.verify_aggregate_proof(
            manifest["cid"]["cid"],
            node_id,
            placement["shard_index"],
            challenges,
            response["sigma_hex"],
            response["mu_hex"],
            manifest["por"],
        ))
        self.assertFalse(PairingPoR.verify_aggregate_proof(
            manifest["cid"]["cid"],
            "different-node",
            placement["shard_index"],
            challenges,
            response["sigma_hex"],
            response["mu_hex"],
            manifest["por"],
        ))
        self.assertFalse(PairingPoR.verify_aggregate_proof(
            manifest["cid"]["cid"],
            node_id,
            (placement["shard_index"] + 1) % XorErasureCode.TOTAL_SHARDS,
            challenges,
            response["sigma_hex"],
            response["mu_hex"],
            manifest["por"],
        ))

    def test_authenticated_node_service_answers_por_challenges(self):
        manifest = self.network.store_por_bytes(b"node service PoR fixture " * 40)
        placement = manifest["placements"][0]
        node_id = placement["stored_on"][0]
        node = self.network._get_node(node_id)
        client = create_node_app(
            node_id,
            node.storage_dir,
            auth_token=NODE_AUTH_TOKEN,
        ).test_client()
        payload = {
            "file_id": manifest["cid"]["cid"],
            "node_id": node_id,
            "shard_index": placement["shard_index"],
            "scheme": manifest["por"]["scheme"],
            "sector_size": manifest["por"]["sector_size"],
            "field_elements_per_sector": manifest["por"]["field_elements_per_sector"],
            "nonce_hex": "cd" * 32,
            "sectors": [
                {
                    "sector_index": index,
                    "chunk_hash": placement["chunk_hash"],
                    "chunk_offset": index * manifest["por"]["sector_size"],
                    "coefficient_hex": format(index + 3, "x"),
                }
                for index in (0, 1)
            ],
        }

        response = client.post(
            "/v1/por/challenge",
            json=payload,
            headers={"Authorization": f"Bearer {NODE_AUTH_TOKEN}"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["node_id"], node_id)

        payload["node_id"] = "different-node"
        mismatch = client.post(
            "/v1/por/challenge",
            json=payload,
            headers={"Authorization": f"Bearer {NODE_AUTH_TOKEN}"},
        )
        self.assertEqual(mismatch.status_code, 400)

    def test_verifier_accepts_por_and_rejects_legacy_manifest(self):
        payload = b"new encrypted file content " * 30
        manifest = self.network.store_por_bytes(payload)
        manifest["storage_encrypted"] = True
        node_id = manifest["placements"][0]["stored_on"][0]
        result = self.verifier.prove_node_possession(node_id, manifest, sample_count=2)
        self.assertEqual(result.status, VerificationStatus.PASSED)

        legacy_network = StorageNetwork(
            base_dir=os.path.join(self.test_dir, "legacy"),
            num_nodes=2,
            replication_factor=1,
        )
        legacy_manifest = legacy_network.store_bytes(b"legacy data")
        legacy_result = self.verifier.prove_node_possession(
            legacy_manifest["placements"][0]["stored_on"][0],
            legacy_manifest,
        )
        self.assertEqual(legacy_result.status, VerificationStatus.ERROR)
        self.assertIn("legacy file", legacy_result.message)

class TestMetadataStore(unittest.TestCase):
    """Tests for the metadata and audit store."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db = MetadataStore(os.path.join(self.test_dir, "test.db"))
        self.network = StorageNetwork(
            base_dir=os.path.join(self.test_dir, "net"),
            num_nodes=2,
            replication_factor=1,
        )

    def tearDown(self):
        self.db.close()
        shutil.rmtree(self.test_dir)

    def test_store_and_retrieve_manifest(self):
        """Store and retrieve a manifest."""
        manifest = self.network.store_bytes(b"DB test")
        self.db.store_manifest(manifest, owner="tester")
        cid_str = manifest["cid"]["cid"]
        retrieved = self.db.get_manifest(cid_str)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["filename"], "unnamed")

    def test_metadata_backends_implement_shared_protocol(self):
        self.assertIsInstance(self.db, MetadataStoreProtocol)
        self.assertTrue(issubclass(MongoMetadataStore, MetadataStoreProtocol))

    def test_list_files(self):
        """List stored files."""
        m1 = self.network.store_bytes(b"File 1", filename="f1.txt")
        m2 = self.network.store_bytes(b"File 2", filename="f2.txt")
        self.db.store_manifest(m1)
        self.db.store_manifest(m2)
        files = self.db.list_files()
        self.assertEqual(len(files), 2)

    def test_list_files_by_owner(self):
        """Filter files by owner."""
        m1 = self.network.store_bytes(b"Alice's file")
        m2 = self.network.store_bytes(b"Bob's file")
        self.db.store_manifest(m1, owner="alice")
        self.db.store_manifest(m2, owner="bob")
        alice_files = self.db.list_files(owner="alice")
        self.assertEqual(len(alice_files), 1)

    def test_delete_file(self):
        """Delete a file's metadata."""
        manifest = self.network.store_bytes(b"Delete me")
        self.db.store_manifest(manifest)
        cid_str = manifest["cid"]["cid"]
        self.assertTrue(self.db.delete_file(cid_str))
        self.assertIsNone(self.db.get_manifest(cid_str))

    def test_delete_shared_space(self):
        self.db.create_shared_space("space-1", "Space", "admin-hash", "share-hash")

        self.assertTrue(self.db.delete_shared_space("space-1"))
        self.assertFalse(self.db.delete_shared_space("space-1"))
        self.assertIsNone(self.db.get_shared_space("space-1"))

    def test_audit_log(self):
        """Audit log records events."""
        self.db.log_event("TEST_EVENT", "cid-123", "test.txt", "Test detail")
        logs = self.db.get_audit_log(event_type="TEST_EVENT")
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["event_type"], "TEST_EVENT")

    def test_audit_stats(self):
        """Audit stats aggregate correctly."""
        self.db.log_event("UPLOAD")
        self.db.log_event("UPLOAD")
        self.db.log_event("VERIFY")
        stats = self.db.get_audit_stats()
        self.assertEqual(stats["total_events"], 3)
        self.assertEqual(stats["by_type"]["UPLOAD"], 2)

    def test_search_files(self):
        """Search files by name."""
        m = self.network.store_bytes(b"Searchable", filename="certificate.pdf")
        self.db.store_manifest(m)
        results = self.db.search_files("certificate")
        self.assertEqual(len(results), 1)


class TestEndToEnd(unittest.TestCase):
    """End-to-end integration tests simulating the university use case."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.network = StorageNetwork(
            base_dir=os.path.join(self.test_dir, "net"),
            num_nodes=5,
            replication_factor=3,
        )
        self.verifier = IntegrityVerifier(self.network)
        self.db = MetadataStore(os.path.join(self.test_dir, "e2e.db"))

    def tearDown(self):
        self.db.close()
        shutil.rmtree(self.test_dir)

    def test_university_certificate_workflow(self):
        """
        Full workflow:
        1. Upload certificate
        2. Verify integrity
        3. Detect tampering
        4. Survive node failure
        """
        # 1. Upload
        cert = b"Certificate: John Doe, B.Sc. CS, GPA 3.85"
        manifest = self.network.store_bytes(cert, filename="cert.txt")
        self.db.store_manifest(manifest, owner="university")

        # 2. Verify
        result = self.verifier.verify_file_integrity(manifest)
        self.assertTrue(result.passed)

        # Re-store for a fresh copy to test corruption on
        cert2 = b"Certificate: Jane Smith, M.Sc. Math, GPA 3.92"
        manifest2 = self.network.store_bytes(cert2, filename="cert2.txt")

        # 3. Detect tampering
        self.verifier.simulate_corruption(manifest2, 0)
        result = self.verifier.verify_file_integrity(manifest2)
        self.assertFalse(result.passed)

        # 4. Survive node failure (original cert)
        self.network.simulate_node_failure("node-000")
        self.network.simulate_node_failure("node-001")
        retrieved = self.network.retrieve_file(manifest)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved, cert)

    def test_multiple_files_independent(self):
        """Multiple files can be stored and verified independently."""
        files = {
            "doc1.txt": b"Document one content",
            "doc2.txt": b"Document two content",
            "doc3.txt": b"Document three content",
        }

        manifests = {}
        for name, data in files.items():
            m = self.network.store_bytes(data, filename=name)
            self.db.store_manifest(m)
            manifests[name] = m

        # Verify all
        for name, m in manifests.items():
            result = self.verifier.verify_file_integrity(m)
            self.assertTrue(result.passed, f"{name} verification failed")

        # Corrupt one, others should still pass
        self.verifier.simulate_corruption(manifests["doc2.txt"], 0)

        result1 = self.verifier.verify_file_integrity(manifests["doc1.txt"])
        self.assertTrue(result1.passed)
        result2 = self.verifier.verify_file_integrity(manifests["doc2.txt"])
        self.assertFalse(result2.passed)
        result3 = self.verifier.verify_file_integrity(manifests["doc3.txt"])
        self.assertTrue(result3.passed)


if __name__ == "__main__":
    unittest.main()

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
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import urlsplit

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
from dcas.verifier.verifier import IntegrityVerifier, VerificationStatus
from dcas.database.metadata import MetadataStore


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

        node_client = create_node_app(node_id, node.storage_dir).test_client()
        self.assertEqual(node_client.get("/v1/chunks/not-a-hash").status_code, 400)
        self.assertEqual(node_client.get(f"/v1/chunks/{'0' * 64}").status_code, 404)

        class InMemoryNodeHTTP:
            def open(opener, request, timeout):
                self.assertEqual(request.method, "GET")
                self.assertEqual(timeout, 5)
                response = node_client.get(urlsplit(request.full_url).path)
                if response.status_code == 404:
                    raise HTTPError(request.full_url, 404, "Not found", {}, None)
                if response.status_code != 200:
                    raise AssertionError(f"Node service returned {response.status_code}")
                return io.BytesIO(response.data)

        self.network.node_urls[node_id] = "http://node-service.test"
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
        node_client = create_node_app(node_id, node.storage_dir).test_client()

        class InMemoryNodeHTTP:
            def open(inner_self, request, timeout):
                self.assertEqual(request.method, "POST")
                self.assertEqual(timeout, 5)
                response = node_client.post(
                    urlsplit(request.full_url).path,
                    data=request.data,
                    content_type="application/json",
                )
                if response.status_code == 404:
                    raise HTTPError(request.full_url, 404, "Not found", {}, None)
                if response.status_code != 200:
                    raise AssertionError(f"Node service returned {response.status_code}")
                return io.BytesIO(response.data)

        self.network.node_urls[node_id] = "http://node-service.test"
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


class TestStoragePDP(unittest.TestCase):
    """Tests for the educational RSA proof-of-data-possession protocol."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.pdp = StoragePDP.from_config(self.test_dir)
        self.network = StorageNetwork(
            base_dir=os.path.join(self.test_dir, "network"),
            num_nodes=3,
            replication_factor=2,
            pdp=self.pdp,
        )
        self.verifier = IntegrityVerifier(self.network)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_pdp_verifies_aggregate_without_returning_file_blocks(self):
        data = bytes(range(256)) * 2
        manifest = self.network.store_bytes(data)
        node_id = manifest["placements"][0]["stored_on"][0]

        result = self.verifier.prove_node_possession(node_id, manifest, sample_count=2)

        self.assertEqual(result.status, VerificationStatus.PASSED)
        self.assertEqual(result.details["data_bytes_returned"], 0)
        self.assertNotIn("data_base64", result.details)
        self.assertEqual(result.details["scheme"], StoragePDP.SCHEME)

    def test_pdp_handles_empty_files_and_repeated_uploads(self):
        manifest = self.network.store_bytes(b"")
        repeated_manifest = self.network.store_bytes(b"")
        node_id = repeated_manifest["placements"][0]["stored_on"][0]

        result = self.verifier.prove_node_possession(node_id, repeated_manifest)

        self.assertEqual(manifest["cid"]["cid"], repeated_manifest["cid"]["cid"])
        self.assertEqual(result.status, VerificationStatus.PASSED)

    def test_pdp_rejects_tampered_authenticator(self):
        manifest = self.network.store_bytes(b"Tamper PDP authenticator " * 20)
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
        manifest = legacy_network.store_bytes(b"Legacy file without PDP tags")

        result = self.verifier.prove_node_possession(
            manifest["placements"][0]["stored_on"][0],
            manifest,
        )

        self.assertEqual(result.status, VerificationStatus.ERROR)
        self.assertIn("no RSA-PDP tags", result.message)

    def test_pdp_survives_node_service_reload(self):
        manifest = self.network.store_bytes(b"Remote PDP challenge " * 20)
        node_id = manifest["placements"][0]["stored_on"][0]
        node = self.network._get_node(node_id)
        node_client = create_node_app(node_id, node.storage_dir).test_client()

        class InMemoryNodeHTTP:
            def open(inner_self, request, timeout):
                self.assertEqual(request.method, "POST")
                self.assertEqual(timeout, 5)
                response = node_client.post(
                    urlsplit(request.full_url).path,
                    data=request.data,
                    content_type="application/json",
                )
                if response.status_code == 404:
                    raise HTTPError(request.full_url, 404, "Not found", {}, None)
                if response.status_code != 200:
                    raise AssertionError(f"Node service returned {response.status_code}")
                return io.BytesIO(response.data)

        self.network.node_urls[node_id] = "http://node-service.test"
        with patch("dcas.storage.network.build_opener", return_value=InMemoryNodeHTTP()):
            result = self.verifier.prove_node_possession(node_id, manifest)

        self.assertEqual(result.status, VerificationStatus.PASSED)

    def test_pdp_key_is_stable_across_restarts(self):
        reloaded = StoragePDP.from_config(self.test_dir)
        self.assertEqual(reloaded.public_parameters, self.pdp.public_parameters)


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

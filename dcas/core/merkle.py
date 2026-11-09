"""
Merkle Tree implementation for efficient data integrity verification.

A Merkle tree allows verifying individual data blocks belong to a dataset
without downloading the entire dataset, using compact cryptographic proofs.
"""

import json
from dataclasses import dataclass, field
from typing import Optional

from .hashing import HashEngine, HashAlgorithm


@dataclass
class MerkleNode:
    """
    A single node in a Merkle tree.

    Attributes:
        hash:   The hash digest of this node.
        left:   Left child node (or None for leaves).
        right:  Right child node (or None for leaves).
        index:  The leaf index (only for leaf nodes).
        data:   The original data (only stored for leaf nodes, optional).
    """
    hash: str
    left: Optional["MerkleNode"] = None
    right: Optional["MerkleNode"] = None
    index: Optional[int] = None
    data: Optional[bytes] = None

    @property
    def is_leaf(self) -> bool:
        return self.left is None and self.right is None


@dataclass
class MerkleProof:
    """
    A proof that a specific leaf belongs to a Merkle tree.

    Attributes:
        leaf_hash:   The hash of the leaf being proved.
        leaf_index:  The index of the leaf in the tree.
        proof_hashes: List of (hash, position) pairs going up the tree.
                      position is 'left' or 'right'.
        root_hash:   The expected root hash.
    """
    leaf_hash: str
    leaf_index: int
    proof_hashes: list  # list of (hash, "left"|"right")
    root_hash: str

    def to_dict(self) -> dict:
        return {
            "leaf_hash": self.leaf_hash,
            "leaf_index": self.leaf_index,
            "proof_hashes": self.proof_hashes,
            "root_hash": self.root_hash,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict) -> "MerkleProof":
        return cls(
            leaf_hash=data["leaf_hash"],
            leaf_index=data["leaf_index"],
            proof_hashes=data["proof_hashes"],
            root_hash=data["root_hash"],
        )


class MerkleTree:
    """
    A binary Merkle tree for verifying data blocks.

    Builds a tree from a list of data chunks, allowing:
    - Root hash computation (the single hash summarizing all data).
    - Proof generation for any leaf.
    - Proof verification without the original data.

    Example:
        >>> tree = MerkleTree()
        >>> tree.build([b"block0", b"block1", b"block2", b"block3"])
        >>> print(tree.root_hash)
        >>> proof = tree.get_proof(1)
        >>> assert MerkleTree.verify_proof(proof)
    """

    def __init__(self, algorithm: HashAlgorithm = HashAlgorithm.SHA256):
        self.engine = HashEngine(algorithm)
        self.root: Optional[MerkleNode] = None
        self.leaves: list[MerkleNode] = []
        self._data_blocks: list[bytes] = []

    @property
    def root_hash(self) -> Optional[str]:
        """The root hash of the tree, or None if not built."""
        return self.root.hash if self.root else None

    @property
    def leaf_count(self) -> int:
        return len(self.leaves)

    def _hash_pair(self, left_hash: str, right_hash: str) -> str:
        """Hash two child hashes together to form a parent hash."""
        combined = (left_hash + right_hash).encode("utf-8")
        return self.engine.hash_bytes(combined)

    def build(self, data_blocks: list[bytes]) -> str:
        """
        Build the Merkle tree from a list of data blocks.

        Args:
            data_blocks: List of byte chunks to form the leaves.

        Returns:
            The root hash of the constructed tree.

        Raises:
            ValueError: If no data blocks are provided.
        """
        if not data_blocks:
            raise ValueError("Cannot build a Merkle tree with no data blocks.")

        self._data_blocks = list(data_blocks)

        # Create leaf nodes
        self.leaves = []
        for i, block in enumerate(data_blocks):
            leaf_hash = self.engine.hash_bytes(block)
            self.leaves.append(MerkleNode(hash=leaf_hash, index=i, data=block))

        # Build up from leaves
        current_level = list(self.leaves)

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                # If odd number of nodes, duplicate the last one
                right = current_level[i + 1] if i + 1 < len(current_level) else current_level[i]
                parent_hash = self._hash_pair(left.hash, right.hash)
                parent = MerkleNode(hash=parent_hash, left=left, right=right)
                next_level.append(parent)
            current_level = next_level

        self.root = current_level[0]
        return self.root.hash

    def get_proof(self, leaf_index: int) -> MerkleProof:
        """
        Generate a Merkle proof for a specific leaf.

        Args:
            leaf_index: The index of the leaf (0-based).

        Returns:
            A MerkleProof object that can verify the leaf's membership.

        Raises:
            ValueError: If the tree hasn't been built or index is out of range.
        """
        if self.root is None:
            raise ValueError("Tree has not been built yet.")
        if leaf_index < 0 or leaf_index >= len(self.leaves):
            raise ValueError(f"Leaf index {leaf_index} is out of range [0, {len(self.leaves)}).")

        proof_hashes = []
        current_level = list(self.leaves)
        idx = leaf_index

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else current_level[i]
                parent_hash = self._hash_pair(left.hash, right.hash)
                parent = MerkleNode(hash=parent_hash, left=left, right=right)
                next_level.append(parent)

                # If the current leaf is in this pair, record the sibling
                if i == idx or i + 1 == idx:
                    if i == idx:
                        sibling_hash = right.hash
                        position = "right"
                    else:
                        sibling_hash = left.hash
                        position = "left"
                    proof_hashes.append([sibling_hash, position])

            # Update index for next level (integer division)
            idx = idx // 2
            current_level = next_level

        return MerkleProof(
            leaf_hash=self.leaves[leaf_index].hash,
            leaf_index=leaf_index,
            proof_hashes=proof_hashes,
            root_hash=self.root.hash,
        )

    @staticmethod
    def verify_proof(
        proof: MerkleProof,
        algorithm: HashAlgorithm = HashAlgorithm.SHA256,
    ) -> bool:
        """
        Verify a Merkle proof without the original tree.

        Args:
            proof:     The MerkleProof to verify.
            algorithm: The hash algorithm used when the tree was built.

        Returns:
            True if the proof is valid (the leaf belongs to the tree
            with the given root hash), False otherwise.
        """
        engine = HashEngine(algorithm)
        current_hash = proof.leaf_hash

        for sibling_hash, position in proof.proof_hashes:
            if position == "left":
                combined = (sibling_hash + current_hash).encode("utf-8")
            else:
                combined = (current_hash + sibling_hash).encode("utf-8")
            current_hash = engine.hash_bytes(combined)

        return current_hash == proof.root_hash

    def get_tree_visual(self) -> str:
        """
        Return a simple text visualization of the tree structure.

        Returns:
            A multi-line string showing the tree layout.
        """
        if self.root is None:
            return "(empty tree)"

        lines = []

        def _walk(node: MerkleNode, prefix: str, is_last: bool):
            connector = "+-- " if is_last else "|-- "
            label = node.hash[:16] + "..."
            if node.is_leaf:
                label += f" [leaf {node.index}]"
            lines.append(f"{prefix}{connector}{label}")
            new_prefix = prefix + ("    " if is_last else "|   ")
            children = []
            if node.left:
                children.append(node.left)
            if node.right and node.right is not node.left:
                children.append(node.right)
            for i, child in enumerate(children):
                _walk(child, new_prefix, i == len(children) - 1)

        lines.append(f"Root: {self.root.hash[:16]}...")
        if self.root.left:
            _walk(self.root.left, "", self.root.right is None or self.root.right is self.root.left)
        if self.root.right and self.root.right is not self.root.left:
            _walk(self.root.right, "", True)

        return "\n".join(lines)

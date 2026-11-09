"""
DCAS Interactive Demo — Command-line demonstration of all system features.

Run:  python demo.py
"""

import os
import sys
import json
import shutil
import tempfile

# Rich console for pretty output
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich import box

# DCAS modules
from dcas.core.hashing import HashEngine, HashAlgorithm
from dcas.core.cid import CIDGenerator
from dcas.core.chunker import FileChunker
from dcas.core.merkle import MerkleTree
from dcas.storage.network import StorageNetwork
from dcas.verifier.verifier import IntegrityVerifier
from dcas.database.metadata import MetadataStore


console = Console(force_terminal=True, force_jupyter=False, legacy_windows=False)

# ── Paths ───────────────────────────────────────────────────────────
DEMO_DIR = os.path.join(tempfile.gettempdir(), "dcas_demo")
NETWORK_DIR = os.path.join(DEMO_DIR, "network")
DB_PATH = os.path.join(DEMO_DIR, "demo_metadata.db")


def separator(title: str = ""):
    console.print()
    if title:
        console.rule(f"[bold cyan]{title}[/]")
    else:
        console.rule()
    console.print()


def demo_hashing():
    """Demonstrate the hashing engine."""
    separator("1. Cryptographic Hashing")

    engine = HashEngine(HashAlgorithm.SHA256)

    samples = [
        b"Hello, World!",
        b"Hello, World!",   # Same content → same hash
        b"Hello, World.",   # One char changed → different hash
        b"University Certificate: John Doe, Computer Science, 2024",
    ]

    table = Table(title="SHA-256 Hash Demonstration", box=box.ROUNDED)
    table.add_column("Input", style="green", max_width=50)
    table.add_column("SHA-256 Hash", style="yellow")
    table.add_column("Note", style="dim")

    prev_hash = None
    for data in samples:
        h = engine.hash_bytes(data)
        note = ""
        if prev_hash and h == prev_hash:
            note = "OK: Same as above (identical content)"
        elif prev_hash and h != prev_hash:
            note = "DIFFERENT: hash changed"
        table.add_row(data.decode("utf-8", errors="replace"), h[:32] + "...", note)
        prev_hash = h

    console.print(table)

    # Demonstrate verification
    original = b"Important Document Content"
    h = engine.hash_bytes(original)
    console.print(f"\n[bold]Verification demo:[/]")
    console.print(f"  Original hash: [yellow]{h[:32]}...[/]")
    console.print(f"  Verify same data:    {'OK MATCH' if engine.verify_bytes(original, h) else 'FAIL MISMATCH'}")
    console.print(f"  Verify altered data: {'OK MATCH' if engine.verify_bytes(original + b'!', h) else 'FAIL MISMATCH'}")


def demo_cid():
    """Demonstrate Content Identifier generation."""
    separator("2. Content Identifier (CID) Generation")

    gen = CIDGenerator(HashAlgorithm.SHA256)

    data = b"Student Certificate: Jane Smith, Mathematics, 2024"
    cid = gen.generate(data, codec="certificate")

    console.print(Panel(
        f"[bold green]CID String:[/] {cid.cid_string}\n"
        f"[bold]Full Hash:[/]  {cid.hash_digest}\n"
        f"[bold]Algorithm:[/]  {cid.algorithm}\n"
        f"[bold]Codec:[/]      {cid.codec}\n"
        f"[bold]Size:[/]       {cid.size} bytes\n"
        f"[bold]Created:[/]    {cid.created_at}",
        title="Content Identifier",
        border_style="green",
    ))

    # Show that same content → same CID
    cid2 = gen.generate(data, codec="certificate")
    console.print(f"\n  Same content -> Same CID:  {cid.hash_digest == cid2.hash_digest}  OK")

    # Different content -> different CID
    cid3 = gen.generate(data + b" (modified)", codec="certificate")
    console.print(f"  Diff content -> Diff CID:  {cid.hash_digest != cid3.hash_digest}  OK")


def demo_chunking():
    """Demonstrate file chunking."""
    separator("3. File Chunking for Distributed Storage")

    # Create sample data (simulating a file)
    data = b"A" * 500 + b"B" * 500 + b"C" * 300
    chunker = FileChunker(chunk_size=512)
    chunks = chunker.chunk_bytes(data)

    table = Table(title=f"Chunking {len(data)} bytes with chunk_size=512", box=box.ROUNDED)
    table.add_column("Chunk #", style="cyan", justify="center")
    table.add_column("Offset", justify="right")
    table.add_column("Size (bytes)", justify="right")
    table.add_column("Hash (SHA-256)", style="yellow")
    table.add_column("Preview", style="dim")

    for c in chunks:
        preview = repr(c.data[:20])[2:-1] + "..."
        table.add_row(
            str(c.index),
            str(c.offset),
            str(c.size),
            c.hash[:24] + "...",
            preview,
        )

    console.print(table)

    # Verify reassembly
    reassembled = FileChunker.reassemble(chunks)
    console.print(f"\n  Reassembled size: {len(reassembled)} bytes")
    console.print(f"  Matches original: {'OK Yes' if reassembled == data else 'FAIL No'}")


def demo_merkle_tree():
    """Demonstrate Merkle tree construction and proof verification."""
    separator("4. Merkle Tree & Proof Verification")

    blocks = [
        b"Block 0: Certificate Data",
        b"Block 1: Student Info",
        b"Block 2: Course Records",
        b"Block 3: Grades & GPA",
    ]

    tree = MerkleTree(HashAlgorithm.SHA256)
    root = tree.build(blocks)

    console.print(f"[bold]Merkle Root:[/] [yellow]{root[:32]}...[/]")
    console.print(f"[bold]Leaf Count:[/]  {tree.leaf_count}")
    console.print()

    # Show tree visualization
    console.print(Panel(tree.get_tree_visual(), title="Merkle Tree Structure", border_style="blue"))

    # Generate and verify proofs
    console.print("\n[bold]Proof Verification:[/]")
    for i in range(len(blocks)):
        proof = tree.get_proof(i)
        is_valid = MerkleTree.verify_proof(proof)
        status = "OK VALID" if is_valid else "FAIL INVALID"
        console.print(f"  Proof for leaf {i}: {status}  (depth={len(proof.proof_hashes)})")


def demo_distributed_storage():
    """Demonstrate the full decentralized storage workflow."""
    separator("5. Decentralized Storage Network")

    # Create network
    network = StorageNetwork(
        base_dir=NETWORK_DIR,
        num_nodes=4,
        replication_factor=2,
    )

    # Show network status
    status = network.get_network_status()
    console.print(f"[bold]Network:[/] {status['total_nodes']} nodes, "
                  f"replication factor = {status['replication_factor']}")

    # Create sample files
    files = {
        "certificate.txt": b"UNIVERSITY CERTIFICATE\n"
                           b"Name: John Doe\n"
                           b"Degree: B.Sc. Computer Science\n"
                           b"GPA: 3.85 / 4.00\n"
                           b"Date: June 15, 2024\n"
                           b"ID: CERT-2024-001\n",
        "transcript.txt":  b"ACADEMIC TRANSCRIPT\n"
                           b"Student: John Doe\n"
                           b"Course: Introduction to CS - A\n"
                           b"Course: Data Structures - A-\n"
                           b"Course: Algorithms - B+\n"
                           b"Course: Operating Systems - A\n",
        "research.txt":    b"RESEARCH PAPER ABSTRACT\n"
                           b"Title: Decentralized Storage Systems\n"
                           b"Author: John Doe\n"
                           b"This paper explores content-addressed storage...\n"
                           * 3,  # Make it larger
    }

    manifests = {}
    table = Table(title="Stored Files", box=box.ROUNDED)
    table.add_column("Filename", style="green")
    table.add_column("CID", style="yellow")
    table.add_column("Size", justify="right")
    table.add_column("Chunks", justify="center")
    table.add_column("Merkle Root", style="dim")

    for name, data in files.items():
        manifest = network.store_bytes(data, filename=name)
        manifests[name] = manifest
        cid_str = manifest["cid"]["cid"]
        table.add_row(
            name,
            cid_str[:30] + "...",
            f"{manifest['total_size']} B",
            str(manifest["chunk_count"]),
            manifest["merkle_root"][:20] + "...",
        )

    console.print(table)

    # Show chunk distribution
    console.print("\n[bold]Chunk Distribution Across Nodes:[/]")
    for name, manifest in manifests.items():
        console.print(f"\n  [green]{name}[/]:")
        for p in manifest["placements"]:
            nodes = ", ".join(p["stored_on"])
            console.print(f"    Chunk {p['chunk_index']}: {p['chunk_hash'][:16]}... -> [{nodes}]")

    return network, manifests


def demo_integrity_verification(network: StorageNetwork, manifests: dict):
    """Demonstrate integrity verification."""
    separator("6. Integrity Verification")

    verifier = IntegrityVerifier(network)

    # ── 6a. Full hash verification ──────────────────────────────────
    console.print("[bold cyan]6a. Full File Hash Verification[/]\n")

    for name, manifest in manifests.items():
        result = verifier.verify_file_integrity(manifest)
        status_icon = "OK" if result.passed else "FAIL"
        console.print(f"  {status_icon} {name}: {result.message} ({result.elapsed_ms:.1f}ms)")

    # ── 6b. Chunk-level verification ────────────────────────────────
    console.print(f"\n[bold cyan]6b. Chunk-Level Verification[/]\n")

    cert_manifest = manifests["certificate.txt"]
    result = verifier.verify_chunks(cert_manifest)
    console.print(f"  {'OK' if result.passed else 'FAIL'} certificate.txt: {result.message}")

    # ── 6c. Merkle proof verification ───────────────────────────────
    console.print(f"\n[bold cyan]6c. Merkle Proof Verification[/]\n")

    result = verifier.verify_merkle_proof(cert_manifest, 0)
    console.print(f"  {'OK' if result.passed else 'FAIL'} {result.message}")
    if result.passed and "tree_visualization" in result.details:
        console.print(Panel(
            result.details["tree_visualization"],
            title="Merkle Tree (certificate.txt)",
            border_style="blue",
        ))

    # ── 6d. Storage proof (challenge-response) ──────────────────────
    console.print(f"\n[bold cyan]6d. Storage Proof (Challenge-Response)[/]\n")

    chunk_hash = cert_manifest["placements"][0]["chunk_hash"]
    node_id = cert_manifest["placements"][0]["stored_on"][0]
    result = verifier.challenge_node(node_id, chunk_hash)
    console.print(f"  {'OK' if result.passed else 'FAIL'} {result.message}")

    return verifier


def demo_tamper_detection(network: StorageNetwork, manifests: dict, verifier: IntegrityVerifier):
    """Demonstrate tamper / corruption detection."""
    separator("7. Tamper & Corruption Detection")

    cert_manifest = manifests["certificate.txt"]
    cid_str = cert_manifest["cid"]["cid"]

    console.print("[bold red]Simulating data corruption...[/]\n")
    console.print("  Corrupting chunk 0 of certificate.txt on all nodes...")
    verifier.simulate_corruption(cert_manifest, 0)

    # Verify again — should fail
    console.print("\n[bold]Re-verifying after corruption:[/]\n")

    result = verifier.verify_file_integrity(cert_manifest)
    console.print(f"  Full hash:    {'OK PASSED' if result.passed else 'FAIL FAILED'}  - {result.message}")

    result = verifier.verify_chunks(cert_manifest)
    console.print(f"  Chunk check:  {'OK PASSED' if result.passed else 'FAIL FAILED'}  - {result.message}")

    # Full audit
    result = verifier.audit_network(cert_manifest)
    console.print(f"  Network audit: {'OK PASSED' if result.passed else 'FAIL FAILED'} - {result.message}")
    if result.details.get("issues"):
        for issue in result.details["issues"]:
            console.print(f"    WARN  {issue}")


def demo_node_failure(network: StorageNetwork, manifests: dict):
    """Demonstrate resilience to node failures."""
    separator("8. Node Failure & Recovery")

    verifier = IntegrityVerifier(network)
    transcript_manifest = manifests["transcript.txt"]

    console.print("[bold]Taking node-000 offline...[/]")
    network.simulate_node_failure("node-000")

    # Try to retrieve — should succeed due to replication
    file_data = network.retrieve_file(transcript_manifest)
    if file_data:
        console.print("  OK File still retrievable (thanks to replication)")
    else:
        console.print("  FAIL File NOT retrievable!")

    # Verify
    result = verifier.verify_file_integrity(transcript_manifest)
    console.print(f"  Verification: {'OK PASSED' if result.passed else 'FAIL FAILED'}")

    # Recover
    console.print("\n[bold]Recovering node-000...[/]")
    network.simulate_node_recovery("node-000")
    console.print("  OK Node-000 is back online")


def demo_metadata_and_audit():
    """Demonstrate the metadata store and audit log."""
    separator("9. Metadata Store & Audit Log")

    db = MetadataStore(DB_PATH)

    # Store some manifests
    network = StorageNetwork(
        base_dir=NETWORK_DIR + "_audit",
        num_nodes=3,
        replication_factor=2,
    )

    data = b"Audit test document content"
    manifest = network.store_bytes(data, filename="audit_test.txt")
    db.store_manifest(manifest, owner="admin", tags=["test", "audit"])

    # Log some events
    cid_str = manifest["cid"]["cid"]
    db.log_event("VERIFY", cid_str, "audit_test.txt", "Integrity check passed")
    db.log_event("RETRIEVE", cid_str, "audit_test.txt", "File downloaded by employer")

    # Show stored files
    files = db.list_files()
    table = Table(title="Stored Files (Metadata)", box=box.ROUNDED)
    table.add_column("CID", style="yellow")
    table.add_column("Filename", style="green")
    table.add_column("Size", justify="right")
    table.add_column("Owner")
    table.add_column("Created", style="dim")

    for f in files:
        table.add_row(
            str(f["cid"])[:30] + "...",
            str(f["filename"]),
            f"{f['total_size']} B",
            str(f["owner"]),
            str(f["created_at"])[:19],
        )
    console.print(table)

    # Show audit log
    logs = db.get_audit_log(limit=10)
    table = Table(title="Audit Log (Last 10 Events)", box=box.ROUNDED)
    table.add_column("Timestamp", style="dim")
    table.add_column("Event", style="cyan")
    table.add_column("CID", style="yellow")
    table.add_column("Details")
    table.add_column("Status")

    for log in logs:
        status_style = "green" if log["status"] == "success" else "red"
        table.add_row(
            str(log["timestamp"])[:19],
            str(log["event_type"]),
            (str(log["cid"])[:20] + "...") if log["cid"] else "-",
            str(log["details"] or "-"),
            f"[{status_style}]{log['status']}[/]",
        )
    console.print(table)

    # Show stats
    stats = db.get_audit_stats()
    console.print(f"\n[bold]Audit Statistics:[/] {stats['total_events']} total events")
    for event_type, count in stats["by_type"].items():
        console.print(f"  {event_type}: {count}")

    db.close()
    network.cleanup()


def demo_use_case():
    """Demonstrate the university certificate use case end-to-end."""
    separator("10. Use Case: University Certificate Verification")

    console.print(Panel(
        "[bold]Scenario:[/] A university issues a digital certificate.\n"
        "Years later, an employer wants to verify it's authentic.",
        border_style="magenta",
    ))

    # Step 1: University uploads the certificate
    console.print("\n[bold cyan]Step 1:[/] University uploads the certificate\n")

    network = StorageNetwork(
        base_dir=NETWORK_DIR + "_usecase",
        num_nodes=5,
        replication_factor=3,
    )
    verifier = IntegrityVerifier(network)
    db = MetadataStore(os.path.join(DEMO_DIR, "usecase.db"))

    certificate = (
        b"=" * 50 + b"\n"
        b"       UNIVERSITY CERTIFICATE\n"
        b"=" * 50 + b"\n\n"
        b"  This certifies that:\n\n"
        b"       JANE SMITH\n\n"
        b"  has successfully completed the requirements\n"
        b"  for the degree of:\n\n"
        b"       Bachelor of Science in Computer Science\n\n"
        b"  with a cumulative GPA of 3.92 / 4.00\n\n"
        b"  Issued: June 15, 2024\n"
        b"  Certificate ID: CERT-2024-42\n"
        b"  Institution: Tech University\n\n"
        b"=" * 50 + b"\n"
    )

    manifest = network.store_bytes(certificate, filename="jane_smith_certificate.txt")
    db.store_manifest(manifest, owner="tech_university", tags=["certificate", "2024"])

    cid = manifest["cid"]["cid"]
    console.print(f"  OK Certificate stored with CID: [yellow]{cid}[/]")
    console.print(f"  OK Distributed across {manifest['replication_factor']} nodes")
    console.print(f"  OK Merkle root: [dim]{manifest['merkle_root'][:32]}...[/]")

    # Step 2: Employer requests verification
    console.print(f"\n[bold cyan]Step 2:[/] Employer requests certificate verification (years later)\n")

    # Retrieve and verify
    result = verifier.verify_file_integrity(manifest)
    db.log_event("VERIFY", cid, "jane_smith_certificate.txt",
                 f"Employer verification: {result.status.value}")

    console.print(f"  Hash verification: {'OK PASSED' if result.passed else 'FAIL FAILED'}")
    console.print(f"  Expected hash: [dim]{result.details.get('expected_hash', '')[:32]}...[/]")
    console.print(f"  Actual hash:   [dim]{result.details.get('actual_hash', '')[:32]}...[/]")

    # Merkle proof
    result = verifier.verify_merkle_proof(manifest, 0)
    console.print(f"  Merkle proof:  {'OK VALID' if result.passed else 'FAIL INVALID'}")

    # Step 3: Tamper attempt
    console.print(f"\n[bold cyan]Step 3:[/] Someone tries to alter the certificate\n")

    fake_certificate = certificate.replace(b"3.92", b"4.00")
    fake_engine = HashEngine(HashAlgorithm.SHA256)
    fake_hash = fake_engine.hash_bytes(fake_certificate)

    console.print(f"  Original hash: [green]{manifest['cid']['hash_digest'][:32]}...[/]")
    console.print(f"  Altered hash:  [red]{fake_hash[:32]}...[/]")
    console.print(f"  Hashes match:  {'OK' if fake_hash == manifest['cid']['hash_digest'] else 'FAIL - TAMPERING DETECTED!'}")

    # Step 4: Full audit
    console.print(f"\n[bold cyan]Step 4:[/] Full network audit\n")
    result = verifier.audit_network(manifest)
    console.print(f"  Audit result: {'OK ALL CLEAR' if result.passed else 'FAIL ISSUES FOUND'}")
    console.print(f"  Time: {result.elapsed_ms:.1f}ms")

    db.close()
    network.cleanup()


def main():
    """Run the full demo."""
    console.print(Panel.fit(
        "[bold blue]Decentralized Content-Addressed Storage[/]\n"
        "[bold blue]& Integrity Verifier[/]\n\n"
        "[dim]A complete demonstration of distributed file storage,\n"
        "content addressing, and cryptographic verification.[/]",
        border_style="blue",
    ))

    # Clean up previous demo
    if os.path.exists(DEMO_DIR):
        shutil.rmtree(DEMO_DIR)
    os.makedirs(DEMO_DIR, exist_ok=True)

    try:
        # Core concepts
        demo_hashing()
        demo_cid()
        demo_chunking()
        demo_merkle_tree()

        # Distributed storage
        network, manifests = demo_distributed_storage()

        # Verification
        verifier = demo_integrity_verification(network, manifests)

        # Tamper detection
        demo_tamper_detection(network, manifests, verifier)

        # Node failure resilience
        demo_node_failure(network, manifests)

        # Metadata & audit
        demo_metadata_and_audit()

        # Full use case
        demo_use_case()

        separator("Demo Complete")
        console.print("[bold green]OK All demonstrations completed successfully![/]\n")
        console.print("[dim]Run the REST API server with:[/]  python run_server.py")
        console.print("[dim]Run the tests with:[/]           python -m pytest tests/ -v\n")

    finally:
        # Clean up
        if os.path.exists(DEMO_DIR):
            shutil.rmtree(DEMO_DIR)


if __name__ == "__main__":
    main()

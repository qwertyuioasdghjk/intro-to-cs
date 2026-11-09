"""
Flask REST API for the Decentralized Content-Addressed Storage system.

Endpoints:
    GET    /                  Web dashboard
    POST   /api/upload         Upload a file
    GET    /api/files           List stored files
    GET    /api/file/<cid>      Get file info
    GET    /api/download/<cid>  Download a file
    POST   /api/verify/<cid>   Verify file integrity
    POST   /api/verify/<cid>/chunks     Verify individual chunks
    POST   /api/verify/<cid>/merkle/<n> Verify Merkle proof for chunk n
    POST   /api/verify/<cid>/audit      Full network audit
    GET    /api/network/status  Network status
    POST   /api/network/fail/<node_id>  Simulate node failure
    POST   /api/network/recover/<node_id>  Recover node
    GET    /api/audit-log       View audit log
    POST   /api/simulate/corrupt/<cid>/<n>  Simulate data corruption
"""

import io
import os
import json
import tempfile

from flask import Flask, jsonify, render_template, request, send_file

from ..storage.network import StorageNetwork
from ..verifier.verifier import IntegrityVerifier
from ..database.metadata import MetadataStore


def create_app(
    network_dir: str = "./dcas_network",
    db_path: str = "dcas_metadata.db",
    num_nodes: int = 4,
    replication_factor: int = 2,
) -> Flask:
    """
    Create and configure the Flask application.

    Args:
        network_dir:        Base directory for storage nodes.
        db_path:            Path to the SQLite database.
        num_nodes:          Number of storage nodes.
        replication_factor: Chunks are replicated to this many nodes.

    Returns:
        A configured Flask app.
    """
    app = Flask(__name__)

    # Initialize components
    network = StorageNetwork(
        base_dir=network_dir,
        num_nodes=num_nodes,
        replication_factor=replication_factor,
    )
    verifier = IntegrityVerifier(network)
    metadata = MetadataStore(db_path)
    app.extensions["dcas"] = {
        "network": network,
        "verifier": verifier,
        "metadata": metadata,
    }

    @app.route("/")
    def index():
        """Serve the DCAS web dashboard."""
        return render_template("index.html")

    # ── Upload ──────────────────────────────────────────────────────

    @app.route("/api/upload", methods=["POST"])
    def upload_file():
        """Upload a file to the decentralized network."""
        if "file" not in request.files:
            return jsonify({"error": "No file part in request"}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "No selected file"}), 400

        owner = request.form.get("owner", "system")
        tags_str = request.form.get("tags", "[]")
        try:
            tags = json.loads(tags_str)
        except json.JSONDecodeError:
            tags = []

        # Read file data
        file_data = file.read()

        # Store in network
        manifest = network.store_bytes(file_data, filename=file.filename)

        # Store manifest in metadata DB
        metadata.store_manifest(manifest, owner=owner, tags=tags)

        return jsonify({
            "message": "File uploaded and distributed successfully.",
            "cid": manifest["cid"]["cid"],
            "hash_digest": manifest["cid"]["hash_digest"],
            "filename": manifest["filename"],
            "total_size": manifest["total_size"],
            "chunk_count": manifest["chunk_count"],
            "merkle_root": manifest["merkle_root"],
            "replication_factor": manifest["replication_factor"],
        }), 201

    # ── Upload raw text ─────────────────────────────────────────────

    @app.route("/api/upload/text", methods=["POST"])
    def upload_text():
        """Upload text content directly."""
        data = request.get_json()
        if not data or "content" not in data:
            return jsonify({"error": "Missing 'content' field"}), 400

        content = data["content"].encode("utf-8")
        filename = data.get("filename", "text_upload.txt")
        owner = data.get("owner", "system")

        manifest = network.store_bytes(content, filename=filename)
        metadata.store_manifest(manifest, owner=owner)

        return jsonify({
            "message": "Text uploaded successfully.",
            "cid": manifest["cid"]["cid"],
            "hash_digest": manifest["cid"]["hash_digest"],
            "filename": filename,
            "total_size": manifest["total_size"],
            "chunk_count": manifest["chunk_count"],
            "merkle_root": manifest["merkle_root"],
        }), 201

    # ── List files ──────────────────────────────────────────────────

    @app.route("/api/files", methods=["GET"])
    def list_files():
        """List all stored files."""
        owner = request.args.get("owner")
        files = metadata.list_files(owner=owner)
        return jsonify({"files": files, "count": len(files)})

    # ── File info ───────────────────────────────────────────────────

    @app.route("/api/file/<cid>", methods=["GET"])
    def get_file_info(cid):
        """Get file metadata by CID."""
        info = metadata.get_file_info(cid)
        if info is None:
            return jsonify({"error": "File not found"}), 404
        # Remove the full manifest JSON for the info endpoint
        info.pop("manifest_json", None)
        return jsonify(info)

    # ── Download ────────────────────────────────────────────────────

    @app.route("/api/download/<cid>", methods=["GET"])
    def download_file(cid):
        """Download a file by CID."""
        manifest = metadata.get_manifest(cid)
        if manifest is None:
            return jsonify({"error": "File not found"}), 404

        file_data = network.retrieve_file(manifest)
        if file_data is None:
            return jsonify({"error": "Could not retrieve file from network"}), 500

        metadata.log_event("RETRIEVE", cid, manifest["filename"], "File downloaded")

        return send_file(
            io.BytesIO(file_data),
            download_name=manifest["filename"],
            as_attachment=True,
        )

    # ── Verify full file ────────────────────────────────────────────

    @app.route("/api/verify/<cid>", methods=["POST"])
    def verify_file(cid):
        """Verify file integrity by recomputing the hash."""
        manifest = metadata.get_manifest(cid)
        if manifest is None:
            return jsonify({"error": "File not found"}), 404

        result = verifier.verify_file_integrity(manifest)
        metadata.log_event(
            "VERIFY",
            cid,
            manifest["filename"],
            result.message,
            status="success" if result.passed else "failure",
        )
        return jsonify(result.to_dict())

    # ── Verify chunks ──────────────────────────────────────────────

    @app.route("/api/verify/<cid>/chunks", methods=["POST"])
    def verify_chunks(cid):
        """Verify each chunk individually."""
        manifest = metadata.get_manifest(cid)
        if manifest is None:
            return jsonify({"error": "File not found"}), 404

        result = verifier.verify_chunks(manifest)
        metadata.log_event(
            "VERIFY_CHUNKS",
            cid,
            manifest["filename"],
            result.message,
            status="success" if result.passed else "failure",
        )
        return jsonify(result.to_dict())

    # ── Verify Merkle proof ─────────────────────────────────────────

    @app.route("/api/verify/<cid>/merkle/<int:chunk_index>", methods=["POST"])
    def verify_merkle(cid, chunk_index):
        """Verify a Merkle proof for a specific chunk."""
        manifest = metadata.get_manifest(cid)
        if manifest is None:
            return jsonify({"error": "File not found"}), 404

        if chunk_index < 0 or chunk_index >= manifest["chunk_count"]:
            return jsonify({"error": f"Chunk index out of range (0-{manifest['chunk_count']-1})"}), 400

        result = verifier.verify_merkle_proof(manifest, chunk_index)
        metadata.log_event(
            "VERIFY_MERKLE",
            cid,
            manifest["filename"],
            result.message,
            status="success" if result.passed else "failure",
        )
        return jsonify(result.to_dict())

    # ── Full network audit ──────────────────────────────────────────

    @app.route("/api/verify/<cid>/audit", methods=["POST"])
    def audit_file(cid):
        """Perform a full network audit for a file."""
        manifest = metadata.get_manifest(cid)
        if manifest is None:
            return jsonify({"error": "File not found"}), 404

        result = verifier.audit_network(manifest)
        metadata.log_event(
            "AUDIT",
            cid,
            manifest["filename"],
            result.message,
            status="success" if result.passed else "failure",
        )
        return jsonify(result.to_dict())

    # ── Network status ──────────────────────────────────────────────

    @app.route("/api/network/status", methods=["GET"])
    def network_status():
        """Get the current network status."""
        return jsonify(network.get_network_status())

    # ── Simulate node failure ───────────────────────────────────────

    @app.route("/api/network/fail/<node_id>", methods=["POST"])
    def fail_node(node_id):
        """Simulate a node failure (take offline)."""
        network.simulate_node_failure(node_id)
        metadata.log_event("NODE_FAILURE", node_id=node_id, details=f"Node {node_id} taken offline")
        return jsonify({"message": f"Node {node_id} is now offline."})

    @app.route("/api/network/recover/<node_id>", methods=["POST"])
    def recover_node(node_id):
        """Recover a failed node (bring online)."""
        network.simulate_node_recovery(node_id)
        metadata.log_event("NODE_RECOVERY", node_id=node_id, details=f"Node {node_id} brought online")
        return jsonify({"message": f"Node {node_id} is now online."})

    # ── Audit log ───────────────────────────────────────────────────

    @app.route("/api/audit-log", methods=["GET"])
    def get_audit_log():
        """View the audit log."""
        cid = request.args.get("cid")
        event_type = request.args.get("event_type")
        limit = request.args.get("limit", 50, type=int)
        logs = metadata.get_audit_log(cid=cid, event_type=event_type, limit=limit)
        stats = metadata.get_audit_stats()
        return jsonify({"logs": logs, "stats": stats})

    # ── Simulate corruption ─────────────────────────────────────────

    @app.route("/api/simulate/corrupt/<cid>/<int:chunk_index>", methods=["POST"])
    def corrupt_chunk(cid, chunk_index):
        """Simulate data corruption for testing."""
        manifest = metadata.get_manifest(cid)
        if manifest is None:
            return jsonify({"error": "File not found"}), 404

        success = verifier.simulate_corruption(manifest, chunk_index)
        if success:
            metadata.log_event(
                "CORRUPTION_SIMULATED",
                cid,
                details=f"Chunk {chunk_index} corrupted for testing",
                status="warning",
            )
            return jsonify({"message": f"Chunk {chunk_index} has been corrupted on all nodes."})
        else:
            return jsonify({"error": "Could not corrupt chunk"}), 400

    # ── Delete file ─────────────────────────────────────────────────

    @app.route("/api/file/<cid>", methods=["DELETE"])
    def delete_file(cid):
        """Delete a file's metadata."""
        success = metadata.delete_file(cid)
        if success:
            return jsonify({"message": f"File {cid} deleted."})
        return jsonify({"error": "File not found"}), 404

    # ── Search ──────────────────────────────────────────────────────

    @app.route("/api/search", methods=["GET"])
    def search_files():
        """Search files by name or CID."""
        query = request.args.get("q", "")
        if not query:
            return jsonify({"error": "Missing 'q' query parameter"}), 400
        results = metadata.search_files(query)
        return jsonify({"results": results, "count": len(results)})

    return app

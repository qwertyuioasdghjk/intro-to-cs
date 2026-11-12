"""
Flask REST API for the Decentralized Content-Addressed Storage system.

Endpoints:
    GET    /                  Web dashboard
    POST   /api/upload         Upload a file
    POST   /api/spaces         Create a capability-protected shared space
    GET    /api/spaces/<id>/files       List shared-space files with an access token
    POST   /api/spaces/<id>/files       Upload an encrypted file with write access
    POST   /api/spaces/<id>/files/<cid>/verify  Verify a shared-space file
    POST   /api/spaces/<id>/link/rotate Replace the read-only access link
    DELETE /api/spaces/<id>/link        Revoke the read-only access link
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
import hashlib
import os
import json
import secrets
import hmac
import tempfile

from flask import Flask, jsonify, render_template, request, send_file

from ..storage.network import StorageNetwork
from ..verifier.verifier import IntegrityVerifier
from ..database.metadata import MetadataStore
from ..database.mongo_metadata import MongoMetadataStore


def create_app(
    network_dir: str = "./dcas_network",
    db_path: str = "dcas_metadata.db",
    num_nodes: int = 4,
    replication_factor: int = 2,
    mongodb_uri: str | None = None,
    mongodb_database: str | None = None,
) -> Flask:
    """
    Create and configure the Flask application.

    Args:
        network_dir:        Base directory for storage nodes.
        db_path:            Path to the SQLite database when MongoDB is not configured.
        num_nodes:          Number of storage nodes.
        replication_factor: Chunks are replicated to this many nodes.
        mongodb_uri:        MongoDB URI; defaults to DCAS_MONGODB_URI.
        mongodb_database:   MongoDB database name; defaults to DCAS_MONGODB_DATABASE or "dcas".

    Returns:
        A configured Flask app.
    """
    app = Flask(__name__)

    @app.after_request
    def set_security_headers(response):
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        if request.path == "/api/spaces" or request.path.startswith("/api/spaces/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    # Initialize components
    network = StorageNetwork(
        base_dir=network_dir,
        num_nodes=num_nodes,
        replication_factor=replication_factor,
    )
    verifier = IntegrityVerifier(network)
    mongodb_uri = mongodb_uri if mongodb_uri is not None else os.environ.get("DCAS_MONGODB_URI")
    mongodb_database = (
        mongodb_database
        if mongodb_database is not None
        else os.environ.get("DCAS_MONGODB_DATABASE", "dcas")
    )
    metadata = (
        MongoMetadataStore(mongodb_uri, mongodb_database)
        if mongodb_uri
        else MetadataStore(db_path)
    )
    app.extensions["dcas"] = {
        "network": network,
        "verifier": verifier,
        "metadata": metadata,
    }

    @app.route("/")
    def index():
        """Serve the DCAS web dashboard."""
        return render_template("index.html")

    @app.route("/share/<space_id>")
    def shared_space_page(space_id):
        """Serve the recipient view; its capability arrives only in the URL fragment."""
        return render_template("index.html")

    def token_hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def request_token() -> str:
        authorization = request.headers.get("Authorization", "")
        scheme, separator, token = authorization.partition(" ")
        return token.strip() if separator and scheme.lower() == "bearer" else ""

    def get_space_access(space_id: str) -> tuple[dict | None, str | None]:
        space = metadata.get_shared_space(space_id)
        if space is None:
            return None, None
        token = request_token()
        if not token:
            return space, None
        digest = token_hash(token)
        if hmac.compare_digest(digest, space["admin_token_hash"]):
            return space, "admin"
        share_hash = space.get("share_token_hash")
        if share_hash and hmac.compare_digest(digest, share_hash):
            return space, "writer" if space.get("allow_upload") else "reader"
        return space, None

    def private_file_response(cid: str):
        info = metadata.get_file_info(cid)
        if info and info.get("space_id"):
            return jsonify({"error": "File not found"}), 404
        return None

    @app.route("/api/spaces", methods=["POST"])
    def create_shared_space():
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or not isinstance(data.get("name"), str):
            return jsonify({"error": "A space name is required"}), 400
        name = data["name"].strip()
        if not name or len(name) > 120:
            return jsonify({"error": "Space name must be between 1 and 120 characters"}), 400
        allow_upload = data.get("allow_upload", False)
        if not isinstance(allow_upload, bool):
            return jsonify({"error": "'allow_upload' must be a boolean"}), 400

        space_id = secrets.token_urlsafe(18)
        admin_token = secrets.token_urlsafe(32)
        share_token = secrets.token_urlsafe(32)
        metadata.create_shared_space(
            space_id,
            name,
            token_hash(admin_token),
            token_hash(share_token),
            allow_upload=allow_upload,
        )
        metadata.log_event("SPACE_CREATE", details="Shared space created")
        return jsonify({
            "space_id": space_id,
            "name": name,
            "admin_token": admin_token,
            "share_token": share_token,
            "allow_upload": allow_upload,
        }), 201

    @app.route("/api/spaces/<space_id>/files", methods=["GET"])
    def list_shared_space_files(space_id):
        space, access = get_space_access(space_id)
        if space is None or access is None:
            return jsonify({"error": "Shared space not found or access denied"}), 404
        files = metadata.list_files(space_id=space_id)
        return jsonify({
            "space_id": space_id,
            "name": space["name"],
            "files": files,
            "count": len(files),
            "can_upload": access in ("admin", "writer"),
        })

    @app.route("/api/spaces/<space_id>/files", methods=["POST"])
    def upload_shared_space_file(space_id):
        space, access = get_space_access(space_id)
        if space is None or access not in ("admin", "writer"):
            return jsonify({"error": "Shared space not found or write access required"}), 404
        if "file" not in request.files:
            return jsonify({"error": "No file part in request"}), 400
        file = request.files["file"]
        if not file.filename:
            return jsonify({"error": "No selected file"}), 400

        file_data = file.read()
        if not file_data.startswith(b"DCAS1"):
            return jsonify({"error": "Shared-space uploads must be encrypted in the browser first"}), 400
        try:
            manifest = network.store_bytes(file_data, filename=file.filename)
        except RuntimeError as error:
            return jsonify({"error": str(error)}), 503

        cid = manifest["cid"]["cid"]
        existing = metadata.get_file_info(cid)
        if existing:
            return jsonify({"error": "This content is already stored; choose a different file"}), 409
        metadata.store_manifest(manifest, owner="shared", space_id=space_id)
        return jsonify({
            "message": "Encrypted file added to the shared space.",
            "cid": cid,
            "filename": manifest["filename"],
            "total_size": manifest["total_size"],
            "created_at": metadata.get_file_info(cid)["created_at"],
        }), 201

    @app.route("/api/spaces/<space_id>/files/<cid>/download", methods=["GET"])
    def download_shared_space_file(space_id, cid):
        space, access = get_space_access(space_id)
        info = metadata.get_file_info(cid)
        if space is None or access is None or not info or info.get("space_id") != space_id:
            return jsonify({"error": "File not found"}), 404
        manifest = metadata.get_manifest(cid)
        file_data = network.retrieve_file(manifest)
        if file_data is None:
            return jsonify({"error": "Could not retrieve file from network"}), 500
        metadata.log_event("RETRIEVE", cid, manifest["filename"], "Shared file downloaded")
        return send_file(
            io.BytesIO(file_data),
            download_name=manifest["filename"],
            as_attachment=True,
        )

    @app.route("/api/spaces/<space_id>/files/<cid>/verify", methods=["POST"])
    def verify_shared_space_file(space_id, cid):
        space, access = get_space_access(space_id)
        info = metadata.get_file_info(cid)
        if space is None or access is None or not info or info.get("space_id") != space_id:
            return jsonify({"error": "File not found"}), 404
        manifest = metadata.get_manifest(cid)
        result = verifier.verify_file_integrity(manifest)
        metadata.log_event(
            "VERIFY",
            cid,
            manifest["filename"],
            result.message,
            status="success" if result.passed else "failure",
        )
        return jsonify(result.to_dict())

    @app.route("/api/spaces/<space_id>/link/rotate", methods=["POST"])
    def rotate_shared_space_link(space_id):
        space, access = get_space_access(space_id)
        if space is None or access != "admin":
            return jsonify({"error": "Shared space not found or owner access required"}), 404
        share_token = secrets.token_urlsafe(32)
        metadata.update_shared_space_link(space_id, token_hash(share_token))
        return jsonify({"share_token": share_token, "message": "A new access link is ready."})

    @app.route("/api/spaces/<space_id>/link", methods=["DELETE"])
    def revoke_shared_space_link(space_id):
        space, access = get_space_access(space_id)
        if space is None or access != "admin":
            return jsonify({"error": "Shared space not found or owner access required"}), 404
        metadata.update_shared_space_link(space_id, None)
        metadata.log_event("SPACE_LINK_REVOKE", details="Shared-space access link revoked")
        return jsonify({"message": "The shared access link has been revoked."})

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
        try:
            manifest = network.store_bytes(file_data, filename=file.filename)
        except RuntimeError as error:
            return jsonify({"error": str(error)}), 503

        existing = metadata.get_file_info(manifest["cid"]["cid"])
        if existing and existing.get("space_id"):
            return jsonify({"error": "This content belongs to a shared space and cannot be replaced"}), 409

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
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or "content" not in data:
            return jsonify({"error": "Missing 'content' field"}), 400
        if not isinstance(data["content"], str):
            return jsonify({"error": "'content' must be a string"}), 400

        content = data["content"].encode("utf-8")
        filename = data.get("filename", "text_upload.txt")
        owner = data.get("owner", "system")
        if not isinstance(filename, str) or not isinstance(owner, str):
            return jsonify({"error": "'filename' and 'owner' must be strings"}), 400

        try:
            manifest = network.store_bytes(content, filename=filename)
        except RuntimeError as error:
            return jsonify({"error": str(error)}), 503
        existing = metadata.get_file_info(manifest["cid"]["cid"])
        if existing and existing.get("space_id"):
            return jsonify({"error": "This content belongs to a shared space and cannot be replaced"}), 409
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
        denied = private_file_response(cid)
        if denied:
            return denied
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
        denied = private_file_response(cid)
        if denied:
            return denied
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
        denied = private_file_response(cid)
        if denied:
            return denied
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
        denied = private_file_response(cid)
        if denied:
            return denied
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
        denied = private_file_response(cid)
        if denied:
            return denied
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
        denied = private_file_response(cid)
        if denied:
            return denied
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
        private_cids = metadata.get_private_cids()
        logs = [entry for entry in logs if entry.get("cid") not in private_cids]
        stats = metadata.get_audit_stats()
        return jsonify({"logs": logs, "stats": stats})

    # ── Simulate corruption ─────────────────────────────────────────

    @app.route("/api/simulate/corrupt/<cid>/<int:chunk_index>", methods=["POST"])
    def corrupt_chunk(cid, chunk_index):
        """Simulate data corruption for testing."""
        denied = private_file_response(cid)
        if denied:
            return denied
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
        """Delete a file's metadata and chunks not shared by other files."""
        denied = private_file_response(cid)
        if denied:
            return denied
        manifest = metadata.get_manifest(cid)
        if manifest is None:
            return jsonify({"error": "File not found"}), 404

        success = metadata.delete_file(cid)
        if not success:
            return jsonify({"error": "File not found"}), 404

        referenced_chunk_hashes = set()
        for stored_file in metadata.list_files(include_private=True):
            stored_manifest = metadata.get_manifest(stored_file["cid"])
            if stored_manifest is not None:
                referenced_chunk_hashes.update(
                    placement["chunk_hash"]
                    for placement in stored_manifest["placements"]
                )

        deleted_copies = network.delete_file_chunks(manifest, referenced_chunk_hashes)
        return jsonify({
            "message": f"File {cid} deleted.",
            "deleted_chunk_copies": deleted_copies,
        })

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

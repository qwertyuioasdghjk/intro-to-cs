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
    DELETE /api/spaces/<id>             Delete a shared space and its files
    GET    /api/files           List stored files
    GET    /api/file/<cid>      Get file info
    GET    /api/download/<cid>  Download a file
    POST   /api/verify/<cid>   Verify file integrity
    POST   /api/verify/<cid>/chunks     Verify individual chunks
    POST   /api/verify/<cid>/merkle/<n> Verify Merkle proof for chunk n
    POST   /api/verify/<cid>/nodes/<node_id>  Run a pairing-PoR node challenge
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
import ipaddress
import sqlite3
import threading
import tempfile
import time
from collections import defaultdict
from functools import wraps

from flask import Flask, jsonify, render_template, request, send_file
from pymongo.errors import PyMongoError
from werkzeug.exceptions import RequestEntityTooLarge

from ..storage.network import StorageNetwork
from ..verifier.verifier import IntegrityVerifier
from ..database.metadata import MetadataStore
from ..database.mongo_metadata import MongoMetadataStore
from ..database.protocols import MetadataStoreProtocol
from ..storage.encryption import StorageEncryptor, StorageEncryptionError
from ..storage.por import PairingPoR


def create_app(
    network_dir: str = "./dcas_network",
    db_path: str = "dcas_metadata.db",
    num_nodes: int = 4,
    replication_factor: int = 2,
    mongodb_uri: str | None = None,
    mongodb_database: str | None = None,
    node_urls: dict[str, str] | None = None,
) -> Flask:
    """
    Create and configure the Flask application.

    Args:
        network_dir:        Base directory for storage nodes.
        db_path:            Path to the SQLite database when MongoDB is not configured.
        num_nodes:          Number of storage nodes.
        replication_factor: Legacy setting; PoR stores one shard per distinct node.
        node_urls:          Optional retrieval-service URLs keyed by node ID.
        mongodb_uri:        MongoDB URI; defaults to DCAS_MONGODB_URI.
        mongodb_database:   MongoDB database name; defaults to DCAS_MONGODB_DATABASE or "dcas".

    Returns:
        A configured Flask app.
    """
    app = Flask(__name__)

    def integer_setting(name: str, default: int, *, allow_zero: bool = False) -> int:
        raw_value = os.environ.get(name)
        try:
            value = default if raw_value is None else int(raw_value)
        except ValueError as error:
            raise ValueError(f"{name} must be an integer.") from error
        if value < 0 or (value == 0 and not allow_zero):
            qualifier = "non-negative" if allow_zero else "positive"
            raise ValueError(f"{name} must be {qualifier}.")
        return value

    app.config["MAX_CONTENT_LENGTH"] = (
        integer_setting("DCAS_MAX_UPLOAD_MB", 25) * 1024 * 1024
    )
    app.config["DCAS_MAX_STORAGE_BYTES"] = (
        integer_setting("DCAS_MAX_STORAGE_MB", 1024) * 1024 * 1024
    )
    app.config["DCAS_ENABLE_RATE_LIMIT"] = (
        os.environ.get("DCAS_ENABLE_RATE_LIMIT", "1") == "1"
    )
    app.config["DCAS_TRUST_PROXY"] = os.environ.get("DCAS_TRUST_PROXY", "0") == "1"
    app.config["DCAS_ADMIN_RATE_LIMIT"] = integer_setting(
        "DCAS_ADMIN_RATE_LIMIT", 10
    )
    app.config["DCAS_WRITE_RATE_LIMIT"] = integer_setting(
        "DCAS_WRITE_RATE_LIMIT", 30
    )
    app.config["DCAS_RATE_LIMIT_LOCALHOST"] = (
        os.environ.get("DCAS_RATE_LIMIT_LOCALHOST", "1") != "0"
    )
    app.config["DCAS_ADMIN_TOKEN"] = os.environ.get("DCAS_ADMIN_TOKEN", "")
    app.config["DCAS_APP_TOKEN"] = os.environ.get("DCAS_APP_TOKEN", "")
    app.config["DCAS_APP_RATE_LIMIT"] = integer_setting(
        "DCAS_APP_RATE_LIMIT", 10
    )
    app.config["DCAS_ACCESS_TOKEN"] = os.environ.get("DCAS_ACCESS_TOKEN", "")
    app.config["DCAS_ENABLE_CHAOS"] = os.environ.get("DCAS_ENABLE_CHAOS") == "1"
    app.config["DCAS_GLOBAL_STORAGE_QUOTA_BYTES"] = integer_setting(
        "DCAS_GLOBAL_STORAGE_QUOTA_BYTES", 0, allow_zero=True
    )
    app.config["DCAS_SPACE_STORAGE_QUOTA_BYTES"] = integer_setting(
        "DCAS_SPACE_STORAGE_QUOTA_BYTES", 0, allow_zero=True
    )
    app.config["DCAS_RATE_LIMIT_WINDOW_SECONDS"] = integer_setting(
        "DCAS_RATE_LIMIT_WINDOW_SECONDS", 60
    )
    app.config["DCAS_RATE_LIMITS"] = {
        "audit": integer_setting("DCAS_RATE_LIMIT_AUDIT", 30),
        "challenge": integer_setting("DCAS_RATE_LIMIT_CHALLENGE", 60),
    }

    rate_buckets: defaultdict[tuple[str, str], list[float]] = defaultdict(list)
    rate_limit_lock = threading.Lock()
    quota_lock = threading.Lock()
    app.extensions["dcas_rate_limit_buckets"] = rate_buckets

    @app.errorhandler(RequestEntityTooLarge)
    def handle_payload_too_large(_error):
        return jsonify({"error": "File exceeds maximum upload size"}), 413

    @app.before_request
    def enforce_rate_limits():
        if not app.config["DCAS_ENABLE_RATE_LIMIT"]:
            return None

        app_token = app.config["DCAS_APP_TOKEN"]
        supplied_app_token = request.headers.get("X-App-Token", "")
        app_token_authorized = not app_token or hmac.compare_digest(
            supplied_app_token, app_token
        )
        requires_app_token = (
            request.path.startswith("/api/")
            and request.path != "/api/health"
            and bool(app_token)
        )

        rate_group_by_endpoint = {
            "create_shared_space": "write",
            "upload_shared_space_file": "write",
            "upload_file": "write",
            "upload_text": "write",
            "audit_file": "audit",
            "verify_file": "audit",
            "verify_chunks": "audit",
            "verify_merkle": "audit",
            "verify_shared_space_file": "audit",
            "challenge_node": "challenge",
            "get_audit_log": "audit",
        }
        admin_status_token_supplied = (
            request.headers.get("X-Admin-Token") is not None
            or request.headers.get("Authorization", "").lower().startswith("bearer ")
        )
        if requires_app_token and not app_token_authorized:
            group = "app_auth"
            limit = app.config["DCAS_APP_RATE_LIMIT"]
        elif request.endpoint == "admin_status" and admin_status_token_supplied:
            group = "admin_status"
            limit = app.config["DCAS_ADMIN_RATE_LIMIT"]
        else:
            group = rate_group_by_endpoint.get(request.endpoint)
            if group is None:
                return None
            if group == "write":
                limit = app.config["DCAS_WRITE_RATE_LIMIT"]
            else:
                limit = app.config["DCAS_RATE_LIMITS"][group]

        if group is None:
            return None

        client_ip = request.remote_addr or "unknown"
        if app.config["DCAS_TRUST_PROXY"]:
            forwarded_for = request.headers.get("X-Forwarded-For")
            forwarded_ip = (
                forwarded_for.split(",", 1)[0].strip() if forwarded_for else ""
            )
            client_ip = forwarded_ip or client_ip
        if not app.config["DCAS_RATE_LIMIT_LOCALHOST"]:
            try:
                if ipaddress.ip_address(client_ip).is_loopback:
                    return None
            except ValueError:
                pass

        now = time.monotonic()
        window = app.config["DCAS_RATE_LIMIT_WINDOW_SECONDS"]
        bucket_key = (client_ip, group)
        cutoff = now - window
        with rate_limit_lock:
            if bucket_key not in rate_buckets and len(rate_buckets) >= 10000:
                for existing_key, timestamps in list(rate_buckets.items()):
                    timestamps[:] = [stamp for stamp in timestamps if stamp > cutoff]
                    if not timestamps:
                        del rate_buckets[existing_key]
                if len(rate_buckets) >= 10000:
                    response = jsonify({"error": "Rate limit exceeded. Try again later."})
                    response.status_code = 429
                    response.headers["Retry-After"] = str(window)
                    return response

            timestamps = rate_buckets[bucket_key]
            timestamps[:] = [stamp for stamp in timestamps if stamp > cutoff]
            if len(timestamps) >= limit:
                retry_after = max(1, int(window - (now - timestamps[0])))
                response = jsonify({"error": "Rate limit exceeded. Try again later."})
                response.status_code = 429
                response.headers["Retry-After"] = str(retry_after)
                return response
            timestamps.append(now)
        return None

    @app.before_request
    def require_app_invite():
        app_token = app.config["DCAS_APP_TOKEN"]
        if (
            app_token
            and request.path.startswith("/api/")
            and request.path != "/api/health"
            and not hmac.compare_digest(
                request.headers.get("X-App-Token", ""),
                app_token,
            )
        ):
            return jsonify({"error": "A valid app invite code is required."}), 401
        return None

    @app.after_request
    def set_security_headers(response):
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        if (
            request.path == "/api/admin/status"
            or request.path == "/api/spaces"
            or request.path.startswith("/api/spaces/")
        ):
            response.headers["Cache-Control"] = "no-store"
        return response

    if num_nodes < 3:
        raise ValueError("The 2-of-3 PoR storage mode requires at least three nodes.")
    if replication_factor < 1:
        raise ValueError("The legacy replication setting must be positive.")

    # Initialize components
    pairing_por = PairingPoR.from_config(network_dir)
    network = StorageNetwork(
        base_dir=network_dir,
        num_nodes=num_nodes,
        replication_factor=1,
        node_urls=node_urls,
        pairing_por=pairing_por,
    )
    storage_encryptor = StorageEncryptor.from_config(network.base_dir)
    verifier = IntegrityVerifier(
        network,
        storage_encryptor=storage_encryptor,
        pairing_por_required=True,
    )
    mongodb_uri = mongodb_uri if mongodb_uri is not None else os.environ.get("DCAS_MONGODB_URI")
    mongodb_database = (
        mongodb_database
        if mongodb_database is not None
        else os.environ.get("DCAS_MONGODB_DATABASE", "dcas")
    )
    metadata: MetadataStoreProtocol = (
        MongoMetadataStore(mongodb_uri, mongodb_database)
        if mongodb_uri
        else MetadataStore(db_path)
    )
    app.extensions["dcas"] = {
        "network": network,
        "storage_encryptor": storage_encryptor,
        "pairing_por": pairing_por,
        "verifier": verifier,
        "metadata": metadata,
    }

    @app.route("/")
    def index():
        """Serve the DCAS web dashboard."""
        return render_template("index.html")

    @app.route("/api/health", methods=["GET"])
    def health():
        """Expose a minimal unauthenticated health check for host orchestration."""
        return jsonify({"status": "ok"})

    @app.route("/api/overview", methods=["GET"])
    def overview():
        """Return basic public service status for desktop-client setup validation."""
        return jsonify({
            "status": "ok",
            "public_file_count": len(metadata.list_files()),
            "network": network.get_network_status(),
        })

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

    def admin_token_values() -> list[str]:
        values = [request_token(), request.headers.get("X-Admin-Token", "").strip()]
        return [value for value in values if value]

    def is_admin_authorized() -> bool:
        configured_token = app.config["DCAS_ADMIN_TOKEN"]
        if not configured_token:
            return False
        return any(
            hmac.compare_digest(token, configured_token)
            for token in admin_token_values()
        )

    @app.route("/api/admin/status", methods=["GET"])
    def admin_status():
        """Report admin configuration and whether this request is authorized."""
        return jsonify({
            "admin_configured": bool(app.config["DCAS_ADMIN_TOKEN"]),
            "authorized": is_admin_authorized(),
            "chaos_enabled": app.config["DCAS_ENABLE_CHAOS"],
        })

    def authorization_error():
        if not admin_token_values() and not request.headers.get("X-Access-Token"):
            return jsonify({"error": "Authorization is required."}), 401
        return jsonify({"error": "The supplied authorization is invalid or insufficient."}), 403

    def is_access_authorized() -> bool:
        configured_token = app.config["DCAS_ACCESS_TOKEN"]
        if not configured_token:
            return True
        tokens = [request_token(), request.headers.get("X-Access-Token", "").strip()]
        return is_admin_authorized() or any(
            token and hmac.compare_digest(token, configured_token)
            for token in tokens
        )

    def serialize_quota_upload(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            with quota_lock:
                return view(*args, **kwargs)

        return wrapped

    def quota_error(
        incoming_size: int,
        *,
        space_id: str | None = None,
        replacing_cid: str | None = None,
    ) -> tuple[dict, int] | None:
        global_quota = app.config["DCAS_GLOBAL_STORAGE_QUOTA_BYTES"]
        space_quota = app.config["DCAS_SPACE_STORAGE_QUOTA_BYTES"]
        replaced_file = metadata.get_file_info(replacing_cid) if replacing_cid else None
        global_used = sum(
            item["total_size"] for item in metadata.list_files(include_private=True)
        )
        if replaced_file:
            global_used -= replaced_file["total_size"]
        if global_used + incoming_size > app.config["DCAS_MAX_STORAGE_BYTES"]:
            return {"error": "Maximum storage capacity exceeded."}, 507
        if global_quota:
            if global_used + incoming_size > global_quota:
                return {"error": "Global storage quota exceeded."}, 507

        if space_id is not None and space_quota:
            existing_file_size = sum(
                item["total_size"] for item in metadata.list_files(space_id=space_id)
            )
            if replaced_file and replaced_file.get("space_id") == space_id:
                existing_file_size -= replaced_file["total_size"]
            if existing_file_size + incoming_size > space_quota:
                return {"error": "Shared-space storage quota exceeded."}, 507
        return None

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

    def download_response(file_data: bytes, filename: str):
        sanitized_filename = "".join(
            character
            for character in filename
            if character not in '"\r\n/\\' and 32 <= ord(character) < 127
        ).strip() or "download"
        response = send_file(
            io.BytesIO(file_data),
            download_name=sanitized_filename,
            as_attachment=True,
        )
        response.headers["Content-Disposition"] = (
            f'attachment; filename="{sanitized_filename}"'
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    def private_file_response(cid: str):
        info = metadata.get_file_info(cid)
        if info and info.get("space_id"):
            return jsonify({"error": "File not found"}), 404
        return None

    def retire_replaced_chunks(old_manifest: dict | None, cid: str):
        if old_manifest is None:
            return
        referenced_hashes = set()
        for file_info in metadata.list_files(include_private=True):
            if file_info["cid"] == cid:
                continue
            other_manifest = metadata.get_manifest(file_info["cid"])
            if other_manifest is not None:
                referenced_hashes.update(
                    placement["chunk_hash"]
                    for placement in other_manifest.get("placements", [])
                )
        network.delete_file_chunks(old_manifest, referenced_hashes)

    @app.route("/api/spaces", methods=["POST"])
    def create_shared_space():
        if not is_access_authorized():
            return authorization_error()
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
    @serialize_quota_upload
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
        quota_failure = quota_error(len(file_data), space_id=space_id)
        if quota_failure:
            return jsonify(quota_failure[0]), quota_failure[1]
        if not file_data.startswith(b"DCAS1"):
            return jsonify({"error": "Shared-space uploads must use the DCAS1 client-side envelope"}), 400
        try:
            stored_data = storage_encryptor.encrypt(file_data)
            manifest = network.store_por_bytes(stored_data, filename=file.filename)
        except RuntimeError as error:
            return jsonify({"error": str(error)}), 503

        manifest["storage_encrypted"] = True
        manifest["source_fingerprint"] = storage_encryptor.fingerprint(file_data)
        cid = manifest["cid"]["cid"]
        existing = metadata.get_file_info(cid)
        if existing:
            return jsonify({"error": "This content is already stored; choose a different file"}), 409
        metadata.store_manifest(manifest, owner="shared", space_id=space_id)
        return jsonify({
            "message": "File added to the shared space.",
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
        try:
            file_data = storage_encryptor.decrypt(file_data)
        except StorageEncryptionError:
            return jsonify({"error": "Stored file could not be decrypted; check the storage key and data integrity."}), 500
        metadata.log_event(
            "RETRIEVE",
            details="Encrypted file downloaded from shared space",
        )
        return download_response(file_data, manifest["filename"])

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
            details="Encrypted shared-space file integrity checked",
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

    @app.route("/api/spaces/<space_id>", methods=["DELETE"])
    def delete_shared_space(space_id):
        space, access = get_space_access(space_id)
        if space is None or (access != "admin" and not is_admin_authorized()):
            return jsonify({"error": "Shared space not found or owner access required"}), 404

        files = metadata.list_files(space_id=space_id)
        manifests = [
            metadata.get_manifest(file_info["cid"])
            for file_info in files
        ]
        deleted_files = sum(
            1 for file_info in files if metadata.delete_file(file_info["cid"])
        )

        referenced_chunk_hashes = set()
        for file_info in metadata.list_files(include_private=True):
            manifest = metadata.get_manifest(file_info["cid"])
            if manifest is not None:
                referenced_chunk_hashes.update(
                    placement["chunk_hash"]
                    for placement in manifest.get("placements", [])
                )
        for manifest in manifests:
            if manifest is not None:
                network.delete_file_chunks(manifest, referenced_chunk_hashes)

        if not metadata.delete_shared_space(space_id):
            return jsonify({"error": "Shared space not found or owner access required"}), 404
        metadata.log_event(
            "SPACE_DELETE",
            details=f"Shared space deleted with {deleted_files} files",
        )
        return jsonify({"space_id": space_id, "deleted_files": deleted_files})

    # ── Upload ──────────────────────────────────────────────────────

    @app.route("/api/upload", methods=["POST"])
    @serialize_quota_upload
    def upload_file():
        """Upload a file to the decentralized network."""
        if not is_access_authorized():
            return authorization_error()
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
        source_fingerprint = storage_encryptor.fingerprint(file_data)
        if metadata.has_shared_source_fingerprint(source_fingerprint):
            return jsonify({"error": "This content belongs to a shared space and cannot be uploaded publicly"}), 409
        source_cid = network.cid_generator.generate(file_data)
        existing = metadata.get_file_info(source_cid.cid_string)
        old_manifest = metadata.get_manifest(source_cid.cid_string)
        if existing and existing.get("space_id"):
            return jsonify({"error": "This content belongs to a shared space and cannot be replaced"}), 409
        if (
            old_manifest
            and old_manifest.get("storage_encrypted")
            and old_manifest.get("cid_hash_is_client_content")
            and isinstance(old_manifest.get("por"), dict)
            and old_manifest["por"].get("scheme") == PairingPoR.SCHEME
        ):
            old_manifest["filename"] = file.filename
            metadata.store_manifest(old_manifest, owner=owner, tags=tags)
            return jsonify({
                "message": "File uploaded and distributed successfully.",
                "cid": old_manifest["cid"]["cid"],
                "hash_digest": old_manifest["cid"]["hash_digest"],
                "filename": old_manifest["filename"],
                "total_size": old_manifest["total_size"],
                "chunk_count": old_manifest["chunk_count"],
                "merkle_root": old_manifest["merkle_root"],
                "replication_factor": old_manifest["replication_factor"],
            }), 201

        quota_failure = quota_error(
            len(file_data),
            replacing_cid=source_cid.cid_string,
        )
        if quota_failure:
            return jsonify(quota_failure[0]), quota_failure[1]

        # Encrypt before storage-node distribution; PoR tags cover ciphertext shards.
        try:
            stored_data = storage_encryptor.encrypt(file_data)
            manifest = network.store_por_bytes(
                stored_data,
                filename=file.filename,
                cid_override=source_cid,
            )
        except RuntimeError as error:
            return jsonify({"error": str(error)}), 503
        except (OSError, sqlite3.Error):
            app.logger.exception("File upload failed during storage.")
            return jsonify({"error": "Upload failed due to a storage error."}), 500
        manifest["storage_size"] = manifest["total_size"]
        manifest["total_size"] = len(file_data)
        manifest["storage_encrypted"] = True
        manifest["cid_hash_is_client_content"] = True
        manifest["source_fingerprint"] = source_fingerprint

        # Store manifest in metadata DB
        try:
            metadata.store_manifest(manifest, owner=owner, tags=tags)
        except (OSError, sqlite3.Error, PyMongoError):
            app.logger.exception("File upload failed while saving metadata.")
            return jsonify({"error": "Upload failed while saving file metadata."}), 500
        retire_replaced_chunks(old_manifest, manifest["cid"]["cid"])

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
    @serialize_quota_upload
    def upload_text():
        """Upload text content directly."""
        if not is_access_authorized():
            return authorization_error()
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

        source_fingerprint = storage_encryptor.fingerprint(content)
        if metadata.has_shared_source_fingerprint(source_fingerprint):
            return jsonify({"error": "This content belongs to a shared space and cannot be uploaded publicly"}), 409
        source_cid = network.cid_generator.generate(content)
        existing = metadata.get_file_info(source_cid.cid_string)
        old_manifest = metadata.get_manifest(source_cid.cid_string)
        if existing and existing.get("space_id"):
            return jsonify({"error": "This content belongs to a shared space and cannot be replaced"}), 409
        if (
            old_manifest
            and old_manifest.get("storage_encrypted")
            and old_manifest.get("cid_hash_is_client_content")
            and isinstance(old_manifest.get("por"), dict)
            and old_manifest["por"].get("scheme") == PairingPoR.SCHEME
        ):
            old_manifest["filename"] = filename
            metadata.store_manifest(old_manifest, owner=owner)
            return jsonify({
                "message": "Text uploaded successfully.",
                "cid": old_manifest["cid"]["cid"],
                "hash_digest": old_manifest["cid"]["hash_digest"],
                "filename": filename,
                "total_size": old_manifest["total_size"],
                "chunk_count": old_manifest["chunk_count"],
                "merkle_root": old_manifest["merkle_root"],
            }), 201

        quota_failure = quota_error(
            len(content),
            replacing_cid=source_cid.cid_string,
        )
        if quota_failure:
            return jsonify(quota_failure[0]), quota_failure[1]

        try:
            stored_data = storage_encryptor.encrypt(content)
            manifest = network.store_por_bytes(
                stored_data,
                filename=filename,
                cid_override=source_cid,
            )
        except RuntimeError as error:
            return jsonify({"error": str(error)}), 503
        manifest["storage_size"] = manifest["total_size"]
        manifest["total_size"] = len(content)
        manifest["storage_encrypted"] = True
        manifest["cid_hash_is_client_content"] = True
        manifest["source_fingerprint"] = source_fingerprint
        metadata.store_manifest(manifest, owner=owner)
        retire_replaced_chunks(old_manifest, manifest["cid"]["cid"])

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
        if manifest.get("storage_encrypted"):
            try:
                file_data = storage_encryptor.decrypt(file_data)
            except StorageEncryptionError:
                return jsonify({
                    "error": "Stored file could not be decrypted; check the storage key and data integrity."
                }), 500

        metadata.log_event("RETRIEVE", cid, manifest["filename"], "File downloaded")

        return download_response(file_data, manifest["filename"])

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

    @app.route("/api/verify/<cid>/nodes/<node_id>", methods=["POST"])
    def challenge_node(cid, node_id):
        """Verify a pairing-PoR challenge for a node's assigned coded shard."""
        denied = private_file_response(cid)
        if denied:
            return denied
        manifest = metadata.get_manifest(cid)
        if manifest is None:
            return jsonify({"error": "File not found"}), 404

        data = request.get_json(silent=True)
        if data is None:
            data = {}
        if not isinstance(data, dict):
            return jsonify({"error": "Request body must be an object"}), 400
        sample_count = data.get("sample_count")
        if sample_count is not None and (
            not isinstance(sample_count, int)
            or isinstance(sample_count, bool)
            or sample_count < 2
            or sample_count > 64
        ):
            return jsonify({"error": "'sample_count' must be an integer from 2 to 64"}), 400

        try:
            result = verifier.prove_node_possession(
                node_id,
                manifest,
                sample_count=sample_count,
            )
        except ValueError as error:
            return jsonify({"error": str(error)}), 400
        metadata.log_event(
            "NODE_POR_CHALLENGE",
            cid,
            manifest["filename"],
            result.message,
            status="success" if result.passed else "failure",
            node_id=node_id,
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
        if not is_admin_authorized():
            return authorization_error()
        if not app.config["DCAS_ENABLE_CHAOS"]:
            return jsonify({"error": "Chaos/simulation routes are disabled."}), 403
        network.simulate_node_failure(node_id)
        metadata.log_event("NODE_FAILURE", node_id=node_id, details=f"Node {node_id} taken offline")
        return jsonify({"message": f"Node {node_id} is now offline."})

    @app.route("/api/network/recover/<node_id>", methods=["POST"])
    def recover_node(node_id):
        """Recover a failed node (bring online)."""
        if not is_admin_authorized():
            return authorization_error()
        if not app.config["DCAS_ENABLE_CHAOS"]:
            return jsonify({"error": "Chaos/simulation routes are disabled."}), 403
        network.simulate_node_recovery(node_id)
        metadata.log_event("NODE_RECOVERY", node_id=node_id, details=f"Node {node_id} brought online")
        return jsonify({"message": f"Node {node_id} is now online."})

    # ── Audit log ───────────────────────────────────────────────────

    @app.route("/api/events", methods=["GET"])
    @app.route("/api/audit-log", methods=["GET"])
    def get_audit_log():
        """View the audit log."""
        cid = request.args.get("cid")
        event_type = request.args.get("event_type")
        limit = request.args.get("limit", 50, type=int)
        logs = metadata.get_audit_log(cid=cid, event_type=event_type, limit=limit)
        public_cids = {
            file_info["cid"] for file_info in metadata.list_files()
        }
        logs = [
            entry
            for entry in logs
            if not entry.get("cid") or entry.get("cid") in public_cids
        ]
        stats = metadata.get_audit_stats()
        return jsonify({"logs": logs, "stats": stats})

    # ── Simulate corruption ─────────────────────────────────────────

    @app.route("/api/simulate/corrupt/<cid>/<int:chunk_index>", methods=["POST"])
    def corrupt_chunk(cid, chunk_index):
        """Simulate data corruption for testing."""
        if not is_admin_authorized():
            return authorization_error()
        if not app.config["DCAS_ENABLE_CHAOS"]:
            return jsonify({"error": "Chaos/simulation routes are disabled."}), 403
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
        info = metadata.get_file_info(cid)
        if info is None:
            return jsonify({"error": "File not found"}), 404
        if info.get("space_id"):
            _, access = get_space_access(info["space_id"])
            if access not in ("admin", "writer") and not is_admin_authorized():
                return authorization_error()
        elif not is_admin_authorized():
            return authorization_error()
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

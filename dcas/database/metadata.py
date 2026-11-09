"""
SQLite-backed metadata store and audit log.

Stores file manifests, CID mappings, ownership info,
and a full audit trail of every verification event.
"""

import os
import json
import sqlite3
from datetime import datetime, timezone
from typing import Optional


class MetadataStore:
    """
    Persistent metadata and audit store backed by SQLite.

    Tables:
        files      – File manifests, CIDs, and ownership.
        audit_log  – Timestamped records of uploads, retrievals,
                     verifications, and errors.
    """

    def __init__(self, db_path: str = "dcas_metadata.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        """Initialize the database schema."""
        cursor = self.conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                cid             TEXT UNIQUE NOT NULL,
                filename        TEXT NOT NULL,
                hash_digest     TEXT NOT NULL,
                algorithm       TEXT NOT NULL DEFAULT 'sha256',
                total_size      INTEGER NOT NULL,
                chunk_count     INTEGER NOT NULL,
                merkle_root     TEXT NOT NULL,
                manifest_json   TEXT NOT NULL,
                owner           TEXT DEFAULT 'system',
                tags            TEXT DEFAULT '[]',
                created_at      TEXT NOT NULL,
                updated_at      TEXT NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                event_type  TEXT NOT NULL,
                cid         TEXT,
                filename    TEXT,
                details     TEXT,
                status      TEXT NOT NULL DEFAULT 'success',
                node_id     TEXT
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_files_cid ON files(cid)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_cid ON audit_log(cid)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_log(event_type)
        """)

        self.conn.commit()

    # ── File manifest operations ────────────────────────────────────

    def store_manifest(self, manifest: dict, owner: str = "system", tags: list[str] | None = None) -> int:
        """
        Store a file manifest in the database.

        Args:
            manifest: The manifest dict from StorageNetwork.store_file().
            owner:    Owner identifier.
            tags:     Optional list of string tags.

        Returns:
            The database row ID.
        """
        now = datetime.now(timezone.utc).isoformat()
        cid_info = manifest["cid"]
        cid_str = cid_info["cid"]

        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO files
                (cid, filename, hash_digest, algorithm, total_size,
                 chunk_count, merkle_root, manifest_json, owner, tags,
                 created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cid_str,
                manifest["filename"],
                cid_info["hash_digest"],
                cid_info["algorithm"],
                manifest["total_size"],
                manifest["chunk_count"],
                manifest["merkle_root"],
                json.dumps(manifest),
                owner,
                json.dumps(tags or []),
                now,
                now,
            ),
        )
        self.conn.commit()

        self.log_event("UPLOAD", cid_str, manifest["filename"], "File stored successfully")
        return cursor.lastrowid

    def get_manifest(self, cid: str) -> Optional[dict]:
        """Retrieve a manifest by CID."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT manifest_json FROM files WHERE cid = ?", (cid,))
        row = cursor.fetchone()
        if row:
            return json.loads(row["manifest_json"])
        return None

    def get_file_info(self, cid: str) -> Optional[dict]:
        """Retrieve full file metadata by CID."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM files WHERE cid = ?", (cid,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None

    def list_files(self, owner: str | None = None) -> list[dict]:
        """List all stored files, optionally filtered by owner."""
        cursor = self.conn.cursor()
        if owner:
            cursor.execute(
                "SELECT id, cid, filename, total_size, chunk_count, owner, created_at FROM files WHERE owner = ? ORDER BY created_at DESC",
                (owner,),
            )
        else:
            cursor.execute(
                "SELECT id, cid, filename, total_size, chunk_count, owner, created_at FROM files ORDER BY created_at DESC"
            )
        return [dict(row) for row in cursor.fetchall()]

    def delete_file(self, cid: str) -> bool:
        """Delete a file's metadata by CID."""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM files WHERE cid = ?", (cid,))
        self.conn.commit()
        if cursor.rowcount > 0:
            self.log_event("DELETE", cid, details="File metadata deleted")
            return True
        return False

    def search_files(self, query: str) -> list[dict]:
        """Search files by filename or CID (partial match)."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT id, cid, filename, total_size, owner, created_at FROM files WHERE filename LIKE ? OR cid LIKE ?",
            (f"%{query}%", f"%{query}%"),
        )
        return [dict(row) for row in cursor.fetchall()]

    # ── Audit log operations ────────────────────────────────────────

    def log_event(
        self,
        event_type: str,
        cid: str | None = None,
        filename: str | None = None,
        details: str | None = None,
        status: str = "success",
        node_id: str | None = None,
    ) -> int:
        """
        Record an event in the audit log.

        Args:
            event_type: E.g. UPLOAD, RETRIEVE, VERIFY, ERROR, DELETE.
            cid:        Related content identifier.
            filename:   Related filename.
            details:    Human-readable description.
            status:     'success', 'failure', or 'warning'.
            node_id:    Related node, if applicable.

        Returns:
            The audit log row ID.
        """
        now = datetime.now(timezone.utc).isoformat()
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO audit_log (timestamp, event_type, cid, filename, details, status, node_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (now, event_type, cid, filename, details, status, node_id),
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_audit_log(
        self,
        cid: str | None = None,
        event_type: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        """
        Query the audit log with optional filters.

        Args:
            cid:        Filter by content identifier.
            event_type: Filter by event type.
            limit:      Maximum number of records to return.

        Returns:
            List of audit log entries (newest first).
        """
        cursor = self.conn.cursor()
        query = "SELECT * FROM audit_log WHERE 1=1"
        params = []
        if cid:
            query += " AND cid = ?"
            params.append(cid)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

    def get_audit_stats(self) -> dict:
        """Return summary statistics of the audit log."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT event_type, COUNT(*) as count FROM audit_log GROUP BY event_type")
        events = {row["event_type"]: row["count"] for row in cursor.fetchall()}
        cursor.execute("SELECT COUNT(*) as total FROM audit_log")
        total = cursor.fetchone()["total"]
        return {"total_events": total, "by_type": events}

    def close(self):
        """Close the database connection."""
        self.conn.close()

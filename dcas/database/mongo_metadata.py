"""MongoDB-backed metadata and audit storage."""

import re
from datetime import datetime, timezone
from typing import Optional

from pymongo import MongoClient, DESCENDING


class MongoMetadataStore:
    """MetadataStore-compatible persistence backed by MongoDB."""

    def __init__(
        self,
        uri: str,
        database_name: str = "dcas",
        server_selection_timeout_ms: int = 5000,
    ):
        self.client = MongoClient(uri, serverSelectionTimeoutMS=server_selection_timeout_ms)
        self.client.admin.command("ping")
        self.db = self.client[database_name]
        self.files = self.db["files"]
        self.shared_spaces = self.db["shared_spaces"]
        self.audit_log = self.db["audit_log"]
        self.files.create_index("cid", unique=True)
        self.files.create_index("space_id")
        self.shared_spaces.create_index("space_id", unique=True)
        self.audit_log.create_index([("cid", 1)])
        self.audit_log.create_index([("event_type", 1)])
        self.audit_log.create_index([("timestamp", DESCENDING)])

    def store_manifest(
        self,
        manifest: dict,
        owner: str = "system",
        tags: list[str] | None = None,
        space_id: str | None = None,
    ) -> str:
        now = datetime.now(timezone.utc).isoformat()
        cid_info = manifest["cid"]
        cid = cid_info["cid"]
        self.files.replace_one(
            {"cid": cid},
            {
                "cid": cid,
                "filename": manifest["filename"],
                "hash_digest": cid_info["hash_digest"],
                "algorithm": cid_info["algorithm"],
                "total_size": manifest["total_size"],
                "chunk_count": manifest["chunk_count"],
                "merkle_root": manifest["merkle_root"],
                "manifest_json": manifest,
                "owner": owner,
                "tags": tags or [],
                "space_id": space_id,
                "created_at": now,
                "updated_at": now,
            },
            upsert=True,
        )
        stored = self.files.find_one({"cid": cid}, {"_id": 1})
        self.log_event("UPLOAD", cid, manifest["filename"], "File stored successfully")
        return str(stored["_id"])

    def get_manifest(self, cid: str) -> Optional[dict]:
        document = self.files.find_one({"cid": cid}, {"manifest_json": 1})
        return document["manifest_json"] if document else None

    def get_file_info(self, cid: str) -> Optional[dict]:
        document = self.files.find_one({"cid": cid})
        if document is None:
            return None
        document["id"] = str(document.pop("_id"))
        return document

    def list_files(
        self,
        owner: str | None = None,
        space_id: str | None = None,
        include_private: bool = False,
    ) -> list[dict]:
        if space_id is not None:
            query = {"space_id": space_id}
        elif include_private:
            query = {}
        else:
            query = {"space_id": None}
        if owner:
            query["owner"] = owner
        projection = {
            "_id": 1,
            "cid": 1,
            "filename": 1,
            "total_size": 1,
            "chunk_count": 1,
            "owner": 1,
            "created_at": 1,
        }
        documents = self.files.find(query, projection).sort("created_at", DESCENDING)
        return [self._with_string_id(document) for document in documents]

    def create_shared_space(
        self,
        space_id: str,
        name: str,
        admin_token_hash: str,
        share_token_hash: str,
        allow_upload: bool = False,
    ) -> None:
        self.shared_spaces.insert_one({
            "space_id": space_id,
            "name": name,
            "admin_token_hash": admin_token_hash,
            "share_token_hash": share_token_hash,
            "allow_upload": allow_upload,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })

    def get_shared_space(self, space_id: str) -> Optional[dict]:
        return self.shared_spaces.find_one({"space_id": space_id}, {"_id": 0})

    def update_shared_space_link(self, space_id: str, share_token_hash: str | None) -> bool:
        result = self.shared_spaces.update_one(
            {"space_id": space_id},
            {"$set": {"share_token_hash": share_token_hash}},
        )
        return result.matched_count > 0

    def get_private_cids(self) -> set[str]:
        return {
            document["cid"]
            for document in self.files.find(
                {"space_id": {"$ne": None}},
                {"_id": 0, "cid": 1},
            )
        }

    def delete_file(self, cid: str) -> bool:
        result = self.files.delete_one({"cid": cid})
        if result.deleted_count:
            self.log_event("DELETE", cid, details="File metadata deleted")
            return True
        return False

    def search_files(self, query: str) -> list[dict]:
        pattern = re.compile(re.escape(query), re.IGNORECASE)
        projection = {
            "_id": 1,
            "cid": 1,
            "filename": 1,
            "total_size": 1,
            "owner": 1,
            "created_at": 1,
        }
        documents = self.files.find(
            {"space_id": None, "$or": [{"filename": pattern}, {"cid": pattern}]},
            projection,
        )
        return [self._with_string_id(document) for document in documents]

    def log_event(
        self,
        event_type: str,
        cid: str | None = None,
        filename: str | None = None,
        details: str | None = None,
        status: str = "success",
        node_id: str | None = None,
    ) -> str:
        document = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "cid": cid,
            "filename": filename,
            "details": details,
            "status": status,
            "node_id": node_id,
        }
        result = self.audit_log.insert_one(document)
        return str(result.inserted_id)

    def get_audit_log(
        self,
        cid: str | None = None,
        event_type: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        query = {}
        if cid:
            query["cid"] = cid
        if event_type:
            query["event_type"] = event_type
        documents = self.audit_log.find(query).sort("timestamp", DESCENDING).limit(limit)
        return [self._with_string_id(document) for document in documents]

    def get_audit_stats(self) -> dict:
        counts = self.audit_log.aggregate([
            {"$group": {"_id": "$event_type", "count": {"$sum": 1}}},
        ])
        by_type = {item["_id"]: item["count"] for item in counts}
        return {
            "total_events": self.audit_log.count_documents({}),
            "by_type": by_type,
        }

    def close(self):
        self.client.close()

    @staticmethod
    def _with_string_id(document: dict) -> dict:
        document["id"] = str(document.pop("_id"))
        return document

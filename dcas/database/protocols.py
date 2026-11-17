"""Structural interfaces for metadata storage backends."""

from typing import Protocol, runtime_checkable


@runtime_checkable
class MetadataStoreProtocol(Protocol):
    """Operations shared by the SQLite and MongoDB metadata stores."""

    def store_manifest(
        self,
        manifest: dict,
        owner: str = "system",
        tags: list[str] | None = None,
        space_id: str | None = None,
    ) -> int | str: ...

    def get_manifest(self, cid: str) -> dict | None: ...

    def update_shared_manifest(self, cid: str, manifest: dict) -> bool: ...

    def get_file_info(self, cid: str) -> dict | None: ...

    def list_files(
        self,
        owner: str | None = None,
        space_id: str | None = None,
        include_private: bool = False,
    ) -> list[dict]: ...

    def has_shared_source_fingerprint(self, fingerprint: str) -> bool: ...

    def create_shared_space(
        self,
        space_id: str,
        name: str,
        admin_token_hash: str,
        share_token_hash: str,
        allow_upload: bool = False,
    ) -> None: ...

    def get_shared_space(self, space_id: str) -> dict | None: ...

    def update_shared_space_link(
        self,
        space_id: str,
        share_token_hash: str | None,
    ) -> bool: ...

    def delete_shared_space(self, space_id: str) -> bool: ...

    def get_private_cids(self) -> set[str]: ...

    def delete_file(self, cid: str) -> bool: ...

    def search_files(self, query: str) -> list[dict]: ...

    def log_event(
        self,
        event_type: str,
        cid: str | None = None,
        filename: str | None = None,
        details: str | None = None,
        status: str = "success",
        node_id: str | None = None,
    ) -> int | str: ...

    def get_audit_log(
        self,
        cid: str | None = None,
        event_type: str | None = None,
        limit: int = 50,
    ) -> list[dict]: ...

    def get_audit_stats(self) -> dict: ...

    def close(self) -> None: ...

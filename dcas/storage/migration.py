"""One-time migration of legacy shared-space files to encrypted node storage."""

from .encryption import StorageEncryptionError, StorageEncryptor


def migrate_shared_storage(components: dict) -> dict[str, int]:
    """Encrypt legacy shared files in place while preserving their CIDs."""
    network = components["network"]
    metadata = components["metadata"]
    encryptor: StorageEncryptor = components["storage_encryptor"]
    migrated = 0
    already_encrypted = 0

    for file_info in metadata.list_files(include_private=True):
        cid = file_info["cid"]
        details = metadata.get_file_info(cid)
        if details is None or not details.get("space_id"):
            continue

        manifest = metadata.get_manifest(cid)
        if manifest is None:
            raise RuntimeError(f"Shared file {cid} has no manifest; migration stopped.")
        stored_data = network.retrieve_file(manifest)
        if stored_data is None:
            raise RuntimeError(f"Shared file {cid} cannot be retrieved; migration stopped.")

        if manifest.get("storage_encrypted"):
            try:
                client_payload = encryptor.decrypt(stored_data)
            except StorageEncryptionError as error:
                raise RuntimeError(
                    f"Shared file {cid} failed storage authentication; restore the original "
                    "storage key or investigate corruption before retrying."
                ) from error
            source_fingerprint = encryptor.fingerprint(client_payload)
            if manifest.get("source_fingerprint") != source_fingerprint:
                manifest["source_fingerprint"] = source_fingerprint
                if not metadata.update_shared_manifest(cid, manifest):
                    raise RuntimeError(f"Shared file {cid} changed during migration.")
            already_encrypted += 1
        else:
            client_payload = stored_data
            is_wrapped = False
            if stored_data.startswith(StorageEncryptor.ENVELOPE_PREFIX):
                try:
                    client_payload = encryptor.decrypt(stored_data)
                except StorageEncryptionError as error:
                    raise RuntimeError(
                        f"Shared file {cid} has an unauthenticated storage envelope; "
                        "restore the original storage key or investigate corruption."
                    ) from error
                else:
                    is_wrapped = True

            if is_wrapped:
                manifest["storage_encrypted"] = True
                manifest["source_fingerprint"] = encryptor.fingerprint(client_payload)
                if not metadata.update_shared_manifest(cid, manifest):
                    raise RuntimeError(f"Shared file {cid} changed during migration.")
                already_encrypted += 1
            else:
                old_chunk_hashes = list(dict.fromkeys(
                    placement["chunk_hash"] for placement in manifest["placements"]
                ))
                replacement = network.store_bytes(
                    encryptor.encrypt(client_payload),
                    filename=manifest["filename"],
                )
                replacement["cid"] = manifest["cid"]
                replacement["total_size"] = len(client_payload)
                replacement["storage_encrypted"] = True
                replacement["cid_hash_is_client_content"] = True
                replacement["source_fingerprint"] = encryptor.fingerprint(client_payload)
                replacement["storage_migration_old_chunks"] = old_chunk_hashes

                if not metadata.update_shared_manifest(cid, replacement):
                    referenced = _referenced_chunks(metadata)
                    network.delete_file_chunks(replacement, referenced)
                    raise RuntimeError(f"Shared file {cid} changed during migration.")
                manifest = replacement
                migrated += 1

        _remove_retired_chunks(network, metadata, manifest)

    return {"migrated": migrated, "already_encrypted": already_encrypted}


def _referenced_chunks(metadata) -> set[str]:
    referenced = set()
    for file_info in metadata.list_files(include_private=True):
        manifest = metadata.get_manifest(file_info["cid"])
        if manifest is not None:
            referenced.update(
                placement["chunk_hash"] for placement in manifest["placements"]
            )
    return referenced


def _remove_retired_chunks(network, metadata, manifest: dict) -> None:
    retired_hashes = manifest.get("storage_migration_old_chunks", [])
    if not retired_hashes:
        return

    network.delete_file_chunks(
        {"placements": [{"chunk_hash": chunk_hash} for chunk_hash in retired_hashes]},
        _referenced_chunks(metadata),
    )
    manifest.pop("storage_migration_old_chunks", None)
    if not metadata.update_shared_manifest(manifest["cid"]["cid"], manifest):
        raise RuntimeError(
            f"Shared file {manifest['cid']['cid']} changed while cleaning old chunks."
        )

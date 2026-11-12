# Shared-space storage encryption

Shared-space uploads have two encryption layers:

1. The browser encrypts the file with the share key before uploading it.
2. The API wraps the upload in AES-256-GCM before chunking and writing it to storage nodes.

The second layer means a writer who bypasses the browser and submits plaintext (even with a `DCAS1` prefix) still sends encrypted bytes to storage nodes. On an authorized download, the API authenticates and removes only its storage layer; the browser then decrypts the original client-side envelope.

## Storage key

For local development, the API creates a random 32-byte key at `.dcas-storage-key` inside the configured network directory. Keep this file private and preserve it with the stored data. Losing or replacing it makes shared-space files unreadable.

For deployment, set `DCAS_STORAGE_ENCRYPTION_KEY` to a stable URL-safe base64 encoding of a random 32-byte key, or set `DCAS_STORAGE_KEY_FILE` to a protected persistent key-file path. Do not commit the key or expose it to storage-node operators. Back it up securely.

This layer protects stored bytes from storage nodes, but does not make the API operator untrusted or blind: the API receives uploads and holds the storage key. With the normal browser flow, the inner AES-GCM envelope still hides file contents from an honest API process because its share key is not sent to the API. However, the API operator controls the JavaScript served to browsers, and a write-link holder can bypass the browser and submit plaintext; `DCAS1` is only a format marker, not proof of client encryption. Regular, non-shared uploads are unchanged.

Files written before this change are not converted automatically and may still be stored without the API encryption layer. Stop the server, back up the metadata and node directories, then run `python -m dcas.run_server --migrate-shared-storage` with the same `--network-dir`, `--db`, node settings, and MongoDB environment as normal. The command keeps existing CIDs and access links, verifies already-wrapped files, encrypts legacy shared files, and removes old chunks that are no longer referenced. It exits without starting the web server. Review the migration result before restarting; preserve the storage key and backups securely.

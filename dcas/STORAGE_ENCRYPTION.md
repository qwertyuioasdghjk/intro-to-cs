# Storage encryption

All uploads through the regular DCAS API are wrapped in AES-256-GCM before
erasure coding, PoR tagging, and writing to storage nodes. The API decrypts
regular file downloads after retrieving the stored data. Public-file CIDs and
reported sizes still describe the original content; shard hashes and PoR
sectors cover the encrypted storage envelope.

The randomized envelope intentionally prevents deduplication of equal plaintext
chunks across different files. Re-uploading an already encrypted public file
through the same API reuses its existing stored copy.

Shared-space uploads have an additional client-side encryption layer:

1. The browser encrypts the file with the share key before uploading it.
2. The API wraps the upload in AES-256-GCM before chunking and writing it to storage nodes.

The second layer means a writer who bypasses the browser and submits plaintext (even with a `DCAS1` prefix) still sends encrypted bytes to storage nodes. On an authorized download, the API authenticates and removes only its storage layer; the browser then decrypts the original client-side envelope.

## Storage key

For local development, the API creates a random 32-byte key at `.dcas-storage-key` inside the configured network directory. Keep this file private and preserve it with the stored data. Losing or replacing it makes API-uploaded files unreadable.

For deployment, set `DCAS_STORAGE_ENCRYPTION_KEY` to a stable URL-safe base64 encoding of a random 32-byte key, or set `DCAS_STORAGE_KEY_FILE` to a protected persistent key-file path. Do not commit the key or expose it to storage-node operators. Back it up securely.

This layer protects stored bytes from storage nodes, but does not make the API operator untrusted or blind: regular uploads reach the API as plaintext, and the API holds the storage key. With the normal browser flow, the inner AES-GCM envelope still hides shared-space file contents from an honest API process because its share key is not sent to the API. However, the API operator controls the JavaScript served to browsers, and a write-link holder can bypass the browser and submit plaintext; `DCAS1` is only a format marker, not proof of client encryption.

Files written before storage encryption was enabled are not converted automatically and may still be stored as plaintext. The `--migrate-shared-storage` command only migrates shared-space files. For legacy public files, upload a new encrypted copy and verify it before retiring the old manifest and chunks. Preserve the storage key and backups securely.

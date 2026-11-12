# Shared-space storage encryption

Shared-space uploads have two encryption layers:

1. The browser encrypts the file with the share key before uploading it.
2. The API wraps the upload in AES-256-GCM before chunking and writing it to storage nodes.

The second layer means a writer who bypasses the browser and submits plaintext (even with a `DCAS1` prefix) still sends encrypted bytes to storage nodes. On an authorized download, the API authenticates and removes only its storage layer; the browser then decrypts the original client-side envelope.

## Storage key

For local development, the API creates a random 32-byte key at `.dcas-storage-key` inside the configured network directory. Keep this file private and preserve it with the stored data. Losing or replacing it makes shared-space files unreadable.

For deployment, set `DCAS_STORAGE_ENCRYPTION_KEY` to a stable URL-safe base64 encoding of a random 32-byte key, or set `DCAS_STORAGE_KEY_FILE` to a protected persistent key-file path. Do not commit the key or expose it to storage-node operators. Back it up securely.

This design protects data from storage nodes, not from the API operator: the API handles the unwrapped upload in memory and holds the storage key. `DCAS1` remains a client-side format marker, not proof that the upload was encrypted in the browser. Shared-space files therefore should only be used with an API operator the owner trusts. Regular, non-shared uploads are unchanged.

Files written before this change are not converted automatically and may still be stored without the API encryption layer. Migrate/re-upload those shared files and securely remove the old node copies and backups before relying on this protection.

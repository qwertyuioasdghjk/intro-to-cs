# Educational pairing-based proof of retrievability

New regular API uploads use the experimental `dcas-pairing-por-2of3-edu-v2`
construction. The API encrypts the stored bytes with AES-256-GCM, calculates a
per-file sector size, applies a 2-of-3 XOR code to those ciphertext bytes, and
places the three distinct shards on three distinct nodes. Any two valid shards
reconstruct the encrypted file. Legacy manifests are not silently upgraded;
the API accepts their existing PoR scheme and identifies manifests without PoR
parameters as legacy. New manifests set `por_status: "active"`; migration
tooling marks upgraded-but-untagged manifests as `por_status: "legacy"`.
Older manifests without that field are recognized as legacy from the missing
`por` parameters.

On Python 3.11 and newer, the requirements install the optional
`py_arkworks_bls12381` native accelerator. PoR tag generation uses its
Rust-backed RFC 9380 hash-to-curve and multi-scalar multiplication (MSM), while
the protocol, compressed tag format, and `py-ecc` proof verification remain
unchanged. Bounded caches reuse decoded public bases and deterministic
hash-to-curve points. If the native module is unavailable, the application logs
a warning and uses the slower `py-ecc` tagger.

## Tags and proof verification

The dynamic calculator divides the encrypted upload length across the two data
shards and the minimum of two sectors per shard. It chooses the smallest sector
size that satisfies that minimum, from 1 byte to a maximum of 4096 bytes. Thus
small uploads need little alignment padding, while large files use larger
sectors to reduce per-sector tag overhead. Each sector is encoded as one or
more 31-byte field elements. A v2 tag is bound to the file, expected node,
shard, sector index, and selected sector size. In the BLS12-381 groups, it is:

```text
sigma[i] = x * (H(file || node || shard || i || sector_size) + sum(u[j] * m[i,j]))
```

For random nonzero challenge coefficients `c[i]`, the node returns only:

```text
sigma = sum(c[i] * sigma[i])
mu[j] = sum(c[i] * m[i,j]) mod r
```

The verifier checks the aggregate pairing equation:

```text
e(sigma, G2) = e(
    sum(c[i] * H(file || node || shard || i || sector_size)) + sum(mu[j] * U[j]),
    public_key
)
```

The challenge API rejects fewer than two sectors. The verifier checks the
response nonce, node ID, shard index, and pairing proof; sector data is not
returned during an audit. Including node and shard identities in the tag
prevents reusing a proof created for a different identity. It cannot stop
colluding nodes from relaying challenges or pooling their data.
The verifier checks the manifest's sector size, field-element count, shard size,
and minimum sector count before issuing a challenge. Existing v1 manifests keep
their original 124-byte sector interpretation and remain verifiable.

Audits remain probabilistic. If `n` sectors contain `b` corrupted sectors and
the verifier samples `c` distinct sectors uniformly, the probability of missing
that corruption is `choose(n-b, c) / choose(n, c)`. PoR does not make every
small corruption detectable in every audit. The 2-of-3 code instead provides
recovery from any one missing or hash-detectably corrupted shard; a full
retrieval also checks each candidate shard against its committed hash.

## Prototype limits and key handling

This is an educational reference prototype, not a production storage protocol.
The `py-ecc` dependency explicitly warns that its experimental code has not been
audited. The native accelerator is an optimization, not a protocol audit or
security upgrade. The XOR erasure code is intentionally simple. Do not use
this implementation for valuable or adversarial production data.

The API requires at least three nodes for new PoR uploads. Each shard is stored
on one node, regardless of the legacy replication-factor setting. The API and
node sidecars must share the same node-service bearer token when using remote
nodes; remote URLs must use HTTPS, while HTTP is allowed only on loopback.
Keep node services private.

The API creates a PoR private key at `.dcas-por-private-key.hex` inside the
configured network directory. Set `DCAS_POR_PRIVATE_KEY_FILE` to use another
path. On POSIX, the API restricts key-file permissions to the service account
(mode `0600`). On Windows, it removes inherited permissions and grants access
to the current account and `SYSTEM`. Existing key files have their permissions
tightened when loaded. These controls limit access by other local accounts but
do not encrypt the key at rest or protect against an administrator or a
compromised service account.

Back up this key only to a protected, encrypted backup location and test
restoration; losing it prevents consistent future tagging. Never commit it or
place an unprotected backup alongside the data. Use an HSM or KMS in production.
The legacy RSA-PDP key (`.dcas-pdp-private-key.pem`) receives the same file
permission protections.

The PoR tagger covers the API's encrypted storage envelope, not plaintext
uploads. The API still receives normal uploads in plaintext and holds the
storage encryption key; this is storage-layer encryption, not end-to-end
encryption against the API operator. See
[STORAGE_ENCRYPTION.md](./STORAGE_ENCRYPTION.md) for key and compatibility
details.

The node-side proof endpoint is `POST /v1/por/challenge`. The public API route
is `POST /api/verify/<cid>/nodes/<node_id>` and accepts `sample_count` from 2
through 64. Existing manifests without PoR tags are legacy and must be
re-uploaded to receive the new protection; encryption migration alone does not
retroactively add PoR tags.

## Web API resource and access controls

The web API binds to `127.0.0.1` by default and uses Waitress as its WSGI server.
Use `python -m dcas.run_server --host 0.0.0.0` or set
`DCAS_ALLOW_PUBLIC_BIND=1` to explicitly request a public bind. For other bind
addresses, set `DCAS_HOST` together with `DCAS_ALLOW_PUBLIC_BIND=1`. Use `--dev`
only for local development; it starts Flask's development server with debug
mode enabled.

Set `DCAS_ADMIN_TOKEN` to a strong secret before exposing administrative
operations. Node failure/recovery and corruption simulation additionally require
`DCAS_ENABLE_CHAOS=1`; those routes are disabled by default. Admin requests
accept `Authorization: Bearer <token>` or `X-Admin-Token`. Public file deletion
requires the admin token; shared-space file deletion also accepts that space's
owner token or its write-enabled share token.

When `DCAS_APP_TOKEN` is configured, every `/api/*` request except
`/api/health` requires the matching `X-App-Token` header. Failed invite-code
attempts are counted against the per-IP application-auth rate limit. The
dashboard itself remains accessible; the desktop client supplies the header
through its local loopback proxy.

`DCAS_ACCESS_TOKEN` optionally gates shared-space creation and public file/text
uploads. When set, supply it as `Authorization: Bearer <token>` or
`X-Access-Token`; otherwise these creation/upload routes remain open. Shared
space file operations continue to use their existing space-specific bearer
capabilities.

`DCAS_MAX_UPLOAD_MB` sets Flask's maximum request size in MiB (default: 25).
`DCAS_MAX_STORAGE_MB` sets the global stored-content ceiling in MiB (default:
1024); uploads that exceed it return HTTP 507. The optional
`DCAS_GLOBAL_STORAGE_QUOTA_BYTES` and `DCAS_SPACE_STORAGE_QUOTA_BYTES` settings
can impose lower global or per-space quotas; unset or `0` disables those
additional quotas. Upload-size and storage-limit errors return JSON.
Storage checks are serialized within one application process; deployments
sharing storage across multiple processes should coordinate quotas at the
storage layer.

The in-memory per-IP/per-route sliding-window limiter uses
`DCAS_ENABLE_RATE_LIMIT` (default `1`; set to `0` to disable) and
`DCAS_RATE_LIMIT_WINDOW_SECONDS` (default 60). `DCAS_ADMIN_RATE_LIMIT`
(default 10) controls status checks carrying an admin token;
`DCAS_WRITE_RATE_LIMIT` (default 30) is shared by uploads and space creation.
Audit and challenge limits use `DCAS_RATE_LIMIT_AUDIT` (default 30) and
`DCAS_RATE_LIMIT_CHALLENGE` (default 60).

Client IPs come from `request.remote_addr` by default. Set
`DCAS_TRUST_PROXY=1` only when requests arrive through a trusted proxy; then the
first `X-Forwarded-For` hop is used. Do not enable this on a directly reachable
server, since clients could forge that header. `DCAS_RATE_LIMIT_LOCALHOST`
defaults to `1`, which enforces limits on loopback addresses; set it to `0` to
exempt `127.0.0.1` and `::1` for local testing. The `.env` file in the project
root is loaded at server startup without overriding variables already set in
the shell. Keep `.env` private; `.env.example` documents safe defaults.

Limits are per application process and reset when it restarts; use a shared
rate-limit backend when deploying multiple workers or instances.

## On-demand Windows hosting and desktop client

On Windows, double-click `Start-DCAS-Host.bat` to initialize persistent host
tokens in the project-root `.env`, start the local API, and expose it using
Cloudflare Tunnel. The launcher generates `DCAS_APP_TOKEN` and
`DCAS_ADMIN_TOKEN` once and keeps them in `.env`, sets trusted-proxy mode, and
keeps Windows awake while serving. Install Cloudflare Tunnel if needed with:

```powershell
winget install -e --id Cloudflare.cloudflared
```

By default the launcher creates a temporary Quick Tunnel and prints its URL,
the app invite code, and the admin token. To use a named Cloudflare Tunnel,
set `DCAS_TUNNEL_NAME` in `.env`; set `DCAS_PUBLIC_URL` to show the stable
hostname in the connection summary. Share the server URL and app invite code
with desktop-client users, and keep the admin token private. Press Ctrl+C in
the launcher window to stop both processes; it checkpoints
`dcas_api_metadata.db` before exiting.

Build the Windows client after installing PyInstaller:

```powershell
python -m pip install pyinstaller
python scripts\build_desktop_client.py
```

The default output is `dist\DCAS.exe`; `--name` changes the executable base
name. On first run, the client asks for the server URL and app invite code,
validates them, and stores them in `~/.dcas/client_config.json`. It forwards
browser traffic through a loopback-only proxy that adds the invite header.
`--reset` reopens setup. The client uses pywebview when installed, otherwise it
opens an Edge/Chrome app window or the default browser. In pywebview, use
**Connection → Change Server...**; in browser mode, use the **Change Server**
button in the status window.

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

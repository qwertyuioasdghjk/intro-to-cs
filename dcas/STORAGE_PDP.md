# Educational RSA proof of data possession

The API's `POST /api/verify/<cid>/nodes/<node_id>` endpoint runs the
`dcas-rsa-pdp-edu-v1` audit. At upload time, the API splits the stored bytes
into 128-byte sectors and creates an RSA homomorphic authenticator for each
sector. A node challenge selects random sectors and coefficients. The node
returns an aggregate authenticator and an aggregate sector value, not the
sector bytes. The verifier checks the aggregate with the public parameters
saved in the manifest.

For file identifier `name`, sector `i`, sector value `m_i`, and RSA parameters
`(N, e, d)`, the educational tag is:

```text
sigma_i = (H(name || i) * u^m_i)^d mod N
```

For random challenge coefficients `v_i`, the node responds with:

```text
sigma = product(sigma_i^v_i) mod N
mu = sum(v_i * m_i)
```

The verifier checks:

```text
sigma^e = product(H(name || i)^v_i) * u^mu mod N
```

This tests possession of the sampled sectors without transmitting those sector
bytes during the audit. It is an educational PDP construction, **not a
production-audited protocol or a formal proof of retrievability**. The Python
implementation performs private RSA exponentiation itself and is not designed
to resist side-channel attacks. It also does not prove that copies are
independent, prevent a node from fetching data from a colluding peer, or
guarantee future retention, or provide privacy against an auditor who collects
many aggregate responses. Tag generation is computationally expensive in this
educational Python implementation, especially for large files. Use a reviewed
PDP/PoR implementation for production storage.

## Key and compatibility

The API creates an RSA-2048 private key at
`.dcas-pdp-private-key.pem` inside the configured network directory. Set
`DCAS_PDP_PRIVATE_KEY_FILE` to use another path. Protect and back up this key
with appropriate filesystem ACLs. The key is unencrypted on disk; do not expose
it to storage-node operators or commit it to source control. Losing it prevents
using the same key for future tags; existing manifests retain the public
parameters needed to verify already-stored tags. The app can generate a
replacement key, but back up the original to preserve key continuity.

Files uploaded before PDP tagging was enabled have no sector authenticators.
Upload those files again to write PDP tags and update their manifests. The
node-side endpoint is `POST /v1/pdp/challenge`; it is read-only and requires the
node to have the chunk data and PDP tags produced at upload.

The API accepts `sample_count` from 1 to 64. It counts challenged 128-byte
sectors, not file chunks. A challenge fails if the requested number exceeds
the number of sectors assigned to that node.

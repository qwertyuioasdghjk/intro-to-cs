# Sampled chunk retrievability

The verifier's `check_node_retrievability` method samples random chunks assigned
to a node, retrieves their full bytes, and verifies their hashes. The node-side
HTTP GET endpoint supports this lower-level availability check.

It checks present-time retrievability, not possession without data transfer.
New API uploads use the pairing-based proof-of-retrievability flow and 2-of-3
erasure layout documented in [STORAGE_PDP.md](./STORAGE_PDP.md). Legacy
manifests without PoR parameters cannot be challenged through the API.

## Run a local node retrieval service

The current storage network writes node data to local directories. To exercise
the separate HTTP read path, run a node service against that node's directory:

```powershell
python -m dcas.storage.node_server --node-id node-000 --storage-dir .\dcas_api_network\node-000 --port 5100
```

First set the same randomly generated secret (at least 32 printable ASCII
characters) in both terminals:

```powershell
$env:DCAS_NODE_AUTH_TOKEN = "<shared-secret>"
```

Then launch the node process. In the API terminal, set the same
`DCAS_NODE_AUTH_TOKEN` and direct checks for that node to the service:

```powershell
$env:DCAS_NODE_AUTH_TOKEN = "<shared-secret>"
python -m dcas.run_server --node-url node-000=http://127.0.0.1:5100
```

The API and sidecar must refer to the same node data. The node service is
read-only, and its raw chunk and challenge endpoints require the shared bearer
secret. HTTP node URLs are allowed only on loopback; use HTTPS and a private
network for remote nodes. The rest of the storage network still uses local node
directories, so this configuration alone does not make uploads or replication
remote/decentralized.

The sampled Merkle challenge defaults to 1 chunk and is capped at 64. This
method returns selected chunk bytes to the verifier, so use it as an
availability signal only. The pairing PoR audit is a separate endpoint; it
returns an aggregate proof rather than chunk data.

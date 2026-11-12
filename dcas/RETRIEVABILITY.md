# Sampled chunk retrievability

The verifier's `check_node_retrievability` method samples random chunks assigned
to a node, retrieves their full bytes, and verifies their hashes. The node-side
HTTP GET endpoint supports this lower-level availability check.

It checks present-time retrievability, not possession without data transfer.
The API's node-verification route now uses the RSA-PDP challenge documented in
[STORAGE_PDP.md](./STORAGE_PDP.md).

## Run a local node retrieval service

The current storage network writes node data to local directories. To exercise
the separate HTTP read path, run a node service against that node's directory:

```powershell
python -m dcas.storage.node_server --node-id node-000 --storage-dir .\dcas_api_network\node-000 --port 5100
```

In another terminal, launch the API and direct checks for that node to the
service:

```powershell
python -m dcas.run_server --node-url node-000=http://127.0.0.1:5100
```

The API and sidecar must refer to the same node data. The node service is
read-only and should only be exposed on a trusted network; deploy HTTPS and
network-level access controls before allowing remote access. The rest of the
storage network still uses local node directories, so this configuration alone
does not make uploads or replication remote/decentralized.

The `sample_count` argument defaults to 1 and is capped at 64. This method
returns selected chunk bytes to the verifier, so use it as an availability
signal only.

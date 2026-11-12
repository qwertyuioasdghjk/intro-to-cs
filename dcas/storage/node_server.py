"""HTTP service for chunk retrieval and Merkle/RSA-PDP challenges."""

import argparse
import re
import base64

from flask import Flask, Response, jsonify, request

from .node import StorageNode


def create_node_app(node_id: str, storage_dir: str) -> Flask:
    """Create a small read-only HTTP API backed by one node's storage directory."""
    app = Flask(__name__)
    node = StorageNode(node_id=node_id, storage_dir=storage_dir)

    @app.get("/v1/chunks/<chunk_hash>")
    def retrieve_chunk(chunk_hash: str):
        if not re.fullmatch(r"[0-9a-f]{64}|[0-9a-f]{128}", chunk_hash):
            return jsonify({"error": "Invalid chunk hash"}), 400
        data = node.retrieve_chunk(chunk_hash)
        if data is None:
            return jsonify({"error": "Chunk not found"}), 404
        return Response(data, mimetype="application/octet-stream")

    @app.post("/v1/challenges")
    def answer_challenge():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Request body must be an object"}), 400

        nonce_hex = payload.get("nonce_hex")
        challenges = payload.get("chunks")
        if (
            not isinstance(nonce_hex, str)
            or not re.fullmatch(r"(?:[0-9a-f]{2}){16,64}", nonce_hex)
        ):
            return jsonify({"error": "Nonce must contain 16 to 64 bytes of lowercase hex"}), 400
        if not isinstance(challenges, list) or not 1 <= len(challenges) <= 64:
            return jsonify({"error": "Challenge must contain between 1 and 64 chunks"}), 400

        challenged_chunks = []
        for item in challenges:
            if not isinstance(item, dict):
                return jsonify({"error": "Each challenged chunk must be an object"}), 400
            chunk_hash = item.get("chunk_hash")
            merkle_root = item.get("merkle_root")
            chunk_index = item.get("chunk_index")
            if (
                not isinstance(chunk_hash, str)
                or not re.fullmatch(r"[0-9a-f]{64}|[0-9a-f]{128}", chunk_hash)
                or not isinstance(merkle_root, str)
                or not re.fullmatch(r"[0-9a-f]{64}|[0-9a-f]{128}", merkle_root)
                or not isinstance(chunk_index, int)
                or isinstance(chunk_index, bool)
                or chunk_index < 0
            ):
                return jsonify({"error": "Invalid chunk challenge"}), 400

            retrieved = node.retrieve_chunk_with_proof(chunk_hash, merkle_root, chunk_index)
            if retrieved is None:
                return jsonify({"error": "Chunk or Merkle proof not found"}), 404
            chunk_data, proof = retrieved
            challenged_chunks.append({
                "chunk_hash": chunk_hash,
                "chunk_index": chunk_index,
                "data_base64": base64.b64encode(chunk_data).decode("ascii"),
                "proof": proof,
            })

        return jsonify({"nonce_hex": nonce_hex, "chunks": challenged_chunks})

    @app.post("/v1/pdp/challenge")
    def answer_pdp_challenge():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Request body must be an object"}), 400

        file_id = payload.get("file_id")
        nonce_hex = payload.get("nonce_hex")
        modulus_hex = payload.get("n")
        sectors = payload.get("sectors")
        if not isinstance(file_id, str) or not file_id or len(file_id) > 512:
            return jsonify({"error": "Invalid file identifier"}), 400
        if not isinstance(nonce_hex, str) or not re.fullmatch(r"[0-9a-f]{64}", nonce_hex):
            return jsonify({"error": "Nonce must contain 32 bytes of lowercase hex"}), 400
        if (
            not isinstance(modulus_hex, str)
            or not re.fullmatch(r"[0-9a-f]{512,1024}", modulus_hex)
        ):
            return jsonify({"error": "Invalid RSA modulus"}), 400
        if not isinstance(sectors, list) or not 1 <= len(sectors) <= 64:
            return jsonify({"error": "Challenge must contain between 1 and 64 sectors"}), 400

        for item in sectors:
            if not isinstance(item, dict):
                return jsonify({"error": "Each challenged sector must be an object"}), 400
            chunk_hash = item.get("chunk_hash")
            sector_index = item.get("sector_index")
            chunk_offset = item.get("chunk_offset")
            length = item.get("length")
            coefficient_hex = item.get("coefficient_hex")
            if (
                not isinstance(chunk_hash, str)
                or not re.fullmatch(r"[0-9a-f]{64}|[0-9a-f]{128}", chunk_hash)
                or not isinstance(sector_index, int)
                or isinstance(sector_index, bool)
                or sector_index < 0
                or not isinstance(chunk_offset, int)
                or isinstance(chunk_offset, bool)
                or chunk_offset < 0
                or not isinstance(length, int)
                or isinstance(length, bool)
                or not 0 <= length <= 128
                or not isinstance(coefficient_hex, str)
                or not re.fullmatch(r"[1-9a-f][0-9a-f]{0,31}", coefficient_hex)
            ):
                return jsonify({"error": "Invalid PDP challenge sector"}), 400

        try:
            proof = node.respond_to_pdp_challenge(payload)
        except (KeyError, ValueError):
            return jsonify({"error": "Invalid PDP challenge"}), 400
        if proof is None:
            return jsonify({"error": "Node is missing challenged data or tags"}), 404
        return jsonify(proof)

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a read-only DCAS storage-node service")
    parser.add_argument("--node-id", required=True, help="Node ID, e.g. node-000")
    parser.add_argument("--storage-dir", required=True, help="This node's storage directory")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, required=True, help="Port to listen on")
    args = parser.parse_args()

    app = create_node_app(args.node_id, args.storage_dir)
    print(
        f"DCAS node {args.node_id} retrieval/PDP endpoint: "
        f"http://{args.host}:{args.port}"
    )
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()

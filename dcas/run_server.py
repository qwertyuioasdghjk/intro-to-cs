"""
Run the DCAS web application and REST API.

Usage:
    python -m dcas.run_server
    python -m dcas.run_server --port 8080
    python -m dcas.run_server --nodes 6 --replication 3

Use --migrate-shared-storage to encrypt existing shared files before serving.
Stop the server and back up storage and metadata before running the migration.

Set DCAS_MONGODB_URI to use MongoDB for metadata and audit logs.
Otherwise, the server uses the SQLite database selected by --db.

The API also creates a private RSA-PDP tagging key in the network directory.
Set DCAS_PDP_PRIVATE_KEY_FILE to use a protected key file at another path.
"""

import argparse
import os
import sys
from urllib.parse import urlsplit

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dcas.api.server import create_app
from dcas.storage.migration import migrate_shared_storage


def main():
    parser = argparse.ArgumentParser(description="DCAS web application and REST API")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on")
    parser.add_argument("--nodes", type=int, default=4, help="Number of storage nodes")
    parser.add_argument("--replication", type=int, default=2, help="Replication factor")
    parser.add_argument("--network-dir", default="./dcas_api_network", help="Network storage directory")
    parser.add_argument("--db", default="dcas_api_metadata.db", help="Database file path")
    parser.add_argument(
        "--node-url",
        action="append",
        default=[],
        metavar="NODE_ID=URL",
        help="Use an HTTP retrieval service for a node; may be supplied more than once",
    )
    parser.add_argument(
        "--migrate-shared-storage",
        action="store_true",
        help="Encrypt existing shared files, then exit without starting the server",
    )
    args = parser.parse_args()
    node_urls = {}
    for node_url in args.node_url:
        node_id, separator, url = node_url.partition("=")
        parsed_url = urlsplit(url)
        if (
            not separator
            or not node_id
            or parsed_url.scheme not in ("http", "https")
            or not parsed_url.netloc
        ):
            parser.error("--node-url must be NODE_ID=http://host:port (or https://host:port)")
        node_urls[node_id] = url.rstrip("/")

    app = create_app(
        network_dir=args.network_dir,
        db_path=args.db,
        num_nodes=args.nodes,
        replication_factor=args.replication,
        node_urls=node_urls,
    )

    if args.migrate_shared_storage:
        components = app.extensions["dcas"]
        try:
            result = migrate_shared_storage(components)
        finally:
            components["metadata"].close()
        print(
            "Shared-storage migration complete: "
            f"{result['migrated']} migrated, "
            f"{result['already_encrypted']} already encrypted."
        )
        return

    display_host = "127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host
    print("DCAS — Decentralized Content-Addressed Storage")
    print(f"Dashboard:    http://{display_host}:{args.port}/")
    print(f"API endpoints: http://{display_host}:{args.port}/api/...")
    print(f"Storage nodes: {args.nodes} (replication factor {args.replication})")
    print(f"Metadata DB:  {'MongoDB' if os.environ.get('DCAS_MONGODB_URI') else args.db}")

    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()

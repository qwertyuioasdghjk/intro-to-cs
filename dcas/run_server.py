"""
Run the DCAS web application and REST API.

Usage:
    python -m dcas.run_server
    python -m dcas.run_server --port 8080
    python -m dcas.run_server --nodes 6 --replication 3
    python -m dcas.run_server --host 0.0.0.0
    python -m dcas.run_server --dev

Use --migrate-shared-storage to encrypt existing shared files before serving.
Stop the server and back up storage and metadata before running the migration.
The production default uses Waitress and binds only to 127.0.0.1.

Set DCAS_MONGODB_URI to use MongoDB for metadata and audit logs.
Otherwise, the server uses the SQLite database selected by --db.

New API uploads use the educational pairing PoR layout and require at least
three storage nodes. The API creates PoR and storage-encryption keys in the
network directory. Set DCAS_POR_PRIVATE_KEY_FILE and DCAS_STORAGE_KEY_FILE to
use protected key files at other paths. Key files are access-restricted but
remain unencrypted at rest; back them up only to an encrypted, protected
location. Remote node services require the same DCAS_NODE_AUTH_TOKEN in the
API and node process; use at least 32 characters.
"""

import argparse
import ipaddress
import os
import signal
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dcas.api.server import create_app
from dcas.storage.migration import migrate_shared_storage
from dcas.storage.network import is_secure_node_url, is_valid_node_auth_token


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="DCAS web application and REST API")
    parser.add_argument("--host", default=None, help="Host to bind to (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on")
    parser.add_argument("--nodes", type=int, default=4, help="Number of storage nodes (minimum 3 for PoR)")
    parser.add_argument(
        "--dev",
        action="store_true",
        help="Use Flask's development server instead of the production WSGI server",
    )
    parser.add_argument(
        "--replication",
        type=int,
        default=2,
        help="Deprecated positive setting; PoR stores one copy of each coded shard",
    )
    parser.add_argument("--network-dir", default="./dcas_api_network", help="Network storage directory")
    parser.add_argument("--db", default="dcas_api_metadata.db", help="Database file path")
    parser.add_argument(
        "--node-url",
        action="append",
        default=[],
        metavar="NODE_ID=URL",
        help="Use an authenticated node service URL; HTTPS required except on loopback",
    )
    parser.add_argument(
        "--migrate-shared-storage",
        action="store_true",
        help="Encrypt existing shared files, then exit without starting the server",
    )
    args = parser.parse_args(argv)
    if args.nodes < 3:
        parser.error("The pairing-PoR 2-of-3 layout requires at least three storage nodes.")
    requested_host = args.host
    allow_public_bind = os.environ.get("DCAS_ALLOW_PUBLIC_BIND") == "1"
    args.host = (
        requested_host
        or os.environ.get("DCAS_HOST")
        or ("0.0.0.0" if allow_public_bind else "127.0.0.1")
    )
    if not is_loopback_host(args.host) and not (
        requested_host or allow_public_bind
    ):
        parser.error(
            "A public bind address requires --host explicitly or DCAS_ALLOW_PUBLIC_BIND=1."
        )
    return args


def is_loopback_host(host):
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def main(argv=None):
    load_env_file()
    args = parse_args(argv)
    node_urls = {}
    for node_url in args.node_url:
        node_id, separator, url = node_url.partition("=")
        if (
            not separator
            or not node_id
            or not is_secure_node_url(url)
        ):
            raise SystemExit(
                "--node-url must be NODE_ID=https://host:port "
                "(HTTP is allowed only for loopback hosts)"
            )
        node_urls[node_id] = url.rstrip("/")

    node_auth_token = os.environ.get("DCAS_NODE_AUTH_TOKEN", "")
    if node_urls and not is_valid_node_auth_token(node_auth_token):
        raise SystemExit(
            "Set DCAS_NODE_AUTH_TOKEN to the same secret (at least 32 printable ASCII characters) "
            "used by every configured node service."
        )

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
    print(f"Storage nodes: {args.nodes} (XOR PoR layout: 2-of-3)")
    print(f"Metadata DB:  {'MongoDB' if os.environ.get('DCAS_MONGODB_URI') else args.db}")

    def request_shutdown(_signum, _frame):
        raise KeyboardInterrupt

    previous_handlers = {}
    for sig in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[sig] = signal.signal(sig, request_shutdown)
    if hasattr(signal, "SIGBREAK"):
        previous_handlers[signal.SIGBREAK] = signal.signal(
            signal.SIGBREAK,
            request_shutdown,
        )
    try:
        try:
            if args.dev:
                app.run(host=args.host, port=args.port, debug=True)
            else:
                from waitress import serve

                print("WSGI server: Waitress")
                serve(app, host=args.host, port=args.port)
        except KeyboardInterrupt:
            pass
    finally:
        app.extensions["dcas"]["metadata"].close()
        for sig, previous_handler in previous_handlers.items():
            signal.signal(sig, previous_handler)


def load_env_file(path: str | os.PathLike[str] | None = None) -> None:
    """Load project .env values without replacing values supplied by the shell."""
    env_path = Path(path) if path is not None else Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return

    with env_path.open(encoding="utf-8") as env_file:
        for raw_line in env_file:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if not key or key in os.environ:
                continue
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            os.environ[key] = value


if __name__ == "__main__":
    main()

"""
Run the DCAS REST API server.

Usage:
    python run_server.py
    python run_server.py --port 8080
    python run_server.py --nodes 6 --replication 3
"""

import argparse
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dcas.api.server import create_app


def main():
    parser = argparse.ArgumentParser(description="DCAS REST API Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on")
    parser.add_argument("--nodes", type=int, default=4, help="Number of storage nodes")
    parser.add_argument("--replication", type=int, default=2, help="Replication factor")
    parser.add_argument("--network-dir", default="./dcas_api_network", help="Network storage directory")
    parser.add_argument("--db", default="dcas_api_metadata.db", help="Database file path")
    args = parser.parse_args()

    app = create_app(
        network_dir=args.network_dir,
        db_path=args.db,
        num_nodes=args.nodes,
        replication_factor=args.replication,
    )

    print(f"""
╔══════════════════════════════════════════════════════╗
║   DCAS — Decentralized Content-Addressed Storage     ║
║   REST API Server                                    ║
╠══════════════════════════════════════════════════════╣
║   Host:        {args.host:<39s}║
║   Port:        {args.port:<39d}║
║   Nodes:       {args.nodes:<39d}║
║   Replication: {args.replication:<39d}║
╠══════════════════════════════════════════════════════╣
║   Endpoints:                                         ║
║   POST   /api/upload           Upload a file         ║
║   POST   /api/upload/text      Upload text           ║
║   GET    /api/files            List files             ║
║   GET    /api/file/<cid>       File info              ║
║   GET    /api/download/<cid>   Download file          ║
║   POST   /api/verify/<cid>     Verify integrity       ║
║   POST   /api/verify/<cid>/chunks    Chunk verify     ║
║   POST   /api/verify/<cid>/merkle/N  Merkle proof     ║
║   POST   /api/verify/<cid>/audit     Full audit       ║
║   GET    /api/network/status   Network status         ║
║   GET    /api/audit-log        Audit log              ║
╚══════════════════════════════════════════════════════╝
""")

    app.run(host=args.host, port=args.port, debug=True)


if __name__ == "__main__":
    main()

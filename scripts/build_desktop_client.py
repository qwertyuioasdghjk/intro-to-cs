"""Build the DCAS desktop client executable with PyInstaller."""

import argparse
import subprocess
import sys
from pathlib import Path


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build the DCAS desktop client")
    parser.add_argument(
        "--name",
        default="DCAS",
        help="Executable base name (default: DCAS)",
    )
    args = parser.parse_args(argv)
    project_root = Path(__file__).resolve().parent.parent
    entry_point = project_root / "dcas" / "desktop_client.py"
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",
        "--windowed",
        "--name",
        args.name,
        "--distpath",
        str(project_root / "dist"),
        "--workpath",
        str(project_root / "build"),
        "--specpath",
        str(project_root / "build"),
        str(entry_point),
    ]
    return subprocess.call(command, cwd=str(project_root))


if __name__ == "__main__":
    raise SystemExit(main())

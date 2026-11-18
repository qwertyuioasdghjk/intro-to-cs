"""Start the local DCAS API and expose it through a Cloudflare Tunnel."""

import ctypes
import os
import re
import secrets
import shutil
import signal
import sqlite3
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path


QUICK_TUNNEL_URL = re.compile(
    r"https://[a-z0-9-]+\.trycloudflare\.com",
    re.IGNORECASE,
)
SERVER_URL = "http://127.0.0.1:5000"
HEALTH_URL = SERVER_URL + "/api/health"
HEALTH_TIMEOUT_SECONDS = 120
TUNNEL_TIMEOUT_SECONDS = 120


def read_env_file(path):
    values = {}
    if not path.exists():
        return values

    with path.open(encoding="utf-8") as env_file:
        for raw_line in env_file:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if (
                len(value) >= 2
                and value[0] == value[-1]
                and value[0] in ("'", '"')
            ):
                value = value[1:-1]
            if key:
                values[key] = value
    return values


def initialize_host_environment(env_path):
    """Create persistent host credentials and preserve unrelated .env entries."""
    values = read_env_file(Path(env_path))
    if not values.get("DCAS_APP_TOKEN", "").strip():
        values["DCAS_APP_TOKEN"] = secrets.token_urlsafe(24)
    if not values.get("DCAS_ADMIN_TOKEN", "").strip():
        values["DCAS_ADMIN_TOKEN"] = secrets.token_urlsafe(32)
    values["DCAS_TRUST_PROXY"] = "1"
    values["DCAS_ENABLE_CHAOS"] = "0"

    env_path = Path(env_path)
    env_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = env_path.with_name(env_path.name + ".tmp")
    temporary_path.write_text(
        "".join(f"{key}={value}\n" for key, value in values.items()),
        encoding="utf-8",
    )
    temporary_path.replace(env_path)
    os.environ.update(values)
    return values


def ensure_server_port_available(host="127.0.0.1", port=5000):
    """Fail before startup if another process already owns the API port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((host, port))
    except OSError as error:
        raise RuntimeError(
            f"Port {port} on {host} is already in use. Stop the existing "
            "server before starting the DCAS host."
        ) from error


def extract_quick_tunnel_url(line):
    match = QUICK_TUNNEL_URL.search(line)
    return match.group(0) if match else None


def checkpoint_sqlite_wal(database_path):
    """Truncate the SQLite WAL after the server has stopped."""
    database_path = Path(database_path)
    if not database_path.exists():
        return None

    max_retries = 5
    retry_delay = 0.2
    row = None
    for attempt in range(max_retries + 1):
        connection = None
        try:
            connection = sqlite3.connect(str(database_path), timeout=5)
            row = connection.execute(
                "PRAGMA wal_checkpoint(TRUNCATE);"
            ).fetchone()
        except sqlite3.OperationalError:
            row = None
        finally:
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.OperationalError:
                    row = None

        if row is not None and row[0] == 0:
            return row
        if attempt < max_retries:
            time.sleep(retry_delay)
    return row


def report_sqlite_checkpoint(row):
    if row is not None and row[0] == 0:
        print("SQLite WAL checkpoint completed.", flush=True)
    else:
        print(
            "Warning: SQLite WAL checkpoint was busy or incomplete.",
            flush=True,
        )


def wait_for_health(process, stop_event, timeout=HEALTH_TIMEOUT_SECONDS):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not stop_event.is_set():
        if process.poll() is not None:
            raise RuntimeError("The DCAS server exited before becoming healthy.")
        try:
            with urllib.request.urlopen(HEALTH_URL, timeout=2) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            pass
        stop_event.wait(0.5)
    if stop_event.is_set():
        raise RuntimeError("Host startup was interrupted.")
    raise RuntimeError("The DCAS server did not become healthy within 120 seconds.")


def _read_tunnel_output(process, captured_urls, url_event):
    if process.stdout is None:
        return
    for line in process.stdout:
        print(f"[cloudflared] {line.rstrip()}", flush=True)
        url = extract_quick_tunnel_url(line)
        if url and not captured_urls:
            captured_urls.append(url)
            url_event.set()


def _wait_for_tunnel_url(process, captured_urls, url_event, stop_event):
    deadline = time.monotonic() + TUNNEL_TIMEOUT_SECONDS
    while time.monotonic() < deadline and not stop_event.is_set():
        if process.poll() is not None:
            raise RuntimeError("cloudflared exited before publishing a tunnel URL.")
        if url_event.wait(0.25):
            return captured_urls[0]
    if stop_event.is_set():
        raise RuntimeError("Host startup was interrupted.")
    raise RuntimeError("Timed out waiting for Cloudflare Quick Tunnel URL.")


def _prevent_system_sleep():
    if os.name != "nt":
        return False
    result = ctypes.windll.kernel32.SetThreadExecutionState(0x80000001)
    if not result:
        print("Warning: Windows could not be told to stay awake.", flush=True)
    return True


def _allow_system_sleep():
    if os.name == "nt":
        ctypes.windll.kernel32.SetThreadExecutionState(0x80000000)


def _terminate_process(process, label):
    if process is None or process.poll() is not None:
        return True
    print(f"Stopping {label}...", flush=True)
    if os.name == "nt" and hasattr(signal, "CTRL_BREAK_EVENT"):
        try:
            process.send_signal(signal.CTRL_BREAK_EVENT)
        except (OSError, ValueError):
            process.terminate()
    else:
        process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            print(f"Could not stop {label} cleanly.", flush=True)
            return False
    return True


def _print_connection_summary(server_url, app_token, admin_token):
    rows = [
        ("Server URL (for DCAS.exe)", server_url),
        ("App Invite Code (DCAS_APP_TOKEN)", app_token),
        ("Admin Token (DCAS_ADMIN_TOKEN)", admin_token),
    ]
    width = max(len(label) + len(value) + 5 for label, value in rows)
    print("+" + "-" * width + "+", flush=True)
    print("|" + " DCAS HOST READY ".center(width) + "|", flush=True)
    print("+" + "-" * width + "+", flush=True)
    for label, value in rows:
        print(f"| {label}: {value}".ljust(width + 1) + "|", flush=True)
    print("+" + "-" * width + "+", flush=True)
    print("Press Ctrl+C to stop the tunnel and server safely.", flush=True)


def run_host(project_root=None):
    project_root = Path(project_root or Path(__file__).resolve().parent.parent)
    try:
        ensure_server_port_available()
    except RuntimeError as error:
        print(f"Host startup failed: {error}", flush=True)
        return 1

    env_path = project_root / ".env"
    host_config = initialize_host_environment(env_path)

    cloudflared = shutil.which("cloudflared")
    if not cloudflared:
        print(
            "cloudflared is not installed or is not on PATH. Install it with:\n"
            "  winget install -e --id Cloudflare.cloudflared",
            flush=True,
        )
        return 1

    server_env = os.environ.copy()
    server_env.update(host_config)
    server_env["DCAS_ACCESS_TOKEN"] = host_config["DCAS_APP_TOKEN"]
    stop_event = threading.Event()
    old_handlers = {}

    def request_shutdown(_signum, _frame):
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        old_handlers[sig] = signal.signal(sig, request_shutdown)

    server_process = None
    tunnel_process = None
    sleep_prevented = False
    tunnel_reader = None
    exit_code = 0
    process_group_flag = (
        subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    )
    try:
        sleep_prevented = _prevent_system_sleep()
        server_process = subprocess.Popen(
            [sys.executable, "-m", "dcas.run_server"],
            cwd=str(project_root),
            env=server_env,
            creationflags=process_group_flag,
        )
        print("Starting DCAS server...", flush=True)
        wait_for_health(server_process, stop_event)
        print("DCAS server is healthy.", flush=True)

        tunnel_name = host_config.get("DCAS_TUNNEL_NAME", "").strip()
        tunnel_command = [cloudflared, "tunnel"]
        if tunnel_name:
            tunnel_command.extend(
                ["run", "--url", SERVER_URL, tunnel_name]
            )
        else:
            tunnel_command.extend(["--url", SERVER_URL])

        tunnel_process = subprocess.Popen(
            tunnel_command,
            cwd=str(project_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            creationflags=process_group_flag,
        )
        captured_urls = []
        tunnel_url_event = threading.Event()
        tunnel_reader = threading.Thread(
            target=_read_tunnel_output,
            args=(tunnel_process, captured_urls, tunnel_url_event),
            name="cloudflared-output",
            daemon=True,
        )
        tunnel_reader.start()

        if tunnel_name:
            public_url = host_config.get("DCAS_PUBLIC_URL", "").strip()
            server_url = public_url or (
                "Set DCAS_PUBLIC_URL in .env for this named tunnel"
            )
        else:
            server_url = _wait_for_tunnel_url(
                tunnel_process,
                captured_urls,
                tunnel_url_event,
                stop_event,
            )
        _print_connection_summary(
            server_url,
            host_config["DCAS_APP_TOKEN"],
            host_config["DCAS_ADMIN_TOKEN"],
        )

        while not stop_event.wait(0.5):
            if server_process.poll() is not None:
                print("The DCAS server exited.", flush=True)
                exit_code = 1
                break
            if tunnel_process.poll() is not None:
                print("cloudflared exited.", flush=True)
                exit_code = 1
                break
    except (OSError, RuntimeError) as error:
        print(f"Host startup failed: {error}", flush=True)
        return 1
    finally:
        if not _terminate_process(tunnel_process, "Cloudflare Tunnel"):
            exit_code = 1
        server_stopped = _terminate_process(server_process, "DCAS server")
        if server_stopped:
            try:
                checkpoint_result = checkpoint_sqlite_wal(
                    project_root / "dcas_api_metadata.db"
                )
                report_sqlite_checkpoint(checkpoint_result)
            except sqlite3.Error as error:
                print(
                    f"Warning: SQLite WAL checkpoint failed: {error}",
                    flush=True,
                )
                exit_code = 1
        else:
            exit_code = 1
        if sleep_prevented:
            _allow_system_sleep()
        for sig, previous_handler in old_handlers.items():
            signal.signal(sig, previous_handler)
        if tunnel_reader is not None:
            tunnel_reader.join(timeout=1)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(run_host())

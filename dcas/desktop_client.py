"""Desktop browser client for a DCAS host."""

import argparse
import json
import shutil
import subprocess
import threading
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


SAVED_SERVER_HEALTH_TIMEOUT = 3


def client_config_path():
    return Path.home() / ".dcas" / "client_config.json"


def is_server_online(server_url, timeout=SAVED_SERVER_HEALTH_TIMEOUT):
    server_url = server_url.strip().rstrip("/")
    try:
        with urllib.request.urlopen(
            server_url + "/api/health",
            timeout=timeout,
        ) as response:
            return response.status == 200
    except (OSError, urllib.error.URLError, ValueError):
        return False


def validate_server(server_url, app_token):
    server_url = server_url.strip().rstrip("/")
    parsed = urllib.parse.urlsplit(server_url)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.netloc
        or parsed.query
        or parsed.fragment
    ):
        return False, "Enter a valid server URL beginning with http:// or https://."

    try:
        with urllib.request.urlopen(
            server_url + "/api/health",
            timeout=10,
        ) as response:
            if response.status != 200:
                return False, "The server health check did not succeed."
        overview_request = urllib.request.Request(
            server_url + "/api/overview",
            headers={"X-App-Token": app_token},
        )
        with urllib.request.urlopen(overview_request, timeout=10) as response:
            if response.status != 200:
                return False, "The invite code was rejected by the server."
    except urllib.error.HTTPError as error:
        if error.code == 401:
            return False, "Invalid App Invite Code."
        return False, f"Server validation failed with HTTP {error.code}."
    except (OSError, urllib.error.URLError) as error:
        return False, f"Could not connect to the server: {error}"
    return True, ""


def show_saved_server_offline_message():
    from tkinter import messagebox

    messagebox.showinfo(
        "DCAS server unavailable",
        "Saved server is offline or URL changed",
    )


def show_setup_dialog(existing=None):
    import tkinter as tk

    existing = existing or {}
    root = tk.Tk()
    root.title("Connect to DCAS")
    root.resizable(False, False)

    frame = tk.Frame(root, padx=18, pady=16)
    frame.pack(fill="both", expand=True)
    tk.Label(frame, text="Server URL").grid(row=0, column=0, sticky="w")
    server_var = tk.StringVar(value=existing.get("server_url", ""))
    server_entry = tk.Entry(frame, textvariable=server_var, width=54)
    server_entry.grid(row=1, column=0, pady=(4, 12), sticky="ew")
    tk.Label(frame, text="App Invite Code").grid(row=2, column=0, sticky="w")
    token_var = tk.StringVar(value=existing.get("app_token", ""))
    token_entry = tk.Entry(frame, textvariable=token_var, width=54, show="*")
    token_entry.grid(row=3, column=0, pady=(4, 10), sticky="ew")
    error_var = tk.StringVar()
    tk.Label(frame, textvariable=error_var, fg="#b00020", wraplength=400).grid(
        row=4,
        column=0,
        sticky="w",
    )
    config = {}

    def submit():
        server_url = server_var.get().strip().rstrip("/")
        app_token = token_var.get().strip()
        valid, error = validate_server(server_url, app_token)
        if not valid:
            error_var.set(error)
            return
        config.update({"server_url": server_url, "app_token": app_token})
        root.destroy()

    buttons = tk.Frame(frame)
    buttons.grid(row=5, column=0, pady=(10, 0), sticky="e")
    tk.Button(buttons, text="Connect", command=submit).pack(side="left")
    tk.Button(
        buttons,
        text="Cancel",
        command=lambda: root.destroy(),
    ).pack(side="left", padx=(8, 0))
    root.bind("<Return>", lambda _event: submit())
    server_entry.focus_set()
    root.mainloop()
    if not config:
        return None

    path = client_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_suffix(".json.tmp")
    temporary_path.write_text(
        json.dumps(config, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary_path.replace(path)
    return config


def load_client_config(reset=False):
    path = client_config_path()
    existing = {}
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(existing, dict):
                existing = {}
            if not reset and (
                isinstance(existing, dict)
                and isinstance(existing.get("server_url"), str)
                and isinstance(existing.get("app_token"), str)
                and existing["server_url"]
            ):
                if is_server_online(existing["server_url"]):
                    return existing
                show_saved_server_offline_message()
        except (OSError, json.JSONDecodeError):
            existing = {}
    return show_setup_dialog(existing)


class LoopbackProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "DCASLoopbackProxy/1.0"

    def _proxy_request(self):
        proxy_server = self.server
        target_url = proxy_server.server_url + self.path
        expected_host = f"127.0.0.1:{proxy_server.server_address[1]}"
        if self.headers.get("Host", "").lower() != expected_host:
            self.send_error(403, "Invalid loopback proxy host")
            return
        origin = self.headers.get("Origin")
        expected_origin = f"http://{expected_host}"
        if origin and origin.rstrip("/") != expected_origin:
            self.send_error(403, "Cross-origin proxy requests are not allowed")
            return

        request_headers = {}
        connection_headers = {
            token.strip().lower()
            for token in self.headers.get("Connection", "").split(",")
            if token.strip()
        }
        excluded_headers = {
            "connection",
            "host",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
        } | connection_headers
        for name, value in self.headers.items():
            if name.lower() not in excluded_headers and name.lower() != "x-app-token":
                request_headers[name] = value
        request_headers["X-App-Token"] = proxy_server.app_token

        content_length = int(self.headers.get("Content-Length", "0") or "0")
        request_body = self.rfile.read(content_length) if content_length else None
        upstream_request = urllib.request.Request(
            target_url,
            data=request_body,
            headers=request_headers,
            method=self.command,
        )
        try:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                _NoRedirectHandler(),
            )
            upstream_response = opener.open(upstream_request, timeout=120)
        except urllib.error.HTTPError as error:
            upstream_response = error
        except (OSError, urllib.error.URLError) as error:
            self.send_error(502, f"Unable to reach DCAS server: {error}")
            return

        with upstream_response:
            self.send_response(upstream_response.status)
            response_connection_headers = {
                token.strip().lower()
                for token in upstream_response.headers.get(
                    "Connection", ""
                ).split(",")
                if token.strip()
            }
            excluded_response_headers = excluded_headers | response_connection_headers
            for name, value in upstream_response.headers.items():
                if (
                    name.lower() == "location"
                    and value.startswith(proxy_server.server_url)
                ):
                    value = (
                        f"http://127.0.0.1:{proxy_server.server_address[1]}"
                        + value[len(proxy_server.server_url):]
                    )
                if name.lower() not in excluded_response_headers:
                    self.send_header(name, value)
            self.send_header("Connection", "close")
            self.end_headers()

            if self.command != "HEAD" and upstream_response.status not in (204, 304):
                while True:
                    chunk = upstream_response.read(64 * 1024)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
            self.wfile.flush()

    do_GET = _proxy_request
    do_HEAD = _proxy_request
    do_POST = _proxy_request
    do_PUT = _proxy_request
    do_PATCH = _proxy_request
    do_DELETE = _proxy_request
    do_OPTIONS = _proxy_request

    def log_message(self, _format, *_args):
        return


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, _request, _response, _code, _message, _headers, _url):
        return None


class LoopbackProxyServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, server_url, app_token):
        self.server_url = server_url.rstrip("/")
        self.app_token = app_token
        super().__init__(server_address, LoopbackProxyHandler)


def open_client_window(local_url):
    try:
        import webview
    except ImportError:
        webview = None

    if webview is not None:
        try:
            return open_pywebview_window(webview, local_url)
        except Exception as error:
            print(f"pywebview could not start ({error}); opening a browser instead.")

    browser = next(
        (
            executable
            for executable in (
                "msedge",
                "msedge.exe",
                "chrome",
                "chrome.exe",
                "google-chrome",
            )
            if shutil.which(executable)
        ),
        None,
    )
    if browser:
        subprocess.Popen([browser, f"--app={local_url}"])
    else:
        webbrowser.open(local_url)

    import tkinter as tk

    root = tk.Tk()
    root.title("DCAS is running")
    root.resizable(False, False)
    change_server_requested = False

    def change_server():
        nonlocal change_server_requested
        change_server_requested = True
        root.destroy()

    tk.Label(
        root,
        text=(
            "DCAS is connected in your browser.\n"
            f"{local_url}\n"
            "Close this window to stop the local connection."
        ),
        padx=24,
        pady=18,
    ).pack()
    buttons = tk.Frame(root)
    buttons.pack(pady=(0, 14))
    tk.Button(
        buttons,
        text="Change Server",
        command=change_server,
    ).pack(side="left")
    tk.Button(
        buttons,
        text="Close DCAS",
        command=root.destroy,
    ).pack(side="left", padx=(8, 0))
    root.mainloop()
    return change_server_requested


def open_pywebview_window(webview, local_url):
    switch_requested = False
    window_holder = {}

    def on_change_server():
        nonlocal switch_requested
        switch_requested = True
        window_holder["window"].destroy()

    menu = webview.menu.Menu(
        "Connection",
        [webview.menu.MenuAction("Change Server...", on_change_server)],
    )
    window_holder["window"] = webview.create_window(
        "DCAS",
        local_url,
        menu=[menu],
    )
    webview.start()
    return switch_requested


def run_client(config, window_opener=None, setup_dialog=None):
    window_opener = window_opener or open_client_window
    setup_dialog = setup_dialog or show_setup_dialog

    while config:
        proxy = LoopbackProxyServer(
            ("127.0.0.1", 0),
            config["server_url"],
            config["app_token"],
        )
        local_url = f"http://127.0.0.1:{proxy.server_address[1]}/"
        proxy_thread = threading.Thread(
            target=proxy.serve_forever,
            name="dcas-loopback-proxy",
            daemon=True,
        )
        proxy_thread.start()
        try:
            change_server_requested = window_opener(local_url)
        finally:
            proxy.shutdown()
            proxy.server_close()
            proxy_thread.join(timeout=5)

        if not change_server_requested:
            break
        config = setup_dialog(config)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Connect the DCAS desktop client")
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Forget the saved server and invite code and show setup again",
    )
    args = parser.parse_args(argv)
    config = load_client_config(reset=args.reset)
    if config is None:
        return 1
    return run_client(config)


if __name__ == "__main__":
    raise SystemExit(main())

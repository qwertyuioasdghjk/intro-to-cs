import copy
import io
import json
import os
import shutil
import socket
import sqlite3
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from werkzeug.serving import make_server

import dcas.desktop_client as desktop_client
import scripts.start_host as start_host
from dcas.api.server import create_app
from dcas.desktop_client import LoopbackProxyServer
from dcas.run_server import load_env_file, main as run_server_main, parse_args
from scripts.build_desktop_client import main as build_desktop_client
from scripts.start_host import (
    checkpoint_sqlite_wal,
    extract_quick_tunnel_url,
    ensure_server_port_available,
    initialize_host_environment,
    report_sqlite_checkpoint,
)
from dcas.storage.migration import migrate_shared_storage


class TestWebApp(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(
            os.environ,
            {
                "DCAS_ADMIN_TOKEN": "test-admin-token",
                "DCAS_APP_TOKEN": "",
                "DCAS_APP_RATE_LIMIT": "10",
                "DCAS_ENABLE_CHAOS": "1",
                "DCAS_ACCESS_TOKEN": "",
                "DCAS_MAX_UPLOAD_MB": "25",
                "DCAS_MAX_STORAGE_MB": "1024",
                "DCAS_ENABLE_RATE_LIMIT": "0",
                "DCAS_TRUST_PROXY": "0",
                "DCAS_ADMIN_RATE_LIMIT": "10",
                "DCAS_WRITE_RATE_LIMIT": "30",
                "DCAS_RATE_LIMIT_LOCALHOST": "1",
                "DCAS_GLOBAL_STORAGE_QUOTA_BYTES": "0",
                "DCAS_SPACE_STORAGE_QUOTA_BYTES": "0",
                "DCAS_RATE_LIMIT_WINDOW_SECONDS": "60",
                "DCAS_RATE_LIMIT_AUDIT": "30",
                "DCAS_RATE_LIMIT_CHALLENGE": "60",
            },
            clear=False,
        )
        self.environment.start()
        self.test_dir = tempfile.mkdtemp()
        self.app = create_app(
            network_dir=os.path.join(self.test_dir, "network"),
            db_path=os.path.join(self.test_dir, "metadata.db"),
            num_nodes=3,
            replication_factor=1,
            mongodb_uri="",
        )
        self.app.testing = True
        self.client = self.app.test_client()

    def tearDown(self):
        components = self.app.extensions["dcas"]
        components["metadata"].close()
        components["network"].cleanup()
        shutil.rmtree(self.test_dir)
        self.environment.stop()

    def test_dashboard_and_assets_are_served(self):
        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertEqual(page.headers["X-Frame-Options"], "DENY")
        self.assertEqual(page.headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(page.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn(b"Distributed files.", page.data)
        self.assertIn(b"Public files", page.data)
        self.assertIn(b"Private &amp; shared spaces", page.data)
        self.assertIn(b"Have an access link?", page.data)
        self.assertIn(b"/static/app.css", page.data)
        self.assertIn(b"/static/app.js", page.data)

        stylesheet = self.client.get("/static/app.css")
        script = self.client.get("/static/app.js")
        self.assertEqual(stylesheet.status_code, 200)
        self.assertIn(b".app-shell", stylesheet.data)
        self.assertEqual(script.status_code, 200)
        self.assertIn(b"loadDashboard", script.data)
        self.assertIn(b"Delete file", script.data)
        self.assertIn(b"method: \"DELETE\"", script.data)

    def test_admin_status_reports_authorization_without_exposing_token(self):
        missing_token = self.client.get("/api/admin/status")
        self.assertEqual(missing_token.status_code, 200)
        self.assertEqual(
            missing_token.get_json(),
            {
                "admin_configured": True,
                "authorized": False,
                "chaos_enabled": True,
            },
        )

        wrong_token = self.client.get(
            "/api/admin/status",
            headers={"X-Admin-Token": "wrong-admin-token"},
        )
        self.assertFalse(wrong_token.get_json()["authorized"])

        valid_token = self.client.get(
            "/api/admin/status",
            headers={"X-Admin-Token": "test-admin-token"},
        )
        self.assertTrue(valid_token.get_json()["authorized"])
        self.assertNotIn("admin_token", valid_token.get_json())

    def test_app_invite_gate_exempts_health_and_rate_limits_failures(self):
        self.app.config["DCAS_APP_TOKEN"] = "test-app-token"
        self.app.config["DCAS_APP_RATE_LIMIT"] = 1
        self.app.config["DCAS_ENABLE_RATE_LIMIT"] = True
        self.app.extensions["dcas_rate_limit_buckets"].clear()

        self.assertEqual(self.client.get("/api/health").status_code, 200)
        denied = self.client.get("/api/overview")
        self.assertEqual(denied.status_code, 401)
        self.assertEqual(
            denied.get_json(),
            {"error": "A valid app invite code is required."},
        )

        authorized = self.client.get(
            "/api/overview",
            headers={"X-App-Token": "test-app-token"},
        )
        self.assertEqual(authorized.status_code, 200)

        self.app.extensions["dcas_rate_limit_buckets"].clear()
        first_failure = self.client.get(
            "/api/files",
            headers={"X-App-Token": "wrong-app-token"},
        )
        second_failure = self.client.get(
            "/api/files",
            headers={"X-App-Token": "wrong-app-token"},
        )
        self.assertEqual(first_failure.status_code, 401)
        self.assertEqual(second_failure.status_code, 429)
        self.assertIn("Retry-After", second_failure.headers)

    def test_desktop_loopback_proxy_forwards_uploads_and_injects_app_token(self):
        class CaptureHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                response = json.dumps({
                    "path": self.path,
                    "app_token": self.headers.get("X-App-Token"),
                    "admin_token": self.headers.get("X-Admin-Token"),
                    "authorization": self.headers.get("Authorization"),
                }).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                response = json.dumps({
                    "path": self.path,
                    "app_token": self.headers.get("X-App-Token"),
                    "admin_token": self.headers.get("X-Admin-Token"),
                    "authorization": self.headers.get("Authorization"),
                    "body": body.decode("utf-8"),
                }).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, _format, *_args):
                return

        upstream = ThreadingHTTPServer(("127.0.0.1", 0), CaptureHandler)
        upstream_thread = threading.Thread(
            target=upstream.serve_forever,
            daemon=True,
        )
        upstream_thread.start()
        proxy = LoopbackProxyServer(
            ("127.0.0.1", 0),
            f"http://127.0.0.1:{upstream.server_address[1]}",
            "expected-app-token",
        )
        proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        proxy_thread.start()
        try:
            with urllib.request.urlopen(
                urllib.request.Request(
                    f"http://127.0.0.1:{proxy.server_address[1]}/api/admin/status",
                    headers={
                        "X-Admin-Token": "browser-admin-token",
                        "Authorization": "Bearer browser-admin-token",
                    },
                ),
                timeout=5,
            ) as response:
                download = json.loads(response.read().decode("utf-8"))
            self.assertEqual(download["path"], "/api/admin/status")
            self.assertEqual(download["app_token"], "expected-app-token")
            self.assertEqual(download["admin_token"], "browser-admin-token")
            self.assertEqual(
                download["authorization"],
                "Bearer browser-admin-token",
            )

            cross_origin_request = urllib.request.Request(
                f"http://127.0.0.1:{proxy.server_address[1]}/api/download/file-1",
                headers={"Origin": "https://untrusted.example"},
            )
            with self.assertRaises(urllib.error.HTTPError) as error_context:
                urllib.request.urlopen(cross_origin_request, timeout=5)
            self.assertEqual(error_context.exception.code, 403)

            request = urllib.request.Request(
                f"http://127.0.0.1:{proxy.server_address[1]}/api/upload?mode=test",
                data=b"uploaded payload",
                headers={"X-App-Token": "attacker-controlled-token"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                body = json.loads(response.read().decode("utf-8"))
            self.assertEqual(body["path"], "/api/upload?mode=test")
            self.assertEqual(body["app_token"], "expected-app-token")
            self.assertIsNone(body["admin_token"])
            self.assertIsNone(body["authorization"])
            self.assertEqual(body["body"], "uploaded payload")
        finally:
            proxy.shutdown()
            proxy.server_close()
            upstream.shutdown()
            upstream.server_close()
            proxy_thread.join(timeout=2)
            upstream_thread.join(timeout=2)

    def test_admin_unlock_succeeds_through_desktop_proxy_with_app_token(self):
        self.app.config["DCAS_APP_TOKEN"] = "test-app-token"
        self.app.config["DCAS_ADMIN_TOKEN"] = "test-admin-token"
        upstream = make_server("127.0.0.1", 0, self.app, threaded=True)
        upstream_thread = threading.Thread(
            target=upstream.serve_forever,
            daemon=True,
        )
        upstream_thread.start()
        proxy = LoopbackProxyServer(
            ("127.0.0.1", 0),
            f"http://127.0.0.1:{upstream.server_port}",
            "test-app-token",
        )
        proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        proxy_thread.start()
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{proxy.server_address[1]}/api/admin/status",
                headers={
                    "X-Admin-Token": "test-admin-token",
                    "Authorization": "Bearer unrelated-token",
                },
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                status = json.loads(response.read().decode("utf-8"))

            self.assertTrue(status["admin_configured"])
            self.assertTrue(status["authorized"])
        finally:
            proxy.shutdown()
            proxy.server_close()
            upstream.shutdown()
            upstream.server_close()
            proxy_thread.join(timeout=2)
            upstream_thread.join(timeout=2)

    def test_saved_server_health_failure_prompts_switch_with_saved_app_token(self):
        config_path = os.path.join(self.test_dir, "client_config.json")
        saved_config = {
            "server_url": "https://old-host.trycloudflare.com",
            "app_token": "saved-invite-token",
        }
        with open(config_path, "w", encoding="utf-8") as config_file:
            json.dump(saved_config, config_file)
        new_config = {
            "server_url": "https://new-host.trycloudflare.com",
            "app_token": "saved-invite-token",
        }

        with (
            patch.object(
                desktop_client,
                "client_config_path",
                return_value=Path(config_path),
            ),
            patch.object(desktop_client, "is_server_online", return_value=False) as health_check,
            patch.object(
                desktop_client,
                "show_saved_server_offline_message",
            ) as offline_message,
            patch.object(
                desktop_client,
                "show_setup_dialog",
                return_value=new_config,
            ) as setup_dialog,
        ):
            result = desktop_client.load_client_config()

        self.assertEqual(result, new_config)
        health_check.assert_called_once_with(saved_config["server_url"])
        offline_message.assert_called_once_with()
        setup_dialog.assert_called_once_with(saved_config)

    def test_saved_server_health_check_uses_short_timeout_and_handles_http_errors(self):
        response = MagicMock()
        response.status = 200
        response.__enter__.return_value = response
        with patch.object(
            desktop_client.urllib.request,
            "urlopen",
            return_value=response,
        ) as urlopen:
            self.assertTrue(
                desktop_client.is_server_online("https://host.example")
            )
        urlopen.assert_called_once_with(
            "https://host.example/api/health",
            timeout=desktop_client.SAVED_SERVER_HEALTH_TIMEOUT,
        )

        http_error = urllib.error.HTTPError(
            "https://host.example/api/health",
            530,
            "Cloudflare Error 1033",
            {},
            None,
        )
        with patch.object(
            desktop_client.urllib.request,
            "urlopen",
            side_effect=http_error,
        ):
            self.assertFalse(
                desktop_client.is_server_online("https://host.example")
            )

    def test_change_server_closes_proxy_before_reopening_setup(self):
        instances = []
        events = []
        configs = [
            {
                "server_url": "https://old-host.example",
                "app_token": "same-invite-token",
            },
            {
                "server_url": "https://new-host.example",
                "app_token": "same-invite-token",
            },
        ]
        window_results = iter((True, False))

        class FakeProxy:
            def __init__(self, address, server_url, app_token):
                self.server_address = (address[0], 45000 + len(instances))
                self.server_url = server_url
                self.app_token = app_token
                instances.append(self)

            def serve_forever(self):
                return

            def shutdown(self):
                events.append(("shutdown", self.server_url))

            def server_close(self):
                events.append(("closed", self.server_url))

        def setup_dialog(existing):
            events.append(("setup", existing["server_url"]))
            return configs[1]

        with patch.object(desktop_client, "LoopbackProxyServer", FakeProxy):
            result = desktop_client.run_client(
                configs[0],
                window_opener=lambda _url: next(window_results),
                setup_dialog=setup_dialog,
            )

        self.assertEqual(result, 0)
        self.assertEqual(
            [proxy.server_url for proxy in instances],
            ["https://old-host.example", "https://new-host.example"],
        )
        self.assertLess(
            events.index(("closed", "https://old-host.example")),
            events.index(("setup", "https://old-host.example")),
        )
        self.assertEqual(
            [proxy.app_token for proxy in instances],
            ["same-invite-token", "same-invite-token"],
        )

    def test_pywebview_change_server_menu_restarts_proxy_loop(self):
        events = []
        configs = [
            {
                "server_url": "https://first-host.example",
                "app_token": "saved-invite-token",
            },
            {
                "server_url": "https://second-host.example",
                "app_token": "saved-invite-token",
            },
        ]
        windows = []

        class FakeMenuAction:
            def __init__(self, title, callback):
                self.title = title
                self.callback = callback

        class FakeMenu:
            def __init__(self, title, actions):
                self.title = title
                self.actions = actions

        class FakeWindow:
            def __init__(self):
                self.destroyed = False

            def destroy(self):
                self.destroyed = True

        class FakeWebview:
            menu = type(
                "MenuNamespace",
                (),
                {"Menu": FakeMenu, "MenuAction": FakeMenuAction},
            )

            def __init__(self, change_server):
                self.change_server = change_server

            def create_window(self, _title, _url, menu):
                self.menu = menu[0]
                self.window = FakeWindow()
                windows.append(self.window)
                return self.window

            def start(self):
                if self.change_server:
                    self.menu.actions[0].callback()

        class FakeProxy:
            def __init__(self, address, server_url, app_token):
                self.server_address = (address[0], 46000 + len(windows))
                self.server_url = server_url
                self.app_token = app_token

            def serve_forever(self):
                return

            def shutdown(self):
                events.append(("shutdown", self.server_url))

            def server_close(self):
                events.append(("closed", self.server_url))

        webviews = iter((FakeWebview(True), FakeWebview(False)))

        def setup_dialog(existing):
            events.append(("setup", existing["server_url"]))
            return configs[1]

        with patch.object(desktop_client, "LoopbackProxyServer", FakeProxy):
            result = desktop_client.run_client(
                configs[0],
                window_opener=lambda local_url: desktop_client.open_pywebview_window(
                    next(webviews),
                    local_url,
                ),
                setup_dialog=setup_dialog,
            )

        self.assertEqual(result, 0)
        self.assertEqual(len(windows), 2)
        self.assertTrue(windows[0].destroyed)
        self.assertFalse(windows[1].destroyed)
        self.assertLess(
            events.index(("closed", "https://first-host.example")),
            events.index(("setup", "https://first-host.example")),
        )
        self.assertEqual(
            [event for event in events if event[0] == "shutdown"],
            [
                ("shutdown", "https://first-host.example"),
                ("shutdown", "https://second-host.example"),
            ],
        )

    def test_dashboard_file_upload_and_verification_workflow(self):
        upload = self.client.post(
            "/api/upload/text",
            json={
                "content": "A note stored by the web dashboard",
                "filename": "dashboard-note.txt",
                "owner": "tester",
            },
        )
        self.assertEqual(upload.status_code, 201)
        cid = upload.get_json()["cid"]

        file_list = self.client.get("/api/files")
        self.assertEqual(file_list.status_code, 200)
        self.assertEqual(file_list.get_json()["count"], 1)
        self.assertEqual(file_list.get_json()["files"][0]["filename"], "dashboard-note.txt")

        details = self.client.get(f"/api/file/{cid}")
        self.assertEqual(details.status_code, 200)
        self.assertEqual(details.get_json()["owner"], "tester")

        verification = self.client.post(f"/api/verify/{cid}")
        self.assertEqual(verification.status_code, 200)
        self.assertEqual(verification.get_json()["status"], "PASSED")

        audit = self.client.get("/api/audit-log?limit=8")
        self.assertEqual(audit.status_code, 200)
        self.assertGreaterEqual(audit.get_json()["stats"]["total_events"], 2)

    def test_text_upload_accepts_empty_content_and_rejects_invalid_content(self):
        upload = self.client.post("/api/upload/text", json={"content": ""})
        self.assertEqual(upload.status_code, 201)

        cid = upload.get_json()["cid"]
        manifest = self.app.extensions["dcas"]["metadata"].get_manifest(cid)
        stored = self.app.extensions["dcas"]["network"].retrieve_file(manifest)
        self.assertNotEqual(stored, b"")
        self.assertTrue(manifest["storage_encrypted"])
        verification = self.client.post(f"/api/verify/{cid}")
        self.assertEqual(verification.get_json()["status"], "PASSED")
        download = self.client.get(f"/api/download/{cid}")
        self.assertEqual(download.status_code, 200)
        self.assertEqual(download.data, b"")

        invalid = self.client.post("/api/upload/text", json={"content": 123})
        self.assertEqual(invalid.status_code, 400)

    def test_public_file_upload_is_encrypted_in_storage_and_decrypted_on_download(self):
        source = b"private upload contents " * 40
        uploaded = self.client.post(
            "/api/upload",
            data={"file": (io.BytesIO(source), "encrypted.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(uploaded.status_code, 201)

        cid = uploaded.get_json()["cid"]
        manifest = self.app.extensions["dcas"]["metadata"].get_manifest(cid)
        stored = self.app.extensions["dcas"]["network"].retrieve_file(manifest)
        self.assertTrue(manifest["storage_encrypted"])
        self.assertEqual(
            cid,
            self.app.extensions["dcas"]["network"].cid_generator.generate(
                source
            ).cid_string,
        )
        self.assertEqual(manifest["total_size"], len(source))
        self.assertEqual(manifest["storage_size"], len(stored))
        self.assertNotEqual(stored, source)
        self.assertTrue(stored.startswith(b"DCAS-STORE-1:"))

        checked = self.client.post(f"/api/verify/{cid}")
        self.assertEqual(checked.get_json()["status"], "PASSED")
        downloaded = self.client.get(f"/api/download/{cid}")
        self.assertEqual(downloaded.status_code, 200)
        self.assertEqual(downloaded.data, source)

        network = self.app.extensions["dcas"]["network"]
        counts_before_duplicate = [node.chunk_count for node in network.nodes]
        duplicate = self.client.post(
            "/api/upload",
            data={"file": (io.BytesIO(source), "renamed.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(duplicate.status_code, 201)
        self.assertEqual(duplicate.get_json()["cid"], cid)
        self.assertEqual(
            [node.chunk_count for node in network.nodes],
            counts_before_duplicate,
        )
        self.assertEqual(
            self.app.extensions["dcas"]["metadata"].get_manifest(cid)["filename"],
            "renamed.txt",
        )

    def test_text_upload_reports_unavailable_storage(self):
        for node in self.app.extensions["dcas"]["network"].nodes:
            node.capacity = 1

        response = self.client.post("/api/upload/text", json={"content": "too large"})

        self.assertEqual(response.status_code, 503)
        self.assertEqual(self.client.get("/api/files").get_json()["count"], 0)

    def test_file_upload_returns_json_for_storage_errors(self):
        network = self.app.extensions["dcas"]["network"]
        with patch.object(network, "store_por_bytes", side_effect=OSError("private path")):
            response = self.client.post(
                "/api/upload",
                data={"file": (io.BytesIO(b"upload data"), "upload.txt")},
                content_type="multipart/form-data",
            )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.get_json(),
            {"error": "Upload failed due to a storage error."},
        )

    def test_dashboard_node_controls_update_network_status(self):
        initial_status = self.client.get("/api/network/status").get_json()
        node_id = initial_status["nodes"][0]["node_id"]
        admin_headers = {"X-Admin-Token": "test-admin-token"}

        failed = self.client.post(f"/api/network/fail/{node_id}", headers=admin_headers)
        self.assertEqual(failed.status_code, 200)
        status_after_failure = self.client.get("/api/network/status").get_json()
        self.assertEqual(status_after_failure["offline_nodes"], 1)

        recovered = self.client.post(f"/api/network/recover/{node_id}", headers=admin_headers)
        self.assertEqual(recovered.status_code, 200)
        status_after_recovery = self.client.get("/api/network/status").get_json()
        self.assertEqual(status_after_recovery["online_nodes"], 3)

    def test_chaos_routes_require_admin_authorization(self):
        uploaded = self.client.post(
            "/api/upload",
            data={"file": (io.BytesIO(b"chaos authorization sample " * 8), "sample.bin")},
            content_type="multipart/form-data",
        )
        self.assertEqual(uploaded.status_code, 201)
        cid = uploaded.get_json()["cid"]
        network = self.app.extensions["dcas"]["network"]
        node_id = network.nodes[0].node_id
        routes = (
            f"/api/network/fail/{node_id}",
            f"/api/network/recover/{node_id}",
            f"/api/simulate/corrupt/{cid}/0",
        )
        for route in routes:
            with self.subTest(route=route):
                self.assertIn(self.client.post(route).status_code, (401, 403))

        headers = {"Authorization": "Bearer test-admin-token"}
        self.assertEqual(self.client.post(routes[0], headers=headers).status_code, 200)
        self.assertEqual(self.client.post(routes[1], headers=headers).status_code, 200)
        self.assertEqual(self.client.post(routes[2], headers=headers).status_code, 200)

    def test_chaos_routes_are_disabled_without_explicit_opt_in(self):
        test_dir = tempfile.mkdtemp()
        app = None
        try:
            with patch.dict(
                os.environ,
                {"DCAS_ADMIN_TOKEN": "test-admin-token", "DCAS_ENABLE_CHAOS": ""},
            ):
                app = create_app(
                    network_dir=os.path.join(test_dir, "network"),
                    db_path=os.path.join(test_dir, "metadata.db"),
                    num_nodes=3,
                    replication_factor=1,
                    mongodb_uri="",
                )
            response = app.test_client().post(
                "/api/network/fail/node-000",
                headers={"X-Admin-Token": "test-admin-token"},
            )
            self.assertEqual(response.status_code, 403)
            status = app.test_client().get(
                "/api/admin/status",
                headers={"X-Admin-Token": "test-admin-token"},
            )
            self.assertTrue(status.get_json()["authorized"])
            self.assertFalse(status.get_json()["chaos_enabled"])
        finally:
            if app is not None:
                app.extensions["dcas"]["metadata"].close()
                app.extensions["dcas"]["network"].cleanup()
            shutil.rmtree(test_dir)

    def test_delete_requires_admin_or_space_write_authorization(self):
        created = self.client.post(
            "/api/spaces",
            json={"name": "Writable space", "allow_upload": True},
        )
        space = created.get_json()
        uploaded = self.client.post(
            f"/api/spaces/{space['space_id']}/files",
            headers={"Authorization": f"Bearer {space['admin_token']}"},
            data={"file": (io.BytesIO(b"DCAS1" + b"\x00" * 12 + b"encrypted"), "private.bin")},
            content_type="multipart/form-data",
        )
        self.assertEqual(uploaded.status_code, 201)
        cid = uploaded.get_json()["cid"]
        self.assertEqual(self.client.delete(f"/api/file/{cid}").status_code, 401)

        response = self.client.delete(
            f"/api/file/{cid}",
            headers={"Authorization": f"Bearer {space['share_token']}"},
        )
        self.assertEqual(response.status_code, 200)

    def test_upload_size_limit_returns_json_413(self):
        test_dir = tempfile.mkdtemp()
        app = None
        try:
            with patch.dict(
                os.environ,
                {
                    "DCAS_MAX_UPLOAD_MB": "1",
                    "DCAS_MAX_STORAGE_MB": "2",
                    "DCAS_ENABLE_RATE_LIMIT": "1",
                },
            ):
                app = create_app(
                    network_dir=os.path.join(test_dir, "network"),
                    db_path=os.path.join(test_dir, "metadata.db"),
                    num_nodes=3,
                    replication_factor=1,
                    mongodb_uri="",
                )
            self.assertEqual(app.config["MAX_CONTENT_LENGTH"], 1024 * 1024)
            self.assertEqual(app.config["DCAS_MAX_STORAGE_BYTES"], 2 * 1024 * 1024)
            self.assertTrue(app.config["DCAS_ENABLE_RATE_LIMIT"])
            response = app.test_client().post(
                "/api/upload",
                data={
                    "file": (
                        io.BytesIO(b"x" * (1024 * 1024 + 1)),
                        "too-large.bin",
                    )
                },
                content_type="multipart/form-data",
            )
            self.assertEqual(response.status_code, 413)
            self.assertEqual(
                response.get_json(),
                {"error": "File exceeds maximum upload size"},
            )
        finally:
            if app is not None:
                app.extensions["dcas"]["metadata"].close()
                app.extensions["dcas"]["network"].cleanup()
            shutil.rmtree(test_dir)

    def test_public_download_uses_safe_attachment_headers(self):
        uploaded = self.client.post(
            "/api/upload",
            data={"file": (io.BytesIO(b"<svg></svg>"), "diagram.svg")},
            content_type="multipart/form-data",
        )
        self.assertEqual(uploaded.status_code, 201)
        cid = uploaded.get_json()["cid"]

        metadata = self.app.extensions["dcas"]["metadata"]
        manifest = metadata.get_manifest(cid)
        manifest["filename"] = 'diagram"/\\\r\n.svg'
        metadata.store_manifest(manifest, owner="tester")

        downloaded = self.client.get(f"/api/download/{cid}")

        self.assertEqual(downloaded.status_code, 200)
        self.assertEqual(
            downloaded.headers["Content-Disposition"],
            'attachment; filename="diagram.svg"',
        )
        self.assertEqual(downloaded.headers["X-Content-Type-Options"], "nosniff")

    def test_max_storage_limit_rejects_uploads(self):
        self.assertEqual(
            self.app.config["DCAS_MAX_STORAGE_BYTES"],
            1024 * 1024 * 1024,
        )
        self.app.config["DCAS_MAX_STORAGE_BYTES"] = 4

        response = self.client.post(
            "/api/upload/text",
            json={"content": "12345"},
        )

        self.assertEqual(response.status_code, 507)
        self.assertEqual(
            response.get_json(),
            {"error": "Maximum storage capacity exceeded."},
        )
        self.assertEqual(self.client.get("/api/files").get_json()["count"], 0)

    def test_global_and_per_space_storage_quotas_reject_uploads(self):
        self.app.config["DCAS_GLOBAL_STORAGE_QUOTA_BYTES"] = 4
        public_upload = self.client.post(
            "/api/upload/text",
            json={"content": "12345"},
        )
        self.assertEqual(public_upload.status_code, 507)
        self.assertEqual(self.client.get("/api/files").get_json()["count"], 0)

        self.app.config["DCAS_GLOBAL_STORAGE_QUOTA_BYTES"] = 0
        self.app.config["DCAS_SPACE_STORAGE_QUOTA_BYTES"] = 4
        space = self.client.post("/api/spaces", json={"name": "Small space"}).get_json()
        response = self.client.post(
            f"/api/spaces/{space['space_id']}/files",
            headers={"Authorization": f"Bearer {space['admin_token']}"},
            data={"file": (io.BytesIO(b"DCAS1" + b"\x00" * 12 + b"encrypted"), "too-large.bin")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 507)

    def test_space_creation_rate_limit_returns_429(self):
        self.app.config["DCAS_ENABLE_RATE_LIMIT"] = True
        self.app.extensions["dcas_rate_limit_buckets"].clear()
        self.app.config["DCAS_WRITE_RATE_LIMIT"] = 1
        self.assertEqual(
            self.client.post("/api/spaces", json={"name": "First space"}).status_code,
            201,
        )
        limited = self.client.post("/api/spaces", json={"name": "Second space"})
        self.assertEqual(limited.status_code, 429)
        self.assertIn("Retry-After", limited.headers)
        self.assertEqual(
            limited.get_json(),
            {"error": "Rate limit exceeded. Try again later."},
        )

        self.app.config["DCAS_RATE_LIMITS"]["audit"] = 1
        self.assertEqual(self.client.get("/api/audit-log").status_code, 200)
        self.assertEqual(self.client.get("/api/audit-log").status_code, 429)

    def test_admin_and_upload_rate_limits_use_per_ip_buckets(self):
        self.app.config["DCAS_ENABLE_RATE_LIMIT"] = True
        self.app.config["DCAS_TRUST_PROXY"] = True
        buckets = self.app.extensions["dcas_rate_limit_buckets"]
        buckets.clear()

        headers = {
            "X-Admin-Token": "test-admin-token",
            "X-Forwarded-For": "192.0.2.10, 10.0.0.1",
        }
        for _ in range(10):
            self.assertEqual(self.client.get("/api/admin/status", headers=headers).status_code, 200)

        limited_status = self.client.get(
            "/api/admin/status",
            headers={
                "X-Admin-Token": "test-admin-token",
                "X-Forwarded-For": "192.0.2.10, 10.0.0.2",
            },
        )
        self.assertEqual(limited_status.status_code, 429)
        self.assertEqual(
            limited_status.get_json(),
            {"error": "Rate limit exceeded. Try again later."},
        )
        self.assertGreaterEqual(int(limited_status.headers["Retry-After"]), 1)
        self.assertEqual(
            self.client.get(
                "/api/admin/status",
                headers={
                    "X-Admin-Token": "test-admin-token",
                    "X-Forwarded-For": "192.0.2.11, 10.0.0.1",
                },
            ).status_code,
            200,
        )

        buckets.clear()
        self.app.config["DCAS_WRITE_RATE_LIMIT"] = 1
        first_upload = self.client.post(
            "/api/upload/text",
            json={"content": "first rate-limited upload"},
        )
        limited_upload = self.client.post(
            "/api/upload/text",
            json={"content": "second rate-limited upload"},
        )
        self.assertEqual(first_upload.status_code, 201)
        self.assertEqual(limited_upload.status_code, 429)
        self.assertEqual(
            limited_upload.get_json(),
            {"error": "Rate limit exceeded. Try again later."},
        )
        self.assertIn("Retry-After", limited_upload.headers)

    def test_forwarded_ip_is_used_only_when_proxy_trust_is_enabled(self):
        self.app.config["DCAS_ENABLE_RATE_LIMIT"] = True
        self.app.config["DCAS_ADMIN_RATE_LIMIT"] = 1
        buckets = self.app.extensions["dcas_rate_limit_buckets"]
        headers = {"X-Admin-Token": "test-admin-token"}

        self.app.config["DCAS_TRUST_PROXY"] = False
        buckets.clear()
        first = self.client.get(
            "/api/admin/status",
            headers={**headers, "X-Forwarded-For": "198.51.100.10"},
            environ_base={"REMOTE_ADDR": "192.0.2.10"},
        )
        forged_second = self.client.get(
            "/api/admin/status",
            headers={**headers, "X-Forwarded-For": "198.51.100.11"},
            environ_base={"REMOTE_ADDR": "192.0.2.10"},
        )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(forged_second.status_code, 429)

        self.app.config["DCAS_TRUST_PROXY"] = True
        buckets.clear()
        trusted_first = self.client.get(
            "/api/admin/status",
            headers={**headers, "X-Forwarded-For": "198.51.100.20, 10.0.0.1"},
        )
        trusted_second = self.client.get(
            "/api/admin/status",
            headers={**headers, "X-Forwarded-For": "198.51.100.21, 10.0.0.1"},
        )
        self.assertEqual(trusted_first.status_code, 200)
        self.assertEqual(trusted_second.status_code, 200)

    def test_localhost_rate_limit_exemption_does_not_exempt_external_ips(self):
        self.app.config["DCAS_ENABLE_RATE_LIMIT"] = True
        self.app.config["DCAS_ADMIN_RATE_LIMIT"] = 1
        self.app.config["DCAS_RATE_LIMIT_LOCALHOST"] = False
        buckets = self.app.extensions["dcas_rate_limit_buckets"]
        buckets.clear()
        headers = {"X-Admin-Token": "test-admin-token"}

        for _ in range(3):
            local_response = self.client.get(
                "/api/admin/status",
                headers=headers,
                environ_base={"REMOTE_ADDR": "127.0.0.1"},
            )
            self.assertEqual(local_response.status_code, 200)

        external_first = self.client.get(
            "/api/admin/status",
            headers=headers,
            environ_base={"REMOTE_ADDR": "192.0.2.25"},
        )
        external_second = self.client.get(
            "/api/admin/status",
            headers=headers,
            environ_base={"REMOTE_ADDR": "192.0.2.25"},
        )
        self.assertEqual(external_first.status_code, 200)
        self.assertEqual(external_second.status_code, 429)

    def test_optional_access_token_gates_open_creation_and_upload_routes(self):
        self.app.config["DCAS_ACCESS_TOKEN"] = "test-access-token"
        denied_space = self.client.post("/api/spaces", json={"name": "Denied"})
        self.assertEqual(denied_space.status_code, 401)
        allowed_space = self.client.post(
            "/api/spaces",
            headers={"X-Access-Token": "test-access-token"},
            json={"name": "Allowed"},
        )
        self.assertEqual(allowed_space.status_code, 201)

        denied_upload = self.client.post(
            "/api/upload/text",
            json={"content": "denied"},
        )
        self.assertEqual(denied_upload.status_code, 401)
        allowed_upload = self.client.post(
            "/api/upload/text",
            headers={"Authorization": "Bearer test-access-token"},
            json={"content": "allowed"},
        )
        self.assertEqual(allowed_upload.status_code, 201)

    def test_run_server_defaults_to_loopback(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(parse_args([]).host, "127.0.0.1")
        with patch.dict(os.environ, {"DCAS_HOST": "0.0.0.0"}, clear=True):
            with self.assertRaises(SystemExit):
                parse_args([])
        with patch.dict(os.environ, {"DCAS_ALLOW_PUBLIC_BIND": "1"}, clear=True):
            self.assertEqual(parse_args([]).host, "0.0.0.0")

    def test_run_server_loads_env_file_without_overriding_shell_values(self):
        env_path = os.path.join(self.test_dir, ".env")
        with open(env_path, "w", encoding="utf-8") as env_file:
            env_file.write(
                "DCAS_TEST_ENV_FILE_VALUE=from-file\n"
                "DCAS_TEST_ENV_SHELL_VALUE=from-file\n"
                "# ignored comment\n"
            )

        with patch.dict(
            os.environ,
            {"DCAS_TEST_ENV_SHELL_VALUE": "from-shell"},
            clear=False,
        ):
            os.environ.pop("DCAS_TEST_ENV_FILE_VALUE", None)
            load_env_file(env_path)
            self.assertEqual(os.environ["DCAS_TEST_ENV_FILE_VALUE"], "from-file")
            self.assertEqual(os.environ["DCAS_TEST_ENV_SHELL_VALUE"], "from-shell")

    def test_run_server_loads_env_before_creating_app(self):
        admin_token = "configured-before-app-creation"
        app = MagicMock()
        app.extensions = {"dcas": {"metadata": MagicMock()}}

        def create_app_after_env_load(**_kwargs):
            self.assertEqual(os.environ["DCAS_ADMIN_TOKEN"], admin_token)
            return app

        with (
            patch.dict(os.environ, {}, clear=True),
            patch(
                "dcas.run_server.load_env_file",
                side_effect=lambda: os.environ.update(
                    {"DCAS_ADMIN_TOKEN": admin_token}
                ),
            ),
            patch(
                "dcas.api.server.create_app",
                side_effect=create_app_after_env_load,
            ),
            patch(
                "dcas.storage.migration.migrate_shared_storage",
                return_value={"migrated": 0, "already_encrypted": 0},
            ),
        ):
            run_server_main(["--migrate-shared-storage"])

    def test_host_environment_initializes_tokens_and_preserves_existing_values(self):
        env_path = os.path.join(self.test_dir, ".env")
        with open(env_path, "w", encoding="utf-8") as env_file:
            env_file.write(
                "DCAS_APP_TOKEN=\n"
                "DCAS_ADMIN_TOKEN=\n"
                "DCAS_TUNNEL_NAME=stable-tunnel\n"
                "DCAS_ENABLE_CHAOS=1\n"
                "DCAS_TRUST_PROXY=0\n"
                "CUSTOM_SETTING=keep-me\n"
            )

        with patch.dict(os.environ, {}, clear=True):
            initialized = initialize_host_environment(env_path)
            self.assertEqual(os.environ["DCAS_ADMIN_TOKEN"], initialized["DCAS_ADMIN_TOKEN"])
            self.assertEqual(os.environ["DCAS_APP_TOKEN"], initialized["DCAS_APP_TOKEN"])
        self.assertTrue(initialized["DCAS_APP_TOKEN"])
        self.assertTrue(initialized["DCAS_ADMIN_TOKEN"])
        self.assertEqual(initialized["DCAS_TUNNEL_NAME"], "stable-tunnel")
        self.assertEqual(initialized["CUSTOM_SETTING"], "keep-me")
        self.assertEqual(initialized["DCAS_ENABLE_CHAOS"], "0")
        self.assertEqual(initialized["DCAS_TRUST_PROXY"], "1")
        self.assertEqual(len(initialized["DCAS_APP_TOKEN"]), 32)
        self.assertEqual(len(initialized["DCAS_ADMIN_TOKEN"]), 43)

        second_load = initialize_host_environment(env_path)
        self.assertEqual(second_load["DCAS_APP_TOKEN"], initialized["DCAS_APP_TOKEN"])
        self.assertEqual(second_load["DCAS_ADMIN_TOKEN"], initialized["DCAS_ADMIN_TOKEN"])

        new_env_path = os.path.join(self.test_dir, "new-host", ".env")
        created = initialize_host_environment(new_env_path)
        self.assertTrue(os.path.isfile(new_env_path))
        self.assertTrue(created["DCAS_APP_TOKEN"])
        self.assertTrue(created["DCAS_ADMIN_TOKEN"])

    def test_host_fails_clearly_when_api_port_is_occupied(self):
        occupied = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(occupied.close)
        occupied.bind(("127.0.0.1", 0))
        occupied.listen()
        with self.assertRaisesRegex(RuntimeError, "is already in use"):
            ensure_server_port_available("127.0.0.1", occupied.getsockname()[1])

    def test_extract_quick_tunnel_url_from_cloudflared_logs(self):
        log_line = (
            "2026-11-17 INF Your quick Tunnel has been created! Visit it at "
            "https://bright-blue-owl.trycloudflare.com"
        )
        self.assertEqual(
            extract_quick_tunnel_url(log_line),
            "https://bright-blue-owl.trycloudflare.com",
        )
        self.assertIsNone(extract_quick_tunnel_url("cloudflared connection established"))

    def test_host_wal_checkpoint_executes_sqlite_checkpoint(self):
        database_path = os.path.join(self.test_dir, "checkpoint.db")
        connection = sqlite3.connect(database_path)
        try:
            connection.execute("PRAGMA journal_mode=WAL;")
            connection.execute("CREATE TABLE sample (value TEXT)")
            connection.execute("INSERT INTO sample VALUES ('pending')")
            connection.commit()
        finally:
            connection.close()

        result = checkpoint_sqlite_wal(database_path)
        self.assertIsNotNone(result)
        self.assertEqual(result[0], 0)

    def test_host_wal_checkpoint_retries_busy_and_reports_busy_vs_success(self):
        database_path = Path(self.test_dir) / "mock-checkpoint.db"
        database_path.touch()
        busy_connection = MagicMock()
        busy_connection.execute.return_value.fetchone.return_value = (1, 3, 2)
        completed_connection = MagicMock()
        completed_connection.execute.return_value.fetchone.return_value = (0, 3, 3)

        with (
            patch.object(
                start_host.sqlite3,
                "connect",
                side_effect=[busy_connection, completed_connection],
            ) as connect,
            patch.object(start_host.time, "sleep") as sleep,
        ):
            result = checkpoint_sqlite_wal(database_path)

        self.assertEqual(result, (0, 3, 3))
        self.assertEqual(connect.call_count, 2)
        sleep.assert_called_once_with(0.2)
        busy_connection.close.assert_called_once_with()
        completed_connection.close.assert_called_once_with()

        with patch("builtins.print") as print_output:
            report_sqlite_checkpoint((1, 3, 2))
            self.assertIn("busy or incomplete", print_output.call_args.args[0])
            report_sqlite_checkpoint((0, 3, 3))
            self.assertIn("completed", print_output.call_args.args[0])

    def test_host_wal_checkpoint_retries_operational_errors(self):
        database_path = Path(self.test_dir) / "error-checkpoint.db"
        database_path.touch()
        completed_connection = MagicMock()
        completed_connection.execute.return_value.fetchone.return_value = (0, 2, 2)

        with (
            patch.object(
                start_host.sqlite3,
                "connect",
                side_effect=[
                    sqlite3.OperationalError("database is locked"),
                    completed_connection,
                ],
            ) as connect,
            patch.object(start_host.time, "sleep") as sleep,
        ):
            result = checkpoint_sqlite_wal(database_path)

        self.assertEqual(result, (0, 2, 2))
        self.assertEqual(connect.call_count, 2)
        sleep.assert_called_once_with(0.2)

    def test_host_wal_checkpoint_warns_when_busy_after_all_retries(self):
        database_path = Path(self.test_dir) / "busy-checkpoint.db"
        database_path.touch()
        busy_connection = MagicMock()
        busy_connection.execute.return_value.fetchone.return_value = (1, 4, 3)

        with (
            patch.object(
                start_host.sqlite3,
                "connect",
                return_value=busy_connection,
            ) as connect,
            patch.object(start_host.time, "sleep") as sleep,
            patch("builtins.print") as print_output,
        ):
            result = checkpoint_sqlite_wal(database_path)
            report_sqlite_checkpoint(result)
            report_sqlite_checkpoint(None)

        self.assertEqual(result, (1, 4, 3))
        self.assertEqual(connect.call_count, 6)
        self.assertEqual(sleep.call_count, 5)
        self.assertTrue(
            all(
                "busy or incomplete" in call.args[0]
                for call in print_output.call_args_list
            )
        )

    def test_desktop_build_defaults_to_dcas_and_supports_name_override(self):
        with patch("scripts.build_desktop_client.subprocess.call", return_value=0) as call:
            self.assertEqual(build_desktop_client([]), 0)
            default_command = call.call_args.args[0]
            self.assertEqual(default_command[default_command.index("--name") + 1], "DCAS")

        with patch("scripts.build_desktop_client.subprocess.call", return_value=0) as call:
            self.assertEqual(build_desktop_client(["--name", "DCAS-Test"]), 0)

        command = call.call_args.args[0]
        self.assertEqual(command[command.index("--name") + 1], "DCAS-Test")
        self.assertEqual(command[command.index("--onefile")], "--onefile")
        self.assertEqual(command[command.index("--windowed")], "--windowed")
        self.assertTrue(command[-1].endswith(os.path.join("dcas", "desktop_client.py")))

    def test_sqlite_metadata_store_uses_write_ahead_logging(self):
        metadata = self.app.extensions["dcas"]["metadata"]
        journal_mode = metadata.conn.execute("PRAGMA journal_mode;").fetchone()[0]
        self.assertEqual(journal_mode.lower(), "wal")

    def test_private_space_events_never_expose_private_metadata(self):
        space_name = "Distinct Private Space Secret"
        private_filename = "distinct-encrypted-filename-secret.dat"
        created = self.client.post("/api/spaces", json={"name": space_name})
        self.assertEqual(created.status_code, 201)
        space = created.get_json()
        space_id = space["space_id"]
        admin_headers = {"Authorization": f"Bearer {space['admin_token']}"}
        share_headers = {"Authorization": f"Bearer {space['share_token']}"}

        uploaded = self.client.post(
            f"/api/spaces/{space_id}/files",
            headers=admin_headers,
            data={
                "file": (
                    io.BytesIO(b"DCAS1" + b"\x00" * 12 + b"encrypted"),
                    private_filename,
                )
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(uploaded.status_code, 201)
        cid = uploaded.get_json()["cid"]

        self.app.extensions["dcas"]["metadata"].log_event(
            "LEGACY_PRIVATE_EVENT",
            cid,
            private_filename,
            f"Legacy record contained {space_name}, {space_id}, and {space['share_token']}",
        )
        self.client.get(
            f"/api/spaces/{space_id}/files/{cid}/download",
            headers=share_headers,
        )
        self.client.post(
            f"/api/spaces/{space_id}/files/{cid}/verify",
            headers=share_headers,
        )
        revoked = self.client.delete(
            f"/api/spaces/{space_id}/link",
            headers=admin_headers,
        )
        self.assertEqual(revoked.status_code, 200)
        deleted = self.client.delete(
            f"/api/spaces/{space_id}",
            headers=admin_headers,
        )
        self.assertEqual(deleted.status_code, 200)

        self.app.extensions["dcas"]["metadata"].log_event(
            "ORPHANED_LEGACY_PRIVATE_EVENT",
            cid,
            private_filename,
            f"Old record contained {space_name}, {space_id}, and {space['share_token']}",
        )
        events = self.client.get("/api/events")
        self.assertEqual(events.status_code, 200)
        serialized_events = json.dumps(events.get_json())
        for private_value in (
            space_name,
            space_id,
            private_filename,
            space["admin_token"],
            space["share_token"],
            cid,
        ):
            self.assertNotIn(private_value, serialized_events)

    def test_api_checks_pairing_por_node_possession(self):
        uploaded = self.client.post(
            "/api/upload",
            data={"file": (io.BytesIO(b"node retrievability API " * 24), "sample.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(uploaded.status_code, 201)
        cid = uploaded.get_json()["cid"]
        manifest = self.app.extensions["dcas"]["metadata"].get_manifest(cid)
        self.assertEqual(manifest["por_status"], "active")
        node_id = manifest["placements"][0]["stored_on"][0]

        checked = self.client.post(
            f"/api/verify/{cid}/nodes/{node_id}",
            json={"sample_count": 2},
        )
        self.assertEqual(checked.status_code, 200)
        self.assertEqual(checked.get_json()["status"], "PASSED")
        self.assertEqual(checked.get_json()["details"]["sample_count"], 2)
        self.assertEqual(checked.get_json()["details"]["data_bytes_returned"], 0)
        self.assertEqual(
            checked.get_json()["details"]["scheme"],
            "dcas-pairing-por-2of3-edu-v2",
        )

        invalid = self.client.post(
            f"/api/verify/{cid}/nodes/{node_id}",
            json={"sample_count": 1},
        )
        self.assertEqual(invalid.status_code, 400)

        small_upload = self.client.post(
            "/api/upload",
            data={"file": (io.BytesIO(b"one sector"), "small.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(small_upload.status_code, 201)
        small_cid = small_upload.get_json()["cid"]
        small_node_id = self.app.extensions["dcas"]["metadata"].get_manifest(
            small_cid
        )["placements"][0]["stored_on"][0]
        one_sector_request = self.client.post(
            f"/api/verify/{small_cid}/nodes/{small_node_id}",
            json={"sample_count": 1},
        )
        self.assertEqual(one_sector_request.status_code, 400)

        small_default = self.client.post(
            f"/api/verify/{small_cid}/nodes/{small_node_id}",
        )
        self.assertEqual(small_default.status_code, 200)
        self.assertEqual(small_default.get_json()["status"], "PASSED")

    def test_shared_space_is_encrypted_and_access_is_revocable(self):
        self.assertEqual(self.client.get("/share/example").status_code, 200)
        created = self.client.post("/api/spaces", json={"name": "Research group"})
        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.headers["Cache-Control"], "no-store")
        space = created.get_json()
        space_id = space["space_id"]
        admin_headers = {"Authorization": f"Bearer {space['admin_token']}"}
        reader_headers = {"Authorization": f"Bearer {space['share_token']}"}

        self.assertEqual(self.client.get(f"/api/spaces/{space_id}/files").status_code, 404)
        reader_upload = self.client.post(
            f"/api/spaces/{space_id}/files",
            headers=reader_headers,
            data={"file": (io.BytesIO(b"DCAS1encrypted"), "private.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(reader_upload.status_code, 404)

        plain_upload = self.client.post(
            f"/api/spaces/{space_id}/files",
            headers=admin_headers,
            data={"file": (io.BytesIO(b"not encrypted"), "private.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(plain_upload.status_code, 400)

        ciphertext = b"DCAS1" + b"\x00" * 12 + b"encrypted"
        encrypted_upload = self.client.post(
            f"/api/spaces/{space_id}/files",
            headers=admin_headers,
            data={"file": (io.BytesIO(ciphertext), "private.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(encrypted_upload.status_code, 201)
        cid = encrypted_upload.get_json()["cid"]

        components = self.app.extensions["dcas"]
        manifest = components["metadata"].get_manifest(cid)
        stored_envelope = components["network"].retrieve_file(manifest)
        if stored_envelope is None:
            self.fail("Shared upload was not retrievable from the network")
        self.assertTrue(stored_envelope.startswith(b"DCAS-STORE-1:"))
        self.assertEqual(components["storage_encryptor"].decrypt(stored_envelope), ciphertext)
        chunk_hash = manifest["placements"][0]["chunk_hash"]
        stored_nodes = [
            node for node in components["network"].nodes if node.has_chunk(chunk_hash)
        ]
        self.assertTrue(stored_nodes)
        for node in stored_nodes:
            self.assertNotEqual(node.retrieve_chunk(chunk_hash), ciphertext)

        reader_list = self.client.get(f"/api/spaces/{space_id}/files", headers=reader_headers)
        self.assertEqual(reader_list.status_code, 200)
        self.assertEqual(reader_list.get_json()["count"], 1)
        self.assertFalse(reader_list.get_json()["can_upload"])
        self.assertNotIn(cid, [item["cid"] for item in self.client.get("/api/files").get_json()["files"]])
        self.assertEqual(self.client.get(f"/api/file/{cid}").status_code, 404)
        self.assertEqual(self.client.get(f"/api/download/{cid}").status_code, 404)
        self.assertEqual(self.client.post(f"/api/verify/{cid}").status_code, 404)
        self.assertEqual(
            self.client.post(f"/api/verify/{cid}/nodes/node-000").status_code,
            404,
        )
        self.assertEqual(self.client.get(f"/api/search?q=private").get_json()["count"], 0)
        public_upload = self.client.post(
            "/api/upload",
            data={"file": (io.BytesIO(ciphertext), "public-copy.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(public_upload.status_code, 409)
        self.assertEqual(self.app.extensions["dcas"]["metadata"].get_file_info(cid)["space_id"], space_id)
        self.assertEqual(
            self.client.get(f"/api/audit-log?cid={cid}").get_json()["logs"],
            [],
        )
        shared_download = self.client.get(
            f"/api/spaces/{space_id}/files/{cid}/download",
            headers=reader_headers,
        )
        self.assertEqual(shared_download.data, ciphertext)
        self.assertTrue(
            shared_download.headers["Content-Disposition"].startswith(
                "attachment; filename="
            )
        )
        self.assertEqual(
            shared_download.headers["X-Content-Type-Options"],
            "nosniff",
        )
        verification = self.client.post(
            f"/api/spaces/{space_id}/files/{cid}/verify",
            headers=reader_headers,
        )
        self.assertEqual(verification.get_json()["status"], "PASSED")

        rotated = self.client.post(
            f"/api/spaces/{space_id}/link/rotate",
            headers=admin_headers,
        ).get_json()
        self.assertEqual(self.client.get(f"/api/spaces/{space_id}/files", headers=reader_headers).status_code, 404)
        new_reader_headers = {"Authorization": f"Bearer {rotated['share_token']}"}
        self.assertEqual(self.client.get(f"/api/spaces/{space_id}/files", headers=new_reader_headers).status_code, 200)

        self.assertEqual(self.client.delete(f"/api/spaces/{space_id}/link", headers=admin_headers).status_code, 200)
        self.assertEqual(self.client.get(f"/api/spaces/{space_id}/files", headers=new_reader_headers).status_code, 404)

    def test_shared_space_delete_rejects_missing_and_share_tokens(self):
        created = self.client.post("/api/spaces", json={"name": "Protected space"})
        space = created.get_json()
        space_id = space["space_id"]
        expected = {"error": "Shared space not found or owner access required"}

        missing_token = self.client.delete(f"/api/spaces/{space_id}")
        wrong_token = self.client.delete(
            f"/api/spaces/{space_id}",
            headers={"Authorization": "Bearer wrong-token"},
        )
        share_token = self.client.delete(
            f"/api/spaces/{space_id}",
            headers={"Authorization": f"Bearer {space['share_token']}"},
        )
        self.assertEqual(missing_token.status_code, 404)
        self.assertEqual(missing_token.get_json(), expected)
        self.assertEqual(wrong_token.status_code, 404)
        self.assertEqual(wrong_token.get_json(), expected)
        self.assertEqual(share_token.status_code, 404)
        self.assertEqual(share_token.get_json(), expected)
        self.assertEqual(
            self.client.get(
                f"/api/spaces/{space_id}/files",
                headers={"Authorization": f"Bearer {space['admin_token']}"},
            ).status_code,
            200,
        )

    def test_shared_space_can_be_deleted_by_global_admin(self):
        space = self.client.post(
            "/api/spaces",
            json={"name": "Global-admin deletion"},
        ).get_json()
        space_id = space["space_id"]

        response = self.client.delete(
            f"/api/spaces/{space_id}",
            headers={"X-Admin-Token": "test-admin-token"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(),
            {"space_id": space_id, "deleted_files": 0},
        )
        self.assertIsNone(self.app.extensions["dcas"]["metadata"].get_shared_space(space_id))
        self.assertEqual(
            self.client.get(
                f"/api/spaces/{space_id}/files",
                headers={"Authorization": f"Bearer {space['admin_token']}"},
            ).status_code,
            404,
        )

    def test_shared_space_delete_cascades_and_preserves_referenced_chunks(self):
        space = self.client.post(
            "/api/spaces",
            json={"name": "Cascade deletion"},
        ).get_json()
        space_id = space["space_id"]
        metadata = self.app.extensions["dcas"]["metadata"]
        network = self.app.extensions["dcas"]["network"]

        referenced_manifest = network.store_por_bytes(
            b"shared chunk content",
            filename="referenced.bin",
        )
        metadata.store_manifest(
            referenced_manifest,
            owner="shared",
            space_id=space_id,
        )

        unreferenced_manifest = network.store_por_bytes(
            b"space-only chunk content",
            filename="unreferenced.bin",
        )
        metadata.store_manifest(
            unreferenced_manifest,
            owner="shared",
            space_id=space_id,
        )

        public_reference_manifest = copy.deepcopy(referenced_manifest)
        public_reference_manifest["cid"]["cid"] = f"public-reference-{space_id}"
        public_reference_manifest["filename"] = "public-reference.bin"
        metadata.store_manifest(public_reference_manifest, owner="system")

        referenced_hashes = {
            placement["chunk_hash"]
            for placement in referenced_manifest["placements"]
        }
        unreferenced_hashes = {
            placement["chunk_hash"]
            for placement in unreferenced_manifest["placements"]
        }
        self.assertTrue(
            all(
                any(node.has_chunk(chunk_hash) for node in network.nodes)
                for chunk_hash in referenced_hashes | unreferenced_hashes
            )
        )

        response = self.client.delete(
            f"/api/spaces/{space_id}",
            headers={"Authorization": f"Bearer {space['admin_token']}"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(),
            {"space_id": space_id, "deleted_files": 2},
        )
        self.assertIsNone(metadata.get_shared_space(space_id))
        self.assertIsNone(metadata.get_file_info(referenced_manifest["cid"]["cid"]))
        self.assertIsNone(metadata.get_file_info(unreferenced_manifest["cid"]["cid"]))
        self.assertIsNotNone(metadata.get_file_info(public_reference_manifest["cid"]["cid"]))
        self.assertTrue(
            all(
                any(node.has_chunk(chunk_hash) for node in network.nodes)
                for chunk_hash in referenced_hashes
            )
        )
        self.assertTrue(
            all(
                not any(node.has_chunk(chunk_hash) for node in network.nodes)
                for chunk_hash in unreferenced_hashes
            )
        )
        self.assertEqual(
            self.client.get(
                f"/api/spaces/{space_id}/files",
                headers={"Authorization": f"Bearer {space['admin_token']}"},
            ).status_code,
            404,
        )
        self.assertEqual(
            len(metadata.get_audit_log(event_type="SPACE_DELETE")),
            1,
        )

    def test_shared_space_owner_can_enable_link_uploads(self):
        created = self.client.post(
            "/api/spaces",
            json={"name": "Collaborative space", "allow_upload": True},
        )
        self.assertEqual(created.status_code, 201)
        space = created.get_json()
        space_id = space["space_id"]
        reader_headers = {"Authorization": f"Bearer {space['share_token']}"}

        listing = self.client.get(f"/api/spaces/{space_id}/files", headers=reader_headers)
        self.assertTrue(listing.get_json()["can_upload"])
        upload = self.client.post(
            f"/api/spaces/{space_id}/files",
            headers=reader_headers,
            data={"file": (io.BytesIO(b"DCAS1" + b"\x00" * 12 + b"encrypted"), "member-upload.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(upload.status_code, 201)
        cid = upload.get_json()["cid"]
        verify = self.client.post(
            f"/api/spaces/{space_id}/files/{cid}/verify",
            headers=reader_headers,
        )
        self.assertEqual(verify.get_json()["status"], "PASSED")

    def test_shared_storage_migration_preserves_access_and_cleans_legacy_chunks(self):
        created = self.client.post("/api/spaces", json={"name": "Legacy space"})
        space = created.get_json()
        space_id = space["space_id"]
        reader_headers = {"Authorization": f"Bearer {space['share_token']}"}
        components = self.app.extensions["dcas"]
        metadata = components["metadata"]
        network = components["network"]
        encryptor = components["storage_encryptor"]

        client_key = b"c" * 32
        nonce = b"n" * 12
        client_payload = b"DCAS1" + nonce + AESGCM(client_key).encrypt(
            nonce,
            b"legacy shared file",
            None,
        )
        legacy_manifest = network.store_bytes(client_payload, filename="legacy.bin")
        legacy_cid = legacy_manifest["cid"]["cid"]
        old_chunk_hashes = {
            placement["chunk_hash"] for placement in legacy_manifest["placements"]
        }
        metadata.store_manifest(legacy_manifest, owner="shared", space_id=space_id)

        previously_wrapped_payload = b"DCAS1old envelope"
        wrapped_manifest = network.store_bytes(
            encryptor.encrypt(previously_wrapped_payload),
            filename="already-wrapped.bin",
        )
        wrapped_cid = wrapped_manifest["cid"]["cid"]
        metadata.store_manifest(wrapped_manifest, owner="shared", space_id=space_id)

        result = migrate_shared_storage(components)

        self.assertEqual(result, {"migrated": 1, "already_encrypted": 1})
        migrated_manifest = metadata.get_manifest(legacy_cid)
        migrated_bytes = network.retrieve_file(migrated_manifest)
        self.assertEqual(migrated_manifest["cid"]["cid"], legacy_cid)
        self.assertTrue(migrated_manifest["cid_hash_is_client_content"])
        self.assertTrue(migrated_manifest["storage_encrypted"])
        self.assertEqual(migrated_manifest["por_status"], "legacy")
        self.assertEqual(encryptor.decrypt(migrated_bytes), client_payload)
        self.assertTrue(metadata.has_shared_source_fingerprint(encryptor.fingerprint(client_payload)))
        self.assertTrue(
            all(
                not node.has_chunk(chunk_hash)
                for node in network.nodes
                for chunk_hash in old_chunk_hashes
            )
        )
        public_duplicate = self.client.post(
            "/api/upload",
            data={"file": (io.BytesIO(client_payload), "public-copy.bin")},
            content_type="multipart/form-data",
        )
        self.assertEqual(public_duplicate.status_code, 409)

        downloaded = self.client.get(
            f"/api/spaces/{space_id}/files/{legacy_cid}/download",
            headers=reader_headers,
        )
        self.assertEqual(downloaded.status_code, 200)
        self.assertEqual(downloaded.data, client_payload)
        verification = self.client.post(
            f"/api/spaces/{space_id}/files/{legacy_cid}/verify",
            headers=reader_headers,
        )
        self.assertEqual(verification.get_json()["status"], "PASSED")

        repeated = migrate_shared_storage(components)
        self.assertEqual(repeated, {"migrated": 0, "already_encrypted": 2})
        self.assertEqual(metadata.get_manifest(wrapped_cid)["cid"]["cid"], wrapped_cid)

    def test_shared_storage_migration_stops_on_invalid_envelope(self):
        created = self.client.post("/api/spaces", json={"name": "Damaged space"})
        space_id = created.get_json()["space_id"]
        components = self.app.extensions["dcas"]
        encryptor = components["storage_encryptor"]
        envelope = encryptor.encrypt(b"client payload")
        damaged = envelope[:-1] + bytes([envelope[-1] ^ 1])
        manifest = components["network"].store_bytes(damaged, filename="damaged.bin")
        manifest["storage_encrypted"] = True
        cid = manifest["cid"]["cid"]
        components["metadata"].store_manifest(manifest, owner="shared", space_id=space_id)

        with self.assertRaisesRegex(RuntimeError, "failed storage authentication"):
            migrate_shared_storage(components)

        self.assertEqual(components["metadata"].get_manifest(cid), manifest)

    def test_delete_file_does_not_remove_another_encrypted_files_chunks(self):
        shared_chunk = b"S" * (256 * 1024)
        first_upload = self.client.post(
            "/api/upload",
            data={"file": (io.BytesIO(shared_chunk + b"first"), "first.bin")},
            content_type="multipart/form-data",
        )
        second_upload = self.client.post(
            "/api/upload",
            data={"file": (io.BytesIO(shared_chunk + b"second"), "second.bin")},
            content_type="multipart/form-data",
        )
        self.assertEqual(first_upload.status_code, 201)
        self.assertEqual(second_upload.status_code, 201)

        first_cid = first_upload.get_json()["cid"]
        second_cid = second_upload.get_json()["cid"]
        metadata = self.app.extensions["dcas"]["metadata"]
        network = self.app.extensions["dcas"]["network"]
        first_manifest = metadata.get_manifest(first_cid)
        second_manifest = metadata.get_manifest(second_cid)
        shared_hash = first_manifest["placements"][0]["chunk_hash"]
        unique_hash = first_manifest["placements"][1]["chunk_hash"]
        second_shared_hash = second_manifest["placements"][0]["chunk_hash"]
        self.assertNotEqual(shared_hash, second_shared_hash)

        unauthorized = self.client.delete(f"/api/file/{first_cid}")
        self.assertEqual(unauthorized.status_code, 401)
        response = self.client.delete(
            f"/api/file/{first_cid}",
            headers={"X-Admin-Token": "test-admin-token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertGreater(response.get_json()["deleted_chunk_copies"], 0)
        self.assertEqual(self.client.get(f"/api/file/{first_cid}").status_code, 404)
        self.assertEqual(self.client.get(f"/api/file/{second_cid}").status_code, 200)
        self.assertIsNotNone(network.retrieve_file(metadata.get_manifest(second_cid)))
        self.assertFalse(any(node.has_chunk(shared_hash) for node in network.nodes))
        self.assertFalse(any(node.has_chunk(unique_hash) for node in network.nodes))
        self.assertTrue(
            any(node.has_chunk(second_shared_hash) for node in network.nodes)
        )

    def test_mongodb_environment_selects_mongodb_metadata_store(self):
        test_dir = tempfile.mkdtemp()
        try:
            with (
                patch.dict(
                    os.environ,
                    {
                        "DCAS_MONGODB_URI": "mongodb://example.invalid",
                        "DCAS_MONGODB_DATABASE": "dcas_test",
                    },
                ),
                patch("dcas.api.server.MongoMetadataStore") as mongo_store,
            ):
                app = create_app(
                    network_dir=os.path.join(test_dir, "network"),
                    db_path=os.path.join(test_dir, "metadata.db"),
                    num_nodes=3,
                    replication_factor=1,
                )

            mongo_store.assert_called_once_with("mongodb://example.invalid", "dcas_test")
            self.assertIs(app.extensions["dcas"]["metadata"], mongo_store.return_value)
            app.extensions["dcas"]["network"].cleanup()
        finally:
            shutil.rmtree(test_dir)


if __name__ == "__main__":
    unittest.main()

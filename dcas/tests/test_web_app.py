import os
import shutil
import tempfile
import unittest

from dcas.api.server import create_app


class TestWebApp(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.app = create_app(
            network_dir=os.path.join(self.test_dir, "network"),
            db_path=os.path.join(self.test_dir, "metadata.db"),
            num_nodes=2,
            replication_factor=1,
        )
        self.app.testing = True
        self.client = self.app.test_client()

    def tearDown(self):
        components = self.app.extensions["dcas"]
        components["metadata"].close()
        components["network"].cleanup()
        shutil.rmtree(self.test_dir)

    def test_dashboard_and_assets_are_served(self):
        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Your files.", page.data)
        self.assertIn(b"/static/app.css", page.data)
        self.assertIn(b"/static/app.js", page.data)

        stylesheet = self.client.get("/static/app.css")
        script = self.client.get("/static/app.js")
        self.assertEqual(stylesheet.status_code, 200)
        self.assertIn(b".app-shell", stylesheet.data)
        self.assertEqual(script.status_code, 200)
        self.assertIn(b"loadDashboard", script.data)

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

    def test_dashboard_node_controls_update_network_status(self):
        initial_status = self.client.get("/api/network/status").get_json()
        node_id = initial_status["nodes"][0]["node_id"]

        failed = self.client.post(f"/api/network/fail/{node_id}")
        self.assertEqual(failed.status_code, 200)
        status_after_failure = self.client.get("/api/network/status").get_json()
        self.assertEqual(status_after_failure["offline_nodes"], 1)

        recovered = self.client.post(f"/api/network/recover/{node_id}")
        self.assertEqual(recovered.status_code, 200)
        status_after_recovery = self.client.get("/api/network/status").get_json()
        self.assertEqual(status_after_recovery["online_nodes"], 2)


if __name__ == "__main__":
    unittest.main()

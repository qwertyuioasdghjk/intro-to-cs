import io
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from dcas.api.server import create_app
from dcas.storage.migration import migrate_shared_storage


class TestWebApp(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.app = create_app(
            network_dir=os.path.join(self.test_dir, "network"),
            db_path=os.path.join(self.test_dir, "metadata.db"),
            num_nodes=2,
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

    def test_dashboard_and_assets_are_served(self):
        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Your files.", page.data)
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
        verification = self.client.post(f"/api/verify/{cid}")
        self.assertEqual(verification.get_json()["status"], "PASSED")

        invalid = self.client.post("/api/upload/text", json={"content": 123})
        self.assertEqual(invalid.status_code, 400)

    def test_text_upload_reports_unavailable_storage(self):
        for node in self.app.extensions["dcas"]["network"].nodes:
            node.capacity = 1

        response = self.client.post("/api/upload/text", json={"content": "too large"})

        self.assertEqual(response.status_code, 503)
        self.assertEqual(self.client.get("/api/files").get_json()["count"], 0)

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
        self.assertEqual(
            self.client.get(f"/api/spaces/{space_id}/files/{cid}/download", headers=reader_headers).data,
            ciphertext,
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

    def test_delete_file_removes_unshared_chunks_and_keeps_shared_chunks(self):
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
        shared_hash = first_manifest["placements"][0]["chunk_hash"]
        unique_hash = first_manifest["placements"][1]["chunk_hash"]

        response = self.client.delete(f"/api/file/{first_cid}")
        self.assertEqual(response.status_code, 200)
        self.assertGreater(response.get_json()["deleted_chunk_copies"], 0)
        self.assertEqual(self.client.get(f"/api/file/{first_cid}").status_code, 404)
        self.assertEqual(self.client.get(f"/api/file/{second_cid}").status_code, 200)
        self.assertIsNotNone(network.retrieve_file(metadata.get_manifest(second_cid)))
        self.assertTrue(any(node.has_chunk(shared_hash) for node in network.nodes))
        self.assertFalse(any(node.has_chunk(unique_hash) for node in network.nodes))

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
                    num_nodes=2,
                    replication_factor=1,
                )

            mongo_store.assert_called_once_with("mongodb://example.invalid", "dcas_test")
            self.assertIs(app.extensions["dcas"]["metadata"], mongo_store.return_value)
            app.extensions["dcas"]["network"].cleanup()
        finally:
            shutil.rmtree(test_dir)


if __name__ == "__main__":
    unittest.main()

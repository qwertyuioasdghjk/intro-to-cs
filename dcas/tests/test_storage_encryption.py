import os
import tempfile
import unittest
from unittest.mock import patch

from dcas.storage.encryption import StorageEncryptor, StorageEncryptionError


class TestStorageEncryptor(unittest.TestCase):
    def test_round_trip_empty_and_nonempty_data(self):
        encryptor = StorageEncryptor(b"k" * StorageEncryptor.KEY_SIZE)

        for original in (b"", b"shared file payload"):
            with self.subTest(original=original):
                envelope = encryptor.encrypt(original)
                self.assertTrue(envelope.startswith(StorageEncryptor.ENVELOPE_PREFIX))
                self.assertEqual(encryptor.decrypt(envelope), original)

    def test_rejects_tampered_or_malformed_envelopes(self):
        encryptor = StorageEncryptor(b"k" * StorageEncryptor.KEY_SIZE)
        envelope = encryptor.encrypt(b"payload")
        tampered = envelope[:-1] + bytes([envelope[-1] ^ 1])

        with self.assertRaises(StorageEncryptionError):
            encryptor.decrypt(tampered)
        with self.assertRaises(StorageEncryptionError):
            encryptor.decrypt(b"DCAS-STORE-1:short")

    def test_generated_key_persists_across_encryptor_instances(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("DCAS_STORAGE_ENCRYPTION_KEY", None)
                os.environ.pop("DCAS_STORAGE_KEY_FILE", None)
                first = StorageEncryptor.from_config(directory)
                envelope = first.encrypt(b"payload")
                second = StorageEncryptor.from_config(directory)

            self.assertEqual(second.decrypt(envelope), b"payload")
            self.assertTrue(os.path.isfile(os.path.join(directory, ".dcas-storage-key")))


if __name__ == "__main__":
    unittest.main()

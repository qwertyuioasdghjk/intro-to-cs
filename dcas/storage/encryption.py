"""Authenticated encryption for data stored on DCAS storage nodes."""

import base64
import binascii
import hashlib
import hmac
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class StorageEncryptionError(ValueError):
    """Raised when a stored-data envelope is malformed or cannot be authenticated."""


class StorageEncryptor:
    """Encrypt data before it reaches storage nodes using AES-256-GCM."""

    ENVELOPE_PREFIX = b"DCAS-STORE-1:"
    KEY_SIZE = 32
    NONCE_SIZE = 12
    TAG_SIZE = 16

    def __init__(self, key: bytes):
        if len(key) != self.KEY_SIZE:
            raise ValueError("The storage encryption key must be exactly 32 bytes.")
        self._aead = AESGCM(key)
        self._fingerprint_key = hmac.new(
            key,
            b"DCAS shared-source fingerprint v1",
            hashlib.sha256,
        ).digest()

    @classmethod
    def from_config(cls, network_dir: str) -> "StorageEncryptor":
        """Load a configured key or create a persistent development key."""
        encoded_key = os.environ.get("DCAS_STORAGE_ENCRYPTION_KEY")
        if encoded_key is not None:
            try:
                key = base64.b64decode(encoded_key, altchars=b"-_", validate=True)
            except (binascii.Error, ValueError) as error:
                raise ValueError(
                    "DCAS_STORAGE_ENCRYPTION_KEY must be URL-safe base64 for a 32-byte key."
                ) from error
            return cls(key)

        key_path = os.environ.get(
            "DCAS_STORAGE_KEY_FILE",
            os.path.join(network_dir, ".dcas-storage-key"),
        )
        return cls._from_key_file(key_path)

    @classmethod
    def _from_key_file(cls, key_path: str) -> "StorageEncryptor":
        key_path = os.path.abspath(key_path)
        os.makedirs(os.path.dirname(key_path), exist_ok=True)

        try:
            descriptor = os.open(
                key_path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
        except FileExistsError:
            with open(key_path, "rb") as key_file:
                key = key_file.read()
        else:
            key = os.urandom(cls.KEY_SIZE)
            with os.fdopen(descriptor, "wb") as key_file:
                key_file.write(key)
                key_file.flush()
                os.fsync(key_file.fileno())

        return cls(key)

    def encrypt(self, data: bytes) -> bytes:
        """Return a versioned, authenticated ciphertext envelope."""
        nonce = os.urandom(self.NONCE_SIZE)
        ciphertext = self._aead.encrypt(nonce, data, self.ENVELOPE_PREFIX)
        return self.ENVELOPE_PREFIX + nonce + ciphertext

    def decrypt(self, envelope: bytes) -> bytes:
        """Authenticate and decrypt a stored-data envelope."""
        minimum_size = len(self.ENVELOPE_PREFIX) + self.NONCE_SIZE + self.TAG_SIZE
        if not envelope.startswith(self.ENVELOPE_PREFIX) or len(envelope) < minimum_size:
            raise StorageEncryptionError("Stored data has an invalid encryption envelope.")

        nonce_start = len(self.ENVELOPE_PREFIX)
        nonce_end = nonce_start + self.NONCE_SIZE
        nonce = envelope[nonce_start:nonce_end]
        ciphertext = envelope[nonce_end:]
        try:
            return self._aead.decrypt(nonce, ciphertext, self.ENVELOPE_PREFIX)
        except InvalidTag as error:
            raise StorageEncryptionError(
                "Stored data failed its encryption authentication check."
            ) from error

    def fingerprint(self, data: bytes) -> str:
        """Return a keyed fingerprint for shared/public content collision checks."""
        return hmac.new(self._fingerprint_key, data, hashlib.sha256).hexdigest()

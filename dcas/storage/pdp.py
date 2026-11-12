"""Educational RSA proof-of-data-possession protocol.

This module is a teaching implementation, not a reviewed production
cryptographic library. The RSA-PDP equations follow the homomorphic-tag
construction: tags authenticate a file block, while an audit proves a random
linear combination of challenged blocks without returning those blocks.
"""

import hashlib
import math
import os
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class StoragePDP:
    """Create homomorphic RSA tags and verify aggregate storage proofs."""

    SCHEME = "dcas-rsa-pdp-edu-v1"
    SECTOR_SIZE = 128
    KEY_SIZE = 2048
    COEFFICIENT_BITS = 128

    def __init__(self, private_key: rsa.RSAPrivateKey):
        if not self.KEY_SIZE <= private_key.key_size <= 4096:
            raise ValueError("PDP RSA keys must be 2048 to 4096 bits.")

        numbers = private_key.private_numbers()
        self._modulus = numbers.public_numbers.n
        self._public_exponent = numbers.public_numbers.e
        self._prime_p = numbers.p
        self._prime_q = numbers.q
        self._exponent_p = numbers.dmp1
        self._exponent_q = numbers.dmq1
        self._coefficient_q = numbers.iqmp
        self._public_base = self._derive_base(self._modulus)

    @classmethod
    def from_config(cls, network_dir: str) -> "StoragePDP":
        """Load or create the persistent PDP signing key."""
        key_path = os.path.abspath(os.environ.get(
            "DCAS_PDP_PRIVATE_KEY_FILE",
            os.path.join(network_dir, ".dcas-pdp-private-key.pem"),
        ))
        os.makedirs(os.path.dirname(key_path), exist_ok=True)

        try:
            with open(key_path, "rb") as key_file:
                key_data = key_file.read()
        except FileNotFoundError:
            generated_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=cls.KEY_SIZE,
            )
            key_data = generated_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            try:
                descriptor = os.open(
                    key_path,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                    0o600,
                )
            except FileExistsError:
                with open(key_path, "rb") as key_file:
                    key_data = key_file.read()
            else:
                with os.fdopen(descriptor, "wb") as key_file:
                    key_file.write(key_data)
                    key_file.flush()
                    os.fsync(key_file.fileno())

        private_key = serialization.load_pem_private_key(key_data, password=None)
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("The configured PDP key is not an RSA private key.")
        return cls(private_key)

    @property
    def public_parameters(self) -> dict[str, str]:
        """Return the public RSA-PDP parameters as lowercase hexadecimal."""
        return {
            "n": format(self._modulus, "x"),
            "e": format(self._public_exponent, "x"),
            "u": format(self._public_base, "x"),
        }

    @classmethod
    def block_count(cls, data_size: int) -> int:
        """Return the number of fixed-size audit sectors, including empty files."""
        if data_size < 0:
            raise ValueError("Data size cannot be negative.")
        return max(1, (data_size + cls.SECTOR_SIZE - 1) // cls.SECTOR_SIZE)

    @classmethod
    def split_sectors(cls, data: bytes) -> list[bytes]:
        """Split data into fixed-size sectors; preserve one empty sector for empty data."""
        if not data:
            return [b""]
        return [
            data[offset:offset + cls.SECTOR_SIZE]
            for offset in range(0, len(data), cls.SECTOR_SIZE)
        ]

    @classmethod
    def message_value(cls, block: bytes) -> int:
        """Encode a sector injectively as an integer smaller than a 2048-bit RSA modulus."""
        if len(block) > cls.SECTOR_SIZE:
            raise ValueError("PDP sector exceeds the configured sector size.")
        encoded = b"\x01" + len(block).to_bytes(2, "big") + block.ljust(cls.SECTOR_SIZE, b"\x00")
        return int.from_bytes(encoded, "big")

    def file_metadata(
        self,
        file_id: str,
        data_size: int,
        storage_chunk_size: int,
    ) -> dict[str, Any]:
        """Build the public commitment parameters to persist in a file manifest."""
        if storage_chunk_size <= 0 or storage_chunk_size % self.SECTOR_SIZE:
            raise ValueError(
                f"Storage chunk size must be divisible by PDP sector size "
                f"({self.SECTOR_SIZE} bytes)."
            )
        return {
            "scheme": self.SCHEME,
            "file_id": file_id,
            "sector_size": self.SECTOR_SIZE,
            "sector_count": self.block_count(data_size),
            "storage_chunk_size": storage_chunk_size,
            **self.public_parameters,
        }

    def create_tags(self, file_id: str, data: bytes) -> list[str]:
        """Tag each sector with an RSA homomorphic authenticator."""
        return [
            format(self._create_tag(file_id, index, block), "x")
            for index, block in enumerate(self.split_sectors(data))
        ]

    def _create_tag(self, file_id: str, index: int, block: bytes) -> int:
        digest_base = self._hash_to_unit(self._modulus, file_id, index)
        message = self.message_value(block)
        base = digest_base * pow(self._public_base, message, self._modulus)
        base %= self._modulus
        result_p = pow(base % self._prime_p, self._exponent_p, self._prime_p)
        result_q = pow(base % self._prime_q, self._exponent_q, self._prime_q)
        return (
            result_q
            + self._prime_q
            * (self._coefficient_q * (result_p - result_q) % self._prime_p)
        ) % self._modulus

    @classmethod
    def verify_aggregate_proof(
        cls,
        file_id: str,
        challenges: list[dict[str, int]],
        sigma: int,
        mu: int,
        public_parameters: dict[str, str],
    ) -> bool:
        """Verify an aggregate RSA-PDP response using only public parameters."""
        try:
            modulus = int(public_parameters["n"], 16)
            exponent = int(public_parameters["e"], 16)
            public_base = int(public_parameters["u"], 16)
        except (KeyError, TypeError, ValueError):
            return False

        if (
            modulus.bit_length() < cls.KEY_SIZE
            or modulus.bit_length() > 4096
            or exponent < 3
            or exponent % 2 == 0
            or exponent >= 2 ** 32
            or not 1 < public_base < modulus
            or math.gcd(public_base, modulus) != 1
            or public_base != cls._derive_base(modulus)
            or not isinstance(sigma, int)
            or isinstance(sigma, bool)
            or not 1 <= sigma < modulus
            or not isinstance(mu, int)
            or isinstance(mu, bool)
            or mu < 0
            or mu.bit_length() > 1182
            or not isinstance(challenges, list)
            or not 1 <= len(challenges) <= 64
        ):
            return False

        right_side = 1
        seen_indices = set()
        try:
            for item in challenges:
                index = item["sector_index"]
                coefficient = item["coefficient"]
                if (
                    not isinstance(index, int)
                    or isinstance(index, bool)
                    or index < 0
                    or index in seen_indices
                    or not isinstance(coefficient, int)
                    or isinstance(coefficient, bool)
                    or not 1 <= coefficient < 2 ** cls.COEFFICIENT_BITS
                ):
                    return False
                seen_indices.add(index)
                block_base = cls._hash_to_unit(modulus, file_id, index)
                right_side = (
                    right_side * pow(block_base, coefficient, modulus)
                ) % modulus
        except (KeyError, TypeError, ValueError):
            return False

        right_side = (
            right_side * pow(public_base, mu, modulus)
        ) % modulus
        return pow(sigma, exponent, modulus) == right_side

    @classmethod
    def _derive_base(cls, modulus: int) -> int:
        """Derive a deterministic nontrivial quadratic-residue base."""
        modulus_bytes = modulus.to_bytes((modulus.bit_length() + 7) // 8, "big")
        counter = 0
        while True:
            digest = hashlib.shake_256(
                b"DCAS RSA PDP public base v1\x00"
                + modulus_bytes
                + counter.to_bytes(4, "big")
            ).digest(len(modulus_bytes))
            candidate = int.from_bytes(digest, "big") % modulus
            if (
                1 < candidate < modulus - 1
                and math.gcd(candidate, modulus) == 1
            ):
                base = pow(candidate, 2, modulus)
                if base != 1:
                    return base
            counter += 1

    @classmethod
    def _hash_to_unit(cls, modulus: int, file_id: str, index: int) -> int:
        """Hash a file/sector label into the RSA multiplicative group."""
        if index < 0:
            raise ValueError("Sector index cannot be negative.")
        label = file_id.encode("utf-8") + b"\x00" + index.to_bytes(8, "big")
        modulus_bytes = modulus.to_bytes((modulus.bit_length() + 7) // 8, "big")
        counter = 0
        while True:
            digest = hashlib.shake_256(
                b"DCAS RSA PDP block base v1\x00"
                + modulus_bytes
                + label
                + counter.to_bytes(4, "big")
            ).digest(len(modulus_bytes))
            candidate = int.from_bytes(digest, "big") % modulus
            if (
                1 < candidate < modulus - 1
                and math.gcd(candidate, modulus) == 1
            ):
                return candidate
            counter += 1

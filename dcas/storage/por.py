"""Educational publicly verifiable pairing-based proof of retrievability."""

import hashlib
import os
import secrets
from typing import Any

from eth_utils import ValidationError
from py_ecc.bls.g2_primitives import (
    G1_to_pubkey,
    G2_to_signature,
    pubkey_to_G1,
    signature_to_G2,
)
from py_ecc.bls.hash_to_curve import hash_to_G1
from py_ecc.optimized_bls12_381 import G1, G2, Z1, add, curve_order, multiply, pairing

from .erasure import XorErasureCode
from .key_security import secure_new_private_file, secure_private_file


class PairingPoR:
    """Tag coded sectors with homomorphic BLS-style pairing authenticators."""

    SCHEME = "dcas-pairing-por-2of3-edu-v1"
    CURVE = "BLS12-381"
    FIELD_ELEMENT_SIZE = 31
    FIELD_ELEMENTS_PER_SECTOR = XorErasureCode.SECTOR_SIZE // FIELD_ELEMENT_SIZE
    HASH_TO_CURVE_DST = b"DCAS_PAIRING_POR_BLS12381G1_XMD:SHA-256_SSWU_RO_V1"
    MAX_CHALLENGE_SECTORS = 64

    def __init__(self, private_scalar: int):
        if not isinstance(private_scalar, int) or not 1 <= private_scalar < curve_order:
            raise ValueError("The PoR private scalar is outside the BLS12-381 field.")
        self._private_scalar = private_scalar
        self._public_key_g2 = G2_to_signature(multiply(G2, private_scalar))

    @classmethod
    def from_config(cls, network_dir: str) -> "PairingPoR":
        """Load or atomically create the persistent educational PoR key."""
        key_path = os.path.abspath(os.environ.get(
            "DCAS_POR_PRIVATE_KEY_FILE",
            os.path.join(network_dir, ".dcas-por-private-key.hex"),
        ))
        os.makedirs(os.path.dirname(key_path), exist_ok=True)

        try:
            if not os.path.exists(key_path):
                raise FileNotFoundError(key_path)
            secure_private_file(key_path)
            with open(key_path, "r", encoding="ascii") as key_file:
                encoded_key = key_file.read().strip()
        except FileNotFoundError:
            private_scalar = secrets.randbelow(curve_order - 1) + 1
            encoded_key = format(private_scalar, "x")
            try:
                descriptor = os.open(
                    key_path,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                    0o600,
                )
            except FileExistsError:
                secure_private_file(key_path)
                with open(key_path, "r", encoding="ascii") as key_file:
                    encoded_key = key_file.read().strip()
            else:
                secure_new_private_file(key_path, descriptor)
                with os.fdopen(descriptor, "w", encoding="ascii") as key_file:
                    key_file.write(encoded_key)
                    key_file.flush()
                    os.fsync(key_file.fileno())

        try:
            private_scalar = int(encoded_key, 16)
        except ValueError as error:
            raise ValueError("The configured PoR key is not valid hexadecimal.") from error
        return cls(private_scalar)

    @staticmethod
    def _encode_g1(point) -> str:
        return G1_to_pubkey(point).hex()

    @staticmethod
    def _decode_g1(encoded: str):
        if not isinstance(encoded, str) or len(encoded) != 96:
            raise ValueError("Invalid compressed BLS12-381 G1 point.")
        return pubkey_to_G1(bytes.fromhex(encoded))

    @staticmethod
    def _decode_g2(encoded: str):
        if not isinstance(encoded, str) or len(encoded) != 192:
            raise ValueError("Invalid compressed BLS12-381 G2 point.")
        return signature_to_G2(bytes.fromhex(encoded))

    @classmethod
    def _label(
        cls,
        file_id: str,
        node_id: str,
        shard_index: int,
        sector_index: int,
    ) -> bytes:
        fields = (
            cls.SCHEME.encode("ascii"),
            file_id.encode("utf-8"),
            node_id.encode("utf-8"),
            shard_index.to_bytes(4, "big"),
            sector_index.to_bytes(8, "big"),
        )
        return b"".join(len(field).to_bytes(4, "big") + field for field in fields)

    @classmethod
    def _hash_sector(
        cls,
        file_id: str,
        node_id: str,
        shard_index: int,
        sector_index: int,
    ):
        return hash_to_G1(
            cls._label(file_id, node_id, shard_index, sector_index),
            cls.HASH_TO_CURVE_DST,
            hashlib.sha256,
        )

    @classmethod
    def _sector_values(cls, sector: bytes) -> tuple[int, ...]:
        if len(sector) != XorErasureCode.SECTOR_SIZE:
            raise ValueError("PoR sectors must have the configured fixed size.")
        return tuple(
            int.from_bytes(sector[offset:offset + cls.FIELD_ELEMENT_SIZE], "big")
            for offset in range(0, len(sector), cls.FIELD_ELEMENT_SIZE)
        )

    def file_metadata(
        self,
        file_id: str,
        storage_size: int,
        shard_size: int,
    ) -> dict[str, Any]:
        """Create public parameters for a file and its 2-of-3 coded shards."""
        if (
            not file_id
            or storage_size < 0
            or shard_size < 2 * XorErasureCode.SECTOR_SIZE
            or shard_size % XorErasureCode.SECTOR_SIZE
        ):
            raise ValueError("Invalid file identifier or erasure-coded shard dimensions.")

        bases = []
        for _ in range(self.FIELD_ELEMENTS_PER_SECTOR):
            scalar = secrets.randbelow(curve_order - 1) + 1
            bases.append(self._encode_g1(multiply(G1, scalar)))

        return {
            "scheme": self.SCHEME,
            "curve": self.CURVE,
            "file_id": file_id,
            "data_shards": XorErasureCode.DATA_SHARDS,
            "total_shards": XorErasureCode.TOTAL_SHARDS,
            "sector_size": XorErasureCode.SECTOR_SIZE,
            "sector_count_per_shard": shard_size // XorErasureCode.SECTOR_SIZE,
            "field_elements_per_sector": self.FIELD_ELEMENTS_PER_SECTOR,
            "storage_size": storage_size,
            "shard_size": shard_size,
            "u_g1_hex": bases,
            "public_key_g2_hex": self._public_key_g2.hex(),
        }

    def create_tags(
        self,
        file_id: str,
        node_id: str,
        shard_index: int,
        shard_data: bytes,
        public_parameters: dict[str, Any],
    ) -> list[str]:
        """Create one node- and shard-bound authenticator per fixed sector."""
        if not node_id or not 0 <= shard_index < XorErasureCode.TOTAL_SHARDS:
            raise ValueError("PoR tags require a valid node ID and shard index.")
        sector_size = public_parameters.get("sector_size")
        encoded_bases = public_parameters.get("u_g1_hex")
        if (
            sector_size != XorErasureCode.SECTOR_SIZE
            or not isinstance(encoded_bases, list)
            or len(encoded_bases) != self.FIELD_ELEMENTS_PER_SECTOR
            or len(shard_data) % sector_size
        ):
            raise ValueError("Invalid public PoR parameters or shard data size.")

        bases = [self._decode_g1(point) for point in encoded_bases]
        tags = []
        for sector_index, offset in enumerate(range(0, len(shard_data), sector_size)):
            sector = shard_data[offset:offset + sector_size]
            tag_point = self._hash_sector(
                file_id,
                node_id,
                shard_index,
                sector_index,
            )
            for base, value in zip(bases, self._sector_values(sector)):
                tag_point = add(tag_point, multiply(base, value))
            tags.append(self._encode_g1(multiply(tag_point, self._private_scalar)))
        return tags

    @classmethod
    def aggregate_response(
        cls,
        sectors: list[tuple[str, bytes, int]],
    ) -> tuple[str, str]:
        """Aggregate stored tags and return a compact sector-linear response."""
        aggregate_tag = Z1
        aggregate_values = [0] * cls.FIELD_ELEMENTS_PER_SECTOR
        for tag_hex, sector, coefficient in sectors:
            if not 1 <= coefficient < curve_order:
                raise ValueError("Invalid PoR challenge coefficient.")
            try:
                tag_point = cls._decode_g1(tag_hex)
            except ValidationError as error:
                raise ValueError("A stored PoR tag is not a valid group point.") from error
            aggregate_tag = add(
                aggregate_tag,
                multiply(tag_point, coefficient),
            )
            for index, value in enumerate(cls._sector_values(sector)):
                aggregate_values[index] = (
                    aggregate_values[index] + coefficient * value
                ) % curve_order
        return (
            cls._encode_g1(aggregate_tag),
            "".join(f"{value:064x}" for value in aggregate_values),
        )

    @classmethod
    def verify_aggregate_proof(
        cls,
        file_id: str,
        node_id: str,
        shard_index: int,
        challenges: list[dict[str, int]],
        sigma_hex: str,
        mu_hex: str,
        public_parameters: dict[str, Any],
    ) -> bool:
        """Publicly verify a node- and shard-bound aggregate PoR proof."""
        try:
            if (
                not isinstance(public_parameters, dict)
                or public_parameters.get("scheme") != cls.SCHEME
                or public_parameters.get("curve") != cls.CURVE
                or not isinstance(file_id, str)
                or not file_id
                or public_parameters.get("file_id") != file_id
                or not isinstance(node_id, str)
                or not node_id
                or not isinstance(shard_index, int)
                or isinstance(shard_index, bool)
                or not 0 <= shard_index < XorErasureCode.TOTAL_SHARDS
                or not isinstance(challenges, list)
                or not 2 <= len(challenges) <= cls.MAX_CHALLENGE_SECTORS
                or not isinstance(mu_hex, str)
                or len(mu_hex) != 64 * cls.FIELD_ELEMENTS_PER_SECTOR
                or not isinstance(public_parameters.get("u_g1_hex"), list)
                or len(public_parameters["u_g1_hex"]) != cls.FIELD_ELEMENTS_PER_SECTOR
            ):
                return False

            mu_values = tuple(
                int(mu_hex[offset:offset + 64], 16)
                for offset in range(0, len(mu_hex), 64)
            )
            if any(not 0 <= value < curve_order for value in mu_values):
                return False

            public_key = cls._decode_g2(public_parameters["public_key_g2_hex"])
            bases = [
                cls._decode_g1(point)
                for point in public_parameters["u_g1_hex"]
            ]
            sigma = cls._decode_g1(sigma_hex)
            expected = Z1
            seen_indices = set()
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
                    or not 1 <= coefficient < curve_order
                    or index >= public_parameters["sector_count_per_shard"]
                ):
                    return False
                seen_indices.add(index)
                expected = add(
                    expected,
                    multiply(
                        cls._hash_sector(file_id, node_id, shard_index, index),
                        coefficient,
                    ),
                )

            for base, value in zip(bases, mu_values):
                expected = add(expected, multiply(base, value))

            return pairing(G2, sigma) == pairing(public_key, expected)
        except (KeyError, TypeError, ValueError, OverflowError, ValidationError):
            return False

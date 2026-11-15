"""Small educational 2-of-3 XOR erasure code for PoR storage shards."""

import math


class XorErasureCode:
    """Split bytes into two data shards and one XOR parity shard."""

    DATA_SHARDS = 2
    TOTAL_SHARDS = 3
    SECTOR_SIZE = 124
    MIN_SECTORS_PER_SHARD = 2

    @classmethod
    def encode(cls, data: bytes) -> tuple[list[bytes], int]:
        """Return three equally sized shards and their padded shard length."""
        if not isinstance(data, bytes):
            raise TypeError("Erasure coding accepts bytes only.")
        minimum_size = cls.MIN_SECTORS_PER_SHARD * cls.SECTOR_SIZE
        shard_size = max(minimum_size, math.ceil(len(data) / cls.DATA_SHARDS))
        shard_size = math.ceil(shard_size / cls.SECTOR_SIZE) * cls.SECTOR_SIZE
        padded = data.ljust(cls.DATA_SHARDS * shard_size, b"\x00")
        first = padded[:shard_size]
        second = padded[shard_size:]
        parity = bytes(left ^ right for left, right in zip(first, second))
        return [first, second, parity], shard_size

    @classmethod
    def decode(
        cls,
        shards: dict[int, bytes],
        original_size: int,
    ) -> bytes:
        """Reconstruct encrypted bytes from any two distinct valid shards."""
        if (
            not isinstance(original_size, int)
            or isinstance(original_size, bool)
            or original_size < 0
            or not isinstance(shards, dict)
            or len(shards) < cls.DATA_SHARDS
        ):
            raise ValueError("Decoding requires at least two shards and a valid size.")

        selected = list(shards.items())[:cls.DATA_SHARDS]
        indices = [index for index, _ in selected]
        shard_data = [data for _, data in selected]
        if (
            any(
                not isinstance(index, int)
                or isinstance(index, bool)
                or not 0 <= index < cls.TOTAL_SHARDS
                for index in indices
            )
            or len(set(indices)) != cls.DATA_SHARDS
            or any(not isinstance(data, bytes) for data in shard_data)
            or len(shard_data[0]) != len(shard_data[1])
            or len(shard_data[0])
            < cls.MIN_SECTORS_PER_SHARD * cls.SECTOR_SIZE
            or len(shard_data[0]) % cls.SECTOR_SIZE
            or original_size > cls.DATA_SHARDS * len(shard_data[0])
        ):
            raise ValueError("Shard indices, sizes, or original length are invalid.")

        first_index, second_index = indices
        first_data, second_data = shard_data
        if {first_index, second_index} == {0, 1}:
            data = first_data + second_data if first_index == 0 else second_data + first_data
        elif {first_index, second_index} == {0, 2}:
            recovered = bytes(left ^ right for left, right in zip(first_data, second_data))
            data_zero = first_data if first_index == 0 else second_data
            data_one = recovered
            data = data_zero + data_one
        else:
            recovered = bytes(left ^ right for left, right in zip(first_data, second_data))
            data_one = first_data if first_index == 1 else second_data
            data_zero = recovered
            data = data_zero + data_one

        return data[:original_size]

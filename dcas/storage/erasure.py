"""Small educational 2-of-3 XOR erasure code for PoR storage shards."""


class XorErasureCode:
    """Split bytes into two data shards and one XOR parity shard."""

    DATA_SHARDS = 2
    TOTAL_SHARDS = 3
    SECTOR_SIZE = 124
    MIN_SECTOR_SIZE = 1
    MAX_SECTOR_SIZE = 4096
    MIN_SECTORS_PER_SHARD = 2

    @classmethod
    def calculate_sector_size(cls, upload_size: int) -> int:
        """Choose the smallest sector that meets the minimum sectors per shard."""
        if (
            not isinstance(upload_size, int)
            or isinstance(upload_size, bool)
            or upload_size < 0
        ):
            raise ValueError("Upload size must be a non-negative integer.")

        minimum_data_capacity = cls.DATA_SHARDS * cls.MIN_SECTORS_PER_SHARD
        required_size = (
            upload_size + minimum_data_capacity - 1
        ) // minimum_data_capacity
        return min(
            cls.MAX_SECTOR_SIZE,
            max(cls.MIN_SECTOR_SIZE, required_size),
        )

    @classmethod
    def encode(
        cls,
        data: bytes,
        sector_size: int | None = None,
    ) -> tuple[list[bytes], int]:
        """Return three equally sized shards and their padded shard length."""
        if not isinstance(data, bytes):
            raise TypeError("Erasure coding accepts bytes only.")
        sector_size = (
            cls.calculate_sector_size(len(data))
            if sector_size is None
            else sector_size
        )
        if (
            not isinstance(sector_size, int)
            or isinstance(sector_size, bool)
            or not cls.MIN_SECTOR_SIZE <= sector_size <= cls.MAX_SECTOR_SIZE
        ):
            raise ValueError("Sector size is outside the supported range.")

        minimum_size = cls.MIN_SECTORS_PER_SHARD * sector_size
        shard_size = max(
            minimum_size,
            (len(data) + cls.DATA_SHARDS - 1) // cls.DATA_SHARDS,
        )
        shard_size = (
            (shard_size + sector_size - 1) // sector_size
        ) * sector_size
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
        sector_size: int | None = None,
    ) -> bytes:
        """Reconstruct encrypted bytes from any two distinct valid shards."""
        sector_size = (
            cls.calculate_sector_size(original_size)
            if sector_size is None
            else sector_size
        )
        if (
            not isinstance(original_size, int)
            or isinstance(original_size, bool)
            or original_size < 0
            or not isinstance(sector_size, int)
            or isinstance(sector_size, bool)
            or not cls.MIN_SECTOR_SIZE <= sector_size <= cls.MAX_SECTOR_SIZE
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
            < cls.MIN_SECTORS_PER_SHARD * sector_size
            or len(shard_data[0]) % sector_size
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

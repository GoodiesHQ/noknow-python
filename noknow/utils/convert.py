"""
Methods used for conversion
"""

from typing import Union


__all__ = [
    "to_bytes", "to_str", "bytes_to_int", "int_to_bytes",
]


def bytes_to_int(value: Union[bytes, bytearray]) -> int:
    return int.from_bytes(bytearray(value), byteorder="big")


def int_to_bytes(value: int) -> bytearray:
    return bytearray(value.to_bytes((value.bit_length() + 7) // 8, byteorder="big"))


def to_bytes(data, encoding="utf-8", errors="replace") -> bytes:
    if isinstance(data, (bytes, bytearray)):
        return data
    if isinstance(data, str):
        return data.encode(encoding=encoding, errors=errors)
    if isinstance(data, int):
        return int_to_bytes(data)
    return bytes(data)


def to_str(data, encoding="utf-8", errors="replace") -> str:
    if isinstance(data, str):
        return data
    if isinstance(data, bytes):
        return data.decode(encoding=encoding, errors=errors)
    return str(data)



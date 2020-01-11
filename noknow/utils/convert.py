"""
Methods used for conversion
"""

from ecpy.curves import Curve, Point
from typing import Union


__all__ = [
    "to_bytes", "to_str", "bytes_to_int", "int_to_bytes", "unpack",
]


def bytes_to_int(value: Union[bytes, bytearray, Point]) -> int:
    return int.from_bytes(to_bytes(value), byteorder="big")


def int_to_bytes(value: int) -> bytearray:
    return bytearray(value.to_bytes((value.bit_length() + 7) // 8, byteorder="big"))


def to_bytes(data, encoding="utf-8", errors="replace") -> bytes:
    if isinstance(data, (bytes, bytearray)):
        return data
    if isinstance(data, str):
        return data.encode(encoding=encoding, errors=errors)
    if isinstance(data, int):
        return int_to_bytes(data)
    if isinstance(data, Point):
        c = data.curve
        return bytes(c.encode_point(data))
    print("UNTYPED:", type(data), "\n", data)
    return bytes(data)


def to_str(data, encoding="utf-8", errors="replace") -> str:
    if isinstance(data, str):
        return data
    if isinstance(data, bytes):
        return data.decode(encoding=encoding, errors=errors)
    return str(data)


def _is_named_tuple(x):
    _type = type(x)
    bases = _type.__bases__
    if len(bases) != 1 or bases[0] != tuple:
        return False
    fields = getattr(_type, '_fields', None)
    if not isinstance(fields, tuple):
        return False
    return all(type(i)==str for i in fields)


def unpack(obj):
    if isinstance(obj, dict):
        return {key: unpack(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [unpack(value) for value in obj]
    elif _is_named_tuple(obj):
        return {key: unpack(value) for key, value in obj._asdict().items()}
    elif isinstance(obj, tuple):
        return tuple(unpack(value) for value in obj)
    else:
        return obj

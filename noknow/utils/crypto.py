from typing import Union, Generator
import codecs
import hashlib
import random

from noknow.utils import convert

from ecpy.curves import Curve
from ecpy.curves import Point
from jwt.algorithms import HMACAlgorithm
from jwt import register_algorithm

__all__ = [
    "curve_by_name", "mod", "hash_data", "hash_numeric",
]

_HASH_TYPES = {
    name: getattr(hashlib, name) for name in (
        "md5", "sha1", "sha224", "sha256", "sha512", "sha3_224",
        "sha3_256", "sha3_384", "sha3_512", "blake2b", "blake2s",
    )
}

# Register new JWT algorithms with supported hashlib algorithms
register_algorithm("HS3_224", HMACAlgorithm(hashlib.sha3_224))
register_algorithm("HS3_256", HMACAlgorithm(hashlib.sha3_256))
register_algorithm("HS3_384", HMACAlgorithm(hashlib.sha3_384))
register_algorithm("HS3_512", HMACAlgorithm(hashlib.sha3_512))
register_algorithm("HB2S", HMACAlgorithm(hashlib.blake2s))
register_algorithm("HB2B", HMACAlgorithm(hashlib.blake2b))

def curve_by_name(name: str) -> Curve:
    """
    Get curve by name, case-insensitive
    """
    valid_names = Curve.get_curve_names()
    for valid_name in valid_names:
        if valid_name.lower() == name.lower():
            return Curve.get_curve(valid_name)
    return None

def mod(a: int, b: int) -> int:
    """
    Return a mod b, account for positive/negative numbers
    """
    return (a % b + b) % b

def hash_data(*values: Union[str, bytes, bytearray, int, Point], alg="sha3_256") -> bytes:
    """
    Convert all provided values to bytes, and return the digest in bytes
    """
    if alg not in _HASH_TYPES:
        raise NotImplementedError(f"Hash algorithm '{alg}' is not supported")
    return _HASH_TYPES[alg](b"".join(map(convert.to_bytes, values))).digest()


def hash_numeric(*values: Union[str, bytes, bytearray, int, Point], alg="sha3_256") -> int:
    """
    Compute the cryptographic hash of the provided values and return the digest in integer form
    """
    return convert.bytes_to_int(hash_data(*values, alg=alg))

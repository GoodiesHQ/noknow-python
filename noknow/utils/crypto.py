from ecpy.curves import Curve
from ecpy.curves import Point
from noknow.utils import convert
from typing import Union, Generator
import hashlib
import random

__all__ = [
    "hash_numeric", "prime_gen", "get_prime", "is_prime",
]

_HASH_TYPES = {
    name: getattr(hashlib, name) for name in [
        "md5", "sha1", "sha224", "sha256", "sha512", "sha3_224", "sha3_256", "sha3_384", "sha3_512",
    ]
}


def hash_numeric(*values: Union[str, bytes, bytearray, int, Point], alg="sha3_256") -> int:
    """
    Compute the cryptographic hash of the provided values and return the digest in integer form
    """
    if alg not in _HASH_TYPES:
        raise NotImplementedError(f"Hash algorithm '{alg}' is not supported")
    return int(_HASH_TYPES[alg](b"".join(map(convert.to_bytes, values))).hexdigest(), 16)


def is_prime(num: int, confidence: int):
    """
    The fastest primality check that I could implement in pure python.
    gmpy2 primality checking is about 4x faster.
    """
    def miller_rabin(d: int, n: int) -> bool:
        a = 2 + random.randint(1, n - 4)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return True
        while d != n - 1:
            x = x ** 2 % n
            d <<= 1
            if x == 1:
                return False
            if x == n - 1:
                return True
        return False

    def fermat(n) -> bool:
        if n == 2:
            return True
        if not n & 1:
            return False
        return pow(2, n - 1, n) == 1

    if not fermat(num):
        return False

    if num == 1 or num == 4:
        return False
    if num == 2:
        return True
    d = num - 1
    while d & 1 == 0:
        d >>= 1
    return all(miller_rabin(d, num) for _ in range(confidence))


def prime_gen(bits: int, confidence: int, safe: bool = False) -> Generator:
    """
    Create a generator of random prime numbers of size `bits` and begin generating prime numbers
    """
    while True:
        n = (1 << (bits - 1)) | random.getrandbits(bits) | 1    # create an odd number of size `bits`
        # while not gmpy2.is_bpsw_prp(n):
        while not is_prime(n, confidence):
            n += 2  # next odd number
        if not safe or is_prime((n - 1) >> 1, confidence):
            yield n


def get_prime(bits: int=256, confidence: int = 15, safe: bool = False) -> int:
    """
    Generate a single prime number of size `bits`
    """
    return next(prime_gen(bits, confidence, safe=safe))


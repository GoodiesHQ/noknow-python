from ecpy.curves import Curve, Point
from noknow.utils import convert
from typing import Union, Generator
import gmpy2
import hashlib
import random

__all__ = [
    "hash_numeric", "prime_gen", "get_prime", "get_random_point",
]


def hash_numeric(value: Union[str, bytes, bytearray], hash_type=hashlib.sha256) -> int:
    return int(hash_type(convert.to_bytes(value)).hexdigest(), 16)


def prime_gen(bits: int) -> Generator:
    """
    Create a generator of random prime numbers of size `bits` and begin generating prime numbers
    """
    while True:
        # create an odd number of size `bits`
        n = random.getrandbits(bits) | 1
        while not gmpy2.is_bpsw_prp(n):
            # next odd number
            n += 2
        yield n


def get_prime(bits: int=256) -> int:
    """
    Generate a single prime number of size `bits`
    """
    return next(prime_gen(bits))


def get_random_point(curve: Curve, d_bits: int = 256, prime: bool = False) -> Point:
    """
    Generate a random point on the provided curve. Determine if scalar `d` should be prime or not
    """
    return curve.generator * (prime_gen(d_bits) if prime else random.getrandbits(d_bits))

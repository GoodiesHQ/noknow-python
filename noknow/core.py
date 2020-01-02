"""
noknow/core.py: Provides the interface for using Zero-Knowledge Proofs within applications
"""
from ecpy.curves import Curve
from ecpy.keys import ECPrivateKey
from noknow.utils import convert, crypto
from random import SystemRandom
from typing import Union, NamedTuple


random = SystemRandom()


__all__ = [
    "ZKParameters", "ZKSignature", "ZKChallenge", "ZKProof",
]


class ZKParameters(NamedTuple):
    """
    The parameters required for creating the Zero-Knowledge Cryptosystem:

    curve: the name of the standardized elliptic curve to use for cyclic group point generation
    d: the large prime number (256 bits recommended) used to generate an elliptic curve point and as a modulo

    TODO: implement curve parameter as a set of ECC parameters instead of ECPy names
    """
    curve: str
    d: int


class ZKSignature(NamedTuple):
    """
    A cryptographic signature distinct from a hash that can be used to validate the same input in the future:

    params: the reference ZK parameters
    signature: the calculated signature derived from the ZK curve and user secret
    """
    params: ZKParameters
    signature: int


class ZKChallenge(NamedTuple):
    """
    A cryptographic challenge created by a user based on the signature (derived from the password)

    params: the reference ZK parameters
    token: the server-provided random tokens
    c: the hash derived from the signature, a random point, and the random token
    z: a value derived from the random point and password hash
    """
    params: ZKParameters
    token: int
    c: int
    z: int


class ZKProof:
    def __init__(self, params: ZKParameters):
        """
        Initialize the ZKProof
        """
        self._curve: Curve = Curve.get_curve(params.curve)
        if self._curve is None:
            raise NotImplementedError(f"Invalid Curve '{params.curve}'")
        self._ecc: ECPrivateKey = ECPrivateKey(params.d, self._curve)
        self._g0: int = convert.point_to_int(self._ecc.get_public_key().W)

    @staticmethod
    def random_token(bits: int = 256):
        """
        Generate a random token of `bits` random bits
        """
        return random.getrandbits(bits)

    @staticmethod
    def new(bits: int = 256, curve_name = "secp256k1"):
        """
        Create a new ZKProof using the elliptic curve `curve` and a `bits`-sized scalar
        """
        if Curve.get_curve(curve_name) is None:
            raise NotImplementedError(f"The curve '{curve_name}' is not implemented")
        return ZKProof(
            ZKParameters(
                curve=curve_name,
                d=crypto.get_prime(bits),
            )
        )

    @property
    def params(self) -> ZKParameters:
        return ZKParameters(
            curve=self._curve.name,
            d=self._ecc.d,
        )

    def create_signature(self, secret: Union[bytes, str, bytearray]):
        signature = pow(self._g0, crypto.hash_numeric(secret), self._ecc.d)
        return ZKSignature(params=self.params, signature=signature)

    def create_challenge(self, secret: Union[bytes, str, bytearray], token: int):
        secret_hash: int = crypto.hash_numeric(secret)
        y: int = pow(self._g0, secret_hash, self._ecc.d)
        r: int = convert.point_to_int(crypto.get_random_point(self._curve))
        t: int = pow(self._g0, r, self._ecc.d)
        payload = b''.join(map(convert.int_to_bytes, (y, t, token)))
        c = crypto.hash_numeric(payload)
        z = r - (secret_hash * c)
        return ZKChallenge(params=self.params, token=token, c=c, z=z)

    def prove_challenge(self, challenge: ZKChallenge, signature: ZKSignature, token: int):
        t = pow(signature.signature, challenge.c, self._ecc.d) * pow(self._g0, challenge.z, self._ecc.d) % self._ecc.d
        payload = b''.join(map(convert.int_to_bytes, (signature.signature, t, token)))
        return challenge.token == token and challenge.c == crypto.hash_numeric(payload)


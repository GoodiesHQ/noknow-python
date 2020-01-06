"""
noknow/core.py: Provides the interface for using Zero-Knowledge Proofs within applications
"""
from base64 import b64encode, b64decode
from noknow.utils import convert, crypto
from random import SystemRandom
from typing import Union, NamedTuple
import json


random = SystemRandom()


__all__ = [
    "ZKParameters", "ZKSignature", "ZKChallenge", "ZKProof", "ZK",
]


class ZKParameters(NamedTuple):
    """
    The parameters required for creating the Zero-Knowledge Cryptosystem
    """
    alg: str    # the hash algorithm to use
    d: int      # large prime modulo to use for calculating the signature
    g: int      # large number N to use as a base number
    s: int      # random salt used during password hashing


class ZKSignature(NamedTuple):
    """
    A cryptographic signature distinct from a hash that can be used to validate the same input in the future:

    params: the reference ZK parameters
    signature: the calculated signature derived from the ZK curve and user secret
    """
    params: ZKParameters
    data: str
    signature: int


class ZKData(NamedTuple):
    params: ZKParameters
    data: str
    c: int
    z: int


class ZKProof(NamedTuple):
    params: ZKParameters
    proof: int


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


class ZK:
    def __init__(self, params: ZKParameters):
        """
        Initialize the ZKProof
        """
        self._bits = (8 * round(params.d.bit_length() / 8))
        self._mask = (1 << self._bits) - 1
        self._params = params

    @property
    def bits(self) -> int:
        return self._bits

    def hash(self, *values):
        return crypto.hash_numeric(*values, self.params.s, alg=self.params.alg) & self._mask

    @property
    def params(self) -> ZKParameters:
        return self._params

    def random_token(self):
        """
        Generate a random token of `bits` random bits
        """
        return random.getrandbits(self.bits)

    @staticmethod
    def load(parameters):
        return ZK(ZKParameters.load(parameters))

    @staticmethod
    def new(bits: int = 256, hash_alg: str = "sha256", prime_confidence: int = 10):
        """
        Create a new ZKProof using the elliptic curve `curve` and a `bits`-sized scalar
        """
        return ZK(
            ZKParameters(
                d=crypto.get_prime(bits, confidence=prime_confidence),  # Large prime modulo
                g=random.getrandbits(bits),                             # Random large base number
                s=random.getrandbits(bits),                             # Random salt value
                alg=hash_alg,                                           # Hash algorithm
            )
        )

    def create_proof(self, secret: Union[bytes, str, bytearray]):
        proof = pow(self.params.g, self.hash(secret), self.params.d)
        return ZKProof(params=self.params, proof=proof)

    def create_signature(self, data: str, secret: Union[bytes, str, bytearray]):
        signature = pow(self.params.g, self.hash(secret, data), self.params.d)
        return ZKSignature(params=self.params, data=data, signature=signature)

    def sign(self, data, signature: ZKSignature, secret: Union[bytes, str, bytearray]):
        if signature.signature != pow(self.params.g, self.hash(secret, signature.data), self.params.d):
            raise Exception("Invalid Password")
        if signature.params != self.params:
            raise ValueError("The signature parameters must match the ZK state")
        c, z = self._prove(secret, hashed_args=(signature.data,), args=(data, signature.data))
        return ZKData(params=self.params, data=data, c=c, z=z)

    @staticmethod
    def verify(data: ZKData, signature: ZKSignature):
        if data.params != signature.params:
            raise ValueError("The signature and data parameters do not match")
        zk = ZK(data.params)
        t = pow(signature.signature, data.c, zk.params.d) \
             * pow(zk.params.g, data.z, zk.params.d) % zk.params.d
        return data.c == zk.hash(signature.signature, t, data.data, signature.data)

    def _prove(self, secret: Union[bytes, str, bytearray], hashed_args=(), args=()):
        h: int = self.hash(secret, *hashed_args)
        y: int = pow(self.params.g, h, self.params.d)
        r: int = random.getrandbits(self.bits*2) | 1 << (self.bits * 2)
        t: int = pow(self.params.g, r, self.params.d)
        c: int = self.hash(y, t, *args)
        z: int = r - (c * h)
        return c, z

    def create_challenge(self, secret: Union[bytes, str, bytearray], token: int):
        c, z = self._prove(secret, args=(token,))
        return ZKChallenge(params=self.params, token=token, c=c, z=z)

    def prove_challenge(self, challenge: ZKChallenge, proof: ZKProof, token: int):
        t = pow(proof.proof, challenge.c, self.params.d) \
            * pow(self.params.g, challenge.z, self.params.d) % self.params.d
        payload = b''.join(map(convert.to_bytes, (proof.proof, t, token)))
        return challenge.token == token and challenge.c == self.hash(payload)

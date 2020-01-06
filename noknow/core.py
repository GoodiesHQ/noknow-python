"""
noknow/core.py: Provides the interface for using Zero-Knowledge Proofs within applications
"""
from noknow.utils import convert, crypto
from random import SystemRandom
from typing import Union, NamedTuple


random = SystemRandom()


__all__ = [
    "ZKParameters", "ZKSignature", "ZKChallenge", "ZKProof",
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
    signature: int      # calculate signature:
    # h = Hash(secret | salt)
    # signature = (g^h mod d)


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
    def new(bits: int = 256, hash_alg: str = "sha256", prime_confidence: int = 10):
        """
        Create a new ZKProof using the elliptic curve `curve` and a `bits`-sized scalar
        """
        return ZKProof(
            ZKParameters(
                d=crypto.get_prime(bits, confidence=prime_confidence),  # Large prime modulo
                g=random.getrandbits(bits),                             # Random large base number
                s=random.getrandbits(bits),                             # Random salt value
                alg=hash_alg,                                           # Hash algorithm
            )
        )

    def create_signature(self, secret: Union[bytes, str, bytearray]):
        signature = pow(self.params.g, self.hash(secret), self.params.d)
        return ZKSignature(params=self.params, signature=signature)

    def create_challenge(self, secret: Union[bytes, str, bytearray], token: int):
        h: int = self.hash(secret)                                          # Salted password hash value
        y: int = pow(self.params.g, h, self.params.d)                       # Calculate signature `Y`
        r: int = random.getrandbits(self.bits * 2) | 1 << (self.bits * 2)   # Random large number
        t: int = pow(self.params.g, r, self.params.d)                       # Calculate g^r mod d
        c: int = self.hash(b''.join(map(convert.int_to_bytes, (y, t, token))))
        z: int = (r - (h * c))                                              # offset from r, negative numbers OK
        return ZKChallenge(params=self.params, token=token, c=c, z=z)

    def prove_challenge(self, challenge: ZKChallenge, signature: ZKSignature, token: int):
        t = pow(signature.signature, challenge.c, self.params.d) \
            * pow(self.params.g, challenge.z, self.params.d) % self.params.d
        payload = b''.join(map(convert.int_to_bytes, (signature.signature, t, token)))
        return challenge.token == token and challenge.c == self.hash(payload)


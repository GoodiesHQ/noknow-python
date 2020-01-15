"""
noknow/core.py: Provides the interface for using Zero-Knowledge Proofs within applications
"""

from base64 import b64encode, b64decode
from ecpy.curves import Curve, Point
from noknow.utils.convert import to_bytes, to_str, bytes_to_int, unpack
from noknow.utils.crypto import hash_numeric
from random import SystemRandom
from typing import NamedTuple, Union
import json

random = SystemRandom()


__all__ = [
    "ZKParameters", "ZKSignature", "ZKProof", "ZKData", "ZK",
]


def _dump(obj):
    return to_str(b64encode(to_bytes(json.dumps(unpack(obj), separators=(",", ":")))))


class ZKParameters(NamedTuple):
    """
    Parameters used to construct a ZK proof state using an curve and a random salt
    """
    alg: str                    # Hashing algorithm name
    curve: str                  # Standard Elliptic Curve name to use
    s: int                      # Random salt for the state

    @staticmethod
    def load(data):
        return ZKParameters(**json.loads(to_str(b64decode(to_bytes(data)))))
    dump = _dump


class ZKSignature(NamedTuple):
    """
    Cryptographic public signature used to verify future messages
    """
    params: ZKParameters        # Reference ZK Parameters
    signature: int              # The public key derived from your original secret

    @staticmethod
    def load(data):
        info = json.loads(to_str(b64decode(to_bytes(data))))
        return ZKSignature(params=ZKParameters(**info.pop("params")), **info)
    dump = _dump


class ZKProof(NamedTuple):
    """
    Cryptographic proof that can be verified to ensure the private key used to create
    the proof is the same key used to generate the signature
    """
    params: ZKParameters        # Reference ZK Parameters
    c: int                      # The hash of the signed data and random point, R
    m: int                      # The offset from the secret `r` (`R=r*g`) from c * Hash(secret)

    @staticmethod
    def load(data):
        info = json.loads(to_str(b64decode(to_bytes(data))))
        return ZKProof(params=ZKParameters(**info.pop("params")), **info)

    dump = _dump


class ZKData(NamedTuple):
    """
    Wrapper to contain data and a signed proof using the data
    """
    data: str
    proof: ZKProof

    @staticmethod
    def load(data, separator="\n"):
        data, proof = data.rsplit(separator, 1)
        return ZKData(data=data, proof=ZKProof.load(proof))

    def dump(self, separator="\n"):
        return self.data + separator + self.proof.dump()


class ZK:
    """
    Implementation of Schnorr's protocol to create and validate proofs
    """
    def __init__(self, parameters: ZKParameters):
        """
        Initialize the curve with the given parameters
        """
        self._curve = Curve.get_curve(parameters.curve)
        if not self._curve:
            raise ValueError("The curve '{}' is invalid".format(parameters.curve))
        self._params = parameters
        self._bits = self._curve.field.bit_length()
        self._mask = (1 << self._bits) - 1

    @property
    def params(self):
        return self._params

    @property
    def bits(self):
        return self._bits

    @property
    def mask(self):
        return self._mask

    @property
    def salt(self):
        return self._params.s

    @salt.setter
    def salt(self, value):
        self._params.s = value

    @property
    def curve(self):
        return self._curve

    @staticmethod
    def new(curve_name: str = "secp256k1", hash_alg: str = "sha256", bits: int =  None):
        curve = Curve.get_curve(curve_name)
        if curve is None:
            raise ValueError("Invalid Curve")
        return ZK(ZKParameters(alg=hash_alg, curve=curve_name, s=random.getrandbits(bits or curve.field.bit_length())))

    def _to_point(self, value: Union[int, bytes, ZKSignature]):
        return self.curve.decode_point(to_bytes(value.signature if isinstance(value, ZKSignature) else value))

    def token(self) -> int:
        return random.getrandbits(self.bits)

    def hash(self, *values):
        return hash_numeric(*[v for v in values if v is not None], self.salt, alg=self.params.alg) & self._mask

    def create_signature(self, secret: Union[str, bytes]) -> ZKSignature:
        return ZKSignature(
            params=self.params,
            signature=bytes_to_int(self.hash(secret) * self.curve.generator),
        )

    def create_proof(self, secret: Union[str, bytes], data: Union[int, str, bytes]=None) -> ZKProof:
        key = self.hash(secret)                     # Create private signing key
        r = self.token()                            # Generate random bits
        R = r * self.curve.generator                # Random point whose discrete log, `r`, is know
        c = self.hash(data, R)                      # Hash the data and random point
        m = (r + (c * key)) % self.curve.order      # Send offset between discrete log of R from c*x
        return ZKProof(params=self.params, c=c, m=m)

    def sign(self, secret: Union[str, bytes], data: Union[int, str, bytes]) -> ZKData:
        data = to_str(data)
        return ZKData(
            data=data,
            proof=self.create_proof(secret, data),
        )

    @staticmethod
    def signature_is_valid(signature: Union[str, ZKSignature]) -> bool:
        try:
            sig = signature if isinstance(signature, ZKSignature) else ZKSignature.load(signature)
            zk = ZK(sig.params)
            return zk.curve.is_on_curve(zk._to_point(signature))
        except:
            return False

    def verify(self, challenge: Union[ZKData, ZKProof], signature: ZKSignature, data: Union[str, bytes, int]=""):
        data, proof = (data, challenge) if isinstance(challenge, ZKProof) else (challenge.data, challenge.proof)
        c, m = proof.c, proof.m
        return c == self.hash(data, (m * self.curve.generator) - (self._to_point(signature) * c))

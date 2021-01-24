"""
Dataclasses and JSON interaction for objects used throughout NoKnow
"""

from dataclasses import dataclass, field
from dataclasses_json import dataclass_json, config
from noknow.utils.convert import b64e, b64d


__all__ = [
    "dump", "ZKParameters", "ZKSignature", "ZKProof", "ZKData"
]


def dump(dc):
    """
    Dump a JSON Dataclass to compressed JSON
    """
    return dc.to_json(separators=(",", ":"))


@dataclass_json
@dataclass
class ZKParameters:
    """
    Parameters used to construct a ZK instance using a hashing scheme,
    a standard elliptic curve name, and a random salt
    """
    alg: str                    # Hashing algorithm name
    curve: str                  # Standard Elliptic Curve name to use
    salt: bytes = field(        # Random salt for the state
        metadata=config(encoder=b64e, decoder=b64d),
    )                


@dataclass_json
@dataclass
class ZKSignature:
    """
    Cryptographic public signature used to verify future messages
    """
    params: ZKParameters        # Reference ZK Parameters
    signature: bytes = field(   # The public key derived from your original secret
        metadata=config(encoder=b64e, decoder=b64d),
    )


@dataclass_json
@dataclass
class ZKProof:
    """
    Cryptographic proof that can be verified to ensure the private key used to create
    the proof is the same key used to generate the signature
    """
    params: ZKParameters        # Reference ZK Parameters
    c: bytes = field(           # The hash of the signed data and random point, R
        metadata=config(encoder=b64e, decoder=b64d),
    )
    m: bytes = field(           # The offset from the secret `r` (`R=r*g`) from c * Hash(secret)
        metadata=config(encoder=b64e, decoder=b64d),
    )


@dataclass_json
@dataclass
class ZKData:
    """
    Wrapper to contain data and a signed proof using the data
    """
    data: bytes = field(        # Signed data
        metadata=config(encoder=b64e, decoder=b64d),
    )
    proof: ZKProof

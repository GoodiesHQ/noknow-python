<h1 align="center">NoKnow</h1>
<div align="center">
  <strong>Zero-Knowledge Proof implementation in pure python</strong>
</div>
<br />
<div align="center">
  <img src="http://badges.github.io/stability-badges/dist/experimental.svg" alt="Experimental" />
</div>
<div align="center">
  <sub>
    Built with ❤︎ by <a href="https://www.linkedin.com/in/austinarcher/">Austin Archer</a> :)
  </sub>
</div>
<br />



## Table of Contents
- [Credits](#credits)
- [Purpose](#purpose)
- [How it Works](#how-it-works)
- [API](#api)
- [Install](#install)
- [Example Usage](#example-usage)


## Credits
This is a slightly modified implementation of Schnorr's protocol that utilizes a state seed. The proofs used are rather complex in nature, but I will do my best to explain its functionality, but please refer to the research papers on which this implementation is based as it does a far more complete job with explanation than I.

[Elliptic Curve Based Zero Knowledge Proofs and Their
Applicability on Resource Constrained Devices](https://arxiv.org/pdf/1107.1626.pdf) by Ioannis Chatzigiannakis, Apostolos Pyrgelis, Paul G. Spirakis, and Yannis C. Stamatiou


## Purpose
Zero-Knowledge Proofs are undoubtedly the future of authentication security within various IT and application development industrires. The ability to verify the veracity of a claim (ex: proving that you know a secret password), without divulging any information about the claim itself (ex: passwords or hashes), allows for servers to guarantee secure AAA operations (authentication, authorization, and accounting) without exposing private information. `NoKnow` is an implementation of a [Non-Interactive Zero-Knowledge Proof](https://en.wikipedia.org/wiki/Non-interactive_zero-knowledge_proof) protocol specifically designed for verifying text-based secrets, which is ideal for passwords or other authentication means.


## How It Works
TODO: explain how it works

## API

The `noknow` Python API is meant to be simple and intuitive:

### Core Components

#### noknow.core.ZKParameters:
The parameters used to initialize the Zero-Knowledge crypto system.

    class ZKParameters(NamedTuple):
        """
        Parameters used to construct a ZK proof state using an curve and a random salt
        """
        alg: str                    # Hashing algorithm name
        curve: str                  # Standard Elliptic Curve name to use
        s: int                      # Random salt for the state

#### noknow.core.ZKSignature:
A crytographic, zero-knowledge signature that can be used to verify future messages.

    class ZKSignature(NamedTuple):
        """
        Cryptographic public signature used to verify future messages
        """
        params: ZKParameters        # Reference ZK Parameters
        signature: int              # The public key derived from your original secret


#### noknow.core.ZKProof:
A cryptograpgic proof that can be verified against a signature.

    class ZKProof(NamedTuple):
        """
        Non-deterministic cryptographic zero-knowledge proof that can be verified to ensure the
        private key used to create the proof is the same key used to generate the signature
        """
        params: ZKParameters        # Reference ZK Parameters
        c: int                      # The hash of the signed data and random point, R
        m: int                      # The offset from the secret `r` (`R=r*g`) from c * Hash(secret)


#### noknow.core.ZKData
Wrapper that contains a proof and the necessary data to validate the proof against a signature.

    class ZKData(NamedTuple):
        """
        Wrapper to contain data and a signed proof using the data
        """
        data: Union[str, bytes, int]
        proof: ZKProof

### ZK
 
The `ZK` class is the central component of `NoKnow` and its state (defined by `ZKParameters`) should be inherently known to both the Client (Prover) and Server (Verifier).

#### instance methods
<table>
  <tr>
    <th width="10%">Method</th>
    <th width="40%">Parameters</th>
    <th width="15%">Role</th>
    <th width="35%">Purpose</th>
  </tr>
  <tr>
    <td><code>create_signature</code></td>
    <td><code>secret: Union[str, bytes]</code></td>
    <td>Prover</td>
    <td>Create a cryptographic signature derived from the value <code>secret</code> to be generated during initial registration and stored for subsequent challenge proofs</td>
  </tr>
  <tr>
    <td><code>sign</code></td>
    <td><code>secret: Union[str, bytes]</code> <br /> <code>data: Union[str, bytes, int]</code></td>
    <td>Prover</td>
    <td>Create a <code>ZKData</code> object using the <code>secret</code> and any additional data
  </tr>
  <tr>
    <td><code>verify</code></td>
    <td><code>challenge: Union[ZKData, ZKProof]</code> <br /> <code>signature: ZKSignature</code> <br /> <code>data: Optional[Union[str, bytes, int]]</code></td>
    <td>Verifier</td>
    <td>Verify the user-provided <code>challenge</code> against the stored <code>signature</code> and randomly generated <code>token</code> to verify the validity of the challenge</td>
  </tr>
</table>

## Install

`NoKnow` is available from PyPi! Simply run:

    pip install -U noknow

## Example Usage
TODO: Include example usage

#### Example 1

    """
    Extremely simple example of NoKnow ZK Proof implementation
    """
    from getpass import getpass
    from noknow.core import ZK, ZKSignature, ZKParameters, ZKData, ZKProof
    from queue import Queue
    from threading import Thread


    def client(iq: Queue, oq: Queue):
        client_zk = ZK.new(curve_name="secp256k1", hash_alg="sha3_256")

        # Create signature and send to server
        signature = client_zk.create_signature(getpass("Enter Password: "))
        oq.put(signature.dump())

        # Receive the token from the server
        token = iq.get()

        # Create a proof that signs the provided token and sends to server
        proof = client_zk.sign(getpass("Enter Password Again: "), token).dump()

        # Send the token and proof to the server
        oq.put(proof)

        # Wait for server response!
        print("Success!" if iq.get() else "Failure!")


    def server(iq: Queue, oq: Queue):
        # Set up server component
        server_password = "SecretServerPassword"
        server_zk = ZK.new(curve_name="secp384r1", hash_alg="sha3_512")
        server_signature: ZKSignature = server_zk.create_signature("SecureServerPassword")

        # Load the received signature from the Client
        sig = iq.get()
        client_signature = ZKSignature.load(sig)
        client_zk = ZK(client_signature.params)

        # Create a signed token and send to the client
        token = server_zk.sign("SecureServerPassword", client_zk.token())
        oq.put(token.dump(separator=":"))

        # Get the token from the client
        proof = ZKData.load(iq.get())
        token = ZKData.load(proof.data, ":")

        # In this example, the server signs the token so it can be sure it has not been modified
        if not server_zk.verify(token, server_signature):
            oq.put(False)
        else:
            oq.put(client_zk.verify(proof, client_signature, data=token))


    def main():
        q1, q2 = Queue(), Queue()
        threads = [
            Thread(target=client, args=(q1, q2)),
            Thread(target=server, args=(q2, q1)),
        ]
        for func in [Thread.start, Thread.join]:
            for thread in threads:
                func(thread)


    if __name__ == "__main__":
        main()

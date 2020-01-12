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
The fundamental problem on which this protocol is based is the Elliptic Curve Discrete Logarithm Problem.

<!--
\\
\texttt{Very Easy: } \text{Given a point, } G \text{, and a scalar, } n \text{, find } P \text { such that } P = nG
\\
\texttt{Very Hard: } \text{Given a point, } P \text{, and a scalar, } n \text{, find } G \text { such that } P = nG
\\
\textbf{ZK Parameters:}
\\ \text{Elliptic Curve (ex: } y^2 = x^3 + ax + b \text{ although other forms are allowed):}
\\ \hspace*{25} a \hspace*{25} \text{a parameter for curve, } C
\\ \hspace*{25} b \hspace*{25} \text{b parameter for curve, } C
\\ \hspace*{25} n \hspace*{25} \text{large prime number that determines the elliptic curve field, } F_n
\\ \hspace*{25} G \hspace*{22} \text{A generator point of the elliptic curve } G \in C/F_n
\\ H(data) \hspace*{15} \text{Hash function converted to integer representation (ex: sha256 )}
\\salt \hspace{37} \text{A random salt used for the hash function, unique to each user}
-->

<img src="https://latex.codecogs.com/gif.latex?%5Cdpi%7B150%7D%20%5Cbg_white%20%5Csmall%20%5C%5C%20%5Ctexttt%7BVery%20Easy%3A%20%7D%20%5Ctext%7BGiven%20a%20point%2C%20%7D%20G%20%5Ctext%7B%2C%20and%20a%20scalar%2C%20%7D%20n%20%5Ctext%7B%2C%20find%20%7D%20P%20%5Ctext%20%7B%20such%20that%20%7D%20P%20%3D%20nG%20%5C%5C%20%5Ctexttt%7BVery%20Hard%3A%20%7D%20%5Ctext%7BGiven%20a%20point%2C%20%7D%20P%20%5Ctext%7B%2C%20and%20a%20scalar%2C%20%7D%20n%20%5Ctext%7B%2C%20find%20%7D%20G%20%5Ctext%20%7B%20such%20that%20%7D%20P%20%3D%20nG%20%5C%5C%20%5Ctextbf%7BZK%20Parameters%3A%7D%20%5C%5C%20%5Ctext%7BElliptic%20Curve%20%28ex%3A%20%7D%20y%5E2%20%3D%20x%5E3%20&plus;%20ax%20&plus;%20b%20%5Ctext%7B%20although%20other%20forms%20are%20allowed%29%3A%7D%20%5C%5C%20%5Chspace*%7B25%7D%20a%20%5Chspace*%7B25%7D%20%5Ctext%7Ba%20parameter%20for%20curve%2C%20%7D%20C%20%5C%5C%20%5Chspace*%7B25%7D%20b%20%5Chspace*%7B25%7D%20%5Ctext%7Bb%20parameter%20for%20curve%2C%20%7D%20C%20%5C%5C%20%5Chspace*%7B25%7D%20n%20%5Chspace*%7B25%7D%20%5Ctext%7Blarge%20prime%20number%20that%20determines%20the%20elliptic%20curve%20field%2C%20%7D%20F_n%20%5C%5C%20%5Chspace*%7B25%7D%20G%20%5Chspace*%7B22%7D%20%5Ctext%7BA%20generator%20point%20of%20the%20elliptic%20curve%20%7D%20G%20%5Cin%20C/F_n%20%5C%5C%20H%28data%29%20%5Chspace*%7B15%7D%20%5Ctext%7BHash%20function%20converted%20to%20integer%20representation%20%28ex%3A%20sha256%20%29%7D%20%5C%5Csalt%20%5Chspace%7B37%7D%20%5Ctext%7BA%20random%20salt%20used%20for%20the%20hash%20function%2C%20unique%20to%20each%20user%7D" />

With this principle in mind, knowing a private variable, `n`, is all that is required to produce the proper point. The first thing to do is generate a signature. This signature is produced by multiplying a known value, such as the hashed result of a password, by the elliptic curve's generator point:

<!--
\\ secret= "SuperSecretPassword"
\\ k = H(secret || salt) \mod n
\\ S = k * G
-->

<img src="https://latex.codecogs.com/gif.latex?%5Cdpi%7B150%7D%20%5Cbg_white%20%5Csmall%20%5C%5C%20secret%3D%20%22SuperSecretPassword%22%20%5C%5C%20k%20%3D%20H%28secret%20%7C%7C%20salt%29%20%5Cmod%20n%20%5C%5C%20S%20%3D%20k%20*%20G" />

Now that we have produced this signature, `S`, which can be represented as an `(x, y)` pair, we can publish this signature publicly so that subsequent messages can be proven to have been produced by the same key that produced the signature, while ensuring that the signature itself reveals nothing about the data used to produce it.

One of my main goals for developing this library was producing a secure and effective method of Zero-Knowledge authentication. Because messages can be verified against a signature, one method of authentication is for the verifier (server) to produce a random message (called a token, `t`), and send it to the user with a request for them to produce a proof with the provided token that can be verified against their public signature. This ensures that a single proof cannot be re-used by a malicious actor in future authentication attempts. Any proof generated will always be valid against a particular signature, but checking the value of the signed data against what the server expects will ensure, with a large enough random token, it is extremely unlikely that there will ever be a request that provides the same random token. Additionally, another method could be to use a JWT with a short expiration, e.g. 10 seconds, whos validity is checked before processing the proof. However, in this example, I will choose a static random token, `"MyRandomToken"`.

<!--
\\\texttt{Verifier:}
\\ t := random\_token()  \text{ // a randomized token value}
\\ \text{*send } t \text{ to prover*}
\\
\\ \texttt{Prover:}
\\ k := H(secret || salt) \mod n \text{ such that } k \in F_n
\\ r := \text{ random } r \text{ such that } r \in F_n
\\ R := r \cdotp G
\\ c := H(t||R||salt)
\\ m := r + c*k
\\ (c, m) \text{ is the proof!}
\\
\\ \texttt{Verifier:}
\\ M := m \cdotp G
\\ C := c \cdotp S
\\ \text{Valid if }H(t||M-C||salt) == c
-->

<img src="https://latex.codecogs.com/gif.latex?%5Cdpi%7B150%7D%20%5Cbg_white%20%5Csmall%20%5C%5C%5Ctexttt%7BVerifier%3A%7D%20%5C%5C%20t%20%3A%3D%20random%5C_token%28%29%20%5Ctext%7B%20//%20a%20randomized%20token%20value%7D%20%5C%5C%20%5Ctext%7B*send%20%7D%20t%20%5Ctext%7B%20to%20prover*%7D%20%5C%5C%20%5C%5C%20%5Ctexttt%7BProver%3A%7D%20%5C%5C%20k%20%3A%3D%20H%28secret%20%7C%7C%20salt%29%20%5Cmod%20n%20%5Ctext%7B%20such%20that%20%7D%20k%20%5Cin%20F_n%20%5C%5C%20r%20%3A%3D%20%5Ctext%7B%20random%20%7D%20r%20%5Ctext%7B%20such%20that%20%7D%20r%20%5Cin%20F_n%20%5C%5C%20R%20%3A%3D%20r%20%5Ccdotp%20G%20%5C%5C%20c%20%3A%3D%20H%28t%7C%7CR%7C%7Csalt%29%20%5C%5C%20m%20%3A%3D%20r%20&plus;%20c*k%20%5C%5C%20%28c%2C%20m%29%20%5Ctext%7B%20is%20the%20proof%21%7D%20%5C%5C%20%5C%5C%20%5Ctexttt%7BVerifier%3A%7D%20%5C%5C%20M%20%3A%3D%20m%20%5Ccdotp%20G%20%5C%5C%20C%20%3A%3D%20c%20%5Ccdotp%20S%20%5C%5C%20%5Ctext%7BValid%20if%20%7DH%2ji98t%7C%7CM-C%7C%7Csalt%29%20%3D%3D%20c" />

Ultimately, this comes down to the fact that some of these values cancel out arithmetically during the proof, so they are simply not needed by the prover. First, let's look at some basic principles of point multiplication with elliptic curves:

<!--
\\a \cdot G + b \cdot G == (a+b) \cdot G
\\a \cdot G - b \cdot G == (a-b) \cdot G
-->

<img src="https://latex.codecogs.com/gif.latex?%5Cdpi%7B150%7D%20%5Cbg_white%20%5Csmall%20%5C%5Ca%20%5Ccdot%20G%20&plus;%20b%20%5Ccdot%20G%20%3D%3D%20%28a&plus;b%29%20%5Ccdot%20G%20%5C%5Ca%20%5Ccdot%20G%20-%20b%20%5Ccdot%20G%20%3D%3D%20%28a-b%29%20%5Ccdot%20G" />

During the validation project, what is ultimately checked is a hash, namely:

<!--
H(t||R||salt) == H(t||((m \cdotp G)-(c \cdotp S))||salt)
-->

<img src="https://latex.codecogs.com/gif.latex?%5Cdpi%7B150%7D%20%5Cbg_white%20%5Csmall%20H%28t%7C%7CR%7C%7Csalt%29%20%3D%3D%20H%28t%7C%7C%28%28m%20%5Ccdotp%20G%29-%28c%20%5Ccdotp%20S%29%29%7C%7Csalt%29" />

Since both `t` and `salt` are public pieces of information, what is actually important is the specific point that is generated. What we need to do is prove:
<!--
\\\hspace*{1} \text{ P: } \hspace*{2} R == M - c \cdot S
\\\text{P1: } R == (m \cdotp G)-(c \cdotp S) \hspace*{113} \text{Substitute } M
\\\text{P2: } r \cdot G == (m \cdotp G)-(c \cdotp S) \hspace*{100} \text{Substitute } R
\\\text{P3: } r \cdot G == ((r + ck) \cdot G) - (c \cdot S) \hspace*{61} \text{ Substitute } m
\\\text{P4: } r \cdot G == ((r + ck) \cdot G) - (c \cdot (k \cdot G)) \hspace*{37} \text{ Substitute } S
\\\text{P5: } r \cdot G == ((r \cdot G) + ((ck) \cdot G)) - ((ck) \cdot G)) \hspace*{10} \text{Distributive property}
\\\text{P6: } r \cdot G == (r \cdot G) + ((ck \cdot G) - (ck \cdot G)) \hspace{31} \text{Associative property}
\\\hspace*{1} \text{ C:  } \hspace*{1} r \cdot G == r \cdot G
\\ \textbf{QED}
-->
<img src="https://latex.codecogs.com/gif.latex?%5Cdpi%7B150%7D%20%5Cbg_white%20%5Csmall%20%5C%5C%5Chspace*%7B1%7D%20%5Ctext%7B%20P%3A%20%7D%20%5Chspace*%7B2%7D%20R%20%3D%3D%20M%20-%20c%20%5Ccdot%20S%20%5C%5C%5Ctext%7BP1%3A%20%7D%20R%20%3D%3D%20%28m%20%5Ccdotp%20G%29-%28c%20%5Ccdotp%20S%29%20%5Chspace*%7B113%7D%20%5Ctext%7BSubstitute%20%7D%20M%20%5C%5C%5Ctext%7BP2%3A%20%7D%20r%20%5Ccdot%20G%20%3D%3D%20%28m%20%5Ccdotp%20G%29-%28c%20%5Ccdotp%20S%29%20%5Chspace*%7B100%7D%20%5Ctext%7BSubstitute%20%7D%20R%20%5C%5C%5Ctext%7BP3%3A%20%7D%20r%20%5Ccdot%20G%20%3D%3D%20%28%28r%20&plus;%20ck%29%20%5Ccdot%20G%29%20-%20%28c%20%5Ccdot%20S%29%20%5Chspace*%7B61%7D%20%5Ctext%7B%20Substitute%20%7D%20m%20%5C%5C%5Ctext%7BP4%3A%20%7D%20r%20%5Ccdot%20G%20%3D%3D%20%28%28r%20&plus;%20ck%29%20%5Ccdot%20G%29%20-%20%28c%20%5Ccdot%20%28k%20%5Ccdot%20G%29%29%20%5Chspace*%7B37%7D%20%5Ctext%7B%20Substitute%20%7D%20S%20%5C%5C%5Ctext%7BP5%3A%20%7D%20r%20%5Ccdot%20G%20%3D%3D%20%28%28r%20%5Ccdot%20G%29%20&plus;%20%28%28ck%29%20%5Ccdot%20G%29%29%20-%20%28%28ck%29%20%5Ccdot%20G%29%29%20%5Chspace*%7B10%7D%20%5Ctext%7BDistributive%20property%7D%20%5C%5C%5Ctext%7BP6%3A%20%7D%20r%20%5Ccdot%20G%20%3D%3D%20%28r%20%5Ccdot%20G%29%20&plus;%20%28%28ck%20%5Ccdot%20G%29%20-%20%28ck%20%5Ccdot%20G%29%29%20%5Chspace%7B31%7D%20%5Ctext%7BAssociative%20property%7D%20%5C%5C%5Chspace*%7B1%7D%20%5Ctext%7B%20C%3A%20%7D%20%5Chspace*%7B1%7D%20r%20%5Ccdot%20G%20%3D%3D%20r%20%5Ccdot%20G%20%5C%5C%20%5Ctextbf%7BQED%7D" />

There we go! We have demonstrated that the point R can be demonstrated to be able to be derived from `c` and `M` without knowing the discriminators of `S` (`k`), `M` (`m`), or `R` (`r`). And since knowledge of all of these are required to create the proof, but their values are not transmitted during proving, the zero knowledge proof is complete.=---=9

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
    <th width="9%">Method</th>
    <th width="46%">Parameters</th>
    <th width="10%">Role</th>
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

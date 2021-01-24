from pprint import pprint
from queue import Queue
from threading import Thread
import json
import random
    
from noknow import ZK, ZKData, ZKParameters, ZKProof, ZKSignature, utils


def show(x, title=None):
    if title:
        print(title)
    try:
        pprint(json.loads(utils.to_str(x)))
    except:
        pprint(utils.to_str(x))
    print()

def client(parameters: ZKParameters, qi: Queue, qo: Queue):
    password = b"Secr3tP@ssw0rd!"

    # Step 1) User Registration
    zk = ZK(parameters)
    sig = zk.create_signature(password)
    qo.put(sig)
    show(sig, "Client Signature:")

    # Step 3) User signs the provided token
    token = qi.get()
    qi.task_done()
    show(token, "Challenge Token:")

    data = zk.sign(password, token)
    qo.put(data)
    show(data, "Client Login Data:")
    
    if qi.get():
        print("Login Successful!")
    qi.task_done()

def server(parameters: ZKParameters, qi: Queue, qo: Queue):
    jwt_secret = utils.b64d(b"nKxAQ50yOKormsKWLSG0XR+uh0CudkKsDZ7A3kyqOO8=")

    zk = ZK(parameters, jwt_secret)
    client_sig = qi.get()
    qi.task_done()

    # Step 2) Server generates a token usable for authentication
    qo.put(zk.jwt(client_sig))

    # Step 4) Server validates the integrity of the signed JWT and Schnorr signature
    login_data = qi.get()
    qi.task_done()
    x = zk.login(login_data)
    qo.put(x)

def main():
    curves = [
        "secp256r1", "secp256k1", "secp224k1", "secp224r1",
        "secp192k1", "secp192r1", "secp160k1", "secp160r1", "secp160r2",
        "Brainpool-p256r1", "Brainpool-p256t1", "Brainpool-p224r1", 
        "Brainpool-p224t1", "Brainpool-p192r1", "Brainpool-p192t1",
        "Brainpool-p160r1", "Brainpool-p160t1", "NIST-P256", "NIST-P224",
        "NIST-P192", "Ed25519", 
        # "Curve25519",  # does not work
    ]

    hash_algs = [
        "blake2s", "blake2b", "md5", "sha3_256", "sha3_512",
    ]

    jwt_algs = [
        "HS3_256", "HS3_512", "HB2S", "HB2B",
    ]

    zk = ZK.new(
        curve_name=random.choice(curves),
        hash_alg=random.choice(hash_algs),
        salt_size=16,
    )
    parameters = zk.params
    q1, q2 = Queue(), Queue()

    threads = [
        Thread(target=client, args=(parameters, q1, q2)),
        Thread(target=server, args=(parameters, q2, q1)),
    ]

    for func in (Thread.start, Thread.join):
        for thread in threads:
            func(thread)
    q1.join()
    q2.join()

if __name__ == "__main__":
    main()
import secrets
import sys
from ecpy.keys   import ECPublicKey, ECPrivateKey
from ecpy.curves import Curve
from typing import Tuple
import blake3 as b3

def generate_proof(curve: Curve, prk: ECPrivateKey, PK: ECPublicKey, id: int, gid: int, data=b"sample"):
    n = curve.order
    G = curve.generator

    # if (len(sys.argv)>1):
    #     message = str(sys.argv[1])

    M = data
    
    v = ECPrivateKey(secrets.randbits(256), curve)  # choose v randomly
    V = v.get_public_key()                                                 # V = G x v

    c = generate_challenge(G, V, PK, id, gid, M)

    r = (v.d - (prk.d * c)) % n                     # proof

    return (PK, id, gid, M, V, r)

def generate_proof_fog(curve, prk, PK, data=b"sample"):
    n = curve.order
    G = curve.generator

    if (len(sys.argv)>1):
        message = str(sys.argv[1])

    M = data

    v = ECPrivateKey(secrets.randbits(256), curve)  # choose v randomly
    V = v.get_public_key()                          # V = G x v

    c = generate_challenge_fog(G, V, PK, M)

    r = (v.d - (prk.d * c)) % n                     # proof

    return (PK, M, V, r)

def generate_challenge(G, V, PK, id, gid, M):
    hasher = b3.blake3((G.x).to_bytes(32)              # 256 bits
            + (G.y).to_bytes(32)
            + (V.W.x).to_bytes(32)
            + (V.W.y).to_bytes(32)
            + (PK.W.x).to_bytes(32)
            + (PK.W.y).to_bytes(32)
            + (id).to_bytes(32)
            + (gid).to_bytes(32)
            + M)

    return int.from_bytes(hasher.digest())

def generate_challenge_fog(G, V, PK, M):
    hasher = b3.blake3((G.x).to_bytes(32)              # 256 bits
            + (G.y).to_bytes(32)
            + (V.W.x).to_bytes(32)
            + (V.W.y).to_bytes(32)
            + (PK.W.x).to_bytes(32)
            + (PK.W.y).to_bytes(32)
            + M)

    return int.from_bytes(hasher.digest())

def verify_proof(proof: Tuple[ECPublicKey, int, int, bytes, ECPublicKey, int], G) -> bool:
  (PK, id, gid, M, V, r) = proof
  c = generate_challenge(G, V, PK, id, gid, M)

  v1 = V.W
  v2 = (G * r) + (PK.W * c)
  
  return v1==v2

def verify_proof_fog(proof: Tuple[ECPublicKey, bytes, ECPublicKey, int], G) -> bool:
  (PK, M, V, r) = proof
  c = generate_challenge_fog(G, V, PK, M)

  v1 = V.W
  v2 = (G * r) + (PK.W * c)
  
  return v1==v2
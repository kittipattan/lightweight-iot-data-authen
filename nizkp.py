import secrets
import sys
from hashlib     import sha256
from ecpy.keys   import ECPublicKey, ECPrivateKey
from ecpy.curves import Curve

def generate_proof(curve, prk, PK, id=12345678, gid=1, data="sample"):
    n = curve.order
    G = curve.generator

    message = data # IoT data

    if (len(sys.argv)>1):
        message = str(sys.argv[1])

    M = message.encode()

    v = ECPrivateKey(secrets.randbits(256), curve)  # choose v randomly
    V = v.get_public_key()                          # V = G x v

    c = generate_challenge(G, V, PK, id, gid, M)

    r = (v.d - (prk.d * c)) % n                     # proof

    return (PK, id, gid, M, V, r)

def generate_challenge(G, V, PK, id, gid, M):
    hasher = sha256((G.x).to_bytes(32)              # 256 bits
            + (G.y).to_bytes(32)
            + (V.W.x).to_bytes(32)
            + (V.W.y).to_bytes(32)
            + (PK.W.x).to_bytes(32)
            + (PK.W.y).to_bytes(32)
            + (id).to_bytes(32)
            + (gid).to_bytes(32)
            + M)

    return int.from_bytes(hasher.digest())

def verify_proof(proof, G):
  (PK, id, gid, M, V, r) = proof
  c = generate_challenge(G, V, PK, id, gid, M)

  v1 = V.W
  v2 = (G * r) + (PK.W * c)
  
  return v1==v2
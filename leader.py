from hashlib     import sha256
from ecpy.keys   import ECPublicKey, ECPrivateKey
from ecpy.curves import Curve
from nizkp import generate_challenge, generate_proof, verify_proof
from measurement import measure_computation_cost

###### (1) Group Authentication ######

# ---- (1.1) Mutual authen with fog using NIZKP and digital certificate

def verify_fog(fog_data, G):
  return verify_proof(fog_data, G)

def generate_proof_to_fog(curve, prkL, PKL, id, gid, data="none"):
  return generate_proof(curve, prkL, PKL, id, gid, data)

# ---- (1.2) Key exchange

def derive_SSK(prkL, PKF):
  return prkL * PKF

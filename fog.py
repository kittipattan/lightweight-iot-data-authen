import utils
import base64
import secrets
import measurement
from aes256 import AESCipher
from ecpy.curves import Curve
from ecpy.keys   import ECPublicKey, ECPrivateKey
from nizkp import generate_challenge, generate_proof, verify_proof

###### (1) Group Authentication ######

# ---- (1.1) Mutual authen with leader using NIZKP and digital certificate

def verify_leader(leader_data, G):
  return verify_proof(leader_data, G)

def generate_proof_to_leader(curve, prkF, PKF, id, gid, data="none"):
  return generate_proof(curve, prkF, PKF, id, gid, data)

# ---- (1.2) Key exchange

def derive_SSK(prkF, PKL):
  return prkF * PKL
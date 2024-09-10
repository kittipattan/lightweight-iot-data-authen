import secrets
import hashlib

# random 128-bit
def generateSecret128Bits():
  return secrets.randbits(128)

def hash_sha256(s):
  return hashlib.sha256(s.encode()).digest()

def generate_AES_key():
  return secrets.token_bytes(32)


import utils

### (1) token generation
def generate_token(GID, ID, S, message):
  return utils.hash_sha256(GID + ID + S + message)
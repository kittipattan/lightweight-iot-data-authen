import secrets
import sys
import leader
import fog
import iot
import hashlib
import utils.utils as utils
import random
import string
from utils.aes256 import AESCipher
from utils.measurement import measure_computation_cost
from utils.nizkp import generate_proof, verify_proof
from base64 import b64encode, b64decode
from hashlib     import sha256
from ecpy.keys   import ECPublicKey, ECPrivateKey
from ecpy.curves import Curve
from ecpy.ecdsa  import ECDSA

# Public data
curve_name = "secp256k1"
curve = Curve.get_curve(curve_name) # known to Fog already
G = curve.generator
n = curve.order

# Leader IIoT public key
prk = ECPrivateKey(secrets.randbits(256), curve) # private key PrKL
PK = prk.get_public_key()                        # PK

# IoT Data
data = 'sample'
b_data = str.encode(data)
id = 12345678
gid = 12345678

# Generated Secret by Fog
s = str(secrets.randbits(128))

# IoT token
token = iot.generate_token(str(gid), str(id), s, data)

# Fog AES key
fog_key = secrets.token_bytes(32)

# Encrypted secret
secret_cipher = AESCipher(fog_key)    # key to encrypt secret
ciphered_s = secret_cipher.encrypt(s) # store in database

# Encrypted AES key
hashed_gid = utils.hash_sha256(str(gid)) # encrypt key with hash value of GID
key_cipher = AESCipher(hashed_gid)
encoded_fog_key = b64encode(fog_key).decode("utf-8")
ciphered_fog_key = key_cipher.encrypt(encoded_fog_key) # -> to partition

# Partition AES_cipher
index_to_split = round(len(ciphered_fog_key)*0.8)
partial_ciphered_key_leader = ciphered_fog_key[:index_to_split] # send to leader
partial_ciphered_key_fog = ciphered_fog_key[index_to_split:]    # store in database

# IoT Proof
proof = generate_proof(curve, prk, PK, id, gid, data) # send to Fog

# IoT ECDSA
cv     = Curve.get_curve(curve_name)
pv_key = ECPrivateKey(secrets.randbits(256), cv)
pu_key = pv_key.get_public_key()
signer = ECDSA()
sig    = signer.sign(b_data,pv_key)

def testZKP():
    # Leader data
    data = "ideal"
    id = 12345678
    gid = 12345678

    # Leader ------------------------------------------------------------------------------
    prkL = ECPrivateKey(secrets.randbits(256), curve) # private key PrKL
    PKL = prkL.get_public_key()                        # PK
    (PKL, id, gid, M, V, r) = leader.generate_proof_to_fog(curve, prkL, PKL, id, gid, data) # send to Fog

    # Fog ---------------------------------------------------------------------------------
    is_verified = fog.verify_leader((PKL, id, gid, M, V, r), G)

    print("\n--------------------------------Case 1: Ideal--------------------------------\n")

    print(f"Leader IoT Private key (prkL) = {prkL.d}")
    print(f"Leader IoT Public key (PKL) = ({PKL.W}, {PKL.W})")

    print(f"""Data sent to Fog 
        PK: {PKL.W}
        id: {id}
        gid: {gid}
        Message: {M}
        V: {V.W}
        r: {r}""")

    if (is_verified):  
        print("\nVerified!")
    else:
        print("\nNot verified")

    # MiTM attack : IoT impersonation
    prk_modified = ECPrivateKey(secrets.randbits(256), curve)
    PK_modified = prk_modified.get_public_key()

    id_modified = 87654321
    gid_modified = 30
    data_modified = "case 2"

    (PK_modified, id_modified, gid_modified, M, V_modified, r_modified) = leader.generate_proof_to_fog(curve,
                                                                                                       prk_modified, 
                                                                                                       PK_modified, 
                                                                                                       id_modified, 
                                                                                                       gid_modified, 
                                                                                                       data_modified)   # MiTM send to Fog

    is_verified = fog.verify_leader((PK_modified, id_modified, gid_modified, M, V_modified, r_modified), G)

    print("\n------------------Case 2: MiTM without digital certificate------------------\n")

    print(f"MiTM Private key (prk_modified) = {prk_modified.d}")
    print(f"MiTM Public key (PK_modified) = ({PK_modified.W})")

    print(f"""Data sent to Fog 
        PK: {PK_modified.W}
        id: {id_modified}
        gid: {gid_modified}
        Message: {M}
        V: {V.W}
        r: {r_modified}""")

    if (is_verified):  
        print("\nVerified!")
    else:
        print("\nNot verified")

    # prevent by using digital certificate
    # still use the public key (PK) registered in the certificate
    prk_modified = ECPrivateKey(secrets.randbits(256), curve)
    PK_modified = PKL    # still need to use PK in order to be the same with the one in certificate

    id_modified = id
    gid_modified = gid
    data_modified = "case 3"

    (PK_modified, id_modified, gid_modified, M, V_modified, r_modified) = leader.generate_proof_to_fog(curve, 
                                                                                                       prk_modified, 
                                                                                                       PK_modified, 
                                                                                                       id_modified, 
                                                                                                       gid_modified, 
                                                                                                       data_modified)   # MiTM send to Fog
    
    is_verified = fog.verify_leader((PK_modified, id_modified, gid_modified, M, V_modified, r_modified), G)

    print("\n-------------------Case 3: MiTM with digital certificate--------------------\n")

    print(f"MiTM Private key (prk_modified) = {prk_modified.d}")
    print(f"Cert Public key (PK) = ({PK_modified.W})")

    print(f"""Data sent to Fog 
        PK: {PK_modified.W}
        id: {id_modified}
        gid: {gid_modified}
        Message: {M}
        V: {V.W}
        r: {r_modified}""")

    if (is_verified):  
        print("Verified!")
    else:
        print("Not verified")

    return

def iot_task_1():
    proof = generate_proof(curve, prk, PK, id, gid, data) # send to Fog
    return

def iot_task_2():
    cv     = Curve.get_curve(curve_name)
    signer = ECDSA()
    sig    = signer.sign(b_data, prk)
    return

def iot_task_3():
    iot.generate_token(str(gid), str(id), s, data)
    return

def fog_task_1():
    # NIZKP
    verify_proof(proof, G)
    return

def fog_task_2():
    # ECDSA
    signer.verify(b_data, sig, pu_key)
    return

def fog_task_3():
    # our scheme (token, id, gid, message)
    try:
        ciphered_fog_key = partial_ciphered_key_leader + partial_ciphered_key_fog

        # Encrypted AES key
        hashed_gid = utils.hash_sha256(str(gid)) # encrypt key with hash value of GID
        key_cipher = AESCipher(hashed_gid)
        encoded_fog_key = key_cipher.decrypt(ciphered_fog_key) # to decrypt the ciphered secret
        fog_key = b64decode(encoded_fog_key.encode("utf-8"))

        secret_cipher = AESCipher(fog_key)
        s = secret_cipher.decrypt(ciphered_s)

        concat_data = str(gid) + str(id) + s + data

        if (token == utils.hash_sha256(concat_data)):
            pass

    except Exception as e:
        pass

    return

def main():
    global data, b_data
    for n in [100*1000]:
        data = ''.join(random.choices(string.ascii_letters, k=n))
        b_data = str.encode(data)

        print(f"-------------{n} characters---------------\n")
        # Leader task
        # measure_computation_cost(iot_task_2, "IoT tasks using ECDSA", 1000)
        # measure_computation_cost(iot_task_1, "IoT task using NIZKP", 1000)
        # measure_computation_cost(fog_task_2, "Fog task using ECDSA", 1000)
        # measure_computation_cost(fog_task_1, "Fog task using NIZKP", 1000)

        # IoT task
        # measure_computation_cost(iot_task_2, "IoT tasks using ECDSA", 1000)
        # measure_computation_cost(iot_task_3, "IoT task using our scheme", 1000)
        # measure_computation_cost(fog_task_2, "Fog task using ECDSA", 1000)
        # measure_computation_cost(fog_task_3, "Fog task using our scheme", 1000)

    #testZKP()

    return

if __name__ == "__main__":
    main()
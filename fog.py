import secrets
from aes256 import AESCipher
from ecpy.curves import Curve
from ecpy.keys import ECPublicKey, ECPrivateKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nizkp import generate_proof_fog, verify_proof
from hashlib import sha256
from typing import List
from iot import IoT
from leader import Leader
import json
import os
from dotenv import load_dotenv
from azure.storage.blob import BlobServiceClient
import json


###### (1) Group Authentication ######

# ---- (1.1) Mutual authen with leader using NIZKP and digital certificate

# def verify_leader(leader_data, G):
#   return verify_proof(leader_data, G)

# def generate_proof_to_leader(curve, prkF, PKF, id, gid, data="none"):
#   return generate_proof(curve, prkF, PKF, id, gid, data)

# # ---- (1.2) Key exchange

# def derive_SSK(prkF, PKL):
#   return prkF * PKL


class Fog:
    def __init__(self):
        # NIZKP
        self.curve = Curve.get_curve("secp256k1")
        self.G = self.curve.generator
        self.n = self.curve.order
        self.prk = ECPrivateKey(secrets.randbits(256), self.curve) # private key PrKF
        self.PK = self.prk.get_public_key()                        # PKF
        self.ssk = None

        # Local Database
        self.iotAuthDB = {}         # store gid, enc_secret, partial_ciphered_key (20%)
        self.__iotPartialKeyDB = {}   # store id, partial_ciphered_key (that's been sent to IoT id)
        self.iotTempData = {}       # id : (iot_gid, iot_data, iot_partialKey, iot_token)
        self.aggregatedData = {}   # gid : [iot_data, iot_data, ...]
    
    # NIZKP
    def genProof(self, message="fog data"):
        return generate_proof_fog(self.curve, self.prk, self.PK, message)

    def verifyProof(self, leader_proof):
        return verify_proof(leader_proof, self.G)
      
    def deriveSSK(self, sharing_PK, salt):
        x = (self.prk.d * sharing_PK.W).x.to_bytes(32)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt, 
            info=None
        )
        self.ssk = hkdf.derive(x)

    # Our scheme
    def genSec(self, group: List[IoT]):
        if not isinstance(group[0], Leader):
            raise Exception("Secret generation error")
        gid = group[0].gid

        # Generate Secret by Fog
        secret = secrets.token_bytes(16)  # to send to IoT devices

        # Fog AES key
        fog_key = secrets.token_bytes(32)

        # Encrypted secret
        enc_secret = AESCipher(fog_key).encrypt(secret.hex())

        # Encrypted secret for PUF-based authentication and key exchange
        # sk_puf.append(secrets.token_bytes(32))
        # secret_cipher_puf.append(AESCipher(sk_puf[i]))
        # ciphered_s_puf.append(secret_cipher_puf[i].encrypt(s[i]))  # sent to each device in the group

        # Encrypted Fog AES key
        hashed_gid = sha256(gid.to_bytes(16)).digest()
        ciphered_fog_key = AESCipher(hashed_gid).encrypt(fog_key.hex())  
            # encrypt key with hash value of GID -> to partition

        # Partition AES_cipher (8 for IoTs : 2 for storing in Fog database)
        index_to_split = round(len(ciphered_fog_key) * 0.8)
        partial_ciphered_key = ciphered_fog_key[:index_to_split]
        split_ciphered_keys: List[bytes] = []

        # Store in database
        self.iotAuthDB[gid] = (enc_secret, ciphered_fog_key[index_to_split:])

        for i, device in enumerate(group):
            start = round((i * len(partial_ciphered_key)) / len(group))
            end = round(((i + 1) * len(partial_ciphered_key)) / len(group))

            self.__iotPartialKeyDB[device.id] = partial_ciphered_key[start:end]
            split_ciphered_keys.append(partial_ciphered_key[start:end])

        return (secret, split_ciphered_keys)  # send to Leader via secure channel

    def sendSecToLeader(self, group: List[IoT]):
        (secret, ciphered_keys) = self.genSec(group)
        ciphered_keys = list(map(lambda ck : ck.hex(), ciphered_keys))
        # print(f"ciphered_keys: {ciphered_keys}")
        json_cks = json.dumps(ciphered_keys)
        enc_packet = AESCipher(self.ssk).encrypt(f"{secret.hex()}||||{json_cks}")
        return enc_packet
    
    def recvData(self, iot_packet):
        (iot_id, iot_gid, iot_data, iot_partialKey, iot_token) = iot_packet
        
        if not (iot_id in self.__iotPartialKeyDB):
            assert Exception(f"IoT id {iot_id} is invalid")
        
        if not (iot_gid in self.iotAuthDB):
            assert Exception(f"IoT with gid {iot_gid} is invalid")
            
        if (iot_partialKey != self.__iotPartialKeyDB[iot_id]):
            assert Exception(f"IoT partial ciphered key is invalid")
        
        # Temporary store IoT partial ciphered key and wait to be 100% full
        self.iotTempData[iot_id] = (iot_gid, iot_data, iot_partialKey, iot_token)
        
    def verifyToken(self, group: List[IoT]):
        iot_gid = group[0].gid
        
        ciphered_key: bytes = b''
        for iot in group:
            ciphered_key += self.iotTempData[iot.id][2]
        ciphered_key += self.iotAuthDB[iot_gid][1]

        # Token verification
        for iot in group:
            # Encrypted AES key
            hashed_gid = sha256(iot.gid.to_bytes(16)).digest() # encrypt key with hash value of GID
            str_fog_key = AESCipher(hashed_gid).decrypt(ciphered_key) # to decrypt the ciphered secret
            fog_key = bytes.fromhex(str_fog_key)

            str_secret = AESCipher(fog_key).decrypt(self.iotAuthDB[iot.gid][0])
            secret = bytes.fromhex(str_secret)
            
            # print(f"    secret: {secret}")

            (iot_gid, iot_data, iot_partialKey, iot_token) = self.iotTempData[iot.id]
            iot_data = f"{iot_gid}{iot.id}{iot_data}{iot_partialKey}{secret}"
            iot_token_fog = sha256(iot_data.encode()).digest()
            
            if (iot_token != iot_token_fog):
                assert Exception(f"     Data Authentication failed: IoT {iot.id} Token invalid")
                
            try:
                self.aggregatedData[iot.gid].append(iot.data)
            except KeyError:
                self.aggregatedData[iot.gid] = [iot.data]
                
            del self.iotTempData[iot.id]
    
    def uploadToCloud(self, fog_nodes, devices_per_node, fog_id, gid):
        aggregated_data = {"fog_node_id": fog_id, "aggregated_data": self.aggregatedData[gid]}
        
        try:
            load_dotenv()
            
            # initialize a connection to Azure Blob Storage
            connect_str = os.getenv("AZURE_API")   # to add connection
            # blob_service_client = BlobServiceClient.from_connection_string(connect_str)
            # container_name = "iiot-data-authentication-to-cloud"
            # blob_name = f"our_scheme/fog_no_{fog_nodes}/device_no_{devices_per_node}/aggregated_data_{gid}.json"
            
            # convert aggregated data to JSON
            data = json.dumps(aggregated_data)
            print(f"    {data}")
            
            # upload data
            # blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
            # blob_client.upload_blob(data, overwrite=True)
            # print(f"Uploaded aggregated data of fog node {gid[fog_node_index]} to Azure Blob Storage.")
        
        except Exception as e:
            # print(f"Error uploading data for fog node {gid[fog_node_index]}: {e}")
            pass
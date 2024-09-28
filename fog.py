from utils.aes256 import AESGCMCipher, AESCBCCipher
from ecpy.curves import Curve
from ecpy.keys import ECPublicKey, ECPrivateKey
from utils.nizkp import generate_proof_fog, verify_proof
from typing import List, Tuple
from iot_rasppi import IoTPi
from leader_rasppi import LeaderPi
import json
import os
import secrets
from dotenv import load_dotenv
from azure.storage.blob import BlobServiceClient
import json
import numpy as np
import blake3 as b3
import time
import struct
from threading import Thread

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
        self.curve = Curve.get_curve("Curve25519")
        self.G = self.curve.generator
        self.n = self.curve.order
        self.prk = ECPrivateKey(secrets.randbits(256), self.curve)  # private key PrKF
        self.PK = self.prk.get_public_key()  # PKF
        self.ssk = None

        # Local Database
        self.iotAuthDB = {}  # store gid, enc_secret, partial_ciphered_key (20%)
        self.__iotPartialKeyDB = (
            {}
        )  # store id, partial_ciphered_key (that's been sent to IoT id)
        self.iotTempData = {}  # id : (iot_gid, iot_data, iot_partialKey, iot_token)
        self.aggregatedData = {}  # gid : [iot_data, iot_data, ...]

    # PHASE 1: System initialization    
    def deriveDeviceKey(
        self,
        device_crps: List[Tuple[int, np.ndarray, bytes]],
        group: List[IoTPi]
    ):
        # Retrieve CRP for Leader and IIoT device from Local Server via secure channel
        leader = group[0]
        leader_id = device_crps[0][0]
        leader_challenge = device_crps[0][1]
        leader_response = device_crps[0][2]
        group_key = os.urandom(32)
        
        for device_crp, device in zip(device_crps, group):
            device_id = device_crp[0]
            device_challenge = device_crp[1]
            device_response = device_crp[2]

            # Generate a key for a pair of leader and device
            pair_key = os.urandom(32)

            # Generate nonces
            n_key = os.urandom(32)
            n_gcm = os.urandom(12)

            # Derive session key for devices
            leader_key = b3.blake3((leader_response + leader_id.to_bytes(4) + n_key)).digest()
            device_key = b3.blake3((device_response + device_id.to_bytes(4) + n_key)).digest()

            # Get the current timestamp
            timestamp = time.time()

            # Encrypt keys for devices
            enc_keys_leader = AESGCMCipher(leader_key).encrypt(
                n_gcm,
                (pair_key + group_key),
                (
                    leader_challenge.tobytes()
                    + device_id.to_bytes(4)
                    + n_key
                    + struct.pack("d", timestamp)
                    + n_gcm
                ),
            )

            enc_keys_device = AESGCMCipher(device_key).encrypt(
                n_gcm,
                (pair_key + group_key),
                (
                    device_challenge.tobytes()
                    + leader_id.to_bytes(4)
                    + n_key
                    + struct.pack("d", timestamp)
                    + n_gcm
                ),
            )

            leader_pkt = (
                leader_challenge,
                device_id,
                n_key,
                timestamp,
                n_gcm,
                enc_keys_leader,
            )
            
            device_pkt = (
                device_challenge,
                leader_id,
                n_key,
                timestamp,
                n_gcm,
                enc_keys_device,
            )
            
            leader.recvKeys(leader_pkt)
            device.recvKeys(device_pkt)

    # PHASE 2: Key Exchange
    # IoT devices only

    # PHASE 3: Group Authentication
    # NIZKP
    def genProof(self, message=b"fog data"):
        return generate_proof_fog(self.curve, self.prk, self.PK, message)

    def verifyProof(self, leader_proof):
        return verify_proof(leader_proof, self.G)

    # Secure Communication Establishment
    def deriveSSK(self, sharing_PK, salt):
        x = (self.curve.mul_point(self.prk.d, sharing_PK.W)).x.to_bytes(32)
        self.ssk = b3.blake3(
            (x + salt),
            derive_key_context="LightPUF SSK Derivation 2024-09-26 21:58:05 derive SSK between Leader and Fog"
        ).digest()

    # PHASE 4: Data Authentication and Integrity Verification
    def genSec(self, gk_pkt: Tuple[bytes, float, bytes], group: List[IoTPi]):
        if not isinstance(group[0], LeaderPi):
            raise Exception("Secret generation error")
        gid = group[0].gid

        # 1. Secret Generation
        # Receive group key from Leader
        enc_group_key = gk_pkt[0]
        leader_timestamp = gk_pkt[1]
        leader_n_gcm = gk_pkt[2]

        # Validate timestamp
        if abs(time.time() - leader_timestamp) >= 60:
            raise Exception("Timestamp is too old or too far in the future")

        # Decrypt group key
        group_key = AESGCMCipher(self.ssk).decrypt(
            leader_n_gcm,
            enc_group_key,
            (struct.pack("d", leader_timestamp) + leader_n_gcm)
        )
        
        group_secret = os.urandom(32)
        # group_secret = b'\x0cg\x1dcm\x86p\xfbo\xa5-x\x9d9g\xfe,G\xd5\xbe\x85\xef\xafsY6\x9a\x7f\xfb\x91\x1f\xd2'
        aes_key = os.urandom(32)
        # aes_key = b'M\x84\x179\xf8/\xb4\xb5w!\xec\xf5v\xc6\xbd\xd1\xd3\x05s\xbc\x18T\xda\xaeI\xb8\xa1H5Ir\x07'
        enc_group_secret_database = AESCBCCipher(aes_key).encrypt(group_secret)
        enc_group_secret_device = AESCBCCipher(group_key).encrypt(group_secret)
        enc_aes_key = AESCBCCipher(b3.blake3(gid.to_bytes(4)).digest()).encrypt(aes_key)
        timestamp = time.time()

        # 2. AES Key Encryption and Key Splitting
        # Partition AES_cipher (8 for IoTs : 2 for storing in Fog database)
        index_to_split = round(len(enc_aes_key) * 0.8)
        partial_enc_aes_key = enc_aes_key[:index_to_split]
        messages: List[bytes] = []

        # Store in database
        self.iotAuthDB[gid] = (enc_group_secret_database, enc_aes_key[index_to_split:])

        for i, device in enumerate(group):
            start = round((i * len(partial_enc_aes_key)) / len(group))
            end = round(((i + 1) * len(partial_enc_aes_key)) / len(group))

            # DX
            dx = partial_enc_aes_key[start:end]

            # Fog stores H(DX) in own database
            self.__iotPartialKeyDB[device.id] = b3.blake3(dx).digest()

            # MAC
            device_mac = b3.blake3(
                (device.id.to_bytes(4) + enc_group_secret_device + dx + struct.pack("d", timestamp)),
                key=group_key,
            ).digest()

            messages.append(
                (device.id, enc_group_secret_device, dx, timestamp, device_mac)
            )

        # n_gcm = os.urandom(12)
        # enc_messages = AESGCMCipher(self.ssk).encrypt(
        #     n_gcm, pickle.dumps(messages), (struct.pack("d", timestamp) + n_gcm)
        # )

        return messages

    # def sendSecToLeader(self, group: List[IoT]):
    #     (secret, ciphered_keys) = self.genSec(group)
    #     ciphered_keys = list(map(lambda ck: ck.hex(), ciphered_keys))
    #     # print(f"ciphered_keys: {ciphered_keys}")
    #     json_cks = json.dumps(ciphered_keys)
    #     enc_packet = AESCipher(self.ssk).encrypt(f"{secret.hex()}||||{json_cks}")
    #     return enc_packet

    def recvData(self, iot_packet):
        (iot_gid, iot_id, iot_data, iot_partialKey, iot_token) = iot_packet

        if not (iot_gid in self.iotAuthDB):
            assert Exception(f"IoT with gid {iot_gid} is invalid")

        if not (iot_id in self.__iotPartialKeyDB):
            assert Exception(f"IoT id {iot_id} is invalid")

        if b3.blake3(iot_partialKey).digest() != self.__iotPartialKeyDB[iot_id]:
            assert Exception(f"IoT partial ciphered key is invalid")

        # Temporary store IoT partial ciphered key and wait to be 100% full
        self.iotTempData[iot_id] = (iot_gid, iot_data, iot_partialKey, iot_token)

    def verifyToken(self, group: List[IoTPi]):
        iot_gid = group[0].gid

        enc_aes_key: bytes = b""
        for iot in group:
            enc_aes_key += self.iotTempData[iot.id][2]  # from IoT
        enc_aes_key += self.iotAuthDB[iot_gid][1]  # from Fog

        hashed_gid = b3.blake3(
            iot.gid.to_bytes(4)
        ).digest()  # decrypt key with hash value of GID

        aes_key = AESCBCCipher(hashed_gid).decrypt(
            enc_aes_key
        )  # to decrypt the ciphered secret
        
        # aes_key = b'M\x84\x179\xf8/\xb4\xb5w!\xec\xf5v\xc6\xbd\xd1\xd3\x05s\xbc\x18T\xda\xaeI\xb8\xa1H5Ir\x07'

        # Decrypt the enc_secret in database
        group_secret = AESCBCCipher(aes_key).decrypt(self.iotAuthDB[iot_gid][0])

        # Token verification
        threads = []
        for iot in group:
            self.verifySingleToken(iot, group_secret)
            # del self.iotTempData[iot.id]
            
    def verifySingleToken(self, iot: IoTPi, group_secret: bytes):
        (iot_gid, iot_data, iot_partialKey, iot_token) = self.iotTempData[iot.id]

        iot_msg = (
            iot_gid.to_bytes(4) + iot.id.to_bytes(4) + iot_data + iot_partialKey
        )
        iot_token_fog = b3.blake3(iot_msg, key=group_secret).digest()

        if iot_token != iot_token_fog:
            assert Exception(
                f"     Data Authentication failed: IoT {iot.id} Token invalid"
            )
        try:
            self.aggregatedData[iot.gid].append(iot.data)
        except KeyError:
            self.aggregatedData[iot.gid] = [iot.data]

    def uploadToCloud(self, fog_nodes, devices_per_node, fog_id, gid):
        aggregated_data = {
            "fog_node_id": fog_id,
            "aggregated_data": self.aggregatedData[gid],
        }

        try:
            load_dotenv()

            # initialize a connection to Azure Blob Storage
            connect_str = os.getenv("AZURE_API")  # to add connection
            # blob_service_client = BlobServiceClient.from_connection_string(connect_str)
            # container_name = "iiot-data-authentication-to-cloud"
            # blob_name = f"our_scheme/fog_no_{fog_nodes}/device_no_{devices_per_node}/aggregated_data_{gid}.json"

            # convert aggregated data to JSON
            data = json.dumps(aggregated_data)
            # print(f"\n{data}\n")

        # upload data
        # blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
        # blob_client.upload_blob(data, overwrite=True)
        # print(f"Uploaded aggregated data of fog node {gid[fog_node_index]} to Azure Blob Storage.")

        except Exception as e:
            # print(f"Error uploading data for fog node {gid[fog_node_index]}: {e}")
            pass

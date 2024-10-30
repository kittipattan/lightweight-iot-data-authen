from ecpy.keys import ECPublicKey, ECPrivateKey
from ecpy.curves import Curve
from utils.nizkp import generate_proof, verify_proof_fog
from iot_rasppi import IoTPi
import secrets
from utils.aes256 import AESCBCCipher, AESGCMCipher
from typing import Tuple
import blake3 as b3
import os
import time
import struct
from typing import List, Tuple


class LeaderPi(IoTPi):
    def __init__(self, id, gid, seed, data, n_challenge=64):
        super().__init__(id, gid, seed, data, n_challenge)
        # NIZKP
        self.curve = Curve.get_curve("Curve25519")  # known to Fog already
        self.G = self.curve.generator
        self.n = self.curve.order
        self.prk = ECPrivateKey(secrets.randbits(256), self.curve)  # private key PrKL
        self.PK = self.prk.get_public_key()  # PK
        self.ssk: bytes = None
        self.encSecret: bytes = None

    # NIZKP
    def genProof(self, message):
        return generate_proof(self.curve, self.prk, self.PK, self.id, self.gid, message)

    def verifyProof(self, fog_proof):
        return verify_proof_fog(fog_proof, self.G)

    def deriveSSK(self, sharing_PK, salt):
        x = (self.curve.mul_point(self.prk.d, sharing_PK.W)).x.to_bytes(32)
        self.ssk = b3.blake3(
            (x + salt),
            derive_key_context="LightPUF SSK Derivation 2024-09-26 21:58:05 derive SSK between Leader and Fog"
        ).digest()

    # PHASE 4: Data Authentication and Integrity Verification
    # 1. Secret generation
    def sendGK(self):
        n_gcm = os.urandom(12)
        timestamp = time.time()
        enc_gk = AESGCMCipher(self.ssk).encrypt(
            n_gcm, self.gk, (struct.pack("d", timestamp) + n_gcm)
        )

        return enc_gk, timestamp, n_gcm

    # 3. Secret distribution
    def distributeSecret(
        self,
        messsages: List[Tuple[int, bytes, bytes, float, bytes]],
        group: List[IoTPi],
    ):
        for msg, iot in zip(messsages, group):
            device_id = msg[0]
            msg_to_iot = msg[1:]
            if device_id == self.id:
                self.recvSecret(msg_to_iot)
                continue
            
            iot.recvSecret(msg_to_iot)
            
    # Our scheme
    # def recvSecFromFog(self, enc_packet):
    #     (secret, ciphered_keys) = AESCipher(self.ssk).decrypt(enc_packet).split("||||")
    #     secret = bytes.fromhex(secret)
    #     ciphered_keys = json.loads(ciphered_keys)
    #     ciphered_keys = list(map(lambda ck: bytes.fromhex(ck), ciphered_keys))

    #     self.secret = secret
    #     self.partialKey = ciphered_keys[0]
    #     self.encSecret = AESCipher(self.gk).encrypt(f"{self.secret.hex()}")

    #     return (secret, ciphered_keys)

    # def sendSecToIoT(self, iot_id: int, secret: bytes, partial_ciphered_key: bytes):
    #     return (self.encSecret, partial_ciphered_key)

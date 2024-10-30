from hashlib import sha256
from ecpy.keys import ECPublicKey, ECPrivateKey
from ecpy.curves import Curve
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from utils.nizkp import generate_proof, verify_proof_fog
from iot_confer import IoT
import secrets
from datetime import datetime
from utils.aes256 import AESCipher
import json
from typing import Tuple
import hmac

# def verify_fog(fog_data, G):
#   return verify_proof(fog_data, G)

# def generate_proof_to_fog(curve, prkL, PKL, id, gid, data="none"):
#   return generate_proof(curve, prkL, PKL, id, gid, data)

# def derive_SSK(prkL, PKF):
#   return prkL * PKF


class Leader(IoT):
    def __init__(self, id, gid, seed, data, n_challenge=64):
        super().__init__(id, gid, seed, data, n_challenge)
        # NIZKP
        self.curve = Curve.get_curve("secp256k1")  # known to Fog already
        self.G = self.curve.generator
        self.n = self.curve.order
        self.prk = ECPrivateKey(secrets.randbits(256), self.curve)  # private key PrKL
        self.PK = self.prk.get_public_key()  # PK
        self.ssk: bytes = None
        self.encSecret: bytes = None

    # PUF
    def reqMutAuth(self, pairing_id):
        pairing_challenge = self.localDatabase[pairing_id]
        self.pairing_id = pairing_id
        self.timestamp = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

        return (self.id, self.CRP[0], pairing_id, pairing_challenge, self.timestamp)

    def verifyMutAuthProof(self, pt: Tuple[bytes, datetime]):
        (proof, pairing_timestamp) = pt
        self.pairing_timestamp = pairing_timestamp
        self.p_1 = sha256(self.CRP[1] + self.pairing_id.to_bytes(16)).digest()

        try:
            (pairing_n, timestamp_prime) = (
                AESCipher(self.p_1).decrypt(proof).split("||||")
            )
            self.nonces["pairing_n"] = bytes.fromhex(pairing_n)

            return self.timestamp == timestamp_prime
        except Exception as e:
            print(e)
            raise Exception("Mutual Authentication failed: reject proof from IoT")

    def resMutAuth(self):
        pairing_phi = self.localDatabase[self.pairing_id][1]
        p_2 = sha256(self.p_1).digest()
        pairing_p_2 = (int.from_bytes(pairing_phi) ^ int.from_bytes(p_2)).to_bytes(32)
        self.nonces["n"] = secrets.token_bytes(32)
        proof = AESCipher(pairing_p_2).encrypt(
            f"{self.nonces['n'].hex()}||||{self.pairing_timestamp}"
        )

        return proof

    def exchangeKey(self):
        self.localDatabase[self.pairing_id] = sha256(
            self.nonces["pairing_n"] + self.nonces["n"]
        ).digest()
        
    def genGroupKey(self):
        # Generate Group session key
        self.gk = secrets.token_bytes(32)

    # Our PUF scheme
    def sendGroupKey(self, iot_id: int):
        sk_puf = self.localDatabase[iot_id]

        # Generate Timestamp
        timestamp = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

        # Generate packet to send to IoT
        msg = f"{self.gk.hex()}||||{timestamp}"

        # Encrypted packet to send
        enc_msg = AESCipher(sk_puf).encrypt(msg)

        # Message into HMAC generation
        concat_msg = f"{enc_msg.hex()}{self.id}"

        # Generate HMAC (Enc-Then-MAC) (HMAC-SHA256(enc_msg || id))
        mac = hmac.new(sk_puf, concat_msg.encode(), sha256).digest()

        packet = (enc_msg, mac, self.id)

        return packet

    # NIZKP
    def genProof(self, message):
        return generate_proof(self.curve, self.prk, self.PK, self.id, self.gid, message)

    def verifyProof(self, fog_proof):
        return verify_proof_fog(fog_proof, self.G)

    def deriveSSK(self, sharing_PK, salt):
        x = (self.prk.d * sharing_PK.W).x.to_bytes(32)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=None,
        )
        self.ssk = hkdf.derive(x)

    # Our scheme
    def recvSecFromFog(self, enc_packet):
        (secret, ciphered_keys) = AESCipher(self.ssk).decrypt(enc_packet).split("||||")
        secret = bytes.fromhex(secret)
        ciphered_keys = json.loads(ciphered_keys)
        ciphered_keys = list(map(lambda ck: bytes.fromhex(ck), ciphered_keys))

        self.secret = secret
        self.partialKey = ciphered_keys[0]
        self.encSecret = AESCipher(self.gk).encrypt(f"{self.secret.hex()}")

        return (secret, ciphered_keys)

    def sendSecToIoT(self, iot_id: int, secret: bytes, partial_ciphered_key: bytes):
        return (self.encSecret, partial_ciphered_key)

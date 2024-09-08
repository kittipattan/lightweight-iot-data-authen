from hashlib import sha256
from pypuf.simulation import ArbiterPUF
import secrets
from aes256 import AESCipher
from datetime import datetime
import json
import numpy as np

class IoT:
    def __init__(self, id: int, gid: int, seed: int, data, n_challenge=64) -> None:
        # Our scheme
        self.id = id
        self.gid = gid
        self.token = None
        self.secret = None
        self.partialKey = None
        self.data = data

        # PUF-based authentication
        self.CRP = None
        self.tmpPairing_challenge = None
        self.puf = ArbiterPUF(n=n_challenge, seed=seed)
        self.nonces = {"m": None, "x": None, "n": None, "pairing_n": None}
        self.tmpID = -1
        self.localDatabase = {}
        self.timestamp = None
        self.pairing_timestamp = None
        self.pairing_id = -1
        self.p_1 = None

    def genResponse(self, challenge):
        response = self.puf.eval(challenge)
        response = np.abs(response)

        return int("".join(str(r) for r in response), 2).to_bytes(16)

    # Enrollment/Update phase
    def genAuth(self, m):
        auth = sha256(
            (int.from_bytes(self.CRP[1]) ^ int.from_bytes(m)).to_bytes(32)
        ).hexdigest()  # AUTH
        x = secrets.token_bytes(32)  # random nonce

        return (auth, x)

    def recvEnrollReq(self, req):
        (id, challenge, pairing_id, pairing_challenge, m) = req
        if self.id != id:
            raise Exception("Enrollment failed")

        self.CRP = (challenge, self.genResponse(challenge))
        self.tmpPairing_challenge = pairing_challenge
        self.tmpID = pairing_id
        self.nonces["m"] = m

        return (self.genAuth(m), m)

    def addPairingInfo(self, X):
        response = self.CRP[1]
        (x, phi) = AESCipher(sha256(response).digest()).decrypt(X).split("||||")
        (x, phi) = (bytes.fromhex(x), bytes.fromhex(phi))
        if self.nonces["x"] != x:  # nonce is fresh
            self.nonces["x"] = x
            self.localDatabase[self.tmpID] = (self.tmpPairing_challenge, phi)

    # Mutual Authentication
    def resMutAuth(self, req):
        (pairing_id, pairing_challenge, id, challenge, timestamp) = req
        if (id != self.id) or not (self.localDatabase[pairing_id]):
            raise Exception("Mutual Authentication failed")

        self.pairing_id = pairing_id
        pairing_phi = self.localDatabase[pairing_id][1]

        self.p_1 = sha256(self.CRP[1] + pairing_id.to_bytes(16)).digest()
        pairing_p_1 = (int.from_bytes(pairing_phi) ^ int.from_bytes(self.p_1)).to_bytes(
            32
        )
        self.nonces["n"] = secrets.token_bytes(32)
        proof = AESCipher(pairing_p_1).encrypt(
            f"{self.nonces['n'].hex()}||||{timestamp}"
        )
        self.timestamp = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

        return (proof, self.timestamp)

    def verifyMutAuthProof(self, proof):
        p_2 = sha256(self.p_1).digest()
        try:
            (pairing_n, timestamp_prime) = AESCipher(p_2).decrypt(proof).split("||||")
            self.nonces["pairing_n"] = bytes.fromhex(pairing_n)

            return self.timestamp == timestamp_prime
        except:
            raise Exception("Mutual Authentication failed: reject proof from Leader")

    # Key Exchange
    def exchangeKey(self):
        self.localDatabase[self.pairing_id] = sha256(
            self.nonces["n"] + self.nonces["pairing_n"]
        ).digest()
        
    # Our scheme
    def recvSecFromLeader(self, leader_id: int, enc_packet: bytes):
        (secret, partial_ciphered_key) = AESCipher(self.localDatabase[leader_id]).decrypt(enc_packet).split('||||')
        self.secret = bytes.fromhex(secret)
        self.partialKey = bytes.fromhex(partial_ciphered_key)

    def generateToken(self):
        return sha256(f"{self.gid}{self.id}{self.data}{self.partialKey}{self.secret}".encode()).digest()

    def createPacket(self):
        return (self.id, self.gid, self.data, self.partialKey, self.generateToken())

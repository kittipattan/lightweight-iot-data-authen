from hashlib import sha256
from pypuf.simulation import ArbiterPUF
import secrets
from utils.aes256 import AESCipher
from datetime import datetime
import json
import numpy as np
from typing import Tuple
import hmac
import timeit


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
        self.puf = ArbiterPUF(n=n_challenge, seed=seed)
        self.gk: bytes = None

        self.CRP = None
        self.tmpPairing_challenge = None
        self.nonces = {"m": None, "x": None, "n": None, "pairing_n": None}
        self.tmpID = -1
        self.localDatabase = {}
        self.timestamp = None
        self.pairing_timestamp = None
        self.pairing_id: int = -1
        self.p_1 = None

    def genResponse(self, challenge):
        response = self.puf.eval(challenge)
        response = np.abs(response)

        return int("".join(str(r) for r in response), 2).to_bytes(32)

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

    def exchangeKey(self):
        self.localDatabase[self.pairing_id] = sha256(
            self.nonces["n"] + self.nonces["pairing_n"]
        ).digest()

    def recvGroupKey(self, pkt: Tuple[bytes, bytes, int]):
        (enc_msg, mac_leader, leader_id) = pkt
        sk_puf = self.localDatabase[leader_id]

        # Message into HMAC generation
        concat_msg = f"{enc_msg.hex()}{leader_id}"

        # Verify MAC
        mac_iot = hmac.new(sk_puf, concat_msg.encode(), sha256).digest()
        if not hmac.compare_digest(mac_leader, mac_iot):
            assert Exception("Leader MAC invalid")

        # Decrypt the received packet
        packet = AESCipher(sk_puf).decrypt(enc_msg)
        (gk, timestamp) = packet.split("||||")

        # Validate timestamp
        timestamp = datetime.strptime(timestamp, "%m/%d/%Y, %H:%M:%S")
        timestamp_iot = datetime.now()

        # current_timestamp - timestamp
        if (timestamp_iot - timestamp).total_seconds() > 60:
            assert Exception("Leader timestamp exceed limit")

        # Store Group Key
        self.gk = bytes.fromhex(gk)

    # def recvSecFromLeader(self, leader_id: int, packet: Tuple[bytes, bytes]):
    #     (enc_secret, partial_ciphered_key) = packet
    #     secret = AESCipher(self.localDatabase[leader_id]).decrypt(enc_secret)
    #     self.secret = bytes.fromhex(secret)
    #     self.partialKey = partial_ciphered_key

    def recvSecFromLeader(self, leader_id: int, packet: Tuple[bytes, bytes]):
        (enc_secret, partial_ciphered_key) = packet
        secret = AESCipher(self.gk).decrypt(enc_secret)
        self.secret = bytes.fromhex(secret)
        self.partialKey = partial_ciphered_key

    def generateToken(self):
        # return sha256(f"{self.gid}{self.id}{self.data}{self.partialKey}{self.secret}".encode()).digest()
        # print(f"token iot 1 {sha256(f"{self.gid}{self.id}{self.data}{self.partialKey}{self.secret}".encode()).digest()}")

        token = hmac.new(
            sha256(self.secret).digest(),
            f"{self.gid}{self.id}{self.data}{self.partialKey}".encode(),
            sha256,
        ).digest()

        return token

    def createPacket(self):
        # start_time = timeit.default_timer()
        # (self.id, self.gid, self.data, self.partialKey, self.generateToken())
        # print(f"Token gen within: {(timeit.default_timer() - start_time)*1000} ms")

        return (self.id, self.gid, self.data, self.partialKey, self.generateToken())

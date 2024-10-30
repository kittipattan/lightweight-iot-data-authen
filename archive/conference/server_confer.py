import json
import mysql.connector
import secrets
from hashlib import sha256
from utils.aes256 import AESCBCCipher
import numpy as np
from typing import Tuple
import os
from dotenv import load_dotenv
import hmac
from datetime import datetime


class LocalServer:
    def __init__(self):
        load_dotenv()
        self.__connection = mysql.connector.connect(
            database=os.getenv("DB_NAME"),
            host=os.getenv("DB_HOST"),
            user=os.getenv("DB_USERNAME"),
            password=os.getenv("DB_PASSWORD"),
        )
        self._cursor = self.__connection.cursor(prepared=True)
        self._db_table = "crps"

    def dropCRP(self):
        stmt = f"DELETE FROM crps"
        self._cursor.execute(stmt)
        self.__connection.commit()

    def _getGID(self, iot_id: int):
        stmt = f"SELECT gid FROM crps WHERE id = %s"
        self._cursor.execute(stmt, (iot_id,))

        return self._cursor.fetchone()[0]

    def _getResponse(self, iot_id: int):
        stmt = f"SELECT response FROM crps WHERE id = %s"
        self._cursor.execute(stmt, (iot_id,))
        response = bytes.fromhex(self._cursor.fetchall()[0][0])

        return response

    def _getChallengeJSON(self, iot_id: int):
        stmt = f"SELECT challenge FROM crps WHERE id = %s"
        self._cursor.execute(stmt, (iot_id,))
        challenge: str = self._cursor.fetchall()[0][0]

        return challenge

    # Enrollment
    def registerCRP(
        self, id, gid, challenge, response
    ):  # assume to perform over secure channel
        stmt = (
            f"INSERT INTO crps (id, gid, challenge, response) VALUES (%s, %s, %s, %s)"
        )
        data = (id, gid, json.dumps(challenge.tolist()), response.hex())
        self._cursor.execute(stmt, data)
        self.__connection.commit()

        return self._cursor.rowcount

    def genEnrollReq(self, id: int, pairing_id: int):
        challenge: np.ndarray = np.array(json.loads(self._getChallengeJSON(id)))
        pairing_challenge: np.ndarray = np.array(
            json.loads(self._getChallengeJSON(pairing_id))
        )
        nonce: bytes = secrets.token_bytes(32)

        return (id, challenge, pairing_id, pairing_challenge, nonce)

    def resToAuth(
        self,
        id: int,
        pairing_id: int,
        AUTHX: Tuple[bytes, bytes],
        pairing_AUTHX: Tuple[bytes, bytes],
        m: bytes,
        n: bytes,
    ):
        (auth, nonce) = AUTHX
        (pairing_auth, pairing_nonce) = pairing_AUTHX

        response = self._getResponse(id)
        pairing_response = self._getResponse(pairing_id)

        auth_prime = sha256(
            (int.from_bytes(response) ^ int.from_bytes(m)).to_bytes(32)
        ).hexdigest()
        pairing_auth_prime = sha256(
            (int.from_bytes(pairing_response) ^ int.from_bytes(n)).to_bytes(32)
        ).hexdigest()

        if not (auth == auth_prime and pairing_auth == pairing_auth_prime):
            raise Exception("Enrollment failed: invalid AUTH to Local server")

        p_1 = sha256(response + pairing_id.to_bytes(16)).digest()
        pairing_p_1 = sha256(pairing_response + id.to_bytes(16)).digest()

        p_2 = sha256(p_1).digest()
        pairing_p_2 = sha256(pairing_p_1).digest()

        phi = (int.from_bytes(p_1) ^ int.from_bytes(pairing_p_1)).to_bytes(32)
        pairing_phi = (int.from_bytes(p_2) ^ int.from_bytes(pairing_p_2)).to_bytes(32)

        X = AESCipher(sha256(response).digest()).encrypt(
            f"{nonce.hex()}||||{pairing_phi.hex()}"
        )
        pairing_X = AESCipher(sha256(pairing_response).digest()).encrypt(
            f"{pairing_nonce.hex()}||||{phi.hex()}"
        )

        return (X, pairing_X)


# class GroupLocalServer(LocalServer):
#     def __init__(self):
#         super().__init__()

#     def __genGroupKey(self, gid: int):
#         query = "SELECT GROUP_CONCAT(response SEPARATOR '') AS concatenated_responses FROM crps WHERE gid = %s"
#         self._cursor.execute(query, (gid,))
#         concat_response = self._cursor.fetchone()[0]
#         group_key = sha256(bytes.fromhex(concat_response)).digest()

#         return group_key

#     def sendGroupKey(self, iot_id: int):
#         gid = self._getGID(iot_id)
#         iot_response = self._getResponse(iot_id)
#         response_key = sha256(iot_response).digest()
#         iot_challenge_json = self._getChallengeJSON(iot_id)
#         gk = self.__genGroupKey(gid)

#         timestamp = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

#         # Generate packet to send to IoT
#         packet = f"{gk.hex()}||||{timestamp}"

#         # Encrypted packet to send
#         enc_packet = AESCipher(response_key).encrypt(packet)

#         # Message into HMAC generation
#         concat_msg = f"{enc_packet.hex()}{iot_challenge_json}"

#         # Generate HMAC (Enc-Then-MAC)
#         mac = hmac.new(response_key, concat_msg.encode(), sha256).digest()

#         # Challenge to send
#         challenge = np.array(json.loads(iot_challenge_json))

#         return (enc_packet, mac, challenge)

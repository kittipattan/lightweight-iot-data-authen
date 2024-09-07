import json
import mysql.connector
import secrets
from hashlib import sha256
from aes256 import AESCipher
import numpy as np
from typing import Tuple
import os
from dotenv import load_dotenv


class LocalServer():
    def __init__(self):
        load_dotenv()
        self.__connection = mysql.connector.connect(database=os.getenv('DB_NAME'),
                                            host=os.getenv('DB_HOST'),
                                            user=os.getenv('DB_USERNAME'),
                                            password=os.getenv('DB_PASSWORD'))
        self.__cursor = self.__connection.cursor(prepared=True)
        self.__db_table = 'crps'

    def dropCRP(self):
        stmt = f'DELETE FROM crps'
        self.__cursor.execute(stmt)
        self.__connection.commit()

    # Enrollment
    def registerCRP(self, id, challenge, response): # assume to perform over secure channel
        stmt = f'INSERT INTO crps (id, challenge, response) VALUES (%s, %s, %s)'
        json_data = (id, json.dumps(challenge.tolist()), response.hex())
        self.__cursor.execute(stmt, json_data)
        self.__connection.commit()

        return self.__cursor.rowcount
    
    def genEnrollReq(self, id: int, pairing_id: int):
        stmt = f'SELECT challenge FROM crps WHERE id = %s'
        self.__cursor.execute(stmt, (id,))
        challenge: np.ndarray = np.array(json.loads(self.__cursor.fetchall()[0][0]))
        self.__cursor.execute(stmt, (pairing_id,))
        pairing_challenge: np.ndarray = np.array(json.loads(self.__cursor.fetchall()[0][0]))
        nonce: bytes = secrets.token_bytes(32)

        return (id, challenge, pairing_id, pairing_challenge, nonce)

    def resToAuth(self, id: int, pairing_id: int, AUTHX: Tuple[bytes, bytes], pairing_AUTHX: Tuple[bytes, bytes], m: bytes, n: bytes):
        (auth, nonce) = AUTHX
        (pairing_auth, pairing_nonce) = pairing_AUTHX

        stmt = f'SELECT response FROM crps WHERE id = %s'
        self.__cursor.execute(stmt, (id,))
        response = bytes.fromhex(self.__cursor.fetchall()[0][0])

        self.__cursor.execute(stmt, (pairing_id,))
        pairing_response = bytes.fromhex(self.__cursor.fetchall()[0][0])

        auth_prime = sha256((int.from_bytes(response) ^ int.from_bytes(m)).to_bytes(32)).hexdigest()
        pairing_auth_prime = sha256((int.from_bytes(pairing_response) ^ int.from_bytes(n)).to_bytes(32)).hexdigest()

        if not (auth == auth_prime and pairing_auth == pairing_auth_prime):
            raise Exception("Enrollment failed: invalid AUTH to Local server")
        
        p_1 = sha256(response + pairing_id.to_bytes(16)).digest()
        pairing_p_1 = sha256(pairing_response + id.to_bytes(16)).digest()

        p_2 = sha256(p_1).digest()
        pairing_p_2 = sha256(pairing_p_1).digest()

        phi = (int.from_bytes(p_1) ^ int.from_bytes(pairing_p_1)).to_bytes(32)
        pairing_phi = (int.from_bytes(p_2) ^ int.from_bytes(pairing_p_2)).to_bytes(32)

        X = AESCipher(sha256(response).digest()).encrypt(f"{nonce.hex()}||||{pairing_phi.hex()}")
        pairing_X = AESCipher(sha256(pairing_response).digest()).encrypt(f"{pairing_nonce.hex()}||||{phi.hex()}")

        return (X, pairing_X)


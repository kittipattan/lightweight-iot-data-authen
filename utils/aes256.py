from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import os

class AESCipher:
    def __init__(self, key):
        self.block_size = 16  # AES block size is 16 bytes
        if isinstance(key, bytes):
            self.key = key
        elif isinstance(key, str):
            # Derive a 32-byte AES-256 key using SHA-256
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(key.encode())
            self.key = digest.finalize()

    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = os.urandom(self.block_size)  # Generate a random IV
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_text = encryptor.update(plain_text.encode()) + encryptor.finalize()
        return iv + encrypted_text  # Return IV concatenated with the ciphertext

    def decrypt(self, encrypted_text):
        iv = encrypted_text[:self.block_size]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plain_text = decryptor.update(encrypted_text[self.block_size:]) + decryptor.finalize()
        return self.__unpad(plain_text.decode())

    def __pad(self, plain_text) -> str:
        padding_needed = self.block_size - len(plain_text) % self.block_size
        padding_char = chr(padding_needed)
        return plain_text + padding_needed * padding_char

    @staticmethod
    def __unpad(plain_text) -> str:
        padding_char = plain_text[-1]
        padding_needed = ord(padding_char)
        return plain_text[:-padding_needed]
    

# import hashlib
# from Crypto import Random
# from Crypto.Cipher import AES
# from base64 import b64encode, b64decode

# class AESCipher(object):
#     def __init__(self, key):
#         self.block_size = AES.block_size
#         if isinstance(key, bytes):
#             self.key = key
#         elif isinstance(key, str):
#             self.key = hashlib.sha256(key.encode()).digest()

#     def encrypt(self, plain_text):
#         plain_text = self.__pad(plain_text)
#         iv = Random.new().read(self.block_size)
#         cipher = AES.new(self.key, AES.MODE_CBC, iv)
#         encrypted_text = cipher.encrypt(plain_text.encode())
#         return b64encode(iv + encrypted_text).decode("utf-8")

#     def decrypt(self, encrypted_text):
#         encrypted_text = b64decode(encrypted_text)
#         iv = encrypted_text[:self.block_size]
#         cipher = AES.new(self.key, AES.MODE_CBC, iv)
#         plain_text = cipher.decrypt(encrypted_text[self.block_size:]).decode("utf-8")
#         return self.__unpad(plain_text)

#     def __pad(self, plain_text):
#         number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
#         ascii_string = chr(number_of_bytes_to_pad)
#         padding_str = number_of_bytes_to_pad * ascii_string
#         padded_plain_text = plain_text + padding_str
#         return padded_plain_text

#     @staticmethod
#     def __unpad(plain_text):
#         last_character = plain_text[len(plain_text) - 1:]
#         return plain_text[:-ord(last_character)]
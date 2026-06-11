
import os,base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
class AESService:
    @staticmethod
    def generate_key():
        return base64.b64encode(AESGCM.generate_key(bit_length=256)).decode()
    @staticmethod
    def encrypt(message,key):
        k=base64.b64decode(key); nonce=os.urandom(12)
        ct=AESGCM(k).encrypt(nonce,message.encode(),None)
        return {'nonce':base64.b64encode(nonce).decode(),'ciphertext':base64.b64encode(ct).decode()}
    @staticmethod
    def decrypt(ciphertext,nonce,key):
        k=base64.b64decode(key)
        pt=AESGCM(k).decrypt(base64.b64decode(nonce),base64.b64decode(ciphertext),None)
        return pt.decode()

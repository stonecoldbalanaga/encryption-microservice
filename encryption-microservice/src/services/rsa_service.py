
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import serialization,hashes
import base64
class RSAService:
    @staticmethod
    def generate_keys():
        p=rsa.generate_private_key(public_exponent=65537,key_size=4096)
        pub=p.public_key()
        return (
        p.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode(),
        pub.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode())
    @staticmethod
    def encrypt(message,public_pem):
        pub=serialization.load_pem_public_key(public_pem.encode())
        return base64.b64encode(pub.encrypt(message.encode(),padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None))).decode()
    @staticmethod
    def decrypt(cipher,private_pem):
        p=serialization.load_pem_private_key(private_pem.encode(),password=None)
        return p.decrypt(base64.b64decode(cipher),padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None)).decode()

import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from typing import Optional


class CryptoTool:
    @staticmethod
    def base64_encode(data: str) -> str:
        return base64.b64encode(data.encode()).decode()

    @staticmethod
    def base64_decode(data: str) -> str:
        try:
            return base64.b64decode(data).decode()
        except:
            return base64.b64decode(data + "==").decode()

    @staticmethod
    def base32_encode(data: str) -> str:
        return base32.b32encode(data.encode()).decode()

    @staticmethod
    def base32_decode(data: str) -> str:
        return base32.b32decode(data).decode()

    @staticmethod
    def base58_encode(data: str) -> str:
        from base58 import b58encode
        return b58encode(data.encode()).decode()

    @staticmethod
    def base58_decode(data: str) -> str:
        from base58 import b58decode
        return b58decode(data).decode()

    @staticmethod
    def md5_hash(data: str) -> str:
        return hashlib.md5(data.encode()).hexdigest()

    @staticmethod
    def sha256_hash(data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()

    @staticmethod
    def sha1_hash(data: str) -> str:
        return hashlib.sha1(data.encode()).hexdigest()

    @staticmethod
    def crc32_checksum(data: str) -> str:
        import zlib
        return hex(zlib.crc32(data.encode()) & 0xffffffff)

    @staticmethod
    def rot13(data: str) -> str:
        return data.translate(str.maketrans(
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
            'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
        ))

    @staticmethod
    def caesar_cipher(data: str, shift: int = 3) -> str:
        result = []
        for char in data:
            if char.isalpha():
                shifted = ord(char) + shift
                if char.islower():
                    if shifted > ord('z'):
                        shifted -= 26
                else:
                    if shifted > ord('Z'):
                        shifted -= 26
                result.append(chr(shifted))
            else:
                result.append(char)
        return ''.join(result)

    @staticmethod
    def xor_cipher(data: str, key: str) -> str:
        result = []
        key_len = len(key)
        for i, char in enumerate(data):
            result.append(chr(ord(char) ^ ord(key[i % key_len])))
        return ''.join(result)

    @staticmethod
    def generate_aes_key() -> str:
        return Fernet.generate_key().decode()

    @staticmethod
    def aes_encrypt(data: str, key: str) -> str:
        fernet = Fernet(key.encode())
        return fernet.encrypt(data.encode()).decode()

    @staticmethod
    def aes_decrypt(data: str, key: str) -> str:
        fernet = Fernet(key.encode())
        return fernet.decrypt(data.encode()).decode()

    @staticmethod
    def generate_rsa_key_pair() -> dict:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        return {
            "private_key": private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode(),
            "public_key": public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        }

    @staticmethod
    def rsa_encrypt(data: str, public_key_str: str) -> str:
        public_key = serialization.load_pem_public_key(
            public_key_str.encode(),
            backend=default_backend()
        )
        encrypted = public_key.encrypt(
            data.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode()

    @staticmethod
    def rsa_decrypt(data: str, private_key_str: str) -> str:
        private_key = serialization.load_pem_private_key(
            private_key_str.encode(),
            password=None,
            backend=default_backend()
        )
        decrypted = private_key.decrypt(
            base64.b64decode(data),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode()

    @staticmethod
    def url_encode(data: str) -> str:
        from urllib.parse import quote
        return quote(data)

    @staticmethod
    def url_decode(data: str) -> str:
        from urllib.parse import unquote
        return unquote(data)

    @staticmethod
    def html_encode(data: str) -> str:
        from html import escape
        return escape(data)

    @staticmethod
    def html_decode(data: str) -> str:
        from html import unescape
        return unescape(data)

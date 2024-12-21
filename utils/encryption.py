import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class ZeroKnowledgeEncryption:
    def __init__(self, password):
        # Generate a key derivation function
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        # Derive the key from the password
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.cipher_suite = Fernet(key)
        self.salt = salt

    def encrypt_data(self, data):
        """
        Encrypt data before sending through VPN
        """
        if isinstance(data, str):
            data = data.encode()
        return {
            'encrypted_data': self.cipher_suite.encrypt(data).decode(),
            'salt': base64.urlsafe_b64encode(self.salt).decode()
        }

    def decrypt_data(self, encrypted_data, salt):
        """
        Decrypt data received through VPN
        """
        return self.cipher_suite.decrypt(encrypted_data.encode()).decode()

    @staticmethod
    def generate_ephemeral_key():
        """
        Generate a one-time use encryption key
        """
        return Fernet.generate_key()
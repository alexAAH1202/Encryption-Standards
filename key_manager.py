import boto3
import os
import logging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import json
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class KeyManager:
    def __init__(self, master_password):
        self.master_password = master_password.encode()
        self.salt = os.urandom(16)
        self.key = self._derive_key()
        self.keys = {}
        self.key_rotation_interval = timedelta(days=30)  # Rotate keys every 30 days
        self.hsm_client = boto3.client('cloudhsmv2')

    def _derive_key(self):
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=100000,
                backend=default_backend()
            )
            return base64.urlsafe_b64encode(kdf.derive(self.master_password))
        except Exception as e:
            logger.error(f"Failed to derive key: {e}")
            raise

    def generate_key(self, key_type, key_id, key_size=None):
        try:
            if key_type == 'AES':
                if key_size is None or key_size != 32:
                    key_size = 32  # Ensure 256-bit key for AES
                key = os.urandom(key_size)
            elif key_type == 'RSA':
                key = self._generate_rsa_key(key_size if key_size else 2048)
            elif key_type == 'ECC':
                key = self._generate_ecc_key()
            else:
                raise ValueError(f"Unsupported key type: {key_type}")

            creation_time = datetime.utcnow()
            self.keys[key_id] = {
                'key': key,
                'type': key_type,
                'created': creation_time,
                'rotated': creation_time
            }
            logger.info(f"Generated {key_type} key with ID {key_id}")
        except Exception as e:
            logger.error(f"Failed to generate key: {e}")
            raise

    def _generate_rsa_key(self, key_size):
        try:
            response = self.hsm_client.create_key_pair(
                KeySpec='RSA_2048' if key_size == 2048 else 'RSA_4096'
            )
            logger.info(f"Generated RSA key with size {key_size}")
            return response['KeyId']
        except Exception as e:
            logger.error(f"Failed to generate RSA key: {e}")
            raise

    def _generate_ecc_key(self):
        try:
            response = self.hsm_client.create_key_pair(
                KeySpec='ECC_NIST_P256'
            )
            logger.info("Generated ECC key")
            return response['KeyId']
        except Exception as e:
            logger.error(f"Failed to generate ECC key: {e}")
            raise

    def get_key(self, key_id):
        try:
            if key_id not in self.keys:
                raise KeyError(f"Key not found: {key_id}")
            key_info = self.keys[key_id]
            if datetime.utcnow() - key_info['rotated'] > self.key_rotation_interval:
                self.rotate_key(key_id)
            logger.info(f"Retrieved key with ID {key_id}")
            return key_info['key']
        except KeyError as e:
            logger.error(e)
            raise
        except Exception as e:
            logger.error(f"Failed to get key: {e}")
            raise

    def rotate_key(self, key_id):
        try:
            if key_id not in self.keys:
                raise KeyError(f"Key not found: {key_id}")
            key_info = self.keys[key_id]
            self.generate_key(key_info['type'], key_id)
            self.keys[key_id]['rotated'] = datetime.utcnow()
            logger.info(f"Rotated key with ID {key_id}")
        except KeyError as e:
            logger.error(e)
            raise
        except Exception as e:
            logger.error(f"Failed to rotate key: {e}")
            raise

    def encrypt_keys(self):
        try:
            f = Fernet(self.key)
            encrypted_keys = f.encrypt(json.dumps(self.keys, default=self._serialize_key).encode())
            logger.info("Encrypted keys")
            return encrypted_keys
        except Exception as e:
            logger.error(f"Failed to encrypt keys: {e}")
            raise

    def decrypt_keys(self, encrypted_keys):
        try:
            f = Fernet(self.key)
            decrypted_keys = f.decrypt(encrypted_keys)
            self.keys = json.loads(decrypted_keys.decode(), object_hook=self._deserialize_key)
            logger.info("Decrypted keys")
        except Exception as e:
            logger.error(f"Failed to decrypt keys: {e}")
            raise

    def save_keys(self, filename):
        try:
            encrypted_keys = self.encrypt_keys()
            with open(filename, 'wb') as f:
                f.write(encrypted_keys)
            logger.info(f"Saved keys to {filename}")
        except Exception as e:
            logger.error(f"Failed to save keys: {e}")
            raise

    def load_keys(self, filename):
        try:
            with open(filename, 'rb') as f:
                encrypted_keys = f.read()
            self.decrypt_keys(encrypted_keys)
            logger.info(f"Loaded keys from {filename}")
        except Exception as e:
            logger.error(f"Failed to load keys: {e}")
            raise

    def _serialize_key(self, key):
        try:
            if isinstance(key, rsa.RSAPrivateKey) or isinstance(key, ec.EllipticCurvePrivateKey):
                return key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode()
            return key
        except Exception as e:
            logger.error(f"Failed to serialize key: {e}")
            raise

    def _deserialize_key(self, key_data):
        try:
            if isinstance(key_data, str) and key_data.startswith("-----BEGIN PRIVATE KEY-----"):
                return serialization.load_pem_private_key(
                    key_data.encode(),
                    password=None,
                    backend=default_backend()
                )
            return key_data
        except Exception as e:
            logger.error(f"Failed to deserialize key: {e}")
            raise

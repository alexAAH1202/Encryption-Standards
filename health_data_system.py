import ssl
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import os
import logging
from key_manager import KeyManager

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class HealthDataSystem:
    def __init__(self, master_password):
        self.key_manager = KeyManager(master_password)
        self.setup_keys()
        self.tls_context = self.setup_tls()

    def setup_keys(self):
        self.key_manager.generate_key('AES', 'aes_key', key_size=32)
        self.key_manager.generate_key('RSA', 'rsa_key', key_size=2048)
        self.key_manager.generate_key('ECC', 'ecc_key')

    def setup_tls(self):
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            # In a real-world scenario, you would load your actual certificate and private key
            # context.load_cert_chain(certfile="path/to/cert.pem", keyfile="path/to/key.pem")
            return context
        except ssl.SSLError as e:
            logger.error(f"Failed to set up TLS context: {e}")
            raise

    def encrypt_data_aes(self, data, key):
        try:
            if len(key) != 32:
                raise ValueError("AES key must be 256 bits (32 bytes)")
            
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
            return iv + encryptor.tag + ciphertext
        except Exception as e:
            logger.error(f"AES encryption failed: {e}")
            raise

    def decrypt_data_aes(self, encrypted_data, key):
        try:
            if len(key) != 32:
                raise ValueError("AES key must be 256 bits (32 bytes)")
            
            iv = encrypted_data[:16]
            tag = encrypted_data[16:32]
            ciphertext = encrypted_data[32:]
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()
        except InvalidSignature:
            logger.error("AES decryption failed: Invalid tag")
            raise
        except Exception as e:
            logger.error(f"AES decryption failed: {e}")
            raise

    def encrypt_data_rsa(self, data, public_key):
        try:
            return public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            logger.error(f"RSA encryption failed: {e}")
            raise

    def decrypt_data_rsa(self, encrypted_data):
        try:
            private_key = self.key_manager.get_key('rsa_key')
            return private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            logger.error(f"RSA decryption failed: {e}")
            raise

    def get_public_key_rsa(self):
        private_key = self.key_manager.get_key('rsa_key')
        return private_key.public_key()

    def create_mac(self, data, key):
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(data.encode())
        return h.finalize()

    def verify_mac(self, data, mac, key):
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(data.encode())
        try:
            h.verify(mac)
            return True
        except InvalidSignature:
            return False

    def serialize_public_key(self, public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def deserialize_public_key(self, pem_data):
        return serialization.load_pem_public_key(pem_data, backend=default_backend())

    def end_to_end_encrypt(self, data, recipient_public_key):
        # Generate a new AES key for this session
        session_key = os.urandom(32)

        # Encrypt the data with the session AES key
        encrypted_data = self.encrypt_data_aes(data, session_key)

        # Encrypt the session AES key with the recipient's RSA public key
        encrypted_session_key = self.encrypt_data_rsa(session_key, recipient_public_key)

        return encrypted_session_key, encrypted_data

    def end_to_end_decrypt(self, encrypted_session_key, encrypted_data):
        # Decrypt the session AES key with the recipient's RSA private key
        session_key = self.decrypt_data_rsa(encrypted_session_key)

        # Decrypt the data with the session AES key
        decrypted_data = self.decrypt_data_aes(encrypted_data, session_key)

        return decrypted_data

# Example usage
def example_usage():
    try:
        alice = HealthDataSystem("alice_master_password")
        bob = HealthDataSystem("bob_master_password")

        # Alice wants to send a message to Bob
        message = "Confidential health data"

        # Alice encrypts the message with Bob's public key (RSA)
        bob_public_key = bob.get_public_key_rsa()
        encrypted_session_key, encrypted_message = alice.end_to_end_encrypt(message, bob_public_key)

        # Bob receives the encrypted session key and encrypted message, and decrypts them
        decrypted_message = bob.end_to_end_decrypt(encrypted_session_key, encrypted_message)

        print(f"Original message: {message}")
        print(f"Decrypted message: {decrypted_message.decode()}")

    except Exception as e:
        logger.error(f"An error occurred: {e}")

if __name__ == "__main__":
    example_usage()

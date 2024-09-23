from auth_system import AuthSystem
from health_data_system import HealthDataSystem
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    auth_system = AuthSystem()

    # Authenticate user
    username = "test_user"
    password = "test_password"
    if auth_system.authenticate_user(username, password):
        logger.info("User authenticated successfully")

        # Generate access token
        token = auth_system.generate_access_token(username)
        logger.info(f"Access token generated: {token}")

        # Verify access token
        user = auth_system.verify_access_token(token)
        if user:
            logger.info(f"Token verified for user: {user}")

            # Initialize HealthDataSystem instances for Alice and Bob
            alice_system = HealthDataSystem("alice_master_password")
            bob_system = HealthDataSystem("bob_master_password")

            # Test end-to-end encryption
            message = "This is a secret message encrypted with end-to-end encryption"
            bob_public_key = bob_system.get_public_key_rsa()
            encrypted_session_key, encrypted_message = alice_system.end_to_end_encrypt(message, bob_public_key)
            decrypted_message = bob_system.end_to_end_decrypt(encrypted_session_key, encrypted_message)

            logger.info(f"Original message: {message}")
            logger.info(f"Decrypted message: {decrypted_message.decode()}")
        else:
            logger.error("Token verification failed")
    else:
        logger.error("Authentication failed")

if __name__ == "__main__":
    main()

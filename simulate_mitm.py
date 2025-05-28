from crypto_utils import *
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    logger.info("=== Man-in-the-Middle Attack Simulation ===")
    # 1. Generate ECC key pairs for client and server
    client_priv, client_pub = generate_ecc_keypair()
    server_priv, server_pub = generate_ecc_keypair()
    logger.info("Client and server key pairs generated")

    # 2. Attacker generates its own key pair
    attacker_priv, attacker_pub = generate_ecc_keypair()
    logger.info("Attacker key pair generated")

    # 3. Attacker intercepts and replaces public keys
    client_pub_bytes = serialize_public_key(client_pub)
    server_pub_bytes = serialize_public_key(server_pub)
    attacker_pub_bytes = serialize_public_key(attacker_pub)
    logger.info(f"Client public key: {client_pub_bytes.hex()[:32]}...")
    logger.info(f"Server public key: {server_pub_bytes.hex()[:32]}...")
    logger.info(f"Attacker public key: {attacker_pub_bytes.hex()[:32]}...")
    client_peer_pub = attacker_pub
    server_peer_pub = attacker_pub

    # 4. Client and attacker derive shared secret, server and attacker derive shared secret
    client_shared = derive_shared_secret(client_priv, client_peer_pub)
    server_shared = derive_shared_secret(server_priv, server_peer_pub)
    attacker_shared_with_client = derive_shared_secret(attacker_priv, client_pub)
    attacker_shared_with_server = derive_shared_secret(attacker_priv, server_pub)
    logger.info(f"Client-attacker shared secret: {client_shared.hex()[:32]}...")
    logger.info(f"Server-attacker shared secret: {server_shared.hex()[:32]}...")
    logger.info(f"Attacker-client shared secret: {attacker_shared_with_client.hex()[:32]}...")
    logger.info(f"Attacker-server shared secret: {attacker_shared_with_server.hex()[:32]}...")

    # 5. Client encrypts command (attacker can decrypt)
    session_key_client = derive_aes_key(client_shared)
    session_key_attacker_client = derive_aes_key(attacker_shared_with_client)
    command = b'UNLOCK'
    nonce, ciphertext = encrypt_command(session_key_client, command)
    logger.info(f"Nonce: {nonce.hex()}")
    logger.info(f"Client ciphertext: {ciphertext.hex()}")

    # 6. Attacker decrypts command
    decrypted_by_attacker = decrypt_command(session_key_attacker_client, nonce, ciphertext)
    logger.info(f"Attacker decrypted command: {decrypted_by_attacker.decode()}")

    # 7. Attacker tampers command and re-encrypts for server
    tampered_command = b'LOCK'  # Tampered to LOCK command
    session_key_attacker_server = derive_aes_key(attacker_shared_with_server)
    nonce2, tampered_ciphertext = encrypt_command(session_key_attacker_server, tampered_command)
    logger.info(f"Attacker tampered command: {tampered_command.decode()}")
    logger.info(f"Tampered ciphertext: {tampered_ciphertext.hex()}")

    # 8. Server decrypts command
    session_key_server = derive_aes_key(server_shared)
    if is_nonce_used(nonce2):
        logger.error("Replay attack detected!")
        return
    decrypted_by_server = decrypt_command(session_key_server, nonce2, tampered_ciphertext)
    logger.info(f"Server final decrypted result: {decrypted_by_server.decode()}")
    if decrypted_by_server == b'LOCK':
        logger.info("Man-in-the-middle attack succeeded, command tampered!")
    else:
        logger.info("Man-in-the-middle attack failed!")

if __name__ == "__main__":
    main() 
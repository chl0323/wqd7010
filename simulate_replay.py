from crypto_utils import *
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    logger.info("=== Replay Attack Simulation ===")
    # 1. Generate ECC key pairs for client and server
    client_priv, client_pub = generate_ecc_keypair()
    server_priv, server_pub = generate_ecc_keypair()
    logger.info("Client and server key pairs generated")

    # 2. Exchange public keys
    client_pub_bytes = serialize_public_key(client_pub)
    server_pub_bytes = serialize_public_key(server_pub)
    logger.info(f"Client public key: {client_pub_bytes.hex()[:32]}...")
    logger.info(f"Server public key: {server_pub_bytes.hex()[:32]}...")
    client_peer_pub = deserialize_public_key(server_pub_bytes)
    server_peer_pub = deserialize_public_key(client_pub_bytes)
    logger.info("Public key exchange completed")

    # 3. ECDH derive shared secret
    client_shared = derive_shared_secret(client_priv, client_peer_pub)
    server_shared = derive_shared_secret(server_priv, server_peer_pub)
    assert client_shared == server_shared
    session_key = derive_aes_key(client_shared)
    logger.info(f"ECDH shared secret: {client_shared.hex()[:32]}...")
    logger.info(f"AES session key: {session_key.hex()[:32]}...")

    # 4. Client encrypts command
    command = b'UNLOCK'
    nonce, ciphertext = encrypt_command(session_key, command)
    logger.info(f"Nonce: {nonce.hex()}")
    logger.info(f"Ciphertext: {ciphertext.hex()}")

    # 5. Server first receives and decrypts command
    if is_nonce_used(nonce):
        logger.error("Replay attack detected!")
        return
    decrypted = decrypt_command(session_key, nonce, ciphertext)
    logger.info(f"Server first decrypted result: {decrypted.decode()}")
    assert decrypted == command
    logger.info("Command integrity verified!")

    # 6. Attacker replays the same nonce+ciphertext
    logger.info("Attacker replays the same nonce+ciphertext...")
    if is_nonce_used(nonce):
        logger.error("Server detected replay attack, rejected!")
    else:
        decrypted2 = decrypt_command(session_key, nonce, ciphertext)
        logger.info(f"Server decrypted result: {decrypted2.decode()}")

if __name__ == "__main__":
    main() 
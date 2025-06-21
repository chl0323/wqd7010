from crypto_utils import *
import logging
import time
import os
import psutil
import asyncio

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 1. Devices generate their own ECC key pairs
def generate_ecc_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

# 2. Public key serialization (simulating BLE transmission)
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

def deserialize_public_key(data):
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)

# 3. ECDH protocol: Both parties use the other party's public key and their own private key to calculate the shared key
def derive_shared_secret(private_key, peer_public_key):
    return private_key.exchange(ec.ECDH(), peer_public_key)

# 4. Use HKDF to derive the AES-GCM session key from the shared secret
def derive_aes_key(shared_secret):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit AES key
        salt=None,
        info=b'ble-vehicle-lock-session',
    )
    return hkdf.derive(shared_secret)

# 5. Use AES-GCM to encrypt command
def encrypt_command(aes_key, plaintext):
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # 96-bit nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext
    
# 6. Use AES-GCM to decrypt command
def decrypt_command(aes_key, nonce, ciphertext):
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)

# 7. Anti-replay attack: record used nonces
used_nonces = set()

def is_nonce_used(nonce):
    if nonce in used_nonces:
        return True
    used_nonces.add(nonce)
    return False

# 8. Simulate BLE pairing process
def simulate_ble_pairing():
    logger.info("Starting BLE pairing process...")
    # Simulate device discovery
    logger.info("Discovering devices...")
    time.sleep(1)
    # Simulate user confirmation
    logger.info("User confirms pairing...")
    time.sleep(1)
    logger.info("Pairing successful!")

# 9. Performance Analysis
def measure_performance(func, *args, **kwargs):
    start_time = time.time()
    result = func(*args, **kwargs)
    end_time = time.time()
    logger.info(f"{func.__name__} execution time: {end_time - start_time:.6f} seconds")
    return result

# 10. Resource Constraint Analysis
def measure_resources():
    process = psutil.Process(os.getpid())
    memory_info = process.memory_info()
    cpu_percent = process.cpu_percent(interval=1)
    logger.info(f"Memory usage: {memory_info.rss / 1024 / 1024:.2f} MB")
    logger.info(f"CPU usage: {cpu_percent}%")

# 11. BLE connection (using bleak room)
async def simulate_ble_communication():
    logger.info("Simulating BLE communication...")
    # Simulate client sending encrypted command
    logger.info("Client sends encrypted command...")
    time.sleep(1)
    # Simulate server receiving and decrypting command
    logger.info("Server receives and decrypts command...")
    time.sleep(1)
    logger.info("BLE communication simulation complete!")

# 12. Simulate attacks (MITM, replay attack)
def simulate_attacks():
    logger.info("Simulating attacks...")
    # Simulate Man-in-the-Middle attack
    logger.info("=== Man-in-the-Middle Attack Simulation ===")
    logger.info(f"Attacker intercepts client public key: {client_pub_bytes.hex()[:32]}...")
    logger.info(f"Attacker derives key with client: {attacker_shared_with_client.hex()[:32]}...")
    logger.info(f"Attacker decrypts command: {decrypted_by_attacker.decode()}")
    logger.info(f"Attacker tampers command to: {tampered_command.decode()}")
    logger.info(f"Server final decrypted result: {decrypted_by_server.decode()}")
    time.sleep(1)
    # Simulate replay attack
    logger.info("Simulating replay attack...")
    time.sleep(1)
    logger.info("Attack simulation complete!")

# 13. Generate report
def generate_report():
    logger.info("Generating report...")
    # Simulate report generation
    logger.info("Report generation complete!")

# --- Simulation Process ---

if __name__ == "__main__":
    # Simulate BLE pairing
    simulate_ble_pairing()

    # Step 1: Generate key pairs
    client_priv, client_pub = measure_performance(generate_ecc_keypair)
    lock_priv, lock_pub = measure_performance(generate_ecc_keypair)

    # Step 2: Public key exchange (serialization/deserialization simulating BLE transmission)
    client_pub_bytes = serialize_public_key(client_pub)
    lock_pub_bytes = serialize_public_key(lock_pub)

    client_peer_pub = deserialize_public_key(lock_pub_bytes)
    lock_peer_pub = deserialize_public_key(client_pub_bytes)

    # Step 3: ECDH compute shared secret
    client_shared = measure_performance(derive_shared_secret, client_priv, client_peer_pub)
    lock_shared = measure_performance(derive_shared_secret, lock_priv, lock_peer_pub)
    assert client_shared == lock_shared  # Both parties should get the same shared secret

    # Step 4: Derive AES-GCM session key
    session_key = measure_performance(derive_aes_key, client_shared)

    # Step 5: Client encrypts "UNLOCK" command
    command = b'UNLOCK'
    nonce, ciphertext = measure_performance(encrypt_command, session_key, command)
    logger.info(f"Client public key: {client_pub_bytes.hex()[:32]}...")
    logger.info(f"Server public key: {lock_pub_bytes.hex()[:32]}...")
    logger.info(f"ECDH shared secret: {client_shared.hex()[:32]}...")
    logger.info(f"AES session key: {session_key.hex()[:32]}...")
    logger.info(f"Nonce: {nonce.hex()}")
    logger.info(f"Ciphertext: {ciphertext.hex()}")

    # Anti-replay attack check
    if is_nonce_used(nonce):
        logger.error("Replay attack detected!")
    else:
        # Step 6: Lock decrypts and verifies command
        decrypted = measure_performance(decrypt_command, session_key, nonce, ciphertext)
        logger.info(f"Decryption result: {decrypted.decode()}")

        # Integrity check
        assert decrypted == command
        logger.info("Command integrity check passed!")

    # Resource constraint analysis
    measure_resources()

    # Simulate BLE communication
    asyncio.run(simulate_ble_communication())

    # Simulate attacks
    simulate_attacks()

    # Generate report
    generate_report() 

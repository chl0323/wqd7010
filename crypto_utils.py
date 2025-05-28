from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# 1. Generate ECC key pair
def generate_ecc_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

# 2. Public key serialization
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

def deserialize_public_key(data):
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)

# 3. ECDH derive shared secret
def derive_shared_secret(private_key, peer_public_key):
    return private_key.exchange(ec.ECDH(), peer_public_key)

# 4. Use HKDF to derive AES-GCM session key
def derive_aes_key(shared_secret):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit AES key
        salt=None,
        info=b'ble-vehicle-lock-session',
    )
    return hkdf.derive(shared_secret)

# 5. AES-GCM encryption/decryption
def encrypt_command(aes_key, plaintext):
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # 96-bit nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext

def decrypt_command(aes_key, nonce, ciphertext):
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)

# 6. Nonce management (anti-replay)
used_nonces = set()

def is_nonce_used(nonce):
    if nonce in used_nonces:
        return True
    used_nonces.add(nonce)
    return False 
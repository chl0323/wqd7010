from crypto_utils import *
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    logger.info("=== 正常安全通信流程模拟 ===")
    # 1. 客户端和服务器各自生成密钥对
    client_priv, client_pub = generate_ecc_keypair()
    server_priv, server_pub = generate_ecc_keypair()
    logger.info("客户端和服务器密钥对已生成")

    # 2. 交换公钥
    client_pub_bytes = serialize_public_key(client_pub)
    server_pub_bytes = serialize_public_key(server_pub)
    logger.info(f"客户端公钥: {client_pub_bytes.hex()[:32]}...")
    logger.info(f"服务器公钥: {server_pub_bytes.hex()[:32]}...")
    client_peer_pub = deserialize_public_key(server_pub_bytes)
    server_peer_pub = deserialize_public_key(client_pub_bytes)
    logger.info("公钥交换完成")

    # 3. ECDH 派生共享密钥
    client_shared = derive_shared_secret(client_priv, client_peer_pub)
    server_shared = derive_shared_secret(server_priv, server_peer_pub)
    assert client_shared == server_shared
    logger.info(f"ECDH 共享密钥: {client_shared.hex()[:32]}...")

    # 4. 派生 AES-GCM 会话密钥
    session_key = derive_aes_key(client_shared)
    logger.info(f"AES 会话密钥: {session_key.hex()[:32]}...")

    # 5. 客户端加密命令
    command = b'UNLOCK'
    nonce, ciphertext = encrypt_command(session_key, command)
    logger.info(f"Nonce: {nonce.hex()}")
    logger.info(f"密文: {ciphertext.hex()}")

    # 6. 服务器端解密命令
    if is_nonce_used(nonce):
        logger.error("检测到重放攻击！")
        return
    decrypted = decrypt_command(session_key, nonce, ciphertext)
    logger.info(f"服务器解密结果: {decrypted.decode()}")
    assert decrypted == command
    logger.info("命令完整性验证成功！")

if __name__ == "__main__":
    main() 
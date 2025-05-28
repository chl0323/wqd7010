from crypto_utils import *
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    logger.info("=== 中间人攻击模拟 ===")
    # 1. 客户端和服务器各自生成密钥对
    client_priv, client_pub = generate_ecc_keypair()
    server_priv, server_pub = generate_ecc_keypair()
    logger.info("客户端和服务器密钥对已生成")

    # 2. 攻击者生成自己的密钥对
    attacker_priv, attacker_pub = generate_ecc_keypair()
    logger.info("中间人攻击者密钥对已生成")

    # 3. 公钥交换时，攻击者拦截并替换公钥
    client_pub_bytes = serialize_public_key(client_pub)
    server_pub_bytes = serialize_public_key(server_pub)
    attacker_pub_bytes = serialize_public_key(attacker_pub)
    logger.info(f"客户端公钥: {client_pub_bytes.hex()[:32]}...")
    logger.info(f"服务器公钥: {server_pub_bytes.hex()[:32]}...")
    logger.info(f"攻击者公钥: {attacker_pub_bytes.hex()[:32]}...")
    client_peer_pub = attacker_pub
    server_peer_pub = attacker_pub

    # 4. 客户端与攻击者派生密钥，服务器与攻击者派生密钥
    client_shared = derive_shared_secret(client_priv, client_peer_pub)
    server_shared = derive_shared_secret(server_priv, server_peer_pub)
    attacker_shared_with_client = derive_shared_secret(attacker_priv, client_pub)
    attacker_shared_with_server = derive_shared_secret(attacker_priv, server_pub)
    logger.info(f"客户端与攻击者共享密钥: {client_shared.hex()[:32]}...")
    logger.info(f"服务器与攻击者共享密钥: {server_shared.hex()[:32]}...")
    logger.info(f"攻击者与客户端共享密钥: {attacker_shared_with_client.hex()[:32]}...")
    logger.info(f"攻击者与服务器共享密钥: {attacker_shared_with_server.hex()[:32]}...")

    # 5. 客户端加密命令（攻击者可解密）
    session_key_client = derive_aes_key(client_shared)
    session_key_attacker_client = derive_aes_key(attacker_shared_with_client)
    command = b'UNLOCK'
    nonce, ciphertext = encrypt_command(session_key_client, command)
    logger.info(f"Nonce: {nonce.hex()}")
    logger.info(f"客户端加密命令: {ciphertext.hex()}")

    # 6. 攻击者解密命令
    decrypted_by_attacker = decrypt_command(session_key_attacker_client, nonce, ciphertext)
    logger.info(f"中间人解密得到命令: {decrypted_by_attacker.decode()}")

    # 7. 攻击者可篡改命令并重新加密发给服务器
    tampered_command = b'LOCK'  # 篡改为LOCK命令
    session_key_attacker_server = derive_aes_key(attacker_shared_with_server)
    nonce2, tampered_ciphertext = encrypt_command(session_key_attacker_server, tampered_command)
    logger.info(f"中间人篡改命令为: {tampered_command.decode()}")
    logger.info(f"篡改后密文: {tampered_ciphertext.hex()}")

    # 8. 服务器解密命令
    session_key_server = derive_aes_key(server_shared)
    if is_nonce_used(nonce2):
        logger.error("检测到重放攻击！")
        return
    decrypted_by_server = decrypt_command(session_key_server, nonce2, tampered_ciphertext)
    logger.info(f"服务器最终解密结果: {decrypted_by_server.decode()}")
    if decrypted_by_server == b'LOCK':
        logger.info("中间人攻击成功，命令被篡改！")
    else:
        logger.info("中间人攻击未成功！")

if __name__ == "__main__":
    main() 
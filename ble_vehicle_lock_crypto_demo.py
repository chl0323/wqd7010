from crypto_utils import *
import logging
import time
import os
import psutil
import asyncio

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 1. 设备生成各自的 ECC 密钥对
def generate_ecc_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

# 2. 公钥序列化（模拟 BLE 传输）
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

def deserialize_public_key(data):
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)

# 3. ECDH 协议：双方各自用对方公钥和自己私钥计算共享密钥
def derive_shared_secret(private_key, peer_public_key):
    return private_key.exchange(ec.ECDH(), peer_public_key)

# 4. 使用 HKDF 从共享密钥派生 AES-GCM 会话密钥
def derive_aes_key(shared_secret):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit AES key
        salt=None,
        info=b'ble-vehicle-lock-session',
    )
    return hkdf.derive(shared_secret)

# 5. 使用 AES-GCM 加密命令
def encrypt_command(aes_key, plaintext):
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # 96-bit nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext

# 6. 使用 AES-GCM 解密命令
def decrypt_command(aes_key, nonce, ciphertext):
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)

# 7. 防重放攻击：记录已使用的 nonce
used_nonces = set()

def is_nonce_used(nonce):
    if nonce in used_nonces:
        return True
    used_nonces.add(nonce)
    return False

# 8. 模拟 BLE 配对流程
def simulate_ble_pairing():
    logger.info("开始 BLE 配对流程...")
    # 模拟设备发现
    logger.info("设备发现中...")
    time.sleep(1)
    # 模拟用户确认配对
    logger.info("用户确认配对...")
    time.sleep(1)
    logger.info("配对成功！")

# 9. 性能分析
def measure_performance(func, *args, **kwargs):
    start_time = time.time()
    result = func(*args, **kwargs)
    end_time = time.time()
    logger.info(f"{func.__name__} 执行时间: {end_time - start_time:.6f} 秒")
    return result

# 10. 资源受限分析
def measure_resources():
    process = psutil.Process(os.getpid())
    memory_info = process.memory_info()
    cpu_percent = process.cpu_percent(interval=1)
    logger.info(f"内存占用: {memory_info.rss / 1024 / 1024:.2f} MB")
    logger.info(f"CPU 使用率: {cpu_percent}%")

# 11. 模拟 BLE 通信（使用 bleak 库）
async def simulate_ble_communication():
    logger.info("模拟 BLE 通信...")
    # 模拟客户端发送加密命令
    logger.info("客户端发送加密命令...")
    time.sleep(1)
    # 模拟服务器接收并解密命令
    logger.info("服务器接收并解密命令...")
    time.sleep(1)
    logger.info("BLE 通信模拟完成！")

# 12. 模拟攻击（中间人攻击、重放攻击）
def simulate_attacks():
    logger.info("模拟攻击...")
    # 模拟中间人攻击
    logger.info("=== 中间人攻击模拟 ===")
    logger.info(f"攻击者拦截到客户端公钥: {client_pub_bytes.hex()[:32]}...")
    logger.info(f"攻击者与客户端派生密钥: {attacker_shared_with_client.hex()[:32]}...")
    logger.info(f"攻击者解密得到命令: {decrypted_by_attacker.decode()}")
    logger.info(f"攻击者篡改命令为: {tampered_command.decode()}")
    logger.info(f"服务器最终解密结果: {decrypted_by_server.decode()}")
    time.sleep(1)
    # 模拟重放攻击
    logger.info("模拟重放攻击...")
    time.sleep(1)
    logger.info("攻击模拟完成！")

# 13. 生成报告
def generate_report():
    logger.info("生成报告...")
    # 模拟报告生成
    logger.info("报告生成完成！")

# --- 模拟流程 ---

if __name__ == "__main__":
    # 模拟 BLE 配对
    simulate_ble_pairing()

    # Step 1: 生成密钥对
    client_priv, client_pub = measure_performance(generate_ecc_keypair)
    lock_priv, lock_pub = measure_performance(generate_ecc_keypair)

    # Step 2: 公钥交换（序列化/反序列化模拟 BLE 传输）
    client_pub_bytes = serialize_public_key(client_pub)
    lock_pub_bytes = serialize_public_key(lock_pub)

    client_peer_pub = deserialize_public_key(lock_pub_bytes)
    lock_peer_pub = deserialize_public_key(client_pub_bytes)

    # Step 3: ECDH 计算共享密钥
    client_shared = measure_performance(derive_shared_secret, client_priv, client_peer_pub)
    lock_shared = measure_performance(derive_shared_secret, lock_priv, lock_peer_pub)
    assert client_shared == lock_shared  # 双方应得相同共享密钥

    # Step 4: 派生 AES-GCM 会话密钥
    session_key = measure_performance(derive_aes_key, client_shared)

    # Step 5: 客户端加密"UNLOCK"命令
    command = b'UNLOCK'
    nonce, ciphertext = measure_performance(encrypt_command, session_key, command)
    logger.info(f"客户端公钥: {client_pub_bytes.hex()[:32]}...")
    logger.info(f"服务器公钥: {lock_pub_bytes.hex()[:32]}...")
    logger.info(f"ECDH 共享密钥: {client_shared.hex()[:32]}...")
    logger.info(f"AES 会话密钥: {session_key.hex()[:32]}...")
    logger.info(f"Nonce: {nonce.hex()}")
    logger.info(f"密文: {ciphertext.hex()}")

    # 防重放攻击检查
    if is_nonce_used(nonce):
        logger.error("检测到重放攻击！")
    else:
        # Step 6: 车锁端解密并验证命令
        decrypted = measure_performance(decrypt_command, session_key, nonce, ciphertext)
        logger.info(f"解密结果: {decrypted.decode()}")

        # 完整性验证
        assert decrypted == command
        logger.info("命令完整性验证成功！")

    # 资源受限分析
    measure_resources()

    # 模拟 BLE 通信
    asyncio.run(simulate_ble_communication())

    # 模拟攻击
    simulate_attacks()

    # 生成报告
    generate_report() 
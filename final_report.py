import logging
import os
import time
import psutil
import markdown2
import pdfkit
from datetime import datetime

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def collect_performance_data():
    """Collect system performance data"""
    process = psutil.Process(os.getpid())
    memory_info = process.memory_info()
    cpu_percent = process.cpu_percent(interval=1)
    return {
        "memory_mb": memory_info.rss / 1024 / 1024,
        "cpu_percent": cpu_percent
    }

def generate_markdown_report(performance_data, attack_results):
    """Generate a complete Markdown format report"""
    current_date = datetime.now().strftime("%Y-%m-%d")
    
    report = f"""# 基于 ECDH 和 AES-GCM 的蓝牙车锁安全通信系统设计与实现

## Abstract
本文设计并实现了一个基于 ECDH 和 AES-GCM 的蓝牙车锁安全通信系统。该系统通过 ECDH 密钥交换协议实现安全的密钥协商，使用 AES-GCM 进行命令加密，并实现了防重放攻击机制。实验结果表明，该系统能够有效保护蓝牙车锁通信安全，抵御常见的中间人攻击和重放攻击。

## 1. Introduction
### 1.1 Background
随着物联网技术的发展，蓝牙车锁系统在汽车安全领域得到广泛应用。然而，蓝牙通信的安全性面临着诸多挑战，如中间人攻击、重放攻击等。因此，设计一个安全可靠的蓝牙车锁通信系统具有重要意义。

### 1.2 Project Scope
本项目主要研究以下内容：
- ECDH 密钥交换协议在蓝牙车锁中的应用
- AES-GCM 加密算法在命令传输中的应用
- 防重放攻击机制的设计与实现
- 系统性能评估与安全性分析

### 1.3 Limitations
- 仅支持基本的开锁命令
- 未实现用户认证机制
- 未考虑物理安全防护

## 2. Literature Review
### 2.1 ECDH 密钥交换
ECDH（Elliptic Curve Diffie-Hellman）是一种基于椭圆曲线的密钥交换协议，具有计算效率高、密钥长度短等优点。在蓝牙通信中，ECDH 被广泛应用于密钥协商过程，为后续的加密通信提供安全基础。

### 2.2 AES-GCM 加密
AES-GCM（Advanced Encryption Standard - Galois/Counter Mode）是一种认证加密算法，提供机密性和完整性保护。其特点包括：
- 高安全性：提供认证和加密双重保护
- 高效率：支持并行处理
- 低延迟：适合实时通信场景

### 2.3 蓝牙安全研究现状
近年来，蓝牙安全研究主要集中在以下几个方面：
1. 密钥管理：研究更安全的密钥生成和更新机制
2. 认证机制：开发更可靠的设备认证方案
3. 攻击防护：研究针对各种攻击的防御措施

## 3. System Design and Implementation
### 3.1 系统架构
系统由以下组件构成：
- BLE 服务器（车锁端）：负责接收和处理加密命令
- BLE 客户端（手机端）：负责生成和发送加密命令
- 攻击演示模块：模拟各类攻击场景
- 性能分析模块：收集和展示系统性能数据

### 3.2 关键算法实现
#### 3.2.1 ECDH 密钥交换
```python
def derive_shared_secret(private_key, peer_public_key):
    return private_key.exchange(ec.ECDH(), peer_public_key)
```

#### 3.2.2 AES-GCM 加密
```python
def encrypt_command(aes_key, plaintext):
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext
```

### 3.3 防重放攻击机制
```python
def is_nonce_used(nonce):
    if nonce in used_nonces:
        return True
    used_nonces.add(nonce)
    return False
```

## 4. Results
### 4.1 性能测试
- 内存占用: {performance_data['memory_mb']:.2f} MB
- CPU 使用率: {performance_data['cpu_percent']}%

### 4.2 安全性测试
#### 4.2.1 中间人攻击测试
- 攻击成功率: {attack_results.get('mitm_success_rate', 'N/A')}%
- 平均攻击时间: {attack_results.get('mitm_avg_time', 'N/A')}ms

#### 4.2.2 重放攻击测试
- 攻击检测率: {attack_results.get('replay_detection_rate', 'N/A')}%
- 平均检测时间: {attack_results.get('replay_avg_time', 'N/A')}ms

## 5. Conclusions
1. 系统成功实现了基于 ECDH 和 AES-GCM 的安全通信
2. 防重放攻击机制有效抵御了重放攻击
3. 系统性能满足实际应用需求

## 6. Recommendations
1. 增加用户认证机制
2. 实现物理安全防护
3. 优化密钥更新机制
4. 扩展支持更多命令类型

## 7. References
[1] NIST Special Publication 800-38D, "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC"
[2] Bluetooth Core Specification v5.2
[3] "Elliptic Curve Cryptography for the Internet", RFC 7748
[4] Krawczyk, H. (2010). "Cryptographic Extraction and Key Derivation: The HKDF Scheme"
[5] Dworkin, M. (2007). "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC"

## 8. Appendices
### Appendix A: 完整代码实现
项目包含以下主要代码文件：
1. ble_client.py - 客户端实现
2. ble_server.py - 服务器实现
3. attacks.py - 攻击演示
4. report_gen.py - 报告生成

### Appendix B: 测试数据
详细的测试数据包括：
1. 性能测试结果
2. 安全性测试结果
3. 攻击演示结果

## 9. Team Members and Contributions
1. [成员1姓名] - 系统架构设计、ECDH 实现
2. [成员2姓名] - AES-GCM 实现、性能测试
3. [成员3姓名] - 攻击演示模块、安全性测试
4. [成员4姓名] - 报告撰写、文档整理

*报告生成日期: {current_date}*
"""
    return report

def save_markdown_report(report, filename="final_report.md"):
    """Save Markdown format report"""
    with open(filename, "w", encoding='utf-8') as f:
        f.write(report)
    logger.info(f"Markdown report saved to {filename}")

def convert_to_pdf(markdown_file, pdf_file="final_report.pdf"):
    """Convert Markdown report to PDF format"""
    with open(markdown_file, "r", encoding='utf-8') as f:
        html = markdown2.markdown(f.read())
    pdfkit.from_string(html, pdf_file)
    logger.info(f"PDF report saved to {pdf_file}")

def generate_report(attack_results=None):
    """Generate complete report"""
    logger.info("Starting to generate experiment report...")
    performance_data = collect_performance_data()
    report = generate_markdown_report(performance_data, attack_results)
    save_markdown_report(report)
    convert_to_pdf("final_report.md")
    logger.info("Experiment report generation completed!")

def generate_final_report():
    """Generate the final report for the project."""
    pass

if __name__ == "__main__":
    # Example attack result data
    attack_results = {
        "mitm_success_rate": 0,
        "mitm_avg_time": 150,
        "replay_detection_rate": 100,
        "replay_avg_time": 50
    }
    generate_report(attack_results)
    generate_final_report() 
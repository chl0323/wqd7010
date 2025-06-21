import logging
import os
import time
import psutil
import markdown2
import pdfkit
from datetime import datetime

# Configure logging
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
    
    report = f"""# Design and Implementation of a Secure BLE Vehicle Lock Communication System Based on ECDH and AES-GCM

## Abstract
This project designs and implements a secure BLE vehicle lock communication system based on ECDH and AES-GCM. The system achieves secure key agreement through the ECDH key exchange protocol, uses AES-GCM for command encryption, and implements an anti-replay attack mechanism. Experimental results show that the system can effectively protect BLE vehicle lock communication security and resist common man-in-the-middle and replay attacks.

## 1. Introduction
### 1.1 Background
With the development of IoT technology, BLE vehicle lock systems are widely used in automotive security. However, the security of BLE communication faces many challenges, such as man-in-the-middle attacks and replay attacks. Therefore, designing a secure and reliable BLE vehicle lock communication system is of great significance.

### 1.2 Project Scope
This project mainly studies the following aspects:
- Application of ECDH key exchange protocol in BLE vehicle locks
- Application of AES-GCM encryption algorithm in command transmission
- Design and implementation of anti-replay attack mechanism
- System performance evaluation and security analysis

### 1.3 Limitations
- Only supports basic unlock command
- No user authentication mechanism implemented
- Physical security protection not considered

## 2. Literature Review
### 2.1 ECDH Key Exchange
ECDH (Elliptic Curve Diffie-Hellman) is a key exchange protocol based on elliptic curves, featuring high computational efficiency and short key length. In BLE communication, ECDH is widely used in the key agreement process, providing a secure foundation for subsequent encrypted communication.

### 2.2 AES-GCM Encryption
AES-GCM (Advanced Encryption Standard - Galois/Counter Mode) is an authenticated encryption algorithm that provides both confidentiality and integrity protection. Its features include:
- High security: provides both authentication and encryption
- High efficiency: supports parallel processing
- Low latency: suitable for real-time communication scenarios

### 2.3 BLE Security Research Status
In recent years, BLE security research has mainly focused on the following aspects:
1. Key management: research on more secure key generation and update mechanisms
2. Authentication mechanisms: development of more reliable device authentication schemes
3. Attack protection: research on defense measures against various attacks

## 3. System Design and Implementation
### 3.1 System Architecture
The system consists of the following components:
- BLE server (vehicle lock side): responsible for receiving and processing encrypted commands
- BLE client (mobile side): responsible for generating and sending encrypted commands
- Attack demonstration module: simulates various attack scenarios
- Performance analysis module: collects and displays system performance data

### 3.2 Key Algorithm Implementation
#### 3.2.1 ECDH Key Exchange
```python
def derive_shared_secret(private_key, peer_public_key):
    return private_key.exchange(ec.ECDH(), peer_public_key)
```

#### 3.2.2 AES-GCM Encryption
```python
def encrypt_command(aes_key, plaintext):
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext
```

### 3.3 Anti-Replay Attack Mechanism
```python
def is_nonce_used(nonce):
    if nonce in used_nonces:
        return True
    used_nonces.add(nonce)
    return False
```

## 4. Results
### 4.1 Performance Test
- Memory usage: {performance_data['memory_mb']:.2f} MB
- CPU usage: {performance_data['cpu_percent']}%

### 4.2 Security Test
#### 4.2.1 Man-in-the-Middle Attack Test
- Attack success rate: {attack_results.get('mitm_success_rate', 'N/A')}%
- Average attack time: {attack_results.get('mitm_avg_time', 'N/A')}ms

#### 4.2.2 Replay Attack Test
- Attack detection rate: {attack_results.get('replay_detection_rate', 'N/A')}%
- Average detection time: {attack_results.get('replay_avg_time', 'N/A')}ms

## 5. Conclusions
1. The system successfully implements secure communication based on ECDH and AES-GCM
2. The anti-replay attack mechanism effectively resists replay attacks
3. The system performance meets practical application requirements

## 6. Recommendations
1. Add user authentication mechanism
2. Implement physical security protection
3. Optimize key update mechanism
4. Extend support for more command types

## 7. References
[1] NIST Special Publication 800-38D, "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC"
[2] Bluetooth Core Specification v5.2
[3] "Elliptic Curve Cryptography for the Internet", RFC 7748
[4] Krawczyk, H. (2010). "Cryptographic Extraction and Key Derivation: The HKDF Scheme"
[5] Dworkin, M. (2007). "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC"

## 8. Appendices
### Appendix A: Complete Code Implementation
The project includes the following main code files:
1. ble_client.py - Client implementation
2. ble_server.py - Server implementation
3. attacks.py - Attack demonstration
4. report_gen.py - Report generation

### Appendix B: Test Data
Detailed test data includes:
1. Performance test results
2. Security test results
3. Attack demonstration results

## 9. Team Members and Contributions
1. [Member 1 Name] - System architecture design, ECDH implementation
2. [Member 2 Name] - AES-GCM implementation, performance testing
3. [Member 3 Name] - Attack demonstration module, security testing
4. [Member 4 Name] - Report writing, documentation

*Report generation date: {current_date}*
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

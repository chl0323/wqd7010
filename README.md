# WQD7010 Network & Security
## Group Assignment – Secure Communication in Bluetooth Vehicle Locks: A Cryptographic Demonstration Using ECDH and AES

### Semester 2, 2024/2025

---

## Project Overview
This project, under the theme "Recent issues in network security," simulates and analyzes the secure communication process of Bluetooth vehicle locks. It uses modern cryptographic techniques (ECDH key exchange, AES-GCM encryption, anti-replay mechanism) and implements normal communication, man-in-the-middle attack, and replay attack scenarios in pure Python code.

---

## Directory Structure
```
ble_crypto_demo/
├── crypto_utils.py         # Cryptographic utility functions
├── simulate_normal.py      # Normal communication simulation
├── simulate_mitm.py        # Man-in-the-middle attack simulation
├── simulate_replay.py      # Replay attack simulation
├── requirements.txt        # Dependencies
├── README.md               # Project documentation (this file)
└── report_gen.py           # Report generation
```

---

## Environment & Dependencies
- Python 3.8+
- cryptography
- psutil
- markdown2
- pdfkit

Install dependencies:
```bash
pip install -r requirements.txt
```

---

## Script Descriptions
- **crypto_utils.py**: Encapsulates key generation, encryption/decryption, and nonce management.
- **simulate_normal.py**: Simulates the full secure communication process between client and server, including key exchange, encryption, decryption, and integrity verification.
- **simulate_mitm.py**: Simulates a man-in-the-middle attack where the attacker intercepts and replaces public keys, decrypts, and tampers with commands.
- **simulate_replay.py**: Simulates a replay attack where the attacker replays a captured valid ciphertext, and the server detects and rejects it.
- **report_gen.py**: Automatically generates an experiment report (Markdown/PDF) for coursework submission.

---

## How to Run
- **Normal secure communication**
  ```bash
  python simulate_normal.py
  ```
- **Man-in-the-middle attack simulation**
  ```bash
  python simulate_mitm.py
  ```
- **Replay attack simulation**
  ```bash
  python simulate_replay.py
  ```
- **Generate experiment report**
  ```bash
  python report_gen.py
  ```

---

## Example Output
Running `python simulate_normal.py` will show detailed logs, including public keys, shared secrets, session keys, nonce, ciphertext, and decrypted results, which are useful for analysis and reporting.

---

## References
Please add IEEE-formatted references in your final report and this README.

---

## Notes
- All communication in this project is simulated in memory; no real Bluetooth stack is involved.
- Do not plagiarize; all code and reports must be original to your group.
- For real BLE communication, refer to libraries like bleak and use actual hardware.

---

## Submission Instructions
- File name format: `groupleadername-groupname.zip`
- Include all code, report, README, and dependency files
- Submit via the spectrum platform as required by the course 

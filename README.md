# WQD7010 Network & Security
## Group Assignment – Secure Communication in Bluetooth Vehicle Locks: A Cryptographic Demonstration Using ECDH and AES

### Semester 2, 2024/2025

---

## 项目简介
本项目以"Recent techniques in cryptography and its application"为主题，模拟并分析了蓝牙车锁场景下的安全通信流程。采用现代密码学技术（ECDH 密钥交换、AES-GCM 加密、防重放机制），用 Python 纯代码实现了正常通信、中间人攻击、重放攻击等流程，便于教学、实验和论文撰写。

---

## 目录结构
```
ble_crypto_demo/
├── crypto_utils.py         # 密码学通用函数
├── simulate_normal.py      # 正常通信流程模拟
├── simulate_mitm.py        # 中间人攻击模拟
├── simulate_replay.py      # 重放攻击模拟
├── requirements.txt        # 依赖
├── README.md               # 项目说明（本文件）
└── report_gen.py           # 报告生成
```

---

## 运行环境与依赖
- Python 3.8+
- cryptography
- psutil
- markdown2
- pdfkit

安装依赖：
```bash
pip install -r requirements.txt
```

---

## 各脚本功能说明
- **crypto_utils.py**：封装密钥生成、加解密、nonce管理等通用函数。
- **simulate_normal.py**：模拟客户端与服务器安全通信全过程，展示密钥交换、加密、解密、完整性验证。
- **simulate_mitm.py**：模拟中间人攻击，攻击者拦截并替换公钥，能解密和篡改通信。
- **simulate_replay.py**：模拟重放攻击，攻击者重放已捕获的合法密文，服务器检测到重放并拒绝。
- **report_gen.py**：自动生成实验报告（Markdown/PDF），便于课程作业提交。

---

## 运行方法
- **正常安全通信流程**
  ```bash
  python simulate_normal.py
  ```
- **中间人攻击模拟**
  ```bash
  python simulate_mitm.py
  ```
- **重放攻击模拟**
  ```bash
  python simulate_replay.py
  ```
- **生成实验报告**
  ```bash
  python report_gen.py
  ```

---

## 输出示例
运行 `python simulate_normal.py`，你会看到详细日志，包括公钥、共享密钥、会话密钥、nonce、密文、解密结果等，便于分析和写报告。

---

## 团队成员与分工
请在最终报告和本 README 中补充如下内容：

| 姓名         | 学号      | 主要贡献                         |
| ------------ | --------- | -------------------------------- |
| 组长A        | xxxxxxxx  | 项目统筹、报告撰写、代码审核     |
| 组员B        | xxxxxxxx  | ECDH/AES-GCM 实现、性能测试      |
| 组员C        | xxxxxxxx  | 攻击模拟、日志优化、数据分析     |
| 组员D        | xxxxxxxx  | 文档整理、参考文献、排版         |
| ...          | ...       | ...                              |

---

## 参考文献
请在最终报告和本 README 中补充 IEEE 格式参考文献。

---

## 注意事项
- 本项目所有通信均为内存模拟，不涉及真实蓝牙协议栈。
- 请勿抄袭，所有代码和报告需为小组原创。
- 如需 BLE 物理通信，请参考 bleak 等库并结合真实硬件。

---

## 提交说明
- 提交文件名格式：`groupleadername-groupname.zip`
- 包含所有代码、报告、README、依赖文件等
- 按课程要求在 spectrum 平台提交 
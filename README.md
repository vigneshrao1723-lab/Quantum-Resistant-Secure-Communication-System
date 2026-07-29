# 🔐 Quantum-Resistant Secure Communication System

> A secure multi-client chat application built with Python that demonstrates modern cryptographic communication using RSA, AES-256, and a modular architecture designed for Post-Quantum Cryptography integration.

![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)
![PySide6](https://img.shields.io/badge/PySide6-GUI-green.svg)
![AES-256](https://img.shields.io/badge/AES--256-Secure-orange.svg)
![RSA](https://img.shields.io/badge/RSA-Key%20Exchange-red.svg)
![Status](https://img.shields.io/badge/Status-Working-success.svg)

---

# 📖 Overview

The **Quantum-Resistant Secure Communication System** is a desktop-based secure messaging application developed as a Final Year Computer Science Engineering Project.

The application provides encrypted communication between multiple clients over a TCP network using:

- RSA Public Key Cryptography
- AES-256 Symmetric Encryption
- Secure Session Key Exchange
- Multi-client Architecture
- Real-time Online User Synchronization

The project is designed with a modular cryptographic architecture, making it easy to replace RSA with **Kyber (ML-KEM)** to achieve Post-Quantum Security.

---

# ✨ Features

## 🔑 Secure Authentication

- Username-based login
- Automatic client registration
- Multi-client support

---

## 🔐 Secure Cryptography

- RSA Public Key Exchange
- AES-256 Encrypted Messaging
- Automatic Secure Session Establishment
- Modular Crypto Layer

---

## 💬 Real-Time Chat

- Private one-to-one messaging
- Automatic online user updates
- Join/Leave notifications
- Real-time message delivery

---

## 🖥️ Modern GUI

Built using **PySide6 (Qt for Python)**

Features include:

- Login Window
- Chat Window
- Online Users Panel
- Secure Message View
- Status Bar
- Dark Theme UI

---

## 📊 Logging

Separate logs for

- Client
- Server

Useful for debugging and monitoring.

---

# 🏗️ Project Structure

```
Quantum-Resistant-Secure-Communication-System/
│
├── client/
│   ├── client.py
│   ├── receiver.py
│   ├── sender.py
│   └── session.py
│
├── server/
│   ├── server.py
│   ├── broadcaster.py
│   ├── client_handler.py
│   └── server_state.py
│
├── crypto/
│   ├── aes.py
│   ├── rsa.py
│   ├── kyber.py
│   └── key_manager.py
│
├── gui/
│   ├── login_window.py
│   ├── chat_window.py
│   ├── main_window.py
│   ├── message_widget.py
│   ├── online_users_widget.py
│   ├── input_bar.py
│   ├── status_bar.py
│   └── styles.py
│
├── database/
│
├── logs/
│
├── screenshots/
│
├── docs/
│
├── utils/
│
├── config.py
├── logger_config.py
├── main.py
└── README.md
```

---

# 🔄 Communication Flow

```
Client A
     │
     ▼
RSA Public Key Exchange
     │
     ▼
Encrypted AES Session Key
     │
     ▼
AES-256 Secure Messaging
     │
     ▼
Client B
```

---

# 🛠️ Technologies Used

| Technology | Purpose |
|------------|---------|
| Python 3.12+ | Programming Language |
| PySide6 | Desktop GUI |
| Socket Programming | Client-Server Communication |
| RSA | Public Key Exchange |
| AES-256 | Message Encryption |
| JSON | Packet Serialization |
| Threading | Concurrent Communication |
| Logging | Monitoring & Debugging |

---

# 🚀 Installation

Clone the repository

```bash
git clone https://github.com/your-username/Quantum-Resistant-Secure-Communication-System.git
```

Move into the project

```bash
cd Quantum-Resistant-Secure-Communication-System
```

Create a virtual environment

```bash
python -m venv venv
```

Activate it

### Windows

```bash
venv\Scripts\activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

# ▶️ Running the Project

## Start the Server

```bash
python -m server.server
```

---

## Start Client 1

```bash
python main.py
```

---

## Start Client 2

```bash
python main.py
```

---

# 📸 Screenshots

Add screenshots inside

```
screenshots/
```

Suggested images:

- Login Screen
- Chat Window
- Online Users
- Multiple Clients
- Secure Messaging

---

# 🔒 Security Features

- RSA Public Key Cryptography
- AES-256 Encryption
- Secure Session Keys
- Private Messaging
- Multi-client Communication
- Automatic Key Exchange

---

# 🔮 Future Enhancements

- ✅ Kyber (ML-KEM) Post-Quantum Key Exchange
- Digital Signatures
- Encrypted File Transfer
- User Authentication
- Chat History Database
- Group Chat
- Voice Communication
- End-to-End Encryption
- Performance Benchmark Dashboard

---

# 📈 Current Project Status

| Module | Status |
|---------|--------|
| Multi-client Server | ✅ Complete |
| GUI | ✅ Complete |
| Online User Synchronization | ✅ Complete |
| RSA Key Exchange | ✅ Complete |
| AES Secure Messaging | ✅ Complete |
| Session Management | ✅ Complete |
| Logging | ✅ Complete |
| Kyber Integration | 🚧 In Progress |

---

# 👨‍💻 Author

**Vignesh Thiyagarajan**

Computer Science & Engineering

Acharya Institute of Technology


---

# 📜 License

This project is developed for educational and research purposes as part of a Final Year Engineering Project.

---

⭐ If you found this project interesting, consider giving it a star!
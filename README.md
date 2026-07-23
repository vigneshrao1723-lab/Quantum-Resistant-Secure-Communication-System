# Quantum-Resistant Secure Communication System

A secure multi-client communication system developed as a Final Year Project using Python. The project combines classical cryptography with Post-Quantum Cryptography (PQC) to demonstrate secure communication against both classical and future quantum computing attacks.

---

## Project Overview

This project implements a client-server communication system that supports multiple users communicating securely over a network. The system is being developed in multiple modules, beginning with TCP socket communication and gradually integrating encryption, logging, benchmarking, and post-quantum cryptographic algorithms.

The final implementation will support both traditional RSA-based key exchange and quantum-resistant Kyber key encapsulation, enabling performance comparison between classical and post-quantum approaches.

---

## Features

### Completed

- Multi-client TCP socket communication
- Username-based chat system
- Professional server logging
- Professional client logging
- Modular project architecture
- Git version control
- GitHub integration

### Upcoming

- AES-256 encrypted messaging
- RSA secure key exchange
- Kyber Post-Quantum Key Exchange
- Secure session key management
- Graphical User Interface (PyQt6)
- Performance benchmarking
- Security analysis
- End-to-End Encryption
- Final documentation and report

---

## Project Structure

```
Quantum-Resistant-Secure-Communication-System/
│
├── client/
│   ├── client.py
│   ├── config.py
│   └── __init__.py
│
├── server/
│   ├── server.py
│   ├── config.py
│   └── __init__.py
│
├── crypto/
│   ├── aes.py
│   ├── rsa.py
│   ├── kyber.py
│   └── key_manager.py
│
├── logs/
│   ├── client.log
│   └── server.log
│
├── benchmark/
├── database/
├── docs/
├── gui/
├── screenshots/
├── tests/
│
├── logger_config.py
├── requirements.txt
├── README.md
└── .gitignore
```

---

## Technologies Used

### Programming Language

- Python 3.13

### Networking

- Python Socket Programming
- Multi-threading

### Cryptography

- AES-256
- RSA
- Kyber (Post-Quantum Cryptography)

### Libraries

- cryptography
- pycryptodome
- matplotlib
- pandas
- psutil
- memory_profiler
- PyQt6

### Development Tools

- Visual Studio Code
- Git
- GitHub

---

## Current Development Progress

| Module | Status |
|----------|--------|
| Module 1 - TCP Client-Server Communication | Completed |
| Module 2 - Multi-client Communication | Completed |
| Module 3 - Username Support | Completed |
| Module 3.5 - Professional Logging | Completed |
| Module 4 - AES Secure Communication | In Progress |
| Module 5 - RSA Key Exchange | Planned |
| Module 6 - Kyber Post-Quantum Key Exchange | Planned |
| Module 7 - GUI Development | Planned |
| Module 8 - Benchmarking | Planned |
| Module 9 - Final Documentation | Planned |

---

## Installation

Clone the repository

```bash
git clone https://github.com/vigneshrao1723-lab/Quantum-Resistant-Secure-Communication-System.git
```

Move into the project directory

```bash
cd Quantum-Resistant-Secure-Communication-System
```

Create a virtual environment

```bash
python -m venv venv
```

Activate the virtual environment

### Windows

```bash
venv\Scripts\activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

## Running the Project

Start the server

```bash
cd server
python server.py
```

Start one or more clients

```bash
cd client
python client.py
```

---

## Future Scope

- End-to-End Encryption
- Secure File Transfer
- Voice Communication
- Video Communication
- Digital Signatures
- Authentication System
- Secure Database Storage
- Quantum-safe Secure Messaging

---

## Author

**Vignesh T**

Bachelor of Engineering (Computer Science & Engineering)

Acharya Institute of Technology

Bengaluru, India

---

## License

This project is developed for educational and research purposes as part of a Final Year Engineering Project.
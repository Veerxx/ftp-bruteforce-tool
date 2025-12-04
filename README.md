# 🔓 FTP Brute Force Tool - Advanced Edition

![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)

**Ultra Modern FTP Brute Force Tool** with multi-protocol support, session management, encryption, and advanced scanning capabilities. Designed for security professionals and penetration testers.

**Author: Veer** | **Signature: DO NOT EDIT**

---

## ✨ Features

### 🔥 Core Features
- **Multi-Protocol Support**: FTP, FTPS (SSL/TLS), FTPES (Explicit SSL), SFTP
- **Advanced Session Management**: Save/Resume scans, track progress
- **Smart Brute Forcing**: Rate limiting, duplicate filtering, connection pooling
- **Vulnerability Assessment**: Anonymous login check, directory traversal detection
- **File Enumeration**: Automatic directory listing and permission checking

### 🛡️ Security & Privacy
- **Encrypted Results**: Optional Fernet encryption for sensitive data
- **Session Encryption**: Secure storage of scanned credentials
- **Rate Limiting**: Avoid detection with controlled request timing
- **Proxy Support**: Route connections through proxies

### 📊 Reporting & Output
- **JSON Reports**: Structured output with full statistics
- **HTML Reports**: Visual reports with charts (optional)
- **Real-time Progress**: Live progress tracking
- **Color-coded Output**: Easy-to-read console interface
- **Multiple Log Levels**: Detailed debugging information

### ⚡ Performance
- **Multi-threading**: Configurable thread count (1-100+)
- **Connection Pooling**: Efficient resource management
- **Memory Efficient**: Processes large wordlists without loading all into memory
- **Resume Capability**: Continue interrupted scans

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/Veerxx/ftp-bruteforce-tool.git
cd ftp-bruteforce-tool

# Run installation script
chmod +x install.sh
./install.sh

# Or manually install dependencies
pip3 install -r requirements.txt

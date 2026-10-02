# 🎯 BlackHunter Pro

**Academic Penetration Testing Tool - Isolated Lab Environment Only**

![Version](https://img.shields.io/badge/version-1.0.0-red)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/platform-Termux-green)
![License](https://img.shields.io/badge/license-Academic-orange)

---

## 📖 Overview

**BlackHunter Pro** is a comprehensive, powerful, and professional web security assessment and exploitation tool designed specifically for **Termux (Android)**. It combines the power of **Python** for logic and orchestration with **C/C++** for high-performance native modules.

Built for **academic cybersecurity research** and **graduation projects** in isolated lab environments.

---

## ✨ Features

### 🔍 Reconnaissance & Scanning
- DNS Resolution (A, AAAA, MX, NS, TXT, CNAME, SOA)
- WHOIS Lookup
- HTTP Headers Analysis
- Security Headers Check
- Technology Detection (CMS, JS, CDN, Analytics)
- SSL/TLS Certificate Analysis
- robots.txt & sitemap.xml Parsing
- Subdomain Enumeration
- Port Scanning (TCP/UDP) - **Powered by C**
- Service Banner Grabbing - **Powered by C**
- Directory & File Bruteforce
- HTTP Methods Testing
- Parameter Discovery

### 💉 Vulnerability Detection
| Module | Detects | Severity |
|--------|---------|----------|
| **SQL Injection** | Error, Union, Boolean, Time-based | CRITICAL |
| **XSS** | Reflected, Stored, DOM-based | MEDIUM |
| **LFI/RFI** | Path Traversal, PHP Wrappers | HIGH |
| **Command Injection** | Linux & Windows | CRITICAL |
| **SSRF** | Basic, Blind, Cloud Metadata | HIGH |
| **File Upload** | Extension/MIME/Path Bypass | CRITICAL |
| **XXE** | XML External Entity | HIGH |
| **CSRF** | Cross-Site Request Forgery | MEDIUM |
| **IDOR** | Insecure Direct Object Reference | HIGH |
| **Open Redirect** | URL Redirection | LOW |

### 📦 CMS-Specific Scanners
- **WordPress**: Version, users, plugins, themes, XML-RPC, CVEs
- **Joomla**: Version, components, config exposure, CVEs
- **Craft CMS**: Version, plugins, GraphQL, CVEs
- **Drupal**: Version detection, module enumeration
- **Magento**: Detection, admin panel
- **PrestaShop**: Version, modules

### ⚔️ Exploitation (Isolated Lab Only)
- SQL Injection data extraction
- LFI file reading
- Command injection execution
- XSS payload delivery
- SSRF internal access
- File upload web shells
- Session management
- Post-exploitation modules

### 🎛️ C2 Server
- TLS Encrypted communication
- Web UI dashboard
- Multi-client management
- Command execution
- File transfer
- Session logging

### 📊 Reporting
- JSON report (machine-readable)
- HTML report (professional dark theme)
- PDF report (optional)
- CVSS scoring
- Detailed vulnerability information

---

## 🛠️ Installation

### Termux (Android)

```bash
# Clone the repository
git clone https://github.com/enma404/BlackHunter.git
cd BlackHunter

# Make scripts executable
chmod +x setup.sh blackhunter.sh

# Run setup (installs all dependencies)
./setup.sh

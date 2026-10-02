# 🏗️ BlackHunter Pro - Architecture Documentation

**Academic Penetration Testing Tool - Isolated Lab Environment Only**

---

## 📖 Table of Contents

1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Component Diagram](#component-diagram)
4. [Data Flow](#data-flow)
5. [Module Breakdown](#module-breakdown)
6. [Communication Protocol](#communication-protocol)
7. [Database Schema](#database-schema)
8. [Security Model](#security-model)
9. [Deployment](#deployment)
10. [Performance](#performance)

---

## 📌 Overview

**BlackHunter Pro** is a modular, high-performance penetration testing suite designed for Termux (Android), Linux, and macOS. It combines **Python** for orchestration and logic with **C/C++** for performance-critical operations.

### Key Design Principles

| Principle | Description |
|-----------|-------------|
| **Modularity** | Each component is independent and replaceable |
| **Performance** | C/C++ for intensive tasks (scanning, cracking) |
| **Extensibility** | Easy to add new scanners and exploits |
| **Stealth** | Obfuscation and anti-forensics built-in |
| **Ethics** | Guardrails prevent misuse |

---

## 🏛️ System Architecture

### High-Level Architecture

┌─────────────────────────────────────────────────────────────────┐
│ BlackHunter Pro │
├─────────────────────────────────────────────────────────────────┤
│ │
│ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ │
│ │ Launcher │ │ Web UI │ │ CLI Mode │ │
│ │ blackhunter.sh│ │ (Flask) │ │ (Python) │ │
│ └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ │
│ │ │ │ │
│ └─────────────────┼─────────────────┘ │
│ │ │
│ ┌──────▼───────┐ │
│ │ Core │ │
│ │ (Python) │ │
│ └──────┬───────┘ │
│ │ │
│ ┌─────────────────┼─────────────────┐ │
│ │ │ │ │
│ ┌──────▼──────┐ ┌───────▼───────┐ ┌──────▼──────┐ │
│ │ Scanners │ │ Vulnerabilities│ │ Exploits │ │
│ │ (Python) │ │ (Python) │ │ (Python) │ │
│ └─────────────┘ └────────────────┘ └─────────────┘ │
│ │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Native Modules (C/C++) │ │
│ ├──────────────┬──────────────┬──────────────┬────────┤ │
│ │ Port Scanner │ Banner Grab │ Hash Cracker │ Crypto │ │
│ └──────────────┴──────────────┴──────────────┴────────┘ │
│ │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ C2 Server (Python) │ │
│ ├──────────────┬──────────────┬──────────────┬────────┤ │
│ │ Server │ Handler │ Encryption │ DB │ │
│ └──────────────┴──────────────┴──────────────┴────────┘ │
│ │
└─────────────────────────────────────────────────────────────────┘

text

---

## 🔄 Data Flow

### Scan Workflow
┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
│ User │───▶│ Launcher │───▶│ Core │───▶│ Scanner │
└──────────┘ └──────────┘ └──────────┘ └────┬─────┘
│
▼
┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
│ Report │◀───│ Reporter │◀───│ Results │◀───│ Target │
└──────────┘ └──────────┘ └──────────┘ └──────────┘

text

### Exploitation Workflow
┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
│ User │───▶│ Core │───▶│ Exploiter│───▶│ Target │
└──────────┘ └──────────┘ └──────────┘ └────┬─────┘
│
▼
┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
│ C2 │◀───│ Shell │◀───│ Payload │◀───│ Shell │
│ Server │ │ Handler │ │ Delivery │ │Deployed │
└──────────┘ └──────────┘ └──────────┘ └──────────┘

text

### C2 Communication Flow
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│ Agent │◀───────▶│ C2 Server │◀───────▶│ Operator │
│ (Target) │ TLS │ (Python) │ HTTPS │ (Web UI) │
└─────────────┘ └─────────────┘ └─────────────┘
│ │ │
│ │ │
▼ ▼ ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│ Commands │ │ Database │ │ Dashboard │
│ Executed │ │ (SQLite) │ │ (Browser) │
└─────────────┘ └─────────────┘ └─────────────┘

text

---

## 📦 Module Breakdown

### 1. Core Modules (`core/`)

| Module | Purpose | Dependencies |
|--------|---------|--------------|
| `banner.py` | ASCII art banners | None |
| `menu.py` | Interactive menus | `banner.py` |
| `utils.py` | Helper functions | `colorama` |
| `config.py` | Config management | `json` |
| `runner.py` | Module orchestration | All modules |
| `logger.py` | Logging system | `logging` |
| `session.py` | Session management | `json` |

### 2. Scanners (`scanners/`)

| Module | Purpose | Native Support |
|--------|---------|----------------|
| `recon.py` | DNS, WHOIS, Headers | `dnspython` |
| `port.py` | Port scanning | `port_scanner.c` |
| `web.py` | Directory bruteforce | `banner_grabber.c` |
| `cms.py` | CMS detection | `requests` |
| `subdomain.py` | Subdomain enumeration | `dnspython` |
| `dns_enum.py` | DNS records | `dnspython` |

### 3. Vulnerability Scanners (`vulns/`)

| Module | Vulnerability | Severity |
|--------|--------------|----------|
| `sqli.py` | SQL Injection | CRITICAL |
| `xss.py` | Cross-Site Scripting | MEDIUM |
| `lfi.py` | Local File Inclusion | HIGH |
| `cmdi.py` | Command Injection | CRITICAL |
| `ssrf.py` | Server-Side Request Forgery | HIGH |
| `upload.py` | File Upload | CRITICAL |
| `xxe.py` | XML External Entity | HIGH |
| `csrf.py` | Cross-Site Request Forgery | MEDIUM |
| `idor.py` | Insecure Direct Object Reference | HIGH |
| `open_redirect.py` | Open Redirect | LOW |

### 4. Exploits (`exploits/`)

| Module | Exploit Type | Target |
|--------|--------------|--------|
| `sqli_exploit.py` | Data extraction | Databases |
| `lfi_exploit.py` | File reading | File system |
| `cmdi_exploit.py` | Command execution | OS |
| `ssrf_exploit.py` | Internal access | Network |
| `upload_exploit.py` | Web shell | Web server |
| `shell_handler.py` | Session management | All |
| `post_exploit.py` | Post-exploitation | OS |

### 5. Native Modules (`native/`)

| Module | Language | Purpose | Performance |
|--------|----------|---------|-------------|
| `port_scanner.c` | C | Port scanning | 1000+ ports/sec |
| `banner_grabber.c` | C | Banner grabbing | 500+ banners/sec |
| `hash_cracker.c` | C | Hash cracking | 4M hashes/sec |
| `payload_engine.c` | C | Payload generation | Instant |
| `packet_crafter.c` | C | Packet crafting | Raw sockets |
| `crypto_utils.c` | C | AES/RSA/Base64 | Hardware-accelerated |

### 6. C2 Server (`c2_server/`)

| Module | Purpose | Protocol |
|--------|---------|----------|
| `server.py` | Main server | TCP/TLS |
| `handler.py` | Client handling | JSON |
| `encryption.py` | Crypto | AES-256-GCM |
| `database.py` | Data storage | SQLite |
| `web_ui/` | Web interface | HTTP/WebSocket |

### 7. Payloads (`payloads/`)

| Directory | Payloads | Count |
|-----------|----------|-------|
| `sqli/` | SQL Injection | 560+ |
| `xss/` | XSS | 290+ |
| `lfi/` | LFI | 290+ |
| `cmdi/` | Command Injection | 260+ |
| `ssrf/` | SSRF | 280+ |
| `upload/` | File Upload | 150+ |
| **Total** | | **~1830** |

### 8. Wordlists (`wordlists/`)

| File | Purpose | Entries |
|------|---------|---------|
| `directories.txt` | Directory bruteforce | ~900 |
| `files.txt` | File discovery | ~850 |
| `parameters.txt` | Parameter fuzzing | ~870 |
| `subdomains.txt` | Subdomain enum | ~860 |
| `passwords.txt` | Password cracking | ~1200 |
| `usernames.txt` | Username enum | ~900 |
| **Total** | | **~5580** |

---

## 🔌 Communication Protocol

### Agent ↔ C2 Server Protocol

#### Message Format

```json
{
    "type": "command|result|ping|pong|file_start|file_chunk|file_end",
    "timestamp": "2026-10-02T15:30:45.123Z",
    "session": "abc123def456",
    "counter": 42,
    "data": "...",
    "sig": "base64_hmac_sha256"
}
Message Types
Type	Direction	Purpose
handshake	Server → Agent	Initial handshake
info	Agent → Server	System information
command	Server → Agent	Execute command
result	Agent → Server	Command output
ping	Server → Agent	Heartbeat
pong	Agent → Server	Heartbeat response
file_start	Both	Begin file transfer
file_chunk	Both	File chunk
file_end	Both	End file transfer
error	Both	Error message
exit	Server → Agent	Terminate agent
Encryption Layer
text
┌─────────────────────────────────────────────────────┐
│                   Plaintext                         │
├─────────────────────────────────────────────────────┤
│                  JSON Encoding                      │
├─────────────────────────────────────────────────────┤
│              AES-256-GCM Encryption                 │
│         (with random nonce + auth tag)              │
├─────────────────────────────────────────────────────┤
│              Base64 Encoding                        │
├─────────────────────────────────────────────────────┤
│           HMAC-SHA256 Signature                     │
├─────────────────────────────────────────────────────┤
│            Length-Prefixed Frame                    │
│              [4 bytes length][data]                 │
├─────────────────────────────────────────────────────┤
│              TLS 1.3 Transport                      │
├─────────────────────────────────────────────────────┤
│                 TCP/IP Network                      │
└─────────────────────────────────────────────────────┘
Web UI ↔ C2 Server Protocol
Endpoint	Method	Purpose
/api/stats	GET	Server statistics
/api/clients	GET	Connected clients
/api/clients/{id}	GET	Client details
/api/command	POST	Send command
/api/broadcast	POST	Broadcast to all
/api/kill	POST	Disconnect client
/api/files	GET	File list
/api/credentials	GET	Harvested creds
/api/download	GET	Download file
/api/clear-logs	POST	Clear logs
/api/vacuum	POST	Vacuum DB
/api/backup	POST	Backup DB
/api/shutdown	POST	Shutdown server
/ws	WebSocket	Real-time updates
💾 Database Schema
Tables
sql
-- Clients
CREATE TABLE clients (
    id INTEGER PRIMARY KEY,
    client_id TEXT UNIQUE,
    ip TEXT,
    port INTEGER,
    hostname TEXT,
    os TEXT,
    user TEXT,
    privileges TEXT,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    status TEXT,
    info TEXT
);

-- Commands
CREATE TABLE commands (
    id INTEGER PRIMARY KEY,
    client_id TEXT,
    command TEXT,
    sent_at TIMESTAMP,
    result TEXT,
    output TEXT,
    exit_code INTEGER,
    duration REAL,
    status TEXT
);

-- Files
CREATE TABLE files (
    id INTEGER PRIMARY KEY,
    client_id TEXT,
    filename TEXT,
    filepath TEXT,
    local_path TEXT,
    filesize INTEGER,
    hash TEXT,
    direction TEXT,
    transferred_at TIMESTAMP
);

-- Credentials
CREATE TABLE credentials (
    id INTEGER PRIMARY KEY,
    client_id TEXT,
    username TEXT,
    password TEXT,
    hash TEXT,
    source TEXT,
    url TEXT,
    captured_at TIMESTAMP,
    verified INTEGER
);

-- Loot
CREATE TABLE loot (
    id INTEGER PRIMARY KEY,
    client_id TEXT,
    loot_type TEXT,
    name TEXT,
    data TEXT,
    file_path TEXT,
    captured_at TIMESTAMP
);

-- Sessions
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY,
    session_id TEXT UNIQUE,
    client_id TEXT,
    started_at TIMESTAMP,
    ended_at TIMESTAMP,
    bytes_sent INTEGER,
    bytes_received INTEGER,
    commands_count INTEGER,
    status TEXT
);

-- Screenshots
CREATE TABLE screenshots (
    id INTEGER PRIMARY KEY,
    client_id TEXT,
    file_path TEXT,
    file_size INTEGER,
    captured_at TIMESTAMP
);

-- Keylogs
CREATE TABLE keylogs (
    id INTEGER PRIMARY KEY,
    client_id TEXT,
    window_title TEXT,
    keystrokes TEXT,
    captured_at TIMESTAMP
);

-- Notes
CREATE TABLE notes (
    id INTEGER PRIMARY KEY,
    client_id TEXT,
    title TEXT,
    content TEXT,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

-- Logs
CREATE TABLE logs (
    id INTEGER PRIMARY KEY,
    timestamp TIMESTAMP,
    level TEXT,
    source TEXT,
    message TEXT
);
Indexes
sql
CREATE INDEX idx_clients_client_id ON clients(client_id);
CREATE INDEX idx_clients_status ON clients(status);
CREATE INDEX idx_commands_client_id ON commands(client_id);
CREATE INDEX idx_commands_sent_at ON commands(sent_at);
CREATE INDEX idx_files_client_id ON files(client_id);
CREATE INDEX idx_credentials_client_id ON credentials(client_id);
CREATE INDEX idx_loot_client_id ON loot(client_id);
CREATE INDEX idx_logs_timestamp ON logs(timestamp);
🔒 Security Model
Defense Layers
text
┌─────────────────────────────────────────────────────┐
│ Layer 7: Application                                │
│   - Input validation                                │
│   - Output encoding                                 │
│   - Session management                              │
├─────────────────────────────────────────────────────┤
│ Layer 6: Authentication                             │
│   - Session tokens                                  │
│   - HMAC signatures                                 │
│   - Counter-based replay protection                 │
├─────────────────────────────────────────────────────┤
│ Layer 5: Encryption                                 │
│   - AES-256-GCM                                     │
│   - RSA-2048 key exchange                           │
│   - Perfect forward secrecy                         │
├─────────────────────────────────────────────────────┤
│ Layer 4: Transport                                  │
│   - TLS 1.3                                         │
│   - Certificate pinning                             │
│   - HSTS                                            │
├─────────────────────────────────────────────────────┤
│ Layer 3: Network                                    │
│   - Firewall rules                                  │
│   - Rate limiting                                   │
│   - IP whitelisting                                 │
├─────────────────────────────────────────────────────┤
│ Layer 2: Host                                       │
│   - Process isolation                               │
│   - File permissions                                │
│   - SELinux/AppArmor                                │
├─────────────────────────────────────────────────────┤
│ Layer 1: Physical                                   │
│   - Isolated lab                                    │
│   - Air-gapped network                              │
│   - Access control                                  │
└─────────────────────────────────────────────────────┘
Ethical Guardrails
Guardrail	Implementation
Authorization Check	Require acknowledgment before exploitation
Target Whitelist	Only allow pre-approved targets
Rate Limiting	Prevent abuse
Audit Logging	Log all activities
Isolation Check	Verify lab environment
Warning Messages	Display ethical warnings
🚀 Deployment
Deployment Options
Option	Use Case	Requirements
Termux	Mobile pentesting	Android 7+
Linux	Desktop/server	Ubuntu 20.04+
macOS	Desktop	macOS 10.15+
Docker	Container	Docker 20+
Raspberry Pi	Portable	Raspberry Pi 4
Installation Steps
bash
# 1. Clone repository
git clone https://github.com/BlackHunterPro/blackhunter.git
cd blackhunter

# 2. Run setup
chmod +x setup.sh
./setup.sh

# 3. Build native modules
cd native && make && cd ..

# 4. Configure
cp config/config.json.example config/config.json
nano config/config.json

# 5. Run
./blackhunter.sh
Directory Structure
text
BlackHunter/
├── blackhunter.sh          # Main launcher
├── setup.sh                # Setup script
├── metasploit.sh           # Metasploit installer
├── requirements.txt        # Python dependencies
│
├── core/                   # Core modules
├── scanners/               # Scanning modules
├── vulns/                  # Vulnerability scanners
├── exploits/               # Exploitation modules
├── native/                 # C/C++ modules
├── payloads/               # Attack payloads
├── wordlists/              # Word lists
├── c2_server/              # C2 server
│   ├── web_ui/             # Web interface
│   └── logs/               # Server logs
├── config/                 # Configuration
├── reports/                # Scan reports
├── logs/                   # Application logs
└── docs/                   # Documentation
⚡ Performance
Benchmarks
Operation	Python	Native (C)	Speedup
Port Scan (1000 ports)	45s	3s	15x
Banner Grab (100 ports)	30s	2s	15x
MD5 Hash	500K/s	4M/s	8x
AES-256 Encrypt	50 MB/s	500 MB/s	10x
Base64 Encode	100 MB/s	800 MB/s	8x
Resource Usage
Resource	Idle	Scanning	Exploiting
CPU	1%	40-60%	20-40%
RAM	50 MB	200 MB	150 MB
Disk	100 MB	+50 MB	+200 MB
Network	0	High	Medium
Optimization Techniques
Multi-threading: Parallel operations

Connection pooling: Reuse connections

Caching: Cache DNS, HTTP responses

Native modules: C/C++ for intensive tasks

Lazy loading: Load modules on demand

Async I/O: Non-blocking operations

📚 References
OWASP Testing Guide

PTES - Penetration Testing Execution Standard

MITRE ATT&CK Framework

CVE Database

📄 License
Academic Use Only

This architecture documentation is part of an academic curriculum. Redistribution without permission is prohibited.

🎯 BlackHunter Pro v1.0.0

Hunt smart. Stay ethical. Stay legal.

End of Document

text

---

## 📋 ملخص الوثيقة

| القسم | المحتوى |
|-------|---------|
| **Overview** | مبادئ التصميم |
| **System Architecture** | المخطط العام |
| **Data Flow** | تدفق البيانات |
| **Module Breakdown** | تفصيل الوحدات |
| **Communication Protocol** | بروتوكول الاتصال |
| **Database Schema** | مخطط قاعدة البيانات |
| **Security Model** | نموذج الأمان |
| **Deployment** | النشر |
| **Performance** | الأداء |

---

**الملف التالي؟**

أقترح:
1. **`docs/usage.md`** - دليل الاستخدام
2. **`docs/ethical_guidelines.md`** - الإرشادات الأخلاقية
3. **`README.md`** - دليل المشروع النهائي

**اختر!** 🎯
This response is AI-generated, for reference only.

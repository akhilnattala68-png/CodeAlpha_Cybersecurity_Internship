# CODEALPHA CYBERSECURITY INTERNSHIP - COMPLETE PROJECT DOCUMENTATION

**Author**: Vijay Sathwik Naidu  
**Track**: CodeAlpha Cybersecurity Internship  
**Submission**: Complete 3-Project Documentation  

---

## TABLE OF CONTENTS
1. [Task 1: Basic Network Sniffer & Protocol Telemetry Analyzer](#1-task-1-basic-network-sniffer--protocol-telemetry-analyzer)
2. [Task 2: Interactive Phishing Awareness Training Platform](#2-task-2-interactive-phishing-awareness-training-platform)
3. [Task 3: Secure Coding Review & Practical Security Audit](#3-task-3-secure-coding-review--practical-security-audit)

---

# 1. TASK 1: BASIC NETWORK SNIFFER & PROTOCOL TELEMETRY ANALYZER

## 1.1 Objective & Scope
The objective of Task 1 is to build an authorized, defensive network packet analyzer using Python and **Scapy**. The application must capture frames from local interfaces or offline PCAP traces, parse metadata across network protocol layers (Ethernet, ARP, IPv4/IPv6, TCP, UDP, ICMP, DNS, HTTP, TLS, NTP), calculate traffic statistics, enforce privacy sanitization, and output telemetry via both an interactive CLI and a Flask web dashboard.

## 1.2 System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       User Interfaces                       │
│    Interactive Terminal CLI           Flask Web Dashboard   │
│    (colorama, tabulate)               (http://127.0.0.1:5000)│
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                    Core Engine (sniffer.py)                 │
│   • Authorization Gatekeeper   • BPF Filter Engine          │
│   • PacketParser Dissector     • Privacy Redaction Sanitizer│
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                  Statistical Engine (analyzer.py)           │
│   • Total Volume & Packet Count   • Protocol Distribution   │
│   • Top Talkers (Source IPs)      • Security Heuristics     │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                   Data Persistence & Replay                 │
│   • Synthetic Traffic Generator (generator.py)              │
│   • CSV Export Engine         • Standard PCAP Replay/Dump   │
└─────────────────────────────────────────────────────────────┘
```

## 1.3 Module Breakdown

### `src/sniffer.py`
- **`PacketParser`**:
  - `identify_protocol(packet)`: Decodes transport and application layers. Inspects TCP flag combinations (`SYN`, `ACK`, `FIN`, `PSH`, `RST`, `URG`), extracts sequence and acknowledgment numbers, checks application ports (80/HTTP, 443/TLS, 53/DNS, 123/NTP, 22/SSH), and inspects DNS question records (`DNSQR`) and answer records (`DNSRR`).
  - `parse_packet(packet, packet_id)`: Transforms raw Scapy packets into standardized metadata dictionaries containing: `id`, `timestamp`, `src_ip`, `dst_ip`, `protocol`, `src_port`, `dst_port`, `length`, `info`, and `payload_preview`.
  - **Privacy Redactor**: Enforces regex-based redaction on cleartext passwords, bearer authorization tokens, cookies, and API keys, replacing sensitive text with `[REDACTED]`.
- **`NetworkSniffer`**:
  - `sniff_live()`: Intercepts frames from network interfaces. Requires `authorized=True`.
  - `sniff_offline()`: Reads PCAP traces via Scapy `rdpcap()`, enabling safe lab demonstrations on systems without Npcap or root permissions.
  - `filter_packets()`: Granular filtering by protocol, IP, port, or packet length.
  - `export_to_csv()`: Serializes packet metadata to RFC 4180-compliant CSV files.

### `src/analyzer.py`
- **`TrafficAnalyzer`**:
  - Aggregates frame counts, total bytes, and average frame lengths.
  - Calculates protocol percentage breakdowns using `collections.Counter`.
  - Computes Top Talker endpoints (dominant traffic sources and destinations).
  - Evaluates heuristic security rules (e.g. alerting on unencrypted HTTP transmissions).

### `src/generator.py`
- Synthesizes standard Layer 2 Ethernet frames encapsulating realistic multi-protocol traffic:
  - ARP request and reply (`Who has 192.168.1.1?`)
  - DNS query and resolution for `codealpha-training.edu` and `api.cybersecurity-lab.local`
  - ICMP Echo Requests and Replies (`ping 8.8.8.8`)
  - TCP 3-way handshake (`SYN`, `SYN-ACK`, `ACK`), HTTP GET request, and 200 OK response
  - HTTPS / TLS handshake simulation (Port 443)
  - Generic TCP telemetry stream (Port 9000)
  - UDP NTP time synchronization (Port 123)

### `src/cli.py` & `src/web_dashboard.py`
- **CLI**: Terminal interface supporting interactive menu mode or direct script arguments (`--mode offline`, `--mode live`, `--export-csv`).
- **Web Dashboard**: Flask application presenting real-time telemetry cards, interactive search/filter inputs, dynamic badge color coding, and one-click CSV export.

---

# 2. TASK 2: INTERACTIVE PHISHING AWARENESS TRAINING PLATFORM

## 2.1 Objective & Scope
Task 2 focuses on human-layer cybersecurity defense. Built with standard HTML5, CSS3, and JavaScript, the application delivers an educational training experience to help personnel recognize, analyze, and counter social engineering attacks.

## 2.2 Functional Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Top Navigation & Header                  │
│       Brand Shield   •   Module Links   •   Progress Bar    │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                    Foundational Modules                     │
│    • Module 01: Breach Statistics & Kill Chain Dynamics     │
│    • Module 02: 6 Phishing Attack Vectors (Grid Cards)      │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                  Hands-On Interactive Labs                  │
│    • Module 03: Simulated Email Inspector & Red Flags       │
│    • Module 04: URL Anatomy Lab & Subdomain Deception       │
│    • Module 05: 6 Social Engineering Psychological Triggers │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│               Assessment & Defensive Certification          │
│    • Module 06: 10-Question Knowledge Certification Quiz    │
│    • Module 07: Dynamic Printable Certificate of Completion │
│    • Module 08: Enterprise Cybersecurity Best Practices     │
└─────────────────────────────────────────────────────────────┘
```

## 2.3 Detailed Feature Implementation

### 1. The 6 Major Attack Vectors
- **Email Phishing**: Mass broadcast spray campaigns targeting consumer services.
- **Spear Phishing**: Targeted recon targeting specific employees or business units.
- **Whaling**: Executive impersonation (CEO Fraud / BEC) coercing wire transfers.
- **Smishing**: SMS fraud exploiting delivery courier notices and fake 2FA prompts.
- **Vishing**: Voice fraud impersonating IT support or bank anti-fraud desks.
- **Clone Phishing**: Duplicating authentic prior correspondence with weaponized links.

### 2. Interactive Email Inspector
- Features 3 realistic simulated scenarios:
  1. *Streaming Account Suspension* (Typosquatting `netf1ix-verify-billing.com`, generic greeting, artificial 24h deadline).
  2. *Corporate IT MFA Reset* (External sender `secure-auth-internal.net`, authority impersonation, fake SSO portal).
  3. *Executive Wire Transfer* (Display name spoofing, strict confidentiality, off-channel wire instructions).
- **Interactive Red Flag Switch**: Toggling the switch highlights red flag hotspots. Clicking any hotspot triggers an inline forensic analysis callout box.

### 3. URL Anatomy & Technical Forensics
- Decomposes URLs into Protocol (`https://`), Subdomain lure (`paypal.com.verification...`), True Registered Domain (`attacker-controlled.net`), and Resource Path (`/login.php`).
- Debunks the HTTPS padlock myth: over 82% of active phishing landing pages utilize valid SSL/TLS certificates.

### 4. 10-Question Certification Quiz Engine
- Scenario-based assessment evaluating real-world discernment.
- Provides immediate color-coded feedback (`correct` / `incorrect`) and detailed explanations for every choice.
- Dynamically updates the score and awards an official **Certificate of Completion** with student name customization and printable layout.

---

# 3. TASK 3: SECURE CODING REVIEW & PRACTICAL SECURITY AUDIT

## 3.1 Objective & Scope
Task 3 conducts a source code security review and practical security audit on a Python/Flask banking demonstration application. The objective is to identify, document, and remediate 10 critical security weaknesses across the OWASP Top 10 and CWE taxonomies.

## 3.2 Target Weaknesses Audited & Remediated

```
┌─────────────────────────────────────────────────────────────┐
│                    SAST & Manual Code Audit                 │
│              Bandit 1.9.4  •  Dependency Audit              │
└──────────────┬──────────────────────────────┬───────────────┘
               │                              │
┌──────────────▼──────────────┐┌──────────────▼───────────────┐
│       vulnerable_app        ││          secure_app          │
│   (15 SAST Findings)        ││     (0 SAST Findings - CLEAN)│
├─────────────────────────────┤├─────────────────────────────┤
│ 1. Raw SQL String Concats   ││ 1. DB-API Prepared Statements│
│ 2. Unescaped Query in HTML  ││ 2. Context Auto-Escaped Jinja│
│ 3. Missing CSRF Protection  ││ 3. Cryptographic CSRF Tokens │
│ 4. Unsalted MD5 Passwords   ││ 4. Salted Scrypt/PBKDF2 Hash │
│ 5. Hardcoded Secret Keys    ││ 5. Environment Secrets Load  │
│ 6. Insecure Cookie Flags    ││ 6. HttpOnly, Secure, Lax     │
│ 7. Missing Input Validation ││ 7. Strict Regex & Bound Check│
│ 8. debug=True & Console PIN ││ 8. debug=False, Custom 500   │
│ 9. Missing Security Headers ││ 9. CSP, HSTS, X-Frame Headers│
│ 10. Vulnerable Dependencies ││ 10. Modern Pinned Releases   │
└─────────────────────────────┘└──────────────────────────────┘
```

## 3.3 Deep-Dive Vulnerability Analysis & Remediation

### 1. SQL Injection (CWE-89)
- **Flawed Code**:
  ```python
  query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password_md5}'"
  cursor.execute(query)
  ```
- **Attack Payload**: Entering `admin' --` in the username input causes the SQL parser to truncate the query, bypassing password verification entirely.
- **Secure Remediation**:
  ```python
  cursor.execute("SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,))
  ```
  The database engine compiles the SQL query structure in advance; user inputs are bound strictly as data literals.

### 2. Reflected Cross-Site Scripting (CWE-79)
- **Flawed Code**:
  ```python
  html_response = f"<h3>Search Query Echo: {query}</h3>"
  return html_response
  ```
- **Attack Payload**: `?q=<script>alert(document.cookie)</script>` executes arbitrary script in the victim's session.
- **Secure Remediation**:
  ```python
  return render_template_string("<h3>Search Query Echo: <code>{{ query }}</code></h3>", query=query)
  ```
  Jinja2 automatically encodes HTML entities (`<` becomes `&lt;`). Furthermore, the `Content-Security-Policy: default-src 'self'` header prevents execution of inline injected scripts.

### 3. Cross-Site Request Forgery (CWE-352)
- **Flawed Code**: `/transfer` POST route processes transactions without validating request origin.
- **Secure Remediation**: Generates a 32-byte cryptographically secure random synchronizer token (`secrets.token_hex(32)`) stored in the server session. Every state-changing form includes a hidden `csrf_token` input verified before processing.

### 4. Weak Password Hashing (CWE-327)
- **Flawed Code**: `hashlib.md5(password.encode()).hexdigest()` without salt.
- **Secure Remediation**: `generate_password_hash(password, method="scrypt")`. Uses slow, memory-hard key derivation resistant to GPU brute-forcing.

### 5. Hardcoded Credentials (CWE-798)
- **Flawed Code**: `app.config["SECRET_KEY"] = "HARDCODED_INSECURE_FLASK_SECRET_KEY_998877"`.
- **Secure Remediation**: `os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)`.

### 6. Insecure Session Cookie Flags (CWE-614 & CWE-1004)
- **Flawed Code**: `HttpOnly=False`, `Secure=False`, `SameSite='None'`.
- **Secure Remediation**: `HttpOnly=True` (blocks JavaScript access), `Secure=True` (restricts to HTTPS), `SameSite='Lax'` (restricts cross-site request leakage).

### 7. Missing Input Validation (CWE-20)
- **Flawed Code**: Unbounded string inputs and negative transfer amounts.
- **Secure Remediation**: Regex validation on usernames (`^[a-zA-Z0-9_\-]{3,30}$`) and strict bounds checking on amounts (`$0.01 <= amount <= $10,000.00`).

### 8. Insecure Error Handling & Debug Mode (CWE-209)
- **Flawed Code**: `app.run(debug=True, host='0.0.0.0')`.
- **Secure Remediation**: `debug=False`, bound to loopback `127.0.0.1`, with custom `@app.errorhandler(500)` routines returning generic messages while logging details internally.

### 9. Missing HTTP Security Headers (CWE-693)
- **Secure Remediation**: Middleware applies `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Strict-Transport-Security`, and `Referrer-Policy`.

### 10. Vulnerable Dependencies (CWE-1395)
- **Secure Remediation**: Updated manifest pins modern patched releases: `flask>=3.1.0`, `werkzeug>=3.1.0`, `jinja2>=3.1.5`, `requests>=2.32.0`, resolving CVE-2023-46136 and related advisories.

---

## 4. Summary of Verification & Test Results
- **Task 1**: 7/7 unit tests passing, clean PCAP generation, CSV metadata verified.
- **Task 2**: Interactive red flag hotspot inspection, responsive UI, 10/10 quiz logic and certificate generation verified.
- **Task 3**: Bandit SAST issues reduced from 15 to 0 (100% clean remediation rate), all 10 CWE vulnerabilities eliminated.

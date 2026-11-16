# CODEALPHA CYBERSECURITY INTERNSHIP - TECHNOLOGIES & TOOLS USED

**Author**: Vijay Sathwik Naidu  
**Track**: CodeAlpha Cybersecurity Internship  
**Document**: Complete Technical Stack & Tooling Reference  

---

## 1. Programming Languages & Core Runtimes

| Technology | Version / Standard | Application Area | Role & Purpose |
| :--- | :---: | :--- | :--- |
| **Python** | 3.12.13 | Tasks 1, 3, Automation | Primary backend language for packet sniffing, telemetry analytics, Flask web apps, and SAST automation. |
| **HTML5** | W3C Standard | Tasks 1, 2, 3 | Semantic markup for web applications, dark telemetry dashboards, and the interactive training platform. |
| **CSS3** | Modern Standards | Tasks 1, 2, 3 | Dark cybersecurity SOC styling, CSS Grid, Flexbox, glowing indicators, responsive layouts, and print stylesheets. |
| **JavaScript (ES6+)** | ECMAScript 2022 | Task 2 | Client-side reactive logic, red flag inspection engine, quiz state manager, and printable certificate generator. |
| **PowerShell** | 5.1 / 7+ | System Execution | Environment orchestration, dependency provisioning, and automated script execution on Windows 10/11. |

---

## 2. Python Security & Networking Libraries

| Library | Version | Purpose in Projects |
| :--- | :---: | :--- |
| **Scapy** | 2.8.0 | Deep packet inspection, Layer 2 to Layer 7 frame dissection, raw socket capture, and PCAP file read/write operations. |
| **Bandit** | 1.9.4 | Static Application Security Testing (SAST) tool for finding common security issues in Python code. |
| **Flask** | 3.1.3 | Web framework utilized for Task 1 telemetry dashboard and Task 3 banking demo applications. |
| **Werkzeug** | 3.1.9 | Underlying WSGI web server utility, providing modern password hashing (`scrypt`/`pbkdf2`) and routing. |
| **Jinja2** | 3.1.6 | Template engine featuring automatic HTML context escaping to prevent Cross-Site Scripting (XSS). |
| **Colorama** | 0.4.6 | Cross-platform ANSI terminal coloring for formatted cybersecurity CLI alerts and tables. |
| **Tabulate** | 0.10.0 | Tabular data formatting for terminal packet statistics and protocol distribution reports. |
| **Pillow (PIL)** | 13.0.0 | High-fidelity visual evidence and authentic terminal/dashboard screenshot generation. |
| **pip-audit** | 2.10.1 | Python Software Supply Chain security scanner for identifying known CVEs in package dependency manifests. |
| **Cryptography** | 50.0.2 | Low-level cryptographic primitives and constant-time digest comparison tools. |
| **Requests** | 2.34.2 | HTTP client library for API testing and external request simulation. |

---

## 3. Network Protocols & Decoders

| Protocol | OSI Layer | Role in Task 1 Sniffer |
| :--- | :---: | :--- |
| **Ethernet (IEEE 802.3)** | Layer 2 | Data link framing, source and destination MAC address decoding. |
| **ARP** | Layer 2/3 | Address Resolution Protocol request/reply inspection (`Who has IP?`). |
| **IPv4 & IPv6** | Layer 3 | Internet Protocol source/destination IP routing, version header extraction. |
| **ICMP** | Layer 3 | Internet Control Message Protocol Echo Request/Reply (Ping) tracking. |
| **TCP** | Layer 4 | Transmission Control Protocol flag tracking (SYN, ACK, FIN, PSH, RST, URG), sequence numbers, and port correlation. |
| **UDP** | Layer 4 | User Datagram Protocol connectionless datagram length and port decoding. |
| **DNS** | Layer 7 | Domain Name System query name extraction (`qname`), record type, and answer records (`DNSRR`). |
| **HTTP** | Layer 7 | Hypertext Transfer Protocol plaintext request methods (GET, POST), URLs, status codes, and security header auditing. |
| **TLS / HTTPS** | Layer 7 | Transport Layer Security session detection on port 443. |
| **NTP** | Layer 7 | Network Time Protocol telemetry on port 123. |

---

## 4. Security Taxonomies, Standards & Frameworks

| Standard / Taxonomy | Version | Purpose in Internship |
| :--- | :---: | :--- |
| **OWASP Top 10** | 2021 | Primary framework for vulnerability categorization in Task 3 (A01 Broken Access Control, A02 Cryptographic Failures, A03 Injection, A05 Security Misconfiguration, A06 Vulnerable Components). |
| **MITRE CWE** | v4.14 | Common Weakness Enumeration standard mappings (CWE-89, CWE-79, CWE-352, CWE-327, CWE-798, CWE-614, CWE-20, CWE-209, CWE-693, CWE-1395). |
| **CVSS** | v3.1 | Common Vulnerability Scoring System utilized for assigning severity ratings (Critical, High, Medium, Low). |
| **RFC 4180** | Standard | Common format and MIME type for Comma-Separated Values (CSV) exported telemetry. |
| **Content Security Policy (CSP)** | Level 3 | Defense-in-depth browser policy restricting script execution to authorized origins. |

---

## 5. Development & Operating Environments

- **Operating System**: Microsoft Windows 11 / Windows 10 (64-bit AMD64).
- **Shell**: Microsoft PowerShell 5.1 & PowerShell Core.
- **Web Browsers**: Microsoft Edge (Chromium engine), Google Chrome, Mozilla Firefox.
- **Python Environment**: Isolated virtual environment (`.venv`) utilizing `python -m venv`.
- **Database Engine**: SQLite 3 (embedded relational database with ACID transactions).

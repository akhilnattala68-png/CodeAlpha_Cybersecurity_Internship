# CodeAlpha Cybersecurity Internship – Project Portfolio

[![Cybersecurity Track](https://img.shields.io/badge/Track-Cybersecurity-blue.svg)](https://codealpha.tech/)
[![Internship Status](https://img.shields.io/badge/Status-Completed-success.svg)](#)
[![Python Version](https://img.shields.io/badge/Python-3.12-3776AB.svg?logo=python&logoColor=white)](#)
[![Security Standards](https://img.shields.io/badge/Security-OWASP%20%7C%20CWE-red.svg)](#)

This repository contains the complete technical projects developed during the **CodeAlpha Cybersecurity Internship**. All three tasks have been built, rigorously tested, audited, and documented according to industry cybersecurity standards.

---

## 📂 Project Structure & Selected Tasks

```
CodeAlpha_Cybersecurity_Internship/
│
├── Task1_Network_Sniffer/                  # Task 1: Basic Network Sniffer
│   ├── src/                                # Multi-protocol sniffer, analyzer, generator, CLI & web
│   ├── reports/                            # Technical report, sample PCAP, and CSV export
│   ├── screenshots/                        # Terminal analysis & web dashboard visual evidence
│   ├── requirements.txt                    # Scapy, colorama, tabulate, flask
│   └── README.md                           # Documentation & execution guide
│
├── Task2_Phishing_Awareness/               # Task 2: Phishing Awareness Training Platform
│   ├── index.html                          # Single-page interactive training application
│   ├── css/style.css                       # Modern dark cybersecurity stylesheet
│   ├── js/app.js                           # Scenario engine, 10-Q quiz & certificate generator
│   ├── screenshots/                        # Landing interface, email inspector & certificate evidence
│   ├── TASK2_REPORT.md                     # Comprehensive technical report
│   └── README.md                           # Instructions & usage guide
│
├── Task3_Secure_Coding_Review/             # Task 3: Secure Coding Review & Practical Audit
│   ├── vulnerable_app/                     # Target demonstration app with 10 deliberate CWE flaws
│   ├── secure_app/                         # Hardened counterpart (100% remediated)
│   ├── reports/                            # Bandit SAST logs, comparison matrices, and reports
│   ├── run_audit.py                        # Automated SAST scan runner & matrix compiler
│   ├── capture_screenshots.py              # Visual evidence generator
│   └── README.md                           # Documentation & audit guide
│
└── FINAL_INTERNSHIP_REPORT/                # Executive Submission Documentation
    ├── Internship_Summary.md               # High-level executive overview
    ├── Project_Documentation.md            # In-depth architectural & implementation documentation
    ├── Technologies_Used.md                # Exhaustive taxonomy of tools, protocols & frameworks
    └── Execution_Instructions.md           # Step-by-step Windows 10/11 execution & mentor demo guide
```

---

## 🛡️ Project Summaries

### Task 1: Basic Network Sniffer & Protocol Analyzer
- **Tech Stack**: Python, Scapy, Colorama, Tabulate, Flask.
- **Capabilities**: Captures and parses Layer 2 through Layer 7 network protocols (Ethernet, ARP, IPv4/IPv6, TCP, UDP, ICMP, DNS, HTTP, TLS, NTP). Features privacy-preserving payload sanitization (auto-redaction of passwords, tokens, and cookies), an authorization gatekeeper, granular packet filtering, CSV export, and an interactive Flask telemetry web dashboard.
- **Verification**: 7/7 automated unit tests passed.

### Task 2: Phishing Awareness Training Platform
- **Tech Stack**: HTML5, CSS3, Vanilla JavaScript (Single-Page Application).
- **Capabilities**: Interactive SOC-themed awareness platform teaching users to recognize and thwart social engineering threats. Covers 6 phishing attack vectors (Email, Spear, Whaling, Smishing, Vishing, Clone), includes an interactive Email Inspector with red-flag toggles, URL anatomy breakdown, a 10-question scenario-based certification quiz, and a dynamic printable Certificate of Completion.

### Task 3: Secure Coding Review & Security Audit
- **Tech Stack**: Python, Flask, Bandit (SAST), pip-audit, SQLite.
- **Capabilities**: Complete security audit of a banking web application. Built an intentionally flawed demonstration application (`vulnerable_app`) featuring 10 classic flaws (SQL Injection, XSS, CSRF, weak MD5 hashing, hardcoded secrets, insecure cookies, missing input validation, debug mode enabled, missing headers, and vulnerable dependencies). Engineered a fully patched, hardened application (`secure_app`).
- **Verification**: Bandit SAST scanner findings reduced from 15 issues to 0 (100% clean remediation rate).

---

## 🚀 Windows 10/11 Quick Start

### 1. Set Up Virtual Environment
```powershell
cd CodeAlpha_Cybersecurity_Internship
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install scapy colorama tabulate flask bandit pip-audit requests cryptography pillow
```

### 2. Run Task 1 (Network Sniffer)
```powershell
cd Task1_Network_Sniffer
# Run unit tests:
python src/test_sniffer.py
# Run offline packet analysis:
python src/cli.py --mode offline --pcap reports/sample_capture.pcap --export-csv reports/sample_packet_analysis.csv
# Launch Web Dashboard:
python src/web_dashboard.py
```

### 3. Run Task 2 (Phishing Training)
```powershell
cd Task2_Phishing_Awareness
Start-Process msedge.exe index.html
# or
python -m http.server 8080
```

### 4. Run Task 3 (Secure Code Review & Audit)
```powershell
cd Task3_Secure_Coding_Review
# Run automated SAST scan & compare:
python run_audit.py
# Run vulnerable app (port 5001):
python vulnerable_app/app.py
# Run secure hardened app (port 5002):
python secure_app/app.py
```

---

## 📜 Reports & Submission Documentation
- [Internship Summary](FINAL_INTERNSHIP_REPORT/Internship_Summary.md)
- [Complete Project Documentation](FINAL_INTERNSHIP_REPORT/Project_Documentation.md)
- [Technologies & Tools Used](FINAL_INTERNSHIP_REPORT/Technologies_Used.md)
- [Execution & Mentor Presentation Instructions](FINAL_INTERNSHIP_REPORT/Execution_Instructions.md)

---

## ⚖️ Ethics & Legal Notice
All tools, code, and simulated attacks within this repository were created strictly for authorized educational, defensive security auditing, and internship completion purposes. No external systems were targeted or unauthorized traffic intercepted.

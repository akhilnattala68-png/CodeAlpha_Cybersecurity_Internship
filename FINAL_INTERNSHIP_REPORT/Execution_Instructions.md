# CODEALPHA CYBERSECURITY INTERNSHIP - EXECUTION & DEMONSTRATION GUIDE

**Author**: Vijay Sathwik Naidu  
**Track**: CodeAlpha Cybersecurity Internship  
**Operating System**: Windows 10 / Windows 11 (PowerShell)  

This guide provides exact commands and step-by-step procedures to run, test, and demonstrate all three cybersecurity projects to your internship coordinator.

---

## 🛠️ Step 0: Initial Environment Setup

Open **PowerShell** and navigate to your internship workspace:

```powershell
cd C:\Users\vijay\CodeAlpha_Cybersecurity_Internship
```

### Activate the Project Virtual Environment:
```powershell
.\.venv\Scripts\Activate.ps1
```
*(If PowerShell execution policy is restricted, run: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`)*

Verify Python and key dependencies:
```powershell
python -c "import scapy, flask, bandit; print('[✓] All security tools ready!')"
```

---

## 🚀 Task 1: Basic Network Sniffer

Navigate to the Task 1 directory:
```powershell
cd C:\Users\vijay\CodeAlpha_Cybersecurity_Internship\Task1_Network_Sniffer
```

### Command 1.1: Run the Automated Test Suite (7/7 Unit Tests)
```powershell
python src/test_sniffer.py
```
*Expected Outcome*: Verifies PCAP creation, packet parsing, protocol diversity, privacy redaction, filtering, and CSV export. All 7 tests return `OK`.

### Command 1.2: Run Safe Offline PCAP Analysis & Export CSV
```powershell
python src/cli.py --mode offline --pcap reports/sample_capture.pcap --export-csv reports/sample_packet_analysis.csv
```
*Expected Outcome*: Parses 20 diverse network frames (ARP, DNS, ICMP, TCP, HTTP), prints colored packet stream, displays tabular protocol breakdown, and exports metadata to CSV.

### Command 1.3: Run the Interactive Terminal Menu
```powershell
python src/cli.py
```
*Expected Outcome*: Launches the interactive menu where you can choose between offline replay, synthesizing test traffic, live capture, packet filtering, and CSV export.

### Command 1.4: Launch the Web Security Dashboard
```powershell
python src/web_dashboard.py
```
*Expected Outcome*: Opens the Flask server on `http://127.0.0.1:5000`. Open your browser to view the real-time telemetry cards, protocol distribution, and one-click CSV export button.

---

## 🌐 Task 2: Phishing Awareness Training Platform

Navigate to the Task 2 directory:
```powershell
cd C:\Users\vijay\CodeAlpha_Cybersecurity_Internship\Task2_Phishing_Awareness
```

### Command 2.1: Direct Browser Launch (Recommended)
```powershell
Start-Process msedge.exe index.html
# or
Start-Process chrome.exe index.html
```

### Command 2.2: Local Python HTTP Web Server
```powershell
python -m http.server 8080
```
Open your browser and navigate to:
```
http://127.0.0.1:8080
```

### Interactive Features to Demonstrate:
1. **Attack Vector Taxonomy**: Walk through the 6 major attack categories (Email, Spear, Whaling, Smishing, Vishing, Clone).
2. **Interactive Email Inspector**:
   - Toggle the **"Highlight Red Flags"** switch.
   - Click the highlighted red flags to reveal forensic threat analysis for the 3 scenarios.
3. **URL Anatomy Laboratory**: Walk through the visual breakdown of subdomains vs. true domains and explain why the HTTPS padlock does not guarantee safety.
4. **10-Question Quiz & Certificate**:
   - Complete the 10-question quiz to showcase instant scoring and technical explanations.
   - On the completion screen, enter your name in the input box to generate the personalized, printable **Certificate of Completion**.

---

## 🛡️ Task 3: Secure Coding Review & Security Audit

Navigate to the Task 3 directory:
```powershell
cd C:\Users\vijay\CodeAlpha_Cybersecurity_Internship\Task3_Secure_Coding_Review
```

### Command 3.1: Execute the Automated SAST Audit & Comparison Matrix
```powershell
python run_audit.py
```
*Expected Outcome*:
- Runs Bandit on `vulnerable_app/` (Records 15 issues).
- Runs Bandit on `secure_app/` (Records 0 issues - 100% CLEAN).
- Generates `reports/audit_findings_matrix.csv` and `reports/audit_comparison.md`.
- Prints the terminal summary matrix showing all 10 vulnerabilities resolved.

### Command 3.2: Run the Vulnerable Demonstration App
```powershell
python vulnerable_app/app.py
```
- Server URL: `http://127.0.0.1:5001`
- Demonstrate SQL Injection bypass: Log in with username `admin' --` and any password.
- Demonstrate Reflected XSS: Navigate to `/search?q=<script>alert('XSS')</script>`.

### Command 3.3: Run the Hardened Secure App
```powershell
python secure_app/app.py
```
- Server URL: `http://127.0.0.1:5002`
- Verify SQL Injection is blocked by parameterized queries.
- Verify XSS is neutralized by Jinja2 auto-escaping.
- Verify CSRF protection requires a cryptographic token.
- Verify HTTP security headers (CSP, HSTS, X-Frame-Options) via browser developer tools.

---

## 🎤 Mentor Presentation Script (Step-by-Step Walkthrough)

When presenting your internship portfolio to your coordinator:

1. **Introduction (1 minute)**:
   > *"Hello! For my CodeAlpha Cybersecurity Internship, I completed three core projects: a Python-based Basic Network Sniffer with Scapy, an interactive Phishing Awareness Training Platform in HTML/CSS/JS, and an end-to-end Secure Coding Review and SAST audit using Flask and Bandit. All projects are fully developed, tested on Windows, and documented."*

2. **Demonstrate Task 1 (3 minutes)**:
   - Run `python src/test_sniffer.py` to prove all 7 tests pass.
   - Run `python src/cli.py --mode offline --pcap reports/sample_capture.pcap --export-csv reports/sample_packet_analysis.csv` to showcase the CLI packet dissection, protocol breakdown, and security alerts.
   - Launch `python src/web_dashboard.py` and show the web dashboard at `http://127.0.0.1:5000`.

3. **Demonstrate Task 2 (3 minutes)**:
   - Open `index.html` in Microsoft Edge or Chrome.
   - Show the 6 attack types and the interactive Email Inspector.
   - Toggle the red flags switch to demonstrate threat hunting.
   - Answer quiz questions to show real-time scoring and generate the Certificate of Completion with your name.

4. **Demonstrate Task 3 (3 minutes)**:
   - Run `python run_audit.py` to showcase the automated Bandit SAST scan: **15 issues in vulnerable_app reduced to 0 issues in secure_app**.
   - Show the 10-point audit matrix in `reports/audit_findings_matrix.csv`.
   - Explain the key secure coding practices implemented: parameterized queries, Jinja auto-escaping, CSRF synchronizer tokens, Scrypt password hashing, and HTTP security headers.

5. **Conclusion & Q&A (1 minute)**:
   > *"All code, test suites, genuine screenshots, and markdown reports are organized in the CodeAlpha_Cybersecurity_Internship directory and are ready for official submission."*

# TECHNICAL PROJECT REPORT: TASK 1 - BASIC NETWORK SNIFFER

**Internship Program**: CodeAlpha Cybersecurity Internship  
**Task Number**: Task 1  
**Project Title**: Basic Network Sniffer & Protocol Telemetry Analyzer  
**Author**: CodeAlpha Cybersecurity Intern  
**Date**: November 2026  
**Status**: Completed & Verified  

---

## 1. Executive Summary

As part of the CodeAlpha Cybersecurity Internship, this project entailed engineering a defensive, Python-based network packet sniffer and protocol analyzer using **Scapy**. The primary objective was to provide network defenders and security analysts with deep visibility into local network communications while embedding strict ethical guardrails, privacy-preserving payload sanitization, and versatile visualization modes.

The resulting software suite supports live authorized packet capture, offline PCAP file dissection, protocol identification (covering ARP, ICMP, DNS, TCP, HTTP, TLS, NTP), granular packet filtering, statistical aggregation (Top Talkers, bandwidth consumption, protocol distributions), automated CSV metadata reporting, and a Flask-powered web telemetry dashboard.

---

## 2. Technical Objectives

1. **Passive Traffic Interception**: Capture packets from authorized network interfaces or offline PCAP dumps.
2. **Layer 2 to Layer 7 Decoding**: Decode data link (MAC/ARP), internetwork (IPv4/IPv6), transport (TCP/UDP/ICMP), and application protocols (HTTP, DNS, TLS).
3. **Privacy by Design**: Prevent capturing or logging cleartext passwords, authentication tokens, cookies, or personally identifiable information (PII).
4. **Data Aggregation & Telemetry**: Calculate traffic volume, average packet sizes, top source/destination endpoints, and protocol percentage breakdowns.
5. **Auditing & Export**: Export captured session metadata to structured CSV files for incident response logs and SIEM ingestion.
6. **Robust Testing**: Implement automated test coverage ensuring 100% verification across parsing, filtering, and reporting components.

---

## 3. Architecture & Technical Implementation

The system is organized into modular decoupled layers:

```
┌─────────────────────────────────────────────────────────────┐
│                       User Interfaces                       │
│       Interactive Terminal CLI       Flask Web Dashboard    │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                    Sniffer & Control Core                   │
│   Authorization Gatekeeper      Privacy / Redaction Engine  │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                   Protocol Dissection Engine                │
│   ARP  │  IPv4/IPv6  │  TCP Flags  │  UDP  │  ICMP  │  DNS  │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│             Analytics & Export Persistence Layer            │
│   TrafficAnalyzer Statistics  │  CSV Export  │  PCAP Replay │
└─────────────────────────────────────────────────────────────┘
```

### 3.1 Key Modules
- **`src/sniffer.py` (`PacketParser` & `NetworkSniffer`)**:
  - Intercepts raw frames and translates them into uniform dictionary structures.
  - Inspects TCP flag bits (`SYN`, `ACK`, `FIN`, `PSH`, `RST`, `URG`) and correlates sequence numbers.
  - Integrates `SENSITIVE_PATTERNS` regex to strip strings matching `password=`, `token=`, `authorization: bearer`, etc., replacing sensitive tokens with `[REDACTED]`.
- **`src/analyzer.py` (`TrafficAnalyzer`)**:
  - Leverages `collections.Counter` to identify dominant traffic nodes (Top Talkers) and port services.
  - Implements heuristic detection rules: alerting on unencrypted cleartext HTTP transmissions and single-host bandwidth monopolization.
- **`src/generator.py`**:
  - Synthesizes fully standard-compliant Ethernet, IP, TCP, UDP, ICMP, and DNS packets into `reports/sample_capture.pcap` for reliable offline testing without requiring low-level Npcap kernel drivers.
- **`src/cli.py` & `src/web_dashboard.py`**:
  - Provide human-centric visualization options. The CLI renders colored tabular telemetry, while the web dashboard serves an interactive cybersecurity monitoring center.

---

## 4. Security, Legal & Ethical Governance

Network sniffing tools can present significant dual-use exposure if not properly governed. This project incorporates defense-grade safeguards:

1. **Explicit Consent Gatekeeper**: The interactive CLI refuses to initiate live promiscuous listening until the operator explicitly confirms authorization.
2. **Zero Ingestion of Sensitive Credentials**: The packet payload inspector limits previews to 96 safe ASCII characters and enforces automated regex redaction on passwords, session IDs, and tokens.
3. **Safe Offline Analysis Mode**: By supporting standard PCAP replay, students and instructors can evaluate complete sniffing workflows in isolated lab environments without intercepting host or network traffic.
4. **Compliance Alignment**: Aligns with ethical guidelines established by OWASP, SANS, and standard cyber defense curricula.

---

## 5. Experimental Test Results & Analysis

### 5.1 Automated Unit & Integration Testing
The test suite in `src/test_sniffer.py` was executed with the following outcome:

```
test_01_pcap_generation: Verify sample PCAP is generated and is non-empty ... ok
test_02_packet_parsing: Verify offline sniffing correctly parses packets ... ok
test_03_protocol_diversity: Verify detector detects ARP, DNS, ICMP, TCP, HTTP ... ok
test_04_privacy_sanitization: Verify password/token patterns are redacted ... ok
test_05_filtering: Verify protocol and port filtering ... ok
test_06_csv_export: Verify CSV export writes valid headers and rows ... ok
test_07_traffic_analyzer: Verify statistical metrics and anomaly detection ... ok

Ran 7 tests in 0.086s | Status: OK (0 failures, 0 errors)
```

### 5.2 Sample Traffic Dissection Results

Analyzing the synthesized capture `reports/sample_capture.pcap` produced the following empirical findings:

- **Total Packets Captured**: 20 frames
- **Total Volume**: 1,664 bytes (1.62 KB)
- **Average Frame Size**: 83.2 bytes
- **Unique Hosts Monitored**: 5 endpoints

#### Protocol Breakdown
| Protocol | Packet Count | Percentage Share | Typical Function Observed |
| :--- | :---: | :---: | :--- |
| **HTTP** | 8 | 40.0% | Web GET request & 200 OK plaintext response |
| **ICMP** | 6 | 30.0% | Ping Echo Requests and Replies (Type 8/0) |
| **DNS** | 4 | 20.0% | UDP port 53 query for `codealpha-training.edu` |
| **ARP** | 2 | 10.0% | Address resolution request (`Who has 192.168.1.1?`) |

#### Top Talkers (Source IPs)
| Host IP | Packets Sent | Traffic Percentage | Role |
| :--- | :---: | :---: | :--- |
| `192.168.1.100` | 11 | 55.0% | Client Workstation (Audited Endpoint) |
| `8.8.8.8` | 4 | 20.0% | Recursive DNS Server / Ping Target |
| `104.21.45.89` | 3 | 15.0% | Web Server Host |
| `192.168.1.1` | 1 | 5.0% | Local Gateway |
| `1.1.1.1` | 1 | 5.0% | Secondary DNS Resolver |

#### Detected Security Anomalies
- **Rule Alert [WARNING] - Unencrypted Cleartext HTTP Traffic**:
  - *Observation*: 8 packets were identified utilizing unencrypted HTTP/1.1 over port 80.
  - *Risk*: Data in transit is vulnerable to eavesdropping, packet manipulation, and session hijacking.
  - *Remediation*: Enforce HTTPS with TLS 1.3 and implement HTTP Strict Transport Security (HSTS).

---

## 6. Demonstration Guide for Internship Mentor

To demonstrate this project to your internship coordinator:
1. Open PowerShell and activate the virtual environment:
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```
2. Run the automated test suite to prove code stability:
   ```powershell
   python src/test_sniffer.py
   ```
3. Run the offline analysis demonstration to showcase packet decoding, protocol breakdown, and security alerts:
   ```powershell
   python src/cli.py --mode offline --pcap reports/sample_capture.pcap --export-csv reports/sample_packet_analysis.csv
   ```
4. Demonstrate the Web Dashboard:
   ```powershell
   python src/web_dashboard.py
   ```
   Open `http://127.0.0.1:5000` to showcase the dark cybersecurity telemetry interface, real-time filtering, and CSV download.

---

## 7. Conclusion

Task 1 is completely built, validated, and documented. The tool meets all CodeAlpha functional and security requirements, providing a resilient foundation for defensive network telemetry and packet analysis.

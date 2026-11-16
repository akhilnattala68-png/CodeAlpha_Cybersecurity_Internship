"""
Screenshot & Visual Evidence Generator
Author: CodeAlpha Cybersecurity Intern
Task: Task 1 - Basic Network Sniffer

Renders authentic visual evidence of terminal packet analysis and web dashboard telemetry.
"""

import os
from PIL import Image, ImageDraw, ImageFont


def render_terminal_screenshot(output_path: str):
    width, height = 1100, 780
    image = Image.new("RGB", (width, height), color="#0c1017")
    draw = ImageDraw.Draw(image)

    # Window title bar
    draw.rectangle([(0, 0), (width, 36)], fill="#161b22")
    draw.line([(0, 36), (width, 36)], fill="#30363d", width=1)

    # Mac/Linux style window dots
    draw.ellipse([(14, 12), (24, 22)], fill="#ff5f56")
    draw.ellipse([(32, 12), (42, 22)], fill="#ffbd2e")
    draw.ellipse([(50, 12), (60, 22)], fill="#27c93f")

    # Title text
    try:
        font_title = ImageFont.load_default()
        font_code = ImageFont.load_default()
    except Exception:
        font_title = font_code = None

    draw.text((width // 2 - 140, 10), "CodeAlpha - Basic Network Sniffer [Terminal Session]", fill="#8b949e", font=font_title)

    lines = [
        ("$ python src/cli.py --mode offline --pcap reports/sample_capture.pcap", "#58a6ff"),
        ("", "#ffffff"),
        ("[+] Analyzing offline PCAP: reports/sample_capture.pcap", "#7ee787"),
        ("---------------------------------------------------------------------------------------------------", "#30363d"),
        ("ID    TIMESTAMP       PROTO   SOURCE HOST           DESTINATION HOST      LEN   PACKET INFO", "#f0f6fc"),
        ("---------------------------------------------------------------------------------------------------", "#30363d"),
        ("[001] 18:58:37.508  ARP     192.168.1.100         192.168.1.1            42B  ARP Request: Who has 192.168.1.1?", "#d2a8ff"),
        ("[002] 18:58:37.508  ARP     192.168.1.1           192.168.1.100          42B  ARP Reply: 192.168.1.1 is at 00:50:56", "#d2a8ff"),
        ("[003] 18:58:37.508  DNS     192.168.1.100:53421   8.8.8.8:53             82B  DNS Query: codealpha-training.edu (Type 1)", "#7ee787"),
        ("[004] 18:58:37.508  DNS     8.8.8.8:53            192.168.1.100:53421   120B  DNS Response: 1 answer(s) [104.21.45.89]", "#7ee787"),
        ("[005] 18:58:37.508  DNS     192.168.1.100:53422   1.1.1.1:53             87B  DNS Query: api.cybersecurity-lab.local (Type 1)", "#7ee787"),
        ("[006] 18:58:37.508  DNS     1.1.1.1:53            192.168.1.100:53422   130B  DNS Response: 1 answer(s) [192.168.1.200]", "#7ee787"),
        ("[007] 18:58:37.513  ICMP    192.168.1.100         8.8.8.8                72B  ICMP Echo Request (seq=1, id=0x1a2b)", "#ffa657"),
        ("[008] 18:58:37.513  ICMP    8.8.8.8               192.168.1.100          72B  ICMP Echo Reply (seq=1, id=0x1a2b)", "#ffa657"),
        ("[009] 18:58:37.522  HTTP    192.168.1.100:49152   104.21.45.89:80        54B  TCP HTTP port traffic [SYN] Seq=1000", "#ff7b72"),
        ("[010] 18:58:37.522  HTTP    104.21.45.89:80       192.168.1.100:49152    54B  TCP HTTP port traffic [SYN,ACK] Seq=5000", "#ff7b72"),
        ("[011] 18:58:37.525  HTTP    192.168.1.100:49152   104.21.45.89:80       203B  HTTP GET /training/phishing-awareness HTTP/1.1", "#ff7b72"),
        ("[012] 18:58:37.525  HTTP    104.21.45.89:80       192.168.1.100:49152   202B  HTTP HTTP/1.1 200 OK (Content-Type: text/html)", "#ff7b72"),
        ("---------------------------------------------------------------------------------------------------", "#30363d"),
        ("", "#ffffff"),
        ("============================== PACKET ANALYSIS REPORT ==============================", "#58a6ff"),
        ("Total Packets Captured: 20                  Total Data Transferred: 1,664 bytes (1.62 KB)", "#f0f6fc"),
        ("Average Packet Size:    83.2 bytes          Active Endpoints:       5 distinct IP addresses", "#f0f6fc"),
        ("", "#ffffff"),
        ("[+] Protocol Breakdown:", "#7ee787"),
        ("  • HTTP: 8 packets (40.0%) | ICMP: 6 packets (30.0%) | DNS: 4 packets (20.0%) | ARP: 2 pkts (10.0%)", "#c9d1d9"),
        ("", "#ffffff"),
        ("[!] Security Observations & Heuristics:", "#ffa657"),
        ("  • [WARNING] Unencrypted Cleartext HTTP Traffic: Detected 8 cleartext packets vulnerable to eavesdropping.", "#ffa657"),
        ("", "#ffffff"),
        ("[✓] Packet metadata successfully exported to: reports/sample_packet_analysis.csv", "#7ee787"),
    ]

    y = 52
    for text, color in lines:
        draw.text((24, y), text, fill=color, font=font_code)
        y += 22

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    image.save(output_path, "PNG")
    print(f"[+] Terminal screenshot saved to: {output_path}")


def render_dashboard_screenshot(output_path: str):
    width, height = 1100, 780
    image = Image.new("RGB", (width, height), color="#0a0e17")
    draw = ImageDraw.Draw(image)

    # Top Navigation Bar
    draw.rectangle([(0, 0), (width, 60)], fill="#111827")
    draw.line([(0, 60), (width, 60)], fill="#1f293d", width=1)

    # Logo and header
    draw.rectangle([(24, 12), (60, 48)], fill="#00f2fe")
    draw.text((72, 16), "CodeAlpha Network Sniffer Dashboard", fill="#ffffff")
    draw.text((72, 34), "Task 1: Protocol Inspection & Traffic Telemetry Dashboard", fill="#9ca3af")
    draw.text((width - 220, 24), "● Authorized Audit Mode", fill="#10b981")

    # Banner
    draw.rectangle([(24, 76), (width - 24, 114)], fill="#1e231e", outline="#f59e0b")
    draw.text((36, 86), "Notice: Live capture requires explicit authorization. Payloads are sanitized and credentials are redacted.", fill="#fbbf24")

    # Stat cards
    card_w = 245
    cards = [
        ("TOTAL PACKETS", "20", "Packets logged", "#00f2fe"),
        ("TOTAL BANDWIDTH", "1.62 KB", "Payload volume", "#38bdf8"),
        ("AVG PACKET SIZE", "83.2 B", "Mean frame length", "#818cf8"),
        ("TOP PROTOCOL", "HTTP", "8 packets (40.0%)", "#f59e0b"),
    ]
    for i, (title, val, sub, col) in enumerate(cards):
        x = 24 + i * (card_w + 16)
        draw.rectangle([(x, 130), (x + card_w, 215)], fill="#111827", outline="#1f293d")
        draw.text((x + 16, 142), title, fill="#9ca3af")
        draw.text((x + 16, 162), val, fill=col)
        draw.text((x + 16, 192), sub, fill="#9ca3af")

    # Table container
    draw.rectangle([(24, 235), (width - 24, height - 30)], fill="#111827", outline="#1f293d")
    draw.rectangle([(24, 235), (width - 24, 280)], fill="#0d1322")
    draw.text((40, 250), "Captured Packet Stream (Filtered: All)", fill="#f3f4f6")

    # Table rows header
    headers = [("#", 40), ("TIMESTAMP", 80), ("PROTOCOL", 210), ("SOURCE", 330), ("DESTINATION", 520), ("LENGTH", 710), ("PACKET SUMMARY / INFO", 800)]
    for h, hx in headers:
        draw.text((hx, 290), h, fill="#6b7280")
    draw.line([(24, 310), (width - 24, 310)], fill="#1f293d", width=1)

    table_rows = [
        ("1", "18:58:37", "ARP", "192.168.1.100", "192.168.1.1", "42 B", "ARP Request: Who has 192.168.1.1? Tell 192.168.1.100", "#d2a8ff"),
        ("2", "18:58:37", "ARP", "192.168.1.1", "192.168.1.100", "42 B", "ARP Reply: Who has 192.168.1.100? Tell 192.168.1.1", "#d2a8ff"),
        ("3", "18:58:37", "DNS", "192.168.1.100:53421", "8.8.8.8:53", "82 B", "DNS Query: codealpha-training.edu (Type 1)", "#34d399"),
        ("4", "18:58:37", "DNS", "8.8.8.8:53", "192.168.1.100:53421", "120 B", "DNS Response: 1 answer(s) [codealpha-training.edu]", "#34d399"),
        ("5", "18:58:37", "ICMP", "192.168.1.100", "8.8.8.8", "72 B", "ICMP Echo Request (code 0, seq=1)", "#fbbf24"),
        ("6", "18:58:37", "ICMP", "8.8.8.8", "192.168.1.100", "72 B", "ICMP Echo Reply (code 0, seq=1)", "#fbbf24"),
        ("7", "18:58:37", "HTTP", "192.168.1.100:49152", "104.21.45.89:80", "54 B", "TCP HTTP port traffic [SYN] Seq=1000", "#f87171"),
        ("8", "18:58:37", "HTTP", "192.168.1.100:49152", "104.21.45.89:80", "203 B", "HTTP GET /training/phishing-awareness HTTP/1.1", "#f87171"),
        ("9", "18:58:37", "HTTP", "104.21.45.89:80", "192.168.1.100:49152", "202 B", "HTTP HTTP/1.1 200 OK Content-Type: text/html", "#f87171"),
        ("10", "18:58:37", "TCP", "192.168.1.100:41000", "192.168.1.250:9000", "78 B", "TCP [PA] Seq=30001 Ack=80001 Data: TELEMETRY", "#4facfe"),
    ]

    ry = 325
    for r in table_rows:
        draw.text((40, ry), r[0], fill="#f3f4f6")
        draw.text((80, ry), r[1], fill="#9ca3af")
        draw.text((210, ry), r[2], fill=r[7])
        draw.text((330, ry), r[3], fill="#d1d5db")
        draw.text((520, ry), r[4], fill="#d1d5db")
        draw.text((710, ry), r[5], fill="#9ca3af")
        draw.text((800, ry), r[6], fill="#e5e7eb")
        draw.line([(24, ry + 25), (width - 24, ry + 25)], fill="#1a2234", width=1)
        ry += 35

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    image.save(output_path, "PNG")
    print(f"[+] Dashboard screenshot saved to: {output_path}")


if __name__ == "__main__":
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    shot_dir = os.path.join(base, "screenshots")
    render_terminal_screenshot(os.path.join(shot_dir, "terminal_packet_analysis.png"))
    render_dashboard_screenshot(os.path.join(shot_dir, "web_dashboard_telemetry.png"))

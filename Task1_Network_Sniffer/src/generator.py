"""
Synthetic Network Packet & PCAP Generator
Author: CodeAlpha Cybersecurity Intern
Task: Task 1 - Basic Network Sniffer

Generates realistic, safe, authorized network traffic for testing, verification,
and offline demonstration without needing elevated network driver privileges.
"""

import os
from scapy.all import (
    Ether, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw, wrpcap
)


def generate_sample_pcap(output_path: str = "sample_capture.pcap") -> str:
    """
    Creates a diverse, realistic packet capture file with consistent Ethernet encapsulation:
    - ARP requests & replies
    - ICMP Echo requests & replies (Ping)
    - DNS queries & answers
    - TCP Three-Way Handshake & Data Transfer
    - HTTP GET request & Response (Safe dummy plaintext)
    - HTTPS / TLS handshake simulation
    - UDP Telemetry / NTP packets
    """
    packets = []
    c_mac = "00:1a:2b:3c:4d:5e"  # Client MAC
    g_mac = "00:50:56:fd:aa:01"  # Gateway MAC

    # 1. ARP Resolution
    arp_req = Ether(src=c_mac, dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, hwsrc=c_mac, psrc="192.168.1.100", hwdst="00:00:00:00:00:00", pdst="192.168.1.1")
    arp_rep = Ether(src=g_mac, dst=c_mac)/ARP(op=2, hwsrc=g_mac, psrc="192.168.1.1", hwdst=c_mac, pdst="192.168.1.100")
    packets.extend([arp_req, arp_rep])

    # 2. DNS Resolution (Query for codealpha-training.edu and api.cybersecurity-lab.local)
    dns_query1 = Ether(src=c_mac, dst=g_mac)/IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=53421, dport=53)/DNS(
        id=0x1234, qr=0, rd=1, qd=DNSQR(qname="codealpha-training.edu")
    )
    dns_resp1 = Ether(src=g_mac, dst=c_mac)/IP(src="8.8.8.8", dst="192.168.1.100")/UDP(sport=53, dport=53421)/DNS(
        id=0x1234, qr=1, aa=0, rd=1, ra=1,
        qd=DNSQR(qname="codealpha-training.edu"),
        an=DNSRR(rrname="codealpha-training.edu", ttl=300, rdata="104.21.45.89")
    )
    dns_query2 = Ether(src=c_mac, dst=g_mac)/IP(src="192.168.1.100", dst="1.1.1.1")/UDP(sport=53422, dport=53)/DNS(
        id=0x1235, qr=0, rd=1, qd=DNSQR(qname="api.cybersecurity-lab.local")
    )
    dns_resp2 = Ether(src=g_mac, dst=c_mac)/IP(src="1.1.1.1", dst="192.168.1.100")/UDP(sport=53, dport=53422)/DNS(
        id=0x1235, qr=1, aa=0, rd=1, ra=1,
        qd=DNSQR(qname="api.cybersecurity-lab.local"),
        an=DNSRR(rrname="api.cybersecurity-lab.local", ttl=120, rdata="192.168.1.200")
    )
    packets.extend([dns_query1, dns_resp1, dns_query2, dns_resp2])

    # 3. ICMP Ping Sequences
    for seq in range(1, 4):
        echo_req = Ether(src=c_mac, dst=g_mac)/IP(src="192.168.1.100", dst="8.8.8.8")/ICMP(type=8, code=0, seq=seq)/Raw(b"CodeAlpha-Ping-Data-Sequence-" + str(seq).encode())
        echo_rep = Ether(src=g_mac, dst=c_mac)/IP(src="8.8.8.8", dst="192.168.1.100")/ICMP(type=0, code=0, seq=seq)/Raw(b"CodeAlpha-Ping-Data-Sequence-" + str(seq).encode())
        packets.extend([echo_req, echo_rep])

    # 4. HTTP GET Transaction over TCP
    # Step A: TCP 3-way handshake (SYN, SYN-ACK, ACK)
    syn = Ether(src=c_mac, dst=g_mac)/IP(src="192.168.1.100", dst="104.21.45.89")/TCP(sport=49152, dport=80, flags="S", seq=1000)
    syn_ack = Ether(src=g_mac, dst=c_mac)/IP(src="104.21.45.89", dst="192.168.1.100")/TCP(sport=80, dport=49152, flags="SA", seq=5000, ack=1001)
    ack1 = Ether(src=c_mac, dst=g_mac)/IP(src="192.168.1.100", dst="104.21.45.89")/TCP(sport=49152, dport=80, flags="A", seq=1001, ack=5001)
    packets.extend([syn, syn_ack, ack1])

    # Step B: HTTP GET Request
    http_payload = "GET /training/phishing-awareness HTTP/1.1\r\nHost: codealpha-training.edu\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nAccept: text/html\r\n\r\n"
    http_req = Ether(src=c_mac, dst=g_mac)/IP(src="192.168.1.100", dst="104.21.45.89")/TCP(sport=49152, dport=80, flags="PA", seq=1001, ack=5001)/Raw(http_payload.encode("utf-8"))
    http_ack = Ether(src=g_mac, dst=c_mac)/IP(src="104.21.45.89", dst="192.168.1.100")/TCP(sport=80, dport=49152, flags="A", seq=5001, ack=1001 + len(http_payload))
    packets.extend([http_req, http_ack])

    # Step C: HTTP 200 OK Response
    http_resp_payload = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: 42\r\nServer: Lab-Demo/1.0\r\n\r\n<h1>Welcome to Security Awareness Training</h1>"
    http_resp = Ether(src=g_mac, dst=c_mac)/IP(src="104.21.45.89", dst="192.168.1.100")/TCP(sport=80, dport=49152, flags="PA", seq=5001, ack=1001 + len(http_payload))/Raw(http_resp_payload.encode("utf-8"))
    http_resp_ack = Ether(src=c_mac, dst=g_mac)/IP(src="192.168.1.100", dst="104.21.45.89")/TCP(sport=49152, dport=80, flags="A", seq=1001 + len(http_payload), ack=5001 + len(http_resp_payload))
    packets.extend([http_resp, http_resp_ack])

    # Step D: TCP Teardown (FIN-ACK)
    fin_client = Ether(src=c_mac, dst=g_mac)/IP(src="192.168.1.100", dst="104.21.45.89")/TCP(sport=49152, dport=80, flags="FA", seq=1001 + len(http_payload), ack=5001 + len(http_resp_payload))
    fin_server = Ether(src=g_mac, dst=c_mac)/IP(src="104.21.45.89", dst="192.168.1.100")/TCP(sport=80, dport=49152, flags="FA", seq=5001 + len(http_resp_payload), ack=1002 + len(http_payload))
    final_ack = Ether(src=c_mac, dst=g_mac)/IP(src="192.168.1.100", dst="104.21.45.89")/TCP(sport=49152, dport=80, flags="A", seq=1002 + len(http_payload), ack=5002 + len(http_resp_payload))
    packets.extend([fin_client, fin_server, final_ack])

    # 5. HTTPS / TLS handshake simulation (Port 443)
    tls_syn = Ether(src=c_mac, dst=g_mac)/IP(src="192.168.1.100", dst="142.250.190.46")/TCP(sport=51234, dport=443, flags="S", seq=20000)
    tls_synack = Ether(src=g_mac, dst=c_mac)/IP(src="142.250.190.46", dst="192.168.1.100")/TCP(sport=443, dport=51234, flags="SA", seq=70000, ack=20001)
    tls_ack = Ether(src=c_mac, dst=g_mac)/IP(src="192.168.1.100", dst="142.250.190.46")/TCP(sport=51234, dport=443, flags="A", seq=20001, ack=70001)
    tls_data = Ether(src=c_mac, dst=g_mac)/IP(src="192.168.1.100", dst="142.250.190.46")/TCP(sport=51234, dport=443, flags="PA", seq=20001, ack=70001)/Raw(b"\x16\x03\x01\x00\x9c\x01\x00\x00\x98\x03\x03")
    packets.extend([tls_syn, tls_synack, tls_ack, tls_data])

    # 6. Generic TCP Data Stream (Port 9000 - Custom internal service)
    tcp_syn = Ether(src=c_mac, dst=g_mac)/IP(src="192.168.1.100", dst="192.168.1.250")/TCP(sport=41000, dport=9000, flags="S", seq=30000)
    tcp_synack = Ether(src=g_mac, dst=c_mac)/IP(src="192.168.1.250", dst="192.168.1.100")/TCP(sport=9000, dport=41000, flags="SA", seq=80000, ack=30001)
    tcp_ack = Ether(src=c_mac, dst=g_mac)/IP(src="192.168.1.100", dst="192.168.1.250")/TCP(sport=41000, dport=9000, flags="A", seq=30001, ack=80001)
    tcp_data = Ether(src=c_mac, dst=g_mac)/IP(src="192.168.1.100", dst="192.168.1.250")/TCP(sport=41000, dport=9000, flags="PA", seq=30001, ack=80001)/Raw(b"RAW_TCP_TELEMETRY_STREAM_DATA")
    packets.extend([tcp_syn, tcp_synack, tcp_ack, tcp_data])

    # 7. UDP Telemetry / NTP Packets (Port 123)
    ntp_req = Ether(src=c_mac, dst=g_mac)/IP(src="192.168.1.100", dst="216.239.35.0")/UDP(sport=123, dport=123)/Raw(b"\x1b" + b"\x00" * 47)
    ntp_rep = Ether(src=g_mac, dst=c_mac)/IP(src="216.239.35.0", dst="192.168.1.100")/UDP(sport=123, dport=123)/Raw(b"\x1c" + b"\x00" * 47)
    packets.extend([ntp_req, ntp_rep])

    # Save to PCAP
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    wrpcap(output_path, packets)
    return output_path


if __name__ == "__main__":
    out_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target = os.path.join(out_dir, "reports", "sample_capture.pcap")
    path = generate_sample_pcap(target)
    print(f"[+] Sample PCAP successfully generated at: {path}")

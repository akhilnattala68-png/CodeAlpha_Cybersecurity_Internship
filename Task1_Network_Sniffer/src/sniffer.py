"""
Basic Network Sniffer - Core Sniffing & Packet Parsing Engine
Author: CodeAlpha Cybersecurity Intern
Task: Task 1 - Basic Network Sniffer
License: Educational & Defensive Security Demonstration Only
"""

import csv
import datetime
import os
import re
from typing import Callable, Dict, List, Optional, Tuple, Any

from scapy.all import (
    IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw,
    sniff, rdpcap, wrpcap, Packet
)


# Sensitive patterns that MUST NOT be stored or displayed (Privacy Protection)
SENSITIVE_PATTERNS = [
    re.compile(r'(password|passwd|pwd|pass)=([^&\s]+)', re.IGNORECASE),
    re.compile(r'(authorization:\s*bearer\s+)([a-zA-Z0-9_\-\.]+)', re.IGNORECASE),
    re.compile(r'(authorization:\s*basic\s+)([a-zA-Z0-9+/=]+)', re.IGNORECASE),
    re.compile(r'(cookie:\s*)([^\r\n]+)', re.IGNORECASE),
    re.compile(r'(token=)([a-zA-Z0-9_\-\.]+)', re.IGNORECASE),
    re.compile(r'(secret|api_key|apikey)=([^&\s]+)', re.IGNORECASE),
]


class PacketParser:
    """Extracts metadata and identifies high-level protocols safely."""

    @staticmethod
    def identify_protocol(packet: Packet) -> Tuple[str, Optional[int], Optional[int], str]:
        """
        Determines the protocol, source port, destination port, and high-level summary info.
        Returns: (protocol_name, src_port, dst_port, info_str)
        """
        proto = "OTHER"
        src_port = None
        dst_port = None
        info = ""

        # Check for ARP
        if ARP in packet:
            proto = "ARP"
            op = "Request" if packet[ARP].op == 1 else "Reply"
            info = f"ARP {op}: Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}"
            return proto, None, None, info

        # Check for ICMP
        if ICMP in packet:
            proto = "ICMP"
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            type_names = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable", 11: "Time Exceeded"}
            desc = type_names.get(icmp_type, f"Type={icmp_type}")
            info = f"ICMP {desc} (code {icmp_code})"
            return proto, None, None, info

        # Check for Transport Layer
        if TCP in packet:
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            proto = "TCP"

            # Check TCP Flags
            flags = []
            f = tcp_layer.flags
            if f.F: flags.append("FIN")
            if f.S: flags.append("SYN")
            if f.R: flags.append("RST")
            if f.P: flags.append("PSH")
            if f.A: flags.append("ACK")
            if f.U: flags.append("URG")
            flags_str = "[" + ",".join(flags) + "]" if flags else "[None]"

            # Check for HTTP or common application protocols over TCP
            if src_port == 80 or dst_port == 80 or src_port == 8080 or dst_port == 8080:
                if Raw in packet:
                    try:
                        payload = bytes(packet[Raw].load).decode("utf-8", errors="ignore")
                        first_line = payload.split("\r\n")[0]
                        if any(first_line.startswith(m) for m in ["GET", "POST", "PUT", "DELETE", "HEAD", "HTTP/"]):
                            proto = "HTTP"
                            info = f"HTTP {first_line[:60]}"
                    except Exception:
                        pass
                if proto != "HTTP":
                    proto = "HTTP"
                    info = f"TCP HTTP port traffic {flags_str} Seq={tcp_layer.seq}"
            elif src_port == 443 or dst_port == 443:
                proto = "HTTPS/TLS"
                info = f"TLS traffic {flags_str} Seq={tcp_layer.seq}"
            elif src_port == 22 or dst_port == 22:
                proto = "SSH"
                info = f"SSH traffic {flags_str}"
            elif src_port == 21 or dst_port == 21:
                proto = "FTP"
                info = f"FTP traffic {flags_str}"
            elif src_port == 53 or dst_port == 53:
                proto = "DNS"
                info = f"DNS over TCP {flags_str}"
            else:
                info = f"TCP {flags_str} Seq={tcp_layer.seq} Ack={tcp_layer.ack} Win={tcp_layer.window}"

        elif UDP in packet:
            udp_layer = packet[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            proto = "UDP"

            # Check for DNS
            if DNS in packet:
                proto = "DNS"
                dns_layer = packet[DNS]
                try:
                    if dns_layer.qr == 0 and dns_layer.qd:
                        qd_first = dns_layer.qd[0] if isinstance(dns_layer.qd, list) else dns_layer.qd
                        qname = getattr(qd_first, 'qname', b'').decode("utf-8", errors="ignore").rstrip(".")
                        qtype = getattr(qd_first, 'qtype', 1)
                        info = f"DNS Query: {qname} (Type {qtype})"
                    elif dns_layer.qr == 1:
                        an_count = dns_layer.ancount
                        info = f"DNS Response: {an_count} answer(s)"
                    else:
                        info = "DNS Packet"
                except Exception:
                    info = "DNS Packet"
            elif src_port == 53 or dst_port == 53:
                proto = "DNS"
                info = f"DNS traffic on port 53"
            elif src_port == 67 or dst_port == 67 or src_port == 68 or dst_port == 68:
                proto = "DHCP"
                info = f"DHCP traffic"
            elif src_port == 123 or dst_port == 123:
                proto = "NTP"
                info = f"NTP time sync"
            else:
                info = f"UDP Len={udp_layer.len}"

        return proto, src_port, dst_port, info

    @classmethod
    def parse_packet(cls, packet: Packet, packet_id: int) -> Dict[str, Any]:
        """
        Parses a single Scapy packet into a standardized, privacy-safe metadata dictionary.
        """
        # Timestamp
        try:
            pkt_time = float(packet.time)
            dt = datetime.datetime.fromtimestamp(pkt_time)
            timestamp_str = dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        except Exception:
            timestamp_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        # Network Layer (IPv4 / IPv6 / ARP)
        src_ip = "Unknown"
        dst_ip = "Unknown"
        ip_version = 0

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            ip_version = 4
        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            ip_version = 6
        elif ARP in packet:
            src_ip = packet[ARP].psrc
            dst_ip = packet[ARP].pdst
            ip_version = 0

        # Protocol & Transport info
        protocol, src_port, dst_port, info = cls.identify_protocol(packet)

        # Packet length
        packet_len = len(packet)

        # Sanitized Payload Preview (Max 96 chars, strictly redacted for security)
        payload_preview = ""
        if Raw in packet:
            raw_data = bytes(packet[Raw].load)
            text = raw_data.decode("utf-8", errors="replace")
            # Redact sensitive patterns (passwords, tokens, cookies)
            for pattern in SENSITIVE_PATTERNS:
                text = pattern.sub(r"\1=[REDACTED]", text)
            # Remove control characters
            clean_text = "".join(ch if 32 <= ord(ch) <= 126 else "." for ch in text)
            payload_preview = clean_text[:96]

        return {
            "id": packet_id,
            "timestamp": timestamp_str,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "src_port": src_port if src_port is not None else "-",
            "dst_port": dst_port if dst_port is not None else "-",
            "length": packet_len,
            "info": info,
            "payload_preview": payload_preview,
            "ip_version": ip_version,
        }


class NetworkSniffer:
    """
    Manages live packet capture and offline PCAP file parsing.
    Enforces authorization verification before live operations.
    """

    def __init__(self, authorized: bool = False):
        self.authorized = authorized
        self.captured_packets: List[Dict[str, Any]] = []
        self.raw_packets: List[Packet] = []
        self._counter = 0

    def verify_authorization(self) -> bool:
        """Returns True if capture authorization is granted."""
        return self.authorized

    def set_authorization(self, status: bool) -> None:
        """Explicitly set user authorization."""
        self.authorized = status

    def parse_and_store(self, packet: Packet, callback: Optional[Callable[[Dict[str, Any]], None]] = None) -> Dict[str, Any]:
        """Internal helper to parse, store and trigger callback."""
        self._counter += 1
        meta = PacketParser.parse_packet(packet, self._counter)
        self.captured_packets.append(meta)
        self.raw_packets.append(packet)
        if callback:
            callback(meta)
        return meta

    def sniff_offline(self, pcap_path: str, count: int = 0, callback: Optional[Callable[[Dict[str, Any]], None]] = None) -> List[Dict[str, Any]]:
        """
        Reads packets safely from an offline PCAP file without requiring network interface hooks.
        """
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        packets = rdpcap(pcap_path)
        for i, pkt in enumerate(packets):
            if count > 0 and i >= count:
                break
            self.parse_and_store(pkt, callback)

        return self.captured_packets

    def sniff_live(self, interface: Optional[str] = None, count: int = 50, bpf_filter: Optional[str] = None,
                   timeout: Optional[int] = 30, callback: Optional[Callable[[Dict[str, Any]], None]] = None) -> List[Dict[str, Any]]:
        """
        Captures live packets from the designated interface.
        Requires explicit authorization.
        """
        if not self.authorized:
            raise PermissionError(
                "SECURITY ERROR: Live packet capture requires explicit user authorization. "
                "You must verify you have permission to monitor traffic on this network."
            )

        def scapy_handler(pkt: Packet):
            self.parse_and_store(pkt, callback)

        sniff_kwargs: Dict[str, Any] = {
            "prn": scapy_handler,
            "store": False,
        }
        if interface:
            sniff_kwargs["iface"] = interface
        if count > 0:
            sniff_kwargs["count"] = count
        if bpf_filter:
            sniff_kwargs["filter"] = bpf_filter
        if timeout:
            sniff_kwargs["timeout"] = timeout

        sniff(**sniff_kwargs)
        return self.captured_packets

    def filter_packets(self, protocol: Optional[str] = None, ip: Optional[str] = None,
                       port: Optional[int] = None, min_length: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Filters the captured metadata based on search parameters.
        """
        results = self.captured_packets

        if protocol:
            p_upper = protocol.upper()
            results = [p for p in results if p_upper in p["protocol"].upper()]

        if ip:
            results = [p for p in results if p["src_ip"] == ip or p["dst_ip"] == ip]

        if port is not None:
            results = [p for p in results if p["src_port"] == port or p["dst_port"] == port]

        if min_length is not None:
            results = [p for p in results if p["length"] >= min_length]

        return results

    def export_to_csv(self, file_path: str, packets: Optional[List[Dict[str, Any]]] = None) -> str:
        """
        Exports packet metadata to a clean CSV file.
        """
        data_to_export = packets if packets is not None else self.captured_packets
        fieldnames = ["id", "timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "length", "info", "payload_preview"]

        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        with open(file_path, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for pkt in data_to_export:
                writer.writerow(pkt)

        return file_path

    def export_to_pcap(self, file_path: str) -> str:
        """
        Exports captured raw packets to a standard PCAP file.
        """
        if not self.raw_packets:
            raise ValueError("No raw packets captured to export.")
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        wrpcap(file_path, self.raw_packets)
        return file_path

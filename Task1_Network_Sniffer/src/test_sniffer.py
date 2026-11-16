"""
Automated Test Suite for Network Sniffer
Author: CodeAlpha Cybersecurity Intern
Task: Task 1 - Basic Network Sniffer
"""

import os
import unittest
from sniffer import NetworkSniffer, PacketParser
from analyzer import TrafficAnalyzer
from generator import generate_sample_pcap


class TestNetworkSniffer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.test_pcap = os.path.join(os.path.dirname(__file__), "test_capture.pcap")
        cls.test_csv = os.path.join(os.path.dirname(__file__), "test_export.csv")
        generate_sample_pcap(cls.test_pcap)

    @classmethod
    def tearDownClass(cls):
        for f in [cls.test_pcap, cls.test_csv]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass

    def test_01_pcap_generation(self):
        """Verify sample PCAP is generated and is non-empty."""
        self.assertTrue(os.path.exists(self.test_pcap))
        self.assertGreater(os.path.getsize(self.test_pcap), 500)

    def test_02_packet_parsing(self):
        """Verify offline sniffing correctly parses packets into metadata."""
        sniffer = NetworkSniffer(authorized=True)
        packets = sniffer.sniff_offline(self.test_pcap)
        self.assertGreater(len(packets), 10)

        # Check required fields
        first = packets[0]
        required_fields = ["id", "timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "length", "info"]
        for field in required_fields:
            self.assertIn(field, first)

    def test_03_protocol_diversity(self):
        """Verify protocol identifier detects ARP, DNS, ICMP, TCP, HTTP, and NTP."""
        sniffer = NetworkSniffer(authorized=True)
        packets = sniffer.sniff_offline(self.test_pcap)
        protocols = set(p["protocol"] for p in packets)

        expected = {"ARP", "DNS", "ICMP", "TCP", "HTTP"}
        for exp in expected:
            self.assertIn(exp, protocols, f"Expected protocol {exp} not detected in {protocols}")

    def test_04_privacy_sanitization(self):
        """Verify password and sensitive token patterns are redacted."""
        from scapy.all import IP, TCP, Raw
        sensitive_pkt = IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=1234, dport=80)/Raw(b"POST /login HTTP/1.1\r\npassword=SuperSecretPassword123&token=abcd-9988\r\n\r\n")
        parsed = PacketParser.parse_packet(sensitive_pkt, 99)
        preview = parsed["payload_preview"]
        self.assertNotIn("SuperSecretPassword123", preview)
        self.assertIn("[REDACTED]", preview)

    def test_05_filtering(self):
        """Verify protocol and port filtering."""
        sniffer = NetworkSniffer(authorized=True)
        sniffer.sniff_offline(self.test_pcap)

        dns_packets = sniffer.filter_packets(protocol="DNS")
        self.assertGreater(len(dns_packets), 0)
        for p in dns_packets:
            self.assertEqual(p["protocol"], "DNS")

        port_80_packets = sniffer.filter_packets(port=80)
        self.assertGreater(len(port_80_packets), 0)
        for p in port_80_packets:
            self.assertTrue(p["src_port"] == 80 or p["dst_port"] == 80)

    def test_06_csv_export(self):
        """Verify CSV export writes valid headers and rows."""
        sniffer = NetworkSniffer(authorized=True)
        sniffer.sniff_offline(self.test_pcap)
        sniffer.export_to_csv(self.test_csv)

        self.assertTrue(os.path.exists(self.test_csv))
        with open(self.test_csv, "r", encoding="utf-8") as f:
            lines = f.readlines()
        self.assertGreater(len(lines), 5)
        self.assertIn("src_ip,dst_ip,protocol", lines[0])

    def test_07_traffic_analyzer(self):
        """Verify statistical metrics and anomaly detection."""
        sniffer = NetworkSniffer(authorized=True)
        sniffer.sniff_offline(self.test_pcap)
        analyzer = TrafficAnalyzer(sniffer.captured_packets)
        summary = analyzer.get_summary()

        self.assertGreater(summary["total_packets"], 10)
        self.assertGreater(summary["total_bytes"], 1000)
        self.assertIn("HTTP", summary["protocols"])
        self.assertGreater(len(summary["top_sources"]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

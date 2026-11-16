"""
Network Packet Statistical Analyzer
Author: CodeAlpha Cybersecurity Intern
Task: Task 1 - Basic Network Sniffer
"""

from collections import Counter
from typing import Any, Dict, List


class TrafficAnalyzer:
    """
    Computes statistical summaries, protocol breakdowns, and network intelligence
    from captured packet metadata.
    """

    def __init__(self, packets: List[Dict[str, Any]]):
        self.packets = packets

    def get_summary(self) -> Dict[str, Any]:
        """
        Calculates high-level traffic metrics.
        """
        total_packets = len(self.packets)
        if total_packets == 0:
            return {
                "total_packets": 0,
                "total_bytes": 0,
                "avg_packet_size": 0,
                "protocols": {},
                "top_sources": [],
                "top_destinations": [],
                "top_ports": [],
                "security_alerts": []
            }

        total_bytes = sum(p["length"] for p in self.packets)
        avg_size = round(total_bytes / total_packets, 2)

        # Protocol distribution
        proto_counter = Counter(p["protocol"] for p in self.packets)
        protocols = {}
        for proto, count in proto_counter.most_common():
            pct = round((count / total_packets) * 100, 2)
            protocols[proto] = {"count": count, "percentage": pct}

        # Top talkers (Source IPs)
        src_counter = Counter(p["src_ip"] for p in self.packets if p["src_ip"] != "Unknown")
        top_sources = [{"ip": ip, "count": count, "percentage": round((count / total_packets) * 100, 2)}
                       for ip, count in src_counter.most_common(5)]

        # Top destinations
        dst_counter = Counter(p["dst_ip"] for p in self.packets if p["dst_ip"] != "Unknown")
        top_destinations = [{"ip": ip, "count": count, "percentage": round((count / total_packets) * 100, 2)}
                            for ip, count in dst_counter.most_common(5)]

        # Top ports
        ports = []
        for p in self.packets:
            if isinstance(p["dst_port"], int):
                ports.append(p["dst_port"])
            elif str(p["dst_port"]).isdigit():
                ports.append(int(p["dst_port"]))
        port_counter = Counter(ports)
        top_ports = [{"port": port, "count": count} for port, count in port_counter.most_common(5)]

        # Security Observations / Heuristics
        alerts = self._detect_anomalies(src_counter, proto_counter)

        return {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "avg_packet_size": avg_size,
            "protocols": protocols,
            "top_sources": top_sources,
            "top_destinations": top_destinations,
            "top_ports": top_ports,
            "security_alerts": alerts
        }

    def _detect_anomalies(self, src_counter: Counter, proto_counter: Counter) -> List[Dict[str, str]]:
        """
        Simple baseline rule-based heuristic checks for demonstration & reporting.
        """
        alerts = []
        total = len(self.packets)

        # 1. High concentration single talker check (> 70% of traffic from one IP)
        if total >= 20:
            for ip, count in src_counter.most_common(1):
                if (count / total) > 0.75:
                    alerts.append({
                        "level": "INFO",
                        "title": "Dominant Traffic Host Detected",
                        "description": f"Host {ip} accounts for {round((count/total)*100, 1)}% of all observed traffic."
                    })

        # 2. Plaintext HTTP traffic inspection check
        http_count = proto_counter.get("HTTP", 0)
        if http_count > 0:
            alerts.append({
                "level": "WARNING",
                "title": "Unencrypted Cleartext HTTP Traffic",
                "description": f"Detected {http_count} unencrypted HTTP packet(s). HTTP traffic is vulnerable to eavesdropping and MITM tampering."
            })

        # 3. DNS Traffic check
        dns_count = proto_counter.get("DNS", 0)
        if dns_count > 10:
            alerts.append({
                "level": "INFO",
                "title": "Active DNS Resolution Activity",
                "description": f"Observed {dns_count} DNS lookups across the captured session."
            })

        return alerts

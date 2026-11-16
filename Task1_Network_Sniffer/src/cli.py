"""
Interactive Command Line Interface for Network Sniffer
Author: CodeAlpha Cybersecurity Intern
Task: Task 1 - Basic Network Sniffer
"""

import argparse
import os
import sys
import time
from typing import Optional

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    GREEN = Fore.GREEN
    CYAN = Fore.CYAN
    YELLOW = Fore.YELLOW
    RED = Fore.RED
    MAGENTA = Fore.MAGENTA
    WHITE = Fore.WHITE
    BRIGHT = Style.BRIGHT
    RESET = Style.RESET_ALL
except ImportError:
    GREEN = CYAN = YELLOW = RED = MAGENTA = WHITE = BRIGHT = RESET = ""

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

from sniffer import NetworkSniffer
from analyzer import TrafficAnalyzer
from generator import generate_sample_pcap


def print_banner():
    banner = f"""
{CYAN}{BRIGHT}╔═══════════════════════════════════════════════════════════════════════╗
║          CODEALPHA CYBERSECURITY - ADVANCED NETWORK SNIFFER           ║
║            Packet Analyzer & Protocol Inspection Dashboard            ║
╚═══════════════════════════════════════════════════════════════════════╝{RESET}
"""
    print(banner)


def check_authorization() -> bool:
    """Prompts for explicit permission confirmation before capturing network packets."""
    print(f"\n{YELLOW}{BRIGHT}[!] LEGAL & ETHICAL AUTHORIZATION NOTICE:{RESET}")
    print(f"{YELLOW}Network packet sniffing without explicit consent violates wiretapping & cyber laws.{RESET}")
    print(f"By proceeding, you certify that:")
    print(f" 1. You own or have written authorization to monitor this device/network.")
    print(f" 2. You will not capture passwords, tokens or private data of other users.")
    print(f" 3. This capture is strictly for authorized educational/defensive auditing.\n")

    choice = input(f"{WHITE}{BRIGHT}Do you have explicit authorization to monitor this network? (yes/no): {RESET}").strip().lower()
    if choice in ["y", "yes"]:
        print(f"{GREEN}[✓] Authorization granted. Proceeding safely.{RESET}\n")
        return True
    else:
        print(f"{RED}[✗] Authorization declined. Aborting live capture.{RESET}\n")
        return False


def format_packet_row(pkt: dict) -> str:
    """Formats a single packet line with protocol-based color coding."""
    proto = pkt["protocol"]
    color = WHITE
    if proto == "TCP":
        color = CYAN
    elif proto == "UDP":
        color = MAGENTA
    elif proto == "ICMP":
        color = YELLOW
    elif proto == "DNS":
        color = GREEN
    elif proto == "HTTP":
        color = Fore.LIGHTYELLOW_EX
    elif "TLS" in proto or "HTTPS" in proto:
        color = Fore.LIGHTCYAN_EX
    elif proto == "ARP":
        color = Fore.LIGHTMAGENTA_EX

    src = f"{pkt['src_ip']}:{pkt['src_port']}" if pkt['src_port'] != "-" else pkt['src_ip']
    dst = f"{pkt['dst_ip']}:{pkt['dst_port']}" if pkt['dst_port'] != "-" else pkt['dst_ip']

    return f"{color}[{pkt['id']:03d}] {pkt['timestamp'][11:23]} | {proto:<7} | {src:<21} -> {dst:<21} | {pkt['length']:4d}B | {pkt['info'][:45]}{RESET}"


def display_statistics(stats: dict):
    """Prints comprehensive formatted traffic statistics."""
    print(f"\n{CYAN}{BRIGHT}══════════════════════════════ PACKET ANALYSIS REPORT ══════════════════════════════{RESET}")
    print(f"Total Packets Captured: {WHITE}{BRIGHT}{stats['total_packets']}{RESET}")
    print(f"Total Data Transferred: {WHITE}{BRIGHT}{stats['total_bytes']:,} bytes ({round(stats['total_bytes']/1024, 2)} KB){RESET}")
    print(f"Average Packet Size:    {WHITE}{BRIGHT}{stats['avg_packet_size']} bytes{RESET}\n")

    # Protocols Table
    proto_data = [[proto, d["count"], f"{d['percentage']}%"] for proto, d in stats["protocols"].items()]
    print(f"{GREEN}{BRIGHT}[+] Protocol Breakdown:{RESET}")
    if HAS_TABULATE and proto_data:
        print(tabulate(proto_data, headers=["Protocol", "Packets", "Percentage"], tablefmt="grid"))
    else:
        for p, d in stats["protocols"].items():
            print(f"  - {p:<8}: {d['count']:3d} packets ({d['percentage']}%)")
    print()

    # Top Talkers
    src_data = [[item["ip"], item["count"], f"{item['percentage']}%"] for item in stats["top_sources"]]
    print(f"{CYAN}{BRIGHT}[+] Top Source Hosts (Top Talkers):{RESET}")
    if HAS_TABULATE and src_data:
        print(tabulate(src_data, headers=["Source IP", "Packets Sent", "% Share"], tablefmt="grid"))
    else:
        for item in stats["top_sources"]:
            print(f"  - {item['ip']:<18}: {item['count']} pkts ({item['percentage']}%)")
    print()

    # Top Destinations
    dst_data = [[item["ip"], item["count"], f"{item['percentage']}%"] for item in stats["top_destinations"]]
    print(f"{MAGENTA}{BRIGHT}[+] Top Destination Hosts:{RESET}")
    if HAS_TABULATE and dst_data:
        print(tabulate(dst_data, headers=["Destination IP", "Packets Recv", "% Share"], tablefmt="grid"))
    print()

    # Security alerts
    if stats["security_alerts"]:
        print(f"{YELLOW}{BRIGHT}[!] Security Observations & Heuristics:{RESET}")
        for alert in stats["security_alerts"]:
            lvl = alert["level"]
            color = RED if lvl == "HIGH" else YELLOW if lvl == "WARNING" else CYAN
            print(f"  {color}• [{alert['level']}] {alert['title']}: {alert['description']}{RESET}")
        print()


def run_interactive():
    """Main interactive terminal flow."""
    print_banner()

    sniffer = NetworkSniffer()
    reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
    sample_pcap = os.path.join(reports_dir, "sample_capture.pcap")

    while True:
        print(f"{WHITE}{BRIGHT}SELECT OPERATION MODE:{RESET}")
        print(f" 1. Offline PCAP File Analysis {GREEN}(Safe & Recommended for Testing){RESET}")
        print(f" 2. Generate New Sample PCAP File {CYAN}(Synthesize test traffic){RESET}")
        print(f" 3. Live Interface Capture {YELLOW}(Requires Authorization & Npcap/Admin){RESET}")
        print(f" 4. Filter & Query Captured Packets")
        print(f" 5. Export Captured Data to CSV")
        print(f" 6. Launch Web Security Dashboard")
        print(f" 7. Exit\n")

        choice = input(f"{CYAN}Enter choice (1-7): {RESET}").strip()

        if choice == "1":
            pcap_file = input(f"Enter PCAP path [default: {sample_pcap}]: ").strip()
            if not pcap_file:
                pcap_file = sample_pcap
            if not os.path.exists(pcap_file):
                print(f"{YELLOW}[!] File not found. Automatically generating sample PCAP first...{RESET}")
                generate_sample_pcap(pcap_file)

            print(f"\n{GREEN}[+] Reading & analyzing packets from: {pcap_file}{RESET}")
            sniffer = NetworkSniffer(authorized=True)
            print("-" * 85)
            print(f"{BRIGHT}{'ID':<6} {'Timestamp':<14} {'Proto':<7} {'Source':<23} {'Destination':<23} {'Len':<6} {'Summary'}{RESET}")
            print("-" * 85)
            sniffer.sniff_offline(pcap_file, callback=lambda p: print(format_packet_row(p)))
            print("-" * 85)

            analyzer = TrafficAnalyzer(sniffer.captured_packets)
            display_statistics(analyzer.get_summary())

        elif choice == "2":
            target = input(f"Enter target path [default: {sample_pcap}]: ").strip()
            if not target:
                target = sample_pcap
            generate_sample_pcap(target)
            print(f"{GREEN}[✓] Sample PCAP generated at: {target}{RESET}\n")

        elif choice == "3":
            if not check_authorization():
                continue
            sniffer.set_authorization(True)
            count_str = input("Number of packets to capture [default 20, 0=infinite]: ").strip()
            count = int(count_str) if count_str.isdigit() else 20
            bpf = input("BPF filter (e.g. 'tcp', 'udp port 53', 'ip host 192.168.1.1', or Enter for all): ").strip()
            bpf = bpf if bpf else None

            print(f"\n{GREEN}[+] Starting live packet capture (Timeout: 20s)...{RESET}")
            print(f"{YELLOW}[!] Press Ctrl+C at any time to halt capture.{RESET}\n")
            print("-" * 85)
            try:
                sniffer.sniff_live(count=count, bpf_filter=bpf, timeout=20, callback=lambda p: print(format_packet_row(p)))
            except PermissionError as pe:
                print(f"{RED}[✗] {pe}{RESET}")
            except Exception as e:
                print(f"{RED}[!] Capture error: {e}{RESET}")
                print(f"{YELLOW}[i] Tip: On Windows, live capture requires Npcap (https://npcap.com) with WinPcap compatibility mode.{RESET}")
            print("-" * 85)

            if sniffer.captured_packets:
                analyzer = TrafficAnalyzer(sniffer.captured_packets)
                display_statistics(analyzer.get_summary())

        elif choice == "4":
            if not sniffer.captured_packets:
                print(f"{YELLOW}[!] No packets currently loaded. Please run Mode 1 or Mode 3 first.{RESET}\n")
                continue
            print(f"\n{CYAN}FILTER OPTIONS (Press Enter to skip any criteria):{RESET}")
            f_proto = input("Protocol (TCP/UDP/ICMP/DNS/HTTP): ").strip()
            f_ip = input("IP Address: ").strip()
            f_port_str = input("Port: ").strip()
            f_port = int(f_port_str) if f_port_str.isdigit() else None

            filtered = sniffer.filter_packets(
                protocol=f_proto if f_proto else None,
                ip=f_ip if f_ip else None,
                port=f_port
            )
            print(f"\n{GREEN}[✓] Matched {len(filtered)} packet(s):{RESET}")
            print("-" * 85)
            for p in filtered:
                print(format_packet_row(p))
            print("-" * 85 + "\n")

        elif choice == "5":
            if not sniffer.captured_packets:
                print(f"{YELLOW}[!] No packets in memory to export.{RESET}\n")
                continue
            default_csv = os.path.join(reports_dir, "exported_packets.csv")
            csv_path = input(f"Enter CSV export path [default: {default_csv}]: ").strip()
            if not csv_path:
                csv_path = default_csv
            out = sniffer.export_to_csv(csv_path)
            print(f"{GREEN}[✓] Packet metadata exported successfully to: {out}{RESET}\n")

        elif choice == "6":
            print(f"{CYAN}[+] Launching Web Security Dashboard on http://127.0.0.1:5000...{RESET}")
            try:
                import web_dashboard
                web_dashboard.run_web_server(port=5000)
            except Exception as e:
                print(f"{RED}[!] Failed to launch dashboard: {e}{RESET}")

        elif choice == "7":
            print(f"{CYAN}Exiting Network Sniffer. Stay secure!{RESET}")
            break


def main():
    parser = argparse.ArgumentParser(description="CodeAlpha Basic Network Sniffer & Packet Analyzer")
    parser.add_argument("--mode", choices=["interactive", "offline", "live", "generate", "web"], default="interactive",
                        help="Operation mode (default: interactive)")
    parser.add_argument("--pcap", type=str, help="Path to PCAP file for offline analysis")
    parser.add_argument("--count", type=int, default=20, help="Number of packets to capture")
    parser.add_argument("--filter", type=str, help="BPF filter string (e.g., 'tcp', 'port 80')")
    parser.add_argument("--export-csv", type=str, help="Path to export results as CSV")
    parser.add_argument("--authorized", action="store_true", help="Explicitly certify permission for live capture")
    parser.add_argument("--port", type=int, default=5000, help="Port for web dashboard")

    args = parser.parse_args()

    reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
    sample_pcap = os.path.join(reports_dir, "sample_capture.pcap")

    if args.mode == "generate":
        target = args.pcap if args.pcap else sample_pcap
        out = generate_sample_pcap(target)
        print(f"[+] Sample PCAP generated at: {out}")
        return

    if args.mode == "web":
        import web_dashboard
        web_dashboard.run_web_server(port=args.port)
        return

    if args.mode == "offline":
        target = args.pcap if args.pcap else sample_pcap
        if not os.path.exists(target):
            generate_sample_pcap(target)
        sniffer = NetworkSniffer(authorized=True)
        print(f"[+] Analyzing offline PCAP: {target}")
        sniffer.sniff_offline(target, count=args.count, callback=lambda p: print(format_packet_row(p)))
        stats = TrafficAnalyzer(sniffer.captured_packets).get_summary()
        display_statistics(stats)
        if args.export_csv:
            sniffer.export_to_csv(args.export_csv)
            print(f"[✓] Exported to CSV: {args.export_csv}")
        return

    if args.mode == "live":
        if not args.authorized:
            if not check_authorization():
                sys.exit(1)
        sniffer = NetworkSniffer(authorized=True)
        print(f"[+] Sniffing live traffic (count={args.count}, filter={args.filter})...")
        sniffer.sniff_live(count=args.count, bpf_filter=args.filter, callback=lambda p: print(format_packet_row(p)))
        stats = TrafficAnalyzer(sniffer.captured_packets).get_summary()
        display_statistics(stats)
        if args.export_csv:
            sniffer.export_to_csv(args.export_csv)
            print(f"[✓] Exported to CSV: {args.export_csv}")
        return

    # Default to interactive
    run_interactive()


if __name__ == "__main__":
    main()

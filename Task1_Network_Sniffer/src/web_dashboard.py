"""
Web Security Dashboard for Network Sniffer
Author: CodeAlpha Cybersecurity Intern
Task: Task 1 - Basic Network Sniffer

Flask-based cybersecurity dashboard providing real-time packet inspection,
protocol analytics, filtering, and CSV download capabilities.
"""

import json
import os
from flask import Flask, render_template_string, jsonify, request, send_file
from sniffer import NetworkSniffer
from analyzer import TrafficAnalyzer
from generator import generate_sample_pcap

app = Flask(__name__)

# Global sniffer session
SNIFFER_STATE = {
    "sniffer": NetworkSniffer(authorized=True),
    "pcap_file": ""
}

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CodeAlpha Network Sniffer Dashboard</title>
    <style>
        :root {
            --bg-dark: #0a0e17;
            --card-bg: #111827;
            --card-border: #1f293d;
            --accent-cyan: #00f2fe;
            --accent-blue: #4facfe;
            --accent-green: #10b981;
            --accent-yellow: #f59e0b;
            --accent-red: #ef4444;
            --accent-purple: #8b5cf6;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
        body { background-color: var(--bg-dark); color: var(--text-main); min-height: 100vh; padding: 24px; }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--card-border); padding-bottom: 18px; margin-bottom: 24px; }
        .logo-group { display: flex; align-items: center; gap: 14px; }
        .logo-icon { width: 42px; height: 42px; background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue)); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 22px; font-weight: bold; color: #000; box-shadow: 0 0 15px rgba(0, 242, 254, 0.4); }
        .title h1 { font-size: 20px; font-weight: 700; letter-spacing: 0.5px; }
        .title p { font-size: 13px; color: var(--text-muted); }
        .auth-badge { display: inline-flex; align-items: center; gap: 6px; padding: 6px 12px; background: rgba(16, 185, 129, 0.15); border: 1px solid var(--accent-green); border-radius: 20px; font-size: 12px; color: var(--accent-green); font-weight: 600; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .stat-card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px; padding: 20px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3); }
        .stat-card h3 { font-size: 12px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 1px; margin-bottom: 8px; }
        .stat-card .val { font-size: 28px; font-weight: 700; color: var(--accent-cyan); }
        .stat-card .sub { font-size: 12px; color: var(--text-muted); margin-top: 4px; }
        .controls-card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px; padding: 18px; margin-bottom: 24px; display: flex; flex-wrap: wrap; gap: 12px; align-items: center; justify-content: space-between; }
        .btn { padding: 9px 18px; border-radius: 8px; border: none; font-size: 13px; font-weight: 600; cursor: pointer; display: inline-flex; align-items: center; gap: 8px; transition: all 0.2s ease; }
        .btn-primary { background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue)); color: #0a0e17; }
        .btn-primary:hover { opacity: 0.9; transform: translateY(-1px); }
        .btn-outline { background: transparent; border: 1px solid var(--card-border); color: var(--text-main); }
        .btn-outline:hover { background: rgba(255, 255, 255, 0.05); }
        .btn-success { background: var(--accent-green); color: #000; }
        .filter-input { background: #0b1120; border: 1px solid var(--card-border); border-radius: 6px; padding: 8px 12px; color: var(--text-main); font-size: 13px; min-width: 140px; }
        .filter-input:focus { outline: none; border-color: var(--accent-cyan); }
        .table-card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px; overflow: hidden; }
        .table-card-header { padding: 16px 20px; border-bottom: 1px solid var(--card-border); display: flex; justify-content: space-between; align-items: center; }
        .table-card-header h2 { font-size: 16px; font-weight: 600; }
        .table-wrapper { overflow-x: auto; max-height: 520px; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; text-align: left; }
        th { background: #0d1322; color: var(--text-muted); padding: 12px 16px; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; position: sticky; top: 0; z-index: 10; border-bottom: 1px solid var(--card-border); }
        td { padding: 12px 16px; border-bottom: 1px solid #1a2234; color: #d1d5db; }
        tr:hover td { background: rgba(255, 255, 255, 0.02); }
        .badge { padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
        .badge-tcp { background: rgba(79, 172, 254, 0.15); color: #4facfe; border: 1px solid #4facfe; }
        .badge-udp { background: rgba(139, 92, 246, 0.15); color: #a78bfa; border: 1px solid #8b5cf6; }
        .badge-icmp { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid #f59e0b; }
        .badge-dns { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid #10b981; }
        .badge-http { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid #ef4444; }
        .badge-other { background: rgba(156, 163, 175, 0.15); color: #d1d5db; border: 1px solid #6b7280; }
        .info-cell { max-width: 320px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-family: monospace; font-size: 12px; }
        .security-banner { background: rgba(245, 158, 11, 0.1); border-left: 4px solid var(--accent-yellow); padding: 12px 16px; border-radius: 6px; margin-bottom: 20px; font-size: 13px; color: #fbbf24; }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo-group">
            <div class="logo-icon">CA</div>
            <div class="title">
                <h1>CodeAlpha Network Security Sniffer</h1>
                <p>Task 1: Protocol Inspection & Traffic Telemetry Dashboard</p>
            </div>
        </div>
        <div class="auth-badge">
            <span style="font-size: 14px;">●</span> Authorized Audit Mode
        </div>
    </div>

    <div class="security-banner">
        <strong>Security & Privacy Policy Notice:</strong> Live packet capture requires explicit consent from network owners. All payloads are automatically sanitized, and authentication tokens/passwords are stripped from logging.
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <h3>Total Packets</h3>
            <div class="val" id="stat-total">0</div>
            <div class="sub">Packets logged</div>
        </div>
        <div class="stat-card">
            <h3>Total Bandwidth</h3>
            <div class="val" id="stat-bytes">0 B</div>
            <div class="sub">Payload volume</div>
        </div>
        <div class="stat-card">
            <h3>Avg Packet Size</h3>
            <div class="val" id="stat-avg">0 B</div>
            <div class="sub">Mean frame length</div>
        </div>
        <div class="stat-card">
            <h3>Top Protocol</h3>
            <div class="val" id="stat-top-proto">None</div>
            <div class="sub" id="stat-proto-count">0 packets</div>
        </div>
    </div>

    <div class="controls-card">
        <div style="display: flex; gap: 8px; flex-wrap: wrap;">
            <button class="btn btn-primary" onclick="loadSampleTraffic()">⚡ Load Sample Capture</button>
            <a href="/api/export-csv" class="btn btn-outline" download="network_packets.csv">📥 Export to CSV</a>
        </div>
        <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
            <input type="text" id="filter-proto" class="filter-input" placeholder="Filter Protocol (TCP/DNS...)" onkeyup="filterTable()">
            <input type="text" id="filter-ip" class="filter-input" placeholder="Filter IP Address..." onkeyup="filterTable()">
            <button class="btn btn-outline" onclick="resetFilters()">Clear Filters</button>
        </div>
    </div>

    <div class="table-card">
        <div class="table-card-header">
            <h2>Captured Packet Stream</h2>
            <span id="packet-counter" style="font-size: 13px; color: var(--text-muted);">0 packets displayed</span>
        </div>
        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th style="width: 50px;">#</th>
                        <th style="width: 140px;">Timestamp</th>
                        <th style="width: 90px;">Protocol</th>
                        <th style="width: 180px;">Source</th>
                        <th style="width: 180px;">Destination</th>
                        <th style="width: 80px;">Length</th>
                        <th>Packet Summary / Info</th>
                    </tr>
                </thead>
                <tbody id="packet-tbody">
                    <tr><td colspan="7" style="text-align: center; padding: 40px; color: var(--text-muted);">No packets loaded yet. Click "Load Sample Capture" above to analyze traffic.</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <script>
        let allPackets = [];

        function getBadgeClass(proto) {
            const p = proto.toUpperCase();
            if (p.includes('TCP')) return 'badge-tcp';
            if (p.includes('UDP')) return 'badge-udp';
            if (p.includes('ICMP')) return 'badge-icmp';
            if (p.includes('DNS')) return 'badge-dns';
            if (p.includes('HTTP')) return 'badge-http';
            return 'badge-other';
        }

        async function loadSampleTraffic() {
            try {
                const res = await fetch('/api/load-sample');
                const data = await res.json();
                allPackets = data.packets || [];
                renderStats(data.stats);
                renderTable(allPackets);
            } catch (err) {
                alert('Error loading packets: ' + err);
            }
        }

        function renderStats(stats) {
            if (!stats) return;
            document.getElementById('stat-total').innerText = stats.total_packets.toLocaleString();
            document.getElementById('stat-bytes').innerText = (stats.total_bytes / 1024).toFixed(2) + ' KB';
            document.getElementById('stat-avg').innerText = stats.avg_packet_size + ' B';
            
            const protos = Object.entries(stats.protocols || {});
            if (protos.length > 0) {
                protos.sort((a, b) => b[1].count - a[1].count);
                document.getElementById('stat-top-proto').innerText = protos[0][0];
                document.getElementById('stat-proto-count').innerText = protos[0][1].count + ' packets (' + protos[0][1].percentage + '%)';
            }
        }

        function renderTable(packets) {
            const tbody = document.getElementById('packet-tbody');
            document.getElementById('packet-counter').innerText = `${packets.length} packets displayed`;

            if (packets.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; padding: 40px; color: var(--text-muted);">No matching packets found.</td></tr>';
                return;
            }

            tbody.innerHTML = packets.map(p => {
                const src = p.src_port && p.src_port !== '-' ? `${p.src_ip}:${p.src_port}` : p.src_ip;
                const dst = p.dst_port && p.dst_port !== '-' ? `${p.dst_ip}:${p.dst_port}` : p.dst_ip;
                const time = p.timestamp ? p.timestamp.substring(11, 23) : '';
                return `
                    <tr>
                        <td><strong>${p.id}</strong></td>
                        <td style="font-family: monospace;">${time}</td>
                        <td><span class="badge ${getBadgeClass(p.protocol)}">${p.protocol}</span></td>
                        <td style="font-family: monospace;">${src}</td>
                        <td style="font-family: monospace;">${dst}</td>
                        <td>${p.length} B</td>
                        <td class="info-cell" title="${p.info}">${p.info}</td>
                    </tr>
                `;
            }).join('');
        }

        function filterTable() {
            const protoFilter = document.getElementById('filter-proto').value.trim().toUpperCase();
            const ipFilter = document.getElementById('filter-ip').value.trim();

            const filtered = allPackets.filter(p => {
                const matchProto = !protoFilter || p.protocol.toUpperCase().includes(protoFilter);
                const matchIp = !ipFilter || p.src_ip.includes(ipFilter) || p.dst_ip.includes(ipFilter);
                return matchProto && matchIp;
            });
            renderTable(filtered);
        }

        function resetFilters() {
            document.getElementById('filter-proto').value = '';
            document.getElementById('filter-ip').value = '';
            renderTable(allPackets);
        }

        // Auto-load sample on startup
        window.onload = loadSampleTraffic;
    </script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/load-sample")
def api_load_sample():
    reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
    sample_pcap = os.path.join(reports_dir, "sample_capture.pcap")
    if not os.path.exists(sample_pcap):
        generate_sample_pcap(sample_pcap)

    sniffer = NetworkSniffer(authorized=True)
    packets = sniffer.sniff_offline(sample_pcap)
    analyzer = TrafficAnalyzer(packets)
    stats = analyzer.get_summary()

    SNIFFER_STATE["sniffer"] = sniffer
    SNIFFER_STATE["pcap_file"] = sample_pcap

    return jsonify({"packets": packets, "stats": stats})


@app.route("/api/export-csv")
def api_export_csv():
    sniffer = SNIFFER_STATE["sniffer"]
    reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
    csv_file = os.path.join(reports_dir, "dashboard_export.csv")
    sniffer.export_to_csv(csv_file)
    return send_file(csv_file, as_attachment=True, download_name="network_packets.csv")


def run_web_server(port: int = 5000):
    print(f"[+] Launching CodeAlpha Network Sniffer Dashboard on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False)


if __name__ == "__main__":
    run_web_server()

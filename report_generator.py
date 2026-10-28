"""
report_generator.py — CSV, JSON, and HTML export utilities.
"""

from __future__ import annotations

import csv
import json
import os
import logging
from datetime import datetime, timezone
from typing import List

import config

logger = logging.getLogger(__name__)

os.makedirs(config.EXPORT_DIR, exist_ok=True)


def _ts() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")


# ─────────────────────────────────────────────────────────────────────────────
#  CSV Export
# ─────────────────────────────────────────────────────────────────────────────

def export_packets_csv(packets: List[dict], interface: str = "", period: str = "") -> str:
    """Write packets to a CSV file and return the file path."""
    filename = f"packets_{_ts()}.csv"
    filepath = os.path.join(config.EXPORT_DIR, filename)

    fields = ["id", "timestamp", "protocol", "src_ip", "dst_ip",
              "src_port", "dst_port", "tcp_flags", "length", "info", "is_demo"]

    with open(filepath, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        # Header comment
        fh.write(f"# Network Analyzer — Packet Export\n")
        fh.write(f"# Interface: {interface}\n")
        fh.write(f"# Period: {period}\n")
        fh.write(f"# Exported: {datetime.now(tz=timezone.utc).isoformat()}\n")
        writer.writeheader()
        for pkt in packets:
            writer.writerow(pkt)

    logger.info("CSV export written to %s (%d rows)", filepath, len(packets))
    return filepath


# ─────────────────────────────────────────────────────────────────────────────
#  JSON Export
# ─────────────────────────────────────────────────────────────────────────────

def export_stats_json(stats: dict, interface: str = "", period: str = "") -> str:
    """Write traffic statistics to a JSON file and return the file path."""
    filename = f"stats_{_ts()}.json"
    filepath = os.path.join(config.EXPORT_DIR, filename)

    payload = {
        "meta": {
            "interface": interface,
            "period":    period,
            "exported":  datetime.now(tz=timezone.utc).isoformat(),
        },
        "statistics": stats,
    }

    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)

    logger.info("JSON export written to %s", filepath)
    return filepath


# ─────────────────────────────────────────────────────────────────────────────
#  HTML Report
# ─────────────────────────────────────────────────────────────────────────────

def export_html_report(
    stats: dict,
    anomalies: List[dict],
    interface: str = "",
    period: str = "",
    mode: str = "live",
) -> str:
    """Generate an HTML summary report and return the file path."""
    filename = f"report_{_ts()}.html"
    filepath = os.path.join(config.EXPORT_DIR, filename)

    now_str = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    demo_banner = (
        '<div class="demo-banner">⚠️  This report contains SIMULATED (demo) data — '
        "not real network traffic.</div>"
        if mode == "demo"
        else ""
    )

    proto_rows = ""
    for proto, count in (stats.get("protocol_distribution") or {}).items():
        proto_rows += f"<tr><td>{proto}</td><td>{count:,}</td></tr>"

    anomaly_rows = ""
    for a in anomalies:
        sev = a.get("severity", "medium")
        ports = ", ".join(str(p) for p in (a.get("dst_ports") or [])[:10])
        anomaly_rows += f"""
        <tr class="sev-{sev}">
          <td>{a.get('detected_at','')[:19]}</td>
          <td>{a.get('finding_type','')}</td>
          <td>{a.get('src_ip') or '—'}</td>
          <td>{a.get('dst_ip') or '—'}</td>
          <td>{ports or '—'}</td>
          <td>{a.get('packet_count','')}</td>
          <td><span class="badge sev-{sev}">{sev.upper()}</span></td>
          <td>{a.get('explanation','')}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Analyzer Report — {now_str}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#c9d1d9;padding:2rem}}
  h1{{color:#58a6ff;font-size:1.8rem;margin-bottom:.25rem}}
  h2{{color:#79c0ff;margin:1.5rem 0 .5rem}}
  .meta{{color:#8b949e;font-size:.85rem;margin-bottom:1.5rem}}
  .demo-banner{{background:#856404;color:#ffe69c;padding:.75rem 1rem;border-radius:6px;margin-bottom:1rem;font-weight:600}}
  table{{width:100%;border-collapse:collapse;font-size:.85rem;margin-bottom:1rem}}
  th,td{{text-align:left;padding:.5rem .75rem;border-bottom:1px solid #21262d}}
  th{{background:#161b22;color:#79c0ff}}
  tr:hover{{background:#161b22}}
  .stat-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:1rem;margin-bottom:1.5rem}}
  .stat-card{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:1rem;text-align:center}}
  .stat-val{{font-size:1.6rem;font-weight:700;color:#58a6ff}}
  .stat-lbl{{font-size:.75rem;color:#8b949e;margin-top:.25rem}}
  .badge{{padding:.2em .55em;border-radius:4px;font-size:.75rem;font-weight:700}}
  .sev-high td,.sev-high{{border-left:3px solid #f85149}}
  .sev-medium td,.sev-medium{{border-left:3px solid #e3b341}}
  .sev-low td,.sev-low{{border-left:3px solid #3fb950}}
  .badge.sev-high{{background:#490202;color:#f85149}}
  .badge.sev-medium{{background:#3a2a00;color:#e3b341}}
  .badge.sev-low{{background:#04260f;color:#3fb950}}
  footer{{margin-top:2rem;color:#484f58;font-size:.75rem;text-align:center}}
</style>
</head>
<body>
<h1>🔍 Network Analyzer Report</h1>
<p class="meta">Interface: <strong>{interface}</strong> &nbsp;|&nbsp;
Period: <strong>{period}</strong> &nbsp;|&nbsp;
Generated: <strong>{now_str}</strong> &nbsp;|&nbsp;
Mode: <strong>{mode.upper()}</strong></p>
{demo_banner}

<h2>Summary</h2>
<div class="stat-grid">
  <div class="stat-card"><div class="stat-val">{stats.get('total_packets',0):,}</div><div class="stat-lbl">Total Packets</div></div>
  <div class="stat-card"><div class="stat-val">{stats.get('total_bytes',0) // 1024:,} KB</div><div class="stat-lbl">Total Data</div></div>
  <div class="stat-card"><div class="stat-val">{stats.get('avg_packet_size',0):.0f}B</div><div class="stat-lbl">Avg Packet Size</div></div>
  <div class="stat-card"><div class="stat-val">{stats.get('packet_rate_pps',0):.1f}</div><div class="stat-lbl">Packets / sec</div></div>
  <div class="stat-card"><div class="stat-val">{len(anomalies)}</div><div class="stat-lbl">Potential Anomalies</div></div>
</div>

<h2>Protocol Distribution</h2>
<table>
  <thead><tr><th>Protocol</th><th>Packet Count</th></tr></thead>
  <tbody>{proto_rows}</tbody>
</table>

<h2>Potential Anomalies</h2>
{'<p style="color:#8b949e">No anomalies detected in this session.</p>' if not anomalies else f"""
<table>
  <thead>
    <tr><th>Timestamp</th><th>Type</th><th>Src IP</th><th>Dst IP</th>
        <th>Ports</th><th>Packets</th><th>Severity</th><th>Explanation</th></tr>
  </thead>
  <tbody>{anomaly_rows}</tbody>
</table>"""}

<footer>Generated by Network Monitoring &amp; Security Analyzer &mdash; for authorized use only.</footer>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write(html)

    logger.info("HTML report written to %s", filepath)
    return filepath

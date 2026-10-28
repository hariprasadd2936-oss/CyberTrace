"""
config.py — Application settings and detection thresholds.
"""

import os
import sys

# ─────────────────────────────────────────
#  Flask / Server
# ─────────────────────────────────────────
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000
FLASK_DEBUG = False
SECRET_KEY = os.environ.get("SECRET_KEY", "network-analyzer-secret-key-2024")

# ─────────────────────────────────────────
#  Database
# ─────────────────────────────────────────
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_PATH = os.path.join(BASE_DIR, "data", "network_analyzer.db")

# ─────────────────────────────────────────
#  Packet Capture
# ─────────────────────────────────────────
# Maximum number of packets kept in-memory per capture session
MAX_PACKET_BUFFER = 10_000
# Packet capture timeout (seconds); None = non-blocking loop
CAPTURE_TIMEOUT = None
# Default filter string (empty = capture everything)
DEFAULT_BPF_FILTER = ""
# Packets returned per API page
PACKETS_PER_PAGE = 100

# ─────────────────────────────────────────
#  Anomaly Detection Thresholds
# ─────────────────────────────────────────

# Port Scan: unique destination ports from one source → one target within window
PORT_SCAN_THRESHOLD = 15          # distinct ports
PORT_SCAN_WINDOW_SECONDS = 10     # rolling window

# Host Scan: unique destination IPs from one source within window
HOST_SCAN_THRESHOLD = 10          # distinct destination IPs
HOST_SCAN_WINDOW_SECONDS = 10

# Packet Burst: packets per second threshold
BURST_THRESHOLD_PPS = 500         # packets per second
BURST_WINDOW_SECONDS = 2

# Repeated SYN: TCP SYN packets to the same dst ip:port within window
SYN_FLOOD_THRESHOLD = 50          # SYN packets
SYN_FLOOD_WINDOW_SECONDS = 5

# Unusual Volume: cumulative byte threshold per session
UNUSUAL_VOLUME_BYTES = 100 * 1024 * 1024   # 100 MB
UNUSUAL_VOLUME_PACKETS = 50_000            # packet count

# Anomaly deduplication cooldown (seconds) — won't re-raise same finding
ANOMALY_COOLDOWN_SECONDS = 30

# ─────────────────────────────────────────
#  Reporting / Export
# ─────────────────────────────────────────
EXPORT_DIR = os.path.join(BASE_DIR, "exports")

# ─────────────────────────────────────────
#  Demo Mode
# ─────────────────────────────────────────
DEMO_PACKET_COUNT = 200   # number of synthetic demo packets to generate

# ─────────────────────────────────────────
#  Retention
# ─────────────────────────────────────────
# Maximum number of capture sessions stored in history
MAX_HISTORY_SESSIONS = 50
# Clear exports older than N days (0 = never auto-clean)
EXPORT_RETENTION_DAYS = 7

# ─────────────────────────────────────────
#  Alerts & Webhooks
# ─────────────────────────────────────────
WEBHOOK_URL = os.environ.get("CYBERTRACE_WEBHOOK_URL", "")
ALERT_MIN_SEVERITY = os.environ.get("CYBERTRACE_ALERT_SEVERITY", "HIGH")

# ─────────────────────────────────────────
#  Google Maps & 3D Threat Engine
# ─────────────────────────────────────────
GOOGLE_MAPS_API_KEY = os.environ.get(
    "GOOGLE_MAPS_API_KEY",
    "AIzaSyAxcACWqSvzmoFHViTmh615aPXBOfcdI38"
)



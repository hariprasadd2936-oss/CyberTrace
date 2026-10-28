# CyberTrace — Network Monitoring & Security Analyzer

## Project Status: ✅ 100% Complete

All files are located in: `c:\Hari project\Network Analysis\`

---

## File Inventory (30 files)

### Backend Modules
| File | Purpose |
|---|---|
| [`app.py`](file:///c:/Hari%20project/Network%20Analysis/app.py) | Flask app — all 20+ API endpoints with PyInstaller asset bundle support |
| [`config.py`](file:///c:/Hari%20project/Network%20Analysis/config.py) | Detection thresholds, server settings, and persistent pathing |
| [`database.py`](file:///c:/Hari%20project/Network%20Analysis/database.py) | SQLite: sessions, anomalies, settings |
| [`packet_capture.py`](file:///c:/Hari%20project/Network%20Analysis/packet_capture.py) | Scapy thread-safe capture + CaptureManager |
| [`packet_parser.py`](file:///c:/Hari%20project/Network%20Analysis/packet_parser.py) | TCP/UDP/ICMP/DNS/ARP header parsing |
| [`traffic_analyzer.py`](file:///c:/Hari%20project/Network%20Analysis/traffic_analyzer.py) | Packet counters, top IPs, time-series |
| [`threat_intel.py`](file:///c:/Hari%20project/Network%20Analysis/threat_intel.py) | GeoIP geolocation, threat reputation & offline heuristics |
| [`anomaly_detector.py`](file:///c:/Hari%20project/Network%20Analysis/anomaly_detector.py) | 5 rule-based detectors + deduplication |
| [`report_generator.py`](file:///c:/Hari%20project/Network%20Analysis/report_generator.py) | CSV, JSON, HTML export |
| [`demo_data.py`](file:///c:/Hari%20project/Network%20Analysis/demo_data.py) | Synthetic demo packets with injected anomalies |

### Frontend
| File | Purpose |
|---|---|
| [`static/css/main.css`](file:///c:/Hari%20project/Network%20Analysis/static/css/main.css) | Dark glassmorphism purple theme, full design system |
| [`static/js/app.js`](file:///c:/Hari%20project/Network%20Analysis/static/js/app.js) | Global JS: status poll, charts, toasts, utils |
| `templates/base.html` | Sidebar navigation with guide link, topbar |
| `templates/index.html` | Bento dashboard with live packet counters |
| `templates/guide.html` | Interactive 6-step Live Capture Walkthrough |
| `templates/packets.html` | Live packet table with filters |
| `templates/statistics.html` | Traffic stats and charts |
| `templates/anomalies.html` | Anomaly findings feed |
| `templates/map.html` | 3D World Threat Map & GeoIP visualization |
| `templates/members.html` | Network Members & Hardware Address Directory |
| `templates/interfaces.html` | Interface selection |
| `templates/history.html` | Session history |
| `templates/export.html` | CSV/JSON/HTML export |
| `templates/settings.html` | Threshold configuration |

### Deployment & Tools
| File | Purpose |
|---|---|
| [`start.bat`](file:///c:/Hari%20project/Network%20Analysis/start.bat) | Windows 1-click launcher with admin elevation & guide auto-open |
| [`build_desktop.bat`](file:///c:/Hari%20project/Network%20Analysis/build_desktop.bat) | Desktop .exe standalone packaging tool |
| `CyberTrace.spec` | Optimized PyInstaller build specification |
| `tests/test_packet_parser.py` | TCP flags, demo passthrough, interface enumeration |
| `tests/test_anomaly_detector.py` | All 5 rules, deduplication, field validation |
| `tests/test_demo_data.py` | Demo packet structure and injected patterns |
| `tests/test_threat_intel.py` | Geolocation, threat scoring, and offline fallbacks |
| `tests/test_bento_api_and_capture.py` | Bento API routes, interface switching, lifecycle |
| [`requirements.txt`](file:///c:/Hari%20project/Network%20Analysis/requirements.txt) | Python dependencies |
| [`README.md`](file:///c:/Hari%20project/Network%20Analysis/README.md) | Full setup and usage guide |

---

## Quick Start (Linux)

```bash
cd "/opt/netwatch"   # or wherever you copy the project
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
sudo apt install libpcap-dev -y          # for Scapy raw sockets
sudo setcap cap_net_raw+eip $(which python3)  # grant capture privilege
python3 app.py
# Open: http://127.0.0.1:5000
```

## Run Tests

```bash
python3 -m pytest tests/ -v
```

---

## Anomaly Detection Rules

| Rule | Trigger | Severity |
|---|---|---|
| Possible Port Scan | ≥15 distinct ports / 10s | 🔴 High |
| Possible Host Scan | ≥10 distinct dst IPs / 10s | 🔴 High |
| Unusual Packet Burst | ≥500 pps over 2s | 🟡 Medium |
| Repeated Connection Attempts | ≥50 TCP SYN to same dst / 5s | 🔴 High |
| Unusual Traffic Volume | >100 MB or >50k packets | 🟢 Low |

All labeled **Potential Anomaly** — not confirmed attacks.

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/interfaces` | List network interfaces |
| POST | `/api/capture/start` | Start live or demo capture |
| POST | `/api/capture/stop` | Stop capture |
| GET | `/api/capture/status` | Current capture status |
| GET | `/api/packets` | Paginated + filtered packet list |
| GET | `/api/stats` | Traffic statistics |
| GET | `/api/anomalies` | Anomaly findings |
| POST | `/api/anomalies/clear` | Clear findings |
| GET | `/api/history` | Session history |
| POST | `/api/history/clear` | Clear history |
| GET/POST | `/api/settings` | Read/write thresholds |
| GET | `/api/export/csv` | Download CSV |
| GET | `/api/export/json` | Download JSON stats |
| GET | `/api/export/html` | Download HTML report |

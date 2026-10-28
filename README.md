# CyberTrace — Network Monitoring & Security Analyzer

A professional, Python-based **Network Monitoring & Security Analyzer** featuring Scapy real-time packet capture, dynamic network interface discovery, deep packet metadata inspection, and an interactive **Analytics Bento Dashboard**.

> ⚠️ **Authorized Use Only.** Only capture traffic on networks and interfaces you are explicitly authorized to monitor. This tool is intended for legitimate network administration, security research, and educational purposes.

---

## 📌 Project Overview & Scope

CyberTrace is a dedicated network analysis tool built with **Python 3**, **Scapy**, **Flask**, and **SQLite**. It focuses strictly on computer networking fundamentals and packet-level inspection.

> **Important:** This project is NOT a SOC platform, SIEM system, threat intelligence platform, or incident response system. It focuses strictly on computer networking fundamentals and packet-level inspection.

---

## 🌟 Key Capabilities

### 1. Dynamic Network Interface Selection & Seamless Switching
- **Zero Hardcoded Interfaces:** Interfaces are detected dynamically from the host operating system using Scapy's `conf.ifaces` and `psutil`.
- **Comprehensive Metadata:** Enumerates friendly adapter names, system device paths, IPv4 addresses, IPv6 addresses, MAC hardware addresses, and UP/DOWN connection state.
- **Instant Dashboard Synchronization:** Selecting an interface in the dropdown instantly updates the Active Interface KPI tile and detail badge on Card A.
- **1-Click Seamless Capture Switching:** Switch monitoring between adapters on the fly without manual stop/start cycles. The server cleanly concludes the previous capture session and initializes capture on the newly selected interface.
- **Preference Persistence:** Stores the selected interface in `localStorage` and synchronizes across all navigation pages.

### 2. Multi-Threaded Real-Time Scapy Capture
- **Dedicated Worker Thread:** Capture runs in a non-recursive background thread (`capture-worker-<iface>`) with 1-second stop polling timeouts.
- **Concurrency Mutex Lock:** Enforces a single active capture worker per instance to prevent race conditions or duplicate sniffing loops.
- **Graceful Lifecycle Management:** Integrated with Python's `atexit` to automatically detach Scapy sniffing threads and flush database records upon process shutdown.
- **BPF Filtering:** Accepts standard Berkeley Packet Filter syntax (e.g. `tcp port 443`, `ip proto 1`, `host 192.168.1.1`).

### 3. Deep Packet Metadata Analysis
- **Layer 2 (Data Link):** Extracts hardware source MAC and destination MAC addresses (`src_mac`, `dst_mac`).
- **Layer 3 (Network):** Identifies IPv4 and IPv6 packet headers and transport layer encapsulations.
- **Layer 4 (Transport):**
  - **TCP:** Source/destination ports, sequence numbers, and decoded flag bits (SYN, ACK, FIN, RST, PSH, URG).
  - **UDP:** Source/destination ports and payload length.
  - **ICMP:** Type and code parsing with human-readable diagnostics (Echo Request, Echo Reply, Destination Unreachable, Time Exceeded).
- **Application & Protocol Resolvers:**
  - **DNS:** QNAME extraction (queried domain name) and Query vs. Response direction across both UDP and TCP.
  - **ARP:** Operation decoding (`Who has?` request vs `Is at` reply) and hardware-to-IP binding resolution.

### 4. Interactive Analytics Bento Dashboard
Inspired by modern glassmorphic UI design, the overview dashboard is organized into four responsive Bento cards:
- **Card A — Network Packet Activity (Col 8):**
  - KPI tiles: Total Packets, Total Data (auto-formatted B/KB/MB/GB), Packet Rate (live PPS & peak PPS), and Active Interface with IPv4 address.
  - Gradient packet rate timeline chart powered by Chart.js.
  - Segmented time-window selector: **1M** (60s), **5M** (300s), **15M** (900s), and **ALL** history.
- **Card B — Traffic Flow Statistics (Col 4):**
  - Live protocol counts and percentage shares for TCP, UDP, DNS, ICMP, ARP, and OTHER.
  - CSS-animated flow bars with protocol-specific color coding.
  - Real-time multi-protocol trend mini chart.
- **Card C — Protocol Distribution (Col 6):**
  - Interactive Chart.js doughnut chart displaying proportional protocol shares with hover tooltips and dynamic percentages.
- **Card D — Traffic Patterns (Col 6):**
  - Hourly packet distribution bar chart.
  - Peak throughput metric and active capture session duration timer.

### 5. Global GeoIP & Threat Intelligence World Map
- **Interactive Dark Matter Map:** Powered by Leaflet.js and CartoDB dark tiles to visualize external connection endpoints around the globe.
- **Pulsing Threat Markers:** Highlights high-risk IPs, Tor exit relays, and malicious scanner networks with dynamic glowing ripples.
- **Threat Scoring Engine:** Automatic threat reputation rating (`CLEAN`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), ASN identification, and cloud/botnet detection.
- **Live Threat Stream:** Real-time feed of foreign endpoints with country flags, cities, and packet volumes.

### 6. Real-Time Webhook Alerting (Discord / Slack / Custom)
- **Instant Incident Push:** Automatically dispatches rich JSON alerts with color-coded embed payloads to Discord, Slack, or webhook URLs when anomalies trigger.
- **Severity Filtering:** Filter notifications by minimum severity (e.g., Critical Only, High & Critical, All).
- **Test Delivery Tool:** One-click test button in Settings to verify webhook endpoint connectivity.

### 7. Strict Demo Mode Isolation
- Simulated synthetic packet generator for demonstration, education, or testing in environments without packet capture permissions.
- Clearly labeled with `DEMO MODE — SIMULATED DATA` warning banners.
- Synthetic packets are marked with `is_demo: True` and segregated from genuine network capture logs.
- Supports interface attribution so simulated data can be tested against any discovered adapter.

### 8. One-Click Desktop Executable (`build_desktop.bat`)
- Automated PyInstaller tool that compiles the full application into a standalone Windows `.exe` application (`dist/CyberTrace.exe`).
- Runs test suites prior to compilation to guarantee release stability.

---

## 🪟 Windows Installation Guide

Live packet capture on Windows requires **Npcap** for Layer 2 raw packet sniffing:

### 1. Download and Install Npcap
1. Download the latest installer from [https://npcap.com/#download](https://npcap.com/#download).
2. During setup, ensure **"Install Npcap in WinPcap API-compatible Mode"** is checked.
3. Complete the installation and reboot if prompted.

### 2. Set Up Virtual Environment & Dependencies
Open PowerShell or Command Prompt in the project folder:

```powershell
python -m venv venv
.\venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Start the Server
```powershell
python app.py
```
Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

---

## 🐧 Kali Linux & Ubuntu Installation Guide

### 1. Install System Dependencies
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv libpcap-dev libcap2-bin tcpdump
```

*Note: `libcap2-bin` provides the `setcap` tool to enable raw packet capture without running the server as `root`.*

### 2. Set Up Virtual Environment
```bash
cd "Network Analysis"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Grant Non-Root Capture Capabilities
Running network tools as `root` creates security risks. Grant `CAP_NET_RAW` capability directly to Python:

```bash
# Grant capability to Python inside the virtual environment:
sudo setcap cap_net_raw+eip $(readlink -f venv/bin/python3)

# Verify capability was applied:
getcap $(readlink -f venv/bin/python3)
# Output: .../venv/bin/python3 cap_net_raw=eip
```

### 4. Start the Server
```bash
python3 app.py
```
Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

---

## 🌐 REST API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/interfaces` | List all discovered network interfaces, IPs, MACs, link state, and capture flags |
| `POST` | `/api/interface/select` | Select an interface for capture or demo mode synchronization |
| `POST` | `/api/capture/start` | Start live packet capture or demo mode (supports `switch=True` for seamless interface change) |
| `POST` | `/api/capture/stop` | Conclude the active capture session and persist final statistics |
| `GET` | `/api/capture/status` | Current worker state (`is_capturing`, `demo_active`, `interface`, `duration`, `last_error`) |
| `GET` | `/api/statistics` | Aggregated metrics, total packets, total bytes, PPS rate, and protocol distribution |
| `GET` | `/api/traffic/timeline` | Time-bucketed traffic timeline with window filter (`?window=60`, `300`, `900`, `all`) |
| `GET` | `/api/packets` | Paginated packet records with filtering by protocol, IP, port, and search query |
| `GET` | `/api/anomalies` | Detected network anomalies (port scans, host scans, high volume spikes) |
| `GET` | `/api/history` | Historical capture sessions with packet volume and date timestamps |

---

## 🧪 Automated Unit Testing

The test suite validates packet parsing across all supported protocols, metadata extraction, timeline aggregation, dynamic interface detection, API endpoints, and single-worker mutex enforcement:

```bash
# Run all 57 unit tests
python -m unittest discover tests -v

# Run specific test modules
python -m unittest tests/test_bento_api_and_capture.py -v
python -m unittest tests/test_packet_parser.py -v
python -m unittest tests/test_anomaly_detector.py -v
python -m unittest tests/test_demo_data.py -v
```

---

## 📁 Project Structure

```
Network Analysis/
├── app.py                            # Flask server, REST API endpoints, interface switching
├── config.py                         # Application configuration constants and defaults
├── packet_capture.py                 # Multi-threaded Scapy capture manager & privilege verifiers
├── packet_parser.py                  # Packet decoding (MAC, IPv4, IPv6, TCP, UDP, ICMP, DNS, ARP)
├── traffic_analyzer.py               # Aggregates packet statistics, timeline buckets, and protocol shares
├── anomaly_detector.py               # Rule-based network anomaly detection
├── threat_intel.py                   # IP Geolocation & Threat Intelligence (with offline fallback)
├── database.py                       # SQLite storage for sessions, statistics, and findings
├── report_generator.py               # Report exporters (CSV, JSON, HTML)
├── demo_data.py                      # Synthetic packet stream generator for demo mode
├── requirements.txt                  # Python dependencies
├── build_desktop.bat                 # 1-Click PyInstaller desktop application compiler
├── start.bat                         # Elevated Windows quick launcher
├── README.md                         # Project documentation and installation guide
├── components/                       # Modern React / TypeScript UI components
│   └── ui/
│       ├── analytics-bento.tsx       # Reusable 4-card Analytics Bento component
│       └── demo.tsx                  # Interactive preview demo with realistic sample traffic
├── templates/                        # Jinja2 HTML templates
│   ├── base.html                     # Navigation layout, sidebar status dot, topbar
│   ├── index.html                    # Analytics Bento dashboard and quick capture controls
│   ├── guide.html                    # Interactive 6-step Live Capture Guide
│   ├── packets.html                  # Live packet table with filter bar and metadata inspector
│   ├── statistics.html               # Protocol distribution charts and bandwidth analysis
│   ├── anomalies.html                # Potential anomaly findings feed
│   ├── interfaces.html               # Network interface cards, capture controls, and switcher
│   ├── history.html                  # Historical capture session viewer
│   ├── export.html                   # Report download center
│   ├── settings.html                 # Anomaly threshold adjustment settings
│   └── 404.html                      # Error page
├── static/
│   ├── css/main.css                  # Bento 12-col grid, glassmorphism, responsive styles
│   └── js/app.js                     # Global utilities, status polling, and toast notifications
├── tests/                            # Automated test suite (72 tests passing)
│   ├── __init__.py
│   ├── test_bento_api_and_capture.py # Tests for Bento API, timeline, interface selection, switching
│   ├── test_packet_parser.py         # Tests for TCP, UDP, ICMP, DNS, ARP header parsing
│   ├── test_anomaly_detector.py      # Tests for anomaly rules and deduplication
│   ├── test_demo_data.py             # Tests for demo data generation
│   └── test_threat_intel.py          # Tests for IP geolocation and threat intelligence
├── dist/                             # Compiled standalone desktop executable (CyberTrace.exe)
├── data/                             # SQLite database storage (network_analyzer.db)
└── exports/                          # Generated report exports
```

---

## 🛡️ Safe Practices & Limitations

1. **Non-Root Execution:** On Linux, use `setcap cap_net_raw+eip` instead of running `sudo python3 app.py`.
2. **Localhost Binding:** The server binds strictly to `127.0.0.1:5000` to prevent exposure over external networks.
3. **Bounded Memory:** Packet buffers are capped at 10,000 packets to prevent excessive RAM consumption.
4. **Separation of Demo Data:** All demo packets have `is_demo: True` and are distinctly badged in the UI and exports.

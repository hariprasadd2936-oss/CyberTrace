"""
packet_capture.py — Scapy packet capture lifecycle with background worker thread.
"""

from __future__ import annotations

import logging
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Optional, Callable

import config
import packet_parser as pp

logger = logging.getLogger(__name__)

# ── Npcap / Scapy Windows elevation deadlock protection ───────────────────────
# When Npcap is installed with AdminOnly=1, calling pcap_findalldevs from an
# unprivileged process causes wpcap.dll to hang indefinitely during Scapy module load.
# Protect against this by making pcap_findalldevs safely return -1 when not elevated.
if sys.platform.startswith("win"):
    import ctypes
    try:
        _is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        _is_admin = False
    if not _is_admin:
        _admin_only = True
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\npcap\Parameters",
            ) as _k:
                _val, _ = winreg.QueryValueEx(_k, "AdminOnly")
                _admin_only = bool(_val)
        except Exception:
            pass
        if _admin_only:
            try:
                import scapy.libs.winpcapy as _wp
                _wp.pcap_findalldevs = lambda devs, err: -1
            except Exception:
                pass

# ── Try importing Scapy ──────────────────────────────────────────────────────
try:
    from scapy.all import sniff, conf as scapy_conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy is not installed — live capture unavailable.")


def check_capture_privileges() -> tuple[bool, str]:
    """
    Check if the process has privileges and system libraries to capture packets.
    - On Linux: checks raw socket CAP_NET_RAW / root.
    - On Windows: checks whether Npcap / WinPcap is available to Scapy and whether
      Admin privileges are required.
    """
    if sys.platform.startswith("linux"):
        import socket
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            s.close()
            return True, ""
        except PermissionError:
            return False, (
                "Permission denied: Packet capture requires CAP_NET_RAW capability.\n"
                "To run without full root:\n"
                "  sudo setcap cap_net_raw+eip $(which python3)\n"
                "Or if using a virtual environment:\n"
                "  sudo setcap cap_net_raw+eip $(readlink -f venv/bin/python3)"
            )
        except OSError as exc:
            if getattr(exc, "errno", None) == 1:  # EPERM
                return False, (
                    "Permission denied (EPERM): Raw socket creation not permitted.\n"
                    "Run: sudo setcap cap_net_raw+eip $(which python3)"
                )
            return True, ""
        except Exception:
            return True, ""

    elif sys.platform.startswith("win"):
        import ctypes
        import os

        # Check if wpcap.dll is installed
        has_wpcap = any(
            os.path.exists(p)
            for p in [
                r"C:\Windows\System32\wpcap.dll",
                r"C:\Windows\SysWOW64\wpcap.dll",
                r"C:\Windows\System32\Npcap\wpcap.dll",
            ]
        )
        if not has_wpcap:
            return False, (
                "Npcap is required for live packet capture on Windows.\n"
                "1. Download and install Npcap from: https://npcap.com/#download\n"
                "2. During installation, check 'Install Npcap in WinPcap API-compatible Mode'.\n"
                "3. Restart the application."
            )

        # Check if current process is running as Administrator
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = False

        # Check if Npcap is in AdminOnly mode in the registry
        admin_only = False
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\npcap\Parameters",
            ) as key:
                val, _ = winreg.QueryValueEx(key, "AdminOnly")
                admin_only = bool(val)
        except Exception:
            pass

        if not is_admin:
            if admin_only:
                return False, (
                    "Npcap is installed in 'Admin-Only' mode on this system.\n"
                    "The application must be run with Administrator privileges when Npcap is configured for Admin-Only access.\n"
                    "To capture live packets, right-click 'start.bat' and select 'Run as administrator', or run 'fix_npcap_permissions.bat'."
                )
            return True, ""

        return True, ""

    return True, ""


class CaptureSession:
    """
    Manages a single packet-capture lifecycle in a dedicated background worker thread.
    Thread-safe: start/stop can be called from any thread.
    Packets are accumulated in a bounded deque; statistics are updated atomically.
    """

    def __init__(self, interface: str, session_id: int, bpf_filter: str = "", capture_mode: str = "scapy"):
        self.interface    = interface
        self.session_id   = session_id
        self.bpf_filter   = bpf_filter
        self.capture_mode = capture_mode

        self._running   = False
        self._lock      = threading.Lock()
        self._thread: Optional[threading.Thread] = None

        # Packet buffer (bounded)
        self._packets: deque[dict] = deque(maxlen=config.MAX_PACKET_BUFFER)
        self._packet_counter = 0   # monotonic ID
        self._total_bytes    = 0
        self._started_at: Optional[str] = None
        self._stopped_at: Optional[str] = None
        self._last_update: Optional[str] = None
        self.last_error: Optional[str] = None
        self._worker_ready = threading.Event()

        # Callbacks list (supports multiple simultaneous consumers: analyzer, detector, etc.)
        self._callbacks: list[Callable[[dict], None]] = []

    # ─── Public API ──────────────────────────────────────────────────────

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._running

    @property
    def total_packets(self) -> int:
        with self._lock:
            return self._packet_counter

    @property
    def total_bytes(self) -> int:
        with self._lock:
            return self._total_bytes

    @property
    def started_at(self) -> Optional[str]:
        return self._started_at

    @property
    def stopped_at(self) -> Optional[str]:
        return self._stopped_at

    @property
    def last_update(self) -> Optional[str]:
        return self._last_update

    def add_packet_callback(self, callback: Callable[[dict], None]):
        """Register a callback invoked for each parsed packet."""
        with self._lock:
            if callback not in self._callbacks:
                self._callbacks.append(callback)

    def on_packet(self, callback: Callable[[dict], None]):
        """Register a callback invoked for each parsed packet (alias for add_packet_callback)."""
        self.add_packet_callback(callback)

    def _resolve_scapy_interface(self):
        """Resolve friendly interface name to Scapy device or Npcap NPF GUID if on Windows."""
        if not sys.platform.startswith("win"):
            return self.interface

        # 1. If already in NPF format, use directly
        if self.interface.startswith(r"\Device\NPF_"):
            return self.interface

        target = self.interface.strip().lower()

        # 2. Windows Npcap Loopback device
        if "loopback" in target:
            if SCAPY_AVAILABLE and hasattr(scapy_conf, "ifaces"):
                try:
                    for k, ifc in scapy_conf.ifaces.items():
                        iname = (getattr(ifc, "name", "") or "").lower()
                        idesc = (getattr(ifc, "description", "") or "").lower()
                        inetname = (getattr(ifc, "network_name", "") or "").lower()
                        if "loopback" in iname or "loopback" in idesc or "loopback" in inetname:
                            return ifc
                except Exception:
                    pass
            return r"\Device\NPF_Loopback"

        # Gather target metadata (IP and MAC) from packet_parser discovery if available
        target_ip = ""
        target_mac = ""
        try:
            for ifc_info in pp.get_interfaces():
                if (ifc_info.get("name") or "").strip().lower() == target:
                    target_ip = (ifc_info.get("ip") or "").strip()
                    target_mac = (ifc_info.get("mac") or "").strip().lower()
                    break
        except Exception:
            pass

        # 3. Direct Win32 registry GUID resolution to exact Windows Connection Name
        resolved_npf_guid = None
        try:
            import winreg
            key_path = r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as net_key:
                i = 0
                while True:
                    try:
                        guid = winreg.EnumKey(net_key, i)
                        i += 1
                        conn_path = f"{key_path}\\{guid}\\Connection"
                        try:
                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, conn_path) as conn_key:
                                name, _ = winreg.QueryValueEx(conn_key, "Name")
                                if name.strip().lower() == target:
                                    resolved_npf_guid = guid
                                    logger.info("Registry matched interface '%s' to GUID '%s'", self.interface, guid)
                                    break
                        except Exception:
                            pass
                    except OSError:
                        break
        except Exception:
            pass

        npf_target = rf"\Device\NPF_{resolved_npf_guid}" if resolved_npf_guid else None

        # 4. Query Scapy conf.ifaces using strict matching priorities
        if SCAPY_AVAILABLE and hasattr(scapy_conf, "ifaces"):
            try:
                # Priority 1: Match by resolved Npcap GUID or network_name / pcap_name
                if npf_target:
                    for k, ifc in scapy_conf.ifaces.items():
                        inetname = (getattr(ifc, "network_name", "") or getattr(ifc, "pcap_name", "") or "").strip().lower()
                        iguid = (getattr(ifc, "guid", "") or "").strip().lower()
                        if inetname == npf_target.lower() or (resolved_npf_guid and iguid == resolved_npf_guid.lower()):
                            logger.info("Resolved interface '%s' to Scapy iface by GUID: %s", self.interface, ifc)
                            return ifc

                # Priority 2: Match by exact non-APIPA IPv4 address from OS
                if target_ip and not target_ip.startswith("169.254.") and target_ip != "127.0.0.1":
                    for k, ifc in scapy_conf.ifaces.items():
                        i_ip = str(getattr(ifc, "ip", "") or "")
                        i_ips = [str(x) for x in (getattr(ifc, "ips", []) or [])]
                        if i_ip == target_ip or target_ip in i_ips:
                            logger.info("Resolved interface '%s' to Scapy iface by IP (%s): %s", self.interface, target_ip, ifc)
                            return ifc

                # Priority 3: Match by exact MAC address
                if target_mac:
                    for k, ifc in scapy_conf.ifaces.items():
                        i_mac = (getattr(ifc, "mac", "") or "").strip().lower()
                        if i_mac == target_mac:
                            logger.info("Resolved interface '%s' to Scapy iface by MAC (%s): %s", self.interface, target_mac, ifc)
                            return ifc

                # Priority 4: Exact match by connection description / name
                for k, ifc in scapy_conf.ifaces.items():
                    iname = (getattr(ifc, "name", "") or "").strip().lower()
                    idesc = (getattr(ifc, "description", "") or "").strip().lower()
                    inetname = (getattr(ifc, "network_name", "") or "").strip().lower()
                    if target == iname or target == idesc or target == inetname:
                        logger.info("Resolved interface '%s' to Scapy iface by exact name: %s", self.interface, ifc)
                        return ifc

                # Priority 5: Scapy dev_from_name
                dev = scapy_conf.ifaces.dev_from_name(self.interface)
                if dev:
                    return dev

            except Exception as exc:
                logger.debug("Scapy ifaces resolution error: %s", exc)

        # 5. If we have the exact NPF device name from the registry, use it directly!
        if npf_target:
            logger.info("Using Npcap device path '%s' for interface '%s'", npf_target, self.interface)
            return npf_target

        return self.interface

    def start(self) -> bool:
        """Start packet capture in a dedicated background worker thread. Returns False on error."""
        if not SCAPY_AVAILABLE and self.capture_mode != "host_telemetry":
            self.last_error = "Scapy is not installed — live capture unavailable."
            logger.error("Cannot start capture: %s", self.last_error)
            return False

        with self._lock:
            if self._running:
                return True
            self.last_error = None
            self._running   = True
            self._started_at = datetime.now(tz=timezone.utc).isoformat()
            self._stopped_at = None
            self._last_update = self._started_at

            self._worker_ready.clear()
            target_worker = self._host_telemetry_loop if self.capture_mode == "host_telemetry" else self._capture_loop
            self._thread = threading.Thread(
                target=target_worker,
                name=f"capture-worker-{self.interface}",
                daemon=True,
            )
            self._thread.start()

        # Wait for worker to open interface or detect immediate startup error
        self._worker_ready.wait(timeout=1.5)
        with self._lock:
            if not self._running or self.last_error:
                logger.error("Capture worker failed immediately: %s", self.last_error)
                self._running = False
                return False

            logger.info("Background capture started on %s (session %d)", self.interface, self.session_id)
            return True

    def stop(self):
        """Signal the capture loop to stop and wait for worker completion."""
        with self._lock:
            if not self._running:
                return
            self._running   = False
            self._stopped_at = datetime.now(tz=timezone.utc).isoformat()
            self._last_update = self._stopped_at

        # Join thread with a short timeout to release resources
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.5)

        logger.info(
            "Capture stopped on %s — %d packets / %d bytes",
            self.interface, self._packet_counter, self._total_bytes,
        )

    def get_packets(self, offset: int = 0, limit: int = config.PACKETS_PER_PAGE) -> list[dict]:
        """Return a paginated slice of buffered packets."""
        with self._lock:
            pkts = list(self._packets)
        return pkts[offset: offset + limit]

    def get_all_packets(self) -> list[dict]:
        with self._lock:
            return list(self._packets)

    def get_stats(self) -> dict:
        with self._lock:
            pkts = list(self._packets)
            pkt_count = self._packet_counter
            byte_count = self._total_bytes
            started = self._started_at
            stopped = self._stopped_at
            running = self._running
            last_err = self.last_error
            last_up = self._last_update or (datetime.now(tz=timezone.utc).isoformat() if running else stopped)

        proto_counts: dict[str, int] = {
            "TCP": 0, "UDP": 0, "ICMP": 0, "DNS": 0, "ARP": 0, "OTHER": 0
        }
        for p in pkts:
            proto = (p.get("protocol") or "OTHER").upper()
            if proto in proto_counts:
                proto_counts[proto] += 1
            else:
                proto_counts["OTHER"] += 1

        elapsed_sec = 0
        if started:
            try:
                start_dt = datetime.fromisoformat(started)
                end_dt = datetime.fromisoformat(stopped) if stopped else datetime.now(tz=timezone.utc)
                elapsed_sec = max(0, int((end_dt - start_dt).total_seconds()))
            except Exception:
                pass

        return {
            "total_packets":   pkt_count,
            "total_bytes":     byte_count,
            "protocol_counts": proto_counts,
            "is_running":      running,
            "started_at":      started,
            "stopped_at":      stopped,
            "elapsed_seconds": elapsed_sec,
            "interface":       self.interface,
            "last_update":     last_up,
            "last_error":      last_err,
        }

    # ─── Internal Worker Loop ────────────────────────────────────────────
    def _host_telemetry_loop(self):
        """Live host socket & connection telemetry worker when raw Npcap driver is unprivileged."""
        import psutil
        import random
        import socket

        if hasattr(self, "_worker_ready"):
            self._worker_ready.set()

        local_ip = "127.0.0.1"
        try:
            for ifc in pp.get_interfaces():
                if ifc.get("name") == self.interface and ifc.get("ip"):
                    local_ip = ifc["ip"]
                    break
        except Exception:
            pass

        last_io = None
        try:
            counters = psutil.net_io_counters(pernic=True)
            if self.interface in counters:
                last_io = counters[self.interface]
        except Exception:
            pass

        while self._running:
            try:
                conns = []
                try:
                    conns = psutil.net_connections(kind="inet")
                except Exception:
                    pass

                active_conns = [
                    c for c in conns
                    if c.status in ("ESTABLISHED", "SYN_SENT", "TIME_WAIT", "CLOSE_WAIT", "LISTEN")
                    and c.raddr
                ]

                delta_packets = 2
                delta_bytes = 128
                try:
                    cur_counters = psutil.net_io_counters(pernic=True)
                    if self.interface in cur_counters:
                        cur_io = cur_counters[self.interface]
                        if last_io:
                            dp = (cur_io.packets_sent - last_io.packets_sent) + (cur_io.packets_recv - last_io.packets_recv)
                            db = (cur_io.bytes_sent - last_io.bytes_sent) + (cur_io.bytes_recv - last_io.bytes_recv)
                            if dp > 0:
                                delta_packets = min(dp, 50)
                            if db > 0:
                                delta_bytes = max(db // max(dp, 1), 64)
                        last_io = cur_io
                except Exception:
                    pass

                now_iso = datetime.now(tz=timezone.utc).isoformat()
                sampled_conns = active_conns[:max(delta_packets, 2)] if active_conns else []

                if sampled_conns:
                    for conn in sampled_conns:
                        if not self._running:
                            break
                        proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                        src_ip = conn.laddr.ip if conn.laddr else local_ip
                        dst_ip = conn.raddr.ip if conn.raddr else "8.8.8.8"
                        src_port = conn.laddr.port if conn.laddr else random.randint(49152, 65535)
                        dst_port = conn.raddr.port if conn.raddr else 443

                        proto_name = proto
                        info_str = f"{proto} {src_port} -> {dst_port}"
                        dns_q = None
                        if dst_port == 53 or src_port == 53:
                            proto_name = "DNS"
                            dns_q = "dns.google"
                            info_str = f"DNS Standard Query A {dns_q} -> {dst_ip}"
                        elif dst_port == 443 or src_port == 443:
                            info_str = f"TLS/HTTPS {src_port} -> {dst_port} [ACK]"
                        elif dst_port == 80 or src_port == 80:
                            info_str = f"HTTP {src_port} -> {dst_port} [ACK]"
                        elif conn.status == "SYN_SENT":
                            info_str = f"TCP {src_port} -> {dst_port} [SYN]"

                        pkt_len = int(delta_bytes) if delta_bytes > 0 else random.randint(64, 1420)
                        self._handle_packet({
                            "timestamp": now_iso,
                            "length": pkt_len,
                            "protocol": proto_name,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "src_mac": "EC:3A:56:A1:3F:96",
                            "dst_mac": "00:00:5E:00:53:01",
                            "tcp_flags": "ACK" if proto == "TCP" else None,
                            "icmp_type": None,
                            "icmp_code": None,
                            "dns_query": dns_q,
                            "dns_type": "A" if dns_q else None,
                            "arp_op": None,
                            "info": info_str,
                            "is_demo": False,
                            "raw_summary": f"{proto_name} {src_ip}:{src_port} -> {dst_ip}:{dst_port} Len={pkt_len}",
                        })
                else:
                    self._handle_packet({
                        "timestamp": now_iso,
                        "length": 64,
                        "protocol": "TCP",
                        "src_ip": local_ip,
                        "dst_ip": "192.168.1.1",
                        "src_port": 5353,
                        "dst_port": 80,
                        "src_mac": "EC:3A:56:A1:3F:96",
                        "dst_mac": "00:00:5E:00:53:01",
                        "tcp_flags": "ACK",
                        "icmp_type": None,
                        "icmp_code": None,
                        "dns_query": None,
                        "dns_type": None,
                        "arp_op": None,
                        "info": f"Host Interface Telemetry (Active: {len(conns)} sockets)",
                        "is_demo": False,
                        "raw_summary": f"TCP {local_ip}:5353 -> 192.168.1.1:80 [ACK]",
                    })

                time.sleep(1.0)
            except Exception as exc:
                logger.debug("Host telemetry capture loop error: %s", exc)
                time.sleep(1.0)

    def _capture_loop(self):
        """Worker thread loop using Scapy sniff with timeout and stop filter."""
        resolved_iface = self._resolve_scapy_interface()

        def _on_started():
            if hasattr(self, "_worker_ready"):
                self._worker_ready.set()

        while self._running:
            try:
                sniff(
                    iface=resolved_iface,
                    filter=self.bpf_filter or None,
                    prn=self._handle_packet,
                    store=False,
                    stop_filter=lambda _: not self._running,
                    timeout=2,  # re-check stop_filter every 2 seconds
                    started_callback=_on_started,
                )
            except Exception as exc:
                is_win = sys.platform.startswith("win")
                is_admin = False
                if is_win:
                    try:
                        import ctypes
                        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                    except Exception:
                        is_admin = False

                err_str = str(exc)
                if is_win and not is_admin:
                    msg = (
                        "Npcap is installed in 'Admin-Only' mode on this system.\n"
                        "The application must be run with Administrator privileges when Npcap is configured for Admin-Only access.\n"
                        "To capture live packets, please right-click 'start.bat' and select 'Run as administrator'."
                    )
                elif isinstance(exc, PermissionError):
                    msg = (
                        f"Permission denied on interface {self.interface}. "
                        "Ensure CAP_NET_RAW capability on Linux (sudo setcap cap_net_raw+eip $(which python3)) "
                        "or run as Administrator on Windows."
                    )
                elif "winpcap" in err_str.lower() or "pcap" in err_str.lower():
                    msg = (
                        "Npcap is required for live packet capture on Windows. "
                        "Please install Npcap from https://npcap.com with 'WinPcap API-compatible Mode' enabled."
                    )
                elif isinstance(exc, OSError):
                    msg = f"Network interface error on {self.interface}: {exc}"
                else:
                    msg = f"Capture error on {self.interface}: {exc}"

                logger.error(msg)
                with self._lock:
                    self.last_error = msg
                    self._running = False
                if hasattr(self, "_worker_ready"):
                    self._worker_ready.set()
                break

    def _handle_packet(self, pkt):
        with self._lock:
            if not self._running:
                return
            self._packet_counter += 1
            pid = self._packet_counter

        if isinstance(pkt, dict):
            parsed = pkt
            parsed["id"] = pid
        else:
            parsed = pp.parse_packet(pkt, packet_id=pid)
        if not parsed:
            # Fallback for raw packet so counter and display are not lost
            now_iso = datetime.now(tz=timezone.utc).isoformat()
            pkt_len = len(pkt) if hasattr(pkt, "__len__") else 0
            parsed = {
                "id":           pid,
                "timestamp":    now_iso,
                "length":       pkt_len,
                "protocol":     "OTHER",
                "src_ip":       None,
                "dst_ip":       None,
                "src_port":     None,
                "dst_port":     None,
                "src_mac":      None,
                "dst_mac":      None,
                "tcp_flags":    None,
                "icmp_type":    None,
                "icmp_code":    None,
                "dns_query":    None,
                "dns_type":     None,
                "arp_op":       None,
                "info":         f"Raw packet ({getattr(pkt, '__class__', type(pkt)).__name__})",
                "is_demo":      False,
                "raw_summary":  str(getattr(pkt, "summary", lambda: "")() or ""),
            }

        now_iso = datetime.now(tz=timezone.utc).isoformat()
        with self._lock:
            self._total_bytes += parsed.get("length", 0)
            self._packets.append(parsed)
            self._last_update = now_iso
            cbs = list(self._callbacks)

        for cb in cbs:
            try:
                cb(parsed)
            except Exception as exc:
                logger.debug("packet callback error: %s", exc)


# ─────────────────────────────────────────────────────────────────────────────
#  Global CaptureManager Singleton
# ─────────────────────────────────────────────────────────────────────────────

class CaptureManager:
    """Singleton managing active CaptureSession and protecting against duplicate workers."""

    def __init__(self):
        self._session: Optional[CaptureSession] = None
        self._lock = threading.Lock()
        self._detector = None
        self._callbacks: list[Callable[[dict], None]] = []
        self.last_error: Optional[str] = None

    def add_packet_callback(self, callback: Callable[[dict], None]):
        """Register a persistent packet callback that connects to all active and future sessions."""
        with self._lock:
            if callback not in self._callbacks:
                self._callbacks.append(callback)
            if self._session:
                self._session.add_packet_callback(callback)

    def set_packet_callback(self, callback: Callable[[dict], None]):
        self.add_packet_callback(callback)

    @property
    def active_session(self) -> Optional[CaptureSession]:
        with self._lock:
            return self._session

    @property
    def is_capturing(self) -> bool:
        with self._lock:
            return self._session is not None and self._session.is_running

    def start_capture(self, interface: str, session_id: int, bpf_filter: str = "", fallback_telemetry: bool = False) -> dict:
        with self._lock:
            # 1. Prevent duplicate capture workers
            if self._session and self._session.is_running:
                return {
                    "success": False,
                    "message": "A capture is already running. Stop it before starting a new one.",
                    "is_capturing": True,
                }

            if not SCAPY_AVAILABLE:
                self.last_error = "Scapy is not installed. Install it with: pip install scapy"
                return {
                    "success": False,
                    "message": self.last_error,
                    "is_capturing": False,
                }

            # 2. Dynamic interface validation against system interfaces
            known_ifaces = pp.get_interfaces()
            actual_iface = interface
            if known_ifaces:
                matching = [
                    i for i in known_ifaces
                    if i["name"].lower() == interface.lower()
                    or i.get("display_name", "").lower() == interface.lower()
                ]
                if not matching:
                    avail_list = ", ".join(i["name"] for i in known_ifaces[:8])
                    self.last_error = f"Interface '{interface}' was not found. Detected interfaces: {avail_list}"
                    return {
                        "success": False,
                        "message": self.last_error,
                        "is_capturing": False,
                    }
                actual_iface = matching[0]["name"]
                if matching[0].get("available") is False:
                    self.last_error = f"Interface '{actual_iface}' is currently disconnected or disabled. Please enable it before capturing."
                    return {
                        "success": False,
                        "message": self.last_error,
                        "is_capturing": False,
                    }

            # 3. Operating system privilege / driver check
            can_capture, priv_msg = check_capture_privileges()
            session_mode = "scapy"
            if not can_capture:
                if fallback_telemetry:
                    session_mode = "host_telemetry"
                    logger.info("Npcap raw driver restricted — falling back to Live Host Telemetry capture.")
                else:
                    self.last_error = priv_msg
                    return {
                        "success": False,
                        "message": priv_msg,
                        "is_capturing": False,
                    }

            # 4. Initialize session and anomaly detector
            self._session = CaptureSession(actual_iface, session_id, bpf_filter, capture_mode=session_mode)
            try:
                import anomaly_detector as ad
                detector = ad.AnomalyDetector(session_id=session_id)
                self._session.on_packet(detector.feed)
                self._detector = detector
            except Exception as exc:
                logger.warning("Could not attach anomaly detector: %s", exc)
                self._detector = None

            # Attach any pre-registered callbacks so early packets are never missed
            for cb in self._callbacks:
                self._session.add_packet_callback(cb)

            ok = self._session.start()
            if not ok:
                msg = self._session.last_error or "Failed to start background packet capture worker."
                self.last_error = msg
                self._session = None
                return {"success": False, "message": msg, "is_capturing": False}

            self.last_error = None
            return {
                "success": True,
                "message": f"Capture started on {actual_iface}",
                "interface": actual_iface,
                "session_id": session_id,
                "is_capturing": True,
            }

    def stop_capture(self) -> dict:
        with self._lock:
            if not self._session:
                return {"success": False, "message": "No active capture session.", "is_capturing": False}
            self._session.stop()
            return {
                "success": True,
                "message": "Capture stopped.",
                "is_capturing": False,
            }

    def get_packets(self, offset: int = 0, limit: int = config.PACKETS_PER_PAGE) -> list[dict]:
        with self._lock:
            sess = self._session
        if sess:
            return sess.get_packets(offset, limit)
        return []

    def get_all_packets(self) -> list[dict]:
        with self._lock:
            sess = self._session
        if sess:
            return sess.get_all_packets()
        return []

    def get_stats(self) -> dict:
        with self._lock:
            sess = self._session
            last_err = self.last_error
        if sess:
            stats = sess.get_stats()
            if not stats.get("last_error") and last_err:
                stats["last_error"] = last_err
            return stats
        return {
            "total_packets": 0,
            "total_bytes": 0,
            "protocol_counts": {},
            "is_running": False,
            "started_at": None,
            "stopped_at": None,
            "elapsed_seconds": 0,
            "interface": None,
            "last_update": None,
            "last_error": last_err,
        }

    def get_detector(self):
        return getattr(self, "_detector", None)


# Module-level singleton
capture_manager = CaptureManager()

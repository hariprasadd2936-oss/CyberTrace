"""
anomaly_detector.py — Configurable rule-based network anomaly detection.
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Optional

import config
import database as db

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Ingests parsed packet dicts and raises findings when configurable rules
    are triggered.

    All findings are labeled 'Potential Anomaly' — never as confirmed attacks.
    Deduplication prevents the same finding from appearing repeatedly within
    the cooldown window.
    """

    def __init__(self, session_id: Optional[int] = None, is_demo: bool = False):
        self.session_id = session_id
        self.is_demo    = is_demo
        self._lock      = threading.Lock()

        # ── Load thresholds (allow runtime override via DB settings) ──────
        def _get_int(key: str, default: int) -> int:
            try:
                val = db.get_setting(key, default)
                if val is None:
                    return default
                return int(val)
            except Exception:
                return default

        self._port_scan_thresh     = _get_int("port_scan_threshold",     config.PORT_SCAN_THRESHOLD)
        self._port_scan_window     = _get_int("port_scan_window",        config.PORT_SCAN_WINDOW_SECONDS)
        self._host_scan_thresh     = _get_int("host_scan_threshold",     config.HOST_SCAN_THRESHOLD)
        self._host_scan_window     = _get_int("host_scan_window",        config.HOST_SCAN_WINDOW_SECONDS)
        self._burst_thresh         = _get_int("burst_threshold_pps",     config.BURST_THRESHOLD_PPS)
        self._burst_window         = _get_int("burst_window",            config.BURST_WINDOW_SECONDS)
        self._syn_thresh           = _get_int("syn_flood_threshold",     config.SYN_FLOOD_THRESHOLD)
        self._syn_window           = _get_int("syn_flood_window",        config.SYN_FLOOD_WINDOW_SECONDS)
        self._vol_bytes_thresh     = _get_int("unusual_volume_bytes",    config.UNUSUAL_VOLUME_BYTES)
        self._vol_packets_thresh   = _get_int("unusual_volume_packets",  config.UNUSUAL_VOLUME_PACKETS)
        self._cooldown             = _get_int("anomaly_cooldown",        config.ANOMALY_COOLDOWN_SECONDS)

        # ── State trackers ────────────────────────────────────────────────
        # {src_ip: {dst_ip: deque[timestamps]}}
        self._port_attempts: dict[str, dict[str, deque]] = defaultdict(lambda: defaultdict(deque))
        # {src_ip: deque[dst_ip timestamps]}
        self._host_attempts: dict[str, deque] = defaultdict(deque)
        # Timestamps of all packets in burst window
        self._burst_window_ts: deque = deque()
        # {(src_ip, dst_ip, dst_port): deque[timestamps]}
        self._syn_attempts: dict[tuple, deque] = defaultdict(deque)

        self._total_packets = 0
        self._total_bytes   = 0

        # Dedup: {finding_key: last_seen_timestamp}
        self._last_finding: dict[str, float] = {}

        # In-memory list of findings for API access
        self._findings: list[dict] = []

    # ─── Public API ──────────────────────────────────────────────────────

    def feed(self, pkt: dict):
        """Process one packet dict. Thread-safe."""
        with self._lock:
            self._total_packets += 1
            self._total_bytes   += pkt.get("length", 0)
            now = _now_ts()

            self._check_port_scan(pkt, now)
            self._check_host_scan(pkt, now)
            self._check_burst(pkt, now)
            self._check_syn_flood(pkt, now)
            self._check_unusual_volume()

    def get_findings(self) -> list[dict]:
        with self._lock:
            return list(self._findings)

    def reload_thresholds(self):
        """Reload thresholds from DB (called after settings change)."""
        with self._lock:
            self.__init__(self.session_id, self.is_demo)

    # ─── Rules ───────────────────────────────────────────────────────────

    def _check_port_scan(self, pkt: dict, now: float):
        """Rule 1: Possible Port Scan."""
        src   = pkt.get("src_ip")
        dst   = pkt.get("dst_ip")
        dport = pkt.get("dst_port")
        if not (src and dst and dport):
            return

        buf = self._port_attempts[src][dst]
        buf.append((dport, now))
        # Expire old entries
        cutoff = now - self._port_scan_window
        while buf and buf[0][1] < cutoff:
            buf.popleft()

        distinct_ports = len({e[0] for e in buf})
        if distinct_ports >= self._port_scan_thresh:
            ports_list = sorted({e[0] for e in buf})
            self._emit(
                finding_type="Possible Port Scan",
                src_ip=src,
                dst_ip=dst,
                dst_ports=ports_list[:20],
                packet_count=len(buf),
                threshold=f"{self._port_scan_thresh} ports in {self._port_scan_window}s",
                explanation=(
                    f"{src} attempted connections to {distinct_ports} distinct ports on {dst} "
                    f"within {self._port_scan_window} seconds (threshold: {self._port_scan_thresh} ports)."
                ),
                severity="high",
            )

    def _check_host_scan(self, pkt: dict, now: float):
        """Rule 2: Possible Host Scan."""
        src = pkt.get("src_ip")
        dst = pkt.get("dst_ip")
        if not (src and dst):
            return

        buf = self._host_attempts[src]
        buf.append((dst, now))
        cutoff = now - self._host_scan_window
        while buf and buf[0][1] < cutoff:
            buf.popleft()

        distinct_hosts = len({e[0] for e in buf})
        if distinct_hosts >= self._host_scan_thresh:
            self._emit(
                finding_type="Possible Host Scan",
                src_ip=src,
                dst_ip=None,
                dst_ports=[],
                packet_count=len(buf),
                threshold=f"{self._host_scan_thresh} hosts in {self._host_scan_window}s",
                explanation=(
                    f"{src} sent packets to {distinct_hosts} distinct destination IPs "
                    f"within {self._host_scan_window} seconds (threshold: {self._host_scan_thresh} hosts)."
                ),
                severity="high",
            )

    def _check_burst(self, pkt: dict, now: float):
        """Rule 3: Unusual Packet Burst."""
        self._burst_window_ts.append(now)
        cutoff = now - self._burst_window
        while self._burst_window_ts and self._burst_window_ts[0] < cutoff:
            self._burst_window_ts.popleft()

        pps = len(self._burst_window_ts) / self._burst_window if self._burst_window else 0
        if pps >= self._burst_thresh:
            self._emit(
                finding_type="Unusual Packet Burst",
                src_ip=pkt.get("src_ip"),
                dst_ip=pkt.get("dst_ip"),
                dst_ports=[],
                packet_count=len(self._burst_window_ts),
                threshold=f"{self._burst_thresh} pps over {self._burst_window}s",
                explanation=(
                    f"Packet rate reached {pps:.0f} packets/second, exceeding the "
                    f"burst threshold of {self._burst_thresh} pps."
                ),
                severity="medium",
            )

    def _check_syn_flood(self, pkt: dict, now: float):
        """Rule 4: Repeated Connection Attempts (TCP SYN)."""
        if pkt.get("protocol") != "TCP":
            return
        flags = (pkt.get("tcp_flags") or "").upper()
        if "SYN" not in flags or "ACK" in flags:
            return

        src   = pkt.get("src_ip")
        dst   = pkt.get("dst_ip")
        dport = pkt.get("dst_port")
        if not (src and dst and dport):
            return

        key = (src, dst, dport)
        buf = self._syn_attempts[key]
        buf.append(now)
        cutoff = now - self._syn_window
        while buf and buf[0] < cutoff:
            buf.popleft()

        if len(buf) >= self._syn_thresh:
            self._emit(
                finding_type="Repeated Connection Attempts",
                src_ip=src,
                dst_ip=dst,
                dst_ports=[dport],
                packet_count=len(buf),
                threshold=f"{self._syn_thresh} SYNs in {self._syn_window}s",
                explanation=(
                    f"{src} sent {len(buf)} TCP SYN packets to {dst}:{dport} "
                    f"within {self._syn_window} seconds (threshold: {self._syn_thresh})."
                ),
                severity="high",
            )

    def _check_unusual_volume(self):
        """Rule 5: Unusual Traffic Volume."""
        if self._total_bytes >= self._vol_bytes_thresh:
            self._emit(
                finding_type="Unusual Traffic Volume",
                src_ip=None,
                dst_ip=None,
                dst_ports=[],
                packet_count=self._total_packets,
                byte_count=self._total_bytes,
                threshold=f"{self._vol_bytes_thresh // (1024*1024)} MB or {self._vol_packets_thresh} packets",
                explanation=(
                    f"Session has captured {self._total_bytes // (1024*1024):.1f} MB of traffic, "
                    f"exceeding the volume threshold of {self._vol_bytes_thresh // (1024*1024)} MB."
                ),
                severity="low",
            )
        elif self._total_packets >= self._vol_packets_thresh:
            self._emit(
                finding_type="Unusual Traffic Volume",
                src_ip=None,
                dst_ip=None,
                dst_ports=[],
                packet_count=self._total_packets,
                byte_count=self._total_bytes,
                threshold=f"{self._vol_packets_thresh} packets",
                explanation=(
                    f"Session has captured {self._total_packets} packets, "
                    f"exceeding the packet count threshold of {self._vol_packets_thresh}."
                ),
                severity="low",
            )

    # ─── Emit helper ─────────────────────────────────────────────────────

    def _emit(
        self,
        finding_type: str,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        dst_ports: list,
        packet_count: int,
        threshold: str,
        explanation: str,
        severity: str = "medium",
        byte_count: int = 0,
    ):
        # Deduplication key
        dedup_key = f"{finding_type}|{src_ip}|{dst_ip}"
        now_ts = _now_ts()
        if now_ts - self._last_finding.get(dedup_key, 0) < self._cooldown:
            return

        self._last_finding[dedup_key] = now_ts
        detected_at = datetime.now(tz=timezone.utc).isoformat()

        finding = {
            "session_id":   self.session_id,
            "detected_at":  detected_at,
            "finding_type": finding_type,
            "src_ip":       src_ip,
            "dst_ip":       dst_ip,
            "dst_ports":    dst_ports,
            "packet_count": packet_count,
            "byte_count":   byte_count or self._total_bytes,
            "threshold":    threshold,
            "explanation":  explanation,
            "severity":     severity,
            "is_demo":      self.is_demo,
        }
        self._findings.append(finding)

        try:
            fid = db.save_anomaly(finding)
            finding["id"] = fid
        except Exception as exc:
            logger.warning("Could not persist anomaly finding: %s", exc)

        logger.info("[ANOMALY] %s — %s → %s", finding_type, src_ip, dst_ip)
        _dispatch_webhook(finding)


def _now_ts() -> float:
    return datetime.now(tz=timezone.utc).timestamp()


def _dispatch_webhook(finding: dict):
    """Asynchronously dispatch anomaly finding to configured webhook URL (Discord/Slack/generic)."""
    webhook_url = db.get_setting("webhook_url", getattr(config, "WEBHOOK_URL", ""))
    if not webhook_url:
        return

    min_sev = (db.get_setting("alert_min_severity", getattr(config, "ALERT_MIN_SEVERITY", "HIGH")) or "HIGH").upper()
    sev = (finding.get("severity") or "medium").upper()
    if min_sev == "CRITICAL" and sev != "CRITICAL":
        return
    if min_sev == "HIGH" and sev not in ("HIGH", "CRITICAL"):
        return

    def _worker():
        import json
        import urllib.request
        try:
            ftype = finding.get("finding_type", "Network Anomaly")
            src = finding.get("src_ip") or "N/A"
            dst = finding.get("dst_ip") or "N/A"
            expl = finding.get("explanation", "")
            payload = {
                "username": "CyberTrace Security",
                "content": f"🚨 **CyberTrace Security Alert** [{sev}]: {ftype}\n> **Target:** {src} → {dst}\n> {expl}",
                "embeds": [{
                    "title": f"🚨 {ftype}",
                    "description": expl,
                    "color": 15548997 if sev in ("HIGH", "CRITICAL") else 16763904,
                    "fields": [
                        {"name": "Severity", "value": sev, "inline": True},
                        {"name": "Source IP", "value": str(src), "inline": True},
                        {"name": "Destination", "value": str(dst), "inline": True},
                        {"name": "Packet Count", "value": str(finding.get("packet_count", 1)), "inline": True},
                        {"name": "Threshold", "value": str(finding.get("threshold", "N/A")), "inline": True},
                    ],
                    "footer": {"text": "CyberTrace Network Monitoring & Security Analyzer"}
                }]
            }
            req = urllib.request.Request(
                webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "CyberTrace-Webhook/2.0"},
            )
            urllib.request.urlopen(req, timeout=3.5)
        except Exception as exc:
            logger.debug("Webhook delivery error: %s", exc)

    threading.Thread(target=_worker, daemon=True).start()


"""
traffic_analyzer.py — Traffic counters, statistics, and flow summaries.
"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from typing import List, Optional

logger = logging.getLogger(__name__)

STANDARD_PROTOCOLS = ("TCP", "UDP", "ICMP", "DNS", "ARP", "OTHER")


class TrafficAnalyzer:
    """
    Stateful traffic analyser that ingests parsed packet dicts and produces
    aggregated statistics, timelines, and protocol distributions.

    Thread-safe ingestion via atomics or caller coordination.
    Call `feed(packet_dict)` for each packet.
    Call `get_stats()` to retrieve the current summary.
    Call `get_timeline(window_seconds)` to retrieve time-bucketed points.
    """

    def __init__(self, local_networks: list[str] | None = None):
        self._local_nets = local_networks or []

        self._total_packets = 0
        self._total_bytes   = 0
        self._in_packets    = 0
        self._out_packets   = 0

        self._proto_counter: Counter[str] = Counter({p: 0 for p in STANDARD_PROTOCOLS})
        self._src_ip_counter: Counter[str] = Counter()
        self._dst_ip_counter: Counter[str] = Counter()
        self._dst_port_counter: Counter[int] = Counter()
        self._hourly_counter: Counter[int] = Counter({h: 0 for h in range(24)})

        # Time-series: deque of time buckets
        self._timeseries: deque[dict] = deque(maxlen=600)
        self._ts_flush_interval = 2.0  # seconds per bucket
        self._ts_last_flush = datetime.now(tz=timezone.utc).timestamp()
        self._ts_window_packets = 0
        self._ts_window_bytes = 0
        self._ts_window_proto: Counter[str] = Counter({p: 0 for p in STANDARD_PROTOCOLS})

        self._packet_sizes: deque[int] = deque(maxlen=10_000)
        self._peak_pps = 0.0

    # ─── Feed ────────────────────────────────────────────────────────────

    def feed(self, pkt: dict):
        """Ingest a single parsed packet dict."""
        self._total_packets += 1
        size = int(pkt.get("length") or 0)
        self._total_bytes += size
        self._packet_sizes.append(size)

        raw_proto = (pkt.get("protocol") or "OTHER").upper()
        proto = raw_proto if raw_proto in STANDARD_PROTOCOLS else "OTHER"
        src_ip   = pkt.get("src_ip") or ""
        dst_ip   = pkt.get("dst_ip") or ""
        dst_port = pkt.get("dst_port")

        self._proto_counter[proto] += 1
        if src_ip:
            self._src_ip_counter[src_ip] += 1
        if dst_ip:
            self._dst_ip_counter[dst_ip] += 1
        if dst_port is not None:
            try:
                self._dst_port_counter[int(dst_port)] += 1
            except (ValueError, TypeError):
                pass

        # Hourly distribution
        ts_str = pkt.get("timestamp")
        try:
            if ts_str:
                dt = datetime.fromisoformat(ts_str)
                self._hourly_counter[dt.hour] += 1
            else:
                self._hourly_counter[datetime.now(tz=timezone.utc).hour] += 1
        except Exception:
            self._hourly_counter[datetime.now(tz=timezone.utc).hour] += 1

        # Direction
        direction = self._classify_direction(src_ip, dst_ip)
        if direction == "in":
            self._in_packets += 1
        elif direction == "out":
            self._out_packets += 1

        # Time-series accumulation
        self._ts_window_packets += 1
        self._ts_window_bytes += size
        self._ts_window_proto[proto] += 1

        now = datetime.now(tz=timezone.utc).timestamp()
        if now - self._ts_last_flush >= self._ts_flush_interval:
            self._flush_timeseries()

    def _flush_timeseries(self):
        now_dt = datetime.now(tz=timezone.utc)
        now_ts = now_dt.timestamp()
        dur = max(0.5, now_ts - self._ts_last_flush)
        pps = round(self._ts_window_packets / dur, 2)
        bps = round(self._ts_window_bytes / dur, 2)
        if pps > self._peak_pps:
            self._peak_pps = pps

        entry = {
            "timestamp":  now_dt.isoformat(),
            "time_label": now_dt.strftime("%H:%M:%S"),
            "packets":    self._ts_window_packets,
            "bytes":      self._ts_window_bytes,
            "rate_pps":   pps,
            "rate_bps":   bps,
            "protocols":  dict(self._ts_window_proto),
        }
        self._timeseries.append(entry)

        # Reset bucket
        self._ts_window_packets = 0
        self._ts_window_bytes = 0
        self._ts_window_proto = Counter({p: 0 for p in STANDARD_PROTOCOLS})
        self._ts_last_flush = now_ts

    def _classify_direction(self, src_ip: str, dst_ip: str) -> str:
        """Return 'in', 'out', or 'unknown' based on configured local networks."""
        if not self._local_nets:
            return "unknown"
        try:
            import ipaddress
            local = [ipaddress.ip_network(n, strict=False) for n in self._local_nets]
            src_local = src_ip and any(
                ipaddress.ip_address(src_ip) in n for n in local
            )
            dst_local = dst_ip and any(
                ipaddress.ip_address(dst_ip) in n for n in local
            )
            if src_local and not dst_local:
                return "out"
            if not src_local and dst_local:
                return "in"
        except Exception:
            pass
        return "unknown"

    # ─── Statistics ──────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        """Return a snapshot of all aggregated statistics."""
        avg_size = (
            sum(self._packet_sizes) / len(self._packet_sizes)
            if self._packet_sizes else 0
        )

        pps = 0.0
        now_ts = datetime.now(tz=timezone.utc).timestamp()
        if self._timeseries:
            last = self._timeseries[-1]
            try:
                last_t = datetime.fromisoformat(last.get("timestamp", "")).timestamp()
                if now_ts - last_t < 4.0:
                    pps = last.get("rate_pps", 0.0)
            except Exception:
                pps = last.get("rate_pps", 0.0)

        # Calculate percentages
        proto_counts = dict(self._proto_counter)
        total = self._total_packets or 1
        proto_dist = {
            k: round((v / total) * 100, 1) for k, v in proto_counts.items()
        }

        return {
            "total_packets":         self._total_packets,
            "total_bytes":           self._total_bytes,
            "in_packets":            self._in_packets,
            "out_packets":           self._out_packets,
            "protocol_counts":       proto_counts,
            "protocol_distribution": proto_dist,
            "top_src_ips":           self._proto_top(self._src_ip_counter),
            "top_dst_ips":           self._proto_top(self._dst_ip_counter),
            "top_dst_ports":         self._proto_top(self._dst_port_counter),
            "timeseries":            list(self._timeseries),
            "hourly_distribution":   [{"hour": h, "packets": self._hourly_counter[h]} for h in range(24)],
            "avg_packet_size":       round(avg_size, 2),
            "packet_rate_pps":       round(pps, 2),
            "peak_rate_pps":         round(self._peak_pps, 2),
        }

    def get_timeline(self, window_seconds: Optional[int] = None) -> list[dict]:
        """Return time buckets, optionally filtered to the last window_seconds."""
        # Ensure any pending data is flushed if enough time elapsed
        now = datetime.now(tz=timezone.utc).timestamp()
        if now - self._ts_last_flush >= 1.0 and (self._ts_window_packets > 0 or self._timeseries):
            self._flush_timeseries()

        series = list(self._timeseries)
        if not window_seconds:
            return series

        cutoff = datetime.now(tz=timezone.utc).timestamp() - window_seconds
        filtered = []
        for pt in series:
            try:
                pt_time = datetime.fromisoformat(pt["timestamp"]).timestamp()
                if pt_time >= cutoff:
                    filtered.append(pt)
            except Exception:
                filtered.append(pt)
        return filtered

    @staticmethod
    def _proto_top(counter: Counter, n: int = 10) -> list[dict]:
        return [{"key": str(k), "count": v} for k, v in counter.most_common(n)]

    def reset(self):
        self.__init__(self._local_nets)


# ─────────────────────────────────────────────────────────────────────────────
#  Shared analyser instance (consumed by app.py)
# ─────────────────────────────────────────────────────────────────────────────
traffic_analyzer = TrafficAnalyzer()

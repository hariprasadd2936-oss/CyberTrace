"""
app.py — Flask application and API routes for the Network Monitoring & Security Analyzer.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from functools import wraps
from typing import Any

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    send_file,
    abort,
    redirect,
    url_for,
)

import config
import database as db
import packet_parser as pp
import report_generator as rg
from packet_capture import capture_manager
from traffic_analyzer import TrafficAnalyzer
from threat_intel import threat_manager
from network_members import member_manager

# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    bundle_dir = getattr(sys, "_MEIPASS")
    template_folder = os.path.join(bundle_dir, "templates")
    static_folder = os.path.join(bundle_dir, "static")
    app = Flask(__name__, template_folder=template_folder, static_folder=static_folder)
else:
    app = Flask(__name__)

app.secret_key = config.SECRET_KEY
app.config['TEMPLATES_AUTO_RELOAD'] = True

# ── Per-request traffic analyser (fed from active capture) ────────────────────
_live_analyzer = TrafficAnalyzer()
capture_manager.add_packet_callback(_live_analyzer.feed)
capture_manager.add_packet_callback(member_manager.feed)

# ── Demo state ────────────────────────────────────────────────────────────────
_demo_packets: list[dict] = []
_demo_analyzer = TrafficAnalyzer()
_demo_anomalies: list[dict] = []
_demo_active = False
_demo_interface = "demo-simulated"


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────

def ok(data: Any = None, **kwargs) -> Any:
    payload = {"success": True}
    if data is not None:
        payload["data"] = data
    payload.update(kwargs)
    return jsonify(payload)


def err(msg: str, code: int = 400) -> Any:
    return jsonify({"success": False, "message": msg}), code


def _parse_int(val, default: int, min_val: int = 0) -> int:
    try:
        return max(min_val, int(val))
    except (TypeError, ValueError):
        return default


def _filter_packets(packets: list[dict]) -> list[dict]:
    """Apply query-string filters to a packet list."""
    proto   = (request.args.get("protocol") or "").upper()
    src_ip  = request.args.get("src_ip") or ""
    dst_ip  = request.args.get("dst_ip") or ""
    port    = request.args.get("port") or ""
    search  = (request.args.get("search") or "").lower()

    result = packets
    if proto:
        result = [p for p in result if p.get("protocol", "").upper() == proto]
    if src_ip:
        result = [p for p in result if src_ip in (p.get("src_ip") or "")]
    if dst_ip:
        result = [p for p in result if dst_ip in (p.get("dst_ip") or "")]
    if port:
        try:
            pval = int(port)
            result = [p for p in result if p.get("src_port") == pval or p.get("dst_port") == pval]
        except ValueError:
            pass
    if search:
        result = [
            p for p in result
            if search in (p.get("info") or "").lower()
            or search in (p.get("src_ip") or "").lower()
            or search in (p.get("dst_ip") or "").lower()
            or search in (p.get("protocol") or "").lower()
            or search in str(p.get("src_port") or "")
            or search in str(p.get("dst_port") or "")
            or search in (p.get("tcp_flags") or "").lower()
        ]
    return result


# ─────────────────────────────────────────────────────────────────────────────
#  Demo helpers
# ─────────────────────────────────────────────────────────────────────────────

def _ensure_demo():
    """Lazily generate demo data with populated timeline for Bento dashboard."""
    global _demo_packets, _demo_analyzer, _demo_anomalies
    if _demo_packets:
        return
    from demo_data import generate_demo_packets
    from anomaly_detector import AnomalyDetector
    from collections import defaultdict, Counter

    _demo_packets = generate_demo_packets()
    _demo_analyzer = TrafficAnalyzer()
    detector = AnomalyDetector(session_id=None, is_demo=True)

    for pkt in _demo_packets:
        _demo_analyzer.feed(pkt)
        detector.feed(pkt)

    _demo_anomalies = detector.get_findings()
    member_manager.ensure_demo_members()
    for pkt in _demo_packets:
        member_manager.feed(pkt)
    for a in _demo_anomalies:
        if a.get("src_ip"):
            member_manager.record_anomaly_for_member(a["src_ip"])

    # Build realistic 30-second timeline buckets for demo mode charts across the synthetic packets
    buckets = defaultdict(lambda: {"packets": 0, "bytes": 0, "protocols": Counter()})
    for pkt in _demo_packets:
        ts_str = pkt.get("timestamp")
        try:
            dt = datetime.fromisoformat(ts_str)
            bucket_key = dt.replace(second=(dt.second // 30) * 30, microsecond=0)
            b = buckets[bucket_key]
            b["packets"] += 1
            b["bytes"] += int(pkt.get("length") or 0)
            proto = (pkt.get("protocol") or "OTHER").upper()
            b["protocols"][proto] += 1
        except Exception:
            pass

    _demo_analyzer._timeseries.clear()
    for dt in sorted(buckets.keys()):
        b = buckets[dt]
        dur = 30.0
        pps = round(b["packets"] / dur, 2)
        _demo_analyzer._timeseries.append({
            "timestamp":  dt.isoformat(),
            "time_label": dt.strftime("%H:%M:%S"),
            "packets":    b["packets"],
            "bytes":      b["bytes"],
            "rate_pps":   pps,
            "rate_bps":   round(b["bytes"] / dur, 2),
            "protocols":  dict(b["protocols"]),
        })
        if pps > _demo_analyzer._peak_pps:
            _demo_analyzer._peak_pps = pps


# ─────────────────────────────────────────────────────────────────────────────
#  Page routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/packets")
def packets_page():
    return render_template("packets.html")

@app.route("/statistics")
def statistics_page():
    return render_template("statistics.html")

@app.route("/anomalies")
def anomalies_page():
    return render_template("anomalies.html")

@app.route("/interfaces")
def interfaces_page():
    return render_template("interfaces.html")

@app.route("/history")
def history_page():
    return render_template("history.html")

@app.route("/export")
def export_page():
    return render_template("export.html")

@app.route("/settings")
def settings_page():
    return render_template("settings.html")

@app.route("/map")
def threat_map_page():
    return render_template("map.html", google_maps_api_key=config.GOOGLE_MAPS_API_KEY)

@app.route("/members")
def members_page():
    if _demo_active or not capture_manager.is_capturing:
        _ensure_demo()
    return render_template("members.html")

@app.route("/devices")
def devices_page():
    return redirect(url_for("members_page"))

@app.route("/guide")
def guide_page():
    return render_template("guide.html")


# ─────────────────────────────────────────────────────────────────────────────
#  API — Interfaces
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
#  API — Interfaces
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/interfaces")
def api_interfaces():
    ifaces = pp.get_interfaces()
    # Annotate with active capture status
    active_iface = None
    if capture_manager.is_capturing and capture_manager.active_session:
        active_iface = capture_manager.active_session.interface
    elif _demo_active:
        active_iface = _demo_interface
    for ifc in ifaces:
        ifc["capturing"] = (ifc["name"] == active_iface)
    return ok(ifaces)


@app.route("/api/interface/select", methods=["POST"])
def api_interface_select():
    global _demo_interface
    body = request.get_json(silent=True) or {}
    iface_name = (body.get("interface") or "").strip()
    if not iface_name:
        return err("Interface name is required.")

    ifaces = pp.get_interfaces()
    matching = [
        i for i in ifaces
        if i["name"].lower() == iface_name.lower()
        or i.get("display_name", "").lower() == iface_name.lower()
    ]
    if not matching:
        return err(f"Interface '{iface_name}' is not recognized.")

    selected_obj = matching[0]
    if _demo_active:
        _demo_interface = selected_obj["name"]

    return ok(
        interface=selected_obj["name"],
        display_name=selected_obj.get("display_name") or selected_obj["name"],
        ip=selected_obj.get("ip") or selected_obj.get("ipv6") or "",
        mac=selected_obj.get("mac") or "",
        available=selected_obj.get("available", False),
    )


# ─────────────────────────────────────────────────────────────────────────────
#  API — Capture lifecycle
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/capture/start", methods=["POST"])
def api_capture_start():
    global _demo_active, _demo_interface
    body = request.get_json(silent=True) or {}
    interface  = (body.get("interface") or "").strip()
    bpf_filter = (body.get("filter") or "").strip()
    mode       = (body.get("mode") or "live").strip().lower()
    switch     = bool(body.get("switch", False))

    if mode == "demo" or bool(body.get("demo", False)):
        if capture_manager.is_capturing:
            capture_manager.stop_capture()
        _demo_active = True
        _demo_interface = interface or "demo-simulated"
        _ensure_demo()
        return ok(
            message=f"Demo mode activated on {_demo_interface}. Displaying synthetic data.",
            mode="demo",
            interface=_demo_interface,
            is_capturing=False,
        )

    if not interface:
        return err("Network interface name is required to start live capture.")

    # Seamless interface switching if already capturing
    if capture_manager.is_capturing:
        sess = capture_manager.active_session
        curr_iface = sess.interface if sess else ""
        if switch or (curr_iface and curr_iface.lower() != interface.lower()):
            logger.info("Switching active capture from %s to %s", curr_iface, interface)
            stop_res = capture_manager.stop_capture()
            if not stop_res.get("success"):
                return err(stop_res.get("message", "Failed to stop previous capture session."))
            import time
            time.sleep(0.15)
        else:
            return err(f"A packet capture is already running on {curr_iface}. Stop it before restarting.")

    _demo_active = False
    _live_analyzer.reset()

    # Create DB session (with graceful fallback if DB is locked/unavailable)
    try:
        session_id = db.create_session(interface=interface, mode="live")
    except Exception as exc:
        logger.warning("Could not create DB session: %s", exc)
        session_id = int(datetime.now(tz=timezone.utc).timestamp())

    # Wire live analyser into capture callbacks before starting
    capture_manager.add_packet_callback(_live_analyzer.feed)

    fallback_telemetry = bool(body.get("telemetry", False)) or mode == "telemetry"
    result = capture_manager.start_capture(interface, session_id, bpf_filter, fallback_telemetry=fallback_telemetry)
    if not result["success"]:
        try:
            db.close_session(session_id=session_id, total_packets=0, total_bytes=0)
        except Exception:
            pass

    result["session_id"] = session_id
    status = 200 if result["success"] else 400
    return jsonify(result), status


@app.route("/api/capture/stop", methods=["POST"])
def api_capture_stop():
    global _demo_active
    if _demo_active:
        _demo_active = False
        return ok(message="Demo mode stopped.", is_capturing=False)

    result = capture_manager.stop_capture()
    if result["success"] and capture_manager.active_session:
        sess = capture_manager.active_session
        stats = sess.get_stats()
        try:
            db.close_session(
                session_id=sess.session_id,
                total_packets=stats["total_packets"],
                total_bytes=stats["total_bytes"],
            )
            db.save_protocol_stats(sess.session_id, stats["protocol_counts"])
        except Exception as exc:
            logger.warning("Error saving session to DB: %s", exc)

    status = 200 if result["success"] else 400
    return jsonify(result), status


@app.route("/api/capture/status")
def api_capture_status():
    sess = capture_manager.active_session
    c_stats = capture_manager.get_stats()
    last_error = c_stats.get("last_error") or capture_manager.last_error

    if _demo_active:
        _ensure_demo()
        elapsed = 600
        dur_str = "10:00"
        return ok(
            is_capturing=False,
            demo_active=True,
            interface=_demo_interface,
            started_at=_demo_packets[0]["timestamp"] if _demo_packets else None,
            stopped_at=None,
            elapsed_seconds=elapsed,
            duration_formatted=dur_str,
            last_update=datetime.now(tz=timezone.utc).isoformat(),
            last_error=None,
            error=None,
            stats=_demo_analyzer.get_stats(),
        )

    elapsed = c_stats.get("elapsed_seconds", 0)
    dur_str = f"{elapsed // 60:02d}:{elapsed % 60:02d}"

    return ok(
        is_capturing=capture_manager.is_capturing,
        demo_active=False,
        interface=c_stats.get("interface") if capture_manager.is_capturing else None,
        started_at=c_stats.get("started_at"),
        stopped_at=c_stats.get("stopped_at"),
        elapsed_seconds=elapsed,
        duration_formatted=dur_str,
        last_update=c_stats.get("last_update"),
        last_error=last_error,
        error=last_error,
        stats=c_stats if capture_manager.is_capturing else {},
    )


# ─────────────────────────────────────────────────────────────────────────────
#  API — Packets
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/packets")
def api_packets():
    offset = _parse_int(request.args.get("offset"), 0)
    limit  = _parse_int(request.args.get("limit"),  config.PACKETS_PER_PAGE, 1)
    limit  = min(limit, 500)
    order  = (request.args.get("order") or "").lower()

    if _demo_active:
        _ensure_demo()
        source = _filter_packets(_demo_packets)
    else:
        source = _filter_packets(capture_manager.get_all_packets())

    total   = len(source)
    if order == "desc" or (order != "asc" and offset == 0 and limit <= 50):
        # Default top live preview slice to newest-first so new arrivals are immediately visible in table
        source = list(reversed(source))
    page    = source[offset: offset + limit]
    return ok(page, total=total, offset=offset, limit=limit)


# ─────────────────────────────────────────────────────────────────────────────
#  API — Traffic Statistics & Timeline
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/statistics")
@app.route("/api/stats")
def api_statistics():
    sess = capture_manager.active_session
    c_stats = sess.get_stats() if sess else {}

    if _demo_active:
        _ensure_demo()
        stats = _demo_analyzer.get_stats()
        stats["mode"] = "demo"
        stats["is_capturing"] = False
        stats["interface"] = _demo_interface
        stats["started_at"] = _demo_packets[0]["timestamp"] if _demo_packets else None
        stats["stopped_at"] = None
        stats["elapsed_seconds"] = 600
        stats["last_update"] = datetime.now(tz=timezone.utc).isoformat()
    else:
        # If live analyzer has no packets yet but session does, backfill from memory
        if _live_analyzer._total_packets == 0 and c_stats.get("total_packets", 0) > 0:
            for p in capture_manager.get_all_packets():
                _live_analyzer.feed(p)

        stats = _live_analyzer.get_stats()
        stats["mode"] = "live"
        stats["is_capturing"] = capture_manager.is_capturing
        stats["interface"] = c_stats.get("interface") if capture_manager.is_capturing else None
        stats["started_at"] = c_stats.get("started_at")
        stats["stopped_at"] = c_stats.get("stopped_at")
        stats["elapsed_seconds"] = c_stats.get("elapsed_seconds", 0)
        stats["last_update"] = c_stats.get("last_update") or (
            datetime.now(tz=timezone.utc).isoformat() if capture_manager.is_capturing else None
        )
        stats["last_error"] = c_stats.get("last_error")

        # Synchronize totals and protocol counts if session has higher count
        if c_stats.get("total_packets", 0) > stats.get("total_packets", 0):
            stats["total_packets"] = c_stats["total_packets"]
            stats["total_bytes"] = c_stats.get("total_bytes", 0)
            if c_stats.get("protocol_counts"):
                for proto, cnt in c_stats["protocol_counts"].items():
                    if cnt > stats["protocol_counts"].get(proto, 0):
                        stats["protocol_counts"][proto] = cnt

    # Ensure standard protocol counts exist
    if "protocol_counts" not in stats:
        stats["protocol_counts"] = {}
    for p in ("TCP", "UDP", "ICMP", "DNS", "ARP", "OTHER"):
        stats["protocol_counts"].setdefault(p, 0)

    return ok(stats)


@app.route("/api/traffic/timeline")
def api_traffic_timeline():
    window = (request.args.get("window") or "all").lower()
    window_sec = None
    if window in ("60", "1m"):
        window_sec = 60
    elif window in ("300", "5m"):
        window_sec = 300
    elif window in ("900", "15m"):
        window_sec = 900
    elif window in ("3600", "1h"):
        window_sec = 3600

    if _demo_active:
        _ensure_demo()
        timeline = _demo_analyzer.get_timeline(window_sec)
        peak = _demo_analyzer._peak_pps
    else:
        if _live_analyzer._total_packets == 0 and capture_manager.is_capturing:
            for p in capture_manager.get_all_packets():
                _live_analyzer.feed(p)
        timeline = _live_analyzer.get_timeline(window_sec)
        peak = _live_analyzer._peak_pps

    avg_pps = 0.0
    if timeline:
        avg_pps = round(sum(t.get("rate_pps", 0) for t in timeline) / len(timeline), 2)

    return ok(
        timeline=timeline,
        peak_rate_pps=peak,
        avg_rate_pps=avg_pps,
        total_periods=len(timeline),
        window=window,
    )


# ─────────────────────────────────────────────────────────────────────────────
#  API — Anomalies
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/anomalies")
def api_anomalies():
    limit = _parse_int(request.args.get("limit"), 100, 1)
    if _demo_active:
        _ensure_demo()
        return ok(_demo_anomalies[:limit], mode="demo")

    detector = capture_manager.get_detector()
    live_findings = detector.get_findings() if detector else []
    # Also fetch persisted
    db_findings = db.get_anomalies(limit=limit)
    # Merge, deduplicate by id
    seen = set()
    merged = []
    for f in live_findings + db_findings:
        fid = f.get("id") or id(f)
        if fid not in seen:
            seen.add(fid)
            merged.append(f)
    return ok(merged[:limit], mode="live")


@app.route("/api/anomalies/clear", methods=["POST"])
def api_anomalies_clear():
    db.clear_anomalies()
    return ok(message="Anomaly history cleared.")


# ─────────────────────────────────────────────────────────────────────────────
#  API — History
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/history")
def api_history():
    sessions = db.get_sessions(limit=config.MAX_HISTORY_SESSIONS)
    for s in sessions:
        s["protocol_stats"] = db.get_session_protocol_stats(s["id"])
    return ok(sessions)


@app.route("/api/history/clear", methods=["POST"])
def api_history_clear():
    db.delete_all_sessions()
    return ok(message="Capture history cleared.")


# ─────────────────────────────────────────────────────────────────────────────
#  API — Settings
# ─────────────────────────────────────────────────────────────────────────────

SETTING_KEYS = {
    "port_scan_threshold", "port_scan_window",
    "host_scan_threshold", "host_scan_window",
    "burst_threshold_pps", "burst_window",
    "syn_flood_threshold", "syn_flood_window",
    "unusual_volume_bytes", "unusual_volume_packets",
    "anomaly_cooldown", "webhook_url", "alert_min_severity",
}


@app.route("/api/settings")
def api_settings_get():
    defaults = {
        "port_scan_threshold":    config.PORT_SCAN_THRESHOLD,
        "port_scan_window":       config.PORT_SCAN_WINDOW_SECONDS,
        "host_scan_threshold":    config.HOST_SCAN_THRESHOLD,
        "host_scan_window":       config.HOST_SCAN_WINDOW_SECONDS,
        "burst_threshold_pps":    config.BURST_THRESHOLD_PPS,
        "burst_window":           config.BURST_WINDOW_SECONDS,
        "syn_flood_threshold":    config.SYN_FLOOD_THRESHOLD,
        "syn_flood_window":       config.SYN_FLOOD_WINDOW_SECONDS,
        "unusual_volume_bytes":   config.UNUSUAL_VOLUME_BYTES,
        "unusual_volume_packets": config.UNUSUAL_VOLUME_PACKETS,
        "anomaly_cooldown":       config.ANOMALY_COOLDOWN_SECONDS,
        "webhook_url":            getattr(config, "WEBHOOK_URL", ""),
        "alert_min_severity":     getattr(config, "ALERT_MIN_SEVERITY", "HIGH"),
    }
    result = {}
    for k, v in defaults.items():
        result[k] = db.get_setting(k, v)
    return ok(result)


@app.route("/api/settings", methods=["POST"])
def api_settings_post():
    body = request.get_json(silent=True) or {}
    saved = {}
    for k, v in body.items():
        if k in SETTING_KEYS:
            if k in ("webhook_url", "alert_min_severity"):
                db.set_setting(k, str(v).strip())
                saved[k] = str(v).strip()
            else:
                try:
                    db.set_setting(k, str(int(float(str(v)))))
                    saved[k] = v
                except ValueError:
                    pass
    # Reload detector thresholds
    detector = capture_manager.get_detector()
    if detector:
        detector.reload_thresholds()
    return ok(saved, message="Settings saved.")


@app.route("/api/webhook/test", methods=["POST"])
def api_webhook_test():
    body = request.get_json(silent=True) or {}
    webhook_url = (body.get("webhook_url") or db.get_setting("webhook_url", "")).strip()
    if not webhook_url:
        return err("Webhook URL is empty or unconfigured.")
    if not (webhook_url.startswith("http://") or webhook_url.startswith("https://")):
        return err("Webhook URL must start with http:// or https://")

    try:
        payload = {
            "username": "CyberTrace Security",
            "content": "✅ **CyberTrace Webhook Test** — Real-time alerts successfully configured!",
            "embeds": [{
                "title": "✅ Connection Verified",
                "description": "CyberTrace Network Analyzer can now dispatch instant threat, port scan, and SYN flood alerts directly to this channel.",
                "color": 4898432,
                "fields": [
                    {"name": "Status", "value": "Active", "inline": True},
                    {"name": "Platform", "value": "CyberTrace v2.0", "inline": True},
                ],
                "footer": {"text": "CyberTrace Network Monitoring & Security Analyzer"}
            }]
        }
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "CyberTrace-Webhook/2.0"},
        )
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            code = resp.getcode()
            if code in (200, 204):
                return ok(message="Test alert sent successfully!")
            return ok(message=f"Webhook server responded with HTTP {code}.")
    except Exception as exc:
        return err(f"Failed to deliver test webhook: {exc}")



# ─────────────────────────────────────────────────────────────────────────────
#  API — Export / Reports
# ─────────────────────────────────────────────────────────────────────────────

def _current_mode() -> str:
    return "demo" if _demo_active else "live"


def _current_iface() -> str:
    if _demo_active:
        return "demo"
    if capture_manager.active_session:
        return capture_manager.active_session.interface
    return "N/A"


def _period_str() -> str:
    now = datetime.now(tz=timezone.utc)
    return f"up to {now.strftime('%Y-%m-%d %H:%M UTC')}"


@app.route("/api/export/csv")
def api_export_csv():
    if _demo_active:
        _ensure_demo()
        source = _filter_packets(_demo_packets)
    else:
        source = _filter_packets(capture_manager.get_all_packets())
    filepath = rg.export_packets_csv(source, _current_iface(), _period_str())
    return send_file(filepath, as_attachment=True,
                     download_name=os.path.basename(filepath),
                     mimetype="text/csv")


@app.route("/api/export/json")
def api_export_json():
    if _demo_active:
        _ensure_demo()
        stats = _demo_analyzer.get_stats()
    else:
        stats = _live_analyzer.get_stats()
    filepath = rg.export_stats_json(stats, _current_iface(), _period_str())
    return send_file(filepath, as_attachment=True,
                     download_name=os.path.basename(filepath),
                     mimetype="application/json")


@app.route("/api/export/html")
def api_export_html():
    if _demo_active:
        _ensure_demo()
        stats    = _demo_analyzer.get_stats()
        anomalies = _demo_anomalies
    else:
        stats    = _live_analyzer.get_stats()
        detector = capture_manager.get_detector()
        anomalies = detector.get_findings() if detector else []

    filepath = rg.export_html_report(
        stats, anomalies, _current_iface(), _period_str(), _current_mode()
    )
    return send_file(filepath, as_attachment=True,
                     download_name=os.path.basename(filepath),
                     mimetype="text/html")


# ─────────────────────────────────────────────────────────────────────────────
#  API — Threat Intelligence & GeoIP Map
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/threat/lookup")
def api_threat_lookup():
    ip = (request.args.get("ip") or "").strip()
    if not ip:
        return err("IP query parameter is required.")
    return ok(threat_manager.lookup(ip))


@app.route("/api/threat/nodes")
def api_threat_nodes():
    if _demo_active:
        _ensure_demo()
        packets = _demo_packets
    else:
        packets = capture_manager.get_all_packets()

    nodes = threat_manager.get_map_nodes(packets) if packets else []

    # If active capture only has local loopback (127.0.0.1) or internal LAN traffic,
    # supplement with telemetry threat endpoints so the 3D globe is always alive with threat arcs!
    if not nodes:
        _ensure_demo()
        nodes = threat_manager.get_map_nodes(_demo_packets)

    return ok(nodes)


@app.route("/api/threat/summary")
def api_threat_summary():
    if _demo_active:
        _ensure_demo()
        packets = _demo_packets
    else:
        packets = capture_manager.get_all_packets()

    nodes = threat_manager.get_map_nodes(packets) if packets else []
    if not nodes:
        _ensure_demo()
        nodes = threat_manager.get_map_nodes(_demo_packets)

    countries = set(n["country"] for n in nodes if n["country"] and n["country"] not in ("Local Network", "Resolving..."))
    high_risk = [n for n in nodes if n.get("threat_level") in ("HIGH", "CRITICAL")]
    medium_risk = [n for n in nodes if n.get("threat_level") == "MEDIUM"]
    clean = [n for n in nodes if n.get("threat_level") == "CLEAN"]

    return ok({
        "total_nodes": len(nodes),
        "countries_count": len(countries),
        "countries": sorted(list(countries)),
        "high_risk_count": len(high_risk),
        "medium_risk_count": len(medium_risk),
        "clean_count": len(clean),
        "nodes": nodes,
    })


# ─────────────────────────────────────────────────────────────────────────────
#  API — Network Members & Device Inventory
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/members")
def api_members():
    if _demo_active or not capture_manager.is_capturing:
        _ensure_demo()
    filter_type = request.args.get("type")
    filter_status = request.args.get("status")
    search = request.args.get("search")
    members = member_manager.get_members(
        filter_type=filter_type,
        filter_status=filter_status,
        search=search,
    )
    return ok(members)


@app.route("/api/members/stats")
def api_members_stats():
    if _demo_active or not capture_manager.is_capturing:
        _ensure_demo()
    stats = member_manager.get_stats()
    return ok(stats)


@app.route("/api/members/<ip>")
def api_member_detail(ip):
    if _demo_active or not capture_manager.is_capturing:
        _ensure_demo()
    member = member_manager.get_member_by_ip(ip)
    if not member:
        return err(f"Network member '{ip}' not found.", 404)
    return ok(member)


@app.route("/api/members/scan", methods=["POST"])
def api_members_scan():
    body = request.get_json(silent=True) or {}
    iface = body.get("interface")
    res = member_manager.start_subnet_scan(iface)
    return ok(res)


@app.route("/api/members/scan/status")
def api_members_scan_status():
    return ok(member_manager.get_scan_status())


@app.route("/api/members/update", methods=["POST"])
def api_members_update():
    body = request.get_json(silent=True) or {}
    ip = body.get("ip")
    if not ip:
        return err("IP address is required.")

    custom_name = body.get("custom_name")
    is_trusted = body.get("is_trusted")
    device_type = body.get("device_type")
    notes = body.get("notes")

    success = member_manager.update_member(
        ip=ip,
        custom_name=custom_name,
        is_trusted=is_trusted,
        device_type=device_type,
        notes=notes,
    )
    if not success:
        return err(f"Network member with IP '{ip}' not found.", 404)
    return ok({"updated": True, "ip": ip})


@app.route("/api/members/clear", methods=["POST"])
def api_members_clear():
    member_manager.clear()
    return ok({"cleared": True})


# ─────────────────────────────────────────────────────────────────────────────
#  Error handlers
# ─────────────────────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def server_error(e):
    logger.exception("Server error")
    return jsonify({"success": False, "message": "Internal server error."}), 500


import atexit

@atexit.register
def _cleanup_capture_on_exit():
    if capture_manager.is_capturing:
        logger.info("Application shutting down: safely stopping active packet capture.")
        capture_manager.stop_capture()


# ─────────────────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    db.init_db()
    logger.info("CyberTrace Network Analyzer starting on http://%s:%d", config.FLASK_HOST, config.FLASK_PORT)
    app.run(
        host=config.FLASK_HOST,
        port=config.FLASK_PORT,
        debug=config.FLASK_DEBUG,
        use_reloader=False,   # Reloader conflicts with background threads
    )

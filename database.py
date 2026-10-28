"""
database.py — SQLite persistence layer.
"""

import sqlite3
import os
import logging
from datetime import datetime, timezone

import config

logger = logging.getLogger(__name__)


def _ensure_dirs():
    os.makedirs(os.path.dirname(config.DB_PATH), exist_ok=True)
    os.makedirs(config.EXPORT_DIR, exist_ok=True)


def get_connection() -> sqlite3.Connection:
    _ensure_dirs()
    conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Create all tables if they do not already exist."""
    _ensure_dirs()
    conn = get_connection()
    try:
        cur = conn.cursor()

        # ── Capture sessions ──────────────────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS capture_sessions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                interface   TEXT NOT NULL,
                started_at  TEXT NOT NULL,
                stopped_at  TEXT,
                mode        TEXT NOT NULL DEFAULT 'live',   -- 'live' | 'demo'
                total_packets INTEGER DEFAULT 0,
                total_bytes   INTEGER DEFAULT 0,
                notes       TEXT
            )
        """)

        # ── Per-session protocol summary ──────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS session_protocol_stats (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL REFERENCES capture_sessions(id),
                protocol   TEXT NOT NULL,
                count      INTEGER DEFAULT 0
            )
        """)

        # ── Anomaly findings ──────────────────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS anomaly_findings (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id    INTEGER REFERENCES capture_sessions(id),
                detected_at   TEXT NOT NULL,
                finding_type  TEXT NOT NULL,
                src_ip        TEXT,
                dst_ip        TEXT,
                dst_ports     TEXT,   -- JSON list
                packet_count  INTEGER,
                byte_count    INTEGER,
                threshold     TEXT,
                explanation   TEXT,
                severity      TEXT DEFAULT 'medium',
                is_demo       INTEGER DEFAULT 0
            )
        """)

        # ── Settings (key/value store) ────────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)

        # ── Network Members / Connected Devices ──────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS network_members (
                ip          TEXT PRIMARY KEY,
                mac         TEXT,
                hostname    TEXT,
                custom_name TEXT,
                vendor      TEXT,
                device_type TEXT DEFAULT 'Workstation',
                is_trusted  INTEGER DEFAULT 1,
                first_seen  TEXT NOT NULL,
                last_seen   TEXT NOT NULL,
                packets_in  INTEGER DEFAULT 0,
                packets_out INTEGER DEFAULT 0,
                bytes_in    INTEGER DEFAULT 0,
                bytes_out   INTEGER DEFAULT 0,
                notes       TEXT,
                is_demo     INTEGER DEFAULT 0
            )
        """)

        conn.commit()
        logger.info("Database initialised at %s", config.DB_PATH)
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
#  Sessions
# ─────────────────────────────────────────────────────────────────────────────

def create_session(interface: str, mode: str = "live") -> int:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO capture_sessions (interface, started_at, mode) VALUES (?,?,?)",
            (interface, datetime.now(tz=timezone.utc).isoformat(), mode),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def close_session(session_id: int, total_packets: int, total_bytes: int):
    conn = get_connection()
    try:
        conn.execute(
            """UPDATE capture_sessions
               SET stopped_at=?, total_packets=?, total_bytes=?
               WHERE id=?""",
            (datetime.now(tz=timezone.utc).isoformat(), total_packets, total_bytes, session_id),
        )
        conn.commit()
    finally:
        conn.close()


def save_protocol_stats(session_id: int, protocol_counts: dict):
    conn = get_connection()
    try:
        conn.execute(
            "DELETE FROM session_protocol_stats WHERE session_id=?", (session_id,)
        )
        for proto, count in protocol_counts.items():
            conn.execute(
                "INSERT INTO session_protocol_stats (session_id, protocol, count) VALUES (?,?,?)",
                (session_id, proto, count),
            )
        conn.commit()
    finally:
        conn.close()


def get_sessions(limit: int = 50):
    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT * FROM capture_sessions ORDER BY id DESC LIMIT ?""", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_session_protocol_stats(session_id: int):
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT protocol, count FROM session_protocol_stats WHERE session_id=?",
            (session_id,),
        ).fetchall()
        return {r["protocol"]: r["count"] for r in rows}
    finally:
        conn.close()


def delete_all_sessions():
    conn = get_connection()
    try:
        conn.execute("DELETE FROM anomaly_findings")
        conn.execute("DELETE FROM session_protocol_stats")
        conn.execute("DELETE FROM capture_sessions")
        conn.commit()
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
#  Anomaly findings
# ─────────────────────────────────────────────────────────────────────────────

def save_anomaly(finding: dict) -> int:
    import json
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO anomaly_findings
               (session_id, detected_at, finding_type, src_ip, dst_ip, dst_ports,
                packet_count, byte_count, threshold, explanation, severity, is_demo)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                finding.get("session_id"),
                finding.get("detected_at", datetime.now(tz=timezone.utc).isoformat()),
                finding.get("finding_type"),
                finding.get("src_ip"),
                finding.get("dst_ip"),
                json.dumps(finding.get("dst_ports", [])),
                finding.get("packet_count"),
                finding.get("byte_count"),
                str(finding.get("threshold")),
                finding.get("explanation"),
                finding.get("severity", "medium"),
                int(finding.get("is_demo", False)),
            ),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_anomalies(session_id: int = None, limit: int = 200):
    import json
    conn = get_connection()
    try:
        if session_id:
            rows = conn.execute(
                "SELECT * FROM anomaly_findings WHERE session_id=? ORDER BY id DESC LIMIT ?",
                (session_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM anomaly_findings ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["dst_ports"] = json.loads(d["dst_ports"] or "[]")
            except Exception:
                d["dst_ports"] = []
            result.append(d)
        return result
    finally:
        conn.close()


def clear_anomalies(session_id: int = None):
    conn = get_connection()
    try:
        if session_id:
            conn.execute(
                "DELETE FROM anomaly_findings WHERE session_id=?", (session_id,)
            )
        else:
            conn.execute("DELETE FROM anomaly_findings")
        conn.commit()
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
#  Settings
# ─────────────────────────────────────────────────────────────────────────────

def get_setting(key: str, default=None):
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT value FROM settings WHERE key=?", (key,)
        ).fetchone()
        return row["value"] if row else default
    finally:
        conn.close()


def set_setting(key: str, value: str):
    conn = get_connection()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)", (key, str(value))
        )
        conn.commit()
    finally:
        conn.close()

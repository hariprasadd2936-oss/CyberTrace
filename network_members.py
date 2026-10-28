"""
network_members.py — Network Members & Device Inventory Engine for CyberTrace.
Provides host discovery, MAC vendor resolution, device fingerprinting,
and per-member bandwidth and protocol analytics.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import config
import database as db

logger = logging.getLogger(__name__)

# ─── Top MAC OUI Database (Offline Resolution) ───────────────────────────────
# Normalized 6-hex uppercase prefixes (e.g. '001A2B' or 'B827EB')
OUI_DATABASE: Dict[str, str] = {
    # Apple
    "000393": "Apple, Inc.",
    "000502": "Apple, Inc.",
    "000A27": "Apple, Inc.",
    "000A95": "Apple, Inc.",
    "000D93": "Apple, Inc.",
    "0010FA": "Apple, Inc.",
    "001451": "Apple, Inc.",
    "0016CB": "Apple, Inc.",
    "0017F2": "Apple, Inc.",
    "001B63": "Apple, Inc.",
    "001C42": "Apple, Inc.",
    "001E52": "Apple, Inc.",
    "001F5B": "Apple, Inc.",
    "0021E9": "Apple, Inc.",
    "002241": "Apple, Inc.",
    "002312": "Apple, Inc.",
    "002332": "Apple, Inc.",
    "00236C": "Apple, Inc.",
    "002436": "Apple, Inc.",
    "002500": "Apple, Inc.",
    "00254B": "Apple, Inc.",
    "002608": "Apple, Inc.",
    "00264A": "Apple, Inc.",
    "0026B0": "Apple, Inc.",
    "003EE1": "Apple, Inc.",
    "006171": "Apple, Inc.",
    "040C56": "Apple, Inc.",
    "041552": "Apple, Inc.",
    "042665": "Apple, Inc.",
    "045453": "Apple, Inc.",
    "04DB56": "Apple, Inc.",
    "086698": "Apple, Inc.",
    "0C4DE9": "Apple, Inc.",
    "10417F": "Apple, Inc.",
    "147DDA": "Apple, Inc.",
    "18AF61": "Apple, Inc.",
    "20A2E4": "Apple, Inc.",
    "28CFE9": "Apple, Inc.",
    "28E02C": "Apple, Inc.",
    "3C0754": "Apple, Inc.",
    "3C2EFE": "Apple, Inc.",
    "406C8F": "Apple, Inc.",
    "44D884": "Apple, Inc.",
    "48D705": "Apple, Inc.",
    "50BC96": "Apple, Inc.",
    "5855CA": "Apple, Inc.",
    "600308": "Apple, Inc.",
    "64A5C3": "Apple, Inc.",
    "70DE39": "Apple, Inc.",
    "784F43": "Apple, Inc.",
    "804971": "Apple, Inc.",
    "843835": "Apple, Inc.",
    "88665A": "Apple, Inc.",
    "9027E4": "Apple, Inc.",
    "9801A7": "Apple, Inc.",
    "A483E7": "Apple, Inc.",
    "A8667F": "Apple, Inc.",
    "ACBC32": "Apple, Inc.",
    "B065BD": "Apple, Inc.",
    "B8782E": "Apple, Inc.",
    "BC926B": "Apple, Inc.",
    "C0D012": "Apple, Inc.",
    "C869CD": "Apple, Inc.",
    "D0034B": "Apple, Inc.",
    "D89695": "Apple, Inc.",
    "E0ACCB": "Apple, Inc.",
    "F01898": "Apple, Inc.",
    "F4F15A": "Apple, Inc.",
    "F8FFC2": "Apple, Inc.",

    # Samsung
    "0000F0": "Samsung Electronics",
    "000278": "Samsung Electronics",
    "0007AB": "Samsung Electronics",
    "000Dae": "Samsung Electronics",
    "001247": "Samsung Electronics",
    "001599": "Samsung Electronics",
    "00166B": "Samsung Electronics",
    "0018AF": "Samsung Electronics",
    "002119": "Samsung Electronics",
    "002454": "Samsung Electronics",
    "002637": "Samsung Electronics",
    "08373D": "Samsung Electronics",
    "107719": "Samsung Electronics",
    "1867B0": "Samsung Electronics",
    "244B03": "Samsung Electronics",
    "28BA81": "Samsung Electronics",
    "30074D": "Samsung Electronics",
    "380195": "Samsung Electronics",
    "400E85": "Samsung Electronics",
    "444E1A": "Samsung Electronics",
    "503275": "Samsung Electronics",
    "549B12": "Samsung Electronics",
    "5C5188": "Samsung Electronics",
    "60AF6D": "Samsung Electronics",
    "68EBae": "Samsung Electronics",
    "7840E4": "Samsung Electronics",
    "8425DB": "Samsung Electronics",
    "90187C": "Samsung Electronics",
    "94350A": "Samsung Electronics",
    "9C0298": "Samsung Electronics",
    "A002DC": "Samsung Electronics",
    "A80600": "Samsung Electronics",
    "B407F9": "Samsung Electronics",
    "BC4486": "Samsung Electronics",
    "C09727": "Samsung Electronics",
    "CC07AB": "Samsung Electronics",
    "E47CF9": "Samsung Electronics",
    "EC1F72": "Samsung Electronics",
    "F409D8": "Samsung Electronics",

    # Intel
    "0002B3": "Intel Corporate",
    "000347": "Intel Corporate",
    "000423": "Intel Corporate",
    "0007E9": "Intel Corporate",
    "000C76": "Intel Corporate",
    "000E0C": "Intel Corporate",
    "001302": "Intel Corporate",
    "001500": "Intel Corporate",
    "0019D1": "Intel Corporate",
    "001B21": "Intel Corporate",
    "001D09": "Intel Corporate",
    "001E64": "Intel Corporate",
    "00215C": "Intel Corporate",
    "002314": "Intel Corporate",
    "0024D7": "Intel Corporate",
    "0026C7": "Intel Corporate",
    "002710": "Intel Corporate",
    "3413E8": "Intel Corporate",
    "3C5282": "Intel Corporate",
    "4851B7": "Intel Corporate",
    "58946B": "Intel Corporate",
    "6805CA": "Intel Corporate",
    "701CE7": "Intel Corporate",
    "7C214A": "Intel Corporate",
    "84A93E": "Intel Corporate",
    "8C8590": "Intel Corporate",
    "94E6F7": "Intel Corporate",
    "A0AFBD": "Intel Corporate",
    "A44CC8": "Intel Corporate",
    "B8B81E": "Intel Corporate",
    "C80AA9": "Intel Corporate",
    "DC5360": "Intel Corporate",
    "F8633F": "Intel Corporate",

    # Raspberry Pi
    "B827EB": "Raspberry Pi Foundation",
    "DC2632": "Raspberry Pi Trading",
    "E45F01": "Raspberry Pi Trading",
    "28CDC1": "Raspberry Pi Trading",

    # Espressif (ESP8266 / ESP32 IoT)
    "18FE34": "Espressif Systems",
    "240AC4": "Espressif Systems",
    "2462AB": "Espressif Systems",
    "246F28": "Espressif Systems",
    "24A160": "Espressif Systems",
    "24B2DE": "Espressif Systems",
    "2C3AE8": "Espressif Systems",
    "30AEA4": "Espressif Systems",
    "3C6105": "Espressif Systems",
    "3C71BF": "Espressif Systems",
    "40F520": "Espressif Systems",
    "4C11AE": "Espressif Systems",
    "545A10": "Espressif Systems",
    "68C63A": "Espressif Systems",
    "70039F": "Espressif Systems",
    "78E36D": "Espressif Systems",
    "840D8E": "Espressif Systems",
    "84F3EB": "Espressif Systems",
    "94B97E": "Espressif Systems",
    "A47B9D": "Espressif Systems",
    "A4CF12": "Espressif Systems",
    "AC67B2": "Espressif Systems",
    "B4E62D": "Espressif Systems",
    "BCDD07": "Espressif Systems",
    "CC50E3": "Espressif Systems",

    # Cisco / Linksys
    "00000C": "Cisco Systems",
    "000142": "Cisco Systems",
    "000143": "Cisco Systems",
    "000163": "Cisco Systems",
    "000196": "Cisco Systems",
    "000216": "Cisco Systems",
    "00044D": "Cisco Systems",
    "000652": "Cisco Systems",
    "0008E3": "Cisco Systems",
    "0018BA": "Cisco Systems",
    "0019A9": "Cisco Systems",
    "0022BD": "Cisco Systems",
    "002414": "Cisco Systems",
    "002584": "Cisco Systems",
    "000625": "Linksys",
    "001839": "Linksys",
    "001EE5": "Linksys",

    # TP-Link
    "002586": "TP-Link Technologies",
    "14CC20": "TP-Link Technologies",
    "1C3BF3": "TP-Link Technologies",
    "30B5C2": "TP-Link Technologies",
    "503EA0": "TP-Link Technologies",
    "60A44C": "TP-Link Technologies",
    "7405A5": "TP-Link Technologies",
    "8416F9": "TP-Link Technologies",
    "984827": "TP-Link Technologies",
    "A0F3C1": "TP-Link Technologies",
    "B0487A": "TP-Link Technologies",
    "C04A00": "TP-Link Technologies",
    "E894F6": "TP-Link Technologies",
    "F4EC38": "TP-Link Technologies",

    # Netgear
    "00095B": "Netgear",
    "000FB5": "Netgear",
    "00146C": "Netgear",
    "00184D": "Netgear",
    "001E2A": "Netgear",
    "0024B2": "Netgear",
    "0026F2": "Netgear",
    "20E52A": "Netgear",
    "28C68E": "Netgear",
    "841B5E": "Netgear",
    "9C3DCF": "Netgear",
    "A00460": "Netgear",
    "C03F0E": "Netgear",

    # Microsoft
    "0003FF": "Microsoft Corporation",
    "000D3A": "Microsoft Corporation",
    "00125A": "Microsoft Corporation",
    "00155D": "Microsoft Hyper-V / Surface",
    "0017FA": "Microsoft Corporation",
    "001D43": "Microsoft Corporation",
    "002248": "Microsoft Corporation",
    "0025AE": "Microsoft Corporation",
    "281878": "Microsoft Surface",
    "7CE9D3": "Microsoft Corporation",
    "DCB4C4": "Microsoft Corporation",

    # Google
    "001A11": "Google LLC",
    "3C5AB4": "Google Nest / Home",
    "546009": "Google Pixel",
    "641666": "Google LLC",
    "703EAC": "Google LLC",
    "94EB2C": "Google LLC",
    "D86C63": "Google Chromecast",
    "F4F5D8": "Google Pixel",

    # Dell
    "00065B": "Dell Inc.",
    "000874": "Dell Inc.",
    "000BDB": "Dell Inc.",
    "001143": "Dell Inc.",
    "001372": "Dell Inc.",
    "001422": "Dell Inc.",
    "0016F0": "Dell Inc.",
    "00188B": "Dell Inc.",
    "0019B9": "Dell Inc.",
    "001A4B": "Dell Inc.",
    "001C23": "Dell Inc.",
    "00219B": "Dell Inc.",
    "0023AE": "Dell Inc.",
    "0024E8": "Dell Inc.",
    "0026B9": "Dell Inc.",
    "180373": "Dell Inc.",
    "24B6FD": "Dell Inc.",
    "34E6D7": "Dell Inc.",
    "44A842": "Dell Inc.",
    "5CF9DD": "Dell Inc.",
    "74867A": "Dell Inc.",
    "847BEB": "Dell Inc.",
    "A4BADB": "Dell Inc.",
    "B499BA": "Dell Inc.",
    "BC305B": "Dell Inc.",
    "C4346B": "Dell Inc.",
    "D481D7": "Dell Inc.",
    "E4F004": "Dell Inc.",
    "F0D5BF": "Dell Inc.",

    # HP / Hewlett Packard
    "0001E6": "HP Inc.",
    "0002A5": "HP Inc.",
    "000802": "HP Inc.",
    "000B86": "Aruba / HP Enterprise",
    "000E7F": "HP Inc.",
    "001083": "HP Inc.",
    "0014C2": "HP Inc.",
    "0017A4": "HP Inc.",
    "001E0B": "HP Inc.",
    "00215A": "HP Inc.",
    "00237D": "HP Inc.",
    "002481": "HP Inc.",
    "0025B3": "HP Inc.",
    "10604B": "HP Inc.",
    "186024": "HP Inc.",
    "2C4138": "HP Inc.",
    "3863BB": "HP Inc.",
    "480FCE": "HP Inc.",
    "705A0F": "HP Inc.",
    "80C16E": "HP Inc.",
    "9C8E99": "HP Inc.",
    "C8D3FF": "HP Inc.",

    # Sony
    "00014A": "Sony Corporation",
    "00041F": "Sony Corporation",
    "0013A9": "Sony PlayStation",
    "0015C1": "Sony Corporation",
    "0019C5": "Sony PlayStation",
    "001A80": "Sony Corporation",
    "001D0D": "Sony PlayStation",
    "00248D": "Sony Corporation",
    "709E29": "Sony PlayStation",
    "A8E3EE": "Sony PlayStation 5",
    "FC0F4B": "Sony Bravia TV",

    # LG Electronics
    "0005F9": "LG Electronics",
    "000B90": "LG Electronics",
    "001469": "LG Electronics",
    "001C62": "LG Electronics",
    "002483": "LG Electronics",
    "10F9EE": "LG Smart TV",
    "14C913": "LG Smart TV",
    "203DB0": "LG Electronics",
    "34FCB9": "LG Smart TV",
    "60A4D0": "LG Electronics",
    "A823FE": "LG Smart TV",

    # Xiaomi
    "009EEA": "Xiaomi Communications",
    "14F65A": "Xiaomi Communications",
    "185936": "Xiaomi Communications",
    "286C07": "Xiaomi Communications",
    "34CE00": "Xiaomi Communications",
    "584498": "Xiaomi Communications",
    "640980": "Xiaomi Communications",
    "7C49EB": "Xiaomi Communications",
    "98FA9B": "Xiaomi Communications",
    "A4C361": "Xiaomi Communications",
    "D89C35": "Xiaomi Communications",
    "F0B429": "Xiaomi Communications",

    # Huawei
    "001882": "Huawei Technologies",
    "001E10": "Huawei Technologies",
    "00259E": "Huawei Technologies",
    "00464B": "Huawei Technologies",
    "104780": "Huawei Technologies",
    "14B968": "Huawei Technologies",
    "200BC7": "Huawei Technologies",
    "286ED4": "Huawei Technologies",
    "4846FB": "Huawei Technologies",
    "707990": "Huawei Technologies",
    "84A8E4": "Huawei Technologies",

    # VMware / VirtualBox / Hyper-V (Virtual Machines)
    "000569": "VMware, Inc.",
    "000C29": "VMware, Inc.",
    "001C14": "VMware, Inc.",
    "005056": "VMware, Inc.",
    "080027": "Oracle VirtualBox",
    "525400": "QEMU / KVM Virtual Machine",

    # Synology / QNAP (NAS Storage)
    "001132": "Synology Inc.",
    "00089B": "QNAP Systems",

    # Ubiquiti
    "00156D": "Ubiquiti Networks",
    "002722": "Ubiquiti Networks",
    "24A43C": "Ubiquiti Networks",
    "68D79A": "Ubiquiti Networks",
    "7483C2": "Ubiquiti Networks",
    "B4FBE4": "Ubiquiti Networks",
    "DC9FDB": "Ubiquiti Networks",
    "F09FC2": "Ubiquiti Networks",

    # Realtek
    "000732": "Realtek Semiconductor",
    "000854": "Realtek Semiconductor",
    "00E04C": "Realtek Semiconductor",
    "52544C": "Realtek Semiconductor",

    # Amazon
    "00FC8B": "Amazon Echo / FireTV",
    "18742E": "Amazon Technologies",
    "38F73D": "Amazon Kindle",
    "40B4CD": "Amazon Echo",
    "6837E9": "Amazon FireTV",
    "747548": "Amazon Echo",
    "84D6D0": "Amazon Technologies",
    "AC63BE": "Amazon Technologies",
    "CC9E00": "Amazon Echo",
    "FC65DE": "Amazon Technologies",
}


def normalize_mac(mac: Optional[str]) -> Optional[str]:
    """Format MAC to uppercase colon-separated standard (e.g. 00:1A:2B:3C:4D:5E)."""
    if not mac:
        return None
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", str(mac)).upper()
    if len(cleaned) == 12:
        return ":".join(cleaned[i:i+2] for i in range(0, 12, 2))
    return str(mac).strip().upper()


def resolve_vendor(mac: Optional[str]) -> str:
    """Look up manufacturer vendor name using OUI database with heuristics."""
    if not mac:
        return "Unknown Vendor"
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", str(mac)).upper()
    if len(cleaned) >= 6:
        prefix = cleaned[:6]
        if prefix in OUI_DATABASE:
            return OUI_DATABASE[prefix]
    return "Generic Device / Private MAC"


def is_lan_ip(ip: Optional[str]) -> bool:
    """Check if an IP address is a private / link-local / local subnet address."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_link_local or addr.is_loopback
    except ValueError:
        return False


def classify_device(
    ip: str,
    vendor: str,
    hostname: Optional[str] = None,
    ports: Optional[List[int]] = None,
    is_gateway: bool = False
) -> str:
    """
    Classify device into one of:
    - Gateway
    - Workstation
    - Mobile
    - Smart TV
    - IoT
    - Server
    - Suspicious
    - Unknown
    """
    v_lower = (vendor or "").lower()
    h_lower = (hostname or "").lower()
    ports_set = set(ports or [])

    # Gateway / Router rule
    if is_gateway or ip.endswith(".1") or ip.endswith(".254"):
        return "Gateway"

    # Router brands
    if any(b in v_lower for b in ("cisco", "linksys", "tp-link", "netgear", "ubiquiti", "d-link", "mikrotik")):
        if ip.endswith(".1") or ip.endswith(".254") or 80 in ports_set or 8080 in ports_set:
            return "Gateway"

    # Mobile Devices
    if any(m in h_lower for m in ("iphone", "ipad", "android", "galaxy", "pixel", "redmi", "oneplus", "mobile")):
        return "Mobile"
    if "apple" in v_lower and ("phone" in h_lower or "pad" in h_lower):
        return "Mobile"
    if "samsung" in v_lower and any(p in h_lower for p in ("sm-", "galaxy", "phone")):
        return "Mobile"
    if "xiaomi" in v_lower or "huawei" in v_lower:
        return "Mobile"

    # Smart TV / Media
    if any(t in h_lower for t in ("tv", "bravia", "firetv", "chromecast", "roku", "appletv", "shield")):
        return "Smart TV"
    if any(t in v_lower for t in ("smart tv", "bravia", "firetv", "chromecast")):
        return "Smart TV"
    if any(t in v_lower for t in ("playstation", "xbox", "nintendo")):
        return "Smart TV"

    # IoT / Smart Home
    if any(i in v_lower for i in ("espressif", "raspberry pi", "nest", "echo", "philips", "tuya", "sonoff")):
        return "IoT"
    if any(i in h_lower for i in ("esp32", "esp8266", "raspberrypi", "bulb", "plug", "sensor", "camera", "iot")):
        return "IoT"

    # Workstation / PC / Laptop
    if any(w in v_lower for w in ("intel", "dell", "hp inc", "lenovo", "microsoft surface", "asus", "realtek")):
        return "Workstation"
    if any(w in h_lower for w in ("desktop", "laptop", "pc", "macbook", "imac", "thinkpad", "workstation", "surface")):
        return "Workstation"
    if "apple" in v_lower and ("mac" in h_lower or not h_lower):
        return "Workstation"

    # Server / Virtual Machine / NAS
    if any(s in v_lower for s in ("vmware", "virtualbox", "qemu", "synology", "qnap")):
        return "Server"
    if any(s in h_lower for s in ("server", "nas", "proxmox", "esxi", "docker", "ubuntu", "debian", "srv")):
        return "Server"
    if any(p in ports_set for p in (22, 445, 3389, 5432, 3306, 8443)):
        return "Server"

    return "Workstation" if is_lan_ip(ip) else "Unknown"


# ─── Network Member Model ───────────────────────────────────────────────────

class NetworkMember:
    def __init__(
        self,
        ip: str,
        mac: Optional[str] = None,
        hostname: Optional[str] = None,
        custom_name: Optional[str] = None,
        vendor: Optional[str] = None,
        device_type: Optional[str] = None,
        is_trusted: bool = True,
        first_seen: Optional[str] = None,
        last_seen: Optional[str] = None,
        packets_in: int = 0,
        packets_out: int = 0,
        bytes_in: int = 0,
        bytes_out: int = 0,
        notes: str = "",
        is_demo: bool = False,
    ):
        now_iso = datetime.now(tz=timezone.utc).isoformat()
        self.ip = ip
        self.mac = normalize_mac(mac)
        self.hostname = hostname
        self.custom_name = custom_name or ""
        self.vendor = vendor or resolve_vendor(self.mac)
        self.device_type = device_type or classify_device(ip, self.vendor, hostname)
        self.is_trusted = is_trusted
        self.first_seen = first_seen or now_iso
        self.last_seen = last_seen or now_iso
        self.packets_in = packets_in
        self.packets_out = packets_out
        self.bytes_in = bytes_in
        self.bytes_out = bytes_out
        self.protocols: Counter[str] = Counter()
        self.ports: Counter[int] = Counter()
        self.notes = notes
        self.is_demo = is_demo
        self.anomaly_count = 0

    @property
    def total_packets(self) -> int:
        return self.packets_in + self.packets_out

    @property
    def total_bytes(self) -> int:
        return self.bytes_in + self.bytes_out

    @property
    def display_name(self) -> str:
        if self.custom_name:
            return self.custom_name
        if self.hostname and not self.hostname.replace(".", "").isdigit():
            return self.hostname
        if self.device_type == "Gateway":
            return f"Default Gateway ({self.ip})"
        if self.vendor and self.vendor != "Unknown Vendor" and self.vendor != "Generic Device / Private MAC":
            return f"{self.vendor} Device"
        return f"Member {self.ip}"

    @property
    def status(self) -> str:
        """Calculate online status based on last seen timestamp."""
        try:
            dt = datetime.fromisoformat(self.last_seen)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            delta = (datetime.now(tz=timezone.utc) - dt).total_seconds()
            if delta <= 90:
                return "Online"
            elif delta <= 600:
                return "Idle"
            else:
                return "Offline"
        except Exception:
            return "Online"

    def to_dict(self, total_lan_bytes: int = 0) -> Dict[str, Any]:
        bw_pct = 0.0
        if total_lan_bytes > 0:
            bw_pct = round((self.total_bytes / total_lan_bytes) * 100, 1)

        risk_level = "Low"
        if not self.is_trusted or self.anomaly_count >= 3:
            risk_level = "High"
        elif self.anomaly_count > 0:
            risk_level = "Medium"

        return {
            "ip": self.ip,
            "mac": self.mac or "--:--:--:--:--:--",
            "hostname": self.hostname or "",
            "custom_name": self.custom_name or "",
            "display_name": self.display_name,
            "vendor": self.vendor,
            "device_type": self.device_type,
            "is_trusted": self.is_trusted,
            "status": self.status,
            "risk_level": risk_level,
            "anomaly_count": self.anomaly_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "packets_in": self.packets_in,
            "packets_out": self.packets_out,
            "total_packets": self.total_packets,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "total_bytes": self.total_bytes,
            "bandwidth_pct": bw_pct,
            "top_protocols": [p for p, _ in self.protocols.most_common(4)],
            "top_ports": [pt for pt, _ in self.ports.most_common(4)],
            "notes": self.notes,
            "is_demo": self.is_demo,
        }


# ─── Network Member Manager ─────────────────────────────────────────────────

class NetworkMemberManager:
    """
    Central engine tracking, discovering, and cataloging all active network members.
    Thread-safe and supports both live packet streams and demo mode.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._members: Dict[str, NetworkMember] = {}  # Key: IP address
        self._mac_to_ip: Dict[str, str] = {}
        self._is_scanning = False
        self._scan_progress = 0
        self._scan_message = ""
        self._init_db_table()
        self._load_saved_members()

    def _init_db_table(self):
        """Ensure network_members table exists in SQLite database."""
        try:
            conn = db.get_connection()
            try:
                cur = conn.cursor()
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
            finally:
                conn.close()
        except Exception as e:
            logger.warning("Could not initialize network_members SQLite table: %s", e)

    def _load_saved_members(self):
        """Load known members from database into memory."""
        try:
            conn = db.get_connection()
            try:
                cur = conn.cursor()
                rows = cur.execute("SELECT * FROM network_members WHERE is_demo = 0").fetchall()
                with self._lock:
                    for r in rows:
                        m = NetworkMember(
                            ip=r["ip"],
                            mac=r["mac"],
                            hostname=r["hostname"],
                            custom_name=r["custom_name"],
                            vendor=r["vendor"],
                            device_type=r["device_type"],
                            is_trusted=bool(r["is_trusted"]),
                            first_seen=r["first_seen"],
                            last_seen=r["last_seen"],
                            packets_in=r["packets_in"],
                            packets_out=r["packets_out"],
                            bytes_in=r["bytes_in"],
                            bytes_out=r["bytes_out"],
                            notes=r["notes"] or "",
                            is_demo=False,
                        )
                        self._members[m.ip] = m
                        if m.mac:
                            self._mac_to_ip[m.mac] = m.ip
            finally:
                conn.close()
        except Exception as e:
            logger.debug("Failed to load saved network members from DB: %s", e)

    def save_member_to_db(self, member: NetworkMember):
        """Persist or update a member in SQLite database."""
        if member.is_demo:
            return
        try:
            conn = db.get_connection()
            try:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO network_members (
                        ip, mac, hostname, custom_name, vendor, device_type,
                        is_trusted, first_seen, last_seen, packets_in, packets_out,
                        bytes_in, bytes_out, notes, is_demo
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        mac=excluded.mac,
                        hostname=coalesce(excluded.hostname, network_members.hostname),
                        custom_name=coalesce(excluded.custom_name, network_members.custom_name),
                        vendor=coalesce(excluded.vendor, network_members.vendor),
                        device_type=coalesce(excluded.device_type, network_members.device_type),
                        is_trusted=excluded.is_trusted,
                        last_seen=excluded.last_seen,
                        packets_in=excluded.packets_in,
                        packets_out=excluded.packets_out,
                        bytes_in=excluded.bytes_in,
                        bytes_out=excluded.bytes_out,
                        notes=coalesce(excluded.notes, network_members.notes)
                """, (
                    member.ip, member.mac, member.hostname, member.custom_name,
                    member.vendor, member.device_type, 1 if member.is_trusted else 0,
                    member.first_seen, member.last_seen, member.packets_in,
                    member.packets_out, member.bytes_in, member.bytes_out,
                    member.notes, 0
                ))
                conn.commit()
            finally:
                conn.close()
        except Exception as e:
            logger.debug("DB save_member error: %s", e)

    # ── Ingest Packet ─────────────────────────────────────────────────────────

    def feed(self, pkt: dict):
        """
        Process a captured packet.
        Updates or discovers LAN member hosts based on src/dst IPs and MACs.
        """
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        src_mac = pkt.get("src_mac")
        dst_mac = pkt.get("dst_mac")
        size = int(pkt.get("length") or 0)
        proto = (pkt.get("protocol") or "OTHER").upper()
        dst_port = pkt.get("dst_port")
        is_demo = bool(pkt.get("is_demo", False))
        ts = pkt.get("timestamp") or datetime.now(tz=timezone.utc).isoformat()

        # Update Source Member (if local network IP)
        if src_ip and is_lan_ip(src_ip):
            self._touch_member(
                ip=src_ip,
                mac=src_mac,
                is_out=True,
                size=size,
                proto=proto,
                port=dst_port,
                is_demo=is_demo,
                ts=ts,
            )

        # Update Destination Member (if local network IP)
        if dst_ip and is_lan_ip(dst_ip):
            self._touch_member(
                ip=dst_ip,
                mac=dst_mac,
                is_out=False,
                size=size,
                proto=proto,
                port=dst_port,
                is_demo=is_demo,
                ts=ts,
            )

    def _touch_member(
        self,
        ip: str,
        mac: Optional[str],
        is_out: bool,
        size: int,
        proto: str,
        port: Optional[int],
        is_demo: bool,
        ts: str,
    ):
        norm_mac = normalize_mac(mac)
        with self._lock:
            member = self._members.get(ip)
            if not member:
                vendor = resolve_vendor(norm_mac)
                dev_type = classify_device(ip, vendor)
                member = NetworkMember(
                    ip=ip,
                    mac=norm_mac,
                    vendor=vendor,
                    device_type=dev_type,
                    first_seen=ts,
                    last_seen=ts,
                    is_demo=is_demo,
                )
                self._members[ip] = member
                if norm_mac:
                    self._mac_to_ip[norm_mac] = ip

                # Resolve hostname asynchronously if live
                if not is_demo and not member.hostname:
                    threading.Thread(
                        target=self._resolve_hostname_bg,
                        args=(ip,),
                        daemon=True,
                    ).start()
            else:
                member.last_seen = ts
                if norm_mac and not member.mac:
                    member.mac = norm_mac
                    self._mac_to_ip[norm_mac] = ip
                    if member.vendor in ("Unknown Vendor", "Generic Device / Private MAC"):
                        member.vendor = resolve_vendor(norm_mac)
                        member.device_type = classify_device(ip, member.vendor, member.hostname)

            if is_out:
                member.packets_out += 1
                member.bytes_out += size
            else:
                member.packets_in += 1
                member.bytes_in += size

            if proto:
                member.protocols[proto] += 1
            if port:
                try:
                    member.ports[int(port)] += 1
                except (ValueError, TypeError):
                    pass

    def _resolve_hostname_bg(self, ip: str):
        """Resolve IP hostname in background without blocking capture."""
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            if name:
                with self._lock:
                    if ip in self._members:
                        m = self._members[ip]
                        m.hostname = name
                        m.device_type = classify_device(ip, m.vendor, name)
                        self.save_member_to_db(m)
        except Exception:
            pass

    def record_anomaly_for_member(self, ip: str):
        """Increment anomaly risk counter when detector flags traffic from/to this member."""
        with self._lock:
            if ip in self._members:
                self._members[ip].anomaly_count += 1

    # ── Demo Data Generation ──────────────────────────────────────────────────

    def ensure_demo_members(self):
        """Populate realistic, rich simulated network members for demo mode."""
        with self._lock:
            # Check if demo members already populated
            if any(m.is_demo for m in self._members.values()):
                return

            now = datetime.now(tz=timezone.utc)
            simulated = [
                {
                    "ip": "192.168.1.1",
                    "mac": "00:25:86:11:22:33",
                    "hostname": "gateway.home.arpa",
                    "custom_name": "Main Router & Gateway",
                    "vendor": "TP-Link Technologies",
                    "device_type": "Gateway",
                    "is_trusted": True,
                    "packets_in": 1420,
                    "packets_out": 1980,
                    "bytes_in": 1845000,
                    "bytes_out": 2490000,
                    "protocols": {"TCP": 1800, "UDP": 900, "DNS": 500, "ICMP": 200},
                    "ports": [80, 443, 53],
                    "notes": "Primary WiFi 6 gateway",
                },
                {
                    "ip": "192.168.1.10",
                    "mac": "F0:18:98:4B:29:1A",
                    "hostname": "haris-macbook-pro.local",
                    "custom_name": "Hari's MacBook Pro",
                    "vendor": "Apple, Inc.",
                    "device_type": "Workstation",
                    "is_trusted": True,
                    "packets_in": 980,
                    "packets_out": 850,
                    "bytes_in": 1250000,
                    "bytes_out": 980000,
                    "protocols": {"TCP": 1200, "UDP": 450, "DNS": 180},
                    "ports": [443, 80, 22],
                    "notes": "Developer workstation",
                },
                {
                    "ip": "192.168.1.20",
                    "mac": "F4:F5:D8:1A:BC:33",
                    "hostname": "pixel-8-pro.lan",
                    "custom_name": "Google Pixel 8",
                    "vendor": "Google Pixel",
                    "device_type": "Mobile",
                    "is_trusted": True,
                    "packets_in": 420,
                    "packets_out": 310,
                    "bytes_in": 450000,
                    "bytes_out": 180000,
                    "protocols": {"TCP": 480, "UDP": 200, "DNS": 50},
                    "ports": [443, 853],
                    "notes": "Personal mobile device",
                },
                {
                    "ip": "192.168.1.30",
                    "mac": "34:FC:B9:77:88:99",
                    "hostname": "lg-oled-tv.lan",
                    "custom_name": "Living Room OLED TV",
                    "vendor": "LG Smart TV",
                    "device_type": "Smart TV",
                    "is_trusted": True,
                    "packets_in": 890,
                    "packets_out": 240,
                    "bytes_in": 3120000,
                    "bytes_out": 85000,
                    "protocols": {"TCP": 800, "UDP": 300, "DNS": 30},
                    "ports": [443, 8008, 1900],
                    "notes": "Streaming 4K media",
                },
                {
                    "ip": "192.168.1.50",
                    "mac": "E4:5F:01:44:55:66",
                    "hostname": "home-assistant.local",
                    "custom_name": "Home Assistant Server",
                    "vendor": "Raspberry Pi Trading",
                    "device_type": "Server",
                    "is_trusted": True,
                    "packets_in": 630,
                    "packets_out": 590,
                    "bytes_in": 410000,
                    "bytes_out": 395000,
                    "protocols": {"TCP": 850, "UDP": 320, "DNS": 50},
                    "ports": [8123, 1883, 22],
                    "notes": "Home automation broker",
                },
                {
                    "ip": "192.168.1.88",
                    "mac": "24:0A:C4:9A:88:12",
                    "hostname": "esp32-living-room.lan",
                    "custom_name": "Living Room Temp Sensor",
                    "vendor": "Espressif Systems",
                    "device_type": "IoT",
                    "is_trusted": True,
                    "packets_in": 85,
                    "packets_out": 120,
                    "bytes_in": 12400,
                    "bytes_out": 24800,
                    "protocols": {"TCP": 140, "UDP": 65},
                    "ports": [1883],
                    "notes": "MQTT telemetry sensor",
                },
                {
                    "ip": "192.168.1.200",
                    "mac": "08:00:27:DD:EE:FF",
                    "hostname": "kali-recon-box.lan",
                    "custom_name": "Unknown Security Scanner",
                    "vendor": "Oracle VirtualBox",
                    "device_type": "Suspicious",
                    "is_trusted": False,
                    "packets_in": 150,
                    "packets_out": 1450,
                    "bytes_in": 9800,
                    "bytes_out": 87000,
                    "protocols": {"TCP": 1400, "ICMP": 200},
                    "ports": [21, 22, 23, 80, 443, 3389, 8080],
                    "notes": "Flagged: Generating rapid TCP SYN sweeps across subnet",
                },
            ]

            for s in simulated:
                m = NetworkMember(
                    ip=s["ip"],
                    mac=s["mac"],
                    hostname=s["hostname"],
                    custom_name=s["custom_name"],
                    vendor=s["vendor"],
                    device_type=s["device_type"],
                    is_trusted=s["is_trusted"],
                    first_seen=now.isoformat(),
                    last_seen=now.isoformat(),
                    packets_in=s["packets_in"],
                    packets_out=s["packets_out"],
                    bytes_in=s["bytes_in"],
                    bytes_out=s["bytes_out"],
                    notes=s["notes"],
                    is_demo=True,
                )
                for proto, cnt in s["protocols"].items():
                    m.protocols[proto] = cnt
                for p in s["ports"]:
                    m.ports[p] = 20
                if not s["is_trusted"]:
                    m.anomaly_count = 3

                self._members[m.ip] = m
                if m.mac:
                    self._mac_to_ip[m.mac] = m.ip

    # ── Subnet Scanning ───────────────────────────────────────────────────────

    def start_subnet_scan(self, interface: Optional[str] = None) -> Dict[str, Any]:
        """
        Trigger an asynchronous local subnet ARP/Ping sweep to discover all silent members.
        """
        with self._lock:
            if self._is_scanning:
                return {"status": "busy", "message": "Scan already in progress."}
            self._is_scanning = True
            self._scan_progress = 0
            self._scan_message = "Initializing network sweep..."

        threading.Thread(
            target=self._run_subnet_sweep,
            args=(interface,),
            daemon=True
        ).start()

        return {"status": "started", "message": "Subnet discovery sweep initiated."}

    def _run_subnet_sweep(self, interface: Optional[str]):
        """Background thread executing fast, safe subnet discovery."""
        try:
            # 1. Determine local subnet base
            local_ip = "192.168.1.100"
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(0.5)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
            except Exception:
                pass

            ip_parts = local_ip.split(".")
            subnet_prefix = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}."

            # Fast ping / connect check on likely active IPs
            targets = [f"{subnet_prefix}{i}" for i in range(1, 255)]
            total = len(targets)
            found_count = 0

            # Scan in chunks of 25 parallel threads
            chunk_size = 25
            for idx in range(0, total, chunk_size):
                chunk = targets[idx:idx+chunk_size]
                threads = []

                def check_host(host_ip):
                    nonlocal found_count
                    try:
                        # Attempt quick TCP handshake on port 80 or 445 or 53
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.2)
                        res = sock.connect_ex((host_ip, 80))
                        if res != 0:
                            res = sock.connect_ex((host_ip, 445))
                        if res != 0:
                            res = sock.connect_ex((host_ip, 53))
                        sock.close()
                        if res == 0:
                            found_count += 1
                            self._touch_member(
                                ip=host_ip,
                                mac=None,
                                is_out=False,
                                size=64,
                                proto="TCP",
                                port=80,
                                is_demo=False,
                                ts=datetime.now(tz=timezone.utc).isoformat(),
                            )
                    except Exception:
                        pass

                for host in chunk:
                    t = threading.Thread(target=check_host, args=(host,))
                    threads.append(t)
                    t.start()

                for t in threads:
                    t.join(timeout=0.4)

                with self._lock:
                    self._scan_progress = int(((idx + len(chunk)) / total) * 100)
                    self._scan_message = f"Scanned {idx + len(chunk)}/{total} hosts... Discovered {found_count} active."

            with self._lock:
                self._is_scanning = False
                self._scan_progress = 100
                self._scan_message = f"Scan complete! Discovered {found_count} active network members."

        except Exception as e:
            logger.warning("Subnet scan exception: %s", e)
            with self._lock:
                self._is_scanning = False
                self._scan_progress = 100
                self._scan_message = f"Scan stopped: {e}"

    # ── Queries & CRUD ────────────────────────────────────────────────────────

    def get_scan_status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "is_scanning": self._is_scanning,
                "progress": self._scan_progress,
                "message": self._scan_message,
            }

    def get_members(
        self,
        filter_type: Optional[str] = None,
        filter_status: Optional[str] = None,
        search: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return list of discovered members with enriched analytics."""
        with self._lock:
            total_lan_bytes = sum(m.total_bytes for m in self._members.values())
            res = []

            for m in self._members.values():
                d = m.to_dict(total_lan_bytes)

                # Filter by device type
                if filter_type and filter_type.lower() != "all":
                    if d["device_type"].lower() != filter_type.lower():
                        continue

                # Filter by online status
                if filter_status and filter_status.lower() != "all":
                    if d["status"].lower() != filter_status.lower():
                        continue

                # Search filter
                if search:
                    s = search.lower()
                    haystack = f"{d['ip']} {d['mac']} {d['display_name']} {d['vendor']} {d['device_type']} {d['hostname']}".lower()
                    if s not in haystack:
                        continue

                res.append(d)

            # Sort: Gateways first, then highest traffic, then IP
            def sort_key(item):
                is_gw = 0 if item["device_type"] == "Gateway" else 1
                return (is_gw, -item["total_bytes"], item["ip"])

            res.sort(key=sort_key)
            return res

    def get_member_by_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            m = self._members.get(ip)
            if not m:
                return None
            total_lan_bytes = sum(mb.total_bytes for mb in self._members.values())
            return m.to_dict(total_lan_bytes)

    def get_stats(self) -> Dict[str, Any]:
        """High-level overview metrics for the Network Members dashboard."""
        with self._lock:
            members = list(self._members.values())
            total = len(members)
            online = sum(1 for m in members if m.status == "Online")
            idle = sum(1 for m in members if m.status == "Idle")
            offline = sum(1 for m in members if m.status == "Offline")
            suspicious = sum(1 for m in members if not m.is_trusted or m.device_type == "Suspicious" or m.anomaly_count > 0)
            total_bytes = sum(m.total_bytes for m in members)
            total_packets = sum(m.total_packets for m in members)

            type_counts = Counter(m.device_type for m in members)
            vendor_counts = Counter(m.vendor for m in members if m.vendor != "Unknown Vendor")

            return {
                "total_members": total,
                "online_members": online,
                "idle_members": idle,
                "offline_members": offline,
                "suspicious_members": suspicious,
                "total_lan_bytes": total_bytes,
                "total_lan_packets": total_packets,
                "type_breakdown": dict(type_counts),
                "top_vendors": [{"vendor": v, "count": c} for v, c in vendor_counts.most_common(5)],
            }

    def update_member(
        self,
        ip: str,
        custom_name: Optional[str] = None,
        is_trusted: Optional[bool] = None,
        device_type: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> bool:
        """Update customized member attributes."""
        with self._lock:
            m = self._members.get(ip)
            if not m:
                return False

            if custom_name is not None:
                m.custom_name = custom_name.strip()
            if is_trusted is not None:
                m.is_trusted = bool(is_trusted)
            if device_type is not None and device_type.strip():
                m.device_type = device_type.strip()
            if notes is not None:
                m.notes = notes.strip()

            self.save_member_to_db(m)
            return True

    def clear(self):
        """Clear all in-memory member records."""
        with self._lock:
            self._members.clear()
            self._mac_to_ip.clear()


# Global singleton instance
member_manager = NetworkMemberManager()

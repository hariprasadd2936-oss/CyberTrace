"""
packet_parser.py — Packet header parsing and protocol identification.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

import sys

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

# Try to import Scapy; graceful fallback if not available
try:
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.packet import Packet as ScapyPacket
    try:
        from scapy.layers.inet6 import IPv6
        IPV6_AVAILABLE = True
    except ImportError:
        IPV6_AVAILABLE = False
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    IPV6_AVAILABLE = False
    logger.warning("Scapy not available — parser will only handle demo dicts.")


def parse_packet(pkt, packet_id: int = 0, is_demo: bool = False) -> Optional[dict]:
    """
    Parse a Scapy packet (or a pre-built dict for demo mode) into a
    flat dictionary ready for JSON serialisation and storage.

    Returns None if the packet is not parseable.
    """
    if is_demo and isinstance(pkt, dict):
        return pkt  # Already parsed demo packet

    if not SCAPY_AVAILABLE:
        return None

    try:
        return _parse_scapy_packet(pkt, packet_id)
    except Exception as exc:
        logger.debug("Failed to parse packet %d: %s", packet_id, exc)
        return None


def _parse_scapy_packet(pkt: "ScapyPacket", packet_id: int) -> dict:
    """Internal: convert a Scapy packet to a dict with complete metadata."""
    ts = getattr(pkt, "time", None)
    if ts is not None:
        try:
            timestamp = datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
        except Exception:
            timestamp = datetime.now(tz=timezone.utc).isoformat()
    else:
        timestamp = datetime.now(tz=timezone.utc).isoformat()

    # Extract MAC addresses when Ether layer is present
    src_mac = None
    dst_mac = None
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        src_mac = getattr(eth, "src", None)
        dst_mac = getattr(eth, "dst", None)

    pkt_len = 0
    try:
        pkt_len = len(pkt)
    except Exception:
        pkt_len = 0

    raw_summary = ""
    try:
        raw_summary = pkt.summary() if hasattr(pkt, "summary") else ""
    except Exception:
        raw_summary = pkt.__class__.__name__

    result = {
        "id":           packet_id,
        "timestamp":    timestamp,
        "length":       pkt_len,
        "protocol":     "OTHER",
        "src_ip":       None,
        "dst_ip":       None,
        "src_port":     None,
        "dst_port":     None,
        "src_mac":      src_mac,
        "dst_mac":      dst_mac,
        "tcp_flags":    None,
        "icmp_type":    None,
        "icmp_code":    None,
        "dns_query":    None,
        "dns_type":     None,
        "arp_op":       None,
        "info":         "",
        "is_demo":      False,
        "raw_summary":  raw_summary,
    }

    # ── ARP ──────────────────────────────────────────────────────────────
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        result["protocol"] = "ARP"
        result["src_ip"]   = getattr(arp, "psrc", None)
        result["dst_ip"]   = getattr(arp, "pdst", None)
        try:
            result["src_mac"] = getattr(arp, "hwsrc", src_mac)
        except Exception:
            result["src_mac"] = src_mac
        try:
            result["dst_mac"] = getattr(arp, "hwdst", dst_mac)
        except Exception:
            result["dst_mac"] = dst_mac
        op_map = {1: "Who has?", 2: "Is at"}
        op_name = op_map.get(getattr(arp, "op", 1), f"Op {getattr(arp, 'op', 1)}")
        result["arp_op"]   = op_name
        result["info"]     = f"ARP {op_name}"
        return result

    # ── IPv4 ─────────────────────────────────────────────────────────────
    if pkt.haslayer(IP):
        ip = pkt[IP]
        result["src_ip"] = ip.src
        result["dst_ip"] = ip.dst

        # ── ICMP ─────────────────────────────────────────────────────────
        if pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            result["protocol"]  = "ICMP"
            result["icmp_type"] = getattr(icmp, "type", None)
            result["icmp_code"] = getattr(icmp, "code", None)
            type_map = {
                0: "Echo Reply",
                3: "Unreachable",
                8: "Echo Request",
                11: "Time Exceeded",
            }
            result["info"] = type_map.get(icmp.type, f"Type {icmp.type}")
            return result

        # ── DNS (UDP or TCP, identified by DNS layer) ───────────────────
        if pkt.haslayer(DNS):
            result["protocol"] = "DNS"
            dns = pkt[DNS]
            try:
                if pkt.haslayer(UDP):
                    result["src_port"] = pkt[UDP].sport
                    result["dst_port"] = pkt[UDP].dport
                elif pkt.haslayer(TCP):
                    result["src_port"] = pkt[TCP].sport
                    result["dst_port"] = pkt[TCP].dport
                qname = ""
                if pkt.haslayer(DNSQR):
                    qn = pkt[DNSQR].qname
                    qname = qn.decode(errors="replace") if isinstance(qn, bytes) else str(qn or "")
                    result["dns_query"] = qname.rstrip(".")
                qr_val = getattr(dns, "qr", 0)
                qr_desc = "Response" if qr_val == 1 else "Query"
                result["dns_type"] = qr_desc
                result["info"] = f"DNS {qr_desc} {qname}".strip()
            except Exception:
                result["info"] = "DNS packet"
            return result

        # ── TCP ───────────────────────────────────────────────────────────
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            result["protocol"]  = "TCP"
            result["src_port"]  = tcp.sport
            result["dst_port"]  = tcp.dport
            result["tcp_flags"] = _tcp_flags_str(tcp.flags)
            result["info"]      = f"TCP {result['tcp_flags']} {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}"
            return result

        # ── UDP ───────────────────────────────────────────────────────────
        if pkt.haslayer(UDP):
            udp = pkt[UDP]
            result["protocol"] = "UDP"
            result["src_port"] = udp.sport
            result["dst_port"] = udp.dport
            result["info"]     = f"UDP {ip.src}:{udp.sport} -> {ip.dst}:{udp.dport}"
            return result

        result["protocol"] = f"IP/{ip.proto}"
        result["info"]     = f"IP proto {ip.proto}"
        return result

    # ── IPv6 ─────────────────────────────────────────────────────────────
    if IPV6_AVAILABLE and pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        result["src_ip"] = ip6.src
        result["dst_ip"] = ip6.dst

        if pkt.haslayer(DNS):
            result["protocol"] = "DNS"
            dns = pkt[DNS]
            try:
                if pkt.haslayer(UDP):
                    result["src_port"] = pkt[UDP].sport
                    result["dst_port"] = pkt[UDP].dport
                elif pkt.haslayer(TCP):
                    result["src_port"] = pkt[TCP].sport
                    result["dst_port"] = pkt[TCP].dport
                qname = ""
                if pkt.haslayer(DNSQR):
                    qn = pkt[DNSQR].qname
                    qname = qn.decode(errors="replace") if isinstance(qn, bytes) else str(qn or "")
                    result["dns_query"] = qname.rstrip(".")
                qr_val = getattr(dns, "qr", 0)
                qr_desc = "Response" if qr_val == 1 else "Query"
                result["dns_type"] = qr_desc
                result["info"] = f"DNS {qr_desc} {qname}".strip()
            except Exception:
                result["info"] = "DNS packet"
            return result

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            result["protocol"]  = "TCP"
            result["src_port"]  = tcp.sport
            result["dst_port"]  = tcp.dport
            result["tcp_flags"] = _tcp_flags_str(tcp.flags)
            result["info"]      = f"TCP {result['tcp_flags']} [{ip6.src}]:{tcp.sport} -> [{ip6.dst}]:{tcp.dport}"
            return result

        if pkt.haslayer(UDP):
            udp = pkt[UDP]
            result["protocol"] = "UDP"
            result["src_port"] = udp.sport
            result["dst_port"] = udp.dport
            result["info"]     = f"UDP [{ip6.src}]:{udp.sport} -> [{ip6.dst}]:{udp.dport}"
            return result

        result["protocol"] = "IPv6"
        result["info"]     = f"IPv6 proto {ip6.nh}"
        return result

    # ── Ethernet only ─────────────────────────────────────────────────────
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        result["protocol"] = "ETHER"
        result["info"]     = f"Ethernet {eth.src} -> {eth.dst}"
        return result

    return result


def _tcp_flags_str(flags) -> str:
    """Convert integer/flag-object TCP flags to a readable string like 'SYN', 'SYN-ACK'."""
    flag_names = {
        0x001: "FIN",
        0x002: "SYN",
        0x004: "RST",
        0x008: "PSH",
        0x010: "ACK",
        0x020: "URG",
        0x040: "ECE",
        0x080: "CWR",
    }
    try:
        val = int(flags)
    except (TypeError, ValueError):
        return str(flags)
    parts = [name for bit, name in flag_names.items() if val & bit]
    return "-".join(parts) if parts else "NONE"


# ─────────────────────────────────────────────────────────────────────────────
#  Interface helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_interfaces() -> list[dict]:
    """
    Dynamically discover all available network interfaces from Scapy / OS.
    Never hardcodes interface IDs.
    Returns list of dicts with:
      - name: system interface identifier (used for capture)
      - display_name: user-friendly label
      - description: adapter description
      - ip / ipv4: IPv4 address
      - ipv6: IPv6 address
      - mac: hardware MAC address
      - available: bool (up and ready for capture)
    """
    interfaces: list[dict] = []
    seen_names = set()

    # 1. Gather from psutil (instant, cross-platform native Win32/POSIX API)
    try:
        import psutil
        import socket as _sock
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()

        for iface_name, snic_list in addrs.items():
            ipv4 = ""
            ipv6 = ""
            mac = ""
            is_up = stats[iface_name].isup if iface_name in stats else True

            for snic in snic_list:
                fam = snic.family
                if fam == _sock.AF_INET:
                    ipv4 = snic.address
                elif getattr(fam, "name", "") in ("AF_INET6", "AF_INET6") or fam == 23:
                    addr = snic.address.split("%")[0]
                    if not ipv6 and not addr.startswith("fe80"):
                        ipv6 = addr
                    elif not ipv6:
                        ipv6 = addr
                elif getattr(fam, "name", "") in ("AF_LINK", "AF_PACKET") or fam == -1:
                    mac = snic.address

            display_name = iface_name
            if ipv4:
                display_name += f" • {ipv4}"

            interfaces.append({
                "name":         iface_name,
                "display_name": display_name,
                "description":  iface_name,
                "ip":           ipv4,
                "ipv4":         ipv4,
                "ipv6":         ipv6,
                "mac":          mac,
                "available":    is_up,
            })
            seen_names.add(iface_name)


        if interfaces:
            # Sort: Active & connected interfaces with IP first, then UP, then others
            interfaces.sort(
                key=lambda x: (
                    not (x["available"] and bool(x["ip"]) and not x["ip"].startswith("169.254")),
                    not x["available"],
                    x["name"].startswith("Loopback") or x["name"] == "lo",
                    x["name"],
                )
            )
            return interfaces
    except Exception as exc:
        logger.debug("psutil interface detection error: %s", exc)

    # 3. Fallback: netifaces
    try:
        import netifaces
        for iface_name in netifaces.interfaces():
            if iface_name in seen_names:
                continue
            addrs = netifaces.ifaddresses(iface_name)
            ipv4 = addrs.get(netifaces.AF_INET, [{}])[0].get("addr", "")
            ipv6 = addrs.get(netifaces.AF_INET6, [{}])[0].get("addr", "")
            mac  = addrs.get(netifaces.AF_LINK, [{}])[0].get("addr", "")
            display_name = f"{iface_name} — {ipv4}" if ipv4 else iface_name
            interfaces.append({
                "name":         iface_name,
                "display_name": display_name,
                "description":  "",
                "ip":           ipv4,
                "ipv4":         ipv4,
                "ipv6":         ipv6,
                "mac":          mac,
                "available":    True,
            })
            seen_names.add(iface_name)
        if interfaces:
            return interfaces
    except Exception:
        pass

    # 4. Fallback: Scapy conf.ifaces directly
    if SCAPY_AVAILABLE:
        try:
            from scapy.all import conf as _sconf
            for dev_key, ifc in _sconf.ifaces.items():
                name = getattr(ifc, "name", "") or dev_key
                if name in seen_names:
                    continue
                ip = getattr(ifc, "ip", "") or ""
                desc = getattr(ifc, "description", "") or ""
                mac = getattr(ifc, "mac", "") or ""
                display_name = f"{name} ({desc})" if desc else name
                if ip:
                    display_name += f" — {ip}"
                interfaces.append({
                    "name":         name,
                    "display_name": display_name,
                    "description":  desc,
                    "ip":           str(ip),
                    "ipv4":         str(ip),
                    "ipv6":         "",
                    "mac":          mac,
                    "available":    True,
                })
                seen_names.add(name)
            if interfaces:
                return interfaces
        except Exception:
            pass

    # 5. Absolute fallback
    import socket
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
    except Exception:
        ip = "127.0.0.1"
    return [
        {"name": "lo", "display_name": "lo (127.0.0.1)", "description": "Loopback", "ip": "127.0.0.1", "ipv4": "127.0.0.1", "ipv6": "::1", "mac": "", "available": True},
        {"name": "eth0", "display_name": f"eth0 ({ip})", "description": "Ethernet", "ip": ip, "ipv4": ip, "ipv6": "", "mac": "", "available": True},
    ]

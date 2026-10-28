"""
demo_data.py — Synthetic demo packet dataset for testing without root/live capture.
All packets are clearly labeled is_demo=True.
"""

from __future__ import annotations

import random
from datetime import datetime, timezone, timedelta

import config

DEMO_IPS = [
    "192.168.1.10", "192.168.1.20", "192.168.1.30", "192.168.1.1",
    "10.0.0.5", "10.0.0.10", "172.16.0.1",
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "93.184.216.34",
    "104.26.10.12", "185.199.108.153", "151.101.193.69",
    "185.220.101.5", "142.250.190.46", "13.107.42.14", "52.95.120.67",
]
COMMON_PORTS = [80, 443, 53, 22, 21, 25, 110, 143, 3306, 5432,
                8080, 8443, 3389, 137, 138, 139, 445]
EPHEMERAL    = list(range(49152, 49200))

PROTOCOLS = ["TCP", "UDP", "ICMP", "DNS", "ARP"]
PROTO_WEIGHTS = [0.40, 0.25, 0.10, 0.15, 0.10]

TCP_FLAG_COMBOS = ["SYN", "SYN-ACK", "ACK", "PSH-ACK", "FIN-ACK", "RST"]


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def generate_demo_packets(n: int = config.DEMO_PACKET_COUNT) -> list[dict]:
    """Return a list of synthetic packet dicts."""
    packets = []
    start = datetime.now(tz=timezone.utc) - timedelta(minutes=10)

    for i in range(n):
        dt = start + timedelta(seconds=i * (600 / n))
        proto = random.choices(PROTOCOLS, PROTO_WEIGHTS)[0]

        src_ip = random.choice(DEMO_IPS)
        dst_ip = random.choice([ip for ip in DEMO_IPS if ip != src_ip])
        length = random.randint(40, 1500)

        pkt: dict = {
            "id":         i + 1,
            "timestamp":  _iso(dt),
            "length":     length,
            "protocol":   proto,
            "src_ip":     src_ip,
            "dst_ip":     dst_ip,
            "src_port":   None,
            "dst_port":   None,
            "tcp_flags":  None,
            "info":       "",
            "is_demo":    True,
            "raw_summary": "",
        }

        if proto == "TCP":
            sport = random.choice(EPHEMERAL)
            dport = random.choice(COMMON_PORTS)
            flags = random.choice(TCP_FLAG_COMBOS)
            pkt.update(src_port=sport, dst_port=dport, tcp_flags=flags,
                       info=f"TCP {flags} {src_ip}:{sport} → {dst_ip}:{dport}")
        elif proto == "UDP":
            sport = random.choice(EPHEMERAL)
            dport = random.choice([53, 67, 68, 123, 161, 5353])
            pkt.update(src_port=sport, dst_port=dport,
                       info=f"UDP {src_ip}:{sport} → {dst_ip}:{dport}")
        elif proto == "ICMP":
            icmp_type = random.choice(["Echo Request", "Echo Reply", "Unreachable"])
            pkt.update(info=f"ICMP {icmp_type} {src_ip} → {dst_ip}", length=random.randint(28, 84))
        elif proto == "DNS":
            domain = random.choice(["example.com", "google.com", "github.com",
                                    "cloudflare.com", "microsoft.com"])
            qtype  = random.choice(["Query", "Response"])
            pkt.update(src_port=random.choice(EPHEMERAL), dst_port=53,
                       info=f"DNS {qtype} {domain}", length=random.randint(50, 300))
        elif proto == "ARP":
            arp_type = random.choice(["Who has?", "Is at"])
            pkt.update(info=f"ARP {arp_type} {dst_ip}", length=60)

        packets.append(pkt)

    # Inject anomaly patterns so detection rules can be demonstrated
    _inject_port_scan(packets, start)
    _inject_syn_burst(packets, start)
    _inject_host_scan(packets, start)

    return packets


def _inject_port_scan(packets: list, start: datetime):
    """Inject a port scan pattern from a single source."""
    attacker = "10.10.10.99"
    victim   = "192.168.1.30"
    base_ts  = start + timedelta(minutes=5)
    for port in range(20, 20 + config.PORT_SCAN_THRESHOLD + 5):
        dt = base_ts + timedelta(milliseconds=port * 50)
        packets.append({
            "id": len(packets) + 1,
            "timestamp": _iso(dt),
            "length": 60,
            "protocol": "TCP",
            "src_ip": attacker,
            "dst_ip": victim,
            "src_port": 54321,
            "dst_port": port,
            "tcp_flags": "SYN",
            "info": f"TCP SYN {attacker}:54321 → {victim}:{port}",
            "is_demo": True,
            "raw_summary": "",
        })


def _inject_syn_burst(packets: list, start: datetime):
    """Inject repeated SYN packets (SYN-flood-like) to the same target."""
    attacker = "10.10.10.88"
    victim   = "192.168.1.20"
    base_ts  = start + timedelta(minutes=7)
    for j in range(config.SYN_FLOOD_THRESHOLD + 10):
        dt = base_ts + timedelta(milliseconds=j * 30)
        packets.append({
            "id": len(packets) + 1,
            "timestamp": _iso(dt),
            "length": 60,
            "protocol": "TCP",
            "src_ip": attacker,
            "dst_ip": victim,
            "src_port": random.randint(40000, 65000),
            "dst_port": 80,
            "tcp_flags": "SYN",
            "info": f"TCP SYN {attacker} → {victim}:80",
            "is_demo": True,
            "raw_summary": "",
        })


def _inject_host_scan(packets: list, start: datetime):
    """Inject host scan pattern from a single source."""
    attacker = "10.10.10.77"
    base_ts  = start + timedelta(minutes=3)
    victims  = [f"192.168.1.{i}" for i in range(1, config.HOST_SCAN_THRESHOLD + 5)]
    for k, victim in enumerate(victims):
        dt = base_ts + timedelta(milliseconds=k * 200)
        packets.append({
            "id": len(packets) + 1,
            "timestamp": _iso(dt),
            "length": 60,
            "protocol": "TCP",
            "src_ip": attacker,
            "dst_ip": victim,
            "src_port": 54321,
            "dst_port": 80,
            "tcp_flags": "SYN",
            "info": f"TCP SYN {attacker} → {victim}:80",
            "is_demo": True,
            "raw_summary": "",
        })

"""
threat_intel.py — GeoIP Location & Threat Intelligence Engine for CyberTrace.
Provides IP geolocation, ASN/ISP lookup, and threat reputation scoring.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import threading
import time
import urllib.request
import urllib.error
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)

# ─── Known Scanner & Datacenter Indicators ───────────────────────────────────
KNOWN_TOR_PREFIXES = (
    "185.220.", "198.98.", "171.25.", "195.176.", "51.15.", "109.70.", "185.100."
)

KNOWN_SCANNER_ASNS = {
    "AS14061": "DigitalOcean",
    "AS16276": "OVH SAS",
    "AS24940": "Hetzner Online",
    "AS20473": "Choopa / Vultr",
    "AS9009":  "M247 Europe",
    "AS51167": "Contabo GmbH",
}

TRUSTED_CDNS = {
    "AS15169": "Google LLC",
    "AS13335": "Cloudflare",
    "AS54113": "Fastly",
    "AS20940": "Akamai",
    "AS8075":  "Microsoft Corporation",
    "AS16509": "Amazon.com",
}

# ─── Country Code to Flag Emoji ──────────────────────────────────────────────
def country_code_to_flag(code: Optional[str]) -> str:
    """Convert 2-letter ISO country code into Unicode flag emoji."""
    if not code or len(code) != 2:
        return "🌐"
    try:
        return "".join(chr(ord(c.upper()) + 127397) for c in code)
    except Exception:
        return "🌐"


class ThreatIntelManager:
    """
    Manages IP Geolocation and Threat Intelligence enrichment with LRU caching
    and asynchronous batch resolution.
    """

    def __init__(self, cache_ttl_seconds: int = 86400):
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._cache_ttl = cache_ttl_seconds
        self._queue: set[str] = set()
        self._worker_thread: Optional[threading.Thread] = None
        self._running = True
        self._start_worker()

    def _start_worker(self):
        self._worker_thread = threading.Thread(target=self._resolution_worker, daemon=True)
        self._worker_thread.start()

    def _is_private_ip(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local or ip.is_multicast
        except ValueError:
            return True

    def lookup(self, ip_str: str) -> Dict[str, Any]:
        """Look up Geolocation and Threat Reputation for an IP address."""
        if not ip_str or not isinstance(ip_str, str):
            return self._empty_result(ip_str)

        clean_ip = ip_str.strip()

        # Check internal cache
        with self._lock:
            cached = self._cache.get(clean_ip)
            if cached:
                return cached

        # Check for Private / Local Network IPs
        if self._is_private_ip(clean_ip):
            res = {
                "ip": clean_ip,
                "is_local": True,
                "country": "Local Network",
                "country_code": "LOC",
                "flag": "🏠",
                "region": "Intranet",
                "city": "Internal LAN",
                "lat": 0.0,
                "lon": 0.0,
                "isp": "Local Subnet / Router",
                "org": "Private RFC1918",
                "asn": "AS0",
                "threat_score": 0,
                "threat_level": "CLEAN",
                "threat_tags": ["Private Network"],
                "cached_at": time.time(),
            }
            with self._lock:
                self._cache[clean_ip] = res
            return res

        # Fast heuristic resolution for known test or common addresses
        heuristic_res = self._heuristic_enrich(clean_ip)
        if heuristic_res:
            with self._lock:
                self._cache[clean_ip] = heuristic_res
            return heuristic_res

        # Enqueue for background online resolution to avoid latency in packet loop
        with self._lock:
            self._queue.add(clean_ip)

        # Return placeholder until background resolution completes
        placeholder = {
            "ip": clean_ip,
            "is_local": False,
            "country": "Resolving...",
            "country_code": "UN",
            "flag": "🌐",
            "region": "Unknown",
            "city": "Unknown",
            "lat": 20.0,
            "lon": 0.0,
            "isp": "Analyzing ISP...",
            "org": "Resolving...",
            "asn": "N/A",
            "threat_score": 10,
            "threat_level": "ANALYZING",
            "threat_tags": ["Lookup Pending"],
            "cached_at": time.time(),
        }
        return placeholder

    def _heuristic_enrich(self, ip_str: str) -> Optional[Dict[str, Any]]:
        """Instant offline fallback & heuristic tagging."""
        # Tor exit nodes simulation / check
        if any(ip_str.startswith(p) for p in KNOWN_TOR_PREFIXES):
            return {
                "ip": ip_str,
                "is_local": False,
                "country": "Tor Network",
                "country_code": "TOR",
                "flag": "🧅",
                "region": "Anonymized",
                "city": "Exit Relay",
                "lat": 52.3702,
                "lon": 4.8952,
                "isp": "Tor Exit Relay",
                "org": "The Tor Project",
                "asn": "AS-TOR",
                "threat_score": 85,
                "threat_level": "HIGH",
                "threat_tags": ["Tor Exit Node", "Anonymizer", "Scanner Source"],
                "cached_at": time.time(),
            }

        # Common public DNS / CDN servers
        if ip_str in ("8.8.8.8", "8.8.4.4"):
            return {
                "ip": ip_str,
                "is_local": False,
                "country": "United States",
                "country_code": "US",
                "flag": "🇺🇸",
                "region": "California",
                "city": "Mountain View",
                "lat": 37.4056,
                "lon": -122.0775,
                "isp": "Google LLC",
                "org": "Google Public DNS",
                "asn": "AS15169",
                "threat_score": 0,
                "threat_level": "CLEAN",
                "threat_tags": ["Trusted Public DNS", "Anycast"],
                "cached_at": time.time(),
            }
        if ip_str in ("1.1.1.1", "1.0.0.1"):
            return {
                "ip": ip_str,
                "is_local": False,
                "country": "Australia",
                "country_code": "AU",
                "flag": "🇦🇺",
                "region": "Queensland",
                "city": "Brisbane",
                "lat": -27.4698,
                "lon": 153.0251,
                "isp": "Cloudflare Inc.",
                "org": "Cloudflare DNS",
                "asn": "AS13335",
                "threat_score": 0,
                "threat_level": "CLEAN",
                "threat_tags": ["Trusted Public DNS", "Anycast"],
                "cached_at": time.time(),
            }

        # Quad9 Public DNS
        if ip_str in ("9.9.9.9", "149.112.112.112"):
            return {
                "ip": ip_str,
                "is_local": False,
                "country": "Switzerland",
                "country_code": "CH",
                "flag": "🇨🇭",
                "region": "Zurich",
                "city": "Zurich",
                "lat": 47.3769,
                "lon": 8.5417,
                "isp": "Quad9",
                "org": "Quad9 Anycast DNS",
                "asn": "AS19281",
                "threat_score": 0,
                "threat_level": "CLEAN",
                "threat_tags": ["Trusted Public DNS", "Malware Blocking"],
                "cached_at": time.time(),
            }

        # OpenDNS / Cisco Umbrella
        if ip_str in ("208.67.222.222", "208.67.220.220"):
            return {
                "ip": ip_str,
                "is_local": False,
                "country": "United States",
                "country_code": "US",
                "flag": "🇺🇸",
                "region": "California",
                "city": "San Francisco",
                "lat": 37.7749,
                "lon": -122.4194,
                "isp": "Cisco OpenDNS LLC",
                "org": "OpenDNS Anycast",
                "asn": "AS36692",
                "threat_score": 0,
                "threat_level": "CLEAN",
                "threat_tags": ["Trusted Public DNS"],
                "cached_at": time.time(),
            }

        # Google Services edge ranges
        if ip_str.startswith("142.250.") or ip_str.startswith("172.217."):
            return {
                "ip": ip_str,
                "is_local": False,
                "country": "United States",
                "country_code": "US",
                "flag": "🇺🇸",
                "region": "California",
                "city": "Mountain View",
                "lat": 37.4220,
                "lon": -122.0841,
                "isp": "Google LLC",
                "org": "Google Infrastructure",
                "asn": "AS15169",
                "threat_score": 0,
                "threat_level": "CLEAN",
                "threat_tags": ["Google Edge Network"],
                "cached_at": time.time(),
            }

        # Cloudflare CDN edge ranges
        if ip_str.startswith("104.16.") or ip_str.startswith("104.17.") or ip_str.startswith("104.21.") or ip_str.startswith("104.26."):
            return {
                "ip": ip_str,
                "is_local": False,
                "country": "United States",
                "country_code": "US",
                "flag": "🇺🇸",
                "region": "California",
                "city": "San Francisco",
                "lat": 37.7749,
                "lon": -122.4194,
                "isp": "Cloudflare Inc.",
                "org": "Cloudflare Anycast",
                "asn": "AS13335",
                "threat_score": 0,
                "threat_level": "CLEAN",
                "threat_tags": ["Cloudflare CDN"],
                "cached_at": time.time(),
            }

        return None

    def _empty_result(self, ip_str: str) -> Dict[str, Any]:
        return {
            "ip": ip_str or "",
            "is_local": True,
            "country": "Unknown",
            "country_code": "",
            "flag": "🌐",
            "region": "",
            "city": "",
            "lat": 0.0,
            "lon": 0.0,
            "isp": "",
            "org": "",
            "asn": "",
            "threat_score": 0,
            "threat_level": "CLEAN",
            "threat_tags": [],
            "cached_at": time.time(),
        }

    def _resolution_worker(self):
        """Background worker thread to resolve batches of public IPs via public GeoIP API."""
        while self._running:
            batch = []
            with self._lock:
                while self._queue and len(batch) < 15:
                    batch.append(self._queue.pop())

            if not batch:
                time.sleep(1.0)
                continue

            for target_ip in batch:
                try:
                    url = f"http://ip-api.com/json/{target_ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,query"
                    req = urllib.request.Request(url, headers={"User-Agent": "CyberTrace-NetworkAnalyzer/2.0"})
                    with urllib.request.urlopen(req, timeout=3.5) as resp:
                        data = json.loads(resp.read().decode("utf-8"))

                    if data.get("status") == "success":
                        asn_str = str(data.get("as") or "")
                        asn_code = asn_str.split()[0] if asn_str else "N/A"
                        threat_score, threat_level, threat_tags = self._score_threat(data)

                        enriched = {
                            "ip": target_ip,
                            "is_local": False,
                            "country": data.get("country") or "Unknown",
                            "country_code": data.get("countryCode") or "",
                            "flag": country_code_to_flag(data.get("countryCode")),
                            "region": data.get("regionName") or "",
                            "city": data.get("city") or "",
                            "lat": float(data.get("lat") or 0.0),
                            "lon": float(data.get("lon") or 0.0),
                            "isp": data.get("isp") or "",
                            "org": data.get("org") or "",
                            "asn": asn_code,
                            "threat_score": threat_score,
                            "threat_level": threat_level,
                            "threat_tags": threat_tags,
                            "cached_at": time.time(),
                        }
                        with self._lock:
                            self._cache[target_ip] = enriched
                    else:
                        self._cache_fallback(target_ip)
                except Exception as exc:
                    logger.debug("GeoIP query error for %s: %s", target_ip, exc)
                    self._cache_fallback(target_ip)

                # Rate limiting to adhere to free API guidelines
                time.sleep(0.1)

    def _cache_fallback(self, ip_str: str):
        # Deterministically distribute unknown offline IPs across realistic coordinates so the map stays readable
        try:
            parts = [int(p) for p in ip_str.split(".") if p.isdigit()]
            seed_lat = 25.0 + (parts[0] % 35) - 10.0 if parts else 30.0
            seed_lon = -60.0 + (parts[1] % 120) if len(parts) > 1 else -40.0
        except Exception:
            seed_lat, seed_lon = 30.0, -40.0

        fallback = {
            "ip": ip_str,
            "is_local": False,
            "country": "External Host (Offline)",
            "country_code": "EXT",
            "flag": "🌐",
            "region": "WAN",
            "city": "Public IP",
            "lat": round(seed_lat, 4),
            "lon": round(seed_lon, 4),
            "isp": "Public Internet Provider",
            "org": "External Network",
            "asn": "AS-EXT",
            "threat_score": 15,
            "threat_level": "LOW",
            "threat_tags": ["Unindexed WAN IP", "Offline Mode"],
            "cached_at": time.time(),
        }
        with self._lock:
            self._cache[ip_str] = fallback

    def _score_threat(self, geo_data: dict) -> tuple[int, str, list[str]]:
        """Calculate threat score (0-100), level, and classification tags."""
        score = 0
        tags = []
        asn = str(geo_data.get("as") or "").upper()
        isp = str(geo_data.get("isp") or "").upper()
        org = str(geo_data.get("org") or "").upper()

        # Check known scanner/hosting ASNs
        for bad_asn, name in KNOWN_SCANNER_ASNS.items():
            if bad_asn.upper() in asn or name.upper() in isp or name.upper() in org:
                score += 45
                tags.append(f"Cloud/Datacenter ({name})")
                tags.append("Potential Botnet/Scanner Source")
                break

        # Check trusted CDNs
        for trusted_asn, name in TRUSTED_CDNS.items():
            if trusted_asn.upper() in asn or name.upper() in isp or name.upper() in org:
                tags.append(f"Verified CDN ({name})")
                score = max(0, score - 20)
                break

        if score >= 70:
            level = "CRITICAL"
        elif score >= 50:
            level = "HIGH"
        elif score >= 30:
            level = "MEDIUM"
        elif score >= 15:
            level = "LOW"
        else:
            level = "CLEAN"

        if not tags:
            tags.append("Standard Internet Host")

        return score, level, tags

    def get_map_nodes(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Extract unique geo-located nodes and communication links from packet list
        to render on Leaflet world threat map.
        """
        nodes_dict: Dict[str, Dict[str, Any]] = {}

        for pkt in packets:
            src = pkt.get("src_ip")
            dst = pkt.get("dst_ip")
            proto = pkt.get("protocol") or "TCP"
            pkt_len = pkt.get("length") or 60

            for ip in (src, dst):
                if not ip or ip == "None":
                    continue
                if ip not in nodes_dict:
                    info = self.lookup(ip)
                    # Filter out purely 0,0 lat/lon unless designated
                    if info.get("lat") != 0.0 or info.get("lon") != 0.0:
                        nodes_dict[ip] = {
                            "ip": ip,
                            "country": info.get("country"),
                            "country_code": info.get("country_code"),
                            "flag": info.get("flag"),
                            "city": info.get("city"),
                            "lat": info.get("lat"),
                            "lon": info.get("lon"),
                            "isp": info.get("isp"),
                            "threat_score": info.get("threat_score", 0),
                            "threat_level": info.get("threat_level", "CLEAN"),
                            "threat_tags": info.get("threat_tags", []),
                            "packet_count": 0,
                            "bytes_total": 0,
                            "protocols": set(),
                        }
                if ip in nodes_dict:
                    nodes_dict[ip]["packet_count"] += 1
                    nodes_dict[ip]["bytes_total"] += pkt_len
                    nodes_dict[ip]["protocols"].add(proto)

        # Convert protocols set to list for JSON serialization
        results = []
        for node in nodes_dict.values():
            node["protocols"] = sorted(list(node["protocols"]))
            results.append(node)

        return results


# Global Singleton
threat_manager = ThreatIntelManager()

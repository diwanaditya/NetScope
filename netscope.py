#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
import time
import ipaddress
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from ipwhois import IPWhois
except Exception:
    IPWhois = None

try:
    from netaddr import IPNetwork
except Exception:
    IPNetwork = None

try:
    import requests
except Exception as exc:
    print("Missing required dependency 'requests'. Install with: pip install requests")
    raise SystemExit(1) from exc

BGPVIEW_BASE = "https://api.bgpview.io"
RIPESTAT_BASE = "https://stat.ripe.net/data"
PEERINGDB_BASE = "https://www.peeringdb.com/api"
IPAPI_BASE = "http://ip-api.com/json"
RDAP_BASE = "https://rdap.org"

CACHE_PATH: Path = Path.home() / ".isp_inspector_cache.json"
DEFAULT_CACHE_TTL = 24 * 3600  # 24 hours

# Logging config
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("isp")

def load_cache() -> Dict[str, Any]:
    """Load JSON cache from disk; return empty dict if file missing or invalid."""
    try:
        if CACHE_PATH.exists():
            data = json.loads(CACHE_PATH.read_text(encoding="utf8"))
            if isinstance(data, dict):
                return data
    except Exception as e:
        logger.debug("Failed to load cache: %s", e)
    return {}

def save_cache(cache: Dict[str, Any]) -> None:
    """Persist cache to disk (best-effort)."""
    try:
        CACHE_PATH.write_text(json.dumps(cache), encoding="utf8")
    except Exception as e:
        logger.debug("Failed to save cache: %s", e)

def cache_get(key: str, ttl: int = DEFAULT_CACHE_TTL) -> Optional[Any]:
    """Return cached value if present and fresh, else None."""
    cache = load_cache()
    entry = cache.get(key)
    if not entry:
        return None
    timestamp = entry.get("_ts", 0)
    if time.time() - timestamp > ttl:
        return None
    return entry.get("value")

def cache_set(key: str, value: Any) -> None:
    """Store value in cache with timestamp."""
    cache = load_cache()
    cache[key] = {"_ts": time.time(), "value": value}
    save_cache(cache)


def safe_get(url: str, params: Optional[Dict[str, Any]] = None, cache_ttl: int = DEFAULT_CACHE_TTL) -> Optional[Any]:
    """
    Perform a GET request and parse JSON. Cache responses to reduce repeated requests.
    Returns parsed JSON on success, otherwise None.
    """
    params = params or {}
    cache_key = f"GET::{url}::{json.dumps(params, sort_keys=True)}"
    cached = cache_get(cache_key, ttl=cache_ttl)
    if cached is not None:
        logger.debug("Cache hit: %s", cache_key)
        return cached

    try:
        resp = requests.get(url, params=params, timeout=20)
        if resp.status_code == 200:
            try:
                data = resp.json()
            except ValueError:
                logger.debug("Non-JSON response from %s", url)
                return None
            cache_set(cache_key, data)
            return data
        else:
            
            try:
                data = resp.json()
                cache_set(cache_key, data)
                return data
            except Exception:
                cache_set(cache_key, {"http_error": resp.status_code})
                return None
    except requests.RequestException as e:
        logger.debug("HTTP request failed for %s: %s", url, e)
        return None


def is_asn(query: str) -> bool:
    s = query.strip().upper()
    return s.startswith("AS") and s[2:].isdigit()

def normalize_asn(query: str) -> Optional[int]:
    s = query.strip().upper()
    if s.startswith("AS"):
        try:
            return int(s[2:])
        except Exception:
            return None
    if s.isdigit():
        return int(s)
    return None

def is_ip(query: str) -> bool:
    try:
        ipaddress.ip_address(query.strip())
        return True
    except Exception:
        return False

def bgpview_asn(asn: int) -> Optional[Dict[str, Any]]:
    return safe_get(f"{BGPVIEW_BASE}/asn/{asn}")

def bgpview_search(query: str) -> Optional[Dict[str, Any]]:
    return safe_get(f"{BGPVIEW_BASE}/search", params={"query": query})

def ripestat_overview(asn: int) -> Optional[Dict[str, Any]]:
    return safe_get(f"{RIPESTAT_BASE}/as-overview/data.json", params={"resource": f"AS{asn}"})

def ripestat_relations(asn: int) -> Optional[Dict[str, Any]]:
    return safe_get(f"{RIPESTAT_BASE}/as-relations/data.json", params={"resource": f"AS{asn}"})

def ripestat_announced_prefixes(asn: int) -> Optional[Dict[str, Any]]:
    return safe_get(f"{RIPESTAT_BASE}/announced-prefixes/data.json", params={"resource": f"AS{asn}"})

def peeringdb_search(query: str) -> Optional[Dict[str, Any]]:
    return safe_get(f"{PEERINGDB_BASE}/search", params={"q": query})

def peeringdb_by_asn(asn: int) -> Optional[Dict[str, Any]]:
    return safe_get(f"{PEERINGDB_BASE}/search", params={"q": str(asn)})

def rdap_autnum(asn: int) -> Optional[Dict[str, Any]]:
    return safe_get(f"{RDAP_BASE}/autnum/{asn}")

def ipapi_geolocate(ip: str) -> Optional[Dict[str, Any]]:
    return safe_get(f"{IPAPI_BASE}/{ip}", params={"fields": "status,country,regionName,city,lat,lon,isp,org,as"})


def prefixes_from_bgpview(bgv: Optional[Dict[str, Any]]) -> List[str]:
    """Extract IPv4/IPv6 prefixes from a BGPView ASN response."""
    if not bgv or "data" not in bgv:
        return []
    data = bgv["data"]
    prefixes: List[str] = []
    for key in ("ipv4_prefixes", "ipv6_prefixes"):
        arr = data.get(key) or []
        for item in arr:
            if isinstance(item, dict):
                p = item.get("prefix") or item.get("route") or item.get("cidr")
                if p:
                    prefixes.append(p)
            elif isinstance(item, str):
                prefixes.append(item)
    # deduplicate while preserving order
    return list(dict.fromkeys(prefixes))

def peering_counts_from_bgpview(bgv: Optional[Dict[str, Any]]) -> Dict[str, Optional[int]]:
    """Return counts for peers, upstreams, and customers from BGPView data if present."""
    res = {"peers": None, "upstreams": None, "customers": None}
    if not bgv or "data" not in bgv:
        return res
    d = bgv["data"]
    res["peers"] = len(d.get("peers") or [])
    res["upstreams"] = len(d.get("upstreams") or [])
    res["customers"] = len(d.get("customers") or [])
    return res

def peering_counts_from_ripestat(rrel: Optional[Dict[str, Any]]) -> Dict[str, Optional[int]]:
    """
    Parse RIPEstat as-relations output for counts. RIPEstat structures vary across regions,
    so this function uses a best-effort approach.
    """
    res = {"peers": None, "upstreams": None, "customers": None}
    if not rrel or "data" not in rrel:
        return res
    d = rrel["data"]
    try:
        rels = d.get("as_relations") or d.get("relations") or []
        peers_set, ups_set, cust_set = set(), set(), set()
        for r in rels:
            if not isinstance(r, dict):
                continue
            typ = (r.get("type") or "").lower()
            other_asn = r.get("asn") or r.get("neighbour") or r.get("neighbor")
            if not other_asn:
                continue
            if typ == "peer":
                peers_set.add(other_asn)
            elif typ in ("provider", "upstream"):
                ups_set.add(other_asn)
            elif typ == "customer":
                cust_set.add(other_asn)
        if peers_set:
            res["peers"] = len(peers_set)
        if ups_set:
            res["upstreams"] = len(ups_set)
        if cust_set:
            res["customers"] = len(cust_set)
    except Exception:
        logger.debug("Failed to parse RIPEstat relations", exc_info=True)
    return res

def rdap_contacts(rdap: Optional[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Extract email and phone contacts from RDAP response entities if available."""
    out: Dict[str, List[str]] = {}
    if not rdap:
        return out
    entities = rdap.get("entities") or []
    for ent in entities:
        roles = ent.get("roles") or []
        vcard = ent.get("vcardArray") or []
        emails: List[str] = []
        phones: List[str] = []
        if isinstance(vcard, list) and len(vcard) >= 2:
            for field in vcard[1]:
                if not isinstance(field, list) or len(field) < 4:
                    continue
                key = field[0]
                val = field[3]
                if key == "email" and isinstance(val, str):
                    emails.append(val)
                if key == "tel" and isinstance(val, str):
                    phones.append(val)
        for r in roles:
            out.setdefault(r, [])
            for e in emails:
                if e not in out[r]:
                    out[r].append(e)
            for ph in phones:
                if ph not in out[r]:
                    out[r].append(ph)
    return out


def sample_ips_from_prefix(prefix: str, max_samples: int = 3) -> List[str]:
    """Pick a small set of representative IPs from a prefix: first usable, middle, last usable."""
    try:
        net = ipaddress.ip_network(prefix, strict=False)
    except Exception:
        return []
    total = net.num_addresses
    samples: List[str] = []
    # For very small networks enumerate hosts up to max_samples
    if total <= max_samples + 2:
        try:
            for i, addr in enumerate(net.hosts()):
                samples.append(str(addr))
                if len(samples) >= max_samples:
                    break
        except Exception:
            samples.append(str(net.network_address))
    else:
        # first usable for IPv4
        if net.version == 4 and total > 2:
            try:
                first = next(net.hosts())
                samples.append(str(first))
            except Exception:
                samples.append(str(net.network_address))
        else:
            samples.append(str(net.network_address))
        # middle
        mid_offset = total // 2
        try:
            mid_ip = str(net.network_address + mid_offset)
            if mid_ip not in samples:
                samples.append(mid_ip)
        except Exception:
            pass
        # last usable for IPv4
        if net.version == 4 and total > 2:
            try:
                last = str(net.broadcast_address - 1)
                if last not in samples:
                    samples.append(last)
            except Exception:
                pass
    return samples[:max_samples]

def geolocate_ip(ip: str, cache_ttl: int = DEFAULT_CACHE_TTL) -> Optional[Dict[str, Any]]:
    """Geolocate an IP using ip-api and cache the result."""
    key = f"geo::{ip}"
    cached = cache_get(key, ttl=cache_ttl)
    if cached:
        return cached
    data = ipapi_geolocate(ip)
    if not data:
        return None
    if isinstance(data, dict) and data.get("status") == "success":
        entry = {
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "as": data.get("as"),
        }
        cache_set(key, entry)
        return entry
    return None

def whois_enrichment(ip: str) -> Optional[Dict[str, Any]]:
    """Optional WHOIS enrichment using ipwhois (if installed). Returns a small dict or None."""
    if IPWhois is None:
        return None
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(asn_methods=["whois", "http"])
        network = res.get("network") or {}
        return {"name": network.get("name"), "country": network.get("country")}
    except Exception:
        logger.debug("ipwhois lookup failed for %s", ip, exc_info=True)
        return None

# Active probing helpers
def ping_average_ms(ip: str, count: int = 3, timeout: int = 2) -> Optional[float]:
    """Run system 'ping' and attempt to parse average RTT in milliseconds. Best-effort."""
    if sys.platform.startswith("win"):
        cmd = ["ping", "-n", str(count), ip]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(timeout), ip]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        out = proc.stdout or ""
        for line in out.splitlines():
            if "min/avg" in line or "rtt min" in line or "round-trip min" in line:
                try:
                    part = line.split("=")[1].strip().split()[0]
                    avg = float(part.split("/")[1])
                    return avg
                except Exception:
                    pass
            if "Average =" in line:
                try:
                    avg = float(line.split("Average =")[1].strip().replace("ms", "").strip())
                    return avg
                except Exception:
                    pass
        return None
    except Exception:
        logger.debug("Ping command failed for %s", ip, exc_info=True)
        return None

def traceroute_hops(ip: str, max_hops: int = 30) -> Optional[List[Dict[str, Any]]]:
    """Run system traceroute/tracert and return list of hops with raw line + optional ip parsed."""
    if sys.platform.startswith("win"):
        cmd = ["tracert", "-d", ip]
    else:
        cmd = ["traceroute", "-n", "-m", str(max_hops), ip]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        out = proc.stdout or ""
        hops: List[Dict[str, Any]] = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            tokens = line.split()
            iptok = None
            for tok in tokens[::-1]:
                try:
                    ipaddress.ip_address(tok)
                    iptok = tok
                    break
                except Exception:
                    continue
            hops.append({"raw": line, "ip": iptok})
        return hops
    except Exception:
        logger.debug("Traceroute failed for %s", ip, exc_info=True)
        return None


# ASCII charts for CLI
def ascii_bar(value: int, max_value: int, width: int = 36) -> str:
    if max_value <= 0:
        filled = 0
    else:
        ratio = min(1.0, float(value) / float(max_value))
        filled = int(round(ratio * width))
    return "[" + "#" * filled + " " * (width - filled) + f"] {value}"

def print_histogram(counts: Dict[str, int], title: str, top_n: int = 10) -> None:
    print("-" * 80)
    print(title)
    print("-" * 80)
    if not counts:
        print("  (no data)")
        return
    items = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
    maxv = max(v for _, v in items) if items else 1
    for key, val in items:
        print(f"{key:20.20} {ascii_bar(val, maxv)}")
    print("-" * 80)

# Report builder & main flow
def build_report_object(
    query: str,
    asn: Optional[int],
    bgpview: Optional[Dict[str, Any]],
    ripe_over: Optional[Dict[str, Any]],
    ripe_rel: Optional[Dict[str, Any]],
    ripe_pref: Optional[Dict[str, Any]],
    pdb: Optional[Dict[str, Any]],
    rdap: Optional[Dict[str, Any]],
    geo_samples: List[Dict[str, Any]],
    active_results: Dict[str, Any],
    warnings: List[str],
) -> Dict[str, Any]:
    """Merge all collected pieces into a structured report dictionary."""
    report: Dict[str, Any] = {
        "query": query,
        "type": "ASN" if asn else ("IP" if is_ip(query) else "NAME"),
        "asn": asn,
        "timestamp": int(time.time()),
        "organization": {"name": None},
        "prefixes": [],
        "peering": {},
        "geo_samples": geo_samples,
        "contacts": {},
        "active_analysis": active_results,
        "warnings": warnings,
    }

    # Organization name heuristics (prefer BGPView -> RIPEstat -> PeeringDB)
    org_name = None
    if bgpview and isinstance(bgpview, dict):
        org_name = bgpview.get("data", {}).get("name") or bgpview.get("data", {}).get("as_name")
    if not org_name and ripe_over and isinstance(ripe_over, dict):
        org_name = ripe_over.get("data", {}).get("holder") or org_name
    if not org_name and pdb and isinstance(pdb, dict):
        nets = pdb.get("data", {}).get("net") or []
        if nets and isinstance(nets, list):
            org_name = nets[0].get("name") or org_name
    report["organization"]["name"] = org_name

    # Prefix list (BGPView preferred, fallback RIPEstat)
    prefixes = prefixes_from_bgpview(bgpview) if bgpview else []
    if not prefixes and ripe_pref:
        try:
            rp = ripe_pref.get("data", {}).get("prefixes") or []
            prefixes = [p.get("prefix") for p in rp if p.get("prefix")]
        except Exception:
            prefixes = []
    report["prefixes"] = prefixes

    # Merge peering counts
    pb = peering_counts_from_bgpview(bgpview)
    rr = peering_counts_from_ripestat(ripe_rel)
    peers = pb.get("peers") if pb.get("peers") is not None and pb.get("peers") > 0 else rr.get("peers")
    upstreams = pb.get("upstreams") if pb.get("upstreams") is not None and pb.get("upstreams") > 0 else rr.get("upstreams")
    customers = pb.get("customers") if pb.get("customers") is not None and pb.get("customers") > 0 else rr.get("customers")
    report["peering"]["peers"] = peers
    report["peering"]["upstreams"] = upstreams
    report["peering"]["customers"] = customers

    # Contacts: RDAP + RIPEstat abuse
    contacts: Dict[str, List[str]] = {}
    if rdap:
        contacts.update(rdap_contacts(rdap))
    if ripe_over and isinstance(ripe_over, dict):
        abuse = ripe_over.get("data", {}).get("abuse_contacts") or ripe_over.get("data", {}).get("abuse")
        if abuse:
            contacts.setdefault("abuse", [])
            if isinstance(abuse, list):
                for a in abuse:
                    if a not in contacts["abuse"]:
                        contacts["abuse"].append(a)
            elif isinstance(abuse, str):
                if abuse not in contacts["abuse"]:
                    contacts["abuse"].append(abuse)
    report["contacts"] = contacts

    return report

def inspect(
    query: str,
    *,
    active: bool = False,
    active_count: int = 3,
    expand_prefixes: bool = False,
    max_prefixes: int = 500,
    geo_rate: float = 1.2,
    cache_ttl: int = DEFAULT_CACHE_TTL,
    json_out: bool = False,
    export_file: Optional[str] = None,
) -> int:
    """
    Main inspector flow: determine type, fetch from multiple sources,
    optionally expand & geolocate prefixes, optionally perform active probes,
    then print or export a structured report.
    """
    q = query.strip()
    asn: Optional[int] = None
    bgpview = ripe_over = ripe_rel = ripe_pref = pdb = rdap = None
    prefixes: List[str] = []
    geo_samples: List[Dict[str, Any]] = []
    warnings: List[str] = []

    # 1) Determine type
    if is_asn(q):
        asn = normalize_asn(q)
    elif is_ip(q):
        # Geolocate the given IP and attempt to extract ASN from ip-api 'as' field
        ip = q
        geo = geolocate_ip(ip, cache_ttl=cache_ttl)
        if geo:
            geo_samples.append({"ip": ip, "geo": geo})
            as_field = geo.get("as") or ""
            if isinstance(as_field, str) and as_field.upper().startswith("AS"):
                numeric = "".join([c for c in as_field.split()[0] if c.isdigit()])
                if numeric:
                    try:
                        asn = int(numeric)
                    except Exception:
                        asn = None
    else:
        # Name search: try BGPView search, then PeeringDB
        sv = bgpview_search(q)
        if sv and isinstance(sv, dict) and sv.get("data"):
            asns = sv["data"].get("asns") or []
            for a in asns:
                if isinstance(a, dict) and a.get("asn"):
                    try:
                        asn = int(a.get("asn"))
                        break
                    except Exception:
                        continue
        if not asn:
            pdb = peeringdb_search(q)
            if pdb and isinstance(pdb, dict) and pdb.get("data"):
                nets = pdb["data"].get("net") or []
                for n in nets:
                    if isinstance(n, dict) and n.get("asn"):
                        try:
                            asn = int(n.get("asn"))
                            break
                        except Exception:
                            continue

    # 2) Fetch ASN-centric data if ASN known
    if asn:
        logger.info("Querying ASN %s ...", asn)
        bgpview = bgpview_asn(asn)
        ripe_over = ripestat_overview(asn)
        ripe_rel = ripestat_relations(asn)
        ripe_pref = ripestat_announced_prefixes(asn)
        try:
            pdb = peeringdb_by_asn(asn)
        except Exception:
            pdb = None
        rdap = rdap_autnum(asn)

        prefixes = prefixes_from_bgpview(bgpview) if bgpview else []
        if not prefixes and ripe_pref:
            try:
                rp = ripe_pref.get("data", {}).get("prefixes") or []
                prefixes = [p.get("prefix") for p in rp if p.get("prefix")]
            except Exception:
                prefixes = []

        # Decide expansion policy
        if prefixes:
            if expand_prefixes:
                to_expand = prefixes[:max_prefixes] if len(prefixes) > max_prefixes else prefixes
            else:
                if len(prefixes) <= 50:
                    to_expand = prefixes
                else:
                    to_expand = prefixes[:8]
                    warnings.append("Large ASN — sampling first 8 prefixes. Use --expand-prefixes to expand more.")
            # Expand prefixes and geolocate sample IPs
            for idx, pfx in enumerate(to_expand):
                samples = sample_ips_from_prefix(pfx, max_samples=3)
                for s_ip in samples:
                    geo = geolocate_ip(s_ip, cache_ttl=cache_ttl)
                    whois = whois_enrichment(s_ip) if IPWhois else None
                    geo_samples.append({"prefix": pfx, "ip": s_ip, "geo": geo, "whois": whois})
                time.sleep(geo_rate)
        else:
            warnings.append("No prefixes discovered from primary sources (BGPView / RIPEstat).")
    else:
        # No ASN found for a name query — attempt PeeringDB nets to seed an ASN
        pdb_try = peeringdb_search(q)
        if pdb_try and isinstance(pdb_try, dict) and pdb_try.get("data"):
            nets = pdb_try["data"].get("net") or []
            candidate_asns = [int(n.get("asn")) for n in nets if isinstance(n, dict) and n.get("asn")]
            if candidate_asns:
                asn = candidate_asns[0]
                # light fetch
                bgpview = bgpview_asn(asn)
                ripe_over = ripestat_overview(asn)
                ripe_rel = ripestat_relations(asn)
                ripe_pref = ripestat_announced_prefixes(asn)
                rdap = rdap_autnum(asn)
                prefixes = prefixes_from_bgpview(bgpview) if bgpview else []
                for pfx in prefixes[:8]:
                    for s_ip in sample_ips_from_prefix(pfx, max_samples=2):
                        geo = geolocate_ip(s_ip, cache_ttl=cache_ttl)
                        geo_samples.append({"prefix": pfx, "ip": s_ip, "geo": geo, "whois": None})

    # 3) Merge peering counts
    pb_counts = peering_counts_from_bgpview(bgpview)
    rr_counts = peering_counts_from_ripestat(ripe_rel)
    peers = pb_counts.get("peers") if pb_counts.get("peers") is not None and pb_counts.get("peers") > 0 else rr_counts.get("peers")
    upstreams = pb_counts.get("upstreams") if pb_counts.get("upstreams") is not None and pb_counts.get("upstreams") > 0 else rr_counts.get("upstreams")
    customers = pb_counts.get("customers") if pb_counts.get("customers") is not None and pb_counts.get("customers") > 0 else rr_counts.get("customers")

    # 4) Active probes if requested
    active_results: Dict[str, Any] = {}
    if active:
        targets: List[str] = []
        for s in geo_samples:
            ip = s.get("ip")
            if ip:
                targets.append(ip)
            if len(targets) >= 3:
                break
        if not targets and prefixes:
            for pfx in prefixes[:3]:
                sp = sample_ips_from_prefix(pfx, max_samples=1)
                if sp:
                    targets.extend(sp)
        pings = []
        traceroutes = []
        for tgt in targets[:3]:
            avg = ping_average_ms(tgt, count=active_count)
            tr = traceroute_hops(tgt)
            pings.append({"target": tgt, "avg_ms": avg})
            traceroutes.append({"target": tgt, "traceroute": tr})
        active_results = {"pings": pings, "traceroutes": traceroutes}

    # 5) Build structured report
    report = build_report_object(
        query=q,
        asn=asn,
        bgpview=bgpview,
        ripe_over=ripe_over,
        ripe_rel=ripe_rel,
        ripe_pref=ripe_pref,
        pdb=pdb,
        rdap=rdap,
        geo_samples=geo_samples,
        active_results=active_results,
        warnings=warnings,
    )
    report["peering"]["peers"] = peers
    report["peering"]["upstreams"] = upstreams
    report["peering"]["customers"] = customers

    # 6) Handy detected ISP company (best-effort)
    detected_isp = None
    if geo_samples:
        for s in geo_samples:
            g = s.get("geo") or {}
            if g and g.get("isp"):
                detected_isp = g.get("isp")
                break
    if not detected_isp:
        if report["organization"].get("name"):
            detected_isp = report["organization"]["name"]
        elif ripe_over and isinstance(ripe_over, dict):
            detected_isp = (ripe_over.get("data") or {}).get("holder")
    report["detected_isp_company"] = detected_isp

    # 7) Country distribution
    country_counts: Dict[str, int] = {}
    for s in geo_samples:
        g = s.get("geo")
        if not g:
            continue
        country = g.get("country") or "Unknown"
        country_counts[country] = country_counts.get(country, 0) + 1

    # 8) Output: JSON or pretty-print
    if json_out:
        serialized = json.dumps(report, indent=2, ensure_ascii=False)
        if export_file:
            try:
                Path(export_file).write_text(serialized, encoding="utf8")
                logger.info("Wrote JSON report to %s", export_file)
            except Exception as e:
                logger.error("Failed to write JSON: %s", e)
        else:
            print(serialized)
        return 0

    # Pretty terminal output
    print("=" * 100)
    print(f"ISP Inspector report for: {q}")
    print("=" * 100)
    if report.get("asn"):
        print(f"ASN: AS{report['asn']}")
    if report["organization"].get("name"):
        print(f"Organization: {report['organization']['name']}")
    if report.get("detected_isp_company"):
        print(f"Detected ISP company: {report['detected_isp_company']}")
    print(f"Type: {report['type']}")
    print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(report['timestamp']))} UTC")
    print("-" * 100)

    # Prefix summary
    pcount = len(report.get("prefixes", []))
    print(f"Announced prefixes (count): {pcount}")
    if pcount:
        sample_show = min(30, pcount)
        for p in report["prefixes"][:sample_show]:
            print(f"  - {p}")
        if pcount > sample_show:
            print(f"  ... (showing first {sample_show} of {pcount})")
    else:
        print("  - (no prefixes found)")

    # Peering info with ASCII bars
    print("-" * 100)
    print("Peering / Network info:")
    maxbar = max(1, peers or 0, upstreams or 0, customers or 0, 100)
    print(f"  Peers: {peers if peers is not None else '(unknown)'} {ascii_bar(peers or 0, maxbar)}")
    print(f"  Upstreams: {upstreams if upstreams is not None else '(unknown)'} {ascii_bar(upstreams or 0, maxbar)}")
    print(f"  Customers: {customers if customers is not None else '(unknown)'} {ascii_bar(customers or 0, maxbar)}")
    print("-" * 100)

    # Geo samples
    print("Geo samples (sampled IPs from prefixes):")
    if report["geo_samples"]:
        for sample in report["geo_samples"][:80]:
            ip = sample.get("ip")
            pfx = sample.get("prefix")
            g = sample.get("geo")
            if ip:
                if g:
                    print(f"  - {ip} (prefix {pfx}): {g.get('country')}, {g.get('region')}, {g.get('city')} lat:{g.get('lat')} lon:{g.get('lon')} isp:{g.get('isp')}")
                else:
                    print(f"  - {ip} (prefix {pfx}): (no geo)")
            else:
                if pfx:
                    print(f"  - prefix {pfx}: (no geo sample)")
    else:
        print("  - (no geo samples)")

    # Distribution histogram
    print_histogram(country_counts, "Prefix distribution by country (top countries)")

    # Contacts
    print("Contacts (RDAP / RIPEstat):")
    if report["contacts"]:
        for role, items in report["contacts"].items():
            print(f"  Role: {role}")
            for it in items:
                print(f"    - {it}")
    else:
        print("  - (no contacts found)")

    # Active analysis
    print("-" * 100)
    if report["active_analysis"]:
        print("Active analysis (enabled):")
        for ping in report["active_analysis"].get("pings", []):
            print(f"  Ping {ping['target']}: avg_ms={ping.get('avg_ms')}")
        for tr in report["active_analysis"].get("traceroutes", []):
            print(f"  Traceroute target: {tr['target']}")
            trace = tr.get("traceroute")
            if trace:
                for i, hop in enumerate(trace[:20], start=1):
                    print(f"    hop {i}: {hop.get('ip') or hop.get('raw')}")
            else:
                print("    - (no traceroute data)")
    else:
        print("Active analysis: (disabled)")

    # Warnings & finish
    print("-" * 100)
    print("Warnings & notes:")
    if report.get("warnings"):
        for w in report.get("warnings"):
            print(f"  - {w}")
    else:
        print("  - (none)")
    print("-" * 100)

    # Optional export
    if export_file:
        try:
            Path(export_file).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf8")
            logger.info("Wrote JSON to %s", export_file)
        except Exception as e:
            logger.error("Failed to export JSON: %s", e)

    return 0


# CLI parsing
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="isp.py", description="ISP Inspector - multi-source ISP intelligence (single file).")
    p.add_argument("--query", "-q", required=True, help='ASN (AS123), IP (1.2.3.4), or ISP/organization name')
    p.add_argument("--json", action="store_true", help="Output JSON instead of pretty terminal report")
    p.add_argument("--export", help="Write JSON report to FILE")
    p.add_argument("--active", action="store_true", help="Enable active probing (ping/traceroute) — use responsibly")
    p.add_argument("--active-count", type=int, default=3, help="Ping count when --active is used (default 3)")
    p.add_argument("--expand-prefixes", action="store_true", help="Expand and geolocate many prefixes (careful on large ASNs)")
    p.add_argument("--max-prefixes", type=int, default=500, help="Max prefixes to expand when --expand-prefixes is used")
    p.add_argument("--rate", type=float, default=1.2, help="Seconds between geolocation calls to respect rate limits")
    p.add_argument("--cache-ttl", type=int, default=DEFAULT_CACHE_TTL, help="Cache TTL in seconds (default 86400)")
    return p.parse_args()

def main() -> int:
    args = parse_args()
    return inspect(
        args.query,
        active=args.active,
        active_count=args.active_count,
        expand_prefixes=args.expand_prefixes,
        max_prefixes=args.max_prefixes,
        geo_rate=args.rate,
        cache_ttl=args.cache_ttl,
        json_out=args.json,
        export_file=args.export,
    )

if __name__ == "__main__":
    try:
        sys.exit(main() or 0)
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(1)

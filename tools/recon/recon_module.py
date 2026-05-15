"""Recon module — 24 endpoints under /api/recon/* matching the React UI.

Each endpoint accepts {target} POST body, returns a tool-specific
JSON shape that the existing frontend's ReconModule renders.
"""
import asyncio
import base64
import datetime
import hashlib
import re
import socket
from typing import Optional

import requests
import dns.resolver
import whois as whois_lib
from fastapi import APIRouter, Depends

from tools._shared import (
    ScanRequest, verify_scan_quota, recon_host, safe_get, web_url,
)

router = APIRouter()


# ── WHOIS ──────────────────────────────────────────────────────
@router.post("/api/recon/whois")
async def recon_whois(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    try:
        w = whois_lib.whois(host)
    except Exception as e:
        return {"ok": False, "skipped_reason": f"WHOIS query failed: {e}"}

    def _first(v):
        return v[0] if isinstance(v, list) and v else v

    def _iso(d):
        d = _first(d)
        if isinstance(d, datetime.datetime):
            return d.isoformat()
        return str(d) if d else None

    return {
        "ok": True,
        "domain": host,
        "registrar": _first(w.registrar),
        "created": _iso(w.creation_date),
        "expires": _iso(w.expiration_date),
        "updated": _iso(w.updated_date),
        "name_servers": sorted({str(n).lower() for n in (w.name_servers or [])}),
        "registrant": _first(w.registrant_name) or _first(w.org),
        "country": _first(w.country),
    }


# ── DNS Records (typed dict) ───────────────────────────────────
@router.post("/api/recon/dns")
async def recon_dns(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    records = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 5
            ans = resolver.resolve(host, rtype)
            records[rtype] = [r.to_text() for r in ans]
        except Exception:
            pass
    if not records:
        return {"ok": False, "skipped_reason": "No DNS records found for this target (private/local IP)."}
    return {"ok": True, "records": records}


# ── DNS Recon (flat list, more shape) ──────────────────────────
@router.post("/api/recon/dnsrecon")
async def recon_dnsrecon(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    records = []
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 5
            ans = resolver.resolve(host, rtype)
            for r in ans:
                records.append({"type": rtype, "name": host, "address": r.to_text()})
        except Exception:
            pass
    return {"ok": True, "records": records}


# ── Subdomains (kept; crtsh does the heavy lifting) ────────────
@router.post("/api/recon/subdomains")
async def recon_subdomains(req: ScanRequest, _=Depends(verify_scan_quota)):
    return {"ok": True, "subdomains": [],
            "skipped_reason": "Use crt.sh tile for CT-based subdomains."}


# ── crt.sh Certificate Transparency ────────────────────────────
@router.post("/api/recon/crtsh")
async def recon_crtsh(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    try:
        r = requests.get(
            f"https://crt.sh/?q=%25.{host}&output=json",
            timeout=20,
            headers={"User-Agent": "VulnusLab/1.0"},
        )
        if r.status_code != 200:
            return {"ok": False, "subdomains": [],
                    "skipped_reason": f"crt.sh returned {r.status_code}"}
        data = r.json()
    except Exception as e:
        return {"ok": False, "subdomains": [],
                "skipped_reason": f"crt.sh query failed: {e}"}

    subs = set()
    for entry in data:
        for line in str(entry.get("name_value", "")).split("\n"):
            line = line.strip().lower().lstrip("*.")
            if line and line.endswith(host):
                subs.add(line)
    return {"ok": True, "subdomains": sorted(subs)}


# ── Amass (heavy Go binary not bundled in pure-Python build) ──
@router.post("/api/recon/amass")
async def recon_amass(req: ScanRequest, _=Depends(verify_scan_quota)):
    return {"ok": True, "subdomains": [],
            "skipped_reason": "Amass not installed in this build — crt.sh tile covers CT-based discovery."}


# ── theHarvester (not bundled) ─────────────────────────────────
@router.post("/api/recon/harvester")
async def recon_harvester(req: ScanRequest, _=Depends(verify_scan_quota)):
    return {"ok": True, "emails": [], "hosts": [],
            "skipped_reason": "theHarvester not bundled — see crt.sh + internetdb tiles for passive intel."}


# ── Shodan (paid API; key from frontend body) ──────────────────
@router.post("/api/recon/shodan")
async def recon_shodan(req: ScanRequest, _=Depends(verify_scan_quota)):
    api_key = getattr(req, "api_key", "") or ""
    if not api_key:
        return {"ok": False, "skipped_reason": "No Shodan API key configured — set in Settings"}
    host = recon_host(req.target)
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return {"ok": False, "skipped_reason": f"Could not resolve {host}"}
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}", timeout=15)
        if r.status_code != 200:
            return {"ok": False, "skipped_reason": f"Shodan API returned {r.status_code}"}
        d = r.json()
        return {
            "ok": True, "ip": d.get("ip_str", ip), "org": d.get("org"),
            "isp": d.get("isp"), "country": d.get("country_name"),
            "city": d.get("city"), "os": d.get("os"),
            "ports": d.get("ports", []),
        }
    except Exception as e:
        return {"ok": False, "skipped_reason": f"Shodan query failed: {e}"}


# ── Port-scan helpers ──────────────────────────────────────────
_PORT_CATALOG = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",
    135:"MS RPC",139:"NetBIOS",143:"IMAP",443:"HTTPS",445:"SMB",
    587:"SMTP-submit",993:"IMAPS",995:"POP3S",1433:"MSSQL",1521:"Oracle",
    2375:"Docker API",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",5672:"AMQP",
    5900:"VNC",6379:"Redis",8000:"HTTP-alt",8080:"HTTP-proxy",8443:"HTTPS-alt",
    8888:"HTTP-alt",9200:"Elasticsearch",11211:"Memcached",15672:"RabbitMQ UI",
    27017:"MongoDB",
}


async def _tcp_probe(host, port, timeout=1.5):
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _scan_open_ports(host):
    ports = sorted(_PORT_CATALOG.keys())
    results = await asyncio.gather(*[_tcp_probe(host, p) for p in ports])
    return [p for p, ok in zip(ports, results) if ok]


@router.post("/api/recon/masscan")
async def recon_masscan(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {"ok": False, "ports": [], "skipped_reason": f"Could not resolve {host}: {e}"}
    open_ports = await _scan_open_ports(ip)
    return {"ok": True, "ip": ip,
            "ports": [{"port": p, "proto": "tcp", "state": "open"} for p in open_ports],
            "engine": "python-asyncio"}


@router.post("/api/recon/nmap")
async def recon_nmap(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {"ok": False, "ports": [], "skipped_reason": f"Could not resolve {host}: {e}"}
    open_ports = await _scan_open_ports(ip)
    return {"ok": True, "ip": ip,
            "ports": [{"port": p, "proto": "tcp", "state": "open",
                       "service": _PORT_CATALOG.get(p, "unknown")} for p in open_ports],
            "engine": "python-asyncio"}


@router.post("/api/recon/services")
async def recon_services(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {"ok": False, "ports": [], "skipped_reason": f"Could not resolve {host}: {e}"}
    open_ports = await _scan_open_ports(ip)
    return {"ok": True,
            "ports": [{"port": p, "service": _PORT_CATALOG.get(p, "unknown"),
                       "version": None} for p in open_ports]}


@router.post("/api/recon/os")
async def recon_os(req: ScanRequest, _=Depends(verify_scan_quota)):
    return {"ok": True, "os": None,
            "skipped_reason": "Active OS fingerprinting needs raw sockets (Kali nmap)."}


async def _grab_banner(host, port, timeout=3.0):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        if port in (80, 8000, 8080, 8443, 8888):
            writer.write(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
            await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(512), timeout=timeout)
        except asyncio.TimeoutError:
            data = b""
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return data.decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


@router.post("/api/recon/banner")
async def recon_banner(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {"ok": False, "banners": {}, "skipped_reason": f"Could not resolve {host}: {e}"}
    open_ports = await _scan_open_ports(ip)
    banners = {}
    for p in open_ports[:10]:
        b = await _grab_banner(ip, p)
        if b:
            banners[p] = b
    return {"ok": True, "banners": banners}


# ── Gobuster (pure-Python dir bruteforce) ──────────────────────
_COMMON_DIRS = [
    "admin","administrator","login","wp-admin","phpmyadmin","backup","config",
    "uploads","files","api","v1","v2","test","dev","staging","old","tmp",
    "robots.txt","sitemap.xml",".git/config",".env","swagger","api-docs","health",
    "metrics","status",".well-known/security.txt",
]


@router.post("/api/recon/gobuster")
async def recon_gobuster(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    found = []
    baseline = safe_get(f"{base}/{hashlib.sha1(req.target.encode()).hexdigest()[:12]}-404probe", req=req)
    if baseline is None:
        return {"ok": False, "found": [], "skipped_reason": f"Could not reach {base}"}
    bs, bl = baseline.status_code, len(baseline.content)
    for path in _COMMON_DIRS:
        r = safe_get(f"{base}/{path}", req=req, allow_redirects=False)
        if r is None:
            continue
        if r.status_code != 404 and (r.status_code != bs or abs(len(r.content) - bl) > 64):
            found.append({"path": "/" + path, "status": r.status_code, "length": len(r.content)})
    return {"ok": True, "found": found, "engine": "python-fuzz"}


# ── JS endpoint extractor ──────────────────────────────────────
@router.post("/api/recon/jsendpoints")
async def recon_jsendpoints(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    r = safe_get(base, req=req, allow_redirects=True)
    if r is None:
        return {"ok": False, "endpoints": [], "skipped_reason": f"Could not reach {base}"}
    js_urls = re.findall(r'src=["\']([^"\']+\.js)', r.text)
    endpoints = set()
    for js_url in js_urls[:5]:
        full = js_url if js_url.startswith("http") else f"{base}/{js_url.lstrip('/')}"
        rjs = safe_get(full, req=req)
        if rjs is None:
            continue
        for m in re.findall(r'["\']/(api/[a-zA-Z0-9_/.-]+)', rjs.text):
            endpoints.add("/" + m)
    return {"ok": True, "endpoints": sorted(endpoints), "js_files": len(js_urls)}


# ── Wayback Machine ────────────────────────────────────────────
@router.post("/api/recon/wayback")
async def recon_wayback(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    try:
        r = requests.get(
            f"http://web.archive.org/cdx/search/cdx?url={host}/*&output=json&limit=200",
            timeout=15,
        )
        if r.status_code != 200:
            return {"ok": False, "urls": [], "skipped_reason": f"Wayback returned {r.status_code}"}
        rows = r.json()
        urls = [row[2] for row in rows[1:]] if rows and len(rows) > 1 else []
        return {"ok": True, "urls": urls[:200]}
    except Exception as e:
        return {"ok": False, "urls": [], "skipped_reason": f"Wayback query failed: {e}"}


# ── robots.txt + sitemap.xml + .well-known ─────────────────────
@router.post("/api/recon/robotsmap")
async def recon_robotsmap(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    disallow, sitemaps, well_known = [], [], []
    r = safe_get(f"{base}/robots.txt", req=req)
    if r is not None and r.status_code == 200:
        for line in r.text.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                p = line.split(":", 1)[1].strip()
                if p:
                    disallow.append(p)
            elif line.lower().startswith("sitemap:"):
                sitemaps.append(line.split(":", 1)[1].strip())
    if not sitemaps:
        rs = safe_get(f"{base}/sitemap.xml", req=req)
        if rs is not None and rs.status_code == 200:
            sitemaps.append(f"{base}/sitemap.xml")
    sec = safe_get(f"{base}/.well-known/security.txt", req=req)
    if sec is not None and sec.status_code == 200:
        well_known.append("/.well-known/security.txt")
    return {"ok": True, "disallow": disallow, "sitemaps": sitemaps, "well_known": well_known}


# ── BFS crawler (depth 1, same-origin) ─────────────────────────
@router.post("/api/recon/crawl")
async def recon_crawl(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    r = safe_get(base, req=req)
    if r is None:
        return {"ok": False, "urls": [], "skipped_reason": f"Could not reach {base}"}
    links = set()
    host = recon_host(req.target)
    for m in re.findall(r'href=["\']([^"\']+)["\']', r.text):
        if m.startswith("http"):
            if recon_host(m) == host:
                links.add(m)
        elif m.startswith("/"):
            links.add(base + m)
    return {"ok": True, "urls": sorted(links)[:50]}


# ── Parameter discovery ────────────────────────────────────────
@router.post("/api/recon/params")
async def recon_params(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    r = safe_get(base, req=req)
    if r is None:
        return {"ok": False, "params": [], "skipped_reason": f"Could not reach {base}"}
    params = set()
    for m in re.findall(r'<input[^>]+name=["\']([^"\']+)', r.text, re.I):
        params.add(m)
    for m in re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]{0,30})=', r.text):
        params.add(m)
    return {"ok": True, "params": sorted(params)[:100]}


# ── Favicon fingerprint ────────────────────────────────────────
@router.post("/api/recon/favicon")
async def recon_favicon(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    r = safe_get(f"{base}/favicon.ico", req=req)
    if r is None or r.status_code != 200 or not r.content:
        return {"ok": True, "favicon": None, "skipped_reason": "No favicon found at /favicon.ico"}
    return {"ok": True,
            "favicon": {"md5": hashlib.md5(r.content).hexdigest(),
                        "size": len(r.content)}}


# ── Cloud buckets (S3 / GCS guess+probe) ──────────────────────
@router.post("/api/recon/cloudbuckets")
async def recon_cloudbuckets(req: ScanRequest, _=Depends(verify_scan_quota)):
    name = recon_host(req.target).split(".")[0]
    candidates = [
        f"https://{name}.s3.amazonaws.com",
        f"https://{name}-prod.s3.amazonaws.com",
        f"https://{name}-staging.s3.amazonaws.com",
        f"https://{name}-backup.s3.amazonaws.com",
        f"https://{name}-uploads.s3.amazonaws.com",
        f"https://storage.googleapis.com/{name}",
        f"https://storage.googleapis.com/{name}-prod",
    ]
    existing, open_buckets = [], []
    for url in candidates:
        r = safe_get(url, req=req, allow_redirects=False)
        if r is None:
            continue
        if r.status_code in (200, 403):
            existing.append({"url": url, "status": r.status_code})
            if r.status_code == 200:
                open_buckets.append(url)
    return {"ok": True, "existing": existing, "open": open_buckets, "tested": len(candidates)}


# ── JS Secret Scanner (tight high-confidence patterns only) ──
_SECRET_PATTERNS = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("Google API Key", r"AIza[0-9A-Za-z_-]{35}"),
    ("Slack Token",    r"xox[baprs]-[0-9a-zA-Z]{10,}"),
    ("GitHub Token",   r"ghp_[0-9A-Za-z]{36}"),
    ("Stripe Live",    r"sk_live_[0-9a-zA-Z]{24,}"),
]


@router.post("/api/recon/secrets")
async def recon_secrets(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    r = safe_get(base, req=req, allow_redirects=True)
    if r is None:
        return {"ok": False, "secrets": [], "skipped_reason": f"Could not reach {base}"}
    js_urls = re.findall(r'src=["\']([^"\']+\.js)', r.text)
    secrets, js_count = [], 0
    for js_url in js_urls[:5]:
        full = js_url if js_url.startswith("http") else f"{base}/{js_url.lstrip('/')}"
        rjs = safe_get(full, req=req)
        if rjs is None:
            continue
        js_count += 1
        for name, pattern in _SECRET_PATTERNS:
            for m in re.finditer(pattern, rjs.text):
                secrets.append({"type": name, "match": m.group(0)[:60], "file": full})
    return {"ok": True, "secrets": secrets, "js_files": js_count}


# ── ASN / IP Ownership ─────────────────────────────────────────
@router.post("/api/recon/asn")
async def recon_asn(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {"ok": False, "skipped_reason": f"Could not resolve {host}: {e}"}
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        if r.status_code != 200:
            return {"ok": False, "skipped_reason": f"ipinfo returned {r.status_code}"}
        d = r.json()
        return {"ok": True, "ip": ip, "asn": d.get("org", ""),
                "country": d.get("country"), "city": d.get("city"),
                "region": d.get("region"), "hostname": d.get("hostname")}
    except Exception as e:
        return {"ok": False, "skipped_reason": f"ASN lookup failed: {e}"}


# ── Free Shodan via InternetDB (no API key) ────────────────────
@router.post("/api/recon/internetdb")
async def recon_internetdb(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {"ok": False, "skipped_reason": f"Could not resolve {host}: {e}"}
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
        if r.status_code == 404:
            return {"ok": True, "ip": ip, "skipped_reason": "No InternetDB record for this IP"}
        if r.status_code != 200:
            return {"ok": False, "skipped_reason": f"InternetDB returned {r.status_code}"}
        d = r.json()
        return {"ok": True, "ip": ip,
                "ports": d.get("ports", []), "cves": d.get("vulns", []),
                "hostnames": d.get("hostnames", []), "tags": d.get("tags", [])}
    except Exception as e:
        return {"ok": False, "skipped_reason": f"InternetDB query failed: {e}"}


def register(app):
    app.include_router(router)

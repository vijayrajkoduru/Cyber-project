"""CVE matching against detected service versions.

Active workflow:
  1. Banner-grab common service ports + HTTP headers + meta generator
  2. Regex-extract (vendor, product, version) from each banner/header
  3. Query NIST NVD API per (vendor, product, version)
  4. Return CVEs with CVSS scores, severity, descriptions

Industry-leading benchmark: matches what Detectify/Acunetix do — turns
"Apache 2.2.8 detected" into "CVE-2017-7679 RCE (CVSS 7.5)".

No API key needed for public NVD endpoint. Rate-limited to 5 req/30s
without key (we sleep 0.5s between to stay safe).
"""
import asyncio
import re
import socket
import time

import requests
from fastapi import APIRouter, Depends

from tools._shared import (
    ScanRequest, verify_scan_quota, recon_host, safe_get, web_url,
)

router = APIRouter()


# Banner-string regex → NVD CPE (vendor, product) mapping.
# Add more as needed; only confident patterns to avoid false matches.
SERVICE_PATTERNS = [
    (r"Apache/(\d+\.\d+(?:\.\d+)?)",          "apache",       "http_server"),
    (r"Apache Tomcat/(\d+\.\d+(?:\.\d+)?)",   "apache",       "tomcat"),
    (r"\bnginx/(\d+\.\d+(?:\.\d+)?)",         "nginx",        "nginx"),
    (r"Microsoft-IIS/(\d+\.\d+)",             "microsoft",    "iis"),
    (r"PHP/(\d+\.\d+(?:\.\d+)?)",             "php",          "php"),
    (r"OpenSSH_(\d+\.\d+(?:p\d+)?)",          "openbsd",      "openssh"),
    (r"\bMySQL\b[^\d]*(\d+\.\d+\.\d+)",       "oracle",       "mysql"),
    (r"PostgreSQL\s+(\d+\.\d+)",              "postgresql",   "postgresql"),
    (r"vsFTPd\s+(\d+\.\d+\.\d+)",             "vsftpd",       "vsftpd"),
    (r"ProFTPD\s+(\d+\.\d+(?:\.\d+)?)",       "proftpd",      "proftpd"),
    (r"Pure-FTPd",                             "pureftpd",     "pure-ftpd"),
    (r"WordPress\s*(\d+\.\d+(?:\.\d+)?)",     "wordpress",    "wordpress"),
    (r"Drupal\s*(\d+(?:\.\d+)?)",             "drupal",       "drupal"),
    (r"Joomla!\s*(\d+\.\d+(?:\.\d+)?)",       "joomla",       "joomla!"),
    (r"Exim\s+(\d+\.\d+)",                    "exim",         "exim"),
    (r"Postfix",                               "postfix",      "postfix"),
    (r"Dovecot",                               "dovecot",      "dovecot"),
    (r"BIND\s+(\d+\.\d+\.\d+)",               "isc",          "bind"),
    (r"Samba\s+(\d+\.\d+\.\d+)",              "samba",        "samba"),
]


def _extract_services(banners, headers):
    services = []
    text_corpus = " | ".join(banners) + " | " + " | ".join(
        f"{k}: {v}" for k, v in (headers or {}).items()
    )
    for pattern, vendor, product in SERVICE_PATTERNS:
        for m in re.finditer(pattern, text_corpus, re.I):
            version = m.group(1) if m.groups() else None
            if not version and vendor in ("postfix", "dovecot", "pureftpd"):
                version = "*"
            if not version:
                continue
            services.append({
                "vendor": vendor, "product": product, "version": version,
                "detected_in": m.group(0)[:80],
            })
    # Dedup
    seen, out = set(), []
    for s in services:
        key = (s["vendor"], s["product"], s["version"])
        if key not in seen:
            seen.add(key)
            out.append(s)
    return out


def _query_nvd(vendor, product, version):
    """Query NVD for matching CVEs. Returns list of dicts."""
    if version == "*":
        params = {"keywordSearch": f"{vendor} {product}", "resultsPerPage": 30}
    else:
        cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
        params = {"cpeName": cpe, "resultsPerPage": 50}
    try:
        r = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params, timeout=20,
            headers={"User-Agent": "VulnusLab/1.0"},
        )
        if r.status_code != 200:
            return []
        data = r.json()
        cves = []
        for v in data.get("vulnerabilities", []):
            cve_obj = v.get("cve", {})
            cve_id = cve_obj.get("id")
            descs = cve_obj.get("descriptions", [])
            desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")[:280]
            metrics = cve_obj.get("metrics", {})
            cvss_score, cvss_severity = None, "UNKNOWN"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                arr = metrics.get(key) or []
                if arr:
                    cd = arr[0].get("cvssData", {})
                    cvss_score = cd.get("baseScore")
                    cvss_severity = (cd.get("baseSeverity")
                                     or arr[0].get("baseSeverity")
                                     or "UNKNOWN").upper()
                    break
            cves.append({
                "id":             cve_id,
                "description":    desc,
                "cvss_score":     cvss_score,
                "cvss_severity":  cvss_severity,
                "published":      cve_obj.get("published", "")[:10],
                "vendor_product": f"{vendor}/{product}",
                "matched_version": version,
            })
        # Sort by CVSS desc, then publish date desc
        cves.sort(key=lambda c: (-(c["cvss_score"] or 0), c["published"]), reverse=False)
        cves = sorted(cves, key=lambda c: -(c["cvss_score"] or 0))
        return cves
    except Exception:
        return []


async def _grab_tcp_banner(host, port, timeout=2.0):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        if port in (80, 8080, 8000):
            writer.write(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
            await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(512), timeout=timeout)
        except asyncio.TimeoutError:
            data = b""
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass
        return data.decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


@router.post("/api/recon/cve_match")
async def recon_cve_match(req: ScanRequest, _=Depends(verify_scan_quota)):
    target = recon_host(req.target)
    banners, headers = [], {}

    # HTTP layer — headers + meta generator
    base = web_url(req.target)
    r = safe_get(base, req=req, allow_redirects=True)
    if r is not None:
        for h in ("Server", "X-Powered-By", "X-Generator", "X-AspNet-Version"):
            v = r.headers.get(h)
            if v:
                headers[h] = v
        try:
            body = r.text[:8000]
            m = re.search(
                r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
                body, re.I,
            )
            if m:
                banners.append(m.group(1))
        except Exception:
            pass

    # TCP banner probes on common service ports
    try:
        ip = socket.gethostbyname(target)
        for port in (21, 22, 25, 80, 110, 143, 443, 3306, 5432):
            b = await _grab_tcp_banner(ip, port)
            if b:
                banners.append(b)
    except Exception:
        pass

    services = _extract_services(banners, headers)

    # Query NVD per (vendor, product, version)
    services_with_cves = []
    all_cves = []
    for svc in services:
        cves = _query_nvd(svc["vendor"], svc["product"], svc["version"])
        crit_high = [c for c in cves if (c.get("cvss_score") or 0) >= 7.0]
        services_with_cves.append({
            **svc,
            "cves_found":         len(cves),
            "cves_high_critical": len(crit_high),
            "cves":               cves[:25],
        })
        all_cves.extend(cves)
        time.sleep(0.6)  # NVD rate limit: 5/30s without API key

    summary = {
        "services_scanned":       len(services),
        "total_cves":             len(all_cves),
        "critical_cves":          sum(1 for c in all_cves if (c.get("cvss_score") or 0) >= 9.0),
        "high_cves":              sum(1 for c in all_cves if 7.0 <= (c.get("cvss_score") or 0) < 9.0),
        "medium_cves":            sum(1 for c in all_cves if 4.0 <= (c.get("cvss_score") or 0) < 7.0),
        "low_cves":               sum(1 for c in all_cves if 0 < (c.get("cvss_score") or 0) < 4.0),
    }

    if not services:
        return {
            "ok": True, "services_detected": [], "cves": [],
            "summary": summary,
            "skipped_reason": "No identifiable service versions in banners/headers — nothing to match against NVD",
        }

    return {
        "ok":                  True,
        "target":              target,
        "services_detected":   services_with_cves,
        "cves":                all_cves[:200],
        "summary":             summary,
    }


def register(app):
    app.include_router(router)

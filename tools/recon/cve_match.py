"""CVE matcher — detects tech (HTTP fingerprints + service banners) → matches CVE map."""
import re
import socket
from urllib.parse import urlparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
from tools._payloads.tech_fingerprints import TECH_FINGERPRINTS
from tools._payloads.tech_cve_map import TECH_CVE_MAP

router = APIRouter()


# Service ports we probe for banner data (SSH/SMTP/FTP versions → CVE matching)
_BANNER_PORTS = [(22, "OpenSSH"), (21, "FTP"), (25, "SMTP"),
                  (110, "POP3"), (143, "IMAP"), (3306, "MySQL"),
                  (5432, "PostgreSQL")]


def _grab_banner(host, port, timeout=4):
    """Raw socket → read first 1KB of service banner."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            return s.recv(1024).decode("utf-8", errors="ignore")[:500]
    except Exception:
        return ""


def _extract_version(banner):
    """Pull a version number out of common service banners."""
    for pat in (r"OpenSSH[_\s](\d+\.\d+(?:\.\d+)?p?\d*)",
                 r"Apache[/\s](\d+\.\d+(?:\.\d+)?)",
                 r"nginx[/\s](\d+\.\d+(?:\.\d+)?)",
                 r"Postfix[/\s](\d+\.\d+(?:\.\d+)?)",
                 r"Exim[/\s](\d+\.\d+(?:\.\d+)?)",
                 r"MySQL[\s](\d+\.\d+(?:\.\d+)?)",
                 r"PHP/(\d+\.\d+(?:\.\d+)?)"):
        m = re.search(pat, banner)
        if m: return m.group(1)
    return None


def _detect_tech_from_response(headers_str, body, cookies_str):
    """Returns list of {name, version, category} from HTTP fingerprinting."""
    detected = []
    body_sample = (body or "")[:30000]
    for fp in TECH_FINGERPRINTS:
        try:
            version = None
            matched = False
            for src, pat in (("header", fp.get("header_regex")),
                              ("body",   fp.get("body_regex")),
                              ("cookie", fp.get("cookie_regex"))):
                if not pat: continue
                tgt = headers_str if src == "header" else (cookies_str if src == "cookie" else body_sample)
                m = re.search(pat, tgt or "", re.IGNORECASE)
                if m:
                    matched = True
                    if fp.get("version_group", 0) > 0:
                        try: version = m.group(fp["version_group"])
                        except (IndexError, AttributeError): pass
                    break
            if matched:
                detected.append({"name": fp["name"], "version": version,
                                 "category": fp.get("category", "unknown")})
        except re.error: continue
    # Dedupe — keep version if any pass detected it
    by_name = {}
    for d in detected:
        if d["name"] not in by_name or (d["version"] and not by_name[d["name"]]["version"]):
            by_name[d["name"]] = d
    return list(by_name.values())


def _match_cves(tech_name, version):
    """Find CVEs in TECH_CVE_MAP matching this tech+version."""
    if not version: return []
    matches = []
    for entry in TECH_CVE_MAP:
        tech = entry.get("tech", "").lower()
        if tech and tech_name.lower() not in tech and tech not in tech_name.lower():
            continue
        vmatch = entry.get("version_match", "")
        if not vmatch: continue
        try:
            if re.search(vmatch, version):
                matches.append(entry)
        except re.error: continue
    return matches


@router.post("/api/recon/cve_match")
async def recon_cve_match(req: ScanRequest, _=Depends(verify_scan_quota)):
    url = web_url(req.target)
    findings = []
    detected_techs = []
    cves_found = 0

    # ── 1. HTTP-based tech detection
    r = safe_get(url, req=req, allow_redirects=True, timeout=12)
    if r is not None:
        headers_str = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        cookies_str = r.headers.get("Set-Cookie", "")
        detected_techs = _detect_tech_from_response(headers_str, r.text or "", cookies_str)
        for tech in detected_techs:
            if not tech.get("version"): continue
            for cve in _match_cves(tech["name"], tech["version"]):
                findings.append(wrap_finding(
                    f"{tech['name']} {tech['version']} vulnerable to {cve['cve']}: {cve.get('description', '')}",
                    cve.get("severity", "MEDIUM"),
                    cvss=str(cve.get("cvss", "5.0")),
                    cwe="CWE-1395", owasp="A06:2021",
                    remediation=f"Upgrade {tech['name']} past the vulnerable version range.",
                    evidence_marker=f"{tech['name']} {tech['version']} detected via HTTP fingerprint → matches {cve['cve']}"))
                cves_found += 1

    # ── 2. Service-banner CVE matching (SSH/SMTP/FTP/etc.)
    host = urlparse(url).netloc.split(":")[0]
    banner_results = []
    for port, service in _BANNER_PORTS:
        banner = _grab_banner(host, port)
        if not banner: continue
        version = _extract_version(banner)
        if not version: continue
        banner_results.append({"port": port, "service": service, "version": version,
                                "banner": banner.strip()[:120]})
        for cve in _match_cves(service, version):
            findings.append(wrap_finding(
                f"{service} {version} on port {port} vulnerable to {cve['cve']}: {cve.get('description', '')}",
                cve.get("severity", "MEDIUM"),
                cvss=str(cve.get("cvss", "5.0")),
                cwe="CWE-1395", owasp="A06:2021",
                remediation=f"Upgrade {service} service on port {port}.",
                evidence_marker=f"Port {port} banner: {banner.strip()[:80]}"))
            cves_found += 1

    return standard_response(tool="cve_match", target=req.target,
        findings=findings,
        tests_performed=max(len(detected_techs) + len(banner_results), 1),
        tests_summary=(f"CVE match: HTTP detected {len(detected_techs)} tech(s), "
                       f"banner detected {len(banner_results)} service(s), "
                       f"matched {cves_found} total CVE(s)"),
        raw_data={"cve_match": {"http_techs": detected_techs[:30],
                                 "banner_results": banner_results,
                                 "cves_found": cves_found}})


def register(app):
    app.include_router(router)

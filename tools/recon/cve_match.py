"""CVE matcher — detects tech (HTTP fingerprints + service banners) → matches CVE map.

Returns BOTH shapes:
  - `findings[]`  → new standard_response shape (PDF / report engine)
  - `cves[]` + `summary{}` + `services_detected[]`  → legacy UI shape (dashboard tile)
"""
import re
import socket
from urllib.parse import urlparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
from tools._payloads.tech_fingerprints import TECH_FINGERPRINTS
from tools._payloads.tech_cve_map import TECH_CVE_MAP

router = APIRouter()

_BANNER_PORTS = [(22, "OpenSSH"), (21, "FTP"), (25, "SMTP"),
                  (110, "POP3"), (143, "IMAP"), (3306, "MySQL"),
                  (5432, "PostgreSQL")]


def _grab_banner(host, port, timeout=4):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            return s.recv(1024).decode("utf-8", errors="ignore")[:500]
    except Exception:
        return ""


def _extract_version(banner):
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
    detected = []
    body_sample = (body or "")[:30000]
    for fp in TECH_FINGERPRINTS:
        try:
            version, matched = None, False
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
    by_name = {}
    for d in detected:
        if d["name"] not in by_name or (d["version"] and not by_name[d["name"]]["version"]):
            by_name[d["name"]] = d
    return list(by_name.values())


def _match_cves(tech_name, version):
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


def _sev_bucket(sev):
    s = (sev or "").upper()
    if s == "CRITICAL": return "critical"
    if s == "HIGH":     return "high"
    if s == "LOW":      return "low"
    return "medium"


@router.post("/api/recon/cve_match")
async def recon_cve_match(req: ScanRequest, _=Depends(verify_scan_quota)):
    url = web_url(req.target)
    findings, detected_techs, ui_cves = [], [], []
    services_ui = []
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    # 1. HTTP tech detection
    r = safe_get(url, req=req, allow_redirects=True, timeout=12)
    if r is not None:
        headers_str = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        cookies_str = r.headers.get("Set-Cookie", "")
        detected_techs = _detect_tech_from_response(headers_str, r.text or "", cookies_str)
        for tech in detected_techs:
            if not tech.get("version"): continue
            services_ui.append({"vendor": tech["name"], "product": tech["name"],
                                "version": tech["version"]})
            for cve in _match_cves(tech["name"], tech["version"]):
                sev  = cve.get("severity", "MEDIUM")
                cvss = str(cve.get("cvss", "5.0"))
                desc = cve.get("description", "")
                cid  = cve.get("cve", "")
                findings.append(wrap_finding(
                    f"{tech['name']} {tech['version']} vulnerable to {cid}: {desc}",
                    sev, cvss=cvss, cwe="CWE-1395", owasp="A06:2021",
                    remediation=f"Upgrade {tech['name']} past the vulnerable version range.",
                    evidence_marker=f"{tech['name']} {tech['version']} detected via HTTP fingerprint -> matches {cid}"))
                ui_cves.append({"id": cid, "cvss_score": float(cvss) if cvss else 0,
                                 "cvss_severity": sev.upper(), "description": desc,
                                 "published": cve.get("published", ""),
                                 "vendor_product": f"{tech['name']}/{tech['name']}",
                                 "matched_version": tech["version"]})
                counts[_sev_bucket(sev)] += 1

    # 2. Service-banner CVE matching
    host = urlparse(url).netloc.split(":")[0]
    banner_results = []
    for port, service in _BANNER_PORTS:
        banner = _grab_banner(host, port)
        if not banner: continue
        version = _extract_version(banner)
        if not version: continue
        banner_results.append({"port": port, "service": service, "version": version,
                                "banner": banner.strip()[:120]})
        services_ui.append({"vendor": service, "product": service, "version": version})
        for cve in _match_cves(service, version):
            sev  = cve.get("severity", "MEDIUM")
            cvss = str(cve.get("cvss", "5.0"))
            desc = cve.get("description", "")
            cid  = cve.get("cve", "")
            findings.append(wrap_finding(
                f"{service} {version} on port {port} vulnerable to {cid}: {desc}",
                sev, cvss=cvss, cwe="CWE-1395", owasp="A06:2021",
                remediation=f"Upgrade {service} service on port {port}.",
                evidence_marker=f"Port {port} banner: {banner.strip()[:80]}"))
            ui_cves.append({"id": cid, "cvss_score": float(cvss) if cvss else 0,
                             "cvss_severity": sev.upper(), "description": desc,
                             "published": cve.get("published", ""),
                             "vendor_product": f"{service}/{service}",
                             "matched_version": version})
            counts[_sev_bucket(sev)] += 1

    base = standard_response(tool="cve_match", target=req.target,
        findings=findings,
        tests_performed=max(len(detected_techs) + len(banner_results), 1),
        tests_summary=(f"CVE match: HTTP detected {len(detected_techs)} tech(s), "
                       f"banner detected {len(banner_results)} service(s), "
                       f"matched {len(ui_cves)} total CVE(s)"),
        raw_data={"cve_match": {"http_techs": detected_techs[:30],
                                 "banner_results": banner_results,
                                 "cves_found": len(ui_cves)}})

    # UI-compat keys merged into the same response (so r.cve_match.cves / .summary work)
    return {**base,
        "cves":               ui_cves[:200],
        "services_detected":  services_ui,
        "summary": {
            "services_scanned": len(services_ui),
            "total_cves":       len(ui_cves),
            "critical_cves":    counts["critical"],
            "high_cves":        counts["high"],
            "medium_cves":      counts["medium"],
            "low_cves":         counts["low"],
        }}


def register(app):
    app.include_router(router)

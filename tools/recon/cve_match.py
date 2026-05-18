"""CVE matcher — detects tech versions then looks them up in the CVE map."""
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
from tools._payloads.tech_fingerprints import TECH_FINGERPRINTS
from tools._payloads.tech_cve_map import TECH_CVE_MAP

router = APIRouter()


def _detect_tech(headers, body, cookies):
    """Returns list of {name, version} detected from response."""
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
                target = headers if src == "header" else (cookies if src == "cookie" else body_sample)
                m = re.search(pat, target or "", re.IGNORECASE)
                if m:
                    matched = True
                    if fp.get("version_group") and fp["version_group"] > 0:
                        try:
                            version = m.group(fp["version_group"])
                        except (IndexError, AttributeError):
                            version = None
                    break
            if matched:
                detected.append({"name": fp["name"], "version": version,
                                 "category": fp.get("category", "unknown")})
        except re.error:
            continue
    # Dedupe by name (keep version if any pass detected it)
    by_name = {}
    for d in detected:
        if d["name"] not in by_name or (d["version"] and not by_name[d["name"]]["version"]):
            by_name[d["name"]] = d
    return list(by_name.values())


def _match_cves(tech, version):
    """Returns list of CVE dicts from TECH_CVE_MAP matching this tech+version."""
    if not version:
        return []
    matches = []
    for entry in TECH_CVE_MAP:
        if entry.get("tech", "").lower() not in tech.lower():
            continue
        vmatch = entry.get("version_match", "")
        try:
            if re.search(vmatch, version):
                matches.append(entry)
        except re.error:
            continue
    return matches




import socket

_BANNER_PORTS = [(22, "SSH"), (21, "FTP"), (25, "SMTP"), (110, "POP3"), (143, "IMAP")]


def _grab_banner(host, port, timeout=4):
    """Open TCP socket, read first response. Used for SSH/SMTP/etc banner CVE matching."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(1024)
            return data.decode("utf-8", errors="ignore")[:300]
    except Exception:
        return ""


def _match_banner_cves(banner, service):
    """Given a service banner, try to find matching CVEs via TECH_CVE_MAP."""
    if not banner:
        return []
    import re as _re
    matches = []
    # Extract a version string from common banner patterns
    # SSH: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-...
    # SMTP: 220 mail.example.com ESMTP Postfix (Debian/Ubuntu)
    version = None
    for pat in (r"OpenSSH[_\s](\d+\.\d+(?:\.\d+)?p?\d*)",
                 r"Apache[/\s](\d+\.\d+\.\d+)",
                 r"nginx[/\s](\d+\.\d+\.\d+)",
                 r"Postfix[/\s](\d+\.\d+\.\d+)",
                 r"Exim[/\s](\d+\.\d+(?:\.\d+)?)"):
        m = _re.search(pat, banner)
        if m:
            version = m.group(1); break
    if not version:
        return []
    # Look up in TECH_CVE_MAP
    tech_map = {"SSH": "OpenSSH", "SMTP": "Postfix"}
    tech_name = tech_map.get(service, service)
    for entry in TECH_CVE_MAP:
        if entry.get("tech", "").lower() not in tech_name.lower():
            continue
        try:
            if _re.search(entry.get("version_match", ""), version):
                matches.append((entry, version))
        except _re.error:
            continue
    return matches


@router.post("/api/recon/cve_match")
async def recon_cve_match(req: ScanRequest, _=Depends(verify_scan_quota)):
    url = web_url(req.target)
    r = safe_get(url, req=req, allow_redirects=True, timeout=12)
    if r is None:
            # Also probe service banners (SSH/SMTP/etc.) for additional CVE matches
    from urllib.parse import urlparse as _up
    host = _up(url).netloc.split(":")[0]
    banner_matches = []
    for port, service in _BANNER_PORTS:
        banner = _grab_banner(host, port)
        if banner:
            for cve, ver in _match_banner_cves(banner, service):
                findings.append(wrap_finding(
                    f"{service} {ver} vulnerable to {cve['cve']}: {cve.get('description', '')}",
                    cve.get("severity", "MEDIUM"),
                    cvss=str(cve.get("cvss", "5.0")),
                    cwe="CWE-1395", owasp="A06:2021",
                    remediation=f"Upgrade {service} service on port {port} past the vulnerable version range.",
                    evidence_marker=f"Port {port} banner: {banner.strip()[:80]}"))
                banner_matches.append({"port": port, "service": service, "version": ver, "cve": cve["cve"]})

    return standard_response(tool="cve_match", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason=f"Could not reach {url}")
    headers_str = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
    cookies_str = r.headers.get("Set-Cookie", "")
    detected_techs = _detect_tech(headers_str, r.text or "", cookies_str)

    findings = []
    cves_found = 0
    tech_with_cve = []
    for tech in detected_techs:
        if not tech.get("version"):
            continue
        cves = _match_cves(tech["name"], tech["version"])
        for cve in cves:
            findings.append(wrap_finding(
                f"{tech['name']} {tech['version']} vulnerable to {cve['cve']}: {cve.get('description', '')}",
                cve.get("severity", "MEDIUM"),
                cvss=str(cve.get("cvss", "5.0")),
                cwe="CWE-1395", owasp="A06:2021",
                remediation=f"Upgrade {tech['name']} to a version not affected by {cve['cve']}.",
                evidence_marker=f"{tech['name']} {tech['version']} detected via fingerprint → matches {cve['cve']}"))
            cves_found += 1
        if cves:
            tech_with_cve.append({"tech": tech["name"], "version": tech["version"], "cve_count": len(cves)})

    return standard_response(tool="cve_match", target=req.target,
        findings=findings,
        tests_performed=max(len(detected_techs), 1),
        tests_summary=(f"CVE match: detected {len(detected_techs)} technolog(y/ies), "
                       f"matched {cves_found} CVE(s) across {len(tech_with_cve)} versioned tech(s)"),
        raw_data={"cve_match": {"detected_techs": detected_techs[:30],
                                 "tech_with_cve": tech_with_cve}})


def register(app):
    app.include_router(router)

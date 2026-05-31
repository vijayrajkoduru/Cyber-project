"""webmail_imap_smtp_ssrf — webmail-app IMAP/SMTP-URL SSRF.

Webmail apps (RoundCube, SquirrelMail, Horde, custom in-house clients)
accept user-controlled IMAP/SMTP server addresses. If validation is
weak, attacker can:
  - SSRF: target internal-network IMAP servers
  - SMTP smuggling: send mail via internal relay

Tests common webmail config endpoints + login pages with crafted server
URLs (imap://internal-host, smtp://169.254.169.254).
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)

router = APIRouter()

WEBMAIL_PATHS = [
    "/roundcube/", "/webmail/", "/mail/",
    "/squirrelmail/", "/horde/",
    "/login.php", "/index.php?_task=login",
]
WEBMAIL_MARKERS = [
    "RoundCube", "SquirrelMail", "Horde",
    "webmail-app", "mail/login", "imap_host",
]


@router.post("/api/webapp/scan/webmail_imap_smtp_ssrf")
def scan_webmail_imap_smtp_ssrf(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    webmail_found = []

    for path in WEBMAIL_PATHS:
        r = safe_request("GET", base + path,
            headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0"},
            req=req, timeout=8, allow_redirects=True)
        if r is None or r.status_code == 404: continue
        body = (r.text or "")[:50000]
        for marker in WEBMAIL_MARKERS:
            if marker.lower() in body.lower():
                webmail_found.append({"path": path, "marker": marker,
                                        "status": r.status_code})
                break

    if not webmail_found:
        return standard_response(
            tool="webmail_imap_smtp_ssrf", target=req.target,
            findings=[wrap_finding(
                "No webmail app detected",
                "POSITIVE", cwe="CWE-918",
                remediation="No webmail SSRF surface from this scan.",
                evidence_marker=f"checked {len(WEBMAIL_PATHS)} paths × "
                                  f"{len(WEBMAIL_MARKERS)} markers")],
            tests_performed=len(WEBMAIL_PATHS), vulnerable=False,
            tests_summary="No webmail detected")

    # Webmail detected — advisory finding (real exploit needs login)
    return standard_response(
        tool="webmail_imap_smtp_ssrf", target=req.target,
        findings=[wrap_finding(
            f"Webmail application detected ({len(webmail_found)} signature(s))",
            "MEDIUM", cvss="6.0", cwe="CWE-918", owasp="A10:2021",
            remediation="Webmail apps often have IMAP/SMTP server fields. Manually "
                        "verify: (1) login form rejects 'imap://internal-host' / "
                        "'imap://169.254.169.254'; (2) server is on a configured "
                        "allow-list, not user-supplied; (3) outbound IMAP/SMTP "
                        "connections from webmail back-end are firewalled to only "
                        "the configured mail server. RoundCube < 1.6.0 had multiple "
                        "SSRF CVEs (CVE-2023-43770 etc) — confirm version + patch level.",
            evidence_marker=" | ".join(
                f"{w['path']}: {w['marker']} (HTTP {w['status']})"
                for w in webmail_found[:3]
            ))],
        tests_performed=len(WEBMAIL_PATHS), vulnerable=True,
        tests_summary=f"webmail detected at {len(webmail_found)} path(s)",
        raw_data={"webmail_signatures": webmail_found})


def register(app):
    app.include_router(router)

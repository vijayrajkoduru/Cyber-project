"""robots_disallow_disclosure — robots.txt Disallow leaks sensitive paths.

robots.txt is meant to tell search-crawlers what NOT to index. But by
listing /admin /api/internal /backup /old-site etc. it ALSO tells
attackers exactly what to target. Classic OSINT mistake.

Audit: fetch /robots.txt + extract Disallow entries, flag entries that
match known-sensitive patterns (admin, api, internal, debug, backup, etc).
"""
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

SENSITIVE_PATTERNS = [
    re.compile(r"/admin", re.IGNORECASE),
    re.compile(r"/api/internal", re.IGNORECASE),
    re.compile(r"/backup", re.IGNORECASE),
    re.compile(r"/\.git", re.IGNORECASE),
    re.compile(r"/\.env", re.IGNORECASE),
    re.compile(r"/config", re.IGNORECASE),
    re.compile(r"/private", re.IGNORECASE),
    re.compile(r"/staging", re.IGNORECASE),
    re.compile(r"/dev/", re.IGNORECASE),
    re.compile(r"/test/", re.IGNORECASE),
    re.compile(r"/internal", re.IGNORECASE),
    re.compile(r"/old", re.IGNORECASE),
    re.compile(r"/debug", re.IGNORECASE),
    re.compile(r"/wp-admin", re.IGNORECASE),
    re.compile(r"/wp-login", re.IGNORECASE),
    re.compile(r"/management", re.IGNORECASE),
    re.compile(r"/actuator", re.IGNORECASE),
    re.compile(r"/swagger", re.IGNORECASE),
    re.compile(r"/graphql", re.IGNORECASE),
    re.compile(r"/health", re.IGNORECASE),
    re.compile(r"/metrics", re.IGNORECASE),
    re.compile(r"/\.well-known/admin", re.IGNORECASE),
    re.compile(r"\.bak$", re.IGNORECASE),
    re.compile(r"\.sql$", re.IGNORECASE),
    re.compile(r"\.zip$", re.IGNORECASE),
]


@router.post("/api/webapp/scan/robots_disallow_disclosure")
@vl_turbo()
@vl_verify()
def scan_robots_disallow_disclosure(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    r = safe_request("GET", base + "/robots.txt",
        headers={"User-Agent": "VulnusLab/1.0"},
        req=req, timeout=8, allow_redirects=True)
    if r is None:
        return standard_response(
            tool="robots_disallow_disclosure", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="No response from /robots.txt")
    if r.status_code != 200:
        return standard_response(
            tool="robots_disallow_disclosure", target=req.target,
            findings=[wrap_finding(
                f"No /robots.txt (HTTP {r.status_code})",
                "POSITIVE", cwe="CWE-200",
                remediation="Either intentionally absent (fine) or hosting "
                            "doesn't serve it. No disclosure via this vector.",
                evidence_marker=f"GET /robots.txt → HTTP {r.status_code}")],
            tests_performed=1, vulnerable=False,
            tests_summary=f"No robots.txt (HTTP {r.status_code})")

    body = r.text or ""
    # Extract all Disallow paths
    paths = []
    for line in body.splitlines()[:500]:
        line = line.strip()
        m = re.match(r"^Disallow:\s*(\S+)", line, re.IGNORECASE)
        if m:
            paths.append(m.group(1))
    # Probe each sensitive entry to see if it actually exists (not 404)
    sensitive_paths = []
    confirmed_live = []
    for p in paths:
        if any(pat.search(p) for pat in SENSITIVE_PATTERNS):
            sensitive_paths.append(p)
            # Quick probe
            r2 = safe_request("GET", base + p,
                headers={"User-Agent": "VulnusLab/1.0"},
                req=req, timeout=6, allow_redirects=False)
            if r2 is not None and r2.status_code in (200, 301, 302, 401, 403):
                confirmed_live.append({"path": p, "status": r2.status_code})

    findings = []
    if confirmed_live:
        findings.append(wrap_finding(
            f"robots.txt advertises {len(confirmed_live)} live sensitive path(s)",
            "MEDIUM", cvss="5.3", cwe="CWE-200", owasp="A05:2021",
            remediation="robots.txt is a roadmap for attackers AS WELL AS crawlers. "
                        "If you DON'T want a path indexed, use HTTP auth + noindex "
                        "meta tag rather than listing in robots.txt. For dead paths, "
                        "remove from robots.txt entirely. For staging/internal: "
                        "host on internal-only domain, not a robots.txt entry.",
            evidence_marker=" | ".join(
                f"{p['path']} (HTTP {p['status']})" for p in confirmed_live[:8]
            )))
    elif sensitive_paths:
        findings.append(wrap_finding(
            f"robots.txt lists {len(sensitive_paths)} sensitive path(s) — but all return 404",
            "LOW", cwe="CWE-200",
            remediation="Paths in robots.txt no longer live. Clean robots.txt — "
                        "old entries give attackers historical-recon hints.",
            evidence_marker=" | ".join(sensitive_paths[:6])))
    else:
        findings.append(wrap_finding(
            f"robots.txt has {len(paths)} Disallow entries, none sensitive",
            "POSITIVE", cwe="CWE-200",
            remediation="Maintain. Avoid adding admin paths.",
            evidence_marker=f"first 5 entries: {paths[:5]}"))

    return standard_response(
        tool="robots_disallow_disclosure", target=req.target, findings=findings,
        tests_performed=1 + len(sensitive_paths),
        vulnerable=bool(confirmed_live),
        tests_summary=f"{len(paths)} disallow entries, {len(sensitive_paths)} sensitive, "
                       f"{len(confirmed_live)} live",
        raw_data={"disallow_entries": paths[:50],
                   "sensitive_listed": sensitive_paths,
                   "live_sensitive": confirmed_live})


def register(app):
    app.include_router(router)

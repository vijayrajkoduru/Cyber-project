"""A05 Security Misconfiguration - passive well-known-path discovery. Self-contained.
Strategy: probe common exposed admin/config/info paths and detect dangerous 200 responses."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import probe_url_async, http_get_async, detect_spa_catchall, is_same_as_canary

router = APIRouter()

# (path, severity_if_200, marker_text, name)
EXPOSED_PATHS = [
    ("/.env",              "CRITICAL", "SECRET", "Exposed .env file"),
    ("/.git/HEAD",         "HIGH",     "ref:",   "Exposed .git repository"),
    ("/.git/config",       "HIGH",     "[core]", "Exposed .git config"),
    ("/phpinfo.php",       "HIGH",     "phpinfo()", "phpinfo() page exposed"),
    ("/server-status",     "HIGH",     "Apache Server Status", "Apache server-status exposed"),
    ("/server-info",       "MEDIUM",   "Server Information", "Apache server-info exposed"),
    ("/.DS_Store",         "MEDIUM",   "",       "macOS .DS_Store exposed"),
    ("/composer.json",     "LOW",      '"require"', "composer.json exposed"),
    ("/package.json",      "LOW",      '"name"',  "package.json exposed"),
    ("/web.config",        "MEDIUM",   "<configuration", "ASP.NET web.config exposed"),
    ("/robots.txt",        "INFO",     "User-agent", "robots.txt present"),
    ("/.well-known/security.txt", "INFO", "Contact:", "security.txt present (good)"),
    ("/wp-config.php.bak", "CRITICAL", "DB_PASSWORD", "WordPress config backup exposed"),
    ("/backup.zip",        "HIGH",     "PK",      "backup.zip exposed"),
]


async def gather(ctx):
    host = str(ctx.host)
    base_url, base = await probe_url_async(host, "/")
    if not base:
        ctx.state["tested"] = 0
        ctx.state["skipped_reason"] = "Target unreachable"
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    ctx.state["probed_paths"] = len(EXPOSED_PATHS)
    # SPA-detect: React/Vue/Angular catch-all returns 200 + HTML shell for
    # any path - and HTML shells often contain substrings like '"name"' from
    # meta tags or JSON-LD blocks, which trips marker-based detection.
    # (User feedback 2026-06-09: /package.json false-positive on SPA target)
    spa = await detect_spa_catchall(base_url)
    ctx.state["spa_detected"] = spa["is_spa"]
    findings = []
    spa_suppressed = []
    for path, sev, marker, name in EXPOSED_PATHS:
        url = f"{base_url}{path}"
        r = await http_get_async(url, timeout=8, read=4000)
        if not r:
            continue
        if r.get("status") != 200:
            continue
        body = r.get("body", "")
        if marker and marker not in body:
            continue
        # SPA suppression: if body matches the SPA canary, the marker hit
        # was just because the shell HTML happens to contain that substring.
        # Real config files would have body uniquely different from the
        # canary's HTML shell.
        if spa["is_spa"] and is_same_as_canary(body, spa["canary_body"]):
            spa_suppressed.append({"path": path, "name": name, "reason": "SPA shell"})
            continue
        # Additional confidence boost for file-format-bound paths: e.g.
        # /package.json must be valid JSON, /web.config must be XML. Reject
        # any response whose content-type or body shape doesn't match.
        ctype = (r.get("headers") or {}).get("content-type", "").lower()
        if path.endswith(".json") and "json" not in ctype and not body.lstrip().startswith("{"):
            spa_suppressed.append({"path": path, "name": name, "reason": "expected JSON, got HTML"})
            continue
        if path.endswith(".config") and "xml" not in ctype and not body.lstrip().startswith("<"):
            spa_suppressed.append({"path": path, "name": name, "reason": "expected XML, got non-XML"})
            continue
        findings.append({"path": path, "severity": sev, "name": name, "marker_seen": bool(marker)})
    ctx.state["exposed"] = findings
    if spa_suppressed:
        ctx.state["spa_suppressed_findings"] = spa_suppressed


def _r_critical(s):
    crit = [f for f in (s.get("exposed") or []) if f["severity"] == "CRITICAL"]
    if not crit:
        return None
    return {"name": f"{len(crit)} CRITICAL exposed config file(s)", "severity": "CRITICAL", "cvss": 9.1,
            "cwe": "CWE-538",
            "evidence": "; ".join(f"{f['path']} ({f['name']})" for f in crit),
            "remediation": "Block these paths at web server / WAF. Remove backup files from webroot. Rotate any leaked secrets."}


def _r_high(s):
    high = [f for f in (s.get("exposed") or []) if f["severity"] == "HIGH"]
    if not high:
        return None
    return {"name": f"{len(high)} HIGH-severity misconfig exposure(s)", "severity": "HIGH", "cvss": 7.5,
            "cwe": "CWE-538",
            "evidence": "; ".join(f"{f['path']}" for f in high),
            "remediation": "Block these paths via web server config (deny /.git, /.env etc)."}


def _r_med(s):
    med = [f for f in (s.get("exposed") or []) if f["severity"] in ("MEDIUM", "LOW")]
    if not med:
        return None
    return {"name": f"{len(med)} medium/low config exposure(s)", "severity": "MEDIUM", "cvss": 5.3,
            "cwe": "CWE-538",
            "evidence": "; ".join(f"{f['path']}" for f in med),
            "remediation": "Restrict access to dev/build artefacts in production."}


FINDING_RULES = [_r_critical, _r_high, _r_med]
INTEL_FIELDS = [("Paths probed", "probed_paths"), ("Exposures", "exposed")]


@router.post("/api/vuln/a05_security_misconfig")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="a05_security_misconfig",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)

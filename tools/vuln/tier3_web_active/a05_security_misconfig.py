"""A05 Security Misconfiguration - passive well-known-path discovery. Self-contained.
Strategy: probe common exposed admin/config/info paths and detect dangerous 200 responses."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import probe_url, http_get

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
    base_url, base = probe_url(host, "/")
    if not base:
        ctx.state["tested"] = 0
        ctx.state["skipped_reason"] = "Target unreachable"
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    ctx.state["probed_paths"] = len(EXPOSED_PATHS)
    findings = []
    for path, sev, marker, name in EXPOSED_PATHS:
        url = f"{base_url}{path}"
        r = http_get(url, timeout=8, read=4000)
        if not r:
            continue
        if r.get("status") != 200:
            continue
        body = r.get("body", "")
        if marker and marker not in body:
            continue
        findings.append({"path": path, "severity": sev, "name": name, "marker_seen": bool(marker)})
    ctx.state["exposed"] = findings


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

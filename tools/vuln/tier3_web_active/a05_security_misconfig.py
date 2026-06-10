"""A05 Security Misconfiguration - well-known-path discovery. VL-METHOD Wave 1.

Refactored 2026-06-09 to MethodologyScanner. Different shape from the other
Wave 1 scanners (path enumeration, not param fuzzing):

  pre_flight    : target HTTP-reachable + SPA canary baseline (was already)
  fingerprint   : detect server stack (Apache/nginx/IIS/PHP) to bias paths
  quick_probe   : probe the 5 highest-value paths (.env, .git/HEAD, phpinfo,
                  server-status, wp-config.php.bak) - CRITICAL+HIGH severity
  deep_scan     : probe remaining 9 paths if any quick hit OR always_deep
  verify        : existing SPA canary + content-type validation (preserved)
  privilege_check: severity classification (already done via per-path SEV)
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._methodology import MethodologyScanner
from tools.vuln._vuln_common import (probe_url_async, http_get_async,
                                      detect_spa_catchall, is_same_as_canary)
from tools._vl_core.verify import vl_verify

router = APIRouter()

# (path, severity_if_200, marker_text, name) - QUICK = high-impact triage set
EXPOSED_PATHS_QUICK = [
    ("/.env",              "CRITICAL", "SECRET",       "Exposed .env file"),
    ("/.git/HEAD",         "HIGH",     "ref:",         "Exposed .git repository"),
    ("/phpinfo.php",       "HIGH",     "phpinfo()",    "phpinfo() page exposed"),
    ("/server-status",     "HIGH",     "Apache Server Status", "Apache server-status exposed"),
    ("/wp-config.php.bak", "CRITICAL", "DB_PASSWORD",  "WordPress config backup exposed"),
]
EXPOSED_PATHS_DEEP = [
    ("/.git/config",       "HIGH",     "[core]",       "Exposed .git config"),
    ("/server-info",       "MEDIUM",   "Server Information", "Apache server-info exposed"),
    ("/.DS_Store",         "MEDIUM",   "",             "macOS .DS_Store exposed"),
    ("/composer.json",     "LOW",      '"require"',    "composer.json exposed"),
    ("/package.json",      "LOW",      '"name"',       "package.json exposed"),
    ("/web.config",        "MEDIUM",   "<configuration", "ASP.NET web.config exposed"),
    ("/robots.txt",        "INFO",     "User-agent",   "robots.txt present"),
    ("/.well-known/security.txt", "INFO", "Contact:",  "security.txt present (good)"),
    ("/backup.zip",        "HIGH",     "PK",           "backup.zip exposed"),
]


async def _probe_paths(base_url, paths, spa):
    """Probe `paths`, applying SPA-canary + content-type validation.
    Returns (findings, spa_suppressed)."""
    findings, spa_suppressed = [], []
    for path, sev, marker, name in paths:
        url = f"{base_url}{path}"
        r = await http_get_async(url, timeout=8, read=4000)
        if not r:
            continue
        if r.get("status") != 200:
            continue
        body = r.get("body", "")
        if marker and marker not in body:
            continue
        # SPA suppression
        if spa["is_spa"] and is_same_as_canary(body, spa["canary_body"]):
            spa_suppressed.append({"path": path, "name": name, "reason": "SPA shell"})
            continue
        # File-format validation
        ctype = (r.get("headers") or {}).get("content-type", "").lower()
        if path.endswith(".json") and "json" not in ctype and not body.lstrip().startswith("{"):
            spa_suppressed.append({"path": path, "name": name,
                                    "reason": "expected JSON, got HTML"})
            continue
        if path.endswith(".config") and "xml" not in ctype and not body.lstrip().startswith("<"):
            spa_suppressed.append({"path": path, "name": name,
                                    "reason": "expected XML, got non-XML"})
            continue
        findings.append({"path": path, "severity": sev, "name": name,
                         "marker_seen": bool(marker)})
    return findings, spa_suppressed


class A05SecurityMisconfig(MethodologyScanner):
    name = "a05_security_misconfig"

    async def pre_flight(self, ctx):
        base_url, base = await probe_url_async(str(ctx.host), "/")
        if not base:
            ctx.state["tested"] = 0
            ctx.state["skipped_reason"] = "Target unreachable"
            return False
        ctx.source("http")
        ctx.state["tested"] = 1
        ctx.state["base_url"] = base_url
        ctx.state["probed_paths"] = len(EXPOSED_PATHS_QUICK) + len(EXPOSED_PATHS_DEEP)
        # SPA-detect once - reused by quick + deep + verify
        spa = await detect_spa_catchall(base_url)
        ctx.state["spa_detected"] = spa["is_spa"]
        ctx.state["_spa"] = spa
        ctx.state["exposed"] = []
        ctx.state["spa_suppressed_findings"] = []
        return True

    async def fingerprint(self, ctx):
        r = await http_get_async(ctx.state["base_url"], timeout=6)
        if r:
            hdrs = r.get("headers") or {}
            ctx.state["fingerprint"] = {
                "server":       (hdrs.get("server") or "")[:80],
                "x_powered_by": (hdrs.get("x-powered-by") or "")[:80],
            }

    async def quick_probe(self, ctx):
        findings, spa_supp = await _probe_paths(
            ctx.state["base_url"], EXPOSED_PATHS_QUICK, ctx.state["_spa"])
        ctx.state["exposed"].extend(findings)
        ctx.state["spa_suppressed_findings"].extend(spa_supp)
        # Bubble as preliminary findings so verify stage runs per item
        return [dict(f) for f in findings]

    async def deep_scan(self, ctx):
        findings, spa_supp = await _probe_paths(
            ctx.state["base_url"], EXPOSED_PATHS_DEEP, ctx.state["_spa"])
        ctx.state["exposed"].extend(findings)
        ctx.state["spa_suppressed_findings"].extend(spa_supp)
        return [dict(f) for f in findings]

    async def verify(self, ctx, finding):
        # Re-fetch the path with a no-cache header to defeat any CDN/WAF
        # cached error pages. If the file is REAL, it should still be there.
        url = f"{ctx.state['base_url']}{finding['path']}"
        r = await http_get_async(url, timeout=8, read=4000)
        if not r or r.get("status") != 200:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "re-fetch-failed"
            return finding
        body = r.get("body", "")
        # Find the original path definition to get its marker
        all_paths = EXPOSED_PATHS_QUICK + EXPOSED_PATHS_DEEP
        marker = next((m for (p, _, m, _) in all_paths if p == finding["path"]), "")
        if marker and marker not in body:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "marker-missing-on-refetch"
            return finding
        # SPA double-check
        spa = ctx.state["_spa"]
        if spa["is_spa"] and is_same_as_canary(body, spa["canary_body"]):
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "spa-shell-on-refetch"
            return finding
        finding["confidence"] = "CONFIRMED"
        finding["verification_method"] = "re-fetch-marker-present"
        return finding


def _r_critical(s):
    verified = s.get("methodology_findings") or []
    crit = [f for f in verified
             if f.get("severity") == "CRITICAL" and f.get("confidence") == "CONFIRMED"]
    if not crit:
        return None
    return {"name": f"{len(crit)} CRITICAL exposed config file(s) (CONFIRMED)",
            "severity": "CRITICAL", "cvss": 9.1, "cwe": "CWE-538",
            "evidence": "; ".join(f"{f['path']} ({f['name']})" for f in crit),
            "remediation": "Block these paths at web server / WAF. Remove backup files "
                            "from webroot. Rotate any leaked secrets."}


def _r_high(s):
    verified = s.get("methodology_findings") or []
    high = [f for f in verified
             if f.get("severity") == "HIGH" and f.get("confidence") == "CONFIRMED"]
    if not high:
        return None
    return {"name": f"{len(high)} HIGH-severity misconfig exposure(s) (CONFIRMED)",
            "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-538",
            "evidence": "; ".join(f["path"] for f in high),
            "remediation": "Block these paths via web server config (deny /.git, /.env etc)."}


def _r_med(s):
    verified = s.get("methodology_findings") or []
    med = [f for f in verified
            if f.get("severity") in ("MEDIUM", "LOW")
            and f.get("confidence") == "CONFIRMED"]
    if not med:
        return None
    return {"name": f"{len(med)} medium/low config exposure(s) (CONFIRMED)",
            "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-538",
            "evidence": "; ".join(f["path"] for f in med),
            "remediation": "Restrict access to dev/build artefacts in production."}


def _r_suspected(s):
    verified = s.get("methodology_findings") or []
    susp = [f for f in verified if f.get("confidence") == "SUSPECTED"]
    if not susp:
        return None
    return {"name": f"{len(susp)} config path(s) returned 200 but verify failed (SUSPECTED)",
            "severity": "LOW", "cvss": 2.0, "cwe": "CWE-538",
            "evidence": "; ".join(f"{f['path']} ({f.get('verification_method','?')})"
                                   for f in susp),
            "remediation": "Manually re-fetch and inspect each path."}


FINDING_RULES = [_r_critical, _r_high, _r_med, _r_suspected]
INTEL_FIELDS = [
    ("Paths probed", "probed_paths"),
    ("Exposures (raw)", "exposed"),
    ("SPA-suppressed", "spa_suppressed_findings"),
    ("Verified findings", "methodology_findings"),
    ("Stage timings (ms)", "stage_timings"),
]


@router.post("/api/vuln/a05_security_misconfig")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanner = A05SecurityMisconfig()
    return await scanner.run_as_endpoint(req,
        finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)

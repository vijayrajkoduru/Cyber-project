"""Vertical access (admin endpoint) - passive privileged-action endpoint enumeration.
Self-contained. Strategy: probe destructive/admin-only API paths, check if they return
200 without authentication (full privesc) or 401/403 (auth correctly required)."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import probe_url_async, http_get_async, http_post_async, detect_spa_catchall, is_same_as_canary

router = APIRouter()

# Privileged action endpoints typically requiring admin auth
PRIV_PATHS_GET = ["/api/admin/users", "/api/admin/config", "/admin/api/users",
                    "/api/v1/admin", "/api/system", "/api/internal"]
PRIV_PATHS_POST = ["/api/admin/users", "/api/users"]  # Test if POST creates user without auth


async def gather(ctx):
    host = str(ctx.host)
    base_url, base = await probe_url_async(host, "/")
    if not base:
        ctx.state["tested"] = 0
        ctx.state["skipped_reason"] = "Target unreachable"
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    # SPA-detect: React/Vue/Angular catch-all routing serves index.html for
    # every path. Without this check, every 200 response gets flagged as
    # "exposed admin endpoint" even when it's just the SPA shell.
    # (User feedback 2026-06-09: 5 false-positives on app.vulnuslab.com)
    spa = await detect_spa_catchall(base_url)
    ctx.state["spa_detected"] = spa["is_spa"]
    if spa["is_spa"]:
        ctx.state["spa_note"] = "SPA catch-all routing detected - suppressing 200-only findings; only real API responses (JSON, non-shell HTML) flagged."
    exposed = []
    protected = []
    spa_suppressed = []
    for path in PRIV_PATHS_GET:
        url = f"{base_url}{path}"
        r = await http_get_async(url, timeout=6, read=4000)
        if not r:
            continue
        status = r.get("status", 0)
        if status == 200:
            body = r.get("body", "")
            # SPA suppression: if response body matches the SPA canary, skip.
            if spa["is_spa"] and is_same_as_canary(body, spa["canary_body"]):
                spa_suppressed.append({"method": "GET", "path": path, "reason": "SPA shell"})
                continue
            # Real API confidence boost: require JSON content-type OR clearly
            # non-HTML body to count as a real privileged endpoint.
            ctype = (r.get("headers") or {}).get("content-type", "").lower()
            looks_json = "json" in ctype or body.strip().startswith(("{", "["))
            if len(body[:300]) > 50 and looks_json:
                exposed.append({"method": "GET", "path": path, "evidence": "200 with JSON body"})
        elif status in (401, 403):
            protected.append({"method": "GET", "path": path, "status": status})
    for path in PRIV_PATHS_POST:
        url = f"{base_url}{path}"
        r = await http_post_async(url, data=b'{}', headers={"Content-Type": "application/json"}, timeout=6)
        if not r:
            continue
        status = r.get("status", 0)
        body = (r.get("body", "") or "").strip()
        if status in (200, 201) and body:
            # Same SPA + JSON-confidence check on POST responses.
            if spa["is_spa"] and is_same_as_canary(body, spa["canary_body"]):
                spa_suppressed.append({"method": "POST", "path": path, "reason": "SPA shell"})
                continue
            ctype = (r.get("headers") or {}).get("content-type", "").lower()
            looks_json = "json" in ctype or body.startswith(("{", "["))
            if looks_json:
                exposed.append({"method": "POST", "path": path, "evidence": f"status {status} with JSON body"})
    ctx.state["exposed_privileged"] = exposed
    ctx.state["protected_privileged"] = protected
    if spa_suppressed:
        ctx.state["spa_suppressed_findings"] = spa_suppressed


def _r_exposed(s):
    exp = s.get("exposed_privileged") or []
    if not exp:
        return None
    return {"name": f"{len(exp)} privileged endpoint(s) accessible without authentication",
            "severity": "CRITICAL", "cvss": 9.1, "cwe": "CWE-285",
            "evidence": "; ".join(f"{e['method']} {e['path']}" for e in exp),
            "remediation": "Require authentication AND admin-role authorisation on every /admin and /api/admin path."}


FINDING_RULES = [_r_exposed]
INTEL_FIELDS = [("Exposed privileged", "exposed_privileged"), ("Auth-protected", "protected_privileged")]


@router.post("/api/vuln/vertical_access_admin")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="vertical_access_admin",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)

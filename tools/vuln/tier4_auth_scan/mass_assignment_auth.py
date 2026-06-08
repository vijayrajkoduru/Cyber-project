"""Mass assignment - passive JSON-API surface check. Self-contained.
Strategy: probe API endpoints that accept JSON, check if they accept arbitrary fields
without 400 error (binding rejects unknown fields = good). Detection only, no escalation."""
import json
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import probe_url_async, http_post_async

router = APIRouter()

PROBE_PATHS = ["/api/users", "/api/v1/users", "/api/register", "/register",
                "/api/signup", "/api/account", "/api/profile"]
PROBE_BODY = json.dumps({"_vlcanary": "test", "is_admin": True, "role": "admin",
                           "isSuperUser": True, "verified": True}).encode()


async def gather(ctx):
    host = str(ctx.host)
    base_url, base = await probe_url_async(host, "/")
    if not base:
        ctx.state["tested"] = 0
        ctx.state["skipped_reason"] = "Target unreachable"
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    ctx.state["probed_paths"] = len(PROBE_PATHS)
    accepting = []
    rejecting = []
    for path in PROBE_PATHS:
        url = f"{base_url}{path}"
        r = await http_post_async(url, data=PROBE_BODY,
                       headers={"Content-Type": "application/json"}, timeout=8)
        if not r:
            continue
        status = r.get("status", 0)
        body = r.get("body", "")
        # 4xx with "field" in body = binding rejects unknown fields (good)
        if status in (400, 422) and ("field" in body.lower() or "unknown" in body.lower() or "invalid" in body.lower()):
            rejecting.append({"path": path, "status": status})
        # 2xx = accepted the payload INCLUDING privileged fields = mass-assignment surface
        elif 200 <= status < 300:
            accepting.append({"path": path, "status": status})
    ctx.state["mass_assign_accepting"] = accepting
    ctx.state["mass_assign_rejecting"] = rejecting


def _r_ma(s):
    acc = s.get("mass_assign_accepting") or []
    if not acc:
        return None
    return {"name": f"{len(acc)} JSON endpoint(s) accept arbitrary unprivileged fields",
            "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-915",
            "evidence": f"Endpoints returning 2xx after POSTing privileged fields: {', '.join(a['path'] for a in acc)}",
            "remediation": "Use explicit allow-list binding (DTO / Serializer fields = [...]) on every API endpoint. Never bind directly from request body to model."}


FINDING_RULES = [_r_ma]
INTEL_FIELDS = [("Paths probed", "probed_paths"), ("Accepting", "mass_assign_accepting"), ("Rejecting", "mass_assign_rejecting")]


@router.post("/api/vuln/mass_assignment_auth")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="mass_assignment_auth",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)

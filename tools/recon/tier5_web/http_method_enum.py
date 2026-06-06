"""http_method_enum — VL-FORGE Recon §5 Web App Recon (real, zero-FP)."""
import asyncio, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url, set_auth_from_req


router = APIRouter()

async def gather(ctx: ScanContext):
    base = base_url(ctx.host)
    # Fire OPTIONS + TRACE concurrently — independent probes, no order dep.
    (code, hdrs, _), (trace_code, _, _) = await asyncio.gather(
        fetch(base, method="OPTIONS"),
        fetch(base, method="TRACE", timeout=4),
    )
    allow = hdrs.get("Allow","") or hdrs.get("allow","") or hdrs.get("Access-Control-Allow-Methods","") or hdrs.get("access-control-allow-methods","")
    methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
    dangerous = [m for m in methods if m in ("PUT","DELETE","TRACE","CONNECT","PATCH")]
    ctx.state["options_status"] = code
    ctx.state["methods_allowed"] = methods
    ctx.state["dangerous_methods"] = dangerous
    ctx.state["trace_responds"] = trace_code in (200, 405)  # 405 means not 200, both inform
    ctx.state["trace_enabled"] = trace_code == 200
    ctx.source("OPTIONS preflight + TRACE probe")

RULES = [
    lambda s: {"name":"HTTP TRACE method enabled (XST risk)","severity":"MEDIUM",
        "evidence":"TRACE returned 200 — Cross-Site Tracing (XST) can expose cookies/headers",
        "remediation":"Disable TRACE: nginx 'if ($request_method = TRACE) { return 405; }'",
        "cwe":"CWE-693","owasp":"A05:2021"
    } if s.get("trace_enabled") else None,
    lambda s: {"name":"Dangerous HTTP methods exposed","severity":"LOW",
        "evidence":f"Methods allowed: {s.get('dangerous_methods')}",
        "remediation":"Restrict to GET/POST/HEAD only unless app needs others. Deny PUT/DELETE/TRACE at proxy.",
        "cwe":"CWE-650","owasp":"A05:2021"
    } if s.get("dangerous_methods") else None,
]

@router.post("/api/recon/http_method_enum")
async def recon_http_method_enum(req: ScanRequest, _=Depends(verify_scan_quota)):
    set_auth_from_req(req)
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="http_method_enum",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Methods Allowed","methods_allowed"),("Dangerous Methods","dangerous_methods"),("Trace Enabled","trace_enabled")])

def register(app):
    app.include_router(router)

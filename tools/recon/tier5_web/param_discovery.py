"""param_discovery — VL-FORGE Recon §5 Web App Recon (real, zero-FP)."""
import asyncio, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url, set_auth_from_req


router = APIRouter()

# Curated baseline of common HTTP parameter names, used to flag interesting
# discoveries and seed mining when the target page is param-poor.
_COMMON_PARAMS = [
    "id", "user_id", "email", "username", "password", "token", "api_key",
    "auth", "session", "redirect", "url", "callback", "next", "return_url",
    "query", "q", "search", "filter", "sort", "page", "limit", "offset",
    "lang", "locale", "format", "type", "category", "action", "method",
    "debug", "verbose", "admin", "role", "file", "path", "include",
]


async def gather(ctx: ScanContext):
    base = base_url(ctx.host)
    # Fetch root + a debug-flavoured path concurrently; sites often echo
    # additional params on /api or /admin probe responses.
    async def _fetch(u):
        _, _, b = await fetch(u)
        return (b or b"").decode("utf-8", "ignore")
    texts = await asyncio.gather(_fetch(base), _fetch(base.rstrip("/") + "/api"))
    text = "\n".join(texts)
    form_params = set()
    for m in re.finditer(r'<input[^>]+name=[\"\']([^\"\']+)', text, re.I):
        form_params.add(m.group(1))
    js_params = set(re.findall(r'[\"\']([a-z][a-zA-Z0-9_]{2,30})[\"\']\s*:', text))
    interesting = sorted((form_params | js_params) & set(_COMMON_PARAMS))
    ctx.state["form_params"] = sorted(form_params)[:40]
    ctx.state["js_params"] = sorted(js_params)[:40]
    ctx.state["interesting_params"] = interesting
    ctx.source("HTML form + JS literal extraction (curated baseline match)")

RULES = [

]

@router.post("/api/recon/param_discovery")
async def recon_param_discovery(req: ScanRequest, _=Depends(verify_scan_quota)):
    set_auth_from_req(req)
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="param_discovery",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Form Params","form_params"),("Js Params","js_params")])

def register(app):
    app.include_router(router)

"""Web Cache Poisoning - passive cache-key + header reflection check. Self-contained.
Strategy: inject a benign canary in X-Forwarded-Host / X-Forwarded-Proto, check if it
reflects in response body. Conservative — flags only when reflection + cacheable response."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import probe_url, http_get_h

router = APIRouter()

CANARY = "vlcache9k.example.com"


async def gather(ctx):
    host = str(ctx.host)
    base_url, base = probe_url(host, "/")
    if not base:
        ctx.state["tested"] = 0
        ctx.state["skipped_reason"] = "Target unreachable"
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    reflected_in = []
    test_headers = [
        ("X-Forwarded-Host", CANARY),
        ("X-Forwarded-Proto", "javascript"),
        ("X-Host", CANARY),
        ("X-Original-URL", f"/?{CANARY}"),
        ("X-Rewrite-URL", f"/?{CANARY}"),
    ]
    for hn, hv in test_headers:
        r = http_get_h(base_url, headers={hn: hv}, timeout=8)
        if not r:
            continue
        body = r.get("body", "")
        cache_ctrl = (r.get("headers") or {}).get("cache-control", "") or ""
        # Find canary in body AND response is cacheable
        if CANARY in body or "javascript" in body.lower():
            if "no-store" not in cache_ctrl.lower() and "private" not in cache_ctrl.lower():
                reflected_in.append({"header": hn, "value": hv, "cache": cache_ctrl[:60]})
    ctx.state["cache_poison_hits"] = reflected_in


def _r_cache(s):
    hits = s.get("cache_poison_hits") or []
    if not hits:
        return None
    return {"name": f"Cacheable response reflects {len(hits)} unkeyed header(s) - cache poisoning surface",
            "severity": "MEDIUM", "cvss": 5.4, "cwe": "CWE-444",
            "evidence": "; ".join(f"{h['header']}: {h['value']}" for h in hits),
            "remediation": "Add these headers to Vary or remove them from response builder. Use 'no-store' for personalised responses."}


FINDING_RULES = [_r_cache]
INTEL_FIELDS = [("Cache poison hits", "cache_poison_hits")]


@router.post("/api/vuln/web_cache_poisoning")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="web_cache_poisoning",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)

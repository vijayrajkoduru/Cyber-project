"""Webapp: Prototype Pollution detection (Node.js)."""
import asyncio
import secrets
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, safe_get, wrap_finding, standard_response
from tools._vl_core.spa_canary import detect_spa_catchall_sync, is_same_as_canary
from tools._vl_core.verify import vl_verify

router = APIRouter()

# AI-curated 87-entry list — gadget patterns specific to lodash/mongoose/jquery/etc.
try:
    from tools._payloads.prototype_pollution_payloads import PROTOTYPE_POLLUTION_PAYLOADS as _AI_PP_PAYLOADS
except Exception:
    _AI_PP_PAYLOADS = []


@router.post("/api/webapp/prototype_pollution")
@vl_verify()
async def webapp_prototype_pollution(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    tests = 0
    canary = secrets.token_hex(8)
    # VL-VERIFY: SPA-canary FP guard — if /api/config returns the SPA shell,
    # any "leak" is just the shell HTML, not real pollution.
    spa = detect_spa_catchall_sync(base)
    spa_suppressed = []

    payloads = [
        f"__proto__[ppMarker]={canary}",
        f"__proto__.ppMarker={canary}",
        f"constructor[prototype][ppMarker]={canary}",
        f"constructor.prototype.ppMarker={canary}",
    ]
    # Append AI-curated query_string variants, substituting our canary into ppMarker= context
    for _ai in _AI_PP_PAYLOADS[:15]:
        if not isinstance(_ai, dict): continue
        if _ai.get("context") != "query_string": continue
        raw = _ai.get("payload", "")
        if "=" in raw and "__proto__" in raw or "constructor" in raw:
            # Substitute the value side with our canary so we can detect leak
            key = raw.split("=", 1)[0]
            payloads.append(f"{key}={canary}")
    
    suspect = []
    tests += len(payloads)

    async def _probe(p):
        # Send pollution payload
        r1 = await asyncio.to_thread(safe_get, f"{base}/?{p}", req=req, timeout=8)
        if r1 is None:
            return None
        # Fetch a different endpoint to check if pollution persisted
        r2 = await asyncio.to_thread(safe_get, f"{base}/api/config", req=req, timeout=6)
        if r2 is None:
            r2 = await asyncio.to_thread(safe_get, f"{base}/health", req=req, timeout=6)
        if r2 is None:
            return None
        # If canary appears in unrelated endpoint response, pollution worked
        if canary in (r2.text or ""):
            return (p, r2)
        return None

    results = await asyncio.gather(
        *[_probe(p) for p in payloads],
        return_exceptions=True)
    # Preserve original break-on-first-hit (only flag first matching payload)
    for res in results:
        if isinstance(res, BaseException) or res is None:
            continue
        p, r2 = res
        # VL-VERIFY: if the "leak" endpoint is just the SPA shell, the canary
        # is in the response only because the SPA shell embeds the request URL
        # — not because pollution actually persisted.
        if spa["is_spa"] and is_same_as_canary(r2.text or "", spa["canary_body"]):
            spa_suppressed.append(p)
            continue
        suspect.append({"payload": p, "leaked_at": r2.url if hasattr(r2,"url") else "unknown"})
        findings.append(wrap_finding(
            f"Prototype Pollution confirmed via '{p}' - canary leaked to unrelated endpoint",
            "HIGH",
            cvss="8.1", cwe="CWE-1321",
            cwe_name="Improperly Controlled Modification of Object Prototype Attributes",
            owasp="A08:2021",
            remediation="Use Object.create(null) for user-controlled object merging. Validate keys against allow-list. Upgrade lodash >= 4.17.12, jQuery >= 3.5.0.",
            evidence_marker=f"GET ?{p} -> canary '{canary}' appeared in subsequent /api/config or /health response",
        ))
        break

    summary = f"{tests} prototype pollution probes with unique canary"
    if spa_suppressed:
        summary += f"; {len(spa_suppressed)} SPA-shell suppression(s)"
    return standard_response(
        tool="prototype_pollution", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=summary,
        raw_data={"prototype_pollution": {"canary": canary, "suspect": suspect,
                                           "spa_catchall": spa["is_spa"],
                                           "spa_suppressed_payloads": spa_suppressed}},
    )


def register(app):
    app.include_router(router)

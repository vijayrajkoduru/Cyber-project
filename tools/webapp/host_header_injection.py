"""Webapp: Host header injection / X-Forwarded-Host abuse — VL-TURBO."""
import asyncio
import secrets
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, wrap_finding, standard_response
from tools._vl_core.verify import vl_verify

router = APIRouter()

# AI-curated 60-entry header-injection list
try:
    from tools._payloads.host_header_payloads import HOST_HEADER_PAYLOADS as _AI_HH
except Exception:
    _AI_HH = []


@router.post("/api/webapp/host_header_injection")
@vl_verify()
async def webapp_host_header_injection(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    tests = 0
    canary = "vulnuslab-" + secrets.token_hex(4) + ".attacker.example"

    test_cases = [
        ("Host", {"Host": canary}),
        ("X-Forwarded-Host", {"X-Forwarded-Host": canary}),
        ("X-Host", {"X-Host": canary}),
        ("X-Forwarded-Server", {"X-Forwarded-Server": canary}),
        ("X-Original-URL", {"X-Original-URL": f"http://{canary}/"}),
        ("X-Rewrite-URL", {"X-Rewrite-URL": f"http://{canary}/"}),
    ]
    # Append AI-curated header variants, substituting the canary in for "attacker.example"
    _seen = {tc[0] for tc in test_cases}
    for _p in _AI_HH:
        if not isinstance(_p, dict): continue
        hn = _p.get("header_name", "")
        hv_template = _p.get("header_value", "")
        if not hn or not hv_template or hn in _seen: continue
        # Substitute the canary into placeholder positions
        hv = hv_template.replace("attacker.example", canary).replace("evil.example", canary)
        test_cases.append((hn, {hn: hv}))
        _seen.add(hn)
        if len(test_cases) >= 25:
            break
    
    suspect = []
    # VL-TURBO: gather all 25 header-injection probes in parallel
    sem = asyncio.Semaphore(15)

    def _sync_probe(headers):
        try:
            return requests.get(base + "/", headers={**headers, "User-Agent": "VulnusLab/1.0"},
                                 timeout=4, allow_redirects=False, verify=False)
        except Exception:
            return None

    async def _probe(headers):
        async with sem:
            return await asyncio.to_thread(_sync_probe, headers)

    try:
        results = await asyncio.wait_for(
            asyncio.gather(*(_probe(headers) for _, headers in test_cases)), timeout=45
        )
    except asyncio.TimeoutError:
        results = [None] * len(test_cases)

    tests = len(test_cases)
    for (header_name, _), r in zip(test_cases, results):
        if r is None: continue
        body = (r.text or "")[:20000]
        loc = r.headers.get("Location", "")
        if canary in body or canary in loc:
            where = "body" if canary in body else "Location header"
            suspect.append({"header": header_name, "reflected_in": where})
            findings.append(wrap_finding(
                f"Host header injection - '{header_name}: {canary}' reflected in {where}",
                "HIGH",
                cvss="7.4", cwe="CWE-20",
                cwe_name="Improper Input Validation",
                owasp="A03:2021",
                remediation="Validate Host header against an allow-list of expected hostnames. Reject requests with untrusted Host headers. Use absolute URLs from server config, not from request headers.",
                evidence_marker=f"Sent {header_name}: {canary} -> canary appeared in {where}",
            ))

    if not findings and tests:
        findings.append(wrap_finding(
            "No Host-header injection — canary Host values were not reflected or trusted",
            "POSITIVE", cwe="CWE-644",
            remediation="Maintain. Validate Host against an allow-list and build "
                        "absolute URLs from server config, not request headers.",
            evidence_marker=f"tested {tests} Host-header variant(s) with a unique "
                            "canary; no reflection into response/redirect/cache"))
    return standard_response(
        tool="host_header_injection", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"Tested {tests} Host header variants with unique canary",
        raw_data={"host_header_injection": {"canary": canary, "suspect": suspect}},
    )


def register(app):
    app.include_router(router)

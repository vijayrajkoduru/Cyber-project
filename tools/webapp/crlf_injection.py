"""Webapp: CRLF injection (header splitting via %0d%0a) — VL-TURBO async-parallel."""
import asyncio
import secrets
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, wrap_finding, standard_response

router = APIRouter()

_TEST_PARAMS = ["redirect","url","return","next","callback","redir","redirect_uri","u","link"]

# AI-curated 60-entry CRLF payload list — each entry: {payload, category, severity}
# Substituted into the canary template at scan time to combine AI breadth + freshness-check.
try:
    from tools._payloads.crlf_injection_payloads import CRLF_INJECTION_PAYLOADS as _AI_CRLF_PAYLOADS
    _AI_CRLF_RAW = [p.get("payload","") for p in _AI_CRLF_PAYLOADS if isinstance(p, dict) and p.get("payload")]
except Exception:
    _AI_CRLF_RAW = []


@router.post("/api/webapp/crlf_injection")
async def webapp_crlf_injection(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    tests = 0
    canary_name = "vlcrlf" + secrets.token_hex(4)
    canary_value = "polluted-" + secrets.token_hex(4)
    
    payloads = [
        f"%0d%0aSet-Cookie:%20{canary_name}={canary_value}",
        f"%0aSet-Cookie:%20{canary_name}={canary_value}",
        f"%E5%98%8A%E5%98%8DSet-Cookie:%20{canary_name}={canary_value}",  # UTF-8 CRLF bypass
    ]
    # Append AI-curated CRLF variants — combine each AI sequence with the canary
    # so we still catch echo even if scanner doesn't know the exact AI payload shape.
    for ai in _AI_CRLF_RAW[:15]:  # cap to keep wave size sane
        if "%0d%0a" in ai or "%0a" in ai or "\r\n" in ai:
            payloads.append(f"{ai}Set-Cookie:%20{canary_name}={canary_value}")
    
    suspect = []
    # VL-TURBO: gather all (param, payload) probes in parallel via Semaphore(20)
    sem = asyncio.Semaphore(20)

    def _sync_probe(url):
        try:
            return requests.get(url, timeout=4, allow_redirects=False, verify=False,
                                 headers={"User-Agent": "VulnusLab/1.0"})
        except Exception:
            return None

    async def _probe(url):
        async with sem:
            return await asyncio.to_thread(_sync_probe, url)

    probe_meta = []  # (param, payload, url)
    for param in _TEST_PARAMS:
        for p in payloads:
            url = f"{base}/?{param}=foo{p}"
            probe_meta.append((param, p, url))
    try:
        results = await asyncio.wait_for(
            asyncio.gather(*(_probe(u) for _, _, u in probe_meta)), timeout=60
        )
    except asyncio.TimeoutError:
        results = [None] * len(probe_meta)

    tests = len(probe_meta)
    seen_params = set()
    for (param, p, url), r in zip(probe_meta, results):
        if r is None or param in seen_params: continue
        for hk, hv in r.headers.items():
            if hk.lower() == "set-cookie" and canary_name in hv and canary_value in hv:
                seen_params.add(param)
                suspect.append({"param": param, "payload": p, "header": f"{hk}: {hv[:80]}"})
                findings.append(wrap_finding(
                    f"CRLF injection - parameter '{param}' allows header injection via %0d%0a",
                    "HIGH",
                    cvss="7.5", cwe="CWE-93",
                    cwe_name="Improper Neutralization of CRLF Sequences (HTTP Response Splitting)",
                    owasp="A03:2021",
                    remediation=("Strip or reject \\r and \\n characters in any user input that flows "
                                 "into response headers (Location, Set-Cookie, custom headers). Most "
                                 "modern frameworks block this automatically - if you see this, you "
                                 "are likely concatenating user input into raw HTTP responses."),
                    evidence_marker=f"GET {url} -> response includes injected Set-Cookie: {canary_name}={canary_value}",
                ))
                break

    return standard_response(
        tool="crlf_injection", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"{tests} CRLF probes across {len(_TEST_PARAMS)} params x {len(payloads)} encodings (parallel)",
        raw_data={"crlf_injection": {"suspect": suspect, "canary": canary_name}},
    )


def register(app):
    app.include_router(router)

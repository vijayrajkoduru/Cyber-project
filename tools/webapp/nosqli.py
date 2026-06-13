"""Webapp: NoSQL injection (MongoDB operator injection)."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, safe_get, wrap_finding, standard_response
from tools._vl_core.spa_canary import detect_spa_catchall_sync
from tools._vl_core.verify import vl_verify

router = APIRouter()

_PARAMS = ["username","user","email","login","id","search","q","name","filter"]
_FALLBACK_PAYLOADS = [
    ("$ne",    "[$ne]=1",       "MongoDB $ne (not-equal) - bypasses equality filters"),
    ("$regex", "[$regex]=.*",   "MongoDB $regex - matches any value"),
    ("$gt",    "[$gt]=",        "MongoDB $gt (greater-than) - bypasses comparison filters"),
    ("$where", "[$where]=1==1", "MongoDB $where - JS expression evaluation"),
]
# AI-curated 131-entry payload list — extract query-string operator-injection
# variants. Most AI entries are json_body, but we mine MongoDB operators from
# them and synthesize query-string equivalents the scanner can probe with.
try:
    from tools._payloads.nosqli_payloads import NOSQLI_PAYLOADS as _AI_NOSQLI
    import re as _re_n
    _PAYLOADS = list(_FALLBACK_PAYLOADS)
    seen_ops = {p[0] for p in _PAYLOADS}
    # Extract every distinct $operator pattern seen in AI payloads
    for _p in _AI_NOSQLI:
        if not isinstance(_p, dict): continue
        payload_str = _p.get("payload", "")
        # Mine $operator names: $ne, $gt, $regex, $where, $exists, $in, $or, etc.
        for op in _re_n.findall(r"\$[a-z]{2,12}", payload_str):
            if op in seen_ops: continue
            cat = _p.get("category", "ai")
            # Synthesize a generic query-string probe for this operator
            qs_payload = f"[{op}]=1" if op != "$where" else f"[{op}]=1==1"
            _PAYLOADS.append((op, qs_payload, f"AI-curated MongoDB {op} ({cat})"))
            seen_ops.add(op)
    _PAYLOADS = _PAYLOADS[:25]
except Exception:
    _PAYLOADS = _FALLBACK_PAYLOADS


@router.post("/api/webapp/nosqli")
@vl_verify()
async def webapp_nosqli(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    spa = detect_spa_catchall_sync(base)
    findings = []
    tests = 0

    async def _fetch(url):
        return await asyncio.to_thread(safe_get, url, req=req, timeout=8)

    # Stage 1: fetch baselines for all params in parallel
    baselines = await asyncio.gather(
        *[_fetch(f"{base}/?{param}=normalvalue") for param in _PARAMS],
        return_exceptions=True)

    # Stage 2: for each param with a valid baseline, fan-out payload probes
    async def _probe_param(param, baseline):
        if isinstance(baseline, BaseException) or baseline is None:
            return None
        b_size = len(baseline.content)
        b_status = baseline.status_code
        # Fire all payloads in parallel for this param
        urls = [(op_name, payload_str, desc,
                 f"{base}/?{param}{payload_str}")
                for op_name, payload_str, desc in _PAYLOADS]
        rs = await asyncio.gather(*[_fetch(u[3]) for u in urls],
                                   return_exceptions=True)
        # Preserve original break-on-first-hit-per-param
        for (op_name, payload_str, desc, _u), r in zip(urls, rs):
            if isinstance(r, BaseException) or r is None:
                continue
            if r.status_code != b_status:
                continue
            if abs(len(r.content) - b_size) < 100:
                continue
            return (param, op_name, payload_str, desc, b_size, len(r.content))
        return None

    param_results = await asyncio.gather(
        *[_probe_param(param, baseline)
          for param, baseline in zip(_PARAMS, baselines)],
        return_exceptions=True)
    # Count tests: one baseline per param + one per payload per param-with-baseline
    for baseline in baselines:
        if isinstance(baseline, BaseException) or baseline is None:
            continue
        tests += len(_PAYLOADS)
    for pres in param_results:
        if isinstance(pres, BaseException) or pres is None:
            continue
        param, op_name, payload_str, desc, b_size, r_size = pres
        findings.append(wrap_finding(
            f"NoSQL injection - parameter '{param}' processes MongoDB '{op_name}' operator",
            "HIGH",
            cvss="8.6", cwe="CWE-943",
            cwe_name="Improper Neutralization of Special Elements in Data Query Logic",
            owasp="A03:2021",
            remediation="Validate input as a string before passing to MongoDB. Reject any value containing $ characters or object structures. Use parameterized queries.",
            evidence_marker=f"GET ?{param}=normalvalue ({b_size}B) vs GET ?{param}{payload_str} ({r_size}B) - significant size delta ({desc})",
        ))

    if not findings and tests:
        findings.append(wrap_finding(
            "No NoSQL injection — operator payloads did not change query behavior",
            "POSITIVE", cwe="CWE-943",
            remediation="Maintain. Enforce scalar types and reject query operators in "
                        "user input. Re-test after data-access changes.",
            evidence_marker=f"{tests} NoSQL probe(s) across {len(_PARAMS)} param(s) x "
                            f"{len(_PAYLOADS)} operator(s); no injection effect"))
    return standard_response(
        tool="nosqli", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"{tests} NoSQL probes across {len(_PARAMS)} params x {len(_PAYLOADS)} operators",
        raw_data={"nosqli": {"operators_tested": [op for op,_,_ in _PAYLOADS],
                                "spa_catchall": spa["is_spa"]}},
    )


def register(app):
    app.include_router(router)

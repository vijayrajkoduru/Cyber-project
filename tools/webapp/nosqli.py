"""Webapp: NoSQL injection (MongoDB operator injection)."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, safe_get, wrap_finding, standard_response

router = APIRouter()

_PARAMS = ["username","user","email","login","id","search","q","name","filter"]
_PAYLOADS = [
    ("$ne",    "[$ne]=1",       "MongoDB $ne (not-equal) - bypasses equality filters"),
    ("$regex", "[$regex]=.*",   "MongoDB $regex - matches any value"),
    ("$gt",    "[$gt]=",        "MongoDB $gt (greater-than) - bypasses comparison filters"),
    ("$where", "[$where]=1==1", "MongoDB $where - JS expression evaluation"),
]


@router.post("/api/webapp/nosqli")
async def webapp_nosqli(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    tests = 0
    for param in _PARAMS:
        baseline = safe_get(f"{base}/?{param}=normalvalue", req=req, timeout=8)
        if baseline is None:
            continue
        b_size = len(baseline.content)
        b_status = baseline.status_code
        for op_name, payload_str, desc in _PAYLOADS:
            tests += 1
            r = safe_get(f"{base}/?{param}{payload_str}", req=req, timeout=8)
            if r is None:
                continue
            if r.status_code != b_status:
                continue
            # If response is significantly different, suggests operator was processed
            if abs(len(r.content) - b_size) < 100:
                continue
            findings.append(wrap_finding(
                f"NoSQL injection - parameter '{param}' processes MongoDB '{op_name}' operator",
                "HIGH",
                cvss="8.6", cwe="CWE-943",
                cwe_name="Improper Neutralization of Special Elements in Data Query Logic",
                owasp="A03:2021",
                remediation="Validate input as a string before passing to MongoDB. Reject any value containing $ characters or object structures. Use parameterized queries.",
                evidence_marker=f"GET ?{param}=normalvalue ({b_size}B) vs GET ?{param}{payload_str} ({len(r.content)}B) - significant size delta ({desc})",
            ))
            break

    return standard_response(
        tool="nosqli", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"{tests} NoSQL probes across {len(_PARAMS)} params x {len(_PAYLOADS)} operators",
        raw_data={"nosqli": {"operators_tested": [op for op,_,_ in _PAYLOADS]}},
    )


def register(app):
    app.include_router(router)

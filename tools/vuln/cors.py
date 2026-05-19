"""CORS misconfiguration scanner -- 3 origin probes (zero-FP: only counts real HTTP responses)."""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
router = APIRouter()
_ATTACKER = "https://evil-attacker.example"

def _probe(url, origin, req):
    r = safe_request("GET", url, headers={"Origin": origin, "User-Agent": "VulnusLab/1.0"},
                     req=req, timeout=10, allow_redirects=True)
    if r is None: return None, None, None
    return r, (r.headers.get("Access-Control-Allow-Origin", "") or "").strip(), \
           (r.headers.get("Access-Control-Allow-Credentials", "") or "").strip().lower()

@router.post("/api/scan/cors")
async def scan_cors(req: ScanRequest, payload=Depends(verify_scan_quota)):
    url = web_url(req.target)
    findings, probes = [], []

    r, ao, ac = _probe(url, _ATTACKER, req)
    if r is not None:
        probes.append({"origin": _ATTACKER, "allow_origin": ao, "allow_credentials": ac})
        if ao == _ATTACKER:
            sev = "CRITICAL" if ac == "true" else "HIGH"
            cvss = "9.1" if ac == "true" else "7.5"
            findings.append(wrap_finding(
                f"CORS reflects attacker origin - cross-origin data theft "
                + ("WITH credentials possible" if ac == "true" else "possible"),
                sev, cvss=cvss, cwe="CWE-942", owasp="A05:2021",
                remediation="Use a strict allow-list of origins, not reflection.",
                evidence_marker=f"Origin: {_ATTACKER} -> Allow-Origin: {ao}, Allow-Credentials: {ac}"))

    r2, ao2, ac2 = _probe(url, "null", req)
    if r2 is not None:
        probes.append({"origin": "null", "allow_origin": ao2, "allow_credentials": ac2})
        if ao2 == "null":
            findings.append(wrap_finding(
                "CORS allows 'null' origin - exploitable from sandboxed iframe / file://",
                "HIGH" if ac2 == "true" else "MEDIUM",
                cvss="7.5" if ac2 == "true" else "5.3",
                cwe="CWE-942", owasp="A05:2021",
                remediation="Reject Origin: null in your CORS policy.",
                evidence_marker="Origin: null -> Allow-Origin: null"))

    # Zero-FP gate: if no probe got a response, report that — don't lie with "3 tests performed"
    if not probes:
        return standard_response(tool="cors", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason=f"Target {url} did not respond to any CORS probe (network/firewall/host down)",
            tests_summary="CORS scan aborted - 0 of 3 probes received a response")

    return standard_response(tool="cors", target=req.target,
        findings=findings, tests_performed=len(probes),
        tests_summary=f"{len(probes)}/2 CORS probes succeeded - {len(findings)} misconfiguration(s) found",
        raw_data={"cors": {"probes": probes}})

def register(app): app.include_router(router)

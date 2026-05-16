"""Open Redirect — Location-header attacker-host verification."""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
router = APIRouter()
_ATTACKER = "evil-attacker.example"
_PAYLOADS = [
    f"https://{_ATTACKER}", f"//{_ATTACKER}", f"/\\{_ATTACKER}", _ATTACKER,
    f"https://target.com.{_ATTACKER}", f"https://target.com@{_ATTACKER}",
    f"//{_ATTACKER}/path", f"https:%2f%2f{_ATTACKER}", f"//{_ATTACKER}#",
]
_COMMON_KEYS = ["url", "next", "redirect", "return", "returnTo", "return_url",
                "goto", "rurl", "dest", "destination", "redir", "u"]

@router.post("/api/scan/open_redirect")
async def scan_open_redirect(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target)
    parsed = urlparse(base)
    params = parse_qs(parsed.query)
    candidates = set(params.keys()) | set(_COMMON_KEYS)
    findings, tests, confirmed = [], 0, []
    for key in candidates:
        for inj in _PAYLOADS:
            tests += 1
            new_params = {k: v[0] for k, v in params.items()}
            new_params[key] = inj
            test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
            r = safe_get(test_url, req=req, allow_redirects=False, timeout=10)
            if r is None or r.status_code not in (301, 302, 303, 307, 308): continue
            location = r.headers.get("Location", "") or r.headers.get("location", "") or ""
            if _ATTACKER in location.lower():
                findings.append(wrap_finding(
                    f"Open Redirect via {key!r}",
                    "MEDIUM", cvss="6.1", cwe="CWE-601", owasp="A01:2021",
                    remediation="Validate redirect destinations against an internal allow-list.",
                    evidence_marker=f"{key}={inj} → HTTP {r.status_code} Location: {location}"))
                confirmed.append({"param": key, "payload": inj, "location": location})
                break
    return standard_response(tool="open_redirect", target=req.target, findings=findings,
        tests_performed=tests,
        tests_summary=f"Open redirect: {tests} probes across {len(candidates)} candidate params",
        raw_data={"open_redirect": {"confirmed": confirmed}})
def register(app): app.include_router(router)

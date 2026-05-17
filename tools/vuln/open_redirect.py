"""Open Redirect -- Location-header attacker-host verification.

Zero-FP rule: the Location header must actually REDIRECT to the attacker
host. Earlier substring matching produced false positives on sites that
preserved the malicious URL inside a same-origin redirect query string
(e.g. 302 -> /login?next=/protected?goto=https://evil-attacker.example).
"""
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


def _redirects_to_attacker(location: str, target_host: str) -> bool:
    """True only if the Location header's DESTINATION host is the attacker.

    Handles the forms attackers actually exploit:
      - absolute:        https://evil-attacker.example/path
      - schemeless:      //evil-attacker.example/path
      - backslash:       /\\evil-attacker.example  (Chrome/Firefox quirk)
      - user-info bypass: https://target.com@evil-attacker.example
      - subdomain trick: https://target.com.evil-attacker.example

    Rejects what's NOT an open redirect:
      - same-origin redirect that *contains* the attacker string in the
        query, e.g. /login?next=https://evil-attacker.example
    """
    if not location:
        return False
    loc = location.strip()
    low_attacker = _ATTACKER.lower()

    # Schemeless //host/path  (most common open-redirect form)
    if loc.startswith("//"):
        host = loc[2:].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        # Strip user-info portion if present (user@host)
        if "@" in host:
            host = host.split("@", 1)[1]
        return low_attacker in host.lower()

    # Backslash-prefixed (browsers normalize \\ -> //)
    if loc.startswith(("/\\", "\\\\", "\\")):
        rest = loc.lstrip("/\\")
        host = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" in host:
            host = host.split("@", 1)[1]
        return low_attacker in host.lower()

    # Absolute URL -- parse and check the netloc only
    try:
        parsed_loc = urlparse(loc)
        if parsed_loc.netloc:
            host = parsed_loc.netloc.lower()
            if "@" in host:
                host = host.split("@", 1)[1]
            # host equals attacker, OR target.com.evil-attacker.example,
            # OR target.com@evil-attacker.example (already stripped)
            return low_attacker in host
    except Exception:
        pass

    # Pure relative ("/login", "page.html"...) cannot be open-redirect
    return False


@router.post("/api/scan/open_redirect")
async def scan_open_redirect(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target)
    parsed = urlparse(base)
    target_host = (parsed.netloc or "").lower()
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
            if _redirects_to_attacker(location, target_host):
                findings.append(wrap_finding(
                    f"Open Redirect via {key!r}",
                    "MEDIUM", cvss="6.1", cwe="CWE-601", owasp="A01:2021",
                    remediation="Validate redirect destinations against an internal allow-list.",
                    evidence_marker=f"{key}={inj} -> HTTP {r.status_code} Location: {location}"))
                confirmed.append({"param": key, "payload": inj, "location": location})
                break
    return standard_response(tool="open_redirect", target=req.target, findings=findings,
        tests_performed=tests,
        tests_summary=f"Open redirect: {tests} probes across {len(candidates)} candidate params (host-verified)",
        raw_data={"open_redirect": {"confirmed": confirmed}})
def register(app): app.include_router(router)

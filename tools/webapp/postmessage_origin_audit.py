"""postmessage_origin_audit — search homepage + crawled JS for missing origin checks.

window.addEventListener('message', e => ...) handlers MUST check e.origin
against an allowlist. Fetches the homepage + linked .js files, looks for
addEventListener('message') handlers, flags missing origin checks.

Static-source heuristic — false-positive resistant (only emits if a real
message-listener pattern is found AND no origin check is detected within
the handler body).
"""
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

# Pattern: addEventListener("message", fn or arrow ...) — capture the handler body
HANDLER_RE = re.compile(
    r"addEventListener\(\s*['\"]message['\"][\s\S]{1,5}"
    r"(function\s*\([^)]*\)\s*\{([\s\S]{1,5000}?)\}|\([^)]*\)\s*=>\s*\{([\s\S]{1,5000}?)\})",
    re.IGNORECASE)
ORIGIN_CHECK_RE = re.compile(
    r"\.origin\s*(===|==|!==|!=)|allowedOrigins|trustedOrigins|originAllowed",
    re.IGNORECASE)
SCRIPT_SRC_RE = re.compile(r'<script[^>]*\bsrc=["\']([^"\']+\.js)["\']', re.IGNORECASE)
INLINE_SCRIPT_RE = re.compile(r"<script[^>]*>([\s\S]*?)</script>", re.IGNORECASE)


def _fetch(url, req):
    return safe_request("GET", url,
        headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0"},
        req=req, timeout=10, allow_redirects=True)


@router.post("/api/webapp/scan/postmessage_origin_audit")
@vl_turbo()
@vl_verify()
def scan_postmessage_origin_audit(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    root = _fetch(base + "/", req)
    if root is None or root.status_code >= 400:
        return standard_response(
            tool="postmessage_origin_audit", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Could not fetch homepage (HTTP {root.status_code if root else 'no-resp'})")

    sources = {"inline": root.text}
    # Pull linked scripts (first 8 same-origin)
    fetched = 0
    for m in SCRIPT_SRC_RE.finditer(root.text):
        if fetched >= 8: break
        src = m.group(1)
        if src.startswith("//"): src = "https:" + src
        if src.startswith("/"):  src = base + src
        elif src.startswith("http"): pass
        else: src = base + "/" + src
        # Same-origin only
        if not src.startswith(base): continue
        r = _fetch(src, req)
        if r is None or r.status_code != 200: continue
        sources[src] = r.text[:200000]
        fetched += 1

    handlers_total = 0
    handlers_no_origin = []
    for src_name, text in sources.items():
        for m in HANDLER_RE.finditer(text):
            handlers_total += 1
            body = (m.group(2) or m.group(3) or "")
            if not ORIGIN_CHECK_RE.search(body):
                handlers_no_origin.append({
                    "source": src_name[:80],
                    "snippet": body[:120].replace("\n", " ").strip(),
                })

    findings = []
    if handlers_no_origin:
        findings.append(wrap_finding(
            f"postMessage handler(s) missing origin check ({len(handlers_no_origin)})",
            "HIGH", cvss="7.5", cwe="CWE-346", owasp="A01:2021",
            remediation="EVERY window.addEventListener('message', ...) handler MUST "
                        "validate event.origin against a whitelist BEFORE acting on "
                        "event.data. Without this check, ANY page that frames yours "
                        "(or any iframe you load) can post arbitrary messages and "
                        "trigger your app's logic (privilege escalation, data leak). "
                        "Example: if (event.origin !== 'https://your-trusted-parent.com') return;",
            evidence_marker=" | ".join(
                f"{h['source']}: {h['snippet']}" for h in handlers_no_origin[:5]
            )))
    if handlers_total > 0 and not handlers_no_origin:
        findings.append(wrap_finding(
            f"All {handlers_total} postMessage handler(s) check origin",
            "POSITIVE", cwe="CWE-346",
            remediation="Maintain. New handlers should always include origin check first.",
            evidence_marker=f"{handlers_total} handlers scanned, 0 missing origin check"))

    if handlers_total == 0:
        return standard_response(
            tool="postmessage_origin_audit", target=req.target, findings=[],
            tests_performed=1 + fetched, vulnerable=False,
            skipped_reason="No window.addEventListener('message',...) handlers found in "
                            "homepage + 8 linked scripts. Could be: SPA loads dynamically "
                            "(use dynamic fuzz) OR no cross-window messaging used.")

    return standard_response(
        tool="postmessage_origin_audit", target=req.target, findings=findings,
        tests_performed=1 + fetched, vulnerable=bool(handlers_no_origin),
        tests_summary=f"{handlers_total} handlers across {1+fetched} files; "
                       f"{len(handlers_no_origin)} unsafe",
        raw_data={"handlers_total": handlers_total,
                   "handlers_no_origin": handlers_no_origin[:10]})


def register(app):
    app.include_router(router)

"""service_worker_audit — discover + analyze Service Worker (sw.js).

Service Workers can intercept ALL network requests in their scope, cache
sensitive responses, and persist across sessions. Misconfig risks:
  - Scope too broad (/ instead of /app/)
  - Fetch handler caches authenticated responses without Vary: Cookie
  - Permissive update strategy (long max-age)
  - Importing untrusted scripts (importScripts to 3rd-party)

This scanner fetches sw.js and audits its source.
"""
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

SW_PATHS = ["/sw.js", "/service-worker.js", "/serviceworker.js",
             "/firebase-messaging-sw.js", "/workbox-sw.js"]


def _fetch(url, req):
    return safe_request("GET", url,
        headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0"},
        req=req, timeout=10, allow_redirects=True)


@router.post("/api/webapp/scan/service_worker_audit")
@vl_turbo()
@vl_verify()
def scan_service_worker_audit(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")

    sw_url = None
    sw_text = None
    sw_scope = None
    for path in SW_PATHS:
        r = _fetch(base + path, req)
        if r is None or r.status_code != 200: continue
        ct = (r.headers.get("content-type") or "").lower()
        if "javascript" not in ct and "octet-stream" not in ct: continue
        sw_url = base + path
        sw_text = r.text or ""
        # Service-Worker-Allowed header expands scope
        sw_scope = r.headers.get("service-worker-allowed") or path.rsplit("/", 1)[0] + "/"
        break

    if not sw_url:
        # Also try discovering registration from homepage
        root = _fetch(base + "/", req)
        if root is not None and root.status_code == 200:
            m = re.search(r"register\(['\"]([^'\"]+)['\"]", root.text or "")
            if m:
                candidate = m.group(1)
                if not candidate.startswith("http"):
                    candidate = base + ("/" + candidate.lstrip("/"))
                r = _fetch(candidate, req)
                if r is not None and r.status_code == 200:
                    sw_url = candidate
                    sw_text = r.text or ""
                    sw_scope = "/ (discovered via register())"

    if not sw_url:
        return standard_response(
            tool="service_worker_audit", target=req.target,
            findings=[wrap_finding(
                "No Service Worker detected",
                "POSITIVE", cwe="CWE-200",
                remediation="No SW attack surface from caching/intercept. If you "
                            "later add a SW for PWA offline support, audit its scope, "
                            "fetch handlers, and importScripts targets.",
                evidence_marker=f"checked {SW_PATHS} + homepage registration")],
            tests_performed=len(SW_PATHS) + 1, vulnerable=False,
            tests_summary="No SW detected")

    # Audit the source
    findings = []
    issues = []

    # 1. Scope audit
    if sw_scope.strip() == "/" or sw_scope.startswith("/")  and not sw_scope.rstrip("/"):
        issues.append(("Broad scope (root /)", "MEDIUM"))

    # 2. importScripts() to third-party
    for m in re.finditer(r"importScripts\(['\"]([^'\"]+)['\"]", sw_text):
        src = m.group(1)
        if src.startswith("http") and not src.startswith(base):
            issues.append((f"importScripts to third-party: {src[:80]}", "HIGH"))

    # 3. event.respondWith without ignoreSearch/cookie consideration
    if "respondWith" in sw_text and "Cookie" not in sw_text:
        # Caching without considering auth → cross-user cache poisoning
        if "cache.put" in sw_text or "caches.open" in sw_text:
            issues.append(("Caching responses without Cookie/auth consideration",
                            "MEDIUM"))

    # 4. eval / new Function in SW (extra concerning since SW runs in privileged context)
    if "eval(" in sw_text or "new Function(" in sw_text:
        issues.append(("eval()/new Function() in SW source", "HIGH"))

    # 5. Workbox version (older versions had CVEs)
    wb_match = re.search(r"workbox.*?v?(\d+\.\d+\.\d+)", sw_text[:5000])
    workbox_version = wb_match.group(1) if wb_match else None

    if issues:
        sev = "HIGH" if any(s == "HIGH" for _, s in issues) else "MEDIUM"
        cvss = "7.5" if sev == "HIGH" else "5.3"
        findings.append(wrap_finding(
            f"Service Worker security issues ({len(issues)})",
            sev, cvss=cvss, cwe="CWE-732", owasp="A05:2021",
            remediation="(1) Narrow scope: register('/app/sw.js', {scope:'/app/'}) "
                        "not '/'. (2) NEVER importScripts() third-party — pin to "
                        "self-hosted versions of analytics/SDKs. (3) When caching, "
                        "use a Vary-Cookie strategy or simply skip authenticated "
                        "responses. (4) Audit Workbox version against known CVEs.",
            evidence_marker=" | ".join(f"{m} ({s})" for m, s in issues[:5])))
    else:
        findings.append(wrap_finding(
            f"Service Worker at {sw_url} — no obvious issues in source",
            "POSITIVE", cwe="CWE-732",
            remediation="Maintain. Re-audit on every SW deploy.",
            evidence_marker=f"scope: {sw_scope}, size: {len(sw_text)}B"
                              + (f", workbox v{workbox_version}" if workbox_version else "")))

    return standard_response(
        tool="service_worker_audit", target=req.target, findings=findings,
        tests_performed=len(SW_PATHS) + 1, vulnerable=bool(issues),
        tests_summary=f"SW: {sw_url}, {len(issues)} issues",
        raw_data={"sw_url": sw_url, "sw_scope": sw_scope,
                   "workbox_version": workbox_version,
                   "issues": [{"desc": m, "severity": s} for m, s in issues]})


def register(app):
    app.include_router(router)

"""nextjs_rsc_audit — Next.js App Router RSC + ISR/SSR security audit.

Next.js App Router introduces React Server Components (RSC) + Server
Actions + ISR (Incremental Static Regeneration). Security gotchas:
  - _rsc query strips auth context, may leak draft content
  - Server Actions accept POST with formData — CSRF risk if not gated
  - On-demand revalidate endpoint exposed without secret
  - getServerSideProps/route.ts data leakage if used in dev mode

Detects Next.js footprint then audits common misconfigs.
"""
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo

router = APIRouter()


def _fetch(url, req, headers=None):
    return safe_request("GET", url,
        headers={**(headers or {}),
                  "User-Agent": "Mozilla/5.0 VulnusLab/1.0"},
        req=req, timeout=8, allow_redirects=False)


@router.post("/api/webapp/scan/nextjs_rsc_audit")
@vl_turbo()
def scan_nextjs_rsc_audit(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")

    # 1. Detect Next.js
    root = _fetch(base + "/", req)
    if root is None:
        return standard_response(
            tool="nextjs_rsc_audit", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="No response from homepage")
    body = root.text or ""
    is_nextjs = ("__NEXT_DATA__" in body or "_next/static" in body or
                  "next/router" in body or "_next/data" in body)

    if not is_nextjs:
        return standard_response(
            tool="nextjs_rsc_audit", target=req.target,
            findings=[wrap_finding(
                "No Next.js footprint detected",
                "POSITIVE", cwe="CWE-200",
                remediation="No Next.js-specific surface to audit.",
                evidence_marker="no __NEXT_DATA__, no _next/ paths in homepage")],
            tests_performed=1, vulnerable=False,
            tests_summary="Not Next.js")

    # 2. Detect Next.js version
    version_match = re.search(r'"buildId":"([^"]+)"', body)
    version = (re.search(r'"nextExport":[^,]+,"buildId":"([^"]+)"', body) or
                re.search(r'/_next/static/([^/]+)/', body))
    findings = []
    issues = []

    # 3. Check for _rsc parameter handling — append ?_rsc=1 to root and check
    rsc_resp = _fetch(base + "/?_rsc=1", req, headers={"RSC": "1"})
    if rsc_resp is not None and rsc_resp.status_code == 200:
        rsc_body = rsc_resp.text or ""
        # RSC payload starts with size-prefix lines (digits or hex)
        if rsc_body and (rsc_body.startswith(("0:", "1:", "2:")) or
                          "self.__next_f" in rsc_body):
            # This is fine — RSC response. Worth flagging only if it leaks
            # different content than user-context render.
            issues.append(("RSC stream accessible — verify no PII leaks via _rsc",
                            "INFO"))

    # 4. Check for revalidate / on-demand revalidation endpoint
    for path in ("/api/revalidate", "/api/revalidate-tag"):
        r = _fetch(base + path, req)
        if r is None: continue
        if r.status_code in (200, 405):  # 405 = method not allowed (endpoint exists)
            # Try with no secret
            r2 = _fetch(base + path + "?path=/", req)
            if r2 is not None and r2.status_code == 200:
                issues.append((f"{path} accepts GET without secret — cache "
                                "poisoning vector", "MEDIUM"))

    # 5. Check for Server Actions endpoints (POST to root with Next-Action header)
    r_sa = safe_request("POST", base + "/",
        headers={"Next-Action": "vulnuslab-fake-action-id",
                  "Content-Type": "multipart/form-data",
                  "User-Agent": "VulnusLab/1.0"},
        data="--x\r\n--x--\r\n", req=req, timeout=8, allow_redirects=False)
    if r_sa is not None and r_sa.status_code in (200, 500):
        # Server Action endpoint exists
        if "next-action" in (r_sa.text or "").lower():
            issues.append(("Server Actions endpoint responds — verify each "
                            "action has explicit auth check", "INFO"))

    # 6. Check for debug page
    for debug_path in ("/_next/data/development/", "/__next/dev/",
                        "/_next/internal", "/__next/diagnostics"):
        r = _fetch(base + debug_path, req)
        if r is not None and r.status_code == 200:
            issues.append((f"{debug_path} reachable — DEV-mode artifacts in prod",
                            "MEDIUM"))

    if issues:
        sev = "MEDIUM" if any(s == "MEDIUM" for _, s in issues) else "INFO"
        cvss = "5.3" if sev == "MEDIUM" else "0.0"
        findings.append(wrap_finding(
            f"Next.js audit issues ({len(issues)})",
            sev, cvss=cvss, cwe="CWE-200", owasp="A05:2021",
            remediation="(1) revalidate endpoints MUST require x-next-revalidate-"
                        "secret header with strong secret. (2) Every Server Action "
                        "MUST check auth context — no Next-Action equals public RPC. "
                        "(3) NEVER ship dev-mode artifacts (`next build` not `next dev` "
                        "in prod). (4) Audit RSC streams for PII leakage when user "
                        "context is null.",
            evidence_marker=" | ".join(f"{m} [{s}]" for m, s in issues[:5])))
    else:
        findings.append(wrap_finding(
            f"Next.js detected, no common misconfigs",
            "POSITIVE", cwe="CWE-200",
            remediation="Maintain. Re-audit on Next.js major upgrades (App Router "
                        "evolves rapidly).",
            evidence_marker=f"Next.js footprint confirmed, all probes clean"))

    return standard_response(
        tool="nextjs_rsc_audit", target=req.target, findings=findings,
        tests_performed=8,
        vulnerable=any(f.get("severity") == "MEDIUM" for f in findings),
        tests_summary=f"Next.js: yes, {len(issues)} issues",
        raw_data={"is_nextjs": is_nextjs, "issues_found": [
            {"desc": m, "severity": s} for m, s in issues]})


def register(app):
    app.include_router(router)

"""Subdomain takeover — checks SPA-state subdomains against takeover signatures."""
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
from tools._payloads.takeover_signatures import TAKEOVER_SIGNATURES

router = APIRouter()


def _query_cname(host):
    try:
        import dns.resolver
        try:
            ans = dns.resolver.resolve(host, "CNAME", lifetime=5)
            return [str(r.target).rstrip(".") for r in ans]
        except Exception:
            return []
    except ImportError:
        return []


@router.post("/api/recon/takeover_check")
async def recon_takeover_check(req: ScanRequest, _=Depends(verify_scan_quota)):
    # Get subdomain list — for now check the target itself + common prefixes
    from urllib.parse import urlparse
    parsed = urlparse(web_url(req.target))
    apex = parsed.netloc.split(":")[0]

    # Build candidate subdomain list from common prefixes
    if apex.count(".") <= 1:
        # apex domain — check common subdomains
        candidates = [f"{prefix}.{apex}" for prefix in
                       ("www", "api", "app", "blog", "shop", "mail", "dev", "staging", "test",
                        "cdn", "static", "assets", "media", "admin", "support",
                        "help", "docs", "status", "old", "legacy", "beta")]
    else:
        candidates = [apex]

    findings, tests, confirmed = [], 0, []
    for sub in candidates[:25]:
        tests += 1
        cnames = _query_cname(sub)
        if not cnames:
            continue
        for cname in cnames:
            # Match against takeover signatures
            for sig in TAKEOVER_SIGNATURES:
                cname_matched = False
                for pat in sig.get("cname_patterns", []) or []:
                    try:
                        if re.search(pat, cname, re.IGNORECASE):
                            cname_matched = True
                            break
                    except re.error: continue
                if not cname_matched:
                    continue
                # CNAME matches a known takeover-vulnerable provider — fetch and check body
                tests += 1
                r = safe_get(f"http://{sub}", req=req, allow_redirects=True, timeout=10)
                if r is None:
                    continue
                expected_status = sig.get("fingerprint_status", 404)
                body_pat = sig.get("fingerprint_body", "")
                try:
                    if r.status_code == expected_status and body_pat and \
                       re.search(body_pat, r.text or "", re.IGNORECASE):
                        findings.append(wrap_finding(
                            f"Subdomain takeover — {sub} points to unclaimed {sig['service']}",
                            sig.get("severity", "HIGH"),
                            cvss="8.1", cwe="CWE-350", owasp="A05:2021",
                            remediation=sig.get("documentation",
                                "Claim the dangling resource at the provider OR remove the CNAME record."),
                            evidence_marker=f"{sub} → CNAME {cname} → HTTP {r.status_code} matches {sig['service']} unclaimed page"))
                        confirmed.append({"subdomain": sub, "cname": cname,
                                          "service": sig["service"]})
                        break
                except re.error:
                    continue

    return standard_response(tool="takeover_check", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"Takeover check: probed {len(candidates)} subdomains against {len(TAKEOVER_SIGNATURES)} provider signatures",
        raw_data={"takeover_check": {"confirmed": confirmed,
                                       "subdomains_probed": len(candidates)}})


def register(app):
    app.include_router(router)

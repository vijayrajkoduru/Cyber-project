"""sri_audit — Subresource Integrity check on external script/style tags.

SRI: <script src=...> from external CDN should have integrity="sha384-..."
attribute. Without it, if CDN gets compromised, attacker injects arbitrary
JS into all sites using that CDN URL (Magecart-style supply-chain attack).

Audits homepage HTML for cross-origin script/link tags without SRI.
"""
import re
from urllib.parse import urlparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo

router = APIRouter()

SCRIPT_RE = re.compile(r'<script\b[^>]*\bsrc=["\']([^"\']+)["\'][^>]*>', re.IGNORECASE)
LINK_RE = re.compile(r'<link\b[^>]*\brel=["\']stylesheet["\'][^>]*\bhref=["\']([^"\']+)["\'][^>]*>', re.IGNORECASE)
INTEGRITY_RE = re.compile(r'\bintegrity=["\']([^"\']+)["\']', re.IGNORECASE)
CROSSORIGIN_RE = re.compile(r'\bcrossorigin=', re.IGNORECASE)


def _classify(url, target_host):
    """Return (is_external, normalized_url)."""
    if url.startswith("//"): url = "https:" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        # Relative — same origin
        return False, url
    return parsed.netloc.lower() != target_host.lower(), url


@router.post("/api/webapp/scan/sri_audit")
@vl_turbo()
def scan_sri_audit(req: ScanRequest, payload=Depends(verify_scan_quota)):
    url = web_url(req.target)
    target_host = urlparse(url).hostname or ""
    r = safe_request("GET", url,
        headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0"},
        req=req, timeout=10, allow_redirects=True)
    if r is None or r.status_code >= 400:
        return standard_response(
            tool="sri_audit", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="Could not fetch homepage")

    body = r.text or ""

    external_no_sri = []
    external_with_sri = []
    same_origin = []

    def _audit_tag_list(pattern, kind):
        for m in pattern.finditer(body):
            src = m.group(1)
            tag = m.group(0)
            is_ext, full = _classify(src, target_host)
            if not is_ext:
                same_origin.append({"kind": kind, "url": full})
                continue
            has_sri = bool(INTEGRITY_RE.search(tag))
            if has_sri:
                external_with_sri.append({"kind": kind, "url": full[:100]})
            else:
                external_no_sri.append({"kind": kind, "url": full[:100]})

    _audit_tag_list(SCRIPT_RE, "script")
    _audit_tag_list(LINK_RE, "stylesheet")

    findings = []
    if external_no_sri:
        # Filter out known-safe origins (your own CDN subdomain, Google Fonts which doesn't support SRI)
        risky = [e for e in external_no_sri
                  if "fonts.googleapis.com" not in e["url"]
                  and "fonts.gstatic.com" not in e["url"]]
        if risky:
            findings.append(wrap_finding(
                f"External {len(risky)} resource(s) loaded WITHOUT SRI integrity",
                "MEDIUM", cvss="5.3", cwe="CWE-829", owasp="A06:2021",
                remediation="Add integrity='sha384-XXXX...' crossorigin='anonymous' "
                            "to each external <script>/<link>. Compute via srihash.org "
                            "or `openssl dgst -sha384 -binary file.js | openssl base64 -A`. "
                            "Without SRI, CDN compromise = arbitrary JS execution in "
                            "your app's origin = supply-chain MagecartM compromise. "
                            "Pin specific versions in URLs (not /latest/).",
                evidence_marker=" | ".join(
                    f"{e['kind']}: {e['url']}" for e in risky[:5]
                )))

    if external_with_sri or not external_no_sri:
        if external_with_sri and not external_no_sri:
            findings.append(wrap_finding(
                f"All {len(external_with_sri)} external resources have SRI",
                "POSITIVE", cwe="CWE-829",
                remediation="Maintain. Re-pin hashes when you bump CDN versions.",
                evidence_marker=f"{len(external_with_sri)} external resources, all with integrity"))
        elif not external_no_sri and not external_with_sri:
            findings.append(wrap_finding(
                "No external resources — minimal supply-chain attack surface",
                "POSITIVE", cwe="CWE-829",
                remediation="Maintain. Self-host critical assets.",
                evidence_marker=f"{len(same_origin)} same-origin resources only"))

    return standard_response(
        tool="sri_audit", target=req.target, findings=findings,
        tests_performed=1,
        vulnerable=bool(external_no_sri and findings and any(f.get("severity") == "MEDIUM" for f in findings)),
        tests_summary=f"external: {len(external_no_sri + external_with_sri)} "
                       f"({len(external_no_sri)} no-SRI), same-origin: {len(same_origin)}",
        raw_data={"external_no_sri": external_no_sri[:20],
                   "external_with_sri": external_with_sri[:20],
                   "same_origin_count": len(same_origin)})


def register(app):
    app.include_router(router)

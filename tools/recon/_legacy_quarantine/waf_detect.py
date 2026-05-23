"""WAF/CDN detection — fingerprint via 50+ provider signatures."""
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
from tools._payloads.waf_fingerprints import WAF_FINGERPRINTS

router = APIRouter()


@router.post("/api/recon/waf_detect")
async def recon_waf_detect(req: ScanRequest, _=Depends(verify_scan_quota)):
    url = web_url(req.target)
    r = safe_get(url, req=req, allow_redirects=True, timeout=12)
    if r is None:
        return standard_response(tool="waf_detect", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason=f"Could not reach {url}")

    headers_str = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
    cookies_str = r.headers.get("Set-Cookie", "")
    body_sample = (r.text or "")[:5000]

    detected = []
    for wf in WAF_FINGERPRINTS:
        matched_sigs = []
        for sig in wf.get("header_signatures", []) or []:
            try:
                if re.search(sig, headers_str, re.IGNORECASE):
                    matched_sigs.append(f"header:{sig[:30]}")
            except re.error: continue
        for sig in wf.get("cookie_signatures", []) or []:
            try:
                if re.search(sig, cookies_str, re.IGNORECASE):
                    matched_sigs.append(f"cookie:{sig[:30]}")
            except re.error: continue
        for sig in wf.get("body_signatures", []) or []:
            try:
                if re.search(sig, body_sample, re.IGNORECASE):
                    matched_sigs.append(f"body:{sig[:30]}")
            except re.error: continue
        if matched_sigs:
            detected.append({"provider": wf["provider"], "category": wf.get("category", "waf"),
                              "signatures_matched": matched_sigs[:3]})

    findings = []
    if detected:
        names = ", ".join(d["provider"] for d in detected[:5])
        findings.append(wrap_finding(
            f"WAF/CDN detected: {names}",
            "INFO", cvss="0.0", cwe="N/A", owasp="N/A",
            remediation="Informational — testing posture should account for WAF rules.",
            evidence_marker=f"{len(detected)} provider(s) matched: {names}"))

    return standard_response(tool="waf_detect", target=req.target,
        findings=findings,
        tests_performed=len(WAF_FINGERPRINTS),
        tests_summary=f"WAF detect: probed {len(WAF_FINGERPRINTS)} providers, matched {len(detected)}",
        raw_data={"waf_detect": {"detected": detected}})


def register(app):
    app.include_router(router)

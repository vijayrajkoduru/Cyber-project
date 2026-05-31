"""permissions_policy_audit — Permissions-Policy / Feature-Policy audit.

Permissions-Policy (formerly Feature-Policy) controls which browser
features the page + its iframes can use: camera, microphone, geolocation,
USB, MIDI, payment, autoplay, etc. Missing/loose Permissions-Policy lets
embedded iframes (ads, 3rd-party widgets) access sensitive APIs.

Modern best practice: deny-by-default + selectively grant only what's used.
"""
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)

router = APIRouter()

# Sensitive features that SHOULD be restricted
SENSITIVE_FEATURES = [
    "camera", "microphone", "geolocation", "usb", "midi",
    "payment", "publickey-credentials-get", "publickey-credentials-create",
    "screen-wake-lock", "serial", "bluetooth", "hid", "accelerometer",
    "gyroscope", "magnetometer", "ambient-light-sensor",
    "fullscreen", "encrypted-media", "autoplay",
]


def _parse_pp(header_value: str) -> dict:
    """Parse Permissions-Policy header into {feature: [allowlist]} dict."""
    out = {}
    for part in header_value.split(","):
        part = part.strip()
        m = re.match(r'^([\w-]+)\s*=\s*\(?([^)]*)\)?$', part)
        if m:
            feat = m.group(1).lower()
            allow_raw = m.group(2).strip()
            # Parse allowlist tokens: self, src, *, "https://..."
            tokens = re.findall(r'"[^"]+"|\bself\b|\bsrc\b|\*', allow_raw)
            out[feat] = tokens
    return out


@router.post("/api/webapp/scan/permissions_policy_audit")
def scan_permissions_policy_audit(req: ScanRequest, payload=Depends(verify_scan_quota)):
    url = web_url(req.target)
    r = safe_request("GET", url,
        headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0"},
        req=req, timeout=8, allow_redirects=True)
    if r is None:
        return standard_response(
            tool="permissions_policy_audit", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="No response from target")

    pp = (r.headers.get("permissions-policy") or
          r.headers.get("Permissions-Policy") or "")
    fp = (r.headers.get("feature-policy") or
          r.headers.get("Feature-Policy") or "")

    findings = []
    if not pp and not fp:
        findings.append(wrap_finding(
            "No Permissions-Policy / Feature-Policy header",
            "MEDIUM", cvss="5.3", cwe="CWE-732", owasp="A05:2021",
            remediation="Add Permissions-Policy header to restrict iframe access "
                        "to sensitive browser APIs. Deny-by-default template: "
                        "Permissions-Policy: accelerometer=(), camera=(), geolocation=(), "
                        "gyroscope=(), magnetometer=(), microphone=(), payment=(), "
                        "usb=(), interest-cohort=(). Allow specific features for "
                        "iframes you trust: camera=(self https://video.example.com).",
            evidence_marker="no Permissions-Policy + no Feature-Policy in response"))
        return standard_response(
            tool="permissions_policy_audit", target=req.target, findings=findings,
            tests_performed=1, vulnerable=True,
            tests_summary="No Permissions-Policy header",
            raw_data={"has_pp": False, "has_fp": False})

    using_legacy = bool(fp and not pp)
    active_header = pp or fp
    parsed = _parse_pp(active_header)

    if using_legacy:
        findings.append(wrap_finding(
            "Using legacy Feature-Policy (deprecated)",
            "LOW", cwe="CWE-732",
            remediation="Migrate to Permissions-Policy header (modern syntax). "
                        "Feature-Policy is deprecated in Chrome 88+ and may be "
                        "ignored entirely in future browsers.",
            evidence_marker=f"Feature-Policy: {active_header[:150]}"))

    issues = []
    for feat in SENSITIVE_FEATURES:
        if feat not in parsed:
            issues.append((feat, "MISSING (defaults to allow on same-origin + iframe inherit)"))
        elif "*" in parsed[feat]:
            issues.append((feat, "= * (allowed for ALL iframes)"))

    if issues:
        findings.append(wrap_finding(
            f"Permissions-Policy missing or permissive for {len(issues)} sensitive feature(s)",
            "LOW" if len(issues) < 5 else "MEDIUM",
            cvss="3.5" if len(issues) < 5 else "5.3",
            cwe="CWE-732", owasp="A05:2021",
            remediation="Add explicit deny / restrictive directive for each sensitive "
                        "feature. e.g. camera=(), microphone=(), geolocation=() to "
                        "deny entirely. Specify allow list if your app actually uses: "
                        "geolocation=(self).",
            evidence_marker=" | ".join(f"{f}: {s}" for f, s in issues[:10])))
    else:
        findings.append(wrap_finding(
            f"Permissions-Policy comprehensive ({len(parsed)} features declared)",
            "POSITIVE", cwe="CWE-732",
            remediation="Maintain. Re-audit when new sensitive APIs ship in browsers.",
            evidence_marker=f"declared: {', '.join(list(parsed.keys())[:8])}"))

    return standard_response(
        tool="permissions_policy_audit", target=req.target, findings=findings,
        tests_performed=1, vulnerable=bool(issues) or using_legacy,
        tests_summary=f"PP: {bool(pp)}, FP: {bool(fp)}, {len(issues)} sensitive issues",
        raw_data={"permissions_policy": pp[:300], "feature_policy": fp[:300],
                   "parsed": {k: v for k, v in list(parsed.items())[:30]}})


def register(app):
    app.include_router(router)

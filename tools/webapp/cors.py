"""CORS misconfiguration scanner.

Active probing: sends GET requests with controlled Origin headers
and inspects Access-Control-* response headers.

Confirmed findings:
  - CRITICAL — ACAO reflects arbitrary Origin AND ACAC: true
              (credential-bearing cross-origin theft)
  - HIGH     — ACAO: '*' AND ACAC: true (invalid but misconfigured)
  - HIGH     — ACAO: 'null' (sandboxed iframes/file:// exploit)
  - HIGH     — ACAO reflects sibling subdomain (any *.parent.tld owns it)
"""
import urllib.parse
from fastapi import APIRouter, Depends

from tools._shared import (
    ScanRequest, verify_scan_quota, web_url,
    safe_get, make_req_headers,
    wrap_finding, standard_response,
)

router = APIRouter()


def _get_with_origin(url, origin, req):
    h = make_req_headers(req)
    h["Origin"] = origin
    return safe_get(url, req=req, headers=h, allow_redirects=False)


@router.post("/api/scan/cors")
async def scan_cors(req: ScanRequest, _=Depends(verify_scan_quota)):
    url = web_url(req.target)
    findings = []
    tests = 0
    raw = {}

    # Probe 1 — attacker-controlled arbitrary origin
    attacker_origin = "https://evil-attacker.example"
    tests += 1
    r1 = _get_with_origin(url, attacker_origin, req)
    if r1 is None:
        return standard_response(
            tool="cors", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Could not reach {url}",
        )

    h1 = {k.lower(): v for k, v in r1.headers.items()}
    acao1 = h1.get("access-control-allow-origin", "")
    acac1 = h1.get("access-control-allow-credentials", "").lower()
    raw["attacker_origin_probe"] = {
        "origin_sent": attacker_origin, "acao": acao1,
        "acac": acac1, "status": r1.status_code,
    }

    if acao1 == attacker_origin and acac1 == "true":
        findings.append(wrap_finding(
            "CORS reflects arbitrary Origin with credentials — cross-origin credential theft possible",
            "CRITICAL", cwe="CWE-942", owasp="A05:2021",
            evidence_marker=f"Origin: {attacker_origin} -> ACAO={acao1}, ACAC={acac1}",
            remediation="Validate Origin against a server-side allowlist; never echo arbitrary origins when ACAC is true.",
            tests_performed=1,
        ))
    elif acao1 == "*" and acac1 == "true":
        findings.append(wrap_finding(
            "CORS uses wildcard origin (*) with credentials — invalid and risky configuration",
            "HIGH", cwe="CWE-942", owasp="A05:2021",
            evidence_marker="ACAO=*, ACAC=true",
            remediation="If credentials are required, set a specific origin (not *).",
            tests_performed=1,
        ))

    # Probe 2 — null origin
    tests += 1
    r2 = _get_with_origin(url, "null", req)
    if r2 is not None:
        h2 = {k.lower(): v for k, v in r2.headers.items()}
        acao2 = h2.get("access-control-allow-origin", "")
        acac2 = h2.get("access-control-allow-credentials", "").lower()
        raw["null_origin_probe"] = {"acao": acao2, "acac": acac2}
        if acao2 == "null":
            findings.append(wrap_finding(
                "CORS accepts 'null' origin — sandboxed iframes / file:// pages can access this endpoint",
                "HIGH" if acac2 == "true" else "MEDIUM",
                cwe="CWE-942", owasp="A05:2021",
                evidence_marker=f"Origin: null -> ACAO=null, ACAC={acac2}",
                remediation="Remove 'null' from the allowed origins list.",
                tests_performed=1,
            ))

    # Probe 3 — sibling-subdomain spoof
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    parts = host.split(".")
    if len(parts) >= 2:
        parent = ".".join(parts[-2:])
        sub_origin = f"https://evil-subdomain.{parent}"
        tests += 1
        r3 = _get_with_origin(url, sub_origin, req)
        if r3 is not None:
            h3 = {k.lower(): v for k, v in r3.headers.items()}
            acao3 = h3.get("access-control-allow-origin", "")
            acac3 = h3.get("access-control-allow-credentials", "").lower()
            raw["subdomain_probe"] = {
                "origin_sent": sub_origin, "acao": acao3, "acac": acac3,
            }
            if acao3 == sub_origin and acac3 == "true":
                findings.append(wrap_finding(
                    f"CORS reflects subdomain origins with credentials — any *.{parent} can access this endpoint",
                    "HIGH", cwe="CWE-942", owasp="A05:2021",
                    evidence_marker=f"Origin: {sub_origin} -> ACAO={acao3}, ACAC={acac3}",
                    remediation="Use strict allowlist matching; do not regex/prefix-match subdomains for credentialed CORS.",
                    tests_performed=1,
                ))

    return standard_response(
        tool="cors", target=req.target, findings=findings,
        tests_performed=tests,
        tests_summary="3 CORS probes: attacker-origin reflection, null origin, subdomain wildcard",
        raw_data={"cors": raw},
    )


def register(app):
    app.include_router(router)

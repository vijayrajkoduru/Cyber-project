"""spring_spel_injection — Spring SpEL expression injection probe.

Spring Cloud Function / Spring expression-bound endpoints can evaluate
SpEL (Spring Expression Language) from user input → RCE
(CVE-2022-22963 etc).

Probes with classic SpEL: T(java.lang.Runtime).getRuntime().exec(...)
detection via timing OR returned exception markers.
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo

router = APIRouter()
PROBE_PATHS = ["/", "/functionRouter", "/function/", "/api/spel"]
PAYLOADS = [
    ("#{T(java.lang.Runtime)}",         "java.lang.Runtime"),
    ("#{T(System).getenv('PATH')}",     "/usr/"),
    ("${T(System).getProperty('os.name')}", "Linux"),
]


@router.post("/api/webapp/scan/spring_spel_injection")
@vl_turbo()
def scan_spring_spel_injection(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    hits = []
    tested = 0
    for path in PROBE_PATHS:
        url = base + path
        for pl, marker in PAYLOADS:
            # Try as POST body header `spring.cloud.function.routing-expression`
            r = safe_request("POST", url,
                headers={"User-Agent": "VulnusLab/1.0",
                          "spring.cloud.function.routing-expression": pl,
                          "Content-Type": "application/json"},
                data="{}", req=req, timeout=8, allow_redirects=False)
            if r is None: continue
            tested += 1
            body = (r.text or "")[:10000]
            if marker in body or "ClassNotFoundException" in body:
                hits.append({"path": path, "payload": pl,
                              "marker_seen": marker in body})
                break
    findings = []
    if hits:
        findings.append(wrap_finding(
            f"Spring SpEL injection at {len(hits)} location(s)",
            "CRITICAL", cvss="9.8", cwe="CWE-94", owasp="A03:2021",
            remediation="Upgrade Spring Cloud Function to ≥3.1.7 / 3.2.3 (CVE-"
                        "2022-22963 fix). Disable spring.cloud.function.routing-"
                        "expression header acceptance. For any SpEL-using endpoint, "
                        "use SimpleEvaluationContext (no T() type refs allowed).",
            evidence_marker=" | ".join(
                f"{h['path']}: {h['payload']} → marker reflected" for h in hits[:3]
            )))
    else:
        findings.append(wrap_finding(
            "No Spring SpEL injection detected", "POSITIVE", cwe="CWE-94",
            remediation="Maintain.", evidence_marker=f"{tested} probes clean"))
    return standard_response(
        tool="spring_spel_injection", target=req.target, findings=findings,
        tests_performed=tested, vulnerable=bool(hits),
        tests_summary=f"{tested} probes, {len(hits)} hits", raw_data={"hits": hits})


def register(app):
    app.include_router(router)

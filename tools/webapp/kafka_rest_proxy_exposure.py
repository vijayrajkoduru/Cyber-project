"""kafka_rest_proxy_exposure — Kafka REST Proxy unauth topic enumeration."""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)

router = APIRouter()
KAFKA_PATHS = ["/topics", "/brokers", "/consumers", "/v3/clusters"]


@router.post("/api/webapp/scan/kafka_rest_proxy_exposure")
def scan_kafka_rest_proxy_exposure(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    exposed = []
    is_kafka = False
    for path in KAFKA_PATHS:
        r = safe_request("GET", base + path,
            headers={"User-Agent": "VulnusLab/1.0",
                      "Accept": "application/vnd.kafka.v2+json,application/json"},
            req=req, timeout=8, allow_redirects=False)
        if r is None or r.status_code != 200: continue
        body = (r.text or "")[:5000]
        # Kafka REST Proxy returns JSON arrays/objects with specific markers
        if any(m in body for m in ('"clusters"', '"broker_id"',
                                    'kafka.v2+json', '"controller"')):
            is_kafka = True
            exposed.append({"path": path, "snippet": body[:200]})
    findings = []
    if is_kafka:
        findings.append(wrap_finding(
            f"Kafka REST Proxy EXPOSED ({len(exposed)} endpoint(s))",
            "CRITICAL", cvss="9.8", cwe="CWE-306", owasp="A01:2021",
            remediation="Kafka REST Proxy MUST require auth. Internet-exposed = "
                        "topic enumeration + message production + consumer "
                        "control. Configure HTTPS + LDAP/OAuth via Confluent "
                        "Cloud or self-hosted Schema Registry security. Firewall "
                        ":8082 to internal-only.",
            evidence_marker=" | ".join(f"{e['path']}: 200" for e in exposed[:3])))
    else:
        findings.append(wrap_finding("No Kafka REST Proxy detected", "POSITIVE",
            cwe="CWE-200", remediation="Maintain.",
            evidence_marker=f"checked {len(KAFKA_PATHS)} Kafka REST paths"))
    return standard_response(
        tool="kafka_rest_proxy_exposure", target=req.target, findings=findings,
        tests_performed=len(KAFKA_PATHS), vulnerable=is_kafka,
        tests_summary=f"kafka={is_kafka}, exposed: {len(exposed)}",
        raw_data={"is_kafka": is_kafka, "exposed": exposed})


def register(app): app.include_router(router)

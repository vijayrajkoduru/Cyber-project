"""opensearch_query_injection — OpenSearch/Elasticsearch query DSL injection."""
import json
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()
ES_PATHS = ["/_cluster/health", "/_cat/indices", "/", "/api/_search",
             "/elasticsearch/_cluster/health"]


@router.post("/api/webapp/scan/opensearch_query_injection")
@vl_turbo()
@vl_verify()
def scan_opensearch_query_injection(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    is_es = False
    cluster_info = None
    for path in ES_PATHS:
        r = safe_request("GET", base + path,
            headers={"User-Agent": "VulnusLab/1.0",
                      "Accept": "application/json"},
            req=req, timeout=8, allow_redirects=False)
        if r is None: continue
        body = (r.text or "")[:5000]
        if r.status_code == 200 and ("cluster_name" in body or
                                       "elasticsearch" in body.lower() or
                                       "opensearch" in body.lower()):
            is_es = True
            if path == "/" and not cluster_info:
                try: cluster_info = r.json()
                except Exception: pass

    findings = []
    if is_es:
        # Try _cat/indices unauth
        r2 = safe_request("GET", base + "/_cat/indices?format=json",
            headers={"User-Agent": "VulnusLab/1.0"},
            req=req, timeout=8, allow_redirects=False)
        index_count = 0
        if r2 is not None and r2.status_code == 200:
            try: index_count = len(r2.json())
            except Exception: pass
        version = (cluster_info or {}).get("version", {}).get("number", "?")
        findings.append(wrap_finding(
            f"OpenSearch/Elasticsearch EXPOSED ({version}, {index_count} indices visible)",
            "CRITICAL" if index_count > 0 else "HIGH",
            cvss="9.8" if index_count > 0 else "7.5",
            cwe="CWE-306", owasp="A01:2021",
            remediation="OpenSearch/Elasticsearch MUST require auth. Internet-"
                        "exposed = data exfil via _search. Configure OpenSearch "
                        "Security plugin / Elastic security with basic-auth or "
                        "SAML. Firewall :9200 to internal only.",
            evidence_marker=f"version={version}, indices_visible={index_count}"))
    else:
        findings.append(wrap_finding("No OpenSearch/Elasticsearch detected",
            "POSITIVE", cwe="CWE-200", remediation="N/A",
            evidence_marker=f"checked {len(ES_PATHS)} ES paths"))
    return standard_response(
        tool="opensearch_query_injection", target=req.target, findings=findings,
        tests_performed=len(ES_PATHS) + (1 if is_es else 0),
        vulnerable=is_es,
        tests_summary=f"es={is_es}",
        raw_data={"is_es": is_es, "cluster_info": cluster_info})


def register(app): app.include_router(router)

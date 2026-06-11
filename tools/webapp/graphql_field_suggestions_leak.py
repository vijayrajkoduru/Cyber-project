"""graphql_field_suggestions_leak — GraphQL "Did you mean..." schema leak.

When client sends an invalid field name, GraphQL servers can suggest
correct field names ("Did you mean 'userEmail'?"). With introspection
disabled, this STILL leaks schema info field-by-field.

Probe: send query with intentionally-wrong field name, look for
"Did you mean" or similar suggestion patterns in error response.
"""
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()
GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]


@router.post("/api/webapp/scan/graphql_field_suggestions_leak")
@vl_turbo()
@vl_verify()
def scan_graphql_field_suggestions_leak(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")

    def _probe(path):
        r = safe_request("POST", base + path,
            headers={"Content-Type": "application/json",
                      "User-Agent": "VulnusLab/1.0"},
            data='{"query":"{__typename}"}', req=req, timeout=8,
            allow_redirects=False)
        if r is None or r.status_code >= 500: return None
        try:
            j = r.json()
            if "data" in j or "errors" in j:
                return base + path
        except Exception:
            return None
        return None

    # VL-TURBO deep: parallelize 4 endpoint discovery probes via pool(4).
    # Was ~32s sequential, now ~8s parallel. Preserves first-match priority.
    endpoint = None
    results = []
    with ThreadPoolExecutor(max_workers=min(4, len(GRAPHQL_PATHS))) as pool:
        for result in pool.map(_probe, GRAPHQL_PATHS, timeout=21):
            results.append(result)
    for r in results:
        if r is not None:
            endpoint = r
            break

    if not endpoint:
        return standard_response(
            tool="graphql_field_suggestions_leak", target=req.target, findings=[],
            tests_performed=len(GRAPHQL_PATHS), vulnerable=False,
            skipped_reason="No GraphQL endpoint")

    # Send query with deliberately misspelled field
    r = safe_request("POST", endpoint,
        headers={"Content-Type": "application/json",
                  "User-Agent": "VulnusLab/1.0"},
        data='{"query":"{ vulnuslabXyz123 }"}',
        req=req, timeout=8, allow_redirects=False)
    if r is None:
        return standard_response(
            tool="graphql_field_suggestions_leak", target=req.target, findings=[],
            tests_performed=2, vulnerable=False,
            skipped_reason="no response to misspelled probe")
    body = (r.text or "")[:5000]
    findings = []
    if "did you mean" in body.lower() or "Did you mean" in body:
        findings.append(wrap_finding(
            "GraphQL field-suggestion ENABLED — schema leak via error messages",
            "MEDIUM", cvss="5.3", cwe="CWE-209", owasp="A05:2021",
            remediation="Disable field suggestions in production GraphQL "
                        "responses. Apollo: ApolloServerPlugin{requestDidStart: "
                        "({errors}) => filter 'Did you mean' from errors}. "
                        "graphql-java: disable graphql.execution.preparsed."
                        "RecommendedFieldNamesProvider in prod. Without this, "
                        "even with introspection off, attacker maps the schema "
                        "field-by-field via wrong-field error tells.",
            evidence_marker="misspelled probe → response contains 'Did you mean'"))
    else:
        findings.append(wrap_finding(
            "GraphQL doesn't expose field suggestions", "POSITIVE", cwe="CWE-209",
            remediation="Maintain.",
            evidence_marker="misspelled query → no 'did you mean' in response"))
    return standard_response(
        tool="graphql_field_suggestions_leak", target=req.target, findings=findings,
        tests_performed=2, vulnerable=bool(findings) and findings[0].get("severity") == "MEDIUM",
        tests_summary=f"endpoint: {endpoint}", raw_data={"endpoint": endpoint})


def register(app):
    app.include_router(router)

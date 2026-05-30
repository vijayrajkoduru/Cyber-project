"""graphql_batching_abuse — POST many queries in one request to bypass rate limits.

Most GraphQL servers accept an ARRAY of queries in a single POST. If the
server's per-request rate limit doesn't account for query-count, an attacker
sends [Q,Q,Q,Q,...] to amplify (login bruteforce, password reset spam, etc.).

Zero-FP: only reports if the server actually processes >1 query AND no rate
limit kicks in.
"""
import json
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)

router = APIRouter()

PROBE_QUERY = {"query": "{__typename}"}
BATCH_QUERY = [{"query": "{__typename}"} for _ in range(10)]
GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]


def _post_json(url, body, req):
    return safe_request(
        "POST", url,
        headers={"Content-Type": "application/json",
                  "User-Agent": "VulnusLab/1.0"},
        data=json.dumps(body), req=req, timeout=12,
        allow_redirects=True)


@router.post("/api/webapp/scan/graphql_batching_abuse")
def scan_graphql_batching_abuse(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    endpoint_found = None
    sample_resp = None

    # 1. Discover GraphQL endpoint
    for path in GRAPHQL_PATHS:
        url = base + path
        r = _post_json(url, PROBE_QUERY, req)
        if r is None or r.status_code >= 500: continue
        try:
            j = r.json()
        except Exception:
            continue
        if "data" in j or "errors" in j or "__typename" in str(j):
            endpoint_found = url
            sample_resp = j
            break

    if not endpoint_found:
        return standard_response(
            tool="graphql_batching_abuse", target=req.target, findings=[],
            tests_performed=len(GRAPHQL_PATHS), vulnerable=False,
            skipped_reason=f"No GraphQL endpoint at common paths: {GRAPHQL_PATHS}",
            tests_summary="No GraphQL endpoint detected")

    # 2. Try batching
    r = _post_json(endpoint_found, BATCH_QUERY, req)
    if r is None:
        return standard_response(
            tool="graphql_batching_abuse", target=req.target, findings=[],
            tests_performed=2, vulnerable=False,
            skipped_reason="batch POST returned no response")

    accepted = False
    rate_limited = r.status_code == 429
    if r.status_code in (200, 207):
        try:
            jr = r.json()
            if isinstance(jr, list) and len(jr) >= 5:
                accepted = True
        except Exception:
            pass

    if accepted and not rate_limited:
        findings.append(wrap_finding(
            "GraphQL batching accepted — rate-limit AMPLIFICATION possible",
            "HIGH", cvss="7.5", cwe="CWE-770", owasp="A04:2021",
            remediation="Reject array-form GraphQL requests OR count each query "
                        "in the batch against the rate-limit budget. Without this, "
                        "an attacker sends 100 login queries in 1 HTTP request to "
                        "bypass per-IP throttling. Alternatively, set max batch size "
                        "via Apollo Server's `validationRules` (NoBatchedQueriesRule).",
            evidence_marker=f"POST {endpoint_found} with 10-query batch "
                              f"returned HTTP {r.status_code} array of {len(jr) if accepted else '?'} responses"))
    elif rate_limited:
        findings.append(wrap_finding(
            "GraphQL endpoint rate-limits batch requests (HTTP 429) — properly protected",
            "POSITIVE", cwe="CWE-770",
            remediation="Continue enforcing per-query rate limits.",
            evidence_marker=f"POST {endpoint_found} with 10-query batch → HTTP 429"))
    else:
        findings.append(wrap_finding(
            f"GraphQL endpoint rejected batched request (HTTP {r.status_code})",
            "POSITIVE", cwe="CWE-770",
            remediation="Maintain. Batching explicitly disabled.",
            evidence_marker=f"POST {endpoint_found} with batch → HTTP {r.status_code}"))

    return standard_response(
        tool="graphql_batching_abuse", target=req.target, findings=findings,
        tests_performed=2, vulnerable=bool(accepted and not rate_limited),
        tests_summary=f"Endpoint: {endpoint_found}; batch {'ACCEPTED' if accepted else 'rejected'}",
        raw_data={"endpoint": endpoint_found, "batch_accepted": accepted,
                   "status_code": r.status_code})


def register(app):
    app.include_router(router)

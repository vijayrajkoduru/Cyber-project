"""graphql_alias_injection — GraphQL aliases bypass field-level rate limits.

Field-level rate-limit defense fails if the limiter counts by field-name
only. Attacker uses aliases: query { a:login(...) b:login(...) c:login(...) }
runs login 3x in one request — each alias is a unique field-name in
the response but same resolver.
"""
import json
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()
GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]


def _post(url, body, req):
    return safe_request("POST", url,
        headers={"Content-Type": "application/json",
                  "User-Agent": "VulnusLab/1.0"},
        data=json.dumps(body), req=req, timeout=12, allow_redirects=False)


@router.post("/api/webapp/scan/graphql_alias_injection")
@vl_turbo()
@vl_verify()
def scan_graphql_alias_injection(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    endpoint = None
    for path in GRAPHQL_PATHS:
        url = base + path
        r = _post(url, {"query": "{__typename}"}, req)
        if r is None or r.status_code >= 500: continue
        try:
            if "data" in r.json() or "errors" in r.json():
                endpoint = url; break
        except Exception:
            continue
    if not endpoint:
        return standard_response(
            tool="graphql_alias_injection", target=req.target, findings=[],
            tests_performed=len(GRAPHQL_PATHS), vulnerable=False,
            skipped_reason="No GraphQL endpoint at common paths")

    # Build query with 20 aliases of __typename
    aliases = "\n".join(f"a{i}:__typename" for i in range(20))
    alias_query = {"query": f"{{ {aliases} }}"}
    r = _post(endpoint, alias_query, req)
    findings = []
    if r is None:
        return standard_response(
            tool="graphql_alias_injection", target=req.target, findings=[],
            tests_performed=2, vulnerable=False,
            skipped_reason="alias query dropped")

    try:
        data = r.json()
        keys_returned = list(data.get("data", {}).keys()) if isinstance(data.get("data"), dict) else []
        accepted = len(keys_returned) >= 10
    except Exception:
        accepted = False
        keys_returned = []

    if accepted and r.status_code == 200:
        findings.append(wrap_finding(
            f"GraphQL aliases accepted ({len(keys_returned)}) — field-level rate-limit bypass",
            "MEDIUM", cvss="5.3", cwe="CWE-770", owasp="A04:2021",
            remediation="Count ALIASES against the rate-limit budget per resolver, "
                        "not just by field name. Apollo: write a custom plugin that "
                        "walks document.definitions and counts SelectionSet entries "
                        "with same name property. Or impose a max-aliases-per-query "
                        "limit via graphql-depth-limit / graphql-cost-analysis.",
            evidence_marker=f"sent 20 aliases of __typename, got {len(keys_returned)} keys in response"))
    elif r.status_code == 429:
        findings.append(wrap_finding(
            "Alias query rate-limited (HTTP 429) — properly defended",
            "POSITIVE", cwe="CWE-770",
            remediation="Maintain. Continue enforcing alias-count limits.",
            evidence_marker=f"alias query → HTTP 429 ({r.status_code})"))
    else:
        findings.append(wrap_finding(
            f"Alias query rejected (HTTP {r.status_code})",
            "POSITIVE", cwe="CWE-770",
            remediation="Maintain. Aliases explicitly limited.",
            evidence_marker=f"alias query → HTTP {r.status_code}"))

    return standard_response(
        tool="graphql_alias_injection", target=req.target, findings=findings,
        tests_performed=2, vulnerable=accepted,
        tests_summary=f"endpoint: {endpoint}, aliases: {len(keys_returned)}",
        raw_data={"endpoint": endpoint, "aliases_returned": len(keys_returned),
                   "status_code": r.status_code})


def register(app):
    app.include_router(router)

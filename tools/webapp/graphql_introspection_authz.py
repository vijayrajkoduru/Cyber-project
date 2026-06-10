"""graphql_introspection_authz — introspection access without auth.

Existing graphql_introspection scanner checks if introspection is enabled.
This one tests AUTHORIZATION: server requires auth for /graphql normal
queries BUT allows introspection without auth → attacker maps entire
schema unauth.
"""
import json
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]

INTROSPECTION_QUERY = {
    "query": "{__schema{types{name fields{name}}}}",
}
NORMAL_QUERY = {
    "query": "{__typename}",
}


def _post(url, body, headers, req):
    return safe_request("POST", url,
        headers={**headers, "Content-Type": "application/json",
                  "User-Agent": "VulnusLab/1.0"},
        data=json.dumps(body), req=req, timeout=10, allow_redirects=False)


@router.post("/api/webapp/scan/graphql_introspection_authz")
@vl_turbo()
@vl_verify()
def scan_graphql_introspection_authz(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")

    endpoint = None
    for path in GRAPHQL_PATHS:
        url = base + path
        # Try a basic typename query — even unauth, GraphQL servers usually
        # respond with either {data:...} or {errors:[...]} on POST
        r = _post(url, NORMAL_QUERY, {}, req)
        if r is None or r.status_code >= 500: continue
        try:
            j = r.json()
        except Exception:
            continue
        if "data" in j or "errors" in j:
            endpoint = url
            break

    if not endpoint:
        return standard_response(
            tool="graphql_introspection_authz", target=req.target, findings=[],
            tests_performed=len(GRAPHQL_PATHS), vulnerable=False,
            skipped_reason="No GraphQL endpoint at common paths")

    # Probe normal query unauth
    r_normal = _post(endpoint, NORMAL_QUERY, {}, req)
    # Probe introspection unauth
    r_intro = _post(endpoint, INTROSPECTION_QUERY, {}, req)

    findings = []
    if r_normal is None or r_intro is None:
        return standard_response(
            tool="graphql_introspection_authz", target=req.target, findings=[],
            tests_performed=2, vulnerable=False,
            skipped_reason="Probe requests dropped")

    try:
        normal_json = r_normal.json()
        intro_json = r_intro.json()
    except Exception:
        return standard_response(
            tool="graphql_introspection_authz", target=req.target, findings=[],
            tests_performed=2, vulnerable=False,
            skipped_reason="Non-JSON GraphQL response")

    # Decisions:
    # CASE A: introspection works (data.__schema present) AND no auth required for normal → public API, no big deal
    # CASE B: introspection works AND normal query requires auth → BUG
    # CASE C: introspection blocked (errors) → fine

    intro_works = isinstance(intro_json.get("data"), dict) and intro_json["data"].get("__schema")
    normal_needs_auth = (isinstance(normal_json.get("errors"), list) and
                          any(
                              any(k in str(e).lower() for k in ("unauthorized", "not authenticated",
                                                                 "must be logged", "auth required",
                                                                 "401", "forbidden"))
                              for e in normal_json["errors"]
                          )) or r_normal.status_code in (401, 403)

    if intro_works and normal_needs_auth:
        # The CRITICAL case
        types = (intro_json.get("data", {}).get("__schema", {}).get("types") or [])
        findings.append(wrap_finding(
            f"Introspection accessible without auth, but normal queries require auth — schema leak ({len(types)} types)",
            "HIGH", cvss="7.5", cwe="CWE-200", owasp="A05:2021",
            remediation="Treat introspection like any other resolver: require "
                        "auth + ABAC. Apollo Server: NoIntrospectionAfter rule, "
                        "or check JWT in context before allowing __schema fields. "
                        "Production servers often disable introspection entirely "
                        "(NODE_ENV=production + introspection: false). Without "
                        "this, attacker maps every mutation/query name + their "
                        "args without ever auth'ing.",
            evidence_marker=f"intro returned {len(types)} types unauth; "
                              f"normal query → {r_normal.status_code} requires auth"))
    elif intro_works:
        findings.append(wrap_finding(
            "Introspection enabled (no auth required for any query)",
            "INFO", cwe="CWE-200",
            remediation="If this is a public API, that's fine. For internal/B2B "
                        "APIs, disable introspection in production.",
            evidence_marker=f"intro + normal both unauth, types: "
                              f"{len(intro_json.get('data', {}).get('__schema', {}).get('types') or [])}"))
    elif not intro_works:
        findings.append(wrap_finding(
            "Introspection blocked",
            "POSITIVE", cwe="CWE-200",
            remediation="Maintain. Continue auditing schema gate logic.",
            evidence_marker=f"intro response: {str(intro_json)[:120]}"))

    return standard_response(
        tool="graphql_introspection_authz", target=req.target, findings=findings,
        tests_performed=3,
        vulnerable=any("HIGH" in f.get("severity", "") for f in findings),
        tests_summary=f"endpoint: {endpoint}, intro: {intro_works}, "
                       f"normal-needs-auth: {normal_needs_auth}",
        raw_data={"endpoint": endpoint,
                   "introspection_accessible": intro_works,
                   "normal_query_needs_auth": normal_needs_auth})


def register(app):
    app.include_router(router)

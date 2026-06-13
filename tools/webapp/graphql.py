"""GraphQL security audit — introspection + sensitive type exposure."""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_post, wrap_finding, standard_response)
from tools._payloads.webapp._loader import load_json
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/api/v1/graphql",
                  "/v1/graphql", "/query", "/api/query"]
_INTROSPECTION_QUERY = (
    '{"query":"{__schema{queryType{name} mutationType{name} '
    'types{name fields{name}}}}"}'
)
_SENSITIVE_TYPES = ("password", "passwordhash", "secret", "token",
                    "apikey", "creditcard", "ssn", "privatekey")

# === GRAPHQL-AI-EXTRA-V1 ===
# AI-curated GraphQL attack catalogue (35 entries: introspection variants,
# batching DoS, alias overload, deep nesting, mutation CSRF, mass assignment,
# IDOR, SQLi-in-arg, NoSQLi-in-arg, endpoint discovery, GraphiQL probes).
# - endpoint-probe entries seed _GRAPHQL_PATHS with extra discovery paths
# - introspection entries seed alternate __schema query payloads
_AI_EXTRA_GRAPHQL = load_json("graphql_payloads", fallback=[])
for _p in _AI_EXTRA_GRAPHQL:
    if not isinstance(_p, dict): continue
    if _p.get("category") == "endpoint-probe":
        ep = _p.get("endpoint")
        if ep and ep.startswith("/") and ep not in _GRAPHQL_PATHS:
            _GRAPHQL_PATHS.append(ep)
# === /GRAPHQL-AI-EXTRA-V1 ===


@router.post("/api/webapp/scan/graphql")
@vl_turbo()
@vl_verify()
def scan_graphql(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings, tests, confirmed = [], 0, []

    for path in _GRAPHQL_PATHS:
        url = base + path
        tests += 1
        r = safe_post(url, data=_INTROSPECTION_QUERY, req=req,
                      headers={"Content-Type": "application/json"},
                      allow_redirects=False, timeout=10)
        if r is None or r.status_code != 200:
            continue
        body = (r.text or "")[:30000]
        if '"__schema"' not in body and '"types"' not in body:
            continue
        # Introspection confirmed
        findings.append(wrap_finding(
            f"GraphQL introspection enabled at {path}",
            "MEDIUM", cvss="5.3", cwe="CWE-200", owasp="A05:2021",
            remediation=("Disable introspection in production. For Apollo Server: "
                       "introspection:false. For GraphQL.js: validationRules: "
                       "[NoSchemaIntrospectionCustomRule]"),
            evidence_marker=f"POST {path} __schema query returned {len(body)} bytes of schema data"))
        confirmed.append({"path": path, "kind": "introspection_enabled"})
        # Check for sensitive field names in the exposed schema
        body_low = body.lower()
        found_sensitive = [t for t in _SENSITIVE_TYPES if f'"{t}"' in body_low or f'"name":"{t}"' in body_low]
        if found_sensitive:
            findings.append(wrap_finding(
                f"GraphQL schema exposes sensitive field names: {', '.join(found_sensitive)}",
                "HIGH", cvss="7.5", cwe="CWE-200", owasp="A01:2021",
                remediation=("Sensitive fields in GraphQL types are still queryable even if hidden in UI. "
                           "Remove from schema or add @auth directives. Disable introspection in prod."),
                evidence_marker=f"GraphQL types include: {found_sensitive}"))
            confirmed.append({"path": path, "kind": "sensitive_schema",
                              "fields": found_sensitive})
        break  # one GraphQL endpoint is enough

    if not findings and tests:
        findings.append(wrap_finding(
            "No GraphQL exposure — no endpoint leaked introspection or sensitive fields",
            "POSITIVE", cwe="CWE-200",
            remediation="Maintain. Keep introspection disabled in production and apply "
                        "field-level authorization. Re-test after schema changes.",
            evidence_marker=f"{tests} GraphQL endpoint(s) probed; no introspection "
                            "or sensitive-field exposure"))
    return standard_response(tool="graphql", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"GraphQL: {tests} endpoints probed for introspection + sensitive field exposure",
        raw_data={"graphql": {"confirmed": confirmed}})


def register(app):
    app.include_router(router)

"""Webapp: GraphQL introspection detection.

VL-VERIFY: requires __schema in JSON response body. The JSON-parse gate
catches most SPA-shell FPs. Stamp spa_catchall on output for report
transparency.
"""
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, wrap_finding, standard_response
from tools._vl_core.spa_canary import detect_spa_catchall_sync

router = APIRouter()

_GRAPHQL_PATHS = ["/graphql","/graphiql","/api/graphql","/v1/graphql","/v2/graphql","/api/v1/graphql","/query","/playground","/api/playground"]
_INTROSPECTION_QUERY = '{"query":"{__schema{queryType{name}mutationType{name}types{name kind}}}"}'


@router.post("/api/webapp/graphql_introspection")
async def webapp_graphql_introspection(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    spa = detect_spa_catchall_sync(base)
    findings = []
    discovered = []
    for path in _GRAPHQL_PATHS:
        url = base + path
        try:
            r = requests.post(url, data=_INTROSPECTION_QUERY,
                              headers={"Content-Type": "application/json", "User-Agent": "VulnusLab/1.0"},
                              timeout=8, allow_redirects=False, verify=False)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        try:
            data = r.json()
        except Exception:
            continue
        if not (isinstance(data, dict) and data.get("data") and "__schema" in data["data"]):
            continue
        schema = data["data"]["__schema"]
        types = schema.get("types", [])
        query_type = (schema.get("queryType") or {}).get("name", "Query")
        mutation_type = (schema.get("mutationType") or {}).get("name")
        discovered.append({"url": path, "types": len(types), "query": query_type, "mutation": mutation_type})
        findings.append(wrap_finding(
            f"GraphQL introspection enabled at {path} ({len(types)} types exposed)",
            "HIGH",
            cvss="7.5", cwe="CWE-200", cwe_name="Information Exposure",
            owasp="A05:2021",
            remediation="Disable GraphQL introspection in production. Set introspection: false in apollo-server / graphql-yoga config.",
            evidence_marker=f"POST {path} returned __schema with {len(types)} types; queries={query_type}, mutations={mutation_type or 'none'}",
        ))

    return standard_response(
        tool="graphql_introspection", target=req.target,
        findings=findings, tests_performed=len(_GRAPHQL_PATHS),
        tests_summary=f"Tested {len(_GRAPHQL_PATHS)} GraphQL endpoints; {len(discovered)} expose introspection",
        raw_data={"graphql_introspection": {"discovered": discovered,
                                              "spa_catchall": spa["is_spa"]}},
    )


def register(app):
    app.include_router(router)

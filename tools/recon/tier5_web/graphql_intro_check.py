"""graphql_intro_check — VL-FORGE Recon §5 Web App Recon (real, zero-FP)."""
import asyncio, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url
import json

router = APIRouter()

async def gather(ctx: ScanContext):
    base = base_url(ctx.host)
    introspection = "{__schema{queryType{name} types{name kind}}}"
    body = json.dumps({"query":introspection}).encode()
    endpoint_found = ""; introspection_enabled = False; types_count = 0
    for path in ("/graphql","/api/graphql","/v1/graphql","/query"):
        c, _, b = await fetch(f"{base}{path}", method="POST",
                              headers={"Content-Type":"application/json"}, body=body, timeout=6)
        if c == 200:
            try:
                d = json.loads(b.decode("utf-8","ignore"))
                if "data" in d and "__schema" in d.get("data",{}):
                    endpoint_found = path
                    introspection_enabled = True
                    types_count = len(d["data"]["__schema"].get("types",[]))
                    break
            except Exception: pass
    ctx.state["endpoint"] = endpoint_found
    ctx.state["introspection_enabled"] = introspection_enabled
    ctx.state["types_count"] = types_count
    ctx.source("POST introspection query to 4 common GraphQL paths")

RULES = [
    lambda s: {"name":"GraphQL Introspection Enabled in Production","severity":"MEDIUM",
        "evidence":f"GraphQL endpoint at {s.get('endpoint')} returned full schema ({s.get('types_count')} types) via introspection",
        "remediation":"Disable introspection in production: GraphQL.Server config { introspection: false }",
        "cwe":"CWE-200","owasp":"A05:2021"
    } if s.get("introspection_enabled") else None,
]

@router.post("/api/recon/graphql_intro_check")
async def recon_graphql_intro_check(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="graphql_intro_check",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Endpoint","endpoint"),("Introspection Enabled","introspection_enabled"),("Types Count","types_count")])

def register(app):
    app.include_router(router)

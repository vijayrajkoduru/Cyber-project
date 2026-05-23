"""GraphQL Introspection v1 — VL-FORGE pattern.

Route: /api/recon/graphql_introspect

Probes common GraphQL endpoint paths; if reachable, sends the standard
__schema query. If introspection is enabled in production, the schema
dumps every type / query / mutation — handing attackers the API map.

Sources (parallel):
  1. Path probing — 12 common GraphQL locations
  2. Schema dump via __schema query
  3. GraphQL Playground / GraphiQL UI detection
"""
import asyncio

import requests

from fastapi import APIRouter, Depends

from tools._shared import (ScanRequest, verify_scan_quota, recon_host,
                            web_url)
from tools._framework import ScanContext, run_scanner
from tools._payloads.tier6_findings import GRAPHQL_FINDING_RULES

router = APIRouter()


_GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/query", "/api/query", "/api/v1/graphql",
    "/graphql/v1", "/gql", "/api/gql", "/_graphql",
    "/admin/graphql",
]


_INTROSPECTION_QUERY = """
{ __schema { types { name fields { name } } queryType { name } mutationType { name } } }
""".strip()


def _probe_endpoint(url):
    """POST introspection query — if response contains __schema, endpoint is exposed."""
    try:
        r = requests.post(url, json={"query": _INTROSPECTION_QUERY},
                           timeout=6, verify=False,
                           headers={"User-Agent": "VulnusLab/1.0",
                                     "Content-Type": "application/json"})
        if r.status_code not in (200, 400): return None
        body = (r.text or "")[:80000]
        if '"__schema"' in body or "queryType" in body:
            return {"url": url, "status": r.status_code,
                    "body_sample": body[:400], "introspection": True}
        # Some servers return error message but endpoint is still graphql
        if "graphql" in body.lower() or "GraphQL" in body:
            return {"url": url, "status": r.status_code,
                    "body_sample": body[:400], "introspection": False}
        return None
    except Exception:
        return None


def _probe_playground(url):
    """GET the endpoint — if HTML response with GraphiQL/Playground UI, it's exposed."""
    try:
        r = requests.get(url, timeout=5, verify=False,
                          headers={"User-Agent": "VulnusLab/1.0",
                                    "Accept": "text/html"})
        if r.status_code != 200: return None
        body = (r.text or "")[:30000]
        if any(m in body for m in ["GraphiQL", "graphql-playground", "Apollo Sandbox", "GraphQL Playground"]):
            return {"url": url, "kind": "GraphQL IDE"}
        return None
    except Exception:
        return None


def _parse_schema(body):
    """Quick parse: count types and mutations from introspection response."""
    try:
        import json as _j
        data = _j.loads(body)
        schema = (data.get("data") or {}).get("__schema") or {}
        types = schema.get("types") or []
        mut = schema.get("mutationType") or {}
        type_count = sum(1 for t in types if not (t.get("name") or "").startswith("__"))
        mut_count = 0
        if mut.get("name"):
            for t in types:
                if t.get("name") == mut.get("name"):
                    mut_count = len(t.get("fields") or [])
                    break
        return type_count, mut_count
    except Exception:
        return 0, 0


async def gather(ctx: ScanContext):
    base = web_url(ctx.host).rstrip("/")
    ctx.state["base_reachable"] = True
    ctx.state["paths_probed"] = len(_GRAPHQL_PATHS)

    # Probe all paths in parallel
    results = await asyncio.gather(*[
        asyncio.to_thread(_probe_endpoint, base + p) for p in _GRAPHQL_PATHS
    ])

    hits = [r for r in results if r]
    if hits:
        # Pick the first introspectable endpoint, else first reachable
        introspectable = next((h for h in hits if h.get("introspection")), None)
        target = introspectable or hits[0]
        ctx.state["endpoint_found"] = target["url"]
        ctx.source(f"path-probe ({len(hits)} reachable)")
        if introspectable:
            ctx.state["introspection_enabled"] = True
            full_body = requests.post(target["url"],
                                       json={"query": _INTROSPECTION_QUERY},
                                       timeout=8, verify=False,
                                       headers={"User-Agent": "VulnusLab/1.0",
                                                 "Content-Type": "application/json"}).text
            tc, mc = _parse_schema(full_body)
            ctx.state["type_count"]     = tc
            ctx.state["mutation_count"] = mc
            ctx.state["schema_sample"]  = full_body[:600]
            ctx.source("schema-dump")

        # Probe each reachable endpoint for Playground UI
        play_results = await asyncio.gather(*[
            asyncio.to_thread(_probe_playground, h["url"]) for h in hits
        ])
        play = next((p for p in play_results if p), None)
        if play:
            ctx.state["playground_exposed"] = True
            ctx.state["playground_url"]     = play["url"]
            ctx.source("playground-detected")


INTEL_FIELDS = [
    ("Paths probed",           "paths_probed"),
    ("Endpoint found",          "endpoint_found"),
    ("Introspection enabled",  "introspection_display"),
    ("Schema size",             "schema_size_display"),
    ("Playground exposed",      "playground_url"),
]


@router.post("/api/recon/graphql_introspect")
async def recon_graphql_introspect(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        if ctx.state.get("introspection_enabled"):
            ctx.state["introspection_display"] = "YES — schema fully exposed"
        elif ctx.state.get("endpoint_found"):
            ctx.state["introspection_display"] = "No (endpoint reachable, properly hardened)"
        tc = ctx.state.get("type_count", 0)
        mc = ctx.state.get("mutation_count", 0)
        if tc or mc:
            ctx.state["schema_size_display"] = f"{tc} type(s), {mc} mutation(s)"

    return await run_scanner(
        host=host, tool="graphql_introspect",
        gather_func=gather_with_display,
        finding_rules=GRAPHQL_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["endpoint_found", "introspection_enabled", "type_count"],
    )


def register(app):
    app.include_router(router)

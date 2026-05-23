"""API Docs Discovery v2 — VL-FORGE pattern.

Route: /api/recon/api_docs

Sources (parallel):
  1. Direct probe of 30+ common API doc paths
  2. Validate response (JSON / HTML content matching swagger/openapi signatures)
"""
import asyncio
import re

import requests

from fastapi import APIRouter, Depends

from tools._shared import (ScanRequest, verify_scan_quota, recon_host,
                            web_url)
from tools._framework import ScanContext, run_scanner
from tools._payloads.tier5_findings import API_DOCS_FINDING_RULES

router = APIRouter()


_API_DOC_PATHS = [
    # Swagger / OpenAPI
    "/swagger", "/swagger.json", "/swagger.yaml", "/swagger/index.html",
    "/swagger-ui", "/swagger-ui.html", "/swagger-ui/index.html",
    "/api-docs", "/api-docs.json", "/v2/api-docs", "/v3/api-docs",
    "/openapi", "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/api/swagger", "/api/openapi", "/api/docs", "/api/v1/swagger",
    "/api/v2/swagger", "/api/v1/openapi",
    # GraphQL
    "/graphql", "/graphiql", "/api/graphql",
    # Postman / Insomnia / Stoplight
    "/postman", "/postman.json", "/collection.json",
    "/redoc", "/redoc/index.html",
    # Other
    "/docs", "/docs/api", "/api/v1/docs",
]


_SWAGGER_SIGNATURES = [
    r'"swagger"\s*:', r'"openapi"\s*:', r'"info"\s*:.*"title"',
    r'swagger-ui', r'graphiql',
    r'<swagger-ui', r'<rapi-doc',
]


def _validate_api_doc(url):
    try:
        r = requests.get(url, timeout=6, verify=False, allow_redirects=False,
                          headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code != 200: return False
        text = (r.text or "")[:5000]
        return any(re.search(p, text, re.I) for p in _SWAGGER_SIGNATURES)
    except Exception:
        return False


async def gather(ctx: ScanContext):
    base = web_url(ctx.host).rstrip("/")
    ctx.state["base_reachable"] = True

    candidates = [base + p for p in _API_DOC_PATHS]
    results = await asyncio.gather(*[
        asyncio.to_thread(_validate_api_doc, url) for url in candidates
    ])

    exposed = []
    for url, ok in zip(candidates, results):
        if ok:
            exposed.append(url)

    ctx.state["exposed_endpoints"] = exposed
    ctx.state["paths_probed"] = len(_API_DOC_PATHS)
    ctx.source(f"api-doc-probe ({len(_API_DOC_PATHS)} paths)")
    if exposed:
        ctx.source(f"swagger-signature-match ({len(exposed)})")


INTEL_FIELDS = [
    ("Paths probed",     "paths_probed"),
    ("Exposed endpoints", "exposed_display"),
]


@router.post("/api/recon/api_docs")
async def recon_api_docs(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        ee = ctx.state.get("exposed_endpoints") or []
        if ee: ctx.state["exposed_display"] = ", ".join(ee[:5])

    return await run_scanner(
        host=host, tool="api_docs",
        gather_func=gather_with_display,
        finding_rules=API_DOCS_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["exposed_endpoints"],
    )


def register(app):
    app.include_router(router)

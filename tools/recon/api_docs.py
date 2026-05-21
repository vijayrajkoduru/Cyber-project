"""recon_api_docs — find exposed Swagger / GraphQL / OAuth endpoints."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, safe_get, web_url

router = APIRouter()

CATEGORIES = {
    "swagger": ["/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger.json",
                "/swagger.yaml", "/swagger/v1/swagger.json", "/api-docs", "/api/docs",
                "/v1/swagger", "/v2/swagger", "/v3/swagger"],
    "openapi": ["/openapi.json", "/openapi.yaml", "/.well-known/openapi.json"],
    "graphql": ["/graphql", "/graphiql", "/graphql-playground", "/api/graphql",
                "/v1/graphql"],
    "redoc": ["/redoc", "/docs/redoc", "/api/redoc"],
    "oauth": ["/.well-known/oauth-authorization-server",
              "/.well-known/openid-configuration", "/.well-known/jwks.json"],
    "actuator": ["/actuator", "/actuator/mappings", "/actuator/env",
                 "/actuator/heapdump"],
}


@router.post("/api/recon/api_docs")
async def recon_api_docs(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings, exposed = [], []
    for category, paths in CATEGORIES.items():
        for path in paths:
            r = safe_get(f"{base}{path}", req=req, allow_redirects=False)
            if r is None or r.status_code != 200:
                continue
            preview = (r.text or "")[:500].lower()
            is_match = any([
                ("swagger" in preview or "openapi" in preview or '"paths"' in preview) and category in ("swagger","openapi","redoc"),
                ("graphql" in preview or "playground" in preview or "__schema" in preview) and category == "graphql",
                ("issuer" in preview or "token_endpoint" in preview) and category == "oauth",
                ("_links" in preview or category == "actuator"),
            ])
            if not is_match: continue
            sev = "HIGH" if category in ("graphql", "swagger", "openapi", "actuator") else "MEDIUM"
            cvss = 7.5 if sev == "HIGH" else 5.3
            kind = {"swagger":"Swagger/OpenAPI doc","openapi":"OpenAPI spec",
                    "graphql":"GraphQL endpoint","redoc":"ReDoc UI",
                    "oauth":"OAuth/OIDC discovery","actuator":"Spring Actuator"}[category]
            exposed.append({"path": path, "url": f"{base}{path}",
                            "category": category, "kind": kind, "size": len(r.content)})
            findings.append({"title": f"{kind} exposed at {path}",
                "severity": sev, "cvss": cvss, "cwe": "CWE-200", "owasp": "A05:2021",
                "evidence": f"{path} returns 200 with {kind.lower()}",
                "remediation": f"Restrict {path} via auth/IP allow-list/VPN."})
    return {"ok": True, "vulnerable": len(findings) > 0, "findings": findings,
            "exposed_endpoints": exposed[:50], "total_exposed": len(exposed),
            "paths_probed": sum(len(v) for v in CATEGORIES.values()),
            "engine": f"API doc discovery ({sum(len(v) for v in CATEGORIES.values())} paths probed)"}


def register(app):
    app.include_router(router)

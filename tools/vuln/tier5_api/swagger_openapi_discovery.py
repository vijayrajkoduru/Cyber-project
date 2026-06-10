"""Swagger/OpenAPI spec exposure + shadow-API inventory - MethodologyScanner.

VL-METHOD Wave 6: probe common OpenAPI spec paths. 6 stages:
  pre_flight    - target reachable
  fingerprint   - SPA detection (catches React Router config in bundle)
  quick_probe   - 4 most common spec paths in parallel
  deep_scan     - 6 less common paths in parallel (only if quick found)
  verify        - re-fetch each spec with Accept:application/json; CONFIRMED
                  only if response is parseable JSON with openapi/swagger version
  privilege_check - exposed spec = "guest" shadow-API surface disclosure
"""
import asyncio
import json

from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url
from tools._vl_core.verify import vl_verify
from tools._methodology import MethodologyScanner
from tools.vuln._vuln_common import http_get, detect_spa_catchall, is_same_as_canary

router = APIRouter()


_QUICK_PATHS = ["/swagger.json", "/openapi.json", "/v2/api-docs", "/v3/api-docs"]
_DEEP_PATHS = [
    "/api-docs",
    "/swagger-ui.html",
    "/swagger/v1/swagger.json",
    "/api/swagger.json",
    "/api/openapi.json",
    "/.well-known/openapi.json",
]


def _looks_like_spec(body, canary_body, spa_is):
    if not body:
        return False
    if spa_is and is_same_as_canary(body, canary_body):
        return False
    if '"swagger"' in body or '"openapi"' in body:
        return True
    if '"paths"' in body and ('":{"/' in body or '": {\n  "/' in body or '":\n  {"/' in body):
        return True
    return False


class SwaggerOpenapiDiscovery(MethodologyScanner):
    name = "swagger_openapi_discovery"

    async def pre_flight(self, ctx):
        ctx.state["base_url"] = web_url(str(ctx.host)).rstrip("/")
        ctx.source("http")
        ctx.state["tested"] = 1
        return True

    async def fingerprint(self, ctx):
        spa = await detect_spa_catchall(ctx.state["base_url"])
        ctx.state["_spa"] = spa
        ctx.state["fingerprint"] = {
            "is_spa": spa.get("is_spa", False),
            "canary_body_len": len(spa.get("canary_body", "")),
        }

    async def _probe_paths(self, ctx, paths):
        base = ctx.state["base_url"]
        spa = ctx.state.get("_spa") or {}
        canary_body = spa.get("canary_body", "") or ""
        spa_is = spa.get("is_spa", False)

        async def _c(p):
            r = await asyncio.to_thread(http_get, base + p, 8, 4000)
            if not (r and r.get("status") == 200):
                return None
            if _looks_like_spec(r.get("body", ""), canary_body, spa_is):
                return p
            return None

        results = await asyncio.gather(*[_c(p) for p in paths])
        return [r for r in results if r]

    async def quick_probe(self, ctx):
        hits = await self._probe_paths(ctx, _QUICK_PATHS)
        ctx.state["_quick_specs"] = hits
        return [{"path": h} for h in hits]

    async def deep_scan(self, ctx):
        hits = await self._probe_paths(ctx, _DEEP_PATHS)
        ctx.state["_deep_specs"] = hits
        return [{"path": h} for h in hits]

    async def verify(self, ctx, finding):
        # Re-fetch with Accept:application/json. Real spec parses as JSON
        # and contains either openapi/swagger version field.
        base = ctx.state["base_url"]
        path = finding["path"]
        r = await asyncio.to_thread(
            http_get, base + path, 8, 100000)
        if not r or r.get("status") != 200:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = f"replay status={r.get('status') if r else 'none'}"
            return finding
        body = r.get("body", "") or ""
        # Try JSON parse
        try:
            j = json.loads(body)
        except Exception:
            j = None
        if isinstance(j, dict) and ("openapi" in j or "swagger" in j or "paths" in j):
            finding["confidence"] = "CONFIRMED"
            ver = j.get("openapi") or j.get("swagger") or "schema-only"
            finding["verification_method"] = f"parseable JSON, spec version={ver}"
            finding["_spec_version"] = ver
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "body did not parse as JSON spec"
        return finding

    async def privilege_check(self, ctx, finding):
        finding["privilege_level"] = "guest" if finding.get("confidence") == "CONFIRMED" else "unknown"
        return finding


def _r_spec(s):
    verified = s.get("methodology_findings") or []
    confirmed = [f for f in verified if f.get("confidence") == "CONFIRMED"]
    if not confirmed:
        return None
    paths = [f["path"] for f in confirmed]
    return {"name": f"API spec exposed publicly ({len(confirmed)}) (CONFIRMED)",
            "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-200",
            "evidence": (f"Reachable: {', '.join(paths[:5])} - full API surface "
                          "(incl. shadow/zombie endpoints) disclosed"),
            "remediation": ("Restrict Swagger/OpenAPI to internal/authenticated access; "
                             "remove from production.")}


def _r_suspected(s):
    verified = s.get("methodology_findings") or []
    suspected = [f for f in verified if f.get("confidence") == "SUSPECTED"]
    if not suspected:
        return None
    paths = [f["path"] for f in suspected]
    return {"name": f"API spec possibly exposed ({len(suspected)}) - SUSPECTED",
            "severity": "LOW", "cvss": 3.1, "cwe": "CWE-200",
            "evidence": f"Probe matched spec markers at {', '.join(paths)} but JSON parse failed.",
            "remediation": "Manually fetch each path to confirm."}


def _r_clean(s):
    verified = s.get("methodology_findings") or []
    if verified:
        return None
    if (s.get("tested") or 0) < 1:
        return None
    return {"name": "No public API spec exposed",
            "severity": "POSITIVE",
            "evidence": "No Swagger/OpenAPI doc reachable on 10 probed paths."}


FINDING_RULES = [_r_spec, _r_suspected, _r_clean]
INTEL_FIELDS = [
    ("Stage timings (ms)", "stage_timings"),
    ("Verified findings", "methodology_findings"),
]


@router.post("/api/vuln/swagger_openapi_discovery")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanner = SwaggerOpenapiDiscovery()
    return await scanner.run_as_endpoint(req,
        finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)

"""GraphQL introspection enabled - MethodologyScanner refactor.

VL-METHOD Wave 6: POST `{__schema{queryType{name}}}` to common GraphQL
endpoints. 6 stages:
  pre_flight    - target reachable
  fingerprint   - SPA detection (suppresses Apollo Studio bundle embeds)
  quick_probe   - 3 most common GraphQL endpoints in parallel
  deep_scan     - 3 less common endpoints (only if quick found)
  verify        - replay with FULL schema query and confirm endpoint
                  actually returns types (not just an error mentioning __schema)
  privilege_check - introspection = guest schema disclosure
"""
import asyncio
import ssl
import urllib.request

from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url
from tools._vl_core.verify import vl_verify
from tools._methodology import MethodologyScanner
from tools.vuln._vuln_common import detect_spa_catchall

router = APIRouter()


_QUICK_EP = ["/graphql", "/api/graphql", "/v1/graphql"]
_DEEP_EP = ["/graphql/v1", "/query", "/api/gql"]

_Q_QUICK = b'{"query":"{__schema{queryType{name}}}"}'
_Q_VERIFY = b'{"query":"{__schema{types{name kind}}}"}'

_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode = ssl.CERT_NONE


def _post(url, query, timeout=8):
    req = urllib.request.Request(
        url, data=query, method="POST",
        headers={"Content-Type": "application/json",
                  "User-Agent": "Mozilla/5.0 (VulnusLab Vuln)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as r:
            return r.status, r.read(4000).decode("utf-8", "ignore")
    except Exception:
        return None, ""


def _looks_introspectable(body, canary_body, spa_is):
    if not body or "__schema" not in body or "queryType" not in body:
        return False
    if spa_is and canary_body and "__schema" in canary_body and "queryType" in canary_body:
        return False
    return True


class GraphqlIntrospection(MethodologyScanner):
    name = "graphql_introspection"

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

    async def _probe_endpoints(self, ctx, endpoints):
        base = ctx.state["base_url"]
        spa = ctx.state.get("_spa") or {}
        canary_body = spa.get("canary_body", "") or ""
        spa_is = spa.get("is_spa", False)

        async def _c(ep):
            st, body = await asyncio.to_thread(_post, base + ep, _Q_QUICK)
            if st != 200:
                return None
            if _looks_introspectable(body, canary_body, spa_is):
                return ep
            return None

        results = await asyncio.gather(*[_c(e) for e in endpoints])
        return [r for r in results if r]

    async def quick_probe(self, ctx):
        hits = await self._probe_endpoints(ctx, _QUICK_EP)
        ctx.state["_quick_ep_hits"] = hits
        return [{"endpoint": h} for h in hits]

    async def deep_scan(self, ctx):
        hits = await self._probe_endpoints(ctx, _DEEP_EP)
        ctx.state["_deep_ep_hits"] = hits
        return [{"endpoint": h} for h in hits]

    async def verify(self, ctx, finding):
        # Replay with a FULL schema query (asks for types[]). A real
        # introspectable endpoint returns a long body with the "types"
        # array. An error response that happens to mention __schema in
        # a stack trace would not contain "types".
        base = ctx.state["base_url"]
        url = base + finding["endpoint"]
        st, body = await asyncio.to_thread(_post, url, _Q_VERIFY)
        if st == 200 and '"types"' in body and len(body) > 500:
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "schema query returned types[] array"
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = (
                f"replay status={st}, body_len={len(body)}, has_types={'types' in body}")
        return finding

    async def privilege_check(self, ctx, finding):
        finding["privilege_level"] = "guest" if finding.get("confidence") == "CONFIRMED" else "unknown"
        return finding


def _r_intro(s):
    verified = s.get("methodology_findings") or []
    confirmed = [f for f in verified if f.get("confidence") == "CONFIRMED"]
    if not confirmed:
        return None
    eps = [f["endpoint"] for f in confirmed]
    return {"name": f"GraphQL introspection enabled ({eps[0]}) (CONFIRMED)",
            "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-200",
            "evidence": f"__schema query returned types[] array at {', '.join(eps)} - full schema disclosed",
            "remediation": ("Disable introspection in production; enforce query "
                             "allow-list + depth/complexity limits.")}


def _r_suspected(s):
    verified = s.get("methodology_findings") or []
    suspected = [f for f in verified if f.get("confidence") == "SUSPECTED"]
    if not suspected:
        return None
    eps = [f["endpoint"] for f in suspected]
    return {"name": f"GraphQL endpoint possibly introspectable ({eps[0]}) - SUSPECTED",
            "severity": "LOW", "cvss": 3.1, "cwe": "CWE-200",
            "evidence": f"Initial probe matched __schema markers at {', '.join(eps)} but full-schema verify did not reproduce.",
            "remediation": "Manually verify with a complete introspection query."}


def _r_clean(s):
    verified = s.get("methodology_findings") or []
    if verified:
        return None
    if (s.get("tested") or 0) < 1:
        return None
    return {"name": "No GraphQL introspection exposed",
            "severity": "POSITIVE",
            "evidence": "No introspectable GraphQL endpoint found across 6 probed paths."}


FINDING_RULES = [_r_intro, _r_suspected, _r_clean]
INTEL_FIELDS = [
    ("Stage timings (ms)", "stage_timings"),
    ("Verified findings", "methodology_findings"),
]


@router.post("/api/vuln/graphql_introspection")
@vl_verify(check_spa=True)
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanner = GraphqlIntrospection()
    return await scanner.run_as_endpoint(req,
        finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)

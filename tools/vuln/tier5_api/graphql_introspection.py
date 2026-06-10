"""GraphQL introspection enabled (schema disclosure). VL-FORGE Vuln tier5 - §5 #72.

VL-VERIFY: existing content gates (__schema + queryType in body) already
prevent SPA-shell FPs since those strings are GraphQL-specific. Belt-and-
braces canary check + state stamp catches edge cases like Apollo Studio
demo embeds in SPA bundles.
"""
import asyncio
import ssl
import urllib.request
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._vl_core import run_scanner
from tools.vuln._vuln_common import detect_spa_catchall

router = APIRouter()
_EP = ["/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1", "/query", "/api/gql"]
_Q = b'{"query":"{__schema{queryType{name}}}"}'
_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode = ssl.CERT_NONE


def _post(url, timeout=8):
    req = urllib.request.Request(url, data=_Q, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "Mozilla/5.0 (VulnusLab Vuln)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as r:
            return r.status, r.read(4000).decode("utf-8", "ignore")
    except Exception:
        return None, ""


async def gather(ctx):
    base = web_url(str(ctx.host)).rstrip("/")
    spa = await detect_spa_catchall(base)
    ctx.state["spa_catchall"] = spa.get("is_spa", False)
    canary_body = spa.get("canary_body", "") or ""

    async def _c(ep):
        st, body = await asyncio.to_thread(_post, base + ep)
        if st != 200:
            return None
        # Drop if the body markers ALSO appear in the SPA canary - means
        # the page is the SPA shell with Apollo/GraphiQL docs inlined.
        if spa.get("is_spa") and canary_body and \
           "__schema" in canary_body and "queryType" in canary_body:
            return None
        if "__schema" in body and "queryType" in body:
            return ep
        return None

    res = await asyncio.gather(*[_c(e) for e in _EP])
    ctx.source("http")
    ctx.state["tested"] = len(_EP)
    found = [e for e in res if e]
    if found:
        ctx.state["graphql_introspection"] = found


def _r_intro(s):
    g = s.get("graphql_introspection") or []
    if not g:
        return None
    return {"name": f"GraphQL introspection enabled ({g[0]})", "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-200",
            "evidence": f"__schema query succeeded at {', '.join(g)} - full schema disclosed",
            "remediation": "Disable introspection in production; enforce query allow-list + depth/complexity limits."}


def _r_clean(s):
    if (s.get("tested") or 0) < 1 or s.get("graphql_introspection"):
        return None
    return {"name": "No GraphQL introspection exposed", "severity": "POSITIVE",
            "evidence": "No introspectable GraphQL endpoint found."}


FINDING_RULES = [_r_intro, _r_clean]
INTEL_FIELDS = [("GraphQL endpoints", "graphql_introspection")]


@router.post("/api/vuln/graphql_introspection")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="graphql_introspection",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)

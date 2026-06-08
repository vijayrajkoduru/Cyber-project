"""A03 NoSQL/LDAP/XPath injection - passive error detection. Self-contained.
Strategy: send minimal injection payloads, look for backend-specific error strings."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import probe_url_async, http_get_async

router = APIRouter()

NOSQL_PAYLOADS = ['{"$ne":null}', "*)(uid=*", "' or 1=1 or '"]
ERROR_FINGERPRINTS = ["mongoerror", "bsonerror", "ldap_search", "xpath syntax error",
                       "couchdb", "neo4j", "syntax error in xpath"]
PROBE_PARAMS = ["q", "user", "id", "filter", "name", "email"]


async def gather(ctx):
    host = str(ctx.host)
    base_url, base = await probe_url_async(host, "/")
    if not base or base.get("status", 0) >= 500:
        ctx.state["tested"] = 0
        ctx.state["skipped_reason"] = "Target unreachable"
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    ctx.state["probes"] = len(PROBE_PARAMS) * len(NOSQL_PAYLOADS)
    hits = []
    for p in PROBE_PARAMS:
        for payload in NOSQL_PAYLOADS:
            url = f"{base_url}?{p}={payload}"
            r = await http_get_async(url, timeout=8)
            if not r:
                continue
            body_lower = r.get("body", "").lower()
            for fp in ERROR_FINGERPRINTS:
                if fp in body_lower:
                    hits.append({"param": p, "error": fp})
                    break
            if hits and hits[-1].get("param") == p:
                break
    ctx.state["nosql_hits"] = hits


def _r_nosql(s):
    hits = s.get("nosql_hits") or []
    if not hits:
        return None
    return {"name": f"NoSQL/LDAP/XPath error exposed via {len(hits)} parameter(s)", "severity": "HIGH", "cvss": 7.5,
            "cwe": "CWE-943",
            "evidence": f"Backend datastore errors leaked from: {', '.join(h['param'] for h in hits)}",
            "remediation": "Validate input types; use parameterised queries for Mongo/LDAP. Suppress detailed errors."}


FINDING_RULES = [_r_nosql]
INTEL_FIELDS = [("Probes sent", "probes"), ("Error hits", "nosql_hits")]


@router.post("/api/vuln/a03_nosql_ldap_xpath")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="a03_nosql_ldap_xpath",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)

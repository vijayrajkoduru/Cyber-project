"""A03 NoSQL/LDAP/XPath injection - passive error detection. VL-METHOD Wave 2.

Refactored 2026-06-09 to MethodologyScanner. Same shape as the Wave 1 payload
scanners. Verify step re-fires with a SECOND payload variant to confirm the
backend is reflecting real parser errors rather than echoing static content.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._methodology import MethodologyScanner
from tools.vuln._vuln_common import probe_url_async, http_get_async
from tools._vl_core.verify import vl_verify

router = APIRouter()

NOSQL_PAYLOADS_QUICK  = ['{"$ne":null}']                  # MongoDB
NOSQL_PAYLOADS_DEEP   = ["*)(uid=*", "' or 1=1 or '"]    # LDAP + XPath
PAYLOAD_VERIFY        = '{"$gt":""}'                       # alt MongoDB op
ERROR_FINGERPRINTS    = ["mongoerror", "bsonerror", "ldap_search",
                          "xpath syntax error", "couchdb", "neo4j",
                          "syntax error in xpath"]
PROBE_PARAMS_QUICK    = ["q", "user", "id"]
PROBE_PARAMS_DEEP     = ["filter", "name", "email"]


async def _fire(base_url, params, payloads):
    hits = []
    for p in params:
        for payload in payloads:
            url = f"{base_url}?{p}={payload}"
            r = await http_get_async(url, timeout=8)
            if not r:
                continue
            body_lower = r.get("body", "").lower()
            for fp in ERROR_FINGERPRINTS:
                if fp in body_lower:
                    hits.append({"param": p, "error": fp, "payload": payload})
                    break
            if hits and hits[-1].get("param") == p:
                break
    return hits


class A03NosqlLdapXpath(MethodologyScanner):
    name = "a03_nosql_ldap_xpath"

    async def pre_flight(self, ctx):
        base_url, base = await probe_url_async(str(ctx.host), "/")
        if not base or base.get("status", 0) >= 500:
            ctx.state["tested"] = 0
            ctx.state["skipped_reason"] = "Target unreachable"
            return False
        ctx.source("http")
        ctx.state["tested"] = 1
        ctx.state["base_url"] = base_url
        ctx.state["probes"] = (len(PROBE_PARAMS_QUICK) + len(PROBE_PARAMS_DEEP)) * \
                               (len(NOSQL_PAYLOADS_QUICK) + len(NOSQL_PAYLOADS_DEEP))
        return True

    async def fingerprint(self, ctx):
        r = await http_get_async(ctx.state["base_url"], timeout=6)
        if r:
            hdrs = r.get("headers") or {}
            ctx.state["fingerprint"] = {
                "server":       (hdrs.get("server") or "")[:80],
                "x_powered_by": (hdrs.get("x-powered-by") or "")[:80],
            }

    async def quick_probe(self, ctx):
        hits = await _fire(ctx.state["base_url"], PROBE_PARAMS_QUICK,
                            NOSQL_PAYLOADS_QUICK)
        ctx.state["quick_hits"] = hits
        return [dict(h) for h in hits]

    async def deep_scan(self, ctx):
        hits = await _fire(ctx.state["base_url"], PROBE_PARAMS_DEEP,
                            NOSQL_PAYLOADS_QUICK + NOSQL_PAYLOADS_DEEP)
        ctx.state["deep_hits"] = hits
        return [dict(h) for h in hits]

    async def verify(self, ctx, finding):
        url = f"{ctx.state['base_url']}?{finding['param']}={PAYLOAD_VERIFY}"
        r = await http_get_async(url, timeout=8)
        if not r:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "verify-probe-failed"
            return finding
        body_lower = r.get("body", "").lower()
        if any(fp in body_lower for fp in ERROR_FINGERPRINTS):
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = f"alt-payload-{PAYLOAD_VERIFY}"
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "alt-payload-no-error"
        return finding


def _r_nosql(s):
    verified = s.get("methodology_findings") or []
    if not verified:
        return None
    confirmed = [f for f in verified if f.get("confidence") == "CONFIRMED"]
    if confirmed:
        params = ", ".join(f["param"] for f in confirmed)
        return {"name": f"NoSQL/LDAP/XPath error CONFIRMED via {len(confirmed)} parameter(s)",
                "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-943",
                "evidence": f"Two distinct payloads both triggered backend errors via: {params}",
                "remediation": "Validate input types; use parameterised queries for Mongo/LDAP. "
                                "Suppress detailed errors."}
    params = ", ".join(f["param"] for f in verified)
    return {"name": f"NoSQL/LDAP/XPath error pattern via {len(verified)} parameter(s) (SUSPECTED)",
            "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-943",
            "evidence": f"Initial payload errored but alt payload did not. Params: {params}",
            "remediation": "Manually verify each parameter."}


FINDING_RULES = [_r_nosql]
INTEL_FIELDS = [
    ("Probes sent", "probes"),
    ("Quick-probe hits", "quick_hits"),
    ("Deep-scan hits", "deep_hits"),
    ("Verified findings", "methodology_findings"),
    ("Stage timings (ms)", "stage_timings"),
]


@router.post("/api/vuln/a03_nosql_ldap_xpath")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanner = A03NosqlLdapXpath()
    return await scanner.run_as_endpoint(req,
        finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)

"""Host Header Injection - passive reflection check. VL-METHOD Wave 3.

Refactored 2026-06-09 to MethodologyScanner. Verify probes the SAME endpoint
with a DIFFERENT attacker host. Real Host-reflection bug echoes any host
value; a static page that just contains "evil.vlattacker.com" by coincidence
wouldn't echo the alt host.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._methodology import MethodologyScanner
from tools.vuln._vuln_common import probe_url_async, http_get_h_async, http_get_async
from tools._vl_core.verify import vl_verify

router = APIRouter()

ATTACKER_HOST_QUICK  = "evil.vlattacker.com"
ATTACKER_HOST_VERIFY = "vlhostcheck.attacker.test"


def _scan_response(r, attacker_host):
    issues = []
    if not r:
        return issues
    loc = (r.get("headers", {}) or {}).get("location", "") or ""
    if attacker_host in loc.lower():
        issues.append({"where": "Location header", "value": loc[:120]})
    body = r.get("body", "") or ""
    if attacker_host in body.lower():
        issues.append({"where": "Response body", "value": "Attacker host reflected"})
    sc = (r.get("headers", {}) or {}).get("set-cookie", "") or ""
    if attacker_host in sc.lower():
        issues.append({"where": "Set-Cookie domain", "value": sc[:120]})
    return issues


class HostHeaderInjection(MethodologyScanner):
    name = "host_header_injection"

    async def pre_flight(self, ctx):
        base_url, base = await probe_url_async(str(ctx.host), "/")
        if not base:
            ctx.state["tested"] = 0
            ctx.state["skipped_reason"] = "Target unreachable"
            return False
        ctx.source("http")
        ctx.state["tested"] = 1
        ctx.state["base_url"] = base_url
        return True

    async def fingerprint(self, ctx):
        r = await http_get_async(ctx.state["base_url"], timeout=6)
        if r:
            hdrs = r.get("headers") or {}
            ctx.state["fingerprint"] = {
                "server": (hdrs.get("server") or "")[:80],
            }

    async def quick_probe(self, ctx):
        r = await http_get_h_async(ctx.state["base_url"],
                                     headers={"Host": ATTACKER_HOST_QUICK}, timeout=8)
        issues = _scan_response(r, ATTACKER_HOST_QUICK)
        ctx.state["quick_hits"] = issues
        ctx.state["host_status"] = (r or {}).get("status")
        # Produce ONE finding per issue so verify runs on each separately
        return [{"where": i["where"], "value": i["value"]} for i in issues]

    async def deep_scan(self, ctx):
        # Single-probe scanner - no deeper attack surface to enumerate
        return []

    async def verify(self, ctx, finding):
        r = await http_get_h_async(ctx.state["base_url"],
                                     headers={"Host": ATTACKER_HOST_VERIFY}, timeout=8)
        issues = _scan_response(r, ATTACKER_HOST_VERIFY)
        # Look for the same "where" location to show in the alt-host probe
        same_loc = [i for i in issues if i["where"] == finding["where"]]
        if same_loc:
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = f"alt-host-{ATTACKER_HOST_VERIFY}-also-reflected"
            finding["verify_value"] = same_loc[0]["value"][:80]
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "alt-host-not-reflected"
        return finding


def _r_hh(s):
    verified = s.get("methodology_findings") or []
    if not verified:
        return None
    confirmed = [f for f in verified if f.get("confidence") == "CONFIRMED"]
    if confirmed:
        return {"name": "Host header reflected without validation (CONFIRMED)",
                "severity": "MEDIUM", "cvss": 6.1, "cwe": "CWE-444",
                "evidence": "; ".join(f"{i['where']}: {i['value']}" for i in confirmed) +
                             " - second probe with different host also reflected",
                "remediation": "Pin trusted hostnames in app + reverse proxy (server_name "
                                "in nginx, Host whitelist in framework). Never use Host "
                                "header to build absolute URLs."}
    return {"name": "Host header may be reflected (SUSPECTED)",
            "severity": "LOW", "cvss": 3.1, "cwe": "CWE-444",
            "evidence": "; ".join(f"{i['where']}: {i['value']}" for i in verified) +
                         " - alt host probe did not reproduce",
            "remediation": "Manually re-test with custom Host values."}


FINDING_RULES = [_r_hh]
INTEL_FIELDS = [
    ("Response status", "host_status"),
    ("Quick-probe hits", "quick_hits"),
    ("Verified findings", "methodology_findings"),
    ("Stage timings (ms)", "stage_timings"),
]


@router.post("/api/vuln/host_header_injection")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanner = HostHeaderInjection()
    return await scanner.run_as_endpoint(req,
        finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)

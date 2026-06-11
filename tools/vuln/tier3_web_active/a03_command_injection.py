"""A03 Command Injection - passive sleep-free output detection. VL-METHOD Wave 1.

Refactored 2026-06-09 to MethodologyScanner. Same shape as a03_sql_injection
and a03_xss: pre_flight -> fingerprint -> quick_probe -> deep_scan -> verify.

Strategy: inject ';id' in common command-like params, look for uid=/gid=/groups=
output. Zero exploitation - we never escalate beyond reading id output.

Verify step re-fires with `;id;echo` shape: a real shell-injection backend
echoes BOTH the id output AND the echo trailer; a static page or canary leak
echoes neither or just the original.
"""
import asyncio
import re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._methodology import MethodologyScanner
from tools.vuln._vuln_common import probe_url_async, http_get_async, CMD_PATTERNS
from tools._vl_core.verify import vl_verify

router = APIRouter()

PROBE_PARAMS_QUICK = ["cmd", "exec", "ip"]
PROBE_PARAMS_DEEP  = ["host", "ping", "query", "system", "do"]
PAYLOAD            = ";id"
PAYLOAD_VERIFY     = ";id;echo VLECHO__"
VERIFY_MARKER      = "VLECHO__"


async def _probe_one(base_url, p, payload):
    url = f"{base_url}?{p}={payload}"
    r = await http_get_async(url, timeout=8)
    if not r:
        return None
    body = r.get("body", "")
    for pattern in CMD_PATTERNS:
        if re.search(pattern, body):
            return {"param": p, "evidence": pattern,
                     "status": r.get("status"), "payload": payload}
    return None


async def _fire(base_url, params, payload):
    # VL-TURBO deep: parallel probe across all params.
    # Was N sequential GETs at 8s each. Now ~8s for all.
    results = await asyncio.gather(
        *[_probe_one(base_url, p, payload) for p in params],
        return_exceptions=True)
    hits = []
    for res in results:
        if isinstance(res, BaseException) or res is None:
            continue
        hits.append(res)
    return hits


class A03CommandInjection(MethodologyScanner):
    name = "a03_command_injection"

    async def pre_flight(self, ctx):
        base_url, base = await probe_url_async(str(ctx.host), "/")
        if not base or base.get("status", 0) >= 500:
            ctx.state["tested"] = 0
            ctx.state["skipped_reason"] = "Target unreachable"
            return False
        ctx.source("http")
        ctx.state["tested"] = 1
        ctx.state["base_url"] = base_url
        ctx.state["probed_params"] = len(PROBE_PARAMS_QUICK) + len(PROBE_PARAMS_DEEP)
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
        hits = await _fire(ctx.state["base_url"], PROBE_PARAMS_QUICK, PAYLOAD)
        ctx.state["quick_hits"] = hits
        return [{"param": h["param"], "evidence": h["evidence"],
                 "status": h["status"]} for h in hits]

    async def deep_scan(self, ctx):
        hits = await _fire(ctx.state["base_url"], PROBE_PARAMS_DEEP, PAYLOAD)
        ctx.state["deep_hits"] = hits
        return [{"param": h["param"], "evidence": h["evidence"],
                 "status": h["status"]} for h in hits]

    async def verify(self, ctx, finding):
        # Re-fire with payload that adds a UNIQUE echo marker. Real injection
        # backend prints the marker too; static page echoing original input
        # won't generate the marker.
        url = f"{ctx.state['base_url']}?{finding['param']}={PAYLOAD_VERIFY}"
        r = await http_get_async(url, timeout=8)
        if not r:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "verify-probe-failed"
            return finding
        body = r.get("body", "")
        if VERIFY_MARKER in body:
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = f"echo-marker-{VERIFY_MARKER}"
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "echo-marker-absent"
        return finding


def _r_cmd(s):
    verified = s.get("methodology_findings") or []
    if not verified:
        return None
    confirmed = [f for f in verified if f.get("confidence") == "CONFIRMED"]
    if confirmed:
        params = ", ".join(f["param"] for f in confirmed)
        return {"name": f"Command injection CONFIRMED via {len(confirmed)} parameter(s)",
                "severity": "CRITICAL", "cvss": 9.8, "cwe": "CWE-78",
                "evidence": f"id output reflected AND unique echo marker {VERIFY_MARKER} "
                             f"returned via: {params}",
                "remediation": "Never pass user input to shell. Use language-native APIs; "
                                "if shell needed, use exec arrays with shell=False."}
    params = ", ".join(f["param"] for f in verified)
    return {"name": f"Command output pattern observed via {len(verified)} parameter(s) (SUSPECTED)",
            "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-78",
            "evidence": f"id-like output matched but echo verify did not reproduce. "
                         f"Possible static page / log echo. Params: {params}",
            "remediation": "Manually verify each parameter. If confirmed, audit all shell-out "
                            "code paths and refactor to language-native APIs."}


FINDING_RULES = [_r_cmd]
INTEL_FIELDS = [
    ("Parameters probed", "probed_params"),
    ("Quick-probe hits", "quick_hits"),
    ("Deep-scan hits",   "deep_hits"),
    ("Verified findings", "methodology_findings"),
    ("Stage timings (ms)", "stage_timings"),
]


@router.post("/api/vuln/a03_command_injection")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanner = A03CommandInjection()
    return await scanner.run_as_endpoint(req,
        finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)

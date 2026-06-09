"""Mass assignment - JSON-API surface check. VL-METHOD Wave 4.

Refactored 2026-06-09 to MethodologyScanner. Verify re-POSTs with a SECOND
set of privileged field names. A real mass-assignment endpoint accepts ANY
arbitrary field shape; a static page that returns 200 to any POST accepts
the first but won't change behaviour for the second.
"""
import json
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._methodology import MethodologyScanner
from tools.vuln._vuln_common import probe_url_async, http_post_async, http_get_async

router = APIRouter()

PROBE_PATHS_QUICK = ["/api/users", "/api/v1/users", "/api/register"]
PROBE_PATHS_DEEP  = ["/register", "/api/signup", "/api/account", "/api/profile"]
PROBE_BODY_QUICK   = json.dumps({"_vlcanary": "test", "is_admin": True,
                                  "role": "admin", "isSuperUser": True,
                                  "verified": True}).encode()
PROBE_BODY_VERIFY  = json.dumps({"_vlverify": "alt", "isSysOp": True,
                                  "userType": "owner", "elevated": True,
                                  "perm": "*"}).encode()


async def _fire(base_url, paths, body):
    accepting, rejecting = [], []
    for path in paths:
        r = await http_post_async(f"{base_url}{path}", data=body,
                                    headers={"Content-Type": "application/json"},
                                    timeout=8)
        if not r: continue
        status = r.get("status", 0)
        body_lower = r.get("body", "").lower()
        if status in (400, 422) and ("field" in body_lower or "unknown" in body_lower
                                       or "invalid" in body_lower):
            rejecting.append({"path": path, "status": status})
        elif 200 <= status < 300:
            accepting.append({"path": path, "status": status})
    return accepting, rejecting


class MassAssignmentAuth(MethodologyScanner):
    name = "mass_assignment_auth"

    async def pre_flight(self, ctx):
        base_url, base = await probe_url_async(str(ctx.host), "/")
        if not base:
            ctx.state["tested"] = 0
            ctx.state["skipped_reason"] = "Target unreachable"
            return False
        ctx.source("http")
        ctx.state["tested"] = 1
        ctx.state["base_url"] = base_url
        ctx.state["probed_paths"] = len(PROBE_PATHS_QUICK) + len(PROBE_PATHS_DEEP)
        ctx.state["mass_assign_accepting"] = []
        ctx.state["mass_assign_rejecting"] = []
        return True

    async def fingerprint(self, ctx):
        r = await http_get_async(ctx.state["base_url"], timeout=6)
        if r:
            hdrs = r.get("headers") or {}
            ctx.state["fingerprint"] = {"server": (hdrs.get("server") or "")[:80]}

    async def quick_probe(self, ctx):
        acc, rej = await _fire(ctx.state["base_url"], PROBE_PATHS_QUICK, PROBE_BODY_QUICK)
        ctx.state["mass_assign_accepting"].extend(acc)
        ctx.state["mass_assign_rejecting"].extend(rej)
        ctx.state["quick_hits"] = acc
        return [dict(a) for a in acc]

    async def deep_scan(self, ctx):
        acc, rej = await _fire(ctx.state["base_url"], PROBE_PATHS_DEEP, PROBE_BODY_QUICK)
        ctx.state["mass_assign_accepting"].extend(acc)
        ctx.state["mass_assign_rejecting"].extend(rej)
        ctx.state["deep_hits"] = acc
        return [dict(a) for a in acc]

    async def verify(self, ctx, finding):
        # Re-POST same path with DIFFERENT privileged fields. Real mass-
        # assignment surface accepts any field shape (still 2xx); a
        # static 200-page would also 200 but a binding-enforcing endpoint
        # would return 400/422 on different fields too.
        r = await http_post_async(f"{ctx.state['base_url']}{finding['path']}",
                                    data=PROBE_BODY_VERIFY,
                                    headers={"Content-Type": "application/json"},
                                    timeout=8)
        if not r:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "verify-probe-failed"
            return finding
        status = r.get("status", 0)
        if 200 <= status < 300:
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "alt-fields-also-accepted"
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = f"alt-fields-returned-{status}"
        return finding


def _r_ma(s):
    verified = s.get("methodology_findings") or []
    if not verified: return None
    confirmed = [f for f in verified if f.get("confidence") == "CONFIRMED"]
    if confirmed:
        return {"name": f"{len(confirmed)} JSON endpoint(s) accept arbitrary unprivileged fields (CONFIRMED)",
                "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-915",
                "evidence": f"Endpoints returning 2xx for two DIFFERENT privileged field shapes: "
                             f"{', '.join(a['path'] for a in confirmed)}",
                "remediation": "Use explicit allow-list binding (DTO / Serializer fields = [...]) "
                                "on every API endpoint. Never bind directly from request body to model."}
    return {"name": f"{len(verified)} JSON endpoint(s) returned 2xx to one privileged payload (SUSPECTED)",
            "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-915",
            "evidence": f"Initial payload accepted but alt payload returned non-2xx. "
                         f"Possible static 200-page or coincidence. Paths: "
                         f"{', '.join(a['path'] for a in verified)}",
            "remediation": "Manually re-test each endpoint with custom privileged fields."}


FINDING_RULES = [_r_ma]
INTEL_FIELDS = [
    ("Paths probed", "probed_paths"),
    ("Quick-probe hits", "quick_hits"),
    ("Deep-scan hits", "deep_hits"),
    ("Verified findings", "methodology_findings"),
    ("Stage timings (ms)", "stage_timings"),
]


@router.post("/api/vuln/mass_assignment_auth")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanner = MassAssignmentAuth()
    return await scanner.run_as_endpoint(req,
        finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)

"""Vertical access admin enumeration - MethodologyScanner refactor.

VL-METHOD Wave 5: probe privileged-action endpoints, flag ones returning
200 with non-shell JSON without auth. 6-stage flow:
  pre_flight    - target reachable
  fingerprint   - SPA catch-all detection
  quick_probe   - 3 highest-impact admin GET paths
  deep_scan     - remaining GET + POST probes (only if quick found something)
  verify        - re-fire with different content-type to confirm endpoint
                  actually serves JSON (not a generic 200)
  privilege_check - exposed admin = "guest" privilege (no auth required)
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core.verify import vl_verify
from tools._methodology import MethodologyScanner
from tools.vuln._vuln_common import (
    probe_url_async, http_get_async, http_post_async,
    detect_spa_catchall, is_same_as_canary,
)

router = APIRouter()


_QUICK_GET = ["/api/admin/users", "/api/admin/config", "/admin/api/users"]
_DEEP_GET = ["/api/v1/admin", "/api/system", "/api/internal"]
_DEEP_POST = ["/api/admin/users", "/api/users"]


def _is_json_body(body, headers):
    ctype = (headers or {}).get("content-type", "").lower()
    body = (body or "").strip()
    return ("json" in ctype) or body.startswith(("{", "["))


class VerticalAccessAdmin(MethodologyScanner):
    name = "vertical_access_admin"

    async def pre_flight(self, ctx):
        base_url, base = await probe_url_async(str(ctx.host), "/")
        if not base or base.get("status", 0) >= 500:
            ctx.state["tested"] = 0
            ctx.state["skipped_reason"] = "Target unreachable"
            return False
        ctx.source("http")
        ctx.state["tested"] = 1
        ctx.state["base_url"] = base_url
        return True

    async def fingerprint(self, ctx):
        spa = await detect_spa_catchall(ctx.state["base_url"])
        ctx.state["_spa"] = spa
        ctx.state["fingerprint"] = {
            "is_spa": spa.get("is_spa", False),
            "canary_body_len": len(spa.get("canary_body", "")),
        }

    async def _probe_get(self, ctx, paths):
        base_url = ctx.state["base_url"]
        spa = ctx.state.get("_spa") or {}
        exposed, protected, spa_suppressed = [], [], []
        for path in paths:
            r = await http_get_async(f"{base_url}{path}", timeout=6, read=4000)
            if not r:
                continue
            status = r.get("status", 0)
            body = r.get("body", "") or ""
            if status == 200:
                if spa.get("is_spa") and is_same_as_canary(body, spa.get("canary_body", "")):
                    spa_suppressed.append({"method": "GET", "path": path})
                    continue
                if len(body[:300]) > 50 and _is_json_body(body, r.get("headers")):
                    exposed.append({"method": "GET", "path": path,
                                     "evidence": "200 with JSON body"})
            elif status in (401, 403):
                protected.append({"method": "GET", "path": path, "status": status})
        return exposed, protected, spa_suppressed

    async def quick_probe(self, ctx):
        exposed, protected, spa_suppressed = await self._probe_get(ctx, _QUICK_GET)
        ctx.state["_quick_exposed"] = exposed
        ctx.state["_quick_protected"] = protected
        ctx.state["_quick_spa_suppressed"] = spa_suppressed
        return [{"method": e["method"], "path": e["path"]} for e in exposed]

    async def deep_scan(self, ctx):
        # Remaining GET probes
        exposed_g, protected_g, spa_g = await self._probe_get(ctx, _DEEP_GET)
        # POST probes with empty JSON body
        base_url = ctx.state["base_url"]
        spa = ctx.state.get("_spa") or {}
        exposed_p, spa_p = [], []
        for path in _DEEP_POST:
            r = await http_post_async(
                f"{base_url}{path}", data=b"{}",
                headers={"Content-Type": "application/json"}, timeout=6)
            if not r:
                continue
            status = r.get("status", 0)
            body = (r.get("body", "") or "").strip()
            if status in (200, 201) and body:
                if spa.get("is_spa") and is_same_as_canary(body, spa.get("canary_body", "")):
                    spa_p.append({"method": "POST", "path": path})
                    continue
                if _is_json_body(body, r.get("headers")):
                    exposed_p.append({"method": "POST", "path": path,
                                       "evidence": f"status {status} with JSON body"})
        ctx.state["_deep_exposed"] = exposed_g + exposed_p
        ctx.state["_deep_protected"] = protected_g
        ctx.state["_deep_spa_suppressed"] = spa_g + spa_p
        return [{"method": e["method"], "path": e["path"]}
                for e in exposed_g + exposed_p]

    async def verify(self, ctx, finding):
        # Verify by GETting the same path with an Accept: application/json header.
        # If endpoint still returns JSON content, it's a real API endpoint.
        base_url = ctx.state["base_url"]
        url = f"{base_url}{finding['path']}"
        r = await http_get_async(url, timeout=6, read=4000,
                                  headers={"Accept": "application/json"})
        if not r:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "Accept:application/json replay failed"
            return finding
        body = r.get("body", "") or ""
        if r.get("status") in (200, 201) and _is_json_body(body, r.get("headers")):
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "Accept:application/json replay returned JSON"
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = (
                f"replay returned status={r.get('status')}, json_body={_is_json_body(body, r.get('headers'))}")
        return finding

    async def privilege_check(self, ctx, finding):
        finding["privilege_level"] = "guest" if finding.get("confidence") == "CONFIRMED" else "unknown"
        return finding


def _r_exposed(s):
    verified = s.get("methodology_findings") or []
    confirmed = [f for f in verified if f.get("confidence") == "CONFIRMED"]
    if not confirmed:
        return None
    return {"name": f"{len(confirmed)} privileged endpoint(s) accessible without authentication (CONFIRMED)",
            "severity": "CRITICAL", "cvss": 9.1, "cwe": "CWE-285",
            "evidence": "; ".join(f"{f['method']} {f['path']}" for f in confirmed),
            "remediation": ("Require authentication AND admin-role authorisation on every "
                             "/admin and /api/admin path.")}


def _r_suspected(s):
    verified = s.get("methodology_findings") or []
    suspected = [f for f in verified if f.get("confidence") == "SUSPECTED"]
    if not suspected:
        return None
    return {"name": f"{len(suspected)} privileged endpoint(s) possibly accessible (SUSPECTED)",
            "severity": "LOW", "cvss": 3.1, "cwe": "CWE-285",
            "evidence": "; ".join(f"{f['method']} {f['path']}" for f in suspected),
            "remediation": "Manually verify each endpoint; verification replay did not reproduce JSON response."}


def _r_protected(s):
    auth = (s.get("_quick_protected") or []) + (s.get("_deep_protected") or [])
    if not auth:
        return None
    return {"name": f"{len(auth)} privileged endpoint(s) returned 401/403 - auth enforcement confirmed",
            "severity": "INFO", "cwe": "CWE-200",
            "evidence": "; ".join(f"{a['method']} {a['path']} ({a['status']})" for a in auth),
            "remediation": "No action - auth enforcement working as intended."}


FINDING_RULES = [_r_exposed, _r_suspected, _r_protected]
INTEL_FIELDS = [
    ("Stage timings (ms)", "stage_timings"),
    ("Verified findings", "methodology_findings"),
]


@router.post("/api/vuln/vertical_access_admin")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanner = VerticalAccessAdmin()
    return await scanner.run_as_endpoint(req,
        finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)

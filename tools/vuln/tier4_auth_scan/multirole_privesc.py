"""Multi-role privesc info-leak - MethodologyScanner refactor.

VL-METHOD Wave 5: probe role/permission endpoints, flag ones that leak
role names without auth. 6 stages:
  pre_flight    - target reachable
  fingerprint   - SPA catch-all detection
  quick_probe   - 3 highest-value role endpoints
  deep_scan     - remaining 4 (only if quick found something)
  verify        - re-fire with Accept: application/json; confirm endpoint
                  returns JSON AND role keywords appear in JSON, not in HTML shell
  privilege_check - role info-leak = "guest" privilege exposure
"""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core.verify import vl_verify
from tools._methodology import MethodologyScanner
from tools.vuln._vuln_common import (
    probe_url_async, http_get_async,
    detect_spa_catchall, is_same_as_canary,
)

router = APIRouter()


_QUICK_PATHS = ["/api/roles", "/api/permissions", "/api/users/me/roles"]
_DEEP_PATHS = [
    "/api/v1/roles", "/api/v1/permissions",
    "/roles", "/permissions",
]
_ROLE_KEYWORDS = ["admin", "superuser", "root", "operator", "owner", "moderator"]


def _is_json_body(body, headers):
    ctype = (headers or {}).get("content-type", "").lower()
    body = (body or "").lstrip()
    return ("json" in ctype) or body.startswith(("{", "["))


def _extract_roles(body):
    body_lower = (body or "").lower()
    return [k for k in _ROLE_KEYWORDS if k in body_lower]


class MultiRolePrivesc(MethodologyScanner):
    name = "multirole_privesc"

    async def pre_flight(self, ctx):
        base_url, base = await probe_url_async(str(ctx.host), "/")
        if not base or base.get("status", 0) >= 500:
            ctx.state["tested"] = 0
            ctx.state["skipped_reason"] = "Target unreachable"
            return False
        ctx.source("http")
        ctx.state["tested"] = 1
        ctx.state["base_url"] = base_url
        ctx.state["probed_paths"] = len(_QUICK_PATHS) + len(_DEEP_PATHS)
        return True

    async def fingerprint(self, ctx):
        spa = await detect_spa_catchall(ctx.state["base_url"])
        ctx.state["_spa"] = spa
        ctx.state["fingerprint"] = {
            "is_spa": spa.get("is_spa", False),
            "canary_body_len": len(spa.get("canary_body", "")),
        }

    async def _probe_set(self, ctx, paths):
        base_url = ctx.state["base_url"]
        spa = ctx.state.get("_spa") or {}
        spa_is = spa.get("is_spa", False)
        canary_body = spa.get("canary_body", "")

        async def _probe(path):
            r = await http_get_async(f"{base_url}{path}", timeout=6, read=12000)
            return (path, r)

        results = await asyncio.gather(
            *[_probe(path) for path in paths],
            return_exceptions=True)
        leaks, suppressed = [], []
        for res in results:
            if isinstance(res, BaseException) or res is None:
                continue
            path, r = res
            if not r or r.get("status") != 200:
                continue
            body = r.get("body", "") or ""
            if spa_is and is_same_as_canary(body, canary_body):
                suppressed.append({"path": path, "reason": "SPA shell"})
                continue
            if not _is_json_body(body, r.get("headers")):
                suppressed.append({"path": path, "reason": "non-JSON response"})
                continue
            matched = _extract_roles(body)
            if matched:
                leaks.append({"path": path, "roles_seen": matched})
        return leaks, suppressed

    async def quick_probe(self, ctx):
        leaks, suppressed = await self._probe_set(ctx, _QUICK_PATHS)
        ctx.state["_quick_leaks"] = leaks
        ctx.state["_quick_suppressed"] = suppressed
        return [{"path": l["path"], "roles_seen": l["roles_seen"]} for l in leaks]

    async def deep_scan(self, ctx):
        leaks, suppressed = await self._probe_set(ctx, _DEEP_PATHS)
        ctx.state["_deep_leaks"] = leaks
        ctx.state["_deep_suppressed"] = suppressed
        return [{"path": l["path"], "roles_seen": l["roles_seen"]} for l in leaks]

    async def verify(self, ctx, finding):
        # Replay with explicit Accept: application/json. If still returns
        # JSON with role keywords, the leak is real (not opportunistic
        # 200-shell echoing).
        base_url = ctx.state["base_url"]
        url = f"{base_url}{finding['path']}"
        r = await http_get_async(url, timeout=6, read=12000,
                                  headers={"Accept": "application/json"})
        if not r or r.get("status") != 200:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "Accept:application/json replay returned non-200"
            return finding
        body = r.get("body", "") or ""
        spa = ctx.state.get("_spa") or {}
        if spa.get("is_spa") and is_same_as_canary(body, spa.get("canary_body", "")):
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "replay returned SPA shell"
            return finding
        if not _is_json_body(body, r.get("headers")):
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "replay returned non-JSON"
            return finding
        replay_roles = _extract_roles(body)
        # CONFIRMED only when replay JSON contains the SAME role keywords
        original = set(finding.get("roles_seen") or [])
        if original & set(replay_roles):
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = (
                f"Accept:application/json replay returned JSON with role keywords "
                f"{sorted(original & set(replay_roles))}")
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "replay returned JSON but without matching role keywords"
        return finding

    async def privilege_check(self, ctx, finding):
        finding["privilege_level"] = "guest" if finding.get("confidence") == "CONFIRMED" else "unknown"
        return finding


def _r_confirmed(s):
    verified = s.get("methodology_findings") or []
    confirmed = [f for f in verified if f.get("confidence") == "CONFIRMED"]
    if not confirmed:
        return None
    return {"name": f"{len(confirmed)} role/permission endpoint(s) leak role names without auth (CONFIRMED)",
            "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-200",
            "evidence": "; ".join(f"{f['path']} -> {f.get('roles_seen', [])}" for f in confirmed),
            "remediation": ("Require authentication on role/permission discovery endpoints. "
                             "Don't expose internal role taxonomy publicly.")}


def _r_suspected(s):
    verified = s.get("methodology_findings") or []
    suspected = [f for f in verified if f.get("confidence") == "SUSPECTED"]
    if not suspected:
        return None
    return {"name": f"{len(suspected)} role/permission endpoint(s) possibly leaking (SUSPECTED)",
            "severity": "LOW", "cvss": 3.1, "cwe": "CWE-200",
            "evidence": "; ".join(f"{f['path']}" for f in suspected),
            "remediation": "Manually verify each path; replay did not reproduce the role keywords in JSON."}


FINDING_RULES = [_r_confirmed, _r_suspected]
INTEL_FIELDS = [
    ("Paths probed", "probed_paths"),
    ("Stage timings (ms)", "stage_timings"),
    ("Verified findings", "methodology_findings"),
]


@router.post("/api/vuln/multirole_privesc")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanner = MultiRolePrivesc()
    return await scanner.run_as_endpoint(req,
        finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)

"""Horizontal access (IDOR) - MethodologyScanner refactor.

VL-METHOD Wave 5: numeric-ID enumeration. Probe /users/1 + /users/2 and
flag pairs that return distinct 200 JSON bodies without auth. 6 stages:
  pre_flight    - target reachable
  fingerprint   - SPA catch-all detection (per-route shell variations)
  quick_probe   - 4 highest-impact ID-pattern paths
  deep_scan     - remaining 8 ID-pattern paths (only if quick found)
  verify        - replay with id=3 to confirm pattern (real IDOR returns
                  three distinct bodies; SPA shell would return identical)
  privilege_check - IDOR access = "guest" privilege
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core.verify import vl_verify
from tools._methodology import MethodologyScanner
from tools.vuln._vuln_common import (
    probe_url_async, http_get_async,
    detect_spa_catchall, is_same_as_canary,
)

router = APIRouter()


_QUICK_PATHS = ["/users/1", "/api/users/1", "/orders/1", "/api/orders/1"]
_DEEP_PATHS = [
    "/user/1", "/api/v1/users/1",
    "/items/1", "/products/1", "/api/products/1",
    "/posts/1", "/articles/1", "/accounts/1",
]


def _is_json_body(body, headers):
    ctype = (headers or {}).get("content-type", "").lower()
    body = (body or "").lstrip()
    return ("json" in ctype) or body.startswith(("{", "["))


def _classify_pair(r1, r2, spa_is, canary_body):
    """Return ('suspect' | 'spa' | 'not-json' | None)."""
    if not r1 or not r2:
        return None
    if r1.get("status") != 200 or r2.get("status") != 200:
        return None
    b1 = (r1.get("body", "") or "")[:500]
    b2 = (r2.get("body", "") or "")[:500]
    if b1 == b2 or len(b1) <= 50 or len(b2) <= 50:
        return None
    if spa_is and (is_same_as_canary(r1.get("body", ""), canary_body) or
                    is_same_as_canary(r2.get("body", ""), canary_body)):
        return "spa"
    if not _is_json_body(b1, r1.get("headers")):
        return "not-json"
    return "suspect"


class HorizontalAccessIdor(MethodologyScanner):
    name = "horizontal_access_idor"

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
        suspects = []
        spa_suppressed = []
        for path in paths:
            r1 = await http_get_async(f"{base_url}{path}", timeout=6, read=12000)
            alt = path[:-1] + "2"
            r2 = await http_get_async(f"{base_url}{alt}", timeout=6, read=12000)
            verdict = _classify_pair(r1, r2, spa_is, canary_body)
            if verdict == "suspect":
                suspects.append({"path": path,
                                  "evidence": "id=1 and id=2 return different 200 JSON bodies without auth"})
            elif verdict in ("spa", "not-json"):
                spa_suppressed.append({"path": path, "reason": verdict})
        return suspects, spa_suppressed

    async def quick_probe(self, ctx):
        suspects, suppressed = await self._probe_set(ctx, _QUICK_PATHS)
        ctx.state["_quick_suspects"] = suspects
        ctx.state["_quick_suppressed"] = suppressed
        return [{"path": s["path"]} for s in suspects]

    async def deep_scan(self, ctx):
        suspects, suppressed = await self._probe_set(ctx, _DEEP_PATHS)
        ctx.state["_deep_suspects"] = suspects
        ctx.state["_deep_suppressed"] = suppressed
        return [{"path": s["path"]} for s in suspects]

    async def verify(self, ctx, finding):
        # Verify with id=3 — real IDOR returns three DIFFERENT bodies;
        # a quirky 200-cache scenario would echo one of the prior bodies.
        base_url = ctx.state["base_url"]
        path = finding["path"]
        url3 = f"{base_url}{path[:-1]}3"
        r3 = await http_get_async(url3, timeout=6, read=12000)
        if not r3 or r3.get("status") != 200:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "id=3 replay returned non-200"
            return finding
        body3 = (r3.get("body", "") or "")[:500]
        # Replay id=1 once for comparison
        url1 = f"{base_url}{path}"
        r1 = await http_get_async(url1, timeout=6, read=12000)
        body1 = (r1.get("body", "") or "")[:500] if r1 else ""
        if body3 and body3 != body1 and len(body3) > 50 and _is_json_body(body3, r3.get("headers")):
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "id=3 returns distinct JSON body from id=1"
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "id=3 replay did not return a distinct JSON body"
        return finding

    async def privilege_check(self, ctx, finding):
        finding["privilege_level"] = "guest" if finding.get("confidence") == "CONFIRMED" else "unknown"
        return finding


def _r_confirmed(s):
    verified = s.get("methodology_findings") or []
    confirmed = [f for f in verified if f.get("confidence") == "CONFIRMED"]
    if not confirmed:
        return None
    return {"name": f"{len(confirmed)} endpoint(s) expose object data by ID without authentication (CONFIRMED)",
            "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-639",
            "evidence": "; ".join(f["path"] for f in confirmed),
            "remediation": ("Require authentication + per-object authorisation on every "
                             "resource access. Replace sequential IDs with UUIDs or hashed "
                             "IDs as defence in depth.")}


def _r_suspected(s):
    verified = s.get("methodology_findings") or []
    suspected = [f for f in verified if f.get("confidence") == "SUSPECTED"]
    if not suspected:
        return None
    return {"name": f"{len(suspected)} endpoint(s) possibly IDOR-prone (SUSPECTED)",
            "severity": "LOW", "cvss": 3.1, "cwe": "CWE-639",
            "evidence": "; ".join(f["path"] for f in suspected),
            "remediation": "Manually verify each path; id=3 verification did not reproduce a distinct response."}


FINDING_RULES = [_r_confirmed, _r_suspected]
INTEL_FIELDS = [
    ("Paths probed", "probed_paths"),
    ("Stage timings (ms)", "stage_timings"),
    ("Verified findings", "methodology_findings"),
]


@router.post("/api/vuln/horizontal_access_idor")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanner = HorizontalAccessIdor()
    return await scanner.run_as_endpoint(req,
        finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)

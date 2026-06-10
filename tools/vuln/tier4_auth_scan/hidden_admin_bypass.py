"""Hidden admin panel discovery - MethodologyScanner refactor.

VL-METHOD Wave 5: probe common admin paths, flag ones returning 200 OK
without a login form. 6-stage flow:
  pre_flight   - target reachable on HTTP(S)
  fingerprint  - detect SPA catch-all so 200 responses can be filtered
  quick_probe  - 8 highest-value admin paths
  deep_scan    - remaining 16 admin paths (only fires if quick found something)
  verify       - re-fire each finding with cache-busting query string;
                 finding stays CONFIRMED only if both responses 200 without login
  privilege_check - admin panel access is "guest" privilege (no auth)
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core.verify import vl_verify
from tools._methodology import MethodologyScanner
from tools.vuln._vuln_common import (
    probe_url_async, http_get_async, detect_spa_catchall, is_same_as_canary,
)

router = APIRouter()


_QUICK_PATHS = [
    "/admin", "/admin/", "/wp-admin/", "/administrator",
    "/dashboard", "/manager", "/portal", "/console",
]
_DEEP_PATHS = [
    "/admin.php", "/admin/index.php", "/wp-admin",
    "/manage", "/control", "/cpanel",
    "/api/admin", "/api/v1/admin", "/admin/api",
    "/phpmyadmin", "/pma", "/db", "/database",
    "/server-manager", "/jenkins", "/grafana", "/kibana",
]


def _classify(r, spa_canary_body, spa_is):
    """Return ('exposed' | 'auth_protected' | 'login_page' | None)."""
    if not r:
        return None
    status = r.get("status", 0)
    body = r.get("body", "") or ""
    body_lower = body.lower()
    if status == 200:
        if spa_is and is_same_as_canary(body, spa_canary_body):
            return None
        has_admin = any(w in body_lower for w in
                         ("admin", "dashboard", "manage", "console"))
        has_login = any(w in body_lower for w in
                         ("password", "login", "sign in", '<input type="password'))
        if has_admin and not has_login:
            return "exposed"
        if has_admin and has_login:
            return "login_page"
    if status in (401, 403):
        return "auth_protected"
    return None


class HiddenAdminBypass(MethodologyScanner):
    name = "hidden_admin_bypass"

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
        base_url = ctx.state["base_url"]
        spa = await detect_spa_catchall(base_url)
        ctx.state["fingerprint"] = {
            "is_spa": spa.get("is_spa", False),
            "canary_body_len": len(spa.get("canary_body", "")),
        }
        ctx.state["_spa"] = spa

    async def _probe_set(self, ctx, paths):
        base_url = ctx.state["base_url"]
        spa = ctx.state.get("_spa") or {}
        spa_is = spa.get("is_spa", False)
        canary_body = spa.get("canary_body", "")
        exposed, auth_protected, login_page = [], [], []
        for path in paths:
            r = await http_get_async(f"{base_url}{path}", timeout=6, read=8000)
            kind = _classify(r, canary_body, spa_is)
            status = (r or {}).get("status", 0)
            if kind == "exposed":
                exposed.append({"path": path, "status": status,
                                 "evidence": "200 OK without login form"})
            elif kind == "login_page":
                login_page.append({"path": path, "status": 200})
            elif kind == "auth_protected":
                auth_protected.append({"path": path, "status": status})
        return exposed, auth_protected, login_page

    async def quick_probe(self, ctx):
        exposed, auth_protected, login_page = await self._probe_set(
            ctx, _QUICK_PATHS)
        ctx.state["_quick_exposed"] = exposed
        ctx.state["_quick_protected"] = auth_protected
        ctx.state["_quick_login"] = login_page
        # Return preliminary findings; verify stage runs on each
        return [{"path": e["path"], "status": e["status"], "kind": "exposed"}
                for e in exposed]

    async def deep_scan(self, ctx):
        exposed, auth_protected, login_page = await self._probe_set(
            ctx, _DEEP_PATHS)
        ctx.state["_deep_exposed"] = exposed
        ctx.state["_deep_protected"] = auth_protected
        ctx.state["_deep_login"] = login_page
        return [{"path": e["path"], "status": e["status"], "kind": "exposed"}
                for e in exposed]

    async def verify(self, ctx, finding):
        # Re-fire with cache-busting query. If both probes return 200 without
        # a login form, the path is confirmed accessible — not a flaky cache.
        base_url = ctx.state["base_url"]
        import secrets
        nonce = secrets.token_hex(6)
        url = f"{base_url}{finding['path']}?vl_verify={nonce}"
        r = await http_get_async(url, timeout=6, read=8000)
        spa = ctx.state.get("_spa") or {}
        kind = _classify(r, spa.get("canary_body", ""), spa.get("is_spa", False))
        if kind == "exposed":
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = f"cache-bust-replay (?vl_verify={nonce})"
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = (
                f"cache-bust-replay did not reproduce; primary kind={finding.get('kind')}, "
                f"replay kind={kind}")
        return finding

    async def privilege_check(self, ctx, finding):
        # Accessing an admin panel without credentials = "guest" privilege
        if finding.get("confidence") == "CONFIRMED":
            finding["privilege_level"] = "guest"
        else:
            finding["privilege_level"] = "unknown"
        return finding


def _r_exposed(s):
    verified = s.get("methodology_findings") or []
    confirmed = [f for f in verified if f.get("confidence") == "CONFIRMED"]
    if not confirmed:
        return None
    return {"name": f"{len(confirmed)} admin path(s) accessible without authentication (CONFIRMED)",
            "severity": "CRITICAL", "cvss": 9.1, "cwe": "CWE-284",
            "evidence": "; ".join(f["path"] for f in confirmed),
            "remediation": ("Require authentication on all admin paths. Block "
                             "/wp-admin /phpmyadmin etc at WAF if not in use.")}


def _r_suspected(s):
    verified = s.get("methodology_findings") or []
    suspected = [f for f in verified if f.get("confidence") == "SUSPECTED"]
    if not suspected:
        return None
    return {"name": f"{len(suspected)} admin path(s) possibly exposed (SUSPECTED)",
            "severity": "LOW", "cvss": 3.1, "cwe": "CWE-284",
            "evidence": "; ".join(f["path"] for f in suspected),
            "remediation": "Manually verify each path; cache-bust replay did not reproduce 200."}


def _r_protected(s):
    auth = (s.get("_quick_protected") or []) + (s.get("_deep_protected") or [])
    if not auth:
        return None
    return {"name": f"{len(auth)} admin panel(s) returned 401/403 - auth enforcement confirmed",
            "severity": "INFO", "cwe": "CWE-200",
            "evidence": "; ".join(f"{a['path']} ({a['status']})" for a in auth),
            "remediation": "Optional: move admin to /a/<random> URL to reduce brute-force surface."}


def _r_login_page(s):
    pages = (s.get("_quick_login") or []) + (s.get("_deep_login") or [])
    if not pages:
        return None
    return {"name": f"{len(pages)} admin path(s) returned 200 with login form - verify auth manually",
            "severity": "INFO", "cwe": "CWE-200",
            "evidence": "; ".join(f"{p['path']} (200)" for p in pages),
            "remediation": ("Verify each path actually requires auth (POST a request "
                             "without credentials). A 200 status alone does not prove auth.")}


FINDING_RULES = [_r_exposed, _r_suspected, _r_protected, _r_login_page]
INTEL_FIELDS = [
    ("Paths probed", "probed_paths"),
    ("Stage timings (ms)", "stage_timings"),
    ("Verified findings", "methodology_findings"),
]


@router.post("/api/vuln/hidden_admin_bypass")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanner = HiddenAdminBypass()
    return await scanner.run_as_endpoint(req,
        finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)

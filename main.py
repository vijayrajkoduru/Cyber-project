"""VulnusLab — Kali-style modular pentest API.

Boot sequence:
  1. FastAPI app + CORS
  2. Health endpoint (always responds even if no tools loaded)
  3. Auto-discover tools/<category>/<tool>.py — each calls register(app)
  4. Auto-discover endpoints/<module>.py — module-level orchestrators

Adding a new tool: create tools/<category>/<tool_name>.py with a
register(app) function that mounts its routes. main.py picks it up on
next boot. ONE bad tool can't break the platform — discovery is
exception-isolated.
"""
import os
import datetime
import importlib
import logging
from pathlib import Path

from tools._framework.turbo import init_turbo
init_turbo()  # VL-TURBO: thread pool 256 + HTTP pool 100 + 60s wall-clock cap
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Fault-isolating autoloader — quarantines modules that fail to import
# (never restores files into the source tree; see tools/_core/healing.py).
# Imported defensively so a bug in healing.py never crashes boot.
try:
    from tools._core.healing import load_with_healing as _heal_load
    _HEAL_AVAILABLE = True
except Exception:
    _HEAL_AVAILABLE = False
    _heal_load = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("vulnuslab")

app = FastAPI(
    title="VulnusLab API",
    version="2.0.0",
    description="Pentest platform — Kali-style modular tool architecture",
)

# ── CORS ────────────────────────────────────────────────────────────
# Production: comma-separated origins in .env (e.g. https://app.vulnuslab.com).
# We never default to "*" — a wildcard with allow_credentials=True is both a
# security risk and rejected by browsers. If CORS_ORIGINS is unset we fall back
# to the local React dev origins and log a warning.
_cors_env = os.getenv("CORS_ORIGINS", "").strip()
if _cors_env:
    CORS_ORIGINS = [o.strip() for o in _cors_env.split(",") if o.strip()]
else:
    CORS_ORIGINS = ["http://localhost:3000", "http://127.0.0.1:3000"]
    log.warning("CORS_ORIGINS not set — defaulting to localhost dev origins. "
                "Set CORS_ORIGINS to your real frontend origin(s) in production.")
if "*" in CORS_ORIGINS:
    log.warning("CORS_ORIGINS contains '*' with credentials enabled — browsers "
                "will reject this and it is unsafe. Use explicit origins.")
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Anti-LFI guard for local-artifact scanners (LFI-GUARD-V2) ───────
# Several scanner families take ScanRequest.target as a filesystem path to an
# uploaded artifact (bof / mobile_* APK+IPA / firmware blobs / supply-chain
# source dirs). Without containment, an authenticated user could point them at
# /app/data/users.db, the JWT secret, /etc/passwd, the source tree, etc.
# Enforced once here (covers the orchestrators AND every individual scanner
# endpoint) instead of in hundreds of scanner modules.
#
#   STRICT   prefixes: target is ALWAYS a file path -> must be contained.
#   PATH-CAPABLE prefixes: target MAY be a path (or a host/package/label) ->
#            if it resolves to anything on local disk it must be contained.
#   everything else: path-shaped targets (/x, ./x, ~, file:) must be
#            contained; hostnames/URLs/CIDRs pass untouched.
# repo_url / image_ref are validated everywhere (git option injection,
# file:// clones, syft/grype `dir:` / `oci-archive:` local sources).
import json as _json
import time as _time
from collections import deque as _deque
from fastapi.responses import JSONResponse as _JSONResponse
from tools._shared import is_contained_artifact as _is_contained_artifact
from tools._shared import is_internal_fanout as _is_internal_fanout
from tools._shared import target_looks_local as _target_looks_local
from tools._shared import validate_image_ref as _validate_image_ref
from tools._shared import validate_repo_url as _validate_repo_url

_ARTIFACT_STRICT_PREFIXES = ("/api/bof/", "/api/mobile_static/", "/api/firmware/")
_ARTIFACT_PATH_CAPABLE_PREFIXES = (
    "/api/mobile_", "/api/supply_chain/",
)
_ARTIFACT_EXEMPT = {"/api/mobile_static/upload"}
_ARTIFACT_MSG = ("Invalid target: local-artifact scanners only accept files "
                 "uploaded via /api/mobile_static/upload.")


def _artifact_guard_error(path, payload):
    if not isinstance(payload, dict):
        return None
    target = payload.get("target")
    if isinstance(target, str) and target:
        if any(path.startswith(p) for p in _ARTIFACT_STRICT_PREFIXES):
            if not _is_contained_artifact(target):
                return _ARTIFACT_MSG
        else:
            bare = any(path.startswith(p) for p in _ARTIFACT_PATH_CAPABLE_PREFIXES)
            if _target_looks_local(target, bare_names=bare) and not _is_contained_artifact(target):
                return _ARTIFACT_MSG
    for field, check in (("repo_url", _validate_repo_url), ("image_ref", _validate_image_ref)):
        val = payload.get(field)
        if isinstance(val, str) and val:
            err = check(val)
            if err:
                return f"Invalid {field}: {err}"
    return None


# ── CUSTOMER mode scope/safety gate (SCOPE-GUARD-V1) ────────────────
# A JSON scan body carrying `profile_id` is checked here (caller owns the
# profile, time window, target in scope, destructive policy, per-tool session
# (re)injection) and a ScanContext is activated for the route so every
# outbound HTTP request the scanner makes is scope-checked + rate-limited
# (tools/_core/scope_guard.py). No profile_id -> nothing changes (LAB mode).
from tools._core import scope_guard as _scope_guard
_scope_guard.install_transport_guards()


@app.middleware("http")
async def _artifact_path_guard(request, call_next):
    path = request.url.path
    ctype = (request.headers.get("content-type") or "").lower()
    if (request.method in ("POST", "PUT", "PATCH")
            and path.startswith("/api/")
            and path not in _ARTIFACT_EXEMPT
            and (not ctype or "json" in ctype)):
        body = await request.body()
        scan_ctx = None
        if body:
            try:
                payload = _json.loads(body)
            except Exception:
                payload = None
            err = _artifact_guard_error(path, payload)
            if err:
                return _JSONResponse(status_code=400, content={"detail": err})
            if (isinstance(payload, dict) and payload.get("profile_id")
                    and not path.startswith("/api/profiles")):
                early, scan_ctx, new_body = await _scope_guard.http_gate(request, path, payload)
                if early is not None:
                    return early
                if new_body is not None:
                    body = new_body
                    # starlette 0.38 _CachedRequest replays request._body to
                    # the downstream app, so the cached copy must be replaced.
                    request._body = body
        # NOTE: no receive-channel "re-arm" here. Starlette 0.38's
        # BaseHTTPMiddleware (_CachedRequest) already replays request._body to
        # the downstream app. Replacing request._receive made the post-body
        # wait-for-disconnect receive() return another http.request, which
        # raised "Unexpected message received: http.request" inside
        # StreamingResponse.listen_for_disconnect and killed every NDJSON
        # run_all stream after the first chunk (reproduced in an isolated
        # container, 2026-11-10).
        if scan_ctx is not None:
            _tok = _scope_guard.activate(scan_ctx)
            try:
                response = await call_next(request)
            finally:
                _scope_guard.deactivate(_tok)
            return await _scope_guard.annotate_response(response, scan_ctx)
    return await call_next(request)


# ── Browser session cookie -> Bearer + CSRF (SESSION-COOKIE-V1) ─────
# The SPA no longer holds the JWT (it was XSS-exfiltratable from
# localStorage). Browsers authenticate with the HttpOnly `vl_session` cookie;
# this middleware, for /api/* requests WITHOUT a real Bearer header:
#   * enforces the double-submit CSRF check (X-CSRF-Token == vl_csrf cookie)
#     on POST/PUT/PATCH/DELETE (login/register/logout exempt), and
#   * rewrites the cookie into `Authorization: Bearer <jwt>` so every
#     downstream consumer — verify_token, the scope guard, and the ~30
#     orchestrators that forward the caller's Authorization header to their
#     internal fan-out — works unchanged.
# Requests that carry a real Bearer header (API keys / CLI / internal
# fan-out) are passed through untouched and never need a CSRF token.
# Registered AFTER _artifact_path_guard so it runs OUTSIDE it (the scope gate
# in that guard resolves the user from the Authorization header).
from tools.auth import _session_cookie as _sc


class _CookieSessionMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or not str(scope.get("path", "")).startswith("/api/"):
            return await self.app(scope, receive, send)
        hdrs = scope.get("headers") or []
        auth_val = None
        cookie_raw = []
        csrf_hdr = None
        for k, v in hdrs:
            if k == b"authorization":
                auth_val = v.decode("latin-1")
            elif k == b"cookie":
                cookie_raw.append(v.decode("latin-1"))
            elif k == b"x-csrf-token":
                csrf_hdr = v.decode("latin-1")
        # A real Bearer token, or a non-Bearer scheme: leave the request alone.
        if auth_val is not None and (_sc.real_bearer(auth_val)
                                     or not auth_val.strip().lower().startswith("bearer")):
            return await self.app(scope, receive, send)
        cookies = _sc.parse_cookie_header("; ".join(cookie_raw))
        sess = cookies.get(_sc.SESSION_COOKIE)
        if not sess:
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        if not _sc.csrf_ok(scope.get("method", "GET"), path,
                           cookies.get(_sc.CSRF_COOKIE), csrf_hdr):
            resp = _JSONResponse(status_code=403,
                                 content={"detail": "CSRF token missing or invalid"})
            return await resp(scope, receive, send)
        new_hdrs = [(k, v) for (k, v) in hdrs if k != b"authorization"]
        new_hdrs.append((b"authorization", b"Bearer " + sess.encode("latin-1")))
        scope = dict(scope)
        scope["headers"] = new_hdrs
        return await self.app(scope, receive, send)


app.add_middleware(_CookieSessionMiddleware)


# ── Security response headers ───────────────────────────────────────
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-origin",
    # API serves JSON only — lock the CSP right down.
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}


@app.middleware("http")
async def _security_headers(request, call_next):
    response = await call_next(request)
    for k, v in _SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    # Only advertise HSTS over HTTPS (harmless, browsers ignore it on http).
    if request.url.scheme == "https":
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


# ── Global rate limiting ────────────────────────────────────────────
# Simple in-process sliding-window limiter per client IP. Protects every
# endpoint from abuse/DoS (the audit only added a login-specific throttle).
# Health checks and trusted internal orchestrator fan-out are exempt. NOTE:
# in-process means the cap is per-uvicorn-worker; move to Redis for a hard
# cluster-wide limit. Tunable via RATE_LIMIT_PER_MIN (0 disables).
_RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "300"))
_RATE_WINDOW = 60.0
_rate_hits: dict = {}
_RATE_EXEMPT_PREFIXES = ("/api/health",)


@app.middleware("http")
async def _rate_limit(request, call_next):
    limit = _RATE_LIMIT_PER_MIN
    path = request.url.path
    if (limit > 0
            and not any(path.startswith(p) for p in _RATE_EXEMPT_PREFIXES)
            and not _is_internal_fanout(request)):
        ip = request.client.host if request.client else "?"
        now = _time.monotonic()
        dq = _rate_hits.get(ip)
        if dq is None:
            dq = _rate_hits[ip] = _deque()
        while dq and now - dq[0] > _RATE_WINDOW:
            dq.popleft()
        if len(dq) >= limit:
            return _JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Please slow down."},
            )
        dq.append(now)
    return await call_next(request)


# ── Global exception handler ────────────────────────────────────────
# Unhandled errors must return a clean JSON envelope, never a stack trace.
# HTTPException / RequestValidationError keep their own (more specific)
# handlers — this only catches the truly-unexpected 500s.
@app.exception_handler(Exception)
async def _unhandled_exception_handler(request, exc):
    log.exception("Unhandled error on %s %s", request.method, request.url.path)
    return _JSONResponse(status_code=500, content={"detail": "Internal server error"})

# ── Observability (metrics + request-id + structured access log) ────
# Dependency-free, fail-open. Adds /api/metrics (Prometheus). Optional Sentry
# activates only if SENTRY_DSN is set. Installed defensively — never crash boot.
try:
    from tools._core.observability import install_observability
    install_observability(app)
except Exception as _obs_exc:  # pragma: no cover
    log.error("observability install failed (continuing): %s", _obs_exc)

# ── Required env ────────────────────────────────────────────────────
JWT_SECRET = os.getenv("JWT_SECRET", "")
if not JWT_SECRET:
    log.error("FATAL: JWT_SECRET environment variable is required")
    raise RuntimeError(
        "JWT_SECRET env var is missing. "
        "Set it in .env on the host (NEVER bake into the image)."
    )

# ── Always-available endpoints ──────────────────────────────────────
@app.get("/api/health")
async def health():
    """Returns 200 always — used by load balancers + the frontend's
    backend-online indicator. Never depends on tools/auth/db."""
    return {
        "status": "ok",
        "service": "vulnuslab-api",
        "version": "2.0.0",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "tools_loaded": getattr(app.state, "tools_loaded", 0),
        "tools_failed": getattr(app.state, "tools_failed", []),
        "tools_healed": getattr(app.state, "tools_healed", []),
        "healing_engine": "active" if _HEAL_AVAILABLE else "unavailable",
    }


@app.get("/api/manifest")
async def manifest():
    """Returns the full module catalogue: every module → its tiers →
    technique counts → playbook reference. Used by:
      - External integrators (CI/CD, partner dashboards)
      - Frontend auto-generation of capability views
      - CLI tool discovery (vulnuslab list)
      - Sales/marketing capability matrix

    Walks every registered route and groups by module slug. Free, no auth.
    """
    from collections import defaultdict
    modules = defaultdict(lambda: {"endpoints": [], "tiers": {}, "run_all": False})
    for route in app.routes:
        path = getattr(route, "path", "")
        if not path.startswith("/api/"): continue
        parts = path.split("/")
        if len(parts) < 4: continue
        module = parts[2]
        # skip non-module routes
        if module in ("health","manifest","auth","admin","user","login","register",
                       "auth_login","auth_register","logout","verify","scan_quota"): continue
        endpoint = "/".join(parts[3:])
        modules[module]["endpoints"].append(endpoint)
        if endpoint == "run_all" or endpoint.startswith("run_all"):
            modules[module]["run_all"] = True
    playbook_map = {
        "recon":"01_recon.md","vuln":"02_vuln.md","webapp":"03_webapp.md","osint":"04_osint.md",
        "mobile_static":"05_mobile.md","mobile_storage":"05_mobile.md","mobile_runtime":"05_mobile.md",
        "mobile_crypto":"05_mobile.md","mobile_network":"05_mobile.md",
        "exploit":"06_exploit.md","bof":"07_bof.md","password":"08_password.md",
        "client_side":"09_client_side.md","system_exploit":"10_system_exploit.md",
        "metasploit":"11_metasploit.md","privesc":"12_privesc.md","post_exploit":"13_post_exploit.md",
        "pivot":"14_pivot.md","tunnel":"15_tunnel.md","network":"16_network.md",
        "auth_attacks":"17_auth_attacks.md","wireless":"18_wireless.md","ad":"19_ad.md",
        "av_evasion":"20_av_evasion.md","cloud":"21_cloud.md","apisec":"22_apisec.md",
        "ai_llm":"23_ai_llm.md","container_k8s":"24_container_k8s.md","supply_chain":"25_supply_chain.md",
        "phishing":"26_phishing.md","red_team":"27_red_team.md","hybrid_identity":"28_hybrid_identity.md",
        "sspm":"29_sspm.md","iot_ot":"30_iot_ot.md","firmware":"31_firmware.md",
    }
    out = []
    for slug, data in sorted(modules.items()):
        eps = sorted(set(data["endpoints"]))
        out.append({
            "slug": slug,
            "playbook": playbook_map.get(slug),
            "endpoint_count": len(eps),
            "has_run_all": data["run_all"],
            "endpoints": eps[:200],  # cap for response size
        })
    return {
        "service": "vulnuslab-api",
        "version": "2.0.0",
        "modules": out,
        "total_modules": len(out),
        "total_endpoints": sum(m["endpoint_count"] for m in out),
        "playbooks_available": list(playbook_map.values()),
    }

# ── Tool + endpoint auto-discovery ──────────────────────────────────
# At startup, walk tools/<category>/<tool>.py and endpoints/<module>.py.
# Each file that exports `register(app)` gets called. Exceptions during
# load are LOGGED but DO NOT crash the platform — Kali's robustness.

def _autoload(directory: str, label: str) -> None:
    root = Path(__file__).parent / directory
    if not root.exists():
        log.warning("%s/ directory missing -- skipping autoload", directory)
        return

    loaded = 0
    healed: list[str] = []
    failed: list[str] = []
    for module_path in root.rglob("*.py"):
        # Skip anything in an underscore- or dot-prefixed path component.
        if any(part.startswith("_") or part.startswith(".") for part in module_path.parts):
            continue
        rel = module_path.relative_to(Path(__file__).parent)
        import_path = ".".join(rel.with_suffix("").parts)

        try:
            if _HEAL_AVAILABLE:
                module, status = _heal_load(import_path, module_path)
            else:
                module = importlib.import_module(import_path)
                status = "loaded"
        except (Exception, SystemExit) as exc:
            # Catch SystemExit too: a tool module that runs argparse or
            # sys.exit() at import time would otherwise raise SystemExit
            # (NOT an Exception), escape this guard, and kill the whole boot —
            # surfacing as an opaque "process exited with code 2" under
            # pytest / uvicorn. One bad module must never take down discovery.
            log.error("Failed to load %s %s: %s", label, import_path, exc)
            module, status = None, "quarantined"

        if module is None:
            failed.append(import_path)
            continue
        if status == "healed":
            healed.append(import_path)

        if hasattr(module, "register"):
            try:
                module.register(app)
                loaded += 1
                log.info("Loaded %s: %s (%s)", label, import_path, status)
            except (Exception, SystemExit) as exc:
                failed.append(import_path)
                log.error("register(app) failed for %s: %s", import_path, exc)
        else:
            log.warning("%s has no register(app) -- skipped: %s", label, import_path)

    app.state.tools_loaded = getattr(app.state, "tools_loaded", 0) + loaded
    app.state.tools_failed = getattr(app.state, "tools_failed", []) + failed
    app.state.tools_healed = getattr(app.state, "tools_healed", []) + healed
    log.info("%s autoload: %d loaded, %d auto-healed, %d quarantined",
             label, loaded, len(healed), len(failed))


# Initial state for /api/health before autoload runs
app.state.tools_loaded = 0
app.state.tools_failed = []
app.state.tools_healed = []

# Discover atomic tool cores first, then module orchestrators
import sys as _sys; _sys.setrecursionlimit(10000)  # FastAPI merged_lifespan nests per-router; 500+ routers exceed default 1000
_autoload("tools", "tool")
_autoload("endpoints", "module endpoint")

log.info("Boot complete. %d tools live.", app.state.tools_loaded)
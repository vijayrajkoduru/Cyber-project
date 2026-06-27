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

# Healing autoloader — wraps importlib with snapshot/restore.
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
# Production: comma-separated origins in .env (e.g. https://app.vulnuslab.com)
# Dev: defaults to "*" so the React dev server on :3000 can talk to us
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Anti-LFI guard for binary-analysis scanners ─────────────────────
# The bof + mobile_static scanners take ScanRequest.target as a filesystem
# path to an uploaded binary. Without containment, an authenticated user
# could point them at /app/data/users.db, the JWT secret, /etc/passwd, etc.
# Enforce once here (covers the orchestrators AND every individual scanner
# endpoint) instead of in all 60+ scanner modules.
import json as _json
from fastapi.responses import JSONResponse as _JSONResponse
from tools._shared import is_contained_artifact as _is_contained_artifact

_ARTIFACT_PREFIXES = ("/api/bof/", "/api/mobile_static/")
_ARTIFACT_EXEMPT = {"/api/mobile_static/upload"}


@app.middleware("http")
async def _artifact_path_guard(request, call_next):
    path = request.url.path
    if (request.method == "POST"
            and path not in _ARTIFACT_EXEMPT
            and any(path.startswith(p) for p in _ARTIFACT_PREFIXES)):
        body = await request.body()
        if body:
            try:
                target = (_json.loads(body) or {}).get("target")
            except Exception:
                target = None
            if isinstance(target, str) and target and not _is_contained_artifact(target):
                return _JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid target: binary-analysis scanners only "
                             "accept files uploaded via /api/mobile_static/upload."},
                )
        # Re-arm the receive channel so the downstream handler can still read
        # the body we just consumed (BaseHTTPMiddleware gotcha).
        async def _receive():
            return {"type": "http.request", "body": body, "more_body": False}
        request._receive = _receive
    return await call_next(request)

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
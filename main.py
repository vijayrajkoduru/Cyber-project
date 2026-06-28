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
# allow_credentials=True with a wildcard origin is rejected by browsers AND
# unsafe — it would let ANY site make authenticated requests with a logged-in
# user's session. So we never pair "*" with credentials:
#   - CORS_ORIGINS = explicit comma-separated origins → use them (credentials on)
#   - CORS_ORIGINS unset or "*"                        → fall back to localhost
#     dev origins (credentials on) and warn loudly
# Production MUST set CORS_ORIGINS in .env, e.g. https://app.vulnuslab.com
_cors_raw = os.getenv("CORS_ORIGINS", "").strip()
if _cors_raw and _cors_raw != "*":
    CORS_ORIGINS = [o.strip() for o in _cors_raw.split(",") if o.strip()]
else:
    CORS_ORIGINS = ["http://localhost:3000", "http://127.0.0.1:3000"]
    log.warning(
        "CORS_ORIGINS not set (or '*') — falling back to localhost dev origins. "
        "Set CORS_ORIGINS to your real origin(s) in production (e.g. "
        "https://app.vulnuslab.com); never serve '*' with credentials."
    )
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Observability + rate limiting ───────────────────────────────────
# Both are dependency-free and fail-open: a bug in either must never take the
# API down. Observability adds /api/metrics (Prometheus) + request-id +
# structured access logs + optional Sentry (active only if SENTRY_DSN set).
# Rate limiting is per-IP, env-tunable (RATE_LIMIT_PER_MIN), disable with
# RATE_LIMIT_ENABLED=0. Installed defensively so neither can crash boot.
try:
    from tools._core.observability import install_observability
    install_observability(app)
except Exception as _obs_exc:  # pragma: no cover
    log.error("observability install failed (continuing): %s", _obs_exc)
try:
    from tools._core.ratelimit import install_rate_limit
    install_rate_limit(app)
except Exception as _rl_exc:  # pragma: no cover
    log.error("rate-limit install failed (continuing): %s", _rl_exc)

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

        if _HEAL_AVAILABLE:
            module, status = _heal_load(import_path, module_path)
        else:
            try:
                module = importlib.import_module(import_path)
                status = "loaded"
            except Exception as exc:
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
            except Exception as exc:
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
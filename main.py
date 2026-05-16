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
_autoload("tools", "tool")
_autoload("endpoints", "module endpoint")

log.info("Boot complete. %d tools live.", app.state.tools_loaded)

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
    }

# ── Tool + endpoint auto-discovery ──────────────────────────────────
# At startup, walk tools/<category>/<tool>.py and endpoints/<module>.py.
# Each file that exports `register(app)` gets called. Exceptions during
# load are LOGGED but DO NOT crash the platform — Kali's robustness.

def _autoload(directory: str, label: str) -> None:
    root = Path(__file__).parent / directory
    if not root.exists():
        log.warning("%s/ directory missing — skipping autoload", directory)
        return

    loaded = 0
    failed: list[str] = []
    # Walk tools/<category>/<tool>.py AND endpoints/<module>.py
    for module_path in root.rglob("*.py"):
        if module_path.name.startswith("_"):
            continue  # skip __init__.py and _shared.py
        # Compute import path: tools/recon/whois.py → tools.recon.whois
        rel = module_path.relative_to(Path(__file__).parent)
        import_path = ".".join(rel.with_suffix("").parts)
        try:
            module = importlib.import_module(import_path)
            if hasattr(module, "register"):
                module.register(app)
                loaded += 1
                log.info("Loaded %s: %s", label, import_path)
            else:
                log.warning("%s has no register(app) — skipped: %s", label, import_path)
        except Exception as exc:
            failed.append(import_path)
            log.error("Failed to load %s %s: %s", label, import_path, exc)

    # Stash counts so /api/health can surface them
    app.state.tools_loaded = getattr(app.state, "tools_loaded", 0) + loaded
    failed_total = getattr(app.state, "tools_failed", [])
    failed_total.extend(failed)
    app.state.tools_failed = failed_total
    log.info("%s autoload complete: %d loaded, %d failed", label, loaded, len(failed))


# Initial state for /api/health before autoload runs
app.state.tools_loaded = 0
app.state.tools_failed = []

# Discover atomic tool cores first, then module orchestrators
_autoload("tools", "tool")
_autoload("endpoints", "module endpoint")

log.info("Boot complete. %d tools live.", app.state.tools_loaded)

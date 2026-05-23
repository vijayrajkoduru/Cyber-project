"""Generic Tool Refresh endpoint.

ONE endpoint, ANY module. Frontend sends {"module": "recon"} (or webapp,
network, vuln, mobile, cloud, etc.) and we clear that module's per-user
scan history + report cache.

Why generic instead of per-module:
  Old approach was /api/recon/clear_history, /api/webapp/clear_history, etc.
  19 modules = 19 near-identical endpoints. This is the same logic with
  a parameter — single source of truth, single test, single deploy.

Per-user isolation:
  - Reads user_id from JWT 'sub' claim (Depends verify_token)
  - Refuses any user_id containing path separators or parent-dir refs
  - Refuses any module name not on the allowlist (no arbitrary path probing)

Endpoint path: POST /api/tool_refresh
Body:          {"module": "recon"}
Returns:       {ok, user_id, module, files_deleted, dirs_deleted, freed_bytes}
"""
import shutil
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from tools._shared import verify_token

router = APIRouter()

_USER_ZONE_ROOT = Path("/data/users")

# Allowlist — every module that exposes a Tool Refresh button MUST be listed
# here. Keeps customers from probing arbitrary directory names via this API.
_ALLOWED_MODULES = {
    # Top-level scan modules
    "recon", "webapp", "vuln", "network", "wireless", "mobile", "cloud",
    "apisec", "password", "osint", "exploitation", "post_exploit",
    "system_exploit", "cloud_attacks", "auth_attacks", "metasploit",
    "buffer_overflow", "client_side", "pivot",
    # Smaller specialty modules (use ModuleShell)
    "ad", "privesc", "av_evasion", "social_eng", "malware",
    "supply_chain", "persistence",
}


class ToolRefreshRequest(BaseModel):
    module: str


@router.post("/api/tool_refresh")
async def tool_refresh(req: ToolRefreshRequest, payload=Depends(verify_token)):
    """Wipe the calling user's scan history + report cache for one module.

    Single shutil.rmtree per directory. No DB. No locks. Fast.
    """
    module = (req.module or "").strip().lower()
    if module not in _ALLOWED_MODULES:
        raise HTTPException(400, f"module '{module}' not in allowlist")

    user_id = payload.get("sub") or "unknown"
    # Defence-in-depth — JWT 'sub' is server-controlled but paranoia is free.
    if not user_id or "/" in user_id or "\\" in user_id or ".." in user_id:
        raise HTTPException(400, "invalid user_id in token")

    files_deleted = 0
    dirs_deleted = 0
    freed_bytes = 0

    targets = (
        _USER_ZONE_ROOT / user_id / "scans"   / module,
        _USER_ZONE_ROOT / user_id / "reports" / module,
        _USER_ZONE_ROOT / user_id / "cache"   / module,
    )
    for zone in targets:
        if not zone.exists():
            continue
        for child in zone.rglob("*"):
            if child.is_file():
                files_deleted += 1
                try: freed_bytes += child.stat().st_size
                except Exception: pass
            elif child.is_dir():
                dirs_deleted += 1
        try:
            shutil.rmtree(zone)
        except Exception as e:
            return {"ok": False,
                    "error": f"rmtree {zone.name} failed: {type(e).__name__}: {str(e)[:100]}",
                    "files_deleted": files_deleted}
        zone.mkdir(parents=True, exist_ok=True)

    return {
        "ok":            True,
        "user_id":       user_id,
        "module":        module,
        "files_deleted": files_deleted,
        "dirs_deleted":  dirs_deleted,
        "freed_bytes":   freed_bytes,
    }


def register(app):
    app.include_router(router)

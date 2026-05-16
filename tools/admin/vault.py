"""Admin VAULT — /api/admin/vault/* — admin-only master backup management."""
import datetime
from fastapi import APIRouter, Depends

from tools._shared import verify_admin
from tools._core.vault import list_vault_days, nightly_sync, VAULT_ROOT

router = APIRouter()


@router.get("/api/admin/vault/list")
async def vault_list(_=Depends(verify_admin)):
    days = list_vault_days()
    return {"count": len(days), "days": days}


@router.get("/api/admin/vault/status")
async def vault_status(_=Depends(verify_admin)):
    days = list_vault_days()
    total_bytes = 0
    if VAULT_ROOT.exists():
        for f in VAULT_ROOT.rglob("*"):
            if f.is_file():
                total_bytes += f.stat().st_size
    last_sync = days[0]["manifest"].get("finished_iso") if days else None
    return {"vault_root": str(VAULT_ROOT), "archived_days": len(days),
            "last_sync_iso": last_sync, "total_size_bytes": total_bytes,
            "checked_iso": datetime.datetime.utcnow().isoformat() + "Z"}


@router.post("/api/admin/vault/sync")
async def vault_force_sync(_=Depends(verify_admin)):
    result = nightly_sync()
    return {"ok": len(result["errors"]) == 0,
            "users": len(result["users"]), "tools": len(result["tools"]),
            "db": result["db"] is not None, "errors": result["errors"],
            "vault_dir": result["vault_dir"]}


def register(app):
    app.include_router(router)

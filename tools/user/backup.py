"""User Backups — /api/user/backups/* — per-user snapshot management."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from tools._shared import verify_scan_quota
from tools._core.userzone import init_zone, zone_size_bytes
from tools._core.userbackup import (
    snapshot_user, list_snapshots, restore_snapshot, restore_latest,
    delete_snapshot,
)

router = APIRouter()


class RestoreRequest(BaseModel):
    snapshot_name: str


@router.get("/api/user/backups")
async def list_backups(payload=Depends(verify_scan_quota)):
    user_id = payload["sub"]
    init_zone(user_id)
    snaps = list_snapshots(user_id)
    return {"user_id": user_id, "snapshot_count": len(snaps),
            "snapshots": snaps, "zone_size": zone_size_bytes(user_id)}


@router.post("/api/user/backups/snapshot")
async def create_snapshot(payload=Depends(verify_scan_quota)):
    user_id = payload["sub"]
    init_zone(user_id)
    snap = snapshot_user(user_id, reason="user_manual")
    if snap is None:
        raise HTTPException(500, "Snapshot creation failed")
    return {"ok": True, "snapshot_name": snap.name, "size_bytes": snap.stat().st_size}


@router.post("/api/user/backups/restore")
async def restore_named(req: RestoreRequest, payload=Depends(verify_scan_quota)):
    user_id = payload["sub"]
    if not req.snapshot_name or "/" in req.snapshot_name:
        raise HTTPException(400, "Invalid snapshot_name")
    ok = restore_snapshot(user_id, req.snapshot_name)
    if not ok:
        raise HTTPException(404, "Snapshot not found or restore failed")
    return {"ok": True, "restored": req.snapshot_name}


@router.post("/api/user/backups/restore-latest")
async def restore_most_recent(payload=Depends(verify_scan_quota)):
    user_id = payload["sub"]
    ok = restore_latest(user_id)
    if not ok:
        raise HTTPException(404, "No snapshots available")
    return {"ok": True, "restored": "latest"}


@router.delete("/api/user/backups/{snapshot_name}")
async def delete_named(snapshot_name: str, payload=Depends(verify_scan_quota)):
    """Permanently delete a snapshot. User can only delete their own."""
    user_id = payload["sub"]
    if not snapshot_name or "/" in snapshot_name or ".." in snapshot_name:
        raise HTTPException(400, "Invalid snapshot_name")
    ok = delete_snapshot(user_id, snapshot_name)
    if not ok:
        raise HTTPException(404, "Snapshot not found")
    return {"ok": True, "deleted": snapshot_name}


def register(app):
    app.include_router(router)

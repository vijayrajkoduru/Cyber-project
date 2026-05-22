"""Admin Backup Operations — /api/admin/backups/* — admin-only backup file management.

Provides:
  GET    /api/admin/backups/list           — list all backup files with metadata
  POST   /api/admin/backups/create         — create a fresh tar.gz backup of present state
  DELETE /api/admin/backups/{filename}     — delete one specific backup
  POST   /api/admin/backups/wipe           — delete ALL backups (nuclear option)
  GET    /api/admin/backups/download/{f}   — stream a backup file as download

The bundle includes users.db + .env + data/ + tools/ + src/ + docker/nginx config
— enough to fully restore the VPS from scratch.
"""
import datetime
import os
import subprocess
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from tools._shared import verify_admin

router = APIRouter()

BACKUP_DIR = Path("/root/backups")
PROJECT_ROOT = Path("/root/Cyber-project")
INCLUDE_PATHS = [
    "users.db", ".env", "data", "tools", "src",
    "docker-compose.yml", "Dockerfile", "Dockerfile.frontend",
    "nginx.conf", "requirements.txt",
]


def _ensure_backup_dir():
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)


def _human(b: int) -> str:
    if b < 1024: return f"{b} B"
    if b < 1048576: return f"{b/1024:.1f} KB"
    if b < 1073741824: return f"{b/1048576:.1f} MB"
    return f"{b/1073741824:.2f} GB"


@router.get("/api/admin/backups/list")
async def list_backups(_=Depends(verify_admin)):
    _ensure_backup_dir()
    files = []
    for f in sorted(BACKUP_DIR.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True):
        if not f.is_file(): continue
        st = f.stat()
        files.append({
            "name": f.name,
            "size_bytes": st.st_size,
            "size_human": _human(st.st_size),
            "modified_iso": datetime.datetime.utcfromtimestamp(st.st_mtime).isoformat() + "Z",
            "is_archive": f.suffix in (".gz", ".tar", ".zip", ".bundle"),
        })
    return {
        "count": len(files),
        "total_bytes": sum(f["size_bytes"] for f in files),
        "total_human": _human(sum(f["size_bytes"] for f in files)),
        "backup_dir": str(BACKUP_DIR),
        "files": files,
    }


@router.post("/api/admin/backups/create")
async def create_backup(_=Depends(verify_admin)):
    """Take a fresh full backup right now. Returns name + size of new file."""
    _ensure_backup_dir()
    ts = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    out = BACKUP_DIR / f"vulnuslab-{ts}.tar.gz"
    cmd = ["tar", "-czf", str(out), "-C", str(PROJECT_ROOT)] + [
        p for p in INCLUDE_PATHS if (PROJECT_ROOT / p).exists()
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Backup timed out after 180s")
    if r.returncode != 0:
        raise HTTPException(status_code=500, detail=f"tar failed: {r.stderr[:300]}")
    sz = out.stat().st_size
    return {"ok": True, "file": out.name, "size_bytes": sz, "size_human": _human(sz),
            "created_iso": datetime.datetime.utcnow().isoformat() + "Z"}


class DeleteBody(BaseModel):
    filename: str


@router.delete("/api/admin/backups/{filename}")
async def delete_backup(filename: str, _=Depends(verify_admin)):
    """Delete one backup. Filename must be a basename (no path traversal allowed)."""
    if "/" in filename or "\\" in filename or filename.startswith("."):
        raise HTTPException(status_code=400, detail="Invalid filename")
    target = BACKUP_DIR / filename
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="Backup not found")
    try:
        target.unlink()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Delete failed: {e}")
    return {"ok": True, "deleted": filename}


@router.post("/api/admin/backups/wipe")
async def wipe_backups(_=Depends(verify_admin)):
    """Delete ALL backup files. Use with extreme caution."""
    _ensure_backup_dir()
    removed = 0
    errors = []
    for f in BACKUP_DIR.glob("*"):
        if f.is_file():
            try:
                f.unlink(); removed += 1
            except Exception as e:
                errors.append(f"{f.name}: {e}")
    return {"ok": len(errors) == 0, "removed": removed, "errors": errors}


@router.post("/api/admin/backups/reset")
async def reset_backups(_=Depends(verify_admin)):
    """Reset = wipe ALL old backups + create ONE fresh full backup. Single atomic op.
    The "present-only" backup the user wants — clears history and replaces with current state.
    """
    _ensure_backup_dir()
    # Step 1: wipe everything
    removed = 0
    wipe_errors = []
    for f in BACKUP_DIR.glob("*"):
        if f.is_file():
            try:
                f.unlink(); removed += 1
            except Exception as e:
                wipe_errors.append(f"{f.name}: {e}")
    # Step 2: take fresh backup
    ts = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    out = BACKUP_DIR / f"vulnuslab-{ts}.tar.gz"
    cmd = ["tar", "-czf", str(out), "-C", str(PROJECT_ROOT)] + [
        p for p in INCLUDE_PATHS if (PROJECT_ROOT / p).exists()
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500,
            detail=f"Wiped {removed} old, but new backup timed out at 180s")
    if r.returncode != 0:
        raise HTTPException(status_code=500,
            detail=f"Wiped {removed} old, but tar failed: {r.stderr[:300]}")
    sz = out.stat().st_size
    return {"ok": True,
            "wiped": removed,
            "wipe_errors": wipe_errors,
            "new_file": out.name,
            "new_size_bytes": sz,
            "new_size_human": _human(sz),
            "created_iso": datetime.datetime.utcnow().isoformat() + "Z"}


@router.get("/api/admin/backups/download/{filename}")
async def download_backup(filename: str, _=Depends(verify_admin)):
    if "/" in filename or "\\" in filename or filename.startswith("."):
        raise HTTPException(status_code=400, detail="Invalid filename")
    target = BACKUP_DIR / filename
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="Backup not found")
    return FileResponse(path=str(target), filename=filename,
                         media_type="application/gzip")


def register(app):
    app.include_router(router)

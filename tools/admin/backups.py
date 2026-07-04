"""Admin Backup Operations — /api/admin/backups/* — admin-only backup file management.

Provides:
  GET    /api/admin/backups/list           — list all backup files with metadata
  POST   /api/admin/backups/create         — create a fresh tar.gz backup of present state
  DELETE /api/admin/backups/{filename}     — delete one specific backup
  POST   /api/admin/backups/wipe           — delete ALL backups (nuclear option)
  GET    /api/admin/backups/download/{f}   — stream a backup file as download

The bundle includes data/ + tools/ + src/ + docker/nginx config — the app and
its state. Secrets (.env) and the credential DB (users.db) are deliberately
EXCLUDED: this archive is downloadable via the admin API, so bundling secrets
would let any admin-token/RCE compromise exfiltrate every key. Back those up
out-of-band (secret manager / encrypted store).
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

# Paths from INSIDE the backend Docker container:
#   /backups        = host's ./backups (mounted in docker-compose.yml)
#   /host-project   = host's project root (./:/host-project:ro) — read-only mount
#                     so we can tar real host files (main.py, src/, configs, etc.)
BACKUP_DIR = Path("/backups")
PROJECT_ROOT = Path("/host-project")
# Complete end-to-end coverage: backend + frontend + infra + data + secrets.
# Restore from this single bundle should produce a working VPS deployment.
INCLUDE_PATHS = [
    # ─── Data (highest criticality) ──────────────────────────────
    # NOTE: secrets are deliberately NOT bundled. `.env` (JWT/vault/payment
    # keys) and `users.db` (password hashes, MFA secrets) were removed — this
    # tarball is downloadable via the admin API and any RCE/token compromise
    # would otherwise exfiltrate every credential. Back up secrets out-of-band
    # (secret manager / encrypted store), never in the app-served bundle.
    "data",                       # scan history, consent log, user state

    # ─── Backend ─────────────────────────────────────────────────
    "main.py",                    # FastAPI entry point + healing autoloader
    "tools",                      # 150 scanners + payloads + shared utils
    "endpoints",                  # admin/user/billing routes
    "profiles",                   # compliance.yaml mappings
    "requirements.txt",           # Python deps lockfile

    # ─── Frontend ────────────────────────────────────────────────
    "src",                        # App.js + components
    "public",                     # index.html, manifest, favicon
    "package.json",               # npm deps
    "package-lock.json",          # npm lockfile

    # ─── Infrastructure / deploy ─────────────────────────────────
    "docker-compose.yml",
    "Dockerfile",
    "Dockerfile.frontend",
    "nginx.conf",
    ".gitignore",
    ".dockerignore",

    # ─── Auxiliary ───────────────────────────────────────────────
    "scripts",                    # any backup / deploy helpers
    "DAILY.md",                   # session notes
    "STANDARDIZATION-SPEC.md",    # arch reference
]
EXCLUDE_PATTERNS = [
    "__pycache__",
    "*.pyc",
    "*.pyo",
    "node_modules",
    ".git",
    "build",
    "*.bak",
    "_legacy_quarantine",
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
        # Hide sidecar manifest .txt files from the UI list — they're audit
        # trail metadata for each .tar.gz, not separate backups themselves.
        # Still written/readable on disk for compliance; just not surfaced here.
        if f.name.endswith(".manifest.txt"): continue
        st = f.stat()
        # Attach manifest size if its sidecar exists (so we report true total).
        manifest_size = 0
        manifest = f.with_suffix("").with_suffix(".manifest.txt")
        if manifest.exists() and manifest.is_file():
            manifest_size = manifest.stat().st_size
        files.append({
            "name": f.name,
            "size_bytes": st.st_size,
            "size_human": _human(st.st_size),
            "has_manifest": manifest_size > 0,
            "modified_iso": datetime.datetime.utcfromtimestamp(st.st_mtime).isoformat() + "Z",
            "is_archive": f.suffix in (".gz", ".tar", ".zip", ".bundle"),
        })
    # Total includes the (hidden) manifests so disk usage reporting stays honest.
    total_disk_bytes = sum(
        ff.stat().st_size for ff in BACKUP_DIR.glob("*") if ff.is_file()
    )
    return {
        "count": len(files),
        "total_bytes": total_disk_bytes,
        "total_human": _human(total_disk_bytes),
        "backup_dir": str(BACKUP_DIR),
        "files": files,
    }


def _build_tar_cmd(out_path: Path) -> list:
    """Build the tar command with excludes + only-existing paths.
    Single source of truth used by both /create and /reset.
    """
    cmd = ["tar", "-czf", str(out_path)]
    for pat in EXCLUDE_PATTERNS:
        cmd += ["--exclude", pat]
    cmd += ["-C", str(PROJECT_ROOT)]
    cmd += [p for p in INCLUDE_PATHS if (PROJECT_ROOT / p).exists()]
    return cmd


def _write_manifest(out_path: Path, included: list) -> Path:
    """Sidecar manifest .txt next to each backup — auditable list of what's in it."""
    manifest = out_path.with_suffix("").with_suffix(".manifest.txt")
    lines = [
        f"VulnusLab Backup Manifest",
        f"Created (UTC): {datetime.datetime.utcnow().isoformat()}Z",
        f"Bundle: {out_path.name}",
        f"Size: {_human(out_path.stat().st_size)}",
        f"",
        f"=== Included paths ({len(included)}) ===",
    ]
    for p in included:
        full = PROJECT_ROOT / p
        if full.is_dir():
            file_count = sum(1 for _ in full.rglob("*") if _.is_file())
            lines.append(f"  {p}/ ({file_count} files)")
        else:
            lines.append(f"  {p}")
    lines.append("")
    lines.append(f"=== Excluded patterns ===")
    for pat in EXCLUDE_PATTERNS:
        lines.append(f"  {pat}")
    manifest.write_text("\n".join(lines))
    return manifest


@router.post("/api/admin/backups/create")
async def create_backup(_=Depends(verify_admin)):
    """Take a fresh full backup right now. Returns name + size of new file."""
    _ensure_backup_dir()
    ts = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    out = BACKUP_DIR / f"vulnuslab-{ts}.tar.gz"
    included = [p for p in INCLUDE_PATHS if (PROJECT_ROOT / p).exists()]
    cmd = _build_tar_cmd(out)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Backup timed out after 300s")
    if r.returncode != 0:
        raise HTTPException(status_code=500, detail=f"tar failed: {r.stderr[:300]}")
    sz = out.stat().st_size
    _write_manifest(out, included)
    return {"ok": True, "file": out.name, "size_bytes": sz, "size_human": _human(sz),
            "included_count": len(included),
            "created_iso": datetime.datetime.utcnow().isoformat() + "Z"}


class DeleteBody(BaseModel):
    filename: str


@router.delete("/api/admin/backups/{filename}")
async def delete_backup(filename: str, _=Depends(verify_admin)):
    """Delete one backup PLUS its sidecar manifest (if present)."""
    if "/" in filename or "\\" in filename or filename.startswith("."):
        raise HTTPException(status_code=400, detail="Invalid filename")
    target = BACKUP_DIR / filename
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="Backup not found")
    also_deleted = []
    try:
        target.unlink()
        # Sweep sidecar manifest .txt (same stem) so deletes leave no orphans.
        manifest = target.with_suffix("").with_suffix(".manifest.txt")
        if manifest.exists() and manifest.is_file():
            manifest.unlink(); also_deleted.append(manifest.name)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Delete failed: {e}")
    return {"ok": True, "deleted": filename, "also_deleted": also_deleted}


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
    included = [p for p in INCLUDE_PATHS if (PROJECT_ROOT / p).exists()]
    cmd = _build_tar_cmd(out)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500,
            detail=f"Wiped {removed} old, but new backup timed out at 300s")
    if r.returncode != 0:
        raise HTTPException(status_code=500,
            detail=f"Wiped {removed} old, but tar failed: {r.stderr[:300]}")
    sz = out.stat().st_size
    _write_manifest(out, included)
    return {"ok": True,
            "wiped": removed,
            "wipe_errors": wipe_errors,
            "new_file": out.name,
            "new_size_bytes": sz,
            "new_size_human": _human(sz),
            "included_count": len(included),
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


@router.get("/api/admin/backups/inspect/{filename}")
async def inspect_backup(filename: str, _=Depends(verify_admin)):
    """Peek inside a backup without extracting — lists what would restore."""
    if "/" in filename or "\\" in filename or filename.startswith("."):
        raise HTTPException(status_code=400, detail="Invalid filename")
    target = BACKUP_DIR / filename
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="Backup not found")
    if not filename.endswith(".tar.gz"):
        raise HTTPException(status_code=400, detail="Only .tar.gz archives can be inspected")
    try:
        r = subprocess.run(["tar", "-tzf", str(target)], capture_output=True,
                           text=True, timeout=30)
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Inspect timed out at 30s")
    if r.returncode != 0:
        raise HTTPException(status_code=500, detail=f"tar -tzf failed: {r.stderr[:200]}")
    lines = [l for l in r.stdout.splitlines() if l.strip()]
    # Group by top-level path component for a clean summary
    top_dirs = {}
    for path in lines:
        top = path.split("/", 1)[0] if "/" in path else path
        top_dirs[top] = top_dirs.get(top, 0) + 1
    return {"ok": True, "file": filename,
            "total_entries": len(lines),
            "top_level": [{"name": k, "files": v} for k, v in sorted(top_dirs.items())],
            "first_50_paths": lines[:50]}


def register(app):
    app.include_router(router)

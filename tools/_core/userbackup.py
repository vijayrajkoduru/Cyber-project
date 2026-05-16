"""USERBACKUP -- per-user snapshot + restore."""
import datetime
import logging
import shutil
import tarfile
from pathlib import Path
from tools._core.userzone import zone_root, _validate_user_id

log = logging.getLogger("vulnuslab.userbackup")
MAX_SNAPSHOTS = 10


def _backup_dir(user_id):
    return zone_root(user_id) / ".backup"


def _next_snap_name(user_id):
    ts = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    return f"snap-{ts}.tar.gz"


def snapshot_user(user_id, reason="manual"):
    _validate_user_id(user_id)
    zr = zone_root(user_id)
    if not zr.exists():
        return None
    bdir = _backup_dir(user_id)
    bdir.mkdir(parents=True, exist_ok=True)
    target = bdir / _next_snap_name(user_id)
    try:
        with tarfile.open(target, "w:gz") as tar:
            for child in zr.iterdir():
                if child.name == ".backup":
                    continue
                tar.add(child, arcname=child.name)
        log.info("snapshot OK for %s reason=%s", user_id, reason)
    except Exception as exc:
        log.error("snapshot FAILED for %s: %s", user_id, exc)
        target.unlink(missing_ok=True)
        return None
    _prune_old_snapshots(user_id)
    return target


def list_snapshots(user_id):
    _validate_user_id(user_id)
    bdir = _backup_dir(user_id)
    if not bdir.exists():
        return []
    snaps = []
    for f in sorted(bdir.glob("snap-*.tar.gz"), reverse=True):
        st = f.stat()
        snaps.append({"name": f.name, "size_bytes": st.st_size,
                      "created_iso": datetime.datetime.utcfromtimestamp(st.st_mtime).isoformat() + "Z"})
    return snaps


def restore_snapshot(user_id, snap_name):
    _validate_user_id(user_id)
    bdir = _backup_dir(user_id)
    snap = bdir / snap_name
    if not snap.exists():
        return False
    zr = zone_root(user_id)
    try:
        for child in zr.iterdir():
            if child.name == ".backup":
                continue
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
        with tarfile.open(snap, "r:gz") as tar:
            tar.extractall(zr)
        log.warning("USER-RESTORE: %s from %s", user_id, snap_name)
        return True
    except Exception as exc:
        log.error("restore FAILED for %s: %s", user_id, exc)
        return False


def restore_latest(user_id):
    snaps = list_snapshots(user_id)
    if not snaps:
        return False
    return restore_snapshot(user_id, snaps[0]["name"])


def _prune_old_snapshots(user_id):
    bdir = _backup_dir(user_id)
    if not bdir.exists():
        return
    for old in sorted(bdir.glob("snap-*.tar.gz"), reverse=True)[MAX_SNAPSHOTS:]:
        try:
            old.unlink()
        except Exception:
            pass

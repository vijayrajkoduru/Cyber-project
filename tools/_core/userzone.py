"""User Zone — multi-tenant data isolation."""
import json
import re
import shutil
from pathlib import Path

DATA_ROOT = Path("/data/users")
_VALID_USER_ID = re.compile(r"^[a-zA-Z0-9_]{1,64}$")


class UserZoneError(Exception):
    pass


def _validate_user_id(user_id):
    if not isinstance(user_id, str):
        raise UserZoneError(f"user_id must be str, got {type(user_id).__name__}")
    if not _VALID_USER_ID.match(user_id):
        raise UserZoneError(f"user_id {user_id!r} invalid")
    return user_id


def zone_root(user_id):
    return DATA_ROOT / _validate_user_id(user_id)


def init_zone(user_id):
    zr = zone_root(user_id)
    (zr / "scans").mkdir(parents=True, exist_ok=True)
    (zr / "reports").mkdir(exist_ok=True)
    (zr / ".backup").mkdir(exist_ok=True)
    for name, default in (("settings.json", {}), ("api_keys.json", {}), ("targets.json", [])):
        p = zr / name
        if not p.exists():
            p.write_text(json.dumps(default, indent=2), encoding="utf-8")
    return zr


def safe_path(user_id, rel):
    zr = zone_root(user_id)
    target = (zr / rel).resolve()
    try:
        target.relative_to(zr.resolve())
    except ValueError:
        raise UserZoneError(f"path traversal blocked: {rel!r}")
    return target


def read_json(user_id, rel):
    p = safe_path(user_id, rel)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def write_json(user_id, rel, data):
    p = safe_path(user_id, rel)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return p


def list_dir(user_id, rel=""):
    p = safe_path(user_id, rel)
    if not p.exists() or not p.is_dir():
        return []
    return sorted(child.name for child in p.iterdir())


def delete_zone(user_id):
    zr = zone_root(user_id)
    if not zr.exists():
        return False
    shutil.rmtree(zr)
    return True


def zone_size_bytes(user_id):
    zr = zone_root(user_id)
    if not zr.exists():
        return 0
    return sum(f.stat().st_size for f in zr.rglob("*") if f.is_file())

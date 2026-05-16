"""VAULT -- master encrypted backup (admin-only)."""
import datetime
import hashlib
import json
import logging
import os
import shutil
from pathlib import Path

log = logging.getLogger("vulnuslab.vault")
VAULT_ROOT = Path("/backups/vault")
RETENTION_DAYS = 30


def _get_cipher():
    from cryptography.fernet import Fernet
    key = os.getenv("VAULT_KEY", "").strip()
    if not key:
        raise RuntimeError("VAULT_KEY env var is not set")
    return Fernet(key.encode())


def _today_dir():
    today = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    d = VAULT_ROOT / today
    d.mkdir(parents=True, exist_ok=True)
    return d


def _file_hash(p):
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def encrypt_file_to_vault(plain_path, vault_relative):
    cipher = _get_cipher()
    out = _today_dir() / f"{vault_relative}.enc"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(cipher.encrypt(plain_path.read_bytes()))
    return out


def decrypt_vault_file(enc_path, output_path):
    cipher = _get_cipher()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(cipher.decrypt(enc_path.read_bytes()))


def nightly_sync(users_data_root=Path("/data/users"),
                 tool_backup_root=Path(".last_known_good"),
                 users_db=None):
    # Honour the same USERS_DB env var auth uses, so vault encrypts
    # the SAME DB the application reads — not the stale empty file
    # at /app/users.db. Bind-mount fix on 2026-05-16 moved real DB
    # to /app/data/users.db.
    if users_db is None:
        users_db = Path(os.getenv("USERS_DB", "/app/data/users.db"))
    started = datetime.datetime.utcnow()
    target = _today_dir()
    manifest = {"started_iso": started.isoformat() + "Z",
                "vault_dir": str(target),
                "users": [], "tools": [], "db": None, "errors": []}

    if users_data_root.exists():
        for user_dir in sorted(users_data_root.iterdir()):
            if not user_dir.is_dir():
                continue
            backup_dir = user_dir / ".backup"
            if not backup_dir.exists():
                continue
            snaps = sorted(backup_dir.glob("snap-*.tar.gz"), reverse=True)
            if not snaps:
                continue
            latest = snaps[0]
            try:
                rel = f"users/{user_dir.name}/{latest.name}"
                enc = encrypt_file_to_vault(latest, rel)
                manifest["users"].append({"user_id": user_dir.name,
                                          "snapshot": latest.name,
                                          "vault": str(enc.relative_to(target)),
                                          "sha256": _file_hash(latest),
                                          "size": latest.stat().st_size})
            except Exception as exc:
                manifest["errors"].append({"user_id": user_dir.name,
                                           "stage": "user_snapshot",
                                           "error": str(exc)[:200]})

    if tool_backup_root.exists():
        for tool_file in tool_backup_root.rglob("*.py"):
            try:
                rel = f"tools/{tool_file.relative_to(tool_backup_root)}"
                enc = encrypt_file_to_vault(tool_file, rel)
                manifest["tools"].append({"tool": str(tool_file.relative_to(tool_backup_root)),
                                          "vault": str(enc.relative_to(target)),
                                          "sha256": _file_hash(tool_file)})
            except Exception as exc:
                manifest["errors"].append({"tool": str(tool_file),
                                           "stage": "tool_snapshot",
                                           "error": str(exc)[:200]})

    if users_db.exists():
        try:
            enc = encrypt_file_to_vault(users_db, "db/users.db")
            manifest["db"] = {"vault": str(enc.relative_to(target)),
                              "sha256": _file_hash(users_db),
                              "size": users_db.stat().st_size}
        except Exception as exc:
            manifest["errors"].append({"stage": "users_db", "error": str(exc)[:200]})

    manifest["finished_iso"] = datetime.datetime.utcnow().isoformat() + "Z"
    (target / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    log.info("VAULT sync done: %d users, %d tools",
             len(manifest["users"]), len(manifest["tools"]))
    _prune_old_vaults()
    return manifest


def _prune_old_vaults():
    if not VAULT_ROOT.exists():
        return
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=RETENTION_DAYS)
    for d in VAULT_ROOT.iterdir():
        if not d.is_dir():
            continue
        try:
            dir_date = datetime.datetime.strptime(d.name, "%Y-%m-%d")
        except ValueError:
            continue
        if dir_date < cutoff:
            try:
                shutil.rmtree(d)
            except Exception:
                pass


def list_vault_days():
    if not VAULT_ROOT.exists():
        return []
    out = []
    for d in sorted(VAULT_ROOT.iterdir(), reverse=True):
        if not d.is_dir():
            continue
        m_path = d / "manifest.json"
        if not m_path.exists():
            continue
        try:
            manifest = json.loads(m_path.read_text())
        except Exception:
            manifest = {"error": "manifest unreadable"}
        out.append({"date": d.name, "manifest": manifest})
    return out

"""Self-healing tool loader — Kali-style isolation + auto-restore.

When a tool file fails to import, this module:
  1. Looks for a 'last known good' snapshot
  2. Restores the file from snapshot if found
  3. Retries the import
  4. Logs the auto-recovery

When a tool DOES load successfully, this module:
  1. Snapshots the file bytes to .last_known_good/<rel_path>
  2. Skips write if hash matches (no churn on container restart)
"""
import hashlib
import importlib
import logging
import shutil
import sys
from pathlib import Path
from typing import Tuple, Optional

log = logging.getLogger("vulnuslab.healing")


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _backup_path(tool_file: Path) -> Path:
    root = _project_root()
    rel = tool_file.resolve().relative_to(root)
    return root / ".last_known_good" / rel


def _hash(path: Path) -> Optional[str]:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        return None


def snapshot_file(tool_file: Path) -> None:
    backup = _backup_path(tool_file)
    if backup.exists() and _hash(backup) == _hash(tool_file):
        return
    try:
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(tool_file, backup)
    except Exception as exc:
        log.warning("snapshot failed for %s: %s", tool_file, exc)


def restore_file(tool_file: Path) -> bool:
    backup = _backup_path(tool_file)
    if not backup.exists():
        return False
    try:
        shutil.copy2(backup, tool_file)
        log.warning("AUTO-HEAL: restored %s from %s", tool_file, backup)
        return True
    except Exception as exc:
        log.error("AUTO-HEAL: restore FAILED for %s: %s", tool_file, exc)
        return False


def load_with_healing(import_path: str, tool_file: Path
                      ) -> Tuple[Optional[object], str]:
    try:
        module = importlib.import_module(import_path)
        snapshot_file(tool_file)
        return module, "loaded"
    except Exception as first_exc:
        log.error("Tool %s failed to load: %s", import_path, first_exc)

    if not restore_file(tool_file):
        log.error("No snapshot for %s — quarantining", import_path)
        return None, "quarantined"

    if import_path in sys.modules:
        del sys.modules[import_path]
    try:
        module = importlib.import_module(import_path)
        log.warning("AUTO-HEAL: %s recovered from snapshot", import_path)
        return module, "healed"
    except Exception as second_exc:
        log.error("AUTO-HEAL: %s still broken after restore: %s",
                  import_path, second_exc)
        return None, "quarantined"

"""Fault-isolating tool loader — quarantine-only (HEAL-QUARANTINE-V1).

History: this module used to "self-heal" a tool that failed to import by
copying a `.last_known_good/` snapshot back over the file in the source tree
and re-importing it. That was a persistence primitive: the snapshot dir is a
writable (bind-mounted) location, so anyone who could write into it — or into
tools/ once, which then got snapshotted on the next successful boot — would
have their code re-written into the source tree on every boot, surviving image
rebuilds and manual cleanups. Unverified snapshots restored over code ==
backdoor.

Now: a module that fails to import is QUARANTINED — it is simply not
registered (its routes are absent), the failure is logged, and the rest of the
platform boots normally. Nothing is ever written into the source tree and no
snapshot is ever read. Code changes ship only via an image rebuild.

`load_with_healing()` keeps its signature and `(module, status)` contract so
main.py / the /api/health `tools_healed` + `healing_engine` fields keep
working; `status` is now only ever "loaded" or "quarantined".
"""
import importlib
import logging
import sys
from pathlib import Path
from typing import Tuple, Optional

log = logging.getLogger("vulnuslab.healing")


def load_with_healing(import_path: str, tool_file: Path
                      ) -> Tuple[Optional[object], str]:
    """Import `import_path`; on failure quarantine it (never restore files)."""
    try:
        module = importlib.import_module(import_path)
        return module, "loaded"
    except (Exception, SystemExit) as exc:
        log.error("Tool %s (%s) failed to load — QUARANTINED (routes disabled): %s",
                  import_path, tool_file, exc)
        # Drop any half-initialised module object so nothing else picks it up.
        sys.modules.pop(import_path, None)
        return None, "quarantined"

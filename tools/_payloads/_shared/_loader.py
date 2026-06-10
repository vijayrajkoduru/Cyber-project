"""VL-CORE shared-payloads loader.

Opt-in escape hatch for genuinely cross-module payloads. Use sparingly —
the default is module isolation. Import from here is a CONSCIOUS decision
to couple modules to a shared resource.

Example legitimate uses:
  - Generic top-1000 passwords list (every module's auth scanner wants it)
  - HIBP-style public breach signal datasets
  - CVE/EPSS API cache shared across vuln + recon

Anti-pattern:
  - Putting a webapp-specific payload here so "vuln might want it later"
"""
import json
import os
from typing import Any, Iterable, Optional
from tools._framework.vl_core import shared_root

_BASE = str(shared_root())


def load_json(name: str, fallback: Optional[Any] = None) -> Any:
    path = os.path.join(_BASE, f"{name}.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return fallback if fallback is not None else []


def load_lines(name: str, fallback: Optional[Iterable[str]] = None) -> list:
    path = os.path.join(_BASE, f"{name}.txt")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [ln.strip() for ln in f
                    if ln.strip() and not ln.strip().startswith("#")]
    except (FileNotFoundError, OSError):
        return list(fallback) if fallback is not None else []

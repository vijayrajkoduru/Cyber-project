"""VL-CORE loader for the Network module.

Same shape as tools/_payloads/webapp/_loader.py. Each module owns its own
loader so VL-CORE isolation can be enforced — network scanners import
ONLY from this file (or network/*.py / network/*.json under the same dir).

If a JSON file is missing or malformed, the loader returns the supplied
fallback — scanners must keep working even when the bundled pool is absent
(e.g. during partial deploy / dev env).
"""
import json
import os
from typing import Any, Iterable, Optional
from tools._framework.vl_core import module_root, assert_isolated_import

_BASE = str(module_root("network"))
assert_isolated_import("network", "network")


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

"""VL-CORE loader for the OSINT module."""
import json
import os
from typing import Any, Iterable, Optional
from tools._framework.vl_core import module_root, assert_isolated_import

_BASE = str(module_root("osint"))
assert_isolated_import("osint", "osint")


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

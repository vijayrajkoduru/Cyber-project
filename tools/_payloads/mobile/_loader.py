"""VL-CORE loader for the Mobile suite (shared across all 10 mobile_* modules).

Same shape as tools/_payloads/webapp/_loader.py. VL-CORE registers a SINGLE
"mobile" pool, so every mobile_* scanner (mobile_static / mobile_crypto /
mobile_privacy / mobile_storage / mobile_webview / mobile_runtime /
mobile_payment / mobile_ipc / mobile_aiml / mobile_network) imports ONLY from
this file — the curated AI pattern pool that backs static-analysis detection.

Each scanner passes its EXISTING inline list/dict as fallback= so behaviour is
identical if a JSON file is ever missing or malformed (zero new failure mode).
"""
import json
import os
from typing import Any, Iterable, Optional
from tools._framework.vl_core import module_root, assert_isolated_import

_BASE = str(module_root("mobile"))
assert_isolated_import("mobile", "mobile")


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

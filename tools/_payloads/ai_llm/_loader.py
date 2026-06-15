"""VL-CORE loader for the AI/LLM module.

Same shape as tools/_payloads/webapp/_loader.py. Each module owns its own
loader so VL-CORE isolation can be enforced — ai_llm scanners import
ONLY from this file (or ai_llm/*.py / ai_llm/*.txt / ai_llm/*.json under
the same dir).
"""
import json
import os
from typing import Any, Iterable, Optional
from tools._framework.vl_core import module_root, assert_isolated_import

_BASE = str(module_root("ai_llm"))
assert_isolated_import("ai_llm", "ai_llm")


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

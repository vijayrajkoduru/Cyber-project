"""AI-curated red-team knowledge base — loader.

Ships the offline ATT&CK technique library + adversary-emulation playbooks as
data (techniques.json / scenarios.json), curated by _build.py. attack_catalog
loads these at import; if the files are absent it falls back to its built-in set
so the engine always works.
"""
from __future__ import annotations

import json
import os

_DIR = os.path.dirname(os.path.abspath(__file__))


def _load(name):
    path = os.path.join(_DIR, name)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def load_techniques():
    """Return the curated technique list, or None if unavailable."""
    return _load("techniques.json")


def load_scenarios():
    """Return the curated scenarios dict, or None if unavailable."""
    return _load("scenarios.json")

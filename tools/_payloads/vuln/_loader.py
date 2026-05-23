"""AI-curated payload loader for the Vulnerability Scanning module.

Mirrors the Recon module's tools/_payloads/recon/ pattern. JSON wordlists
live in this directory and are loaded once at module import.

If a JSON file is missing or malformed, the loader returns the supplied
fallback list — scanners must continue to work even when the bundled
wordlist is absent (e.g. during partial deploy / dev env).
"""
import json
import os
from typing import Any, Iterable, Optional

_BASE = os.path.dirname(os.path.abspath(__file__))


def load_json(name: str, fallback: Optional[Any] = None) -> Any:
    """Load a curated JSON wordlist by file name (no extension).

    Returns parsed JSON (list or dict). If the file is missing or unreadable,
    returns `fallback` (which defaults to []).
    """
    path = os.path.join(_BASE, f"{name}.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return fallback if fallback is not None else []


def load_lines(name: str, fallback: Optional[Iterable[str]] = None) -> list:
    """Load a curated newline-delimited wordlist by file name (.txt added).

    Useful for huge flat lists (5000+ entries) where JSON overhead matters.
    Strips whitespace and skips empty / comment (#) lines.
    """
    path = os.path.join(_BASE, f"{name}.txt")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [ln.strip() for ln in f
                    if ln.strip() and not ln.strip().startswith("#")]
    except (FileNotFoundError, OSError):
        return list(fallback) if fallback is not None else []

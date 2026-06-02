"""Curated payload loader for the Container/K8s module.

Mirrors the Vuln + Recon modules' tools/_payloads/*/  pattern. JSON wordlists
live in this directory and are loaded once at module import. The Container
module's Dockerfile probes (_probe_dockerfile_hardcoded_secret, the new
_probe_dockerfile_base_image_eol, and the antipattern checks) consume these
lists to detect 5-10x more issues than the hard-coded baseline patterns.

Sources (no AI runtime, no API cost):
  - secret_patterns.json: aggregated from public gitleaks + trufflehog configs
  - eol_base_images.json: snapshot from endoflife.date public API
  - dockerfile_antipatterns.json: rules NOT covered by hadolint binary

Refresh cadence: quarterly. Re-run the compile process to pull new patterns
from upstream sources + EOL dates.

If a JSON file is missing or malformed, the loader returns the supplied
fallback list — probes must continue to work with their baseline patterns
even when the bundled wordlist is absent (e.g. during partial deploy /
test env).
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, date
from typing import Any, Optional

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


# ── Cached pattern lists (load once at import) ───────────────────────────

_SECRET_PATTERNS_CACHE: Optional[list] = None
_EOL_IMAGES_CACHE: Optional[list] = None
_DOCKERFILE_ANTIPATTERNS_CACHE: Optional[list] = None


def get_secret_patterns() -> list:
    """Return parsed + compiled secret regex patterns.

    Each entry has the original 'name', 'regex', 'severity', 'category' plus
    a precompiled 'compiled' Pattern object for fast scanning.
    Patterns marked context_required:true must match within the keyword anchor
    already encoded in their regex (the regex itself contains the anchor).
    """
    global _SECRET_PATTERNS_CACHE
    if _SECRET_PATTERNS_CACHE is not None:
        return _SECRET_PATTERNS_CACHE
    data = load_json("secret_patterns", fallback={"patterns": []})
    out = []
    for p in data.get("patterns", []):
        try:
            out.append({
                **p,
                "compiled": re.compile(p["regex"]),
            })
        except re.error:
            # Skip malformed regex but keep loading others — a single
            # bad pattern shouldn't disable the whole list.
            continue
    _SECRET_PATTERNS_CACHE = out
    return out


def get_eol_base_images() -> list:
    """Return list of {image, version, eol_date, ...} dicts."""
    global _EOL_IMAGES_CACHE
    if _EOL_IMAGES_CACHE is not None:
        return _EOL_IMAGES_CACHE
    data = load_json("eol_base_images", fallback={"images": []})
    _EOL_IMAGES_CACHE = data.get("images", [])
    return _EOL_IMAGES_CACHE


def get_dockerfile_antipatterns() -> list:
    """Return parsed + compiled antipattern regex rules."""
    global _DOCKERFILE_ANTIPATTERNS_CACHE
    if _DOCKERFILE_ANTIPATTERNS_CACHE is not None:
        return _DOCKERFILE_ANTIPATTERNS_CACHE
    data = load_json("dockerfile_antipatterns", fallback={"rules": []})
    out = []
    for r in data.get("rules", []):
        try:
            out.append({**r, "compiled": re.compile(r["regex"])})
        except re.error:
            continue
    _DOCKERFILE_ANTIPATTERNS_CACHE = out
    return out


# ── EOL severity helpers ─────────────────────────────────────────────────

def classify_eol(eol_date_str: str, today: Optional[date] = None) -> tuple[str, str, int]:
    """Classify EOL state from today's perspective.

    Returns (severity, label, days_until_or_since_eol).
      severity ∈ {CRITICAL, HIGH, MEDIUM, LOW, INFO}
      label    ∈ {"PAST EOL", "EOL <30d", "EOL <90d", "EOL <180d", "OK"}
      days_until_or_since_eol: negative if past, positive if future

    Computed at probe time so the wordlist itself doesn't need quarterly
    severity re-curation — just date-stamp updates.
    """
    try:
        eol = datetime.strptime(eol_date_str, "%Y-%m-%d").date()
    except (ValueError, TypeError):
        return ("INFO", "EOL DATE PARSE FAILED", 0)
    today = today or datetime.utcnow().date()
    delta = (eol - today).days
    if delta < 0:
        return ("CRITICAL", "PAST EOL", delta)
    if delta < 30:
        return ("HIGH", "EOL <30d", delta)
    if delta < 90:
        return ("HIGH", "EOL <90d", delta)
    if delta < 180:
        return ("MEDIUM", "EOL <180d", delta)
    return ("INFO", "OK", delta)

"""SPA state — shared discovery cache used by every active scanner.

The SPA Crawler writes the URLs, API endpoints, and parameter names it
discovered during the headless browser crawl. Every later scanner reads
this cache instead of guessing what to probe, which unlocks testing of
modern React / Vue / Angular SPAs that return the same shell HTML for
every URL on first paint.
"""
from __future__ import annotations

import datetime
import json
import os
import threading
from urllib.parse import urlparse

_LOCK = threading.Lock()
_PATH = os.environ.get("SPA_STATE_PATH", "/app/data/scan_state.json")


def _target_key(target: str) -> str:
    try:
        u = urlparse(target if "://" in target else "http://" + target)
        return (u.netloc or target).lower()
    except Exception:
        return target.lower()


def _load_all() -> dict:
    if not os.path.exists(_PATH):
        return {}
    try:
        with open(_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def save_spa_state(target: str, urls, endpoints, params) -> None:
    os.makedirs(os.path.dirname(_PATH), exist_ok=True)
    key = _target_key(target)
    with _LOCK:
        data = _load_all()
        data[key] = {
            "urls":      list(urls)[:200],
            "endpoints": dict(list(dict(endpoints).items())[:100]),
            "params":    list(params)[:50],
            "saved_at":  datetime.datetime.utcnow().isoformat() + "Z",
        }
        with open(_PATH, "w") as f:
            json.dump(data, f)


def load_spa_state(target: str) -> dict:
    key = _target_key(target)
    data = _load_all().get(key, {})
    return {
        "urls":      data.get("urls", []),
        "endpoints": data.get("endpoints", {}),
        "params":    data.get("params", []),
    }

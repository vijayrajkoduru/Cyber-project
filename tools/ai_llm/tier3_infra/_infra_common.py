"""Shared helpers for ai_llm tier3_infra exposure probes.

All helpers are READ-ONLY remote inspection — HTTP GET/HEAD on well-known
LLM-infra paths, banner/header parsing, and base-URL normalisation. No
mutating verbs (POST/PUT/DELETE) are issued against discovered admin/API
paths and no payloads are sent. Everything degrades safely on error.
"""
from __future__ import annotations
from urllib.parse import urlsplit, urlunsplit


def normalize_base(target: str) -> str | None:
    """Turn a customer target (URL or bare host[:port]) into a scheme://host[:port]
    base with no path. Returns None for empty/garbage input."""
    if not target:
        return None
    t = target.strip()
    if not t:
        return None
    if not t.startswith(("http://", "https://")):
        # Bare host / host:port — default to http for plaintext infra ports,
        # https only if an obvious 443 marker. We probe both schemes upstream
        # where it matters; default to http here for permissive discovery.
        t = "http://" + t
    try:
        parts = urlsplit(t)
        if not parts.netloc:
            return None
        return urlunsplit((parts.scheme, parts.netloc, "", "", ""))
    except Exception:
        return None


def base_variants(target: str) -> list[str]:
    """Return de-duplicated scheme variants to probe (http + https) for a
    bare host, or just the supplied scheme if the customer was explicit."""
    if not target:
        return []
    t = target.strip()
    explicit_scheme = t.startswith(("http://", "https://"))
    base = normalize_base(t)
    if not base:
        return []
    if explicit_scheme:
        return [base]
    # Bare host — try https first (more common for managed endpoints), then http.
    parts = urlsplit(base)
    https = urlunsplit(("https", parts.netloc, "", "", ""))
    http = urlunsplit(("http", parts.netloc, "", "", ""))
    out = []
    for u in (https, http):
        if u not in out:
            out.append(u)
    return out


def build_headers(bearer: str | None, extra_headers, ua: str) -> dict:
    headers = {"User-Agent": ua, "Accept": "application/json, text/plain, */*"}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    if isinstance(extra_headers, dict):
        for k, v in extra_headers.items():
            try:
                headers[str(k)] = str(v)
            except Exception:
                continue
    return headers


def safe_join(base: str, path: str) -> str:
    if not base.endswith("/") and not path.startswith("/"):
        return base + "/" + path
    if base.endswith("/") and path.startswith("/"):
        return base + path[1:]
    return base + path


def body_excerpt(text, limit: int = 240) -> str:
    """Trim a response body to a short, single-line excerpt for evidence."""
    if not text:
        return ""
    try:
        s = text if isinstance(text, str) else str(text)
    except Exception:
        return ""
    s = " ".join(s.split())
    return (s[:limit] + "...") if len(s) > limit else s

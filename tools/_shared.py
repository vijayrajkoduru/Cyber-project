"""Shared infrastructure used by every tool.

Pattern: import what you need from `tools._shared` and write a single
register(app) function in your tool file. Examples:

    from tools._shared import (
        ScanRequest, verify_token, verify_scan_quota,
        safe_get, safe_post, wrap_finding,
    )
"""
import os
import re
import time
import uuid
import random
import string
import asyncio
import datetime
import contextvars
from typing import Optional, List

from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import jwt as _jwt
import requests as _req_lib
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── JWT auth ────────────────────────────────────────────────────────
JWT_SECRET = os.getenv("JWT_SECRET", "")
bearer = HTTPBearer(auto_error=False)

# Context-vars so tools deep in the stack can read the current request's
# auth without threading it through every function arg.
_AUTH_CTX: contextvars.ContextVar = contextvars.ContextVar("auth_ctx", default=None)
_USER_CTX: contextvars.ContextVar = contextvars.ContextVar("user_ctx", default=None)


class ScanRequest(BaseModel):
    """Standard request shape every tool accepts.
    Tools that need extra fields subclass this in their own file."""
    target: str
    api_key: Optional[str] = None
    auth_cookie: Optional[str] = None       # e.g. "PHPSESSID=abc; token=xyz"
    auth_bearer: Optional[str] = None       # e.g. "eyJhbGci..."
    wordlist: Optional[List[str]] = None    # custom paths for fuzzers


def verify_token(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    """Decode JWT. Raises 401 if missing/invalid. Every tool endpoint
    that requires auth depends on this."""
    if not creds:
        raise HTTPException(401, "Missing Authorization header")
    try:
        payload = _jwt.decode(creds.credentials, JWT_SECRET, algorithms=["HS256"])
    except Exception as e:
        raise HTTPException(401, f"Invalid token: {e}")
    _USER_CTX.set(payload.get("sub", "unknown"))
    return payload


def verify_scan_quota(payload=Depends(verify_token)):
    """Same as verify_token + a placeholder for future per-plan quotas.
    Tools that fire many backend requests (port scans, fuzzers) depend
    on this version so we can rate-limit trial users later."""
    # TODO: per-plan quota check when billing module is wired
    return payload


# ── HTTP helper — Trust-First (adaptive timeout + retry + 429-aware) ──
_BROWSER_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 "
                   "Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive",
}


def make_req_headers(req: Optional[ScanRequest] = None) -> dict:
    """Merge browser headers with optional auth from a ScanRequest."""
    h = dict(_BROWSER_HEADERS)
    auth = req or _AUTH_CTX.get()
    if auth:
        if getattr(auth, "auth_cookie", None):
            h["Cookie"] = auth.auth_cookie
        if getattr(auth, "auth_bearer", None):
            h["Authorization"] = f"Bearer {auth.auth_bearer}"
    return h


def safe_request(method: str, url: str, *,
                 retries: int = 2,
                 timeout: int = 15,
                 headers: Optional[dict] = None,
                 req: Optional[ScanRequest] = None,
                 verify: bool = False,
                 allow_redirects: bool = True,
                 data=None, json=None, params=None):
    """HTTP request with retry + adaptive timeout + 429-aware backoff.

    Real-world targets behind Cloudflare/AWS WAF throw transient 429s,
    502s, connection resets. This helper retries them transparently and
    extends the timeout 1.5× per attempt so slow targets aren't killed.

    Returns the requests.Response on success, or None after final
    failure (callers do `if r is None: ...`).
    """
    h = headers if headers is not None else make_req_headers(req)
    for attempt in range(retries + 1):
        effective_timeout = min(60, int(timeout * (1.5 ** attempt)))
        try:
            kw = dict(timeout=effective_timeout, headers=h, verify=verify,
                      allow_redirects=allow_redirects)
            if data is not None:   kw["data"] = data
            if json is not None:   kw["json"] = json
            if params is not None: kw["params"] = params
            r = _req_lib.request(method.upper(), url, **kw)
            # 429 — honor Retry-After
            if r.status_code == 429 and attempt < retries:
                ra = r.headers.get("Retry-After", "")
                try:
                    wait = float(ra) if ra and ra.isdigit() else 2.0 * (attempt + 1)
                except Exception:
                    wait = 2.0 * (attempt + 1)
                time.sleep(min(wait, 8.0))
                continue
            # 5xx — upstream glitch
            if 500 <= r.status_code < 600 and attempt < retries:
                time.sleep((1.5 ** attempt) + random.random() * 0.5)
                continue
            return r
        except (_req_lib.exceptions.Timeout,
                _req_lib.exceptions.ConnectionError,
                _req_lib.exceptions.ChunkedEncodingError):
            if attempt < retries:
                time.sleep((1.5 ** attempt) + random.random() * 0.4)
                continue
        except Exception:
            return None
    return None


def safe_get(url, **kw):
    return safe_request("GET", url, **kw)


def safe_post(url, **kw):
    return safe_request("POST", url, **kw)


# ── Trust-First finding shape ───────────────────────────────────────
def wrap_finding(detail: str, severity: str, **kw) -> dict:
    """Stamp a finding with the Trust-First mandatory fields.
    Every finding shipped to the PDF MUST pass through this.

    Required (positional):  detail, severity
    Optional via **kw:
        cvss, cve, cwe, cwe_name, owasp, remediation,
        evidence_marker, tests_performed
    Auto-set:
        confidence:   "CONFIRMED"   (no SUSPECTED tier — see memory
                                     feedback-real-findings-zero-fp)
        verified_at:  ISO timestamp of this stamp
    """
    return {
        "detail":          detail,
        "severity":        severity,
        "cvss":            kw.get("cvss", "0.0"),
        "cve":             kw.get("cve", "N/A"),
        "cwe":             kw.get("cwe", "N/A"),
        "cwe_name":        kw.get("cwe_name", ""),
        "owasp":           kw.get("owasp", "N/A"),
        "remediation":     kw.get("remediation", ""),
        "confidence":      "CONFIRMED",
        "verified_at":     datetime.datetime.utcnow().isoformat() + "Z",
        "evidence_marker": kw.get("evidence_marker", ""),
        "tests_performed": kw.get("tests_performed", 1),
    }


def standard_response(*, tool: str, target: str, findings: list,
                      tests_performed: int = 0,
                      tests_summary: str = "",
                      vulnerable: Optional[bool] = None,
                      skipped_reason: Optional[str] = None,
                      raw_data: Optional[dict] = None) -> dict:
    """Standard response shape every tool returns. Keeps the PDF
    generator + frontend consistent across all 100+ tools."""
    if vulnerable is None:
        vulnerable = any(f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM")
                         for f in findings)
    resp = {
        "scan_id":         str(uuid.uuid4()),
        "target":          target,
        "tool":            tool,
        "findings":        findings,
        "total":           len(findings),
        "vulnerable":      vulnerable,
        "tests_performed": tests_performed,
        "tests_summary":   tests_summary,
        "timestamp":       datetime.datetime.utcnow().isoformat() + "Z",
    }
    if skipped_reason:
        resp["skipped_reason"] = skipped_reason
        resp["vulnerable"] = False
    if raw_data:
        resp.update(raw_data)
    return resp


def web_url(target: str) -> str:
    """Normalize target string into a valid HTTP URL."""
    if target.startswith(("http://", "https://")):
        return target
    return "http://" + target


def recon_host(target: str) -> str:
    """Extract just the hostname from a target URL or string."""
    from urllib.parse import urlparse
    if "://" in target:
        return urlparse(target).hostname or target
    return target.split("/")[0]

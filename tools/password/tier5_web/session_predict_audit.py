"""session_predict_audit - HTTP session cookie predictability audit (VL-METHOD).

Phase D web-credential-access scanner. Captures fresh session cookies
from a target web application and analyzes them for predictability:

  - Shannon entropy per cookie value (bits/char + per-token bits)
  - Sequential patterns (incrementing counters, embedded Unix epoch,
    UUIDv1 timestamp + clock_seq, base64 of monotonic data)
  - Token length (<16 chars = trivially guessable)
  - Session fixation (does the server honor an attacker-chosen cookie?)
  - Missing Secure / HttpOnly / SameSite flags

7 stages this scanner runs:

  1. PRE-FLIGHT  - target URL required; httpx HEAD/GET to / must
                   return any HTTP status. If TCP fails or no
                   response, skip cleanly.

  2. FINGERPRINT - GET target/login_url, parse Set-Cookie headers,
                   capture every cookie's attributes (Secure,
                   HttpOnly, SameSite, Domain, Path, Max-Age,
                   Expires). Detect framework from cookie names
                   (JSESSIONID -> Java, PHPSESSID -> PHP, etc).
                   Set primary_session_cookie = highest-entropy or
                   most-likely session cookie.

  3. QUICK PROBE - Capture sample_count (default 50, max 100) fresh
                   session cookies via httpx in parallel (sem=5,
                   100ms inter-request delay). Compute Shannon
                   entropy of each value. Check for sequential
                   patterns (incrementing tail, embedded epoch,
                   sequential UUIDv1, predictable base64). Flag
                   tokens shorter than 16 chars as predictable.

  4. DEEP SCAN   - Gated on quick_probe weak indicators OR
                   options.always_deep:
                     (a) Session fixation: set Cookie:
                         SESSIONID=ATTACKER_CHOSEN_VALUE; GET
                         target/login_url; if server keeps our
                         value -> session fixation VULNERABLE.
                     (b) Verify Secure / HttpOnly / SameSite flag
                         presence in the fingerprint cookies.
                     (c) For Java JSESSIONID, check whether the
                         last 16 chars are monotonic (Tomcat-style
                         sequential ID).
                     (d) Extended entropy: capture 200 more
                         samples (cap 250 total) and compute the
                         standard deviation; if < 0.5 -> sessions
                         are too uniform = predictable.

  5. VERIFY      - For low-entropy findings, re-capture 10 more
                   samples. If pattern persists -> CONFIRMED. For
                   session fixation, retry with a different
                   attacker-chosen value; still kept -> CONFIRMED.
                   For missing flags, attributes don't change
                   between requests -> CONFIRMED.

  6. PRIVILEGE   - Session findings map to:
                     session_predictable  - low entropy / sequential
                     session_fixation     - server honored our value
                     transport_weak       - missing Secure flag
                     xss_exposed          - missing HttpOnly
                     csrf_susceptible     - missing SameSite

  7. CHAIN       - CONFIRMED session fixation -> [post_exploit_session_takeover]
                   CONFIRMED low entropy      -> [post_exploit_session_brute]

Customer input via ScanRequest.options
--------------------------------------
  target           - base URL (REQUIRED)
  options.login_url    - path to fetch session cookie from
                          (default "/")
  options.cookie_name  - specific cookie name to focus on
                          (default: auto-detect highest-entropy)
  options.sample_count - fresh sessions to capture (default 50,
                          max 100)
  options.always_deep  - bool, run deep_scan unconditionally
  options.show_plaintext - bool, return raw cookie values instead of
                            redaction marker (default False)

Safety: total samples are hard-capped at 250 per scan (50 quick +
200 deep). Parallelism capped at 5 concurrent httpx requests.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import math
import re
import statistics
import time
import uuid
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext
from tools._methodology import MethodologyScanner

router = APIRouter()

# Hard caps to prevent runaway scans / target abuse
HARD_MAX_SAMPLES_TOTAL = 250
HARD_MAX_QUICK_SAMPLES = 100
DEEP_EXTRA_SAMPLES = 200
DEFAULT_QUICK_SAMPLES = 50
CONCURRENCY = 5
INTER_REQUEST_DELAY_MS = 100
HTTP_TIMEOUT_SECS = 10.0
VERIFY_RESAMPLE_COUNT = 10

# Framework detection from cookie names
FRAMEWORK_BY_COOKIE = {
    "jsessionid":       "Java (Servlet/Tomcat/JBoss)",
    "phpsessid":        "PHP",
    "asp.net_sessionid": "ASP.NET",
    "connect.sid":      "Express.js (Node)",
    "laravel_session":  "Laravel (PHP)",
    "_session_id":      "Ruby on Rails",
}

# Common cookie names that are session identifiers vs preference/ad cookies
SESSION_COOKIE_NAME_HINTS = {
    "jsessionid", "phpsessid", "asp.net_sessionid", "connect.sid",
    "laravel_session", "_session_id", "session", "sessionid",
    "sess", "sid", "auth", "token", "session_id",
}


class SessionPredictAuditRequest(ScanRequest):
    options: Optional[dict] = None


def _redact(cookie_value: str, show_plaintext: bool = False) -> str:
    """Customer-safe redaction for session cookie values.

    Default returns "len<N>_entropy<E>_hash<sha256_8>" so the customer
    report shows a stable, auditable marker without exposing a live
    session token in a multi-tenant report. show_plaintext=True
    (customer scanning own infra) returns the raw value so it can be
    pasted into a test client."""
    if not cookie_value:
        return "len0_entropy0_hash0"
    if show_plaintext:
        return cookie_value
    n = len(cookie_value)
    ent = round(_shannon_entropy(cookie_value), 2)
    digest = hashlib.sha256(cookie_value.encode("utf-8", errors="ignore")).hexdigest()[:8]
    return f"len{n}_entropy{ent}_hash{digest}"


# ════════════════════════════════════════════════════════════════════
#  Entropy + pattern detection primitives
# ════════════════════════════════════════════════════════════════════


def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/char. -sum(p_i * log2(p_i))."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    ent = 0.0
    for cnt in freq.values():
        p = cnt / n
        ent -= p * math.log2(p)
    return ent


def _detect_incrementing_tail(values: list[str], tail_len: int = 8) -> bool:
    """Return True if the last tail_len chars of each value parse as
    integers AND are monotonically increasing across the captured
    sample sequence."""
    if len(values) < 3:
        return False
    tails: list[int] = []
    for v in values:
        if len(v) < tail_len:
            return False
        tail = v[-tail_len:]
        # Try decimal first
        try:
            tails.append(int(tail, 10))
            continue
        except ValueError:
            pass
        # Try hex
        try:
            tails.append(int(tail, 16))
            continue
        except ValueError:
            return False
    # Check monotonic (strictly or weakly increasing)
    increasing = sum(1 for i in range(1, len(tails)) if tails[i] >= tails[i - 1])
    return increasing >= int(0.8 * (len(tails) - 1))


def _detect_embedded_epoch(values: list[str]) -> bool:
    """Return True if the leading 8-12 chars decode as a plausible
    Unix epoch (within +/- 7 days of now)."""
    now = int(time.time())
    window = 7 * 86400
    hits = 0
    for v in values:
        # Try hex prefix (8 chars = 32-bit timestamp)
        for prefix_len in (8, 10, 12):
            if len(v) < prefix_len:
                continue
            prefix = v[:prefix_len]
            try:
                candidate = int(prefix, 16)
                if abs(candidate - now) < window:
                    hits += 1
                    break
            except ValueError:
                pass
            try:
                candidate = int(prefix, 10)
                if abs(candidate - now) < window:
                    hits += 1
                    break
            except ValueError:
                pass
    return hits >= max(2, int(0.5 * len(values)))


def _detect_sequential_uuidv1(values: list[str]) -> bool:
    """Return True if values are UUIDv1s with timestamps that increase
    monotonically (UUIDv1 leaks MAC + clock_seq + 100ns timestamp)."""
    timestamps: list[int] = []
    for v in values:
        m = re.match(
            r"^([0-9a-f]{8})-([0-9a-f]{4})-1([0-9a-f]{3})-",
            v.lower(),
        )
        if not m:
            return False
        try:
            time_low = int(m.group(1), 16)
            time_mid = int(m.group(2), 16)
            time_hi = int(m.group(3), 16)
            ts = (time_hi << 48) | (time_mid << 32) | time_low
            timestamps.append(ts)
        except ValueError:
            return False
    if len(timestamps) < 3:
        return False
    increasing = sum(1 for i in range(1, len(timestamps))
                      if timestamps[i] >= timestamps[i - 1])
    return increasing >= int(0.8 * (len(timestamps) - 1))


def _detect_sequential_base64(values: list[str]) -> bool:
    """Return True if base64-decoded payloads contain monotonically
    increasing integers (predictable counter encoded as base64)."""
    decoded_ints: list[int] = []
    for v in values:
        try:
            padded = v + "=" * (-len(v) % 4)
            raw = base64.urlsafe_b64decode(padded)
        except Exception:
            try:
                padded = v + "=" * (-len(v) % 4)
                raw = base64.b64decode(padded)
            except Exception:
                return False
        if len(raw) < 4:
            return False
        candidate = int.from_bytes(raw[:4], "big")
        decoded_ints.append(candidate)
    if len(decoded_ints) < 3:
        return False
    increasing = sum(1 for i in range(1, len(decoded_ints))
                      if decoded_ints[i] >= decoded_ints[i - 1])
    return increasing >= int(0.8 * (len(decoded_ints) - 1))


# ════════════════════════════════════════════════════════════════════
#  Cookie parsing helpers
# ════════════════════════════════════════════════════════════════════


def _parse_set_cookie_header(set_cookie_lines: list[str]) -> list[dict]:
    """Parse one or more Set-Cookie header values into structured dicts.

    Returns list of {name, value, secure, http_only, same_site, domain,
    path, max_age, expires, raw}."""
    parsed: list[dict] = []
    for line in set_cookie_lines:
        if not line:
            continue
        parts = [p.strip() for p in line.split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name, _, value = parts[0].partition("=")
        cookie = {
            "name": name.strip(),
            "value": value.strip(),
            "secure": False,
            "http_only": False,
            "same_site": "",
            "domain": "",
            "path": "",
            "max_age": "",
            "expires": "",
            "raw": line[:300],
        }
        for attr in parts[1:]:
            low = attr.lower().strip()
            if low == "secure":
                cookie["secure"] = True
            elif low == "httponly":
                cookie["http_only"] = True
            elif low.startswith("samesite="):
                cookie["same_site"] = attr.split("=", 1)[1].strip()
            elif low.startswith("domain="):
                cookie["domain"] = attr.split("=", 1)[1].strip()
            elif low.startswith("path="):
                cookie["path"] = attr.split("=", 1)[1].strip()
            elif low.startswith("max-age="):
                cookie["max_age"] = attr.split("=", 1)[1].strip()
            elif low.startswith("expires="):
                cookie["expires"] = attr.split("=", 1)[1].strip()
        parsed.append(cookie)
    return parsed


def _detect_framework(cookies: list[dict]) -> str:
    """Identify backend framework from cookie names."""
    for c in cookies:
        name = (c.get("name") or "").lower()
        if name in FRAMEWORK_BY_COOKIE:
            return FRAMEWORK_BY_COOKIE[name]
    return "unknown"


def _pick_primary_session_cookie(cookies: list[dict],
                                   forced_name: str = "") -> str:
    """Pick the most-likely session cookie. Prefer:
      1. Explicit forced_name option.
      2. Known framework session cookie name.
      3. Highest-entropy cookie value (likely a random session ID).
      4. First cookie if all else fails."""
    if not cookies:
        return ""
    if forced_name:
        for c in cookies:
            if c.get("name", "").lower() == forced_name.lower():
                return c["name"]
    for c in cookies:
        name = (c.get("name") or "").lower()
        if name in FRAMEWORK_BY_COOKIE:
            return c["name"]
    for c in cookies:
        name = (c.get("name") or "").lower()
        if name in SESSION_COOKIE_NAME_HINTS:
            return c["name"]
    # Fall back to highest-entropy value
    best_cookie = cookies[0]
    best_ent = _shannon_entropy(cookies[0].get("value", ""))
    for c in cookies[1:]:
        ent = _shannon_entropy(c.get("value", ""))
        if ent > best_ent:
            best_ent = ent
            best_cookie = c
    return best_cookie.get("name", "")


# ════════════════════════════════════════════════════════════════════
#  HTTP capture primitives (httpx async with semaphore)
# ════════════════════════════════════════════════════════════════════


async def _http_probe(url: str) -> tuple[bool, int, dict]:
    """Single httpx GET. Returns (reachable, status_code, headers_dict)."""
    try:
        import httpx
    except ImportError:
        return (False, 0, {})
    try:
        async with httpx.AsyncClient(
            timeout=HTTP_TIMEOUT_SECS,
            follow_redirects=False,
            verify=False,
        ) as client:
            r = await client.get(url)
            return (True, r.status_code, dict(r.headers))
    except Exception:
        return (False, 0, {})


async def _capture_one_session(url: str,
                                primary_cookie_name: str,
                                sem: asyncio.Semaphore) -> str:
    """Capture a single fresh session via httpx. Returns the value of
    primary_cookie_name from Set-Cookie, or "" on failure."""
    try:
        import httpx
    except ImportError:
        return ""
    async with sem:
        await asyncio.sleep(INTER_REQUEST_DELAY_MS / 1000.0)
        try:
            async with httpx.AsyncClient(
                timeout=HTTP_TIMEOUT_SECS,
                follow_redirects=False,
                verify=False,
            ) as client:
                r = await client.get(url)
                # Combine multi-valued Set-Cookie headers
                set_cookies = r.headers.get_list("set-cookie") if hasattr(
                    r.headers, "get_list") else [r.headers.get("set-cookie", "")]
                parsed = _parse_set_cookie_header(set_cookies)
                for c in parsed:
                    if c.get("name", "").lower() == primary_cookie_name.lower():
                        return c.get("value", "")
                return ""
        except Exception:
            return ""


async def _capture_n_sessions(url: str,
                               primary_cookie_name: str,
                               n: int) -> list[str]:
    """Capture n fresh session values in parallel (sem=CONCURRENCY)."""
    if n <= 0 or not primary_cookie_name:
        return []
    sem = asyncio.Semaphore(CONCURRENCY)
    coros = [_capture_one_session(url, primary_cookie_name, sem)
             for _ in range(n)]
    results = await asyncio.gather(*coros, return_exceptions=False)
    return [v for v in results if v]


async def _test_session_fixation(url: str,
                                   primary_cookie_name: str,
                                   attacker_value: str) -> tuple[bool, str]:
    """Set an attacker-chosen cookie and see whether the server
    honors it or rotates to a fresh ID. Returns (kept, server_value)."""
    try:
        import httpx
    except ImportError:
        return (False, "")
    try:
        async with httpx.AsyncClient(
            timeout=HTTP_TIMEOUT_SECS,
            follow_redirects=False,
            verify=False,
        ) as client:
            cookies = {primary_cookie_name: attacker_value}
            r = await client.get(url, cookies=cookies)
            # If server doesn't return Set-Cookie, our value was kept
            set_cookies = r.headers.get_list("set-cookie") if hasattr(
                r.headers, "get_list") else [r.headers.get("set-cookie", "")]
            parsed = _parse_set_cookie_header(set_cookies)
            for c in parsed:
                if c.get("name", "").lower() == primary_cookie_name.lower():
                    new_val = c.get("value", "")
                    if new_val and new_val != attacker_value:
                        return (False, new_val)
            # No fresh value returned -> server accepted attacker value
            return (True, attacker_value)
    except Exception:
        return (False, "")


def _build_login_url(target: str, login_url: str) -> str:
    """Combine target base URL + login_url path safely."""
    base = (target or "").strip()
    path = (login_url or "/").strip()
    if not base:
        return ""
    if "://" not in base:
        base = "http://" + base
    base = base.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return base + path


# ════════════════════════════════════════════════════════════════════
#  SessionPredictAudit - the VL-METHOD scanner class
# ════════════════════════════════════════════════════════════════════


class SessionPredictAudit(MethodologyScanner):
    name = "session_predict_audit"

    # ── STAGE 1: PRE-FLIGHT ──────────────────────────────────────
    async def pre_flight(self, ctx: ScanContext) -> bool:
        target = (ctx.host or "").strip()
        opts = ctx.state.get("_options") or {}
        if not target:
            ctx.state["skipped_reason"] = "requires target URL"
            return False
        login_url = (opts.get("login_url") or "/").strip()
        # Normalize target to a full URL if scheme missing
        if "://" not in target:
            target = "http://" + target
        full_url = _build_login_url(target, login_url)
        reachable, status, headers = await _http_probe(full_url)
        if not reachable:
            ctx.state["skipped_reason"] = "target HTTP not reachable"
            return False
        # Accept any 2xx/3xx/4xx; 5xx still means server alive
        if status < 200 or status >= 600:
            ctx.state["skipped_reason"] = "target HTTP not reachable"
            return False
        ctx.state["target_base"] = target
        ctx.state["login_url"] = full_url
        ctx.state["preflight_status"] = status
        return True

    # ── STAGE 2: FINGERPRINT ─────────────────────────────────────
    async def fingerprint(self, ctx: ScanContext):
        full_url = ctx.state.get("login_url") or ""
        opts = ctx.state.get("_options") or {}
        try:
            import httpx
        except ImportError:
            ctx.state["fingerprint"] = {"error": "httpx not installed"}
            return
        try:
            async with httpx.AsyncClient(
                timeout=HTTP_TIMEOUT_SECS,
                follow_redirects=False,
                verify=False,
            ) as client:
                r = await client.get(full_url)
                set_cookies = r.headers.get_list("set-cookie") if hasattr(
                    r.headers, "get_list") else [r.headers.get("set-cookie", "")]
                cookies = _parse_set_cookie_header(set_cookies)
                framework = _detect_framework(cookies)
                forced_name = (opts.get("cookie_name") or "").strip()
                primary = _pick_primary_session_cookie(cookies, forced_name)
                # Strip raw cookie values from fingerprint dict before
                # exposing to PDF; keep attributes only.
                safe_cookies = []
                show = bool(opts.get("show_plaintext"))
                for c in cookies:
                    safe_cookies.append({
                        "name": c.get("name", ""),
                        "value_marker": _redact(c.get("value", ""), show_plaintext=show),
                        "secure": c.get("secure", False),
                        "http_only": c.get("http_only", False),
                        "same_site": c.get("same_site", ""),
                        "domain": c.get("domain", ""),
                        "path": c.get("path", ""),
                        "max_age": c.get("max_age", ""),
                        "expires": c.get("expires", ""),
                    })
                ctx.state["fingerprint"] = {
                    "framework": framework,
                    "cookies": safe_cookies,
                    "status_code": r.status_code,
                    "server_header": r.headers.get("server", ""),
                }
                ctx.state["primary_session_cookie"] = primary
                # Stash the raw cookies (with values) privately so deep_scan
                # can re-check flag presence without re-fetching.
                ctx.state["_raw_cookies_private"] = cookies
        except Exception as e:
            ctx.state["fingerprint"] = {
                "error": f"{type(e).__name__}: {str(e)[:160]}"}

    # ── STAGE 3: QUICK PROBE (sample fresh sessions + entropy) ───
    async def quick_probe(self, ctx: ScanContext) -> list[dict]:
        opts = ctx.state.get("_options") or {}
        primary = ctx.state.get("primary_session_cookie") or ""
        full_url = ctx.state.get("login_url") or ""
        show = bool(opts.get("show_plaintext"))
        if not primary or not full_url:
            ctx.state["session_samples_count"] = 0
            ctx.state["avg_entropy"] = 0.0
            ctx.state["min_entropy"] = 0.0
            ctx.state["max_entropy"] = 0.0
            ctx.state["quick_probe_attempts"] = 0
            ctx.state["quick_probe_hits"] = 0
            return []

        try:
            sample_count = int(opts.get("sample_count") or DEFAULT_QUICK_SAMPLES)
        except (TypeError, ValueError):
            sample_count = DEFAULT_QUICK_SAMPLES
        sample_count = max(5, min(sample_count, HARD_MAX_QUICK_SAMPLES))

        values = await _capture_n_sessions(full_url, primary, sample_count)
        # Include the fingerprint cookie's own value as a sample too
        for c in (ctx.state.get("_raw_cookies_private") or []):
            if c.get("name", "").lower() == primary.lower():
                fp_val = c.get("value", "")
                if fp_val and fp_val not in values:
                    values.insert(0, fp_val)
                break

        if not values:
            ctx.state["session_samples_count"] = 0
            ctx.state["avg_entropy"] = 0.0
            ctx.state["min_entropy"] = 0.0
            ctx.state["max_entropy"] = 0.0
            ctx.state["quick_probe_attempts"] = sample_count
            ctx.state["quick_probe_hits"] = 0
            return []

        entropies = [_shannon_entropy(v) for v in values]
        avg_ent = sum(entropies) / len(entropies)
        min_ent = min(entropies)
        max_ent = max(entropies)

        ctx.state["session_samples_count"] = len(values)
        ctx.state["avg_entropy"] = round(avg_ent, 3)
        ctx.state["min_entropy"] = round(min_ent, 3)
        ctx.state["max_entropy"] = round(max_ent, 3)
        ctx.state["_session_values_private"] = values
        ctx.state["quick_probe_attempts"] = sample_count

        findings: list[dict] = []
        # Sample one representative cookie value for the finding (first
        # captured). Redaction handled centrally.
        sample_value = values[0]

        # 3a. Weak entropy (avg < 4.0 bits/char)
        if avg_ent < 4.0:
            findings.append({
                "id": "weak_entropy_quick",
                "kind": "low_entropy_session",
                "cookie_name": primary,
                "cookie_marker": _redact(sample_value, show_plaintext=show),
                "avg_entropy": round(avg_ent, 3),
                "sample_count": len(values),
                "discovery_method": "shannon_entropy_quick_probe",
                "_value_private": sample_value,
            })

        # 3b. Sequential patterns
        if _detect_incrementing_tail(values):
            findings.append({
                "id": "sequential_tail",
                "kind": "sequential_session_id",
                "cookie_name": primary,
                "cookie_marker": _redact(sample_value, show_plaintext=show),
                "pattern": "incrementing_integer_tail_last_8_chars",
                "discovery_method": "tail_monotonic_check",
                "_value_private": sample_value,
            })
        if _detect_embedded_epoch(values):
            findings.append({
                "id": "embedded_epoch",
                "kind": "sequential_session_id",
                "cookie_name": primary,
                "cookie_marker": _redact(sample_value, show_plaintext=show),
                "pattern": "embedded_unix_epoch_in_prefix",
                "discovery_method": "epoch_prefix_decode",
                "_value_private": sample_value,
            })
        if _detect_sequential_uuidv1(values):
            findings.append({
                "id": "sequential_uuidv1",
                "kind": "sequential_session_id",
                "cookie_name": primary,
                "cookie_marker": _redact(sample_value, show_plaintext=show),
                "pattern": "sequential_uuid_v1_timestamp_clockseq",
                "discovery_method": "uuid_v1_timestamp_decode",
                "_value_private": sample_value,
            })
        if _detect_sequential_base64(values):
            findings.append({
                "id": "sequential_base64",
                "kind": "sequential_session_id",
                "cookie_name": primary,
                "cookie_marker": _redact(sample_value, show_plaintext=show),
                "pattern": "predictable_counter_in_base64_payload",
                "discovery_method": "base64_decode_monotonic_check",
                "_value_private": sample_value,
            })

        # 3c. Short token length
        avg_len = sum(len(v) for v in values) / len(values)
        if avg_len < 16:
            findings.append({
                "id": "short_token",
                "kind": "short_session_id",
                "cookie_name": primary,
                "cookie_marker": _redact(sample_value, show_plaintext=show),
                "avg_length": round(avg_len, 1),
                "discovery_method": "token_length_check",
                "_value_private": sample_value,
            })

        ctx.state["quick_probe_hits"] = len(findings)
        return findings

    # ── STAGE 4: DEEP SCAN (fixation + flag check + extended) ────
    async def deep_scan(self, ctx: ScanContext) -> list[dict]:
        opts = ctx.state.get("_options") or {}
        primary = ctx.state.get("primary_session_cookie") or ""
        full_url = ctx.state.get("login_url") or ""
        show = bool(opts.get("show_plaintext"))
        if not primary or not full_url:
            return []

        findings: list[dict] = []

        # 4a. Session fixation test
        attacker_value = "VL_FIXATION_TEST_" + uuid.uuid4().hex[:16]
        kept, server_val = await _test_session_fixation(
            full_url, primary, attacker_value)
        ctx.state["_fixation_attacker_value_private"] = attacker_value
        ctx.state["_fixation_kept_initial"] = kept
        if kept:
            findings.append({
                "id": "session_fixation",
                "kind": "session_fixation",
                "cookie_name": primary,
                "attacker_value_marker": _redact(attacker_value, show_plaintext=show),
                "server_kept_value": True,
                "discovery_method": "manual_cookie_injection",
                "_value_private": attacker_value,
            })

        # 4b. Cookie attribute / flag checks
        raw_cookies = ctx.state.get("_raw_cookies_private") or []
        primary_cookie_dict = None
        for c in raw_cookies:
            if c.get("name", "").lower() == primary.lower():
                primary_cookie_dict = c
                break
        if primary_cookie_dict:
            if not primary_cookie_dict.get("secure"):
                findings.append({
                    "id": "missing_secure",
                    "kind": "missing_secure_flag",
                    "cookie_name": primary,
                    "cookie_marker": _redact(
                        primary_cookie_dict.get("value", ""),
                        show_plaintext=show),
                    "discovery_method": "set_cookie_attribute_inspection",
                })
            if not primary_cookie_dict.get("http_only"):
                findings.append({
                    "id": "missing_httponly",
                    "kind": "missing_httponly_flag",
                    "cookie_name": primary,
                    "cookie_marker": _redact(
                        primary_cookie_dict.get("value", ""),
                        show_plaintext=show),
                    "discovery_method": "set_cookie_attribute_inspection",
                })
            if not primary_cookie_dict.get("same_site"):
                findings.append({
                    "id": "missing_samesite",
                    "kind": "missing_samesite_flag",
                    "cookie_name": primary,
                    "cookie_marker": _redact(
                        primary_cookie_dict.get("value", ""),
                        show_plaintext=show),
                    "discovery_method": "set_cookie_attribute_inspection",
                })

        # 4c. Java JSESSIONID monotonic tail check
        if primary.lower() == "jsessionid":
            values = ctx.state.get("_session_values_private") or []
            if values and _detect_incrementing_tail(values, tail_len=16):
                findings.append({
                    "id": "jsessionid_monotonic",
                    "kind": "sequential_session_id",
                    "cookie_name": primary,
                    "cookie_marker": _redact(values[0], show_plaintext=show),
                    "pattern": "tomcat_style_monotonic_last_16_chars",
                    "discovery_method": "jsessionid_tail_monotonic_check",
                    "_value_private": values[0],
                })

        # 4d. Extended entropy: capture 200 more samples (cap total 250)
        existing = ctx.state.get("_session_values_private") or []
        room = HARD_MAX_SAMPLES_TOTAL - len(existing)
        extra_target = min(DEEP_EXTRA_SAMPLES, room)
        if extra_target > 0:
            extra = await _capture_n_sessions(full_url, primary, extra_target)
            all_values = existing + extra
            ctx.state["_session_values_private"] = all_values
            if len(all_values) >= 5:
                entropies = [_shannon_entropy(v) for v in all_values]
                try:
                    stdev = statistics.stdev(entropies)
                except statistics.StatisticsError:
                    stdev = 0.0
                ctx.state["extended_samples_count"] = len(all_values)
                ctx.state["extended_entropy_stdev"] = round(stdev, 3)
                # Recompute avg/min/max with extended set
                avg_ent = sum(entropies) / len(entropies)
                ctx.state["avg_entropy"] = round(avg_ent, 3)
                ctx.state["min_entropy"] = round(min(entropies), 3)
                ctx.state["max_entropy"] = round(max(entropies), 3)
                ctx.state["session_samples_count"] = len(all_values)
                if stdev < 0.5:
                    findings.append({
                        "id": "uniform_entropy",
                        "kind": "low_entropy_session",
                        "cookie_name": primary,
                        "cookie_marker": _redact(
                            all_values[0], show_plaintext=show),
                        "stdev": round(stdev, 3),
                        "sample_count": len(all_values),
                        "discovery_method": "extended_entropy_stdev_check",
                        "_value_private": all_values[0],
                    })

        return findings

    # ── STAGE 5: VERIFY ──────────────────────────────────────────
    async def verify(self, ctx: ScanContext, finding: dict) -> Optional[dict]:
        # VL-FOUNDRY evidence surfacing: stamp a concrete, per-finding
        # evidence string onto the methodology finding object. This rides
        # into the report via the methodology_findings intel field; it adds
        # no new finding and changes no severity (advisory-by-design safe).
        finding["evidence_marker"] = (
            f"{finding.get('discovery_method') or finding.get('kind') or 'probe'}"
            f" -> verifying {finding.get('kind') or 'finding'} for "
            f"{finding.get('user') or finding.get('attack_label') or ctx.host}")
        kind = finding.get("kind", "")
        opts = ctx.state.get("_options") or {}
        primary = ctx.state.get("primary_session_cookie") or ""
        full_url = ctx.state.get("login_url") or ""

        # Missing-flag findings: attributes don't change across requests
        # so a one-shot inspection IS the verification.
        if kind in ("missing_secure_flag",
                    "missing_httponly_flag",
                    "missing_samesite_flag"):
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "set_cookie_header_inspection"
            return finding

        # Low-entropy: re-capture 10 more samples to confirm pattern.
        if kind == "low_entropy_session":
            if not primary or not full_url:
                finding["confidence"] = "SUSPECTED"
                finding["verification_method"] = "no_target_for_resampling"
                return finding
            extra = await _capture_n_sessions(
                full_url, primary, VERIFY_RESAMPLE_COUNT)
            if not extra:
                finding["confidence"] = "SUSPECTED"
                finding["verification_method"] = "resample_capture_failed"
                return finding
            entropies = [_shannon_entropy(v) for v in extra]
            avg = sum(entropies) / len(entropies)
            if avg < 4.0:
                finding["confidence"] = "CONFIRMED"
                finding["verification_method"] = "entropy_resampling_persisted"
                finding["resample_avg_entropy"] = round(avg, 3)
            else:
                finding["confidence"] = "SUSPECTED"
                finding["verification_method"] = "entropy_resampling_did_not_reproduce"
                finding["resample_avg_entropy"] = round(avg, 3)
            return finding

        # Sequential pattern: re-capture 10 more, re-run the matching detector.
        if kind == "sequential_session_id":
            if not primary or not full_url:
                finding["confidence"] = "SUSPECTED"
                finding["verification_method"] = "no_target_for_resampling"
                return finding
            extra = await _capture_n_sessions(
                full_url, primary, VERIFY_RESAMPLE_COUNT)
            if not extra:
                finding["confidence"] = "SUSPECTED"
                finding["verification_method"] = "resample_capture_failed"
                return finding
            pattern = finding.get("pattern", "")
            persisted = False
            if pattern == "incrementing_integer_tail_last_8_chars":
                persisted = _detect_incrementing_tail(extra)
            elif pattern == "tomcat_style_monotonic_last_16_chars":
                persisted = _detect_incrementing_tail(extra, tail_len=16)
            elif pattern == "embedded_unix_epoch_in_prefix":
                persisted = _detect_embedded_epoch(extra)
            elif pattern == "sequential_uuid_v1_timestamp_clockseq":
                persisted = _detect_sequential_uuidv1(extra)
            elif pattern == "predictable_counter_in_base64_payload":
                persisted = _detect_sequential_base64(extra)
            if persisted:
                finding["confidence"] = "CONFIRMED"
                finding["verification_method"] = "entropy_resampling_persisted"
            else:
                finding["confidence"] = "SUSPECTED"
                finding["verification_method"] = "pattern_did_not_reproduce_on_resample"
            return finding

        # Short token: re-capture + recheck length.
        if kind == "short_session_id":
            if not primary or not full_url:
                finding["confidence"] = "SUSPECTED"
                finding["verification_method"] = "no_target_for_resampling"
                return finding
            extra = await _capture_n_sessions(
                full_url, primary, VERIFY_RESAMPLE_COUNT)
            if not extra:
                finding["confidence"] = "SUSPECTED"
                finding["verification_method"] = "resample_capture_failed"
                return finding
            avg_len = sum(len(v) for v in extra) / len(extra)
            if avg_len < 16:
                finding["confidence"] = "CONFIRMED"
                finding["verification_method"] = "entropy_resampling_persisted"
                finding["resample_avg_length"] = round(avg_len, 1)
            else:
                finding["confidence"] = "SUSPECTED"
                finding["verification_method"] = "length_did_not_reproduce"
                finding["resample_avg_length"] = round(avg_len, 1)
            return finding

        # Session fixation: retry with a different attacker-chosen value.
        if kind == "session_fixation":
            if not primary or not full_url:
                finding["confidence"] = "SUSPECTED"
                finding["verification_method"] = "no_target_for_retest"
                return finding
            new_attacker = "VL_FIXATION_RETEST_" + uuid.uuid4().hex[:16]
            kept, _ = await _test_session_fixation(
                full_url, primary, new_attacker)
            if kept:
                finding["confidence"] = "CONFIRMED"
                finding["verification_method"] = "session_fixation_retest_confirmed"
            else:
                finding["confidence"] = "SUSPECTED"
                finding["verification_method"] = "session_fixation_retest_failed"
            return finding

        # Unknown kind - mark suspected
        finding["confidence"] = "SUSPECTED"
        finding["verification_method"] = "no_verifier_registered_for_kind"
        return finding

    # ── STAGE 6: PRIVILEGE CHECK ─────────────────────────────────
    async def privilege_check(self, ctx: ScanContext, finding: dict) -> dict:
        kind = finding.get("kind", "")
        if kind == "session_fixation":
            finding["privilege"] = "session_fixation"
        elif kind == "missing_secure_flag":
            finding["privilege"] = "transport_weak"
        elif kind == "missing_httponly_flag":
            finding["privilege"] = "xss_exposed"
        elif kind == "missing_samesite_flag":
            finding["privilege"] = "csrf_susceptible"
        else:
            # low_entropy_session, sequential_session_id, short_session_id
            finding["privilege"] = "session_predictable"
        return finding

    # ── STAGE 7: CHAIN HANDOFF ───────────────────────────────────
    async def chain_handoff(self, ctx: ScanContext,
                              findings: list[dict]) -> list[str]:
        next_scanners: list[str] = []
        for f in findings:
            if f.get("confidence") != "CONFIRMED":
                continue
            kind = f.get("kind", "")
            if kind == "session_fixation":
                if "post_exploit_session_takeover" not in next_scanners:
                    next_scanners.append("post_exploit_session_takeover")
                f["chain_next"] = ["post_exploit_session_takeover"]
            elif kind in ("low_entropy_session",
                          "sequential_session_id",
                          "short_session_id"):
                if "post_exploit_session_brute" not in next_scanners:
                    next_scanners.append("post_exploit_session_brute")
                f["chain_next"] = ["post_exploit_session_brute"]
        return next_scanners


# ════════════════════════════════════════════════════════════════════
#  Endpoint wrapper
# ════════════════════════════════════════════════════════════════════


from tools._payloads.session_predict_audit_findings import (
    SESSION_PREDICT_AUDIT_FINDING_RULES,
    INTEL_FIELDS,
)


@router.post("/api/password/session_predict_audit")
async def password_session_predict_audit(
        req: SessionPredictAuditRequest,
        _=Depends(verify_scan_quota)):
    scanner = SessionPredictAudit()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=SESSION_PREDICT_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


def register(app):
    app.include_router(router)


# ════════════════════════════════════════════════════════════════════
#  Chain registry registration - downstream session-takeover / session-
#  brute scanners trigger us via _chain_callable.
# ════════════════════════════════════════════════════════════════════


async def _chain_callable(target: str, options: dict, jwt_token=None) -> dict:
    opts = options or {}
    req = SessionPredictAuditRequest(target=target, options=opts)
    scanner = SessionPredictAudit()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=SESSION_PREDICT_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


from tools._methodology import chain_registry
chain_registry.register("session_predict_audit", _chain_callable)

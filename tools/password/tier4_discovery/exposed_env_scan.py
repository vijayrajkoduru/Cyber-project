"""exposed_env_scan - HTTP-accessible credential / config file discovery
(VL-METHOD methodology).

Passive discovery scanner for secrets that are PUBLICLY SERVED over HTTP
because someone forgot to block dot-files / config files at the web layer.
Walks a curated list of high-yield paths (.env, .git/config, .htpasswd,
wp-config.php, credentials.json, .aws/credentials, *.sql, ...) and parses
returned content for AWS keys / DB connection strings / JWT secrets /
SSH private keys / generic password assignments.

The 7 stages this scanner performs:

  1. PRE-FLIGHT  - Is target a URL we can reach? Probe `/` once; if no HTTP
                    response, skip.
  2. FINGERPRINT - Server header + X-Powered-By + body markers (Laravel,
                    Rails, Django, Express, WordPress). Drives expectations
                    on which leak files matter most.
  3. QUICK PROBE - Top-8 most-leaked paths in parallel (sem=4): /.env,
                    /.git/config, /.htpasswd, /wp-config.php,
                    /credentials.json, /config.php, /.aws/credentials,
                    /backup.sql. Sub-2-second triage.
  4. DEEP SCAN   - Gated on quick_probe hits OR options.always_deep.
                    Walks the full CRITICAL_PATHS list + customer-supplied
                    options.paths. Parses each 200 response for secrets.
                    Hard limits: 50 paths max, 200 secret-matches max.
  5. VERIFY      - Re-fetch each found path with a NEW httpx request;
                    confirms same content-length (stable, not flapping
                    redirect/error). Structurally validates the captured
                    secret (AWS = AKIA + 16 chars, JWT >= 16 chars, DB
                    URL = scheme://user:pass@host/db). CONFIRMED on both
                    passes; SUSPECTED if structure fails.
  6. PRIVILEGE   - Classify by secret type:
                    aws_credentials      -> cloud_root
                    db_connection_string -> database_owner
                    jwt_secret           -> auth_bypass_capable
                    ssh_private_key      -> key_material
                    generic_password     -> credential
  7. CHAIN       - For CONFIRMED aws -> ['post_exploit_aws_iam_audit'].
                    For CONFIRMED db  -> ['mysql_brute','postgres_brute'].
                    For CONFIRMED jwt -> ['jwt_forge_audit']. Empty
                    otherwise.

Customer input via ScanRequest.options:
  - target              = base URL (required - taken from req.target)
  - options.paths       = optional list of additional paths
  - options.timeout     = per-request timeout seconds (default 5)
  - options.always_deep = bool, force full deep_scan path list

Safety guards:
  - Hard max 4 concurrent HTTP requests
  - 100ms inter-path delay to avoid WAF / rate limiter
  - 50-path cap on deep_scan, 200-match cap on parsed secrets
  - 404 detection (skip <title>404</title> bodies + status=404)
"""
from __future__ import annotations

import asyncio
import hashlib
import re
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext
from tools._methodology import MethodologyScanner, helpers
from tools._payloads.exposed_env_scan_findings import (
    EXPOSED_ENV_SCAN_FINDING_RULES,
    INTEL_FIELDS,
)

router = APIRouter()

DEFAULT_TIMEOUT = 5
HARD_MAX_PATHS = 50
HARD_MAX_MATCHES = 200
MAX_CONCURRENCY = 4
INTER_PROBE_DELAY = 0.10  # seconds between path probes


# Top-8 highest-yield paths probed in QUICK_PROBE stage (sub-2-sec triage).
QUICK_PROBE_PATHS = [
    "/.env",
    "/.git/config",
    "/.htpasswd",
    "/wp-config.php",
    "/credentials.json",
    "/config.php",
    "/.aws/credentials",
    "/backup.sql",
]


# Full critical leak surface walked in DEEP_SCAN. Customer can append
# more via options.paths.
CRITICAL_PATHS = [
    "/.env", "/.env.local", "/.env.production",
    "/.htpasswd", "/.htaccess",
    "/.git/config", "/.git/HEAD",
    "/credentials.json", "/credentials.yml", "/credentials.yaml",
    "/secrets.json", "/secrets.yml", "/secrets.yaml",
    "/config.json", "/config.php", "/config.yml",
    "/.aws/credentials", "/.aws/config",
    "/database.yml", "/db.yml",
    "/wp-config.php", "/wp-config.bak",
    "/web.config", "/web.config.bak",
    "/.DS_Store",
    "/backup.sql", "/dump.sql",
    "/composer.json", "/composer.lock",  # leaks tech stack
    "/package.json",                      # leaks tech stack
]


# Secret-extraction regexes. Each match becomes a separate finding.
RE_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
RE_DB_URL = re.compile(
    r"(?P<scheme>mysql|postgres|postgresql|mongodb)://"
    r"(?P<user>[^:\s@/]+):(?P<pwd>[^@\s/]+)@(?P<host>[^/\s]+)/(?P<db>[^\s\"'?]+)",
    re.IGNORECASE,
)
RE_GENERIC = re.compile(
    r"(?P<key>password|passwd|secret|api[_-]?key|token|access[_-]?key)"
    r"\s*[:=]\s*[\"']?(?P<val>[^\"'\s\n]{8,})",
    re.IGNORECASE,
)
RE_JWT = re.compile(
    r"jwt[_-]?secret\s*[:=]\s*[\"']?(?P<val>[^\"'\s\n]+)",
    re.IGNORECASE,
)
RE_SSH_KEY = re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----")

# Common 404 markers (servers vary)
RE_404_MARKERS = re.compile(
    r"<title>\s*404[^<]*</title>|not\s+found|page\s+not\s+found",
    re.IGNORECASE,
)


class ExposedEnvScanRequest(ScanRequest):
    options: Optional[dict] = None


def _redact(secret: str, show_plaintext: bool = False) -> str:
    """Customer-safe redaction. Format: TYPE_LEN_HASH.
    e.g. 'STR_len=42_sha8=a1b2c3d4'. When show_plaintext=True (customer
    scanning own infra), returns the actual plaintext instead.
    """
    if secret is None:
        return "STR_len=0"
    s = str(secret).strip()
    if show_plaintext:
        return s
    if not s:
        return "STR_len=0"
    h8 = hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()[:8]
    return f"STR_len={len(s)}_sha8={h8}"


def _normalize_url(target: str) -> str:
    """Return scheme://host[:port] (no trailing slash, no path).

    Drop port suffix when it's a non-HTTP port (e.g. example.com:22 became
    https://example.com:22 which is nonsense for a web probe). Keep the
    port only when it's one of the known web/api ports."""
    if not target:
        return ""
    t = target.strip()
    if "://" not in t:
        t = "https://" + t
    p = urlparse(t)
    scheme = (p.scheme or "https").lower()
    netloc = p.netloc or p.path.split("/", 1)[0]
    if not netloc:
        return ""
    # Strip non-web port suffixes so we don't probe https://host:22/
    WEB_PORTS = {80, 443, 8080, 8443, 8000, 8001, 8888, 3000, 5000, 9000, 9090}
    if ":" in netloc:
        host, _, port_str = netloc.rpartition(":")
        try:
            port_int = int(port_str)
            if port_int not in WEB_PORTS:
                # Drop the suffix - let the scheme default (80/443) handle it
                netloc = host
        except (ValueError, TypeError):
            pass
    return f"{scheme}://{netloc}"


def _is_404_body(body: str, status: int) -> bool:
    if status == 404:
        return True
    if not body:
        return True
    snippet = body[:2048]
    return bool(RE_404_MARKERS.search(snippet))


def _detect_framework(headers: dict, body: str) -> str:
    """Best-effort framework fingerprint from headers + body markers."""
    h = {(k or "").lower(): (v or "") for k, v in (headers or {}).items()}
    powered = h.get("x-powered-by", "").lower()
    server = h.get("server", "").lower()
    b = (body or "")[:4096].lower()
    if "laravel_session" in b or "laravel" in powered:
        return "Laravel"
    if "csrf-param" in b and "rails" in b:
        return "Rails"
    if "csrftoken" in b or "django" in b or "django" in powered:
        return "Django"
    if "express" in powered:
        return "Express"
    if "wp-content" in b or "wordpress" in b or "wp-includes" in b:
        return "WordPress"
    if "next-route-announcer" in b or "__next_data__" in b:
        return "Next.js"
    if "nginx" in server:
        return "nginx-app"
    return ""


def _extract_secrets(path: str, body: str, status: int, show_plaintext: bool) -> list[dict]:
    """Run all secret regexes against body; return list of preliminary
    findings (one per match). Each has match_type + redacted_value +
    file_path + http_status + file_size."""
    out: list[dict] = []
    if not body:
        return out
    size = len(body)
    # SSH private key (boolean - one finding per file is enough)
    if RE_SSH_KEY.search(body):
        out.append({
            "match_type": "ssh_private_key",
            "file_path": path,
            "redacted_value": "-----BEGIN PRIVATE KEY----- (block present)",
            "raw_for_verify": "-----BEGIN PRIVATE KEY-----",
            "file_size": size,
            "http_status": status,
        })
    # AWS access keys
    for m in RE_AWS_KEY.finditer(body):
        akia = m.group(0)
        out.append({
            "match_type": "aws_credentials",
            "file_path": path,
            "redacted_value": _redact(akia, show_plaintext=show_plaintext),
            "raw_for_verify": akia,
            "file_size": size,
            "http_status": status,
        })
    # DB connection strings
    for m in RE_DB_URL.finditer(body):
        url = m.group(0)
        out.append({
            "match_type": "db_connection_string",
            "file_path": path,
            "redacted_value": _redact(url, show_plaintext=show_plaintext),
            "raw_for_verify": url,
            "db_scheme": m.group("scheme"),
            "db_user": m.group("user"),
            "db_host": m.group("host"),
            "file_size": size,
            "http_status": status,
        })
    # JWT secret
    for m in RE_JWT.finditer(body):
        val = m.group("val")
        out.append({
            "match_type": "jwt_secret",
            "file_path": path,
            "redacted_value": _redact(val, show_plaintext=show_plaintext),
            "raw_for_verify": val,
            "file_size": size,
            "http_status": status,
        })
    # Generic password / token / api_key assignments
    seen_keys: set = set()
    for m in RE_GENERIC.finditer(body):
        key = m.group("key").lower()
        val = m.group("val")
        # Skip JWT secret duplicates (already captured by RE_JWT)
        if "jwt" in key:
            continue
        # Skip obvious placeholders
        low = val.lower()
        if low in ("changeme", "yourpassword", "your_password", "example",
                   "yoursecret", "secret_here", "todo", "fixme",
                   "your_api_key", "your_token", "xxx", "xxxxxx"):
            continue
        dedup = f"{key}={val[:24]}"
        if dedup in seen_keys:
            continue
        seen_keys.add(dedup)
        out.append({
            "match_type": "generic_password",
            "file_path": path,
            "key_hint": key,
            "redacted_value": _redact(val, show_plaintext=show_plaintext),
            "raw_for_verify": val,
            "file_size": size,
            "http_status": status,
        })
    return out


# ═══════════════════════════════════════════════════════════════════
#  HTTP probe primitives (httpx preferred, requests fallback)
# ═══════════════════════════════════════════════════════════════════


async def _probe_one(base: str, path: str, timeout: float) -> Optional[dict]:
    """GET base+path. Returns dict {status, body, headers} or None on error."""
    url = base.rstrip("/") + path
    try:
        import httpx
    except ImportError:
        return await _probe_one_requests(url, timeout)
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            verify=False,
            headers={"User-Agent": "VulnusLab-ExposedEnvScan/1.0"},
        ) as client:
            r = await client.get(url)
            body = r.text or ""
            return {
                "status": r.status_code,
                "body": body[:65536],   # cap memory per file
                "headers": dict(r.headers),
                "url": url,
            }
    except Exception:
        return None


async def _probe_one_requests(url: str, timeout: float) -> Optional[dict]:
    """Sync-fallback for environments without httpx."""
    try:
        import requests
    except ImportError:
        return None
    def _run():
        try:
            r = requests.get(
                url, timeout=timeout, allow_redirects=False, verify=False,
                headers={"User-Agent": "VulnusLab-ExposedEnvScan/1.0"},
            )
            return {
                "status": r.status_code,
                "body": (r.text or "")[:65536],
                "headers": dict(r.headers),
                "url": url,
            }
        except Exception:
            return None
    return await asyncio.get_event_loop().run_in_executor(None, _run)


async def _probe_paths(base: str, paths: list[str], timeout: float,
                       concurrency: int = MAX_CONCURRENCY) -> list[dict]:
    """Probe a list of paths with a concurrency cap + inter-probe delay.
    Returns list of probe-result dicts (one per path, may be None on error)."""
    sem = asyncio.Semaphore(concurrency)
    results: list[Optional[dict]] = [None] * len(paths)

    async def _do(i: int, path: str):
        async with sem:
            # tiny stagger between starts inside the same slot
            await asyncio.sleep(INTER_PROBE_DELAY)
            results[i] = await _probe_one(base, path, timeout)

    await asyncio.gather(*[_do(i, p) for i, p in enumerate(paths)])
    # Attach the path used so callers can correlate
    cleaned: list[dict] = []
    for i, r in enumerate(results):
        if r is None:
            continue
        r["path"] = paths[i]
        cleaned.append(r)
    return cleaned


# ═══════════════════════════════════════════════════════════════════
#  ExposedEnvScan - the VL-METHOD scanner class
# ═══════════════════════════════════════════════════════════════════


class ExposedEnvScan(MethodologyScanner):
    name = "exposed_env_scan"

    # ── STAGE 1: PRE-FLIGHT ──────────────────────────────────────
    async def pre_flight(self, ctx: ScanContext) -> bool:
        target = ctx.host
        if not target or not isinstance(target, str):
            ctx.state["skipped_reason"] = "form_url not supplied"
            return False
        base = _normalize_url(target)
        if not base:
            ctx.state["skipped_reason"] = "form_url not supplied"
            return False
        ctx.state["target_base"] = base
        # Also record clean host for telemetry
        clean_host, _port = helpers.split_host_port(target, default_port=0)
        ctx.state["target_host"] = clean_host

        opts = ctx.state.get("_options") or {}
        timeout = float(opts.get("timeout") or DEFAULT_TIMEOUT)
        probe = await _probe_one(base, "/", timeout)
        if not probe:
            ctx.state["skipped_reason"] = f"target HTTP not reachable: {base}/"
            ctx.state["target_reachable"] = False
            return False
        status = int(probe.get("status") or 0)
        # Accept 2xx / 3xx / 4xx as "alive HTTP service"; reject 5xx and missing
        if not (200 <= status < 500):
            ctx.state["skipped_reason"] = f"target HTTP not reachable (status={status})"
            ctx.state["target_reachable"] = False
            return False
        ctx.state["target_reachable"] = True
        ctx.state["_root_probe"] = probe
        return True

    # ── STAGE 2: FINGERPRINT ─────────────────────────────────────
    async def fingerprint(self, ctx: ScanContext):
        probe = ctx.state.get("_root_probe") or {}
        headers = probe.get("headers") or {}
        body = probe.get("body") or ""
        # Header keys can be mixed case from httpx; normalize lookup
        h_lower = {(k or "").lower(): (v or "") for k, v in headers.items()}
        fp = {
            "server": h_lower.get("server", "") or "",
            "powered_by": h_lower.get("x-powered-by", "") or "",
            "framework": _detect_framework(headers, body),
            "status_code": int(probe.get("status") or 0),
            "has_csp": bool(h_lower.get("content-security-policy")),
        }
        ctx.state["fingerprint"] = fp

    # ── STAGE 3: QUICK PROBE (top-8 leak paths) ──────────────────
    async def quick_probe(self, ctx: ScanContext) -> list[dict]:
        base = ctx.state.get("target_base") or ""
        if not base:
            return []
        opts = ctx.state.get("_options") or {}
        timeout = float(opts.get("timeout") or DEFAULT_TIMEOUT)
        show = bool(opts.get("show_plaintext"))

        results = await _probe_paths(base, list(QUICK_PROBE_PATHS), timeout)
        attempts = len(QUICK_PROBE_PATHS)
        hits_paths: list[str] = []
        findings: list[dict] = []

        for r in results:
            status = int(r.get("status") or 0)
            body = r.get("body") or ""
            path = r.get("path") or ""
            if status != 200:
                continue
            if len(body) == 0:
                continue
            if _is_404_body(body, status):
                continue
            hits_paths.append(path)
            for f in _extract_secrets(path, body, status, show):
                f["discovery_method"] = "quick_probe_top8"
                findings.append(f)
                if len(findings) >= HARD_MAX_MATCHES:
                    break
            if len(findings) >= HARD_MAX_MATCHES:
                break

        ctx.state["quick_probe_attempts"] = attempts
        ctx.state["quick_probe_hits"] = len(hits_paths)
        ctx.state["quick_probe_hit_paths"] = hits_paths
        return findings

    # ── STAGE 4: DEEP SCAN (full path list, gated) ───────────────
    async def deep_scan(self, ctx: ScanContext) -> list[dict]:
        base = ctx.state.get("target_base") or ""
        if not base:
            return []
        opts = ctx.state.get("_options") or {}
        timeout = float(opts.get("timeout") or DEFAULT_TIMEOUT)
        show = bool(opts.get("show_plaintext"))

        # Build path list: CRITICAL_PATHS + customer extras, deduped, capped
        extra = opts.get("paths") or []
        if not isinstance(extra, list):
            extra = []
        extra_clean: list[str] = []
        for p in extra:
            if not isinstance(p, str):
                continue
            p2 = p.strip()
            if not p2:
                continue
            if not p2.startswith("/"):
                p2 = "/" + p2
            extra_clean.append(p2)

        all_paths: list[str] = []
        seen = set()
        # Skip paths already covered by quick_probe to avoid duplicate probes
        already = set(ctx.state.get("quick_probe_hit_paths") or [])
        # We still re-probe non-hit quick paths if customer wanted always_deep
        # Actually re-probing wastes budget; skip everything already in QUICK_PROBE_PATHS
        skip_set = set(QUICK_PROBE_PATHS)
        for p in list(CRITICAL_PATHS) + extra_clean:
            if p in seen:
                continue
            if p in skip_set:
                continue
            seen.add(p)
            all_paths.append(p)
            if len(all_paths) >= HARD_MAX_PATHS:
                break

        ctx.state["env_deep_paths"] = len(all_paths)
        if not all_paths:
            return []

        results = await _probe_paths(base, all_paths, timeout)
        findings: list[dict] = []
        for r in results:
            status = int(r.get("status") or 0)
            body = r.get("body") or ""
            path = r.get("path") or ""
            if status != 200 or len(body) == 0 or _is_404_body(body, status):
                continue
            for f in _extract_secrets(path, body, status, show):
                f["discovery_method"] = "deep_scan_full_list"
                findings.append(f)
                if len(findings) >= HARD_MAX_MATCHES:
                    break
            if len(findings) >= HARD_MAX_MATCHES:
                break
        return findings

    # ── STAGE 5: VERIFY (re-fetch + structural validation) ───────
    async def verify(self, ctx: ScanContext, finding: dict) -> Optional[dict]:
        base = ctx.state.get("target_base") or ""
        opts = ctx.state.get("_options") or {}
        timeout = float(opts.get("timeout") or DEFAULT_TIMEOUT)
        path = finding.get("file_path") or ""

        # Step A: re-fetch with NEW request, confirm stable (200 + size matches)
        stable = False
        if base and path:
            probe2 = await _probe_one(base, path, timeout)
            if probe2:
                status2 = int(probe2.get("status") or 0)
                body2 = probe2.get("body") or ""
                size2 = len(body2)
                # Allow +/-128 bytes wiggle for dynamic timestamps in config files
                orig_size = int(finding.get("file_size") or 0)
                if status2 == 200 and size2 > 0 and not _is_404_body(body2, status2):
                    if orig_size == 0 or abs(size2 - orig_size) <= max(128, orig_size // 20):
                        stable = True

        # Step B: structural validation of the captured secret
        mt = finding.get("match_type", "")
        raw = finding.get("raw_for_verify", "") or ""
        struct_ok = False
        if mt == "aws_credentials":
            struct_ok = bool(re.fullmatch(r"AKIA[0-9A-Z]{16}", raw))
        elif mt == "db_connection_string":
            struct_ok = bool(RE_DB_URL.fullmatch(raw)) and bool(
                finding.get("db_user")) and bool(finding.get("db_host"))
        elif mt == "jwt_secret":
            struct_ok = len(raw) > 16
        elif mt == "ssh_private_key":
            struct_ok = "PRIVATE KEY" in raw
        elif mt == "generic_password":
            # generic creds are "structurally valid" if length >= 8 (already
            # enforced by regex), and look reasonably random (>= 2 char classes)
            classes = sum([
                bool(re.search(r"[a-z]", raw)),
                bool(re.search(r"[A-Z]", raw)),
                bool(re.search(r"[0-9]", raw)),
                bool(re.search(r"[^a-zA-Z0-9]", raw)),
            ])
            struct_ok = len(raw) >= 8 and classes >= 2

        if stable and struct_ok:
            finding["confidence"] = "CONFIRMED"
        else:
            finding["confidence"] = "SUSPECTED"
        finding["verification_method"] = "httpx_second_fetch_structure_check"
        finding["verify_stable"] = stable
        finding["verify_structure_ok"] = struct_ok
        # Don't ship raw secret in payload; redacted_value already set.
        finding.pop("raw_for_verify", None)
        return finding

    # ── STAGE 6: PRIVILEGE CHECK ─────────────────────────────────
    async def privilege_check(self, ctx: ScanContext, finding: dict) -> dict:
        mt = finding.get("match_type", "")
        if mt == "aws_credentials":
            finding["privilege_level"] = "cloud_root"
        elif mt == "db_connection_string":
            finding["privilege_level"] = "database_owner"
        elif mt == "jwt_secret":
            finding["privilege_level"] = "auth_bypass_capable"
        elif mt == "ssh_private_key":
            finding["privilege_level"] = "key_material"
        elif mt == "generic_password":
            finding["privilege_level"] = "credential"
        else:
            finding["privilege_level"] = "unknown"
        return finding

    # ── STAGE 7: CHAIN HANDOFF ───────────────────────────────────
    async def chain_handoff(self, ctx: ScanContext, findings: list[dict]) -> list[str]:
        next_scanners: list[str] = []
        seen_kinds: set = set()
        for f in findings:
            if f.get("confidence") != "CONFIRMED":
                continue
            mt = f.get("match_type", "")
            if mt in seen_kinds:
                continue
            seen_kinds.add(mt)
            if mt == "aws_credentials":
                next_scanners.append("post_exploit_aws_iam_audit")
            elif mt == "db_connection_string":
                next_scanners.extend(["mysql_brute", "postgres_brute"])
            elif mt == "jwt_secret":
                next_scanners.append("jwt_forge_audit")
        # dedupe preserving order
        out: list[str] = []
        for s in next_scanners:
            if s not in out:
                out.append(s)
        return out


# ═══════════════════════════════════════════════════════════════════
#  Endpoint wrapper
# ═══════════════════════════════════════════════════════════════════


@router.post("/api/password/exposed_env_scan")
async def password_exposed_env_scan(req: ExposedEnvScanRequest,
                                    _=Depends(verify_scan_quota)):
    scanner = ExposedEnvScan()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=EXPOSED_ENV_SCAN_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


def register(app):
    app.include_router(router)

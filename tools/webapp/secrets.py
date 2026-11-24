"""Webapp secrets scanner — regex match against AI-curated 97-pattern catalog.

Route: POST /api/webapp/secrets
Loads tools/_payloads/secrets_patterns.py (97 handcrafted regex patterns
covering AWS / GCP / Azure / GitHub / Slack / Stripe / Twilio / JWT /
RSA keys / DB connection strings / Indian fintech / AI provider keys).

Workflow:
  1. Fetch homepage + crawl ≤ 10 same-origin JS files
  2. Run every AI pattern against each response body
  3. Emit a finding per (file, pattern) hit — capped at 30 to avoid spam
"""
import base64
import json
import re
import string

import httpx

from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()

_FALLBACK_PATTERNS = [
    {"name": "AWS Access Key ID", "regex": r"AKIA[0-9A-Z]{16}",
     "service": "aws", "severity": "CRITICAL", "cvss": "9.8",
     "remediation": "Rotate the AWS key immediately."},
    {"name": "RSA Private Key", "regex": r"-----BEGIN RSA PRIVATE" r" KEY-----",
     "service": "private_key", "severity": "CRITICAL", "cvss": "10.0",
     "remediation": "Rotate key pair IMMEDIATELY."},
    {"name": "JWT Token", "regex": r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{20,}",
     "service": "jwt", "severity": "MEDIUM", "cvss": "5.5",
     "remediation": "Move JWT to HttpOnly cookies."},
]
try:
    from tools._payloads.secrets_patterns import SECRETS_PATTERNS as _AI_SECRETS
    _PATTERNS = list(_AI_SECRETS) if isinstance(_AI_SECRETS, list) and _AI_SECRETS else _FALLBACK_PATTERNS
except Exception:
    _PATTERNS = _FALLBACK_PATTERNS

# Pre-compile patterns once for speed.
# NOTE (SECRETS-FP-V1): compiled CASE-SENSITIVELY. Patterns that need case
# folding carry their own inline (?i). A global IGNORECASE turned vendor
# prefixes like AKIA / AC / SK / ghp_ into matches on arbitrary lowercase
# runs inside minified bundles (e.g. Juice Shop main.js).
_COMPILED = []
for _p in _PATTERNS:
    try:
        _COMPILED.append((_p, re.compile(_p["regex"])))
    except Exception:
        continue  # skip malformed regex


# ── False-positive suppression (SECRETS-FP-V1) ──────────────────────
# Distinctive vendor-prefixed patterns (AKIA…, ghp_…, sk_live_…, -----BEGIN
# … PRIVATE KEY-----, xox…, glpat-…) are kept as-is apart from a placeholder
# check. Generic / weakly-anchored patterns must additionally pass an
# entropy + character-class check, and the purely shape-based ones need a
# credential-ish key name right before the value.
_KEY_CONTEXT_RE = re.compile(
    r"(?i)(secret|passw(?:or)?d|passwd|pwd|token|api[_\-]?key|apikey|"
    r"access[_\-]?key|private[_\-]?key|client[_\-]?secret|credential|"
    r"auth[_\-]?(?:key|token)|signing[_\-]?key|bearer)")
_PER_PATTERN_CONTEXT = {
    "BIP39 Mnemonic (12-24 words)": re.compile(r"(?i)(mnemonic|seed[_\- ]?phrase|recovery[_\- ]?phrase|wallet)"),
    "Twilio Account SID": re.compile(r"(?i)(twilio|account[_\-]?sid)"),
    "Twilio Auth Token": re.compile(r"(?i)(twilio|auth[_\-]?token|api[_\-]?key)"),
    "Ethereum Private Key": re.compile(r"(?i)(private[_\-]?key|priv[_\-]?key|secret|wallet|mnemonic)"),
}
# Shape-only patterns: no vendor prefix at all -> need key-name context.
_NEEDS_CONTEXT = {
    "High-entropy base64 string (64+ chars)",
    "High-entropy hex string (128+ chars)",
    "Cohere API Key",
    "Ethereum Private Key",
    "BIP39 Mnemonic (12-24 words)",
    "Base64 with secret-like prefix",
    "Twilio Account SID",
    "Twilio Auth Token",
    "Telegram Bot Token",
}
# Weakly-anchored: matched on a generic keyword / short prefix / vendor name
# within N chars -> need a high-entropy, mixed-class value.
_WEAK_SERVICES = {"generic", "jwt", "discord", "telegram", "mailgun",
                  "cloudflare", "heroku", "vercel", "netlify", "fastly",
                  "sentry", "datadog", "newrelic", "pusher", "phonepe", "paytm",
                  "cashfree", "instamojo", "asana", "postmark", "zoom",
                  "twilio", "cohere", "crypto", "payu"}
_PLACEHOLDER_RE = re.compile(
    r"(?i)(example|sample|dummy|placeholder|your[_\-]?|xxxx|changeme|"
    r"redacted|<[a-z_ ]+>|\.\.\.|0{12,}|1234567890|abcdef(?:ghij)?)")
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-.~]{8,}")
_LIB_CONTEXT_RE = re.compile(
    r"(?i)(sourceMappingURL|sha(?:256|384|512)-|integrity\s*[:=]|"
    r"\.(?:png|jpe?g|gif|svg|woff2?|ttf|eot|webp|ico|css|js|map)\b)")


def _shannon(s: str) -> float:
    import math
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _secret_token(matched: str) -> str:
    """Longest credential-ish run inside the match (the actual value)."""
    runs = _TOKEN_RE.findall(matched)
    return max(runs, key=len) if runs else matched


def _in_data_uri(body: str, start: int) -> bool:
    """True if offset `start` sits inside a data:...;base64, URI."""
    window = body[max(0, start - 300):start]
    idx = window.rfind("data:")
    if idx == -1:
        return False
    tail = window[idx:]
    return ";base64," in tail and not any(q in tail for q in ("\"", "'", "`", ")", " "))


def _looks_random(tok: str) -> bool:
    """Entropy + character-class gate for a candidate secret value."""
    core = tok.strip("=\"'")
    if len(core) < 16:
        return False
    is_hex = re.fullmatch(r"[0-9a-fA-F]+", core) is not None
    ent = _shannon(core)
    if is_hex:
        return ent >= 3.0 and not core.isdigit()
    classes = sum(bool(re.search(p, core)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]"))
    if classes < 2 or not re.search(r"[0-9]", core):
        # identifiers like "translateServiceLoaderFactory" / "ngOnInitHook"
        return False
    return ent >= 3.5


# ── SECRETS-FP-V2 — minified-bundle hardening ────────────────────────
# Re-measured against Juice Shop's Angular bundle plus a corpus of common
# vendor-library constructs (node-forge / jsencrypt PEM builders, DB-URI
# string concatenation, i18n keys, jwt.io sample tokens, ...).
#
# PEM: a header alone is a library constant (forge/jsencrypt/asn1 parsers
# all ship the bare "BEGIN RSA PRIVATE KEY" PEM header to BUILD or PARSE keys). Only
# report when base64 key material actually follows the header.
_PEM_BODY_RE = re.compile(
    r"(?:\s|\\[rn])*"
    r"(?:(?:Proc-Type|DEK-Info|Comment|Version|Hash)\s*:[^\n\\]*(?:\s|\\[rn])+)*"
    r"[A-Za-z0-9+/=]{40,}")
# DB connection URIs: credentials must be a literal, not code / template.
_URI_SERVICES = {"mongodb", "postgres", "mysql", "redis", "rabbitmq"}
_URI_CODE_CHARS = re.compile(r"[\"'`(){}\[\]<>,;|\\]|\$\{")
_PLACEHOLDER_PASSWORDS = {
    "password", "pass", "passwd", "pwd", "pw", "secret", "changeme",
    "mypassword", "yourpassword", "user", "username", "test",
    "xxx", "xxxx", "foo", "bar", "example",
}
# jwt.io's canonical sample token ships inside many docs/libraries.
_SAMPLE_JWT_CLAIMS = ({"sub": "1234567890", "name": "John Doe"},)
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")
_TOKEN_CHARS = set(string.ascii_letters + string.digits + "+/_-")
_SEQ_RUNS = ("abcdefgh", "bcdefghi", "ABCDEFGH", "BCDEFGHI", "01234567",
             "12345678", "qwertyui", "QWERTYUI")


def _b64url_json(seg: str):
    try:
        raw = base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
        val = json.loads(raw.decode("utf-8"))
        return val if isinstance(val, dict) else None
    except Exception:
        return None


def _jwt_is_real(matched: str) -> bool:
    """Header and payload must base64url-decode to JSON objects, the header
    must name an ``alg``, and it must not be a well-known sample token."""
    jm = _JWT_RE.search(matched)
    if not jm:
        return False
    parts = jm.group(0).split(".")
    hdr, pay = _b64url_json(parts[0]), _b64url_json(parts[1])
    if hdr is None or pay is None or "alg" not in hdr:
        return False
    for sample in _SAMPLE_JWT_CLAIMS:
        if all(pay.get(k) == v for k, v in sample.items()):
            return False
    return True


def _looks_like_identifier(tok: str) -> bool:
    """i18n keys (LABEL_API_KEY_2FA), camelCase / snake_case identifiers and
    alphabet tables — high entropy by Shannon, but not secrets."""
    core = tok.strip("=\"'")
    if re.fullmatch(r"[A-Z0-9]+(?:_[A-Z0-9]+){2,}", core):
        return True
    if any(r in core for r in _SEQ_RUNS):
        return True
    words = re.findall(r"[A-Z]?[a-z]{3,}|[A-Z]{3,}(?![a-z])", core)
    covered = sum(len(w) for w in words)
    return len(words) >= 2 and covered >= 0.75 * len(core)


def _uri_is_fp(matched: str) -> bool:
    try:
        rest = matched.split("://", 1)[1]
        creds, host = rest.split("@", 1)
    except (IndexError, ValueError):
        return True
    if _URI_CODE_CHARS.search(creds) or not host or host[0] in "\"'`$+(":
        return True   # string concatenation / template literal, not a literal URI
    pwd = creds.split(":", 1)[1] if ":" in creds else creds
    return (not pwd or set(pwd) <= {"*", "x", "X"}
            or pwd.lower() in _PLACEHOLDER_PASSWORDS)


def _is_fragment(body: str, m) -> bool:
    """Shape-only match carved out of a longer token (JWT, URL, base64 run)."""
    a = body[m.start() - 1] if m.start() > 0 else ""
    b = body[m.end()] if m.end() < len(body) else ""
    return (a in _TOKEN_CHARS) or (b in _TOKEN_CHARS) or a == "." or b == "."


def _is_false_positive(entry: dict, body: str, m) -> bool:
    name = entry.get("name", "")
    service = entry.get("service", "")
    matched = m.group(0)
    tok = _secret_token(matched)
    if _PLACEHOLDER_RE.search(matched):
        return True
    if _in_data_uri(body, m.start()):
        return True
    before = body[max(0, m.start() - 60):m.start()]
    if service == "private_key":
        # header must be followed by actual base64 key material
        return not _PEM_BODY_RE.match(body, m.end(), m.end() + 600)
    if service in _URI_SERVICES:
        return _uri_is_fp(matched)
    if service == "jwt" or name == "Zoom API Token":
        if not _jwt_is_real(matched):
            return True
    weak = service in _WEAK_SERVICES or name in _NEEDS_CONTEXT
    if not weak:
        return False  # distinctive vendor prefix: AKIA / ghp_ / sk_live_ ...
    if _LIB_CONTEXT_RE.search(before[-40:]):
        return True   # SRI hash / sourcemap / asset filename
    if name == "BIP39 Mnemonic (12-24 words)":
        ctx_re = _PER_PATTERN_CONTEXT[name]
        return not ctx_re.search(before)
    if service != "jwt":
        if not _looks_random(tok):
            return True
        # identifiers / i18n keys — unless the key name says "password"
        if not re.search(r"(?i)pass|pwd", matched) and _looks_like_identifier(tok):
            return True
    if name in _NEEDS_CONTEXT:
        if _is_fragment(body, m):
            return True
        ctx_re = _PER_PATTERN_CONTEXT.get(name, _KEY_CONTEXT_RE)
        # key name must precede the value (inside the match or just before)
        prefix = before + matched[: max(0, matched.find(tok))]
        if not ctx_re.search(prefix[-60:]):
            return True
    return False


def _is_generic(entry: dict) -> bool:
    return entry.get("service") == "generic" or entry.get("name") in _NEEDS_CONTEXT


_TIMEOUT = httpx.Timeout(connect=4.0, read=6.0, write=3.0, pool=8.0)
_MAX_JS_FILES = 10
_MAX_BODY_BYTES = 1_500_000  # cap per-file scan to 1.5MB
_MAX_FINDINGS = 30


async def _get_capped(client, url):
    """GET with a hard byte cap (HTTP-CAP-V1) — never buffer an unbounded
    body from a hostile target; returns decoded text (<= _MAX_BODY_BYTES)."""
    buf = bytearray()
    async with client.stream("GET", url) as r:
        async for chunk in r.aiter_bytes():
            buf.extend(chunk)
            if len(buf) >= _MAX_BODY_BYTES:
                break
        enc = r.encoding or "utf-8"
    try:
        return bytes(buf[:_MAX_BODY_BYTES]).decode(enc, errors="replace")
    except LookupError:
        return bytes(buf[:_MAX_BODY_BYTES]).decode("utf-8", errors="replace")


async def _fetch_with_extracted_js(client, base):
    """Fetch homepage; extract up to N same-origin .js URLs; fetch each."""
    bodies = []  # list of (label, content)
    try:
        html = await _get_capped(client, base + "/")
        bodies.append((base + "/", html))
    except Exception:
        return bodies
    # Extract <script src="..."> URLs (same-origin only)
    src_re = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.I)
    seen = set()
    for m in src_re.finditer(html):
        url = m.group(1)
        if url.startswith("//"): continue
        if url.startswith("http") and not url.startswith(base): continue
        if not url.startswith("http"):
            url = base + ("" if url.startswith("/") else "/") + url.lstrip("/")
        if url in seen: continue
        seen.add(url)
        if len(seen) > _MAX_JS_FILES: break
        try:
            bodies.append((url, await _get_capped(client, url)))
        except Exception:
            continue
    return bodies


@router.post("/api/webapp/secrets")
@vl_verify(check_spa=True)
async def webapp_secrets(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    hits = []
    suppressed = 0

    async with httpx.AsyncClient(
        verify=False, follow_redirects=True, timeout=_TIMEOUT,
        headers={"User-Agent": "VulnusLab/1.0"}
    ) as client:
        bodies = await _fetch_with_extracted_js(client, base)

    # Scan each body against every compiled pattern. Vendor-specific
    # patterns run first; a generic / shape-only hit that overlaps a span
    # already claimed by a specific pattern is the same secret reported
    # twice (e.g. an AIza key also matching "Generic API key param") — skip it.
    # Priority: vendor-specific > generic keyword > shape-only.
    ordered = sorted(_COMPILED, key=lambda c: (_is_generic(c[0]),
                                               c[0].get("name") in _NEEDS_CONTEXT))
    for label, body in bodies:
        if not body: continue
        claimed = []
        for entry, compiled in ordered:
            generic = _is_generic(entry)
            for m in compiled.finditer(body):
                if _is_false_positive(entry, body, m):
                    suppressed += 1
                    continue
                if generic and any(m.start() < e and s0 < m.end() for s0, e in claimed):
                    suppressed += 1
                    continue
                claimed.append((m.start(), m.end()))
                snippet = m.group(0)[:80]
                hits.append({
                    "name": entry["name"], "service": entry["service"],
                    "severity": entry["severity"], "url": label,
                    "snippet": snippet,
                })
                if len(hits) >= _MAX_FINDINGS:
                    break
            if len(hits) >= _MAX_FINDINGS:
                break
        if len(hits) >= _MAX_FINDINGS:
            break

    # Dedupe by (service, snippet) so we don't report the same key twice
    seen = set()
    unique_hits = []
    for h in hits:
        k = (h["service"], h["snippet"])
        if k in seen: continue
        seen.add(k)
        unique_hits.append(h)

    for h in unique_hits[:20]:
        sev = h["severity"] if h["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "MEDIUM"
        # Find the original entry to grab cvss + remediation
        orig = next((e for e in _PATTERNS if e.get("name") == h["name"]), {})
        cvss = orig.get("cvss", "5.0")
        rem = orig.get("remediation", "Rotate the leaked credential immediately.")
        findings.append(wrap_finding(
            f"Secret leaked in client-side response: {h['name']}",
            sev, cvss=cvss, cwe="CWE-200",
            cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
            owasp="A02:2021",
            remediation=rem,
            evidence_marker=f"At {h['url']}: matched pattern '{h['name']}' (snippet: {h['snippet'][:60]}...)",
        ))

    return standard_response(
        tool="secrets", target=req.target,
        findings=findings,
        tests_performed=len(_COMPILED) * len(bodies),
        tests_summary=f"Scanned {len(bodies)} response bodies against {len(_COMPILED)} AI-curated regex patterns; {len(unique_hits)} unique leaks found",
        raw_data={"secrets": {
            "patterns_loaded": len(_COMPILED),
            "bodies_scanned": len(bodies),
            "unique_hits": len(unique_hits),
            "suppressed_false_positives": suppressed,
            "wordlist_source": f"AI-curated ({len(_PATTERNS)} patterns)",
            "services_with_hits": sorted({h["service"] for h in unique_hits}),
        }},
    )


def register(app):
    app.include_router(router)

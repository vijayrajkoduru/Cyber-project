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
import re

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
        return False  # PEM headers are unambiguous
    weak = service in _WEAK_SERVICES or name in _NEEDS_CONTEXT
    if not weak:
        return False  # distinctive vendor prefix: AKIA / ghp_ / sk_live_ ...
    if _LIB_CONTEXT_RE.search(before[-40:]):
        return True   # SRI hash / sourcemap / asset filename
    if name == "BIP39 Mnemonic (12-24 words)":
        ctx_re = _PER_PATTERN_CONTEXT[name]
        return not ctx_re.search(before)
    if service != "jwt" and not _looks_random(tok):
        return True
    if name in _NEEDS_CONTEXT:
        ctx_re = _PER_PATTERN_CONTEXT.get(name, _KEY_CONTEXT_RE)
        # key name must precede the value (inside the match or just before)
        prefix = before + matched[: max(0, matched.find(tok))]
        if not ctx_re.search(prefix[-60:]):
            return True
    return False

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

    # Scan each body against every compiled pattern
    for label, body in bodies:
        if not body: continue
        for entry, compiled in _COMPILED:
            for m in compiled.finditer(body):
                if _is_false_positive(entry, body, m):
                    suppressed += 1
                    continue
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

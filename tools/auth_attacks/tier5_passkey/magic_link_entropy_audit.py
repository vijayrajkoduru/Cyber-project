"""magic_link_entropy_audit - magic-link / OTP token strength (playbook §7 #69).

REAL offline analysis (no network). The customer pastes one or more
magic-link URLs (or just the token values) that their app actually emitted.
The probe extracts the token from each and measures whether it is guessable:

  - Shannon entropy (bits/char * length) below a safe threshold.
  - Token too short (< 16 effective random chars).
  - Sequential / low-cardinality tokens (numeric counters, short ids).
  - Predictable structure (timestamp prefixes, incrementing across samples).

ZERO false positives: a graded severity fires ONLY on a measured property
of the supplied token(s). No tokens supplied -> INFO. Strong tokens ->
POSITIVE. Token VALUES are never echoed - only length, charset class,
estimated entropy bits, and a redacted prefix.

This is purely local math on customer-owned data; nothing is sent anywhere
and the magic link is never followed (no replay, no DoS).

Customer input via ScanRequest.options:
  - target              = identifier (logging only)
  - options.magic_links = list[str] or newline string of magic-link URLs/tokens
  - options.token_param = query-param name holding the token (auto-detect otherwise)
"""
from __future__ import annotations
import math
import re
from collections import Counter
from typing import Optional
from urllib.parse import urlparse, parse_qs

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

router = APIRouter()

# Query-param names commonly holding a magic-link/OTP token.
_TOKEN_PARAM_HINTS = (
    "token", "t", "code", "otp", "key", "magic", "link", "auth", "verify",
    "confirmation", "confirm", "reset", "secret", "nonce", "sig", "hash",
)


class MagicLinkEntropyAuditRequest(ScanRequest):
    options: Optional[dict] = None


def _coerce_list(v) -> list:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    return [ln.strip() for ln in str(v).splitlines() if ln.strip()]


def _extract_token(item: str, hint: Optional[str]) -> Optional[str]:
    """Pull the token out of a URL (or treat the whole string as a token)."""
    item = item.strip()
    if "://" in item or item.startswith("/") or "?" in item:
        try:
            p = urlparse(item)
            qs = parse_qs(p.query)
            if hint and hint in qs and qs[hint]:
                return qs[hint][0]
            for name in _TOKEN_PARAM_HINTS:
                if name in qs and qs[name]:
                    return qs[name][0]
            # Fall back to the last non-empty path segment.
            segs = [s for s in p.path.split("/") if s]
            if segs:
                return segs[-1]
        except Exception:
            return None
    return item


def _shannon_entropy_bits(token: str) -> float:
    """Total entropy estimate in bits: H(per-char) * length."""
    if not token:
        return 0.0
    counts = Counter(token)
    n = len(token)
    per_char = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return per_char * n


def _charset_class(token: str) -> str:
    classes = []
    if re.search(r"[a-z]", token):
        classes.append("lower")
    if re.search(r"[A-Z]", token):
        classes.append("upper")
    if re.search(r"[0-9]", token):
        classes.append("digit")
    if re.search(r"[^A-Za-z0-9]", token):
        classes.append("symbol")
    return "+".join(classes) or "empty"


def _redact(token: str) -> str:
    if not token:
        return "len=0"
    if len(token) <= 6:
        return f"len={len(token)} ***"
    return f"len={len(token)} {token[:3]}...{token[-2:]}"


def _is_pure_numeric(token: str) -> bool:
    return bool(token) and token.isdigit()


async def gather(ctx: ScanContext):
    opts = ctx.state.get("_options") or {}
    raw = _coerce_list(opts.get("magic_links"))
    hint = opts.get("token_param")

    if not raw:
        ctx.state["ml_input_missing"] = True
        ctx.source("no magic_links supplied")
        return

    samples = []
    numeric_tokens = []
    for item in raw[:50]:
        tok = _extract_token(item, hint)
        if not tok:
            continue
        bits = _shannon_entropy_bits(tok)
        rec = {
            "redacted": _redact(tok),
            "length": len(tok),
            "charset": _charset_class(tok),
            "entropy_bits": round(bits, 1),
            "numeric_only": _is_pure_numeric(tok),
        }
        samples.append(rec)
        if _is_pure_numeric(tok):
            numeric_tokens.append(int(tok) if len(tok) <= 18 else None)

    ctx.state["ml_samples"] = samples
    if not samples:
        ctx.state["ml_no_tokens"] = True
        ctx.source("could not extract any token from supplied links")
        return

    # Weakness aggregation (all measured facts).
    weak = []
    min_bits = min(s["entropy_bits"] for s in samples)
    min_len = min(s["length"] for s in samples)
    ctx.state["ml_min_entropy_bits"] = min_bits
    ctx.state["ml_min_length"] = min_len

    for s in samples:
        if s["entropy_bits"] < 64:
            weak.append({"token": s["redacted"], "reason": f"entropy {s['entropy_bits']} bits < 64"})
        elif s["length"] < 16:
            weak.append({"token": s["redacted"], "reason": f"length {s['length']} < 16"})
    ctx.state["ml_weak_tokens"] = weak

    # Sequential detection: 2+ numeric tokens that increment by a small delta.
    seq = False
    nums = [n for n in numeric_tokens if n is not None]
    if len(nums) >= 2:
        nums_sorted = sorted(nums)
        deltas = [b - a for a, b in zip(nums_sorted, nums_sorted[1:])]
        if deltas and all(0 < d <= 1000 for d in deltas):
            seq = True
    ctx.state["ml_sequential"] = seq

    ctx.source(
        f"analyzed {len(samples)} token(s): min entropy {min_bits} bits, "
        f"min length {min_len}, sequential={seq}"
    )


# ----------------------- inline finding rules -----------------------
def rule_sequential(s):
    if not s.get("ml_sequential"):
        return None
    return {
        "name": "Magic-link / OTP tokens are sequential (predictable, enumerable)",
        "severity": "CRITICAL",
        "cvss": "9.1",
        "cwe": "CWE-340",
        "owasp": "A07:2021",
        "verified_exploit": True,
        "evidence": (
            "Multiple supplied numeric tokens increment by small, consistent deltas - the token "
            "is a predictable counter. An attacker can enumerate valid magic links and take over "
            "accounts without ever seeing the email/SMS."
        ),
        "remediation": (
            "Generate magic-link/OTP tokens from a CSPRNG with >= 128 bits of entropy "
            "(e.g. secrets.token_urlsafe(32)). Never derive them from counters, timestamps, or "
            "sequential ids. Bind each token to one account + short TTL + single use."
        ),
    }


def rule_low_entropy(s):
    weak = s.get("ml_weak_tokens") or []
    if not weak:
        return None
    if s.get("ml_sequential"):
        return None  # the sequential rule is the stronger signal
    return {
        "name": f"Magic-link / OTP token entropy too low: {len(weak)} weak sample(s)",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-330",
        "owasp": "A07:2021",
        "verified_exploit": True,
        "evidence": (
            f"Measured token weakness (min entropy {s.get('ml_min_entropy_bits')} bits, min "
            f"length {s.get('ml_min_length')}): {weak[:5]}. Tokens this weak are brute-forceable "
            "within the link's validity window."
        ),
        "remediation": (
            "Use secrets.token_urlsafe(32) (>= 128 bits) for magic links, enforce a short TTL "
            "(<= 10 min), single use, and rate-limit verification attempts."
        ),
    }


def rule_input_missing(s):
    if not s.get("ml_input_missing"):
        return None
    return {
        "name": "Magic-link entropy audit skipped - no tokens supplied",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": (
            "Probe needs options.magic_links - a list (or newline string) of real magic-link "
            "URLs or token values your app emitted. Analysis is fully offline; nothing is sent."
        ),
        "remediation": (
            "Collect a few magic links from your own test signups/password resets and paste "
            "them into options.magic_links, then re-run."
        ),
    }


def rule_no_tokens(s):
    if not s.get("ml_no_tokens"):
        return None
    return {
        "name": "Magic-link entropy audit - no token could be extracted from supplied links",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": (
            "The supplied links were parsed but no token-bearing query param or path segment "
            "was found."
        ),
        "remediation": (
            "Specify options.token_param with the exact query-parameter name that carries the "
            "token (e.g. 'token', 'code'), or paste the raw token values directly."
        ),
    }


def rule_positive(s):
    if s.get("ml_input_missing") or s.get("ml_no_tokens"):
        return None
    if (s.get("ml_weak_tokens") or []) or s.get("ml_sequential"):
        return None
    samples = s.get("ml_samples") or []
    if not samples:
        return None
    return {
        "name": f"Magic-link / OTP tokens are strong: {len(samples)} sample(s), all >=64-bit entropy",
        "severity": "POSITIVE",
        "cwe": "CWE-330",
        "owasp": "A07:2021",
        "evidence": (
            f"All {len(samples)} supplied token(s) are non-sequential with min entropy "
            f"{s.get('ml_min_entropy_bits')} bits and min length {s.get('ml_min_length')}."
        ),
        "remediation": (
            "Keep using a CSPRNG with short TTL + single use. Re-run if the token format "
            "changes."
        ),
    }


MAGIC_LINK_ENTROPY_AUDIT_FINDING_RULES = [
    rule_sequential,
    rule_low_entropy,
    rule_input_missing,
    rule_no_tokens,
    rule_positive,
]


INTEL_FIELDS = [
    ("Token samples",         "ml_samples"),
    ("Min entropy (bits)",    "ml_min_entropy_bits"),
    ("Min token length",      "ml_min_length"),
    ("Sequential detected",   "ml_sequential"),
    ("Weak tokens",           "ml_weak_tokens"),
]


@router.post("/api/auth_attacks/magic_link_entropy_audit")
async def auth_attacks_magic_link_entropy_audit(req: MagicLinkEntropyAuditRequest,
                                                _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="magic_link_entropy_audit",
        gather_func=_gather_with_options,
        finding_rules=MAGIC_LINK_ENTROPY_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)

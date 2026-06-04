"""lookalike_domain_scan - Typosquat / homoglyph / TLD-swap A-record probe
(playbook §2 #19/#20).

For the target email domain (e.g. acme.com), generates a bounded set of
visually-confusable variants and runs an A-record DNS lookup on each:

  1. Character-substitution typos (o<->0, l<->1, i<->1, rn->m, vv->w,
                                   nn->m, cl->d)
  2. Adjacent-key swaps (qwerty layout — already-registered typos)
  3. Character-omission (drop one letter at each position)
  4. Cyrillic/Greek homoglyphs (а=U+0430, е=U+0435, о=U+043E, etc.) -
     emit the Punycode (xn--) form which is what attackers actually
     register
  5. TLD swaps (.com -> .co, .net, .org, .biz, .info, .app,
                .online, .site, .xyz)
  6. Subdomain confusion ("login-acme.com", "acme-login.com",
                          "acme-secure.com")

Every variant that resolves to a public IP is reported as HIGH —
the attacker has the infrastructure to host a phishing landing page
that visually masquerades as the customer's brand.

Customer input via ScanRequest.target = the domain to protect
(e.g. "acme.com").  Optional ScanRequest.options:
  - max_variants  (default 60, hard cap 120)
  - extra_tlds    (newline-separated TLDs to add, e.g. ".de\n.in")

Performance: 60 variants * ~150ms-per-A-lookup = ~9s wall-clock; we
fan out via asyncio.gather with a Semaphore(20) to stay under a single
DNS resolver's burst rate.

References:
  - "ICANN SSAC 122 - The Role of Confusable Domain Names" (2024)
  - https://attack.mitre.org/techniques/T1583/001/  (Acquire Infrastructure)
  - URLcrazy / dnstwist - the canonical typo enumeration tooling
"""
from __future__ import annotations
import asyncio
import string
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.lookalike_domain_scan_findings import (
    LOOKALIKE_DOMAIN_SCAN_FINDING_RULES,
)

router = APIRouter()


class LookalikeRequest(ScanRequest):
    options: Optional[dict] = None


# Visual lookalikes — keep this conservative; full dnstwist has ~200
# but most are noise. These are the highest-impact substitutions.
CHAR_SUBSTITUTIONS = {
    "o": ["0"],
    "0": ["o"],
    "l": ["1", "I"],
    "1": ["l", "I"],
    "i": ["1", "l"],
    "rn": ["m"],
    "m": ["rn"],
    "vv": ["w"],
    "w": ["vv"],
    "nn": ["m"],
    "cl": ["d"],
    "e": ["3"],
    "a": ["4"],
    "s": ["5", "$"],
    "b": ["8"],
}

# Cyrillic homoglyphs — common confusables documented by Unicode TR36.
# (Mapped to Punycode form because that's how registered.)
HOMOGLYPH_MAP = {
    "a": "а",   # Cyrillic 'а'
    "e": "е",   # Cyrillic 'е'
    "o": "о",   # Cyrillic 'о'
    "p": "р",   # Cyrillic 'р'
    "c": "с",   # Cyrillic 'с'
    "x": "х",   # Cyrillic 'х'
    "y": "у",   # Cyrillic 'у'
    "i": "і",   # Ukrainian і
}

COMMON_SWAP_TLDS = [
    "com", "co", "net", "org", "biz", "info",
    "app", "online", "site", "xyz", "cc", "io",
    "us", "uk",
]

PREFIX_SUFFIX_WORDS = [
    "login", "secure", "account", "support",
    "verify", "mail", "billing",
]


def _normalize_domain(target: str) -> str:
    d = (target or "").strip()
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split("?", 1)[0]
    if d.lower().startswith("www."):
        d = d[4:]
    return d.lower().rstrip(".")


def _split_label_tld(domain: str) -> tuple[str, str]:
    """Return (label_without_dot, full_tld_chain).
    For acme.com -> ("acme", "com"). For sub.acme.com -> ("sub.acme", "com").
    We keep this simple — don't try to handle public-suffix-list cases
    like .co.uk (would require tldextract); the user explicitly says
    target=email-domain like 'acme.com'."""
    if "." not in domain:
        return domain, ""
    bits = domain.rsplit(".", 1)
    return bits[0], bits[1]


def _generate_substitutions(label: str) -> list[str]:
    out: set[str] = set()
    # Single-char swaps
    for i, ch in enumerate(label):
        for sub in CHAR_SUBSTITUTIONS.get(ch, []):
            out.add(label[:i] + sub + label[i + 1:])
    # Bigram swaps (rn, vv, nn, cl)
    for bigram, subs in CHAR_SUBSTITUTIONS.items():
        if len(bigram) != 2:
            continue
        idx = 0
        while True:
            j = label.find(bigram, idx)
            if j < 0:
                break
            for sub in subs:
                out.add(label[:j] + sub + label[j + 2:])
            idx = j + 1
    return list(out)


def _generate_keyboard_typos(label: str) -> list[str]:
    """Adjacent-key transposition on a QWERTY layout."""
    out: set[str] = set()
    rows = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]
    for i, ch in enumerate(label):
        for row in rows:
            if ch not in row:
                continue
            idx = row.index(ch)
            for adj_idx in (idx - 1, idx + 1):
                if 0 <= adj_idx < len(row):
                    out.add(label[:i] + row[adj_idx] + label[i + 1:])
        # Also swap adjacent chars (acme -> camea)
        if i + 1 < len(label) and label[i] != label[i + 1]:
            out.add(label[:i] + label[i + 1] + label[i] + label[i + 2:])
    return list(out)


def _generate_omissions(label: str) -> list[str]:
    if len(label) <= 3:
        return []
    return [label[:i] + label[i + 1:] for i in range(len(label))]


def _generate_homoglyphs(label: str) -> list[str]:
    """Replace one letter at a time with its Cyrillic confusable,
    then encode the resulting IDN to its Punycode form. We emit BOTH
    the unicode form (for display) and the xn-- form (what we actually
    query). For simplicity we only return Punycode here."""
    out: set[str] = set()
    for i, ch in enumerate(label):
        if ch in HOMOGLYPH_MAP:
            mixed = label[:i] + HOMOGLYPH_MAP[ch] + label[i + 1:]
            try:
                ascii_form = mixed.encode("idna").decode("ascii")
                if ascii_form != label:
                    out.add(ascii_form)
            except UnicodeError:
                continue
    return list(out)


def _generate_tld_swaps(label: str, current_tld: str,
                        extra_tlds: list[str]) -> list[str]:
    out: set[str] = set()
    targets = COMMON_SWAP_TLDS + [t.lstrip(".") for t in extra_tlds]
    for tld in targets:
        if tld and tld != current_tld:
            out.add(f"{label}.{tld}")
    return list(out)


def _generate_prefix_suffix(label: str, tld: str) -> list[str]:
    out: set[str] = set()
    for word in PREFIX_SUFFIX_WORDS:
        out.add(f"{word}-{label}.{tld}")
        out.add(f"{label}-{word}.{tld}")
    return list(out)


async def _resolve_a(domain: str, dns_module, sem: asyncio.Semaphore) -> Optional[list[str]]:
    """Async A-record resolve. dnspython's resolve is sync but fast
    enough for ~60 queries when wrapped in run_in_executor. Returns
    None on NXDOMAIN, [] on NoAnswer, [ips] on success."""
    loop = asyncio.get_event_loop()
    async with sem:
        try:
            ans = await loop.run_in_executor(
                None,
                lambda: dns_module.resolver.resolve(domain, "A", lifetime=4.0),
            )
        except dns_module.resolver.NXDOMAIN:
            return None
        except dns_module.resolver.NoAnswer:
            return []
        except dns_module.resolver.Timeout:
            return None
        except Exception:
            return None
    out = []
    try:
        for r in ans:
            out.append(str(r))
    except Exception:
        return out
    return out


async def gather(ctx: ScanContext):
    domain = _normalize_domain(ctx.host or "")
    if not domain:
        ctx.source("no-target")
        return
    try:
        import dns.resolver  # noqa: F401
        import dns
    except ImportError:
        ctx.state["lookalike_error"] = (
            "dnspython not installed (pip install dnspython)"
        )
        ctx.source("dnspython missing")
        return

    label, tld = _split_label_tld(domain)
    if not label or not tld:
        ctx.state["lookalike_error"] = (
            f"target '{domain}' must be a 2-label-or-more registrable domain"
        )
        ctx.source("bad-target")
        return

    opts = ctx.state.get("_options") or {}
    try:
        max_variants = min(int(opts.get("max_variants") or 60), 120)
    except (TypeError, ValueError):
        max_variants = 60
    extra_tlds_raw = (opts.get("extra_tlds") or "").strip()
    extra_tlds = [t.strip().lstrip(".") for t in extra_tlds_raw.splitlines() if t.strip()]

    # Combine variant generators with categories preserved for reporting
    variants_by_class: dict[str, list[str]] = {
        "char_substitution": [f"{v}.{tld}" for v in _generate_substitutions(label)],
        "keyboard_typo":     [f"{v}.{tld}" for v in _generate_keyboard_typos(label)],
        "char_omission":     [f"{v}.{tld}" for v in _generate_omissions(label)],
        "homoglyph_idn":     [f"{v}.{tld}" for v in _generate_homoglyphs(label)],
        "tld_swap":          _generate_tld_swaps(label, tld, extra_tlds),
        "prefix_suffix":     _generate_prefix_suffix(label, tld),
    }

    # Build flat list with class tag, dedupe, exclude exact target,
    # clamp to max_variants
    seen: set[str] = set()
    flat: list[tuple[str, str]] = []   # (class, variant_domain)
    for klass, variants in variants_by_class.items():
        for v in variants:
            v = v.lower().strip()
            if not v or v == domain or v in seen:
                continue
            seen.add(v)
            flat.append((klass, v))
            if len(flat) >= max_variants:
                break
        if len(flat) >= max_variants:
            break

    ctx.state["lookalike_target_domain"] = domain
    ctx.state["lookalike_variants_generated"] = len(flat)
    ctx.state["lookalike_max_variants"] = max_variants

    sem = asyncio.Semaphore(20)
    tasks = [_resolve_a(v, dns, sem) for _k, v in flat]
    try:
        results = await asyncio.gather(*tasks, return_exceptions=True)
    except Exception as e:
        ctx.state["lookalike_error"] = (
            f"DNS fan-out failed: {type(e).__name__}: {str(e)[:80]}"
        )
        ctx.source("fanout failed")
        return

    registered: list[dict] = []
    by_class_count: dict[str, int] = {}
    nx_count = 0
    err_count = 0
    for (klass, v), res in zip(flat, results):
        if isinstance(res, Exception):
            err_count += 1
            continue
        if res is None:
            nx_count += 1
            continue
        if not res:
            # NoAnswer (domain exists but no A record) — still suspicious
            registered.append({
                "domain": v,
                "class":  klass,
                "ips":    [],
                "note":   "domain exists (no A record)",
            })
            by_class_count[klass] = by_class_count.get(klass, 0) + 1
            continue
        registered.append({"domain": v, "class": klass, "ips": res})
        by_class_count[klass] = by_class_count.get(klass, 0) + 1

    ctx.state["lookalike_registered"]      = registered
    ctx.state["lookalike_registered_total"] = len(registered)
    ctx.state["lookalike_nx_total"]        = nx_count
    ctx.state["lookalike_err_total"]       = err_count
    ctx.state["lookalike_by_class"]        = by_class_count
    ctx.source(
        f"DNS A {len(flat)} variants -> {len(registered)} registered, "
        f"{nx_count} NXDOMAIN, {err_count} errors"
    )


INTEL_FIELDS = [
    ("Target domain",         "lookalike_target_domain"),
    ("Variants generated",    "lookalike_variants_generated"),
    ("Variants registered",   "lookalike_registered_total"),
    ("Class breakdown",       "lookalike_by_class"),
    ("Registered lookalikes", "lookalike_registered"),
    ("NXDOMAIN count",        "lookalike_nx_total"),
]


@router.post("/api/phishing/lookalike_domain_scan")
async def phishing_lookalike_domain_scan(req: LookalikeRequest,
                                          _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="lookalike_domain_scan",
        gather_func=_gather_with_options,
        finding_rules=LOOKALIKE_DOMAIN_SCAN_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)

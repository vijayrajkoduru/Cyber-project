"""ct_log_lookalike_scan - Certificate Transparency lookalike-domain probe
(playbook §2 #19/#20 — IDN homograph / typosquat detection, and §6 — early
warning for AI-spun phishing landing pages).

Attackers who stand up a phishing landing page on a lookalike domain almost
always obtain a TLS cert for it (Let's Encrypt makes this free + instant),
and every publicly-trusted cert is logged in Certificate Transparency (CT)
logs. This probe queries the public crt.sh CT-log mirror for certificates
whose subject/SAN contains the customer's brand keyword on a domain the
customer does NOT own — i.e. someone provisioned HTTPS for a
brand-impersonating hostname.

This is a READ-ONLY query against a public CT-log API (crt.sh). It does not
touch the customer's infrastructure or the lookalike host at all — it reads
the public record of certificate issuance.

What it does:
  1. Derive the brand keyword from the target apex domain's label
     (acme.com -> "acme"), unless options.brand_keyword overrides it.
  2. Query crt.sh for `%<brand>%` identities issued recently.
  3. Filter to certificates whose covered names contain the brand keyword
     but are NOT under the customer's own registrable domain (and not under
     an explicit owned-domains allowlist the customer can supply).
  4. Group by registered domain, keep the most-recent issuance per domain,
     and report the set of brand-impersonating certificated hostnames.

Severity model — graded ONLY on real CT-log hits:

  MEDIUM   - one or more certificates found for brand-keyword hostnames on
             domains the customer does NOT own (active impersonation infra
             with valid HTTPS) — DETECTED from the public CT record
  INFO     - crt.sh unreachable / httpx missing / no hits / brand keyword
             too short to query safely
  POSITIVE - no non-owned brand-keyword certificates found in the window

ZERO-FP guard: MEDIUM fires ONLY when crt.sh actually returned parseable
JSON rows AND at least one row's covered name contains the brand keyword on
a domain outside the owned set. We exclude the customer's own apex + www +
any options.owned_domains. We also exclude obviously-internal noise
(no covered names, wildcard-only on owned domain).

Customer input via ScanRequest.target = the brand's apex domain (acme.com).
Optional ScanRequest.options:
  - brand_keyword   = override the auto-derived keyword (e.g. "acmecorp")
  - owned_domains   = newline-separated list of domains the customer owns
                      (so legitimate brand subdomains are not flagged)
  - max_results     = cap on reported lookalike domains (default 40, cap 100)
  - timeout_sec     = crt.sh query timeout (default 20, hard cap 45)

References:
  - RFC 6962 (Certificate Transparency) · crt.sh public log mirror
  - MITRE ATT&CK T1583.001 (Acquire Infrastructure: Domains)
  - ICANN SSAC 122 (Confusable Domain Names)
"""
from __future__ import annotations
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.ct_log_lookalike_scan_findings import (
    CT_LOG_LOOKALIKE_SCAN_FINDING_RULES,
)

router = APIRouter()


class CtLookalikeRequest(ScanRequest):
    options: Optional[dict] = None


def _normalize_domain(target: str) -> str:
    d = (target or "").strip()
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split("?", 1)[0]
    if d.lower().startswith("www."):
        d = d[4:]
    return d.lower().rstrip(".")


def _registrable(host: str) -> str:
    """Best-effort registrable-domain (last two labels). We deliberately do
    NOT pull in the full public-suffix list (would need tldextract); two
    labels is good enough to separate owned brand subdomains from external
    lookalikes for the common .com/.net/.org cases the customer targets."""
    host = (host or "").lower().strip().lstrip("*.").rstrip(".")
    bits = host.split(".")
    if len(bits) <= 2:
        return host
    return ".".join(bits[-2:])


async def gather(ctx: ScanContext):
    domain = _normalize_domain(ctx.host or "")
    if not domain or "." not in domain:
        ctx.state["ctlog_error"] = "target must be a registrable domain (e.g. acme.com)"
        ctx.source("bad-target")
        return

    opts = ctx.state.get("_options") or {}
    label = domain.split(".", 1)[0]
    brand = (opts.get("brand_keyword") or label).strip().lower()
    if len(brand) < 4:
        # A keyword shorter than 4 chars makes crt.sh return enormous noise
        # and risks false attribution — bail to INFO rather than guess.
        ctx.state["ctlog_keyword_too_short"] = brand
        ctx.state["ctlog_target_domain"] = domain
        ctx.source(f"brand keyword '{brand}' too short to query safely")
        return

    try:
        timeout = min(max(int(opts.get("timeout_sec") or 20), 5), 45)
    except (TypeError, ValueError):
        timeout = 20
    try:
        max_results = min(max(int(opts.get("max_results") or 40), 1), 100)
    except (TypeError, ValueError):
        max_results = 40

    owned = {domain, f"www.{domain}", _registrable(domain)}
    for line in (opts.get("owned_domains") or "").splitlines():
        v = line.strip().lower().lstrip(".")
        if v:
            owned.add(v)
            owned.add(_registrable(v))

    ctx.state["ctlog_target_domain"] = domain
    ctx.state["ctlog_brand_keyword"] = brand
    ctx.state["ctlog_owned_domains"] = sorted(owned)

    try:
        import httpx
    except ImportError:
        ctx.state["ctlog_error"] = "httpx not installed (pip install httpx)"
        ctx.source("httpx missing")
        return

    # crt.sh JSON endpoint. %brand% matches any identity containing the
    # keyword. We read it; we do not touch any lookalike host.
    url = f"https://crt.sh/?q=%25{brand}%25&output=json"
    rows = None
    try:
        async with httpx.AsyncClient(
            verify=True, timeout=timeout, follow_redirects=True,
            headers={"User-Agent": "VulnusLab-CT-lookalike/1.0",
                     "Accept": "application/json"},
        ) as client:
            r = await client.get(url)
        if r.status_code != 200:
            ctx.state["ctlog_error"] = f"crt.sh returned HTTP {r.status_code}"
            ctx.source(f"crt.sh HTTP {r.status_code}")
            return
        try:
            rows = r.json()
        except Exception:
            # crt.sh occasionally returns NDJSON-ish; fall back to line parse.
            import json
            rows = []
            for line in (r.text or "").splitlines():
                line = line.strip().rstrip(",")
                if not line or line in ("[", "]"):
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    continue
    except Exception as e:
        ctx.state["ctlog_error"] = (
            f"crt.sh query failed: {type(e).__name__}: {str(e)[:120]}"
        )
        ctx.source("crt.sh unreachable")
        return

    if not isinstance(rows, list):
        ctx.state["ctlog_error"] = "crt.sh response was not a JSON array"
        ctx.source("crt.sh bad response")
        return

    ctx.state["ctlog_rows_seen"] = len(rows)

    # Collect distinct covered names that contain the brand keyword and are
    # NOT under an owned registrable domain.
    by_domain: dict[str, dict] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        names = set()
        nv = row.get("name_value") or ""
        for n in str(nv).splitlines():
            n = n.strip().lower().lstrip("*.")
            if n:
                names.add(n)
        cn = (row.get("common_name") or "").strip().lower().lstrip("*.")
        if cn:
            names.add(cn)
        not_after = row.get("not_after") or row.get("entry_timestamp") or ""
        issuer = row.get("issuer_name") or ""
        for n in names:
            if brand not in n:
                continue
            reg = _registrable(n)
            if reg in owned or n in owned:
                continue   # legitimate owned brand hostname
            entry = by_domain.setdefault(reg, {
                "registered_domain": reg,
                "hostnames": set(),
                "last_seen": "",
                "issuer": "",
            })
            entry["hostnames"].add(n)
            if not_after and not_after > entry["last_seen"]:
                entry["last_seen"] = not_after
                entry["issuer"] = str(issuer)[:120]

    lookalikes = []
    for reg, e in by_domain.items():
        lookalikes.append({
            "registered_domain": reg,
            "hostnames": sorted(e["hostnames"])[:10],
            "last_seen": e["last_seen"],
            "issuer": e["issuer"],
        })
    # Most-recently-issued first.
    lookalikes.sort(key=lambda x: x.get("last_seen") or "", reverse=True)
    lookalikes = lookalikes[:max_results]

    ctx.state["ctlog_lookalike_domains"] = lookalikes
    ctx.state["ctlog_lookalike_count"] = len(lookalikes)
    ctx.state["ctlog_queried"] = True
    ctx.source(
        f"crt.sh q=%{brand}% -> {len(rows)} cert rows, "
        f"{len(lookalikes)} non-owned brand-keyword domain(s)"
    )


INTEL_FIELDS = [
    ("Target domain",            "ctlog_target_domain"),
    ("Brand keyword",            "ctlog_brand_keyword"),
    ("Owned domains (excluded)", "ctlog_owned_domains"),
    ("CT-log rows seen",         "ctlog_rows_seen"),
    ("Lookalike domains found",  "ctlog_lookalike_count"),
    ("Lookalike certificates",   "ctlog_lookalike_domains"),
]


@router.post("/api/phishing/ct_log_lookalike_scan")
async def phishing_ct_log_lookalike_scan(req: CtLookalikeRequest,
                                         _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="ct_log_lookalike_scan",
        gather_func=_gather_with_options,
        finding_rules=CT_LOG_LOOKALIKE_SCAN_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)

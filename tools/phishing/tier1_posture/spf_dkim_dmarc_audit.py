"""spf_dkim_dmarc_audit - SPF / DMARC / DKIM TXT-record audit
(playbook §1 #5/#6).

For the target email domain (e.g. acme.com), uses dnspython to query:

  - SPF       : TXT records on <domain> looking for `v=spf1 ...`
  - DMARC     : TXT records on `_dmarc.<domain>` looking for `v=DMARC1 ...`
  - DKIM      : TXT records on `<selector>._domainkey.<domain>` for a
                rotating list of common selectors (default, google, k1,
                selector1, selector2, mandrill, mail, dkim, dkim1)

Each record is parsed into its component tags and reported:

  CRITICAL - no DMARC record at all
  HIGH     - SPF contains `+all` (anyone can send as your domain)
  HIGH     - DMARC `p=none` (policy is monitor-only — spoofed mail is
             delivered to the recipient)
  HIGH     - SPF has `~all` AND DMARC `p=quarantine`/`none` (partial)
  MEDIUM   - no SPF record present
  MEDIUM   - no DKIM selector found for ANY common selector
  POSITIVE - DMARC `p=reject` + SPF `-all` + at least one DKIM selector

Customer input via ScanRequest.target = email domain
(e.g. "acme.com" — strip any leading "www." automatically).
Optional ScanRequest.options.dkim_selectors = newline-separated extra
selectors to try (customer can add tenant-specific ones).

References:
  - RFC 7208 (SPF)
  - RFC 6376 (DKIM-Signatures)
  - RFC 7489 (DMARC)
  - https://dmarc.org/wiki/FAQ
"""
from __future__ import annotations
import re
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.spf_dkim_dmarc_audit_findings import (
    SPF_DKIM_DMARC_AUDIT_FINDING_RULES,
)

router = APIRouter()


class SpfDkimDmarcRequest(ScanRequest):
    options: Optional[dict] = None


# Common DKIM selectors used by major mail providers / mass-mailer SaaS.
# Order matters: hit the high-prevalence ones first so the first match
# wins quickly without 9 queries against a stale DNS resolver.
DEFAULT_DKIM_SELECTORS = [
    "default",       # generic
    "google",        # Google Workspace
    "selector1",     # Microsoft 365
    "selector2",     # Microsoft 365 (rotated key)
    "k1",            # Mailchimp, SendGrid sub-account
    "k2",            # Mailchimp rotated
    "mandrill",      # Mandrill / Mailchimp Transactional
    "mail",          # generic legacy
    "dkim",          # generic legacy
    "dkim1",         # generic / Postmark
    "smtpapi",       # SendGrid main
    "scph0922",      # SparkPost rotating
    "amazonses",     # AWS SES
    "zendesk1",      # Zendesk
    "zendesk2",      # Zendesk
]


def _normalize_domain(target: str) -> str:
    """Strip scheme + leading www. from any target string."""
    d = (target or "").strip()
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split("?", 1)[0]
    if d.lower().startswith("www."):
        d = d[4:]
    return d.lower().rstrip(".")


def _parse_spf(record: str) -> dict:
    """Return parsed SPF tags + the policy qualifier on the trailing 'all'."""
    out: dict = {
        "raw":         record,
        "version":     None,
        "mechanisms":  [],
        "all_qualifier": None,   # +/-/~/?
        "includes":    [],
    }
    if not record:
        return out
    tokens = record.strip().split()
    if tokens and tokens[0].lower() == "v=spf1":
        out["version"] = "spf1"
    for tok in tokens:
        out["mechanisms"].append(tok)
        if tok.lower().startswith("include:"):
            out["includes"].append(tok.split(":", 1)[1])
        if tok.lower().endswith("all"):
            # Qualifier is the first char unless it's just 'all'
            if tok[:1] in ("+", "-", "~", "?"):
                out["all_qualifier"] = tok[:1]
            elif tok.lower() == "all":
                out["all_qualifier"] = "+"   # default qualifier = +
    return out


def _parse_dmarc(record: str) -> dict:
    """Return parsed DMARC tags (RFC 7489 §6.3)."""
    out: dict = {
        "raw":      record,
        "version":  None,
        "p":        None,   # policy
        "sp":       None,   # subdomain policy
        "rua":      None,   # aggregate report URI
        "ruf":      None,   # forensic report URI
        "adkim":    None,   # DKIM alignment (r=relaxed, s=strict)
        "aspf":     None,   # SPF alignment
        "pct":      None,
        "fo":       None,
    }
    if not record:
        return out
    for part in record.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        k = k.strip().lower(); v = v.strip()
        if k == "v":
            out["version"] = v
        elif k in out:
            out[k] = v
    return out


async def _resolve_txt(domain: str, dns_module) -> list[str]:
    """Resolve TXT records for `domain`; return list of joined-up strings
    (DNS TXT can split into multiple character-strings — join them)."""
    try:
        ans = dns_module.resolver.resolve(domain, "TXT", lifetime=8.0)
    except dns_module.resolver.NXDOMAIN:
        return []
    except dns_module.resolver.NoAnswer:
        return []
    except Exception:
        return []
    out = []
    for r in ans:
        try:
            parts = []
            for s in r.strings:
                parts.append(s.decode("utf-8", errors="ignore")
                             if isinstance(s, (bytes, bytearray)) else str(s))
            out.append("".join(parts))
        except Exception:
            try:
                out.append(str(r).strip('"'))
            except Exception:
                continue
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
        ctx.state["spf_dkim_dmarc_error"] = (
            "dnspython not installed (pip install dnspython)"
        )
        ctx.source("dnspython missing")
        return

    opts = ctx.state.get("_options") or {}
    extra_raw = (opts.get("dkim_selectors") or "").strip()
    extra_selectors: list[str] = []
    if extra_raw:
        for line in extra_raw.splitlines():
            v = line.strip()
            if v and v not in DEFAULT_DKIM_SELECTORS and v not in extra_selectors:
                extra_selectors.append(v)
    selectors = DEFAULT_DKIM_SELECTORS + extra_selectors[:10]   # clamp +10

    # ---- SPF -------------------------------------------------------
    spf_records = []
    try:
        txt = await _resolve_txt(domain, dns)
    except Exception as e:
        ctx.state["spf_dkim_dmarc_error"] = (
            f"SPF lookup failed for {domain}: {type(e).__name__}"
        )
        txt = []
    for rec in txt:
        if re.match(r"^\s*v=spf1\b", rec, re.IGNORECASE):
            spf_records.append(_parse_spf(rec))
    ctx.source(f"dig TXT {domain} -> {len(spf_records)} SPF record(s)")

    # ---- DMARC -----------------------------------------------------
    dmarc_records = []
    try:
        dmarc_txt = await _resolve_txt(f"_dmarc.{domain}", dns)
    except Exception:
        dmarc_txt = []
    for rec in dmarc_txt:
        if re.match(r"^\s*v=DMARC1\b", rec, re.IGNORECASE):
            dmarc_records.append(_parse_dmarc(rec))
    ctx.source(f"dig TXT _dmarc.{domain} -> {len(dmarc_records)} DMARC record(s)")

    # ---- DKIM selectors -------------------------------------------
    dkim_found: list[dict] = []
    dkim_tried: list[str] = []
    for sel in selectors:
        dkim_tried.append(sel)
        try:
            sel_txt = await _resolve_txt(f"{sel}._domainkey.{domain}", dns)
        except Exception:
            sel_txt = []
        for rec in sel_txt:
            # DKIM TXT records typically start with v=DKIM1 (some omit version)
            if "k=" in rec.lower() or "p=" in rec.lower() or rec.lower().startswith("v=dkim1"):
                dkim_found.append({
                    "selector": sel,
                    "preview":  rec[:120] + ("..." if len(rec) > 120 else ""),
                    "has_v":    "v=dkim1" in rec.lower(),
                    "has_p":    "p=" in rec.lower(),
                })
                break   # one record per selector is enough
    ctx.source(
        f"DKIM selectors probed: {len(dkim_tried)}, found: {len(dkim_found)}"
    )

    # ---- Stash state -----------------------------------------------
    ctx.state["spf_target_domain"]   = domain
    ctx.state["spf_records"]         = spf_records
    ctx.state["dmarc_records"]       = dmarc_records
    ctx.state["dkim_selectors_tried"] = dkim_tried
    ctx.state["dkim_selectors_found"] = dkim_found
    ctx.state["spf_present"]   = bool(spf_records)
    ctx.state["dmarc_present"] = bool(dmarc_records)
    ctx.state["dkim_present"]  = bool(dkim_found)

    # Easy-evaluate flags for the rules engine
    if spf_records:
        first_spf = spf_records[0]
        ctx.state["spf_all_qualifier"] = first_spf.get("all_qualifier")
    if dmarc_records:
        first_d = dmarc_records[0]
        ctx.state["dmarc_p"]  = (first_d.get("p")  or "").lower()
        ctx.state["dmarc_sp"] = (first_d.get("sp") or "").lower()
        ctx.state["dmarc_pct"] = first_d.get("pct")


INTEL_FIELDS = [
    ("Target domain",         "spf_target_domain"),
    ("SPF records",           "spf_records"),
    ("DMARC records",         "dmarc_records"),
    ("DKIM selectors tried",  "dkim_selectors_tried"),
    ("DKIM selectors found",  "dkim_selectors_found"),
    ("SPF 'all' qualifier",   "spf_all_qualifier"),
    ("DMARC policy",          "dmarc_p"),
]


@router.post("/api/phishing/spf_dkim_dmarc_audit")
async def phishing_spf_dkim_dmarc_audit(req: SpfDkimDmarcRequest,
                                         _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="spf_dkim_dmarc_audit",
        gather_func=_gather_with_options,
        finding_rules=SPF_DKIM_DMARC_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)

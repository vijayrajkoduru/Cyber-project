"""Email Security v1 — VL-FORGE pattern.

Route: /api/recon/email_security

Deep SPF / DMARC / DKIM analysis (we already pull TXT records via dns/dnsrecon
but don't EVALUATE them). This tool validates the records against RFC + best
practices and flags spoofing risks.

Sources (parallel):
  1. SPF record fetch + lookup-count audit (RFC 7208 — max 10 DNS lookups)
  2. DMARC record fetch + policy strength check
  3. DKIM probe — 10 common selectors at <selector>._domainkey.<host>
  4. MTA-STS / TLS-RPT (deliverability signals)
"""
import asyncio
import re

import dns.asyncresolver

from fastapi import APIRouter, Depends

from tools._shared import (ScanRequest, verify_scan_quota, recon_host)
from tools._framework import ScanContext, run_scanner
from tools._payloads.tier6_findings import EMAIL_SECURITY_FINDING_RULES

router = APIRouter()


_DKIM_SELECTORS = [
    "google", "k1", "k2", "selector1", "selector2",
    "mandrill", "mxvault", "default", "dkim", "smtp",
]


async def _resolve_txt(name):
    """Return concatenated TXT record strings, or None."""
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 4
        resolver.lifetime = 4
        ans = await resolver.resolve(name, "TXT")
        out = []
        for r in ans:
            out.append("".join(s.decode() if isinstance(s, bytes) else str(s)
                                for s in r.strings))
        return "\n".join(out)
    except Exception:
        return None


def _count_spf_lookups(spf_text):
    """RFC 7208 — count DNS-querying mechanisms: include, a, mx, ptr, exists, redirect."""
    if not spf_text: return 0
    count = 0
    count += len(re.findall(r"\binclude:", spf_text))
    count += len(re.findall(r"\ba(?::|/|\s|$)", spf_text))
    count += len(re.findall(r"\bmx(?::|/|\s|$)", spf_text))
    count += len(re.findall(r"\bptr(?::|\s|$)", spf_text))
    count += len(re.findall(r"\bexists:", spf_text))
    count += len(re.findall(r"\bredirect=", spf_text))
    return count


async def gather(ctx: ScanContext):
    host = ctx.host
    ctx.state["host"] = host
    ctx.state["scanned"] = True

    # Parallel: SPF, DMARC, MTA-STS
    spf_raw, dmarc_raw, mtasts = await asyncio.gather(
        _resolve_txt(host),
        _resolve_txt(f"_dmarc.{host}"),
        _resolve_txt(f"_mta-sts.{host}"),
    )

    # Extract SPF line (TXT may contain multiple records)
    spf_record = None
    if spf_raw:
        for line in spf_raw.split("\n"):
            if line.strip().lower().startswith("v=spf1"):
                spf_record = line.strip()
                break
    ctx.state["spf_record"] = spf_record
    if spf_record:
        ctx.state["spf_dns_lookups"] = _count_spf_lookups(spf_record)
        ctx.source("spf-record-fetch")

    # DMARC
    dmarc_record = None
    if dmarc_raw:
        for line in dmarc_raw.split("\n"):
            if line.strip().lower().startswith("v=dmarc1"):
                dmarc_record = line.strip()
                break
    ctx.state["dmarc_record"] = dmarc_record
    if dmarc_record:
        ctx.source("dmarc-record-fetch")

    # MTA-STS (informational — indicates modern email security posture)
    if mtasts:
        ctx.state["mta_sts"] = mtasts[:300]
        ctx.source("mta-sts-record-fetch")

    # DKIM — probe selectors in parallel
    dkim_results = await asyncio.gather(*[
        _resolve_txt(f"{sel}._domainkey.{host}") for sel in _DKIM_SELECTORS
    ])
    found_selectors = []
    for sel, txt in zip(_DKIM_SELECTORS, dkim_results):
        if txt and ("v=DKIM1" in txt or "p=" in txt):
            found_selectors.append({"selector": sel, "key_preview": txt[:80]})
    ctx.state["dkim_selectors_found"] = found_selectors
    ctx.state["selectors_probed"]     = len(_DKIM_SELECTORS)
    ctx.state["selectors_probed_list"] = _DKIM_SELECTORS
    if found_selectors:
        ctx.source(f"dkim-selector-found ({len(found_selectors)})")
    else:
        ctx.source(f"dkim-probe ({len(_DKIM_SELECTORS)} selectors)")


INTEL_FIELDS = [
    ("SPF record",           "spf_display"),
    ("SPF DNS lookups",     "spf_dns_lookups"),
    ("DMARC record",         "dmarc_display"),
    ("DKIM selectors",       "dkim_display"),
    ("MTA-STS",              "mta_sts"),
]


@router.post("/api/recon/email_security")
async def recon_email_security(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        if ctx.state.get("spf_record"):
            ctx.state["spf_display"] = ctx.state["spf_record"][:140]
        else:
            ctx.state["spf_display"] = "NOT SET — domain is spoofable"
        if ctx.state.get("dmarc_record"):
            ctx.state["dmarc_display"] = ctx.state["dmarc_record"][:140]
        else:
            ctx.state["dmarc_display"] = "NOT SET — receivers can't act on spoofing"
        ds = ctx.state.get("dkim_selectors_found") or []
        if ds:
            ctx.state["dkim_display"] = (
                f"{len(ds)} found: " + ", ".join(d.get("selector","?") for d in ds[:5]))
        else:
            ctx.state["dkim_display"] = (
                f"None responded among {ctx.state.get('selectors_probed',0)} common selectors")

    return await run_scanner(
        host=host, tool="email_security",
        gather_func=gather_with_display,
        finding_rules=EMAIL_SECURITY_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["spf_record", "dmarc_record", "dkim_selectors_found"],
    )


def register(app):
    app.include_router(router)

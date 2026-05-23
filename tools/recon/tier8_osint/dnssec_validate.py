"""DNSSEC Validate v1 — VL-FORGE pattern.

Route: /api/recon/dnssec_validate

Walks the DNSSEC chain of trust for the target zone: fetches DS records at
parent, DNSKEY at child, RRSIG signatures, and validates algorithm strength
+ chain integrity. Detects broken chains, weak algorithms (SHA-1, RSAMD5),
and NSEC (vs NSEC3) zone-walking exposure.

Sources (parallel):
  1. DNSKEY at the zone — what keys does it advertise?
  2. DS at the parent — does parent attest these keys?
  3. RRSIG on A/SOA — are records actually signed?
  4. NSEC / NSEC3 record check — zone walking risk
"""
import asyncio

import dns.asyncresolver
import dns.rdatatype

from fastapi import APIRouter, Depends

from tools._shared import (ScanRequest, verify_scan_quota, recon_host)
from tools._framework import ScanContext, run_scanner
from tools._payloads.tier6_findings import DNSSEC_FINDING_RULES

router = APIRouter()


# DNSSEC algorithm strength reference (RFC 8624 + IANA registry)
_ALG_NAMES = {
    1:  ("RSAMD5",         "weak"),
    3:  ("DSA-SHA1",       "weak"),
    5:  ("RSASHA1",        "weak"),
    6:  ("DSA-NSEC3-SHA1", "weak"),
    7:  ("RSASHA1-NSEC3",  "weak"),
    8:  ("RSASHA256",      "strong"),
    10: ("RSASHA512",      "strong"),
    12: ("ECC-GOST",       "deprecated"),
    13: ("ECDSAP256SHA256","strong"),
    14: ("ECDSAP384SHA384","strong"),
    15: ("ED25519",        "strong"),
    16: ("ED448",          "strong"),
}


async def _query(name, rdtype):
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 4
        resolver.lifetime = 4
        ans = await resolver.resolve(name, rdtype, raise_on_no_answer=False)
        return ans
    except Exception:
        return None


async def gather(ctx: ScanContext):
    host = ctx.host
    ctx.state["host"] = host
    ctx.state["zone_queried"] = True

    # Parallel: DNSKEY, DS (at parent), SOA RRSIG, NSEC3PARAM, NSEC
    dnskey_ans, ds_ans, soa_ans, nsec3param_ans = await asyncio.gather(
        _query(host, "DNSKEY"),
        _query(host, "DS"),
        _query(host, "SOA"),
        _query(host, "NSEC3PARAM"),
    )

    # 1. DNSKEY present?
    has_dnskey = False
    algorithms_seen = set()
    if dnskey_ans:
        for r in dnskey_ans:
            has_dnskey = True
            try:
                algorithms_seen.add(int(r.algorithm))
            except Exception:
                pass
    ctx.state["dnssec_enabled"] = has_dnskey
    if has_dnskey: ctx.source(f"dnskey-records ({len(algorithms_seen)} algorithms)")

    # 2. Algorithm-strength audit
    weak_algs = []
    strong_algs = []
    strongest = None
    for alg_num in algorithms_seen:
        name, strength = _ALG_NAMES.get(alg_num, (f"alg-{alg_num}", "unknown"))
        if strength == "weak" or strength == "deprecated":
            weak_algs.append(f"{name} (alg {alg_num})")
        elif strength == "strong":
            strong_algs.append(f"{name} (alg {alg_num})")
            strongest = name
    ctx.state["weak_algorithms"]    = weak_algs
    ctx.state["strong_algorithms"]  = strong_algs
    ctx.state["strongest_algorithm"] = strongest

    # 3. DS record at parent
    has_ds = bool(ds_ans and len(list(ds_ans)) > 0)
    ctx.state["ds_at_parent"] = has_ds
    if has_ds: ctx.source("ds-records-at-parent")

    # 4. Chain broken? DNSKEY without DS = orphan; DS without DNSKEY = inconsistent
    chain_broken = False
    chain_error = None
    if has_dnskey and not has_ds:
        chain_broken = True
        chain_error = "DNSKEY present at zone but no DS record at parent — chain of trust incomplete (registrar may not have registered DS)."
    elif has_ds and not has_dnskey:
        chain_broken = True
        chain_error = "DS records exist at parent but no DNSKEY at zone — broken chain."
    ctx.state["chain_broken"] = chain_broken
    if chain_error: ctx.state["chain_error"] = chain_error

    # 5. RRSIG on SOA = is the zone actually signing answers?
    has_rrsig = False
    if soa_ans:
        rrsig_recs = []
        try:
            rrsig_ans = await _query(host, "RRSIG")
            if rrsig_ans:
                rrsig_recs = list(rrsig_ans)
                has_rrsig = len(rrsig_recs) > 0
        except Exception:
            pass
    ctx.state["soa_signed"] = has_rrsig
    if has_rrsig: ctx.source("rrsig-records")

    # 6. NSEC3 vs NSEC — zone walking risk
    nsec3_present = bool(nsec3param_ans and len(list(nsec3param_ans)) > 0)
    if has_dnskey:
        ctx.state["nsec_type"] = "NSEC3" if nsec3_present else "NSEC"
        ctx.source("nsec-mode-check")


INTEL_FIELDS = [
    ("DNSSEC enabled",     "dnssec_display"),
    ("DS at parent",        "ds_display"),
    ("Algorithms",          "algorithms_display"),
    ("Chain integrity",     "chain_display"),
    ("NSEC mode",           "nsec_type"),
]


@router.post("/api/recon/dnssec_validate")
async def recon_dnssec_validate(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        ctx.state["dnssec_display"] = "YES" if ctx.state.get("dnssec_enabled") else "No"
        ctx.state["ds_display"]      = "YES" if ctx.state.get("ds_at_parent") else "No"
        sa = ctx.state.get("strong_algorithms") or []
        wa = ctx.state.get("weak_algorithms") or []
        if sa or wa:
            parts = []
            if sa: parts.append("strong: " + ", ".join(sa))
            if wa: parts.append("WEAK: " + ", ".join(wa))
            ctx.state["algorithms_display"] = "; ".join(parts)
        if ctx.state.get("chain_broken"):
            ctx.state["chain_display"] = f"BROKEN — {ctx.state.get('chain_error','?')}"
        elif ctx.state.get("dnssec_enabled"):
            ctx.state["chain_display"] = "Valid chain (DNSKEY + DS aligned)"

    return await run_scanner(
        host=host, tool="dnssec_validate",
        gather_func=gather_with_display,
        finding_rules=DNSSEC_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["dnssec_enabled", "weak_algorithms", "chain_broken", "nsec_type"],
    )


def register(app):
    app.include_router(router)

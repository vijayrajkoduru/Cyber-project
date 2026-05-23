"""Cert Transparency v2 — VL-FORGE pattern, CT-log intelligence.

Route: /api/recon/crtsh

Distinct from Subdomain Discovery (which uses crt.sh as ONE source).
Cert Transparency analyzes CERTS THEMSELVES — wildcards, internal
hostname leaks, staging exposure, CA diversity, issuance cadence.

Sources (parallel):
  1. crt.sh (primary CT log aggregator)
  2. certspotter (secondary CT source — pre-cert + final)
  3. Recent-issuance window analysis (30-day burst detection)

Findings (~9 rules):
  HIGH    : internal hostnames leaked in SANs
  MEDIUM  : wildcard certs, staging envs exposed in SANs
  LOW     : single-CA dependency
  POSITIVE: multi-CA strategy, mature CT footprint
  INFO    : total certs, unique SANs count, recent burst
"""
import asyncio
import datetime
import re

import requests

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools._payloads.certtrans_findings import (
    CERTTRANS_FINDING_RULES, classify_hostname,
)

router = APIRouter()


def _fetch_crtsh(host: str) -> list:
    """Fetch raw cert records from crt.sh."""
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{host}&output=json",
                          timeout=25, verify=False,
                          headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code != 200: return []
        return r.json() or []
    except Exception:
        return []


def _fetch_certspotter(host: str) -> list:
    """Fetch from certspotter (alt CT source)."""
    try:
        r = requests.get(
            f"https://api.certspotter.com/v1/issuances?domain={host}"
            f"&include_subdomains=true&expand=dns_names&expand=issuer",
            timeout=20, verify=False,
            headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code != 200: return []
        return r.json() or []
    except Exception:
        return []


def _normalize_crtsh(rows: list, host: str) -> list:
    out = []
    for row in rows[:3000]:
        nv = (row.get("name_value") or "").lower()
        names = []
        had_wildcard = False
        for n in nv.split("\n"):
            n_raw = n.strip()
            if "*" in n_raw: had_wildcard = True
            n_clean = n_raw.lstrip("*.")
            if n_clean == host or n_clean.endswith("." + host):
                names.append(n_clean)
        if not names: continue
        out.append({
            "id":         row.get("id"),
            "names":      names,
            "issuer":     (row.get("issuer_name") or "")[:80],
            "not_before": row.get("not_before"),
            "not_after":  row.get("not_after"),
            "wildcard":   had_wildcard,
            "source":     "crt.sh",
        })
    return out


def _normalize_certspotter(rows: list, host: str) -> list:
    out = []
    for row in rows[:1000]:
        raw_names = row.get("dns_names") or []
        names = []
        had_wildcard = False
        for n in raw_names:
            ns = str(n).strip().lower()
            if "*" in ns: had_wildcard = True
            nc = ns.lstrip("*.")
            if nc == host or nc.endswith("." + host):
                names.append(nc)
        if not names: continue
        issuer_obj = row.get("issuer") or {}
        out.append({
            "id":         row.get("id"),
            "names":      names,
            "issuer":     (issuer_obj.get("name") if isinstance(issuer_obj, dict)
                           else str(issuer_obj))[:80],
            "not_before": row.get("not_before"),
            "not_after":  row.get("not_after"),
            "wildcard":   had_wildcard,
            "source":     "certspotter",
        })
    return out


async def gather(ctx: ScanContext):
    host = ctx.host

    crtsh_raw, cs_raw = await asyncio.gather(
        asyncio.to_thread(_fetch_crtsh, host),
        asyncio.to_thread(_fetch_certspotter, host),
    )

    crtsh_certs = _normalize_crtsh(crtsh_raw, host)
    cs_certs = _normalize_certspotter(cs_raw, host)

    if crtsh_certs: ctx.source(f"crt.sh ({len(crtsh_certs)} certs)")
    if cs_certs: ctx.source(f"certspotter ({len(cs_certs)} certs)")

    # Dedupe by id (or names-hash if id missing)
    seen = set()
    all_certs = []
    for cert in crtsh_certs + cs_certs:
        key = cert.get("id") or (cert.get("source"), tuple(cert["names"]),
                                   cert.get("not_before"))
        if key in seen: continue
        seen.add(key)
        all_certs.append(cert)
    ctx.state["certs"] = all_certs

    # Unique SANs across all certs
    unique_sans = set()
    for c in all_certs:
        for n in c["names"]:
            unique_sans.add(n)
    ctx.state["unique_sans"] = unique_sans

    # Wildcards
    wildcards = {c["names"][0] for c in all_certs
                 if c.get("wildcard") and c["names"]}
    ctx.state["wildcard_certs"] = sorted(wildcards)[:10]

    # Internal / staging classification
    internal_hostnames = set()
    staging_envs = set()
    for san in unique_sans:
        is_internal, is_staging = classify_hostname(san)
        if is_internal: internal_hostnames.add(san)
        if is_staging: staging_envs.add(san)
    ctx.state["internal_hostnames"] = sorted(internal_hostnames)
    ctx.state["staging_envs"] = sorted(staging_envs)

    # CA diversity
    issuers = {}
    for c in all_certs:
        iss = (c.get("issuer") or "unknown").strip()
        m = re.search(r"CN=([^,]+)", iss)
        ca = (m.group(1).strip() if m else iss.split(",")[0].strip())[:50]
        issuers[ca] = issuers.get(ca, 0) + 1
    ctx.state["issuers"] = issuers
    if len(issuers) >= 2:
        ctx.source("ca-diversity-analysis")

    # Recent cert burst + oldest cert age
    now = datetime.datetime.utcnow()
    recent = []
    oldest_age = None
    for c in all_certs:
        nb = c.get("not_before")
        if not nb: continue
        try:
            dt = datetime.datetime.fromisoformat(
                str(nb).replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            try:
                dt = datetime.datetime.strptime(str(nb)[:19],
                                                  "%Y-%m-%dT%H:%M:%S")
            except Exception:
                continue
        age_days = (now - dt).days
        if 0 <= age_days <= 30:
            recent.append(c)
        if oldest_age is None or age_days > oldest_age:
            oldest_age = age_days
    ctx.state["recent_certs"] = recent
    if oldest_age is not None:
        ctx.state["oldest_cert_age_days"] = oldest_age
        ctx.source("issuance-window-30d")

    # Backwards-compat: subdomains[] + total_subdomains at top level
    ctx.state["subdomains"] = sorted(unique_sans)
    ctx.state["total_subdomains"] = len(unique_sans)


INTEL_FIELDS = [
    ("Total certificates",        "cert_count_display"),
    ("Unique hostnames in SANs",  "unique_sans_count"),
    ("Wildcard certs",            "wildcard_display"),
    ("Internal hostnames leaked", "internal_display"),
    ("Staging envs in SANs",      "staging_display"),
    ("Issuing CAs",               "issuers_display"),
    ("Recent issuance (30d)",     "recent_count_display"),
    ("Oldest cert age",           "oldest_age_display"),
]


@router.post("/api/recon/crtsh")
async def recon_crtsh(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        certs = ctx.state.get("certs") or []
        if certs:
            ctx.state["cert_count_display"] = (
                f"{len(certs)} unique certs across CT logs")
        sans = ctx.state.get("unique_sans") or set()
        if sans:
            ctx.state["unique_sans_count"] = len(sans)
        wc = ctx.state.get("wildcard_certs") or []
        if wc:
            ctx.state["wildcard_display"] = ", ".join(wc[:5])
        ih = ctx.state.get("internal_hostnames") or []
        if ih:
            ctx.state["internal_display"] = ", ".join(ih[:5])
        se = ctx.state.get("staging_envs") or []
        if se:
            ctx.state["staging_display"] = ", ".join(se[:5])
        iss = ctx.state.get("issuers") or {}
        if iss:
            ctx.state["issuers_display"] = ", ".join(
                f"{ca}({n})" for ca, n in sorted(
                    iss.items(), key=lambda kv: -kv[1])[:4])
        rc = ctx.state.get("recent_certs") or []
        if rc:
            ctx.state["recent_count_display"] = (
                f"{len(rc)} certs issued in last 30 days")
        oa = ctx.state.get("oldest_cert_age_days")
        if oa is not None:
            ctx.state["oldest_age_display"] = (
                f"{oa} days ({oa//365} years)" if oa >= 365 else f"{oa} days")

    return await run_scanner(
        host=host,
        tool="crtsh",
        gather_func=gather_with_display,
        finding_rules=CERTTRANS_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["subdomains", "total_subdomains"],
    )


def register(app):
    app.include_router(router)

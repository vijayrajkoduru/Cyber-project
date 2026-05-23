"""OSINT Harvesting v2 — VL-FORGE pattern.

Route: /api/recon/harvester

Sources (parallel):
  1. theHarvester binary (if installed — uses duckduckgo+bing+crtsh)
  2. crt.sh cert-transparency host extraction
  3. HackerTarget passive DNS reverse-lookup
  4. AlienVault OTX passive DNS
"""
import asyncio
import re
import shutil

import requests

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools._payloads.harvester_findings import HARVESTER_FINDING_RULES

router = APIRouter()


async def _theharvester(domain):
    """Run theHarvester binary if available. Returns (emails, hosts)."""
    if not shutil.which("theHarvester"):
        return [], [], False
    try:
        proc = await asyncio.create_subprocess_exec(
            "theHarvester", "-d", domain, "-b", "duckduckgo,bing,crtsh",
            "-l", "50",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=4 * 1024 * 1024,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=45)
            output = (stdout or b"").decode("utf-8", errors="ignore")
        except asyncio.TimeoutError:
            try: proc.kill()
            except: pass
            return [], [], False
        emails = set()
        hosts = set()
        for m in re.finditer(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", output):
            e = m.group(0).lower()
            if domain.lower() in e: emails.add(e)
        for m in re.finditer(rf"\b([a-zA-Z0-9-]+\.{re.escape(domain)})\b", output):
            h = m.group(0).lower()
            if h != domain.lower(): hosts.add(h)
        return sorted(emails), sorted(hosts), True
    except Exception:
        return [], [], False


def _crtsh_hosts(domain):
    try:
        r = requests.get(f"https://crt.sh/?q={domain}&output=json", timeout=15,
                          verify=False, headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code != 200: return []
        hosts = set()
        for cert in r.json()[:300]:
            nv = (cert.get("name_value") or "").lower()
            for line in nv.split("\n"):
                line = line.strip().lstrip("*.")
                if line.endswith(domain) and "*" not in line:
                    hosts.add(line)
        return sorted(hosts)
    except Exception:
        return []


def _hackertarget(domain):
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}",
                          timeout=12, verify=False,
                          headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code != 200: return []
        hosts = set()
        for line in r.text.splitlines():
            if "," in line:
                h = line.split(",", 1)[0].strip().lower()
                if h.endswith(domain): hosts.add(h)
        return sorted(hosts)
    except Exception:
        return []


def _alienvault(domain):
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=12, verify=False,
            headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code != 200: return []
        data = r.json()
        hosts = set()
        for entry in (data.get("passive_dns") or [])[:500]:
            h = (entry.get("hostname") or "").lower()
            if h.endswith(domain): hosts.add(h)
        return sorted(hosts)
    except Exception:
        return []


async def gather(ctx: ScanContext):
    domain = ctx.host

    # Fire all sources in parallel
    th_emails, th_hosts, th_succeeded = await _theharvester(domain)
    crt_hosts, ht_hosts, av_hosts = await asyncio.gather(
        asyncio.to_thread(_crtsh_hosts, domain),
        asyncio.to_thread(_hackertarget, domain),
        asyncio.to_thread(_alienvault, domain),
    )

    sources_used_internal = []
    all_hosts = set(th_hosts)
    if th_succeeded:
        ctx.source("theHarvester (DDG+Bing+crtsh)")
        sources_used_internal.append("theHarvester")
    if crt_hosts:
        all_hosts.update(crt_hosts)
        ctx.source(f"crt.sh ({len(crt_hosts)})")
        sources_used_internal.append("crt.sh")
    if ht_hosts:
        all_hosts.update(ht_hosts)
        ctx.source(f"hackertarget ({len(ht_hosts)})")
        sources_used_internal.append("hackertarget")
    if av_hosts:
        all_hosts.update(av_hosts)
        ctx.source(f"alienvault-otx ({len(av_hosts)})")
        sources_used_internal.append("alienvault-otx")

    ctx.state["emails"] = sorted(set(th_emails))[:50]
    ctx.state["hosts"] = sorted(all_hosts)[:200]
    ctx.state["sources_used_internal"] = sources_used_internal
    ctx.state["host_count_per_source"] = {
        "theHarvester": len(th_hosts), "crt.sh": len(crt_hosts),
        "hackertarget": len(ht_hosts), "alienvault-otx": len(av_hosts),
    }


INTEL_FIELDS = [
    ("Emails found",       "email_count_display"),
    ("Hosts found",         "host_count_display"),
    ("Sources contributed", "sources_breakdown_display"),
    ("Sample emails",       "sample_emails_display"),
    ("Sample hosts",        "sample_hosts_display"),
]


@router.post("/api/recon/harvester")
async def recon_harvester(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        emails = ctx.state.get("emails") or []
        if emails:
            ctx.state["email_count_display"] = f"{len(emails)} unique"
            ctx.state["sample_emails_display"] = ", ".join(emails[:5])
        hosts = ctx.state.get("hosts") or []
        if hosts:
            ctx.state["host_count_display"] = f"{len(hosts)} unique"
            ctx.state["sample_hosts_display"] = ", ".join(hosts[:5])
        sb = ctx.state.get("host_count_per_source") or {}
        if sb:
            ctx.state["sources_breakdown_display"] = ", ".join(
                f"{k}({v})" for k, v in sb.items() if v)

    return await run_scanner(
        host=host, tool="harvester",
        gather_func=gather_with_display,
        finding_rules=HARVESTER_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["emails", "hosts"],
    )


def register(app):
    app.include_router(router)

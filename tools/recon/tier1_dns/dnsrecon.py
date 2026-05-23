"""DNS Recon Intelligence — second tool built through tools/_framework.

Route: /api/recon/dnsrecon

Distinct from /api/recon/dns (which grades email-auth posture). DNS Recon
focuses on PENETRATION-TEST RECON operations against DNS infrastructure:

Multi-source async gathering (8 sources in parallel):
  1. A/AAAA resolution                  5. NSEC walk attempt
  2. PTR (reverse DNS) per IP           6. SRV records (17 service types)
  3. DNSKEY (DNSSEC apex keys)          7. Cross-resolver query (1.1.1.1)
  4. DS (parent-zone delegation)        8. Cross-resolver query (8.8.8.8)
                                        + Cross-resolver query (9.9.9.9)

Then runs 13 findings rules (tools/_payloads/dnsrecon_findings.py):
  - DNSSEC chain: fully signed / partial-broken / unsigned
  - Cross-resolver: consistent / mismatch (DNS hijacking risk)
  - PTR: all configured / missing / forward-reverse mismatch
  - NSEC: walkable / NSEC3 properly hashed
  - SRV: services discovered (CalDAV / IMAP / SIP / etc.)
  - DoH / DoT availability

Returns named findings + intel + sources_used per framework contract.
"""
import asyncio
import socket

import dns.asyncresolver
import dns.reversename

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner, dns_resolve
from tools._payloads.dnsrecon_findings import DNSRECON_FINDING_RULES

router = APIRouter()


# Public DNS resolvers used for cross-consistency checking.
# Mismatch in answers ⇒ possible DNS hijacking / regional manipulation /
# ISP DNS poisoning.
_PUBLIC_RESOLVERS = {
    "1.1.1.1 (Cloudflare)": "1.1.1.1",
    "8.8.8.8 (Google)":     "8.8.8.8",
    "9.9.9.9 (Quad9)":      "9.9.9.9",
}

# SRV service prefixes we probe — covers calendar / mail / chat / VoIP.
_SRV_SERVICES = [
    "_caldav._tcp", "_carddav._tcp",
    "_imap._tcp", "_imaps._tcp", "_pop3._tcp", "_pop3s._tcp",
    "_smtp._tcp", "_submission._tcp",
    "_sip._tcp", "_sips._tcp",
    "_xmpp-client._tcp", "_xmpp-server._tcp",
    "_jmap._tcp",
    "_autodiscover._tcp",
    "_minecraft._tcp",
    "_h323cs._tcp",
]


async def _resolver_query(host: str, resolver_ip: str, rtype: str = "A") -> list:
    """Query a specific public resolver for a given record type."""
    r = dns.asyncresolver.Resolver(configure=False)
    r.nameservers = [resolver_ip]
    r.lifetime = 4
    r.timeout = 2
    try:
        ans = await r.resolve(host, rtype)
        return sorted(str(x).rstrip(".") for x in ans)
    except Exception:
        return []


async def _reverse_dns(ip: str) -> list:
    """Async PTR lookup. Returns list of hostnames or empty."""
    def _do():
        try:
            return list(socket.gethostbyaddr(ip)[1] or []) + [socket.gethostbyaddr(ip)[0]]
        except Exception:
            return []
    return await asyncio.to_thread(_do)


async def _nsec_walk_probe(host: str) -> tuple[bool, list]:
    """Attempt NSEC-based zone walking. Returns (walkable, sample_hops).

    NSEC records reveal the NEXT name in the zone — chain them together
    to enumerate every record name. NSEC3 (hashed) prevents this.
    """
    try:
        ans = await dns_resolve(host, "NSEC")
        if not ans:
            return False, []
        # Extract next-name from NSEC record (first field after the record name)
        hops = []
        for rec in ans[:5]:
            parts = str(rec).split()
            if parts:
                hops.append(parts[0])
        # If we got real NSEC (not NSEC3), walking IS possible
        return True, hops
    except Exception:
        return False, []


async def gather(ctx: ScanContext):
    """Populate state with PTR + DNSSEC + cross-resolver + NSEC + SRV."""
    host = ctx.host

    # ── Phase 1: resolve host to IPs (needed for PTR + DNSSEC checks) ──
    a, aaaa = await asyncio.gather(
        dns_resolve(host, "A"),
        dns_resolve(host, "AAAA"),
    )
    ips = list(dict.fromkeys((a or []) + (aaaa or [])))[:4]  # dedupe, cap 4
    ctx.state["ips"] = ips
    if ips:
        ctx.source("dig-A")

    # ── Phase 2: all the parallel intel queries ──
    dnskey_task = dns_resolve(host, "DNSKEY")
    ds_task = dns_resolve(host, "DS")
    ptr_tasks = {ip: _reverse_dns(ip) for ip in ips}
    resolver_tasks = {
        name: _resolver_query(host, ip)
        for name, ip in _PUBLIC_RESOLVERS.items()
    }
    srv_tasks = {svc: dns_resolve(f"{svc}.{host}", "SRV")
                  for svc in _SRV_SERVICES}
    nsec_task = _nsec_walk_probe(host)

    # Fire them all in parallel
    (dnskey, ds,
     ptr_results, resolver_results, srv_results,
     (nsec_walkable, nsec_hops)) = await asyncio.gather(
        dnskey_task,
        ds_task,
        asyncio.gather(*ptr_tasks.values()),
        asyncio.gather(*resolver_tasks.values()),
        asyncio.gather(*srv_tasks.values()),
        nsec_task,
    )

    # ── DNSSEC ──
    ctx.state["dnskey"] = dnskey or []
    ctx.state["ds"] = ds or []
    if dnskey or ds:
        ctx.source("dig-dnssec")
    ctx.state["dnssec_chain_valid"] = bool(dnskey) and bool(ds)

    # ── PTR (reverse DNS) ──
    ptr_dict = {}
    for ip, names in zip(ptr_tasks.keys(), ptr_results):
        if names:
            ptr_dict[ip] = list({n for n in names if n})
    ctx.state["ptr_records"] = ptr_dict
    if ptr_dict:
        ctx.source("reverse-dns")

    # ── Cross-resolver consistency ──
    resolver_answers = dict(zip(resolver_tasks.keys(), resolver_results))
    # Filter empty answers — only compare resolvers that actually returned data
    populated = {k: v for k, v in resolver_answers.items() if v}
    ctx.state["resolver_answers"] = resolver_answers
    if len(populated) >= 2:
        unique_answers = {tuple(sorted(v)) for v in populated.values()}
        consistent = len(unique_answers) == 1
        ctx.state["resolver_consistent"] = consistent
        ctx.source("cross-resolver-1.1.1.1")
        ctx.source("cross-resolver-8.8.8.8")
        ctx.source("cross-resolver-9.9.9.9")

    # ── NSEC zone walking ──
    ctx.state["nsec_walk_possible"] = nsec_walkable
    ctx.state["nsec_hop_sample"] = nsec_hops
    if nsec_walkable:
        ctx.source("nsec-walk")

    # ── SRV records ──
    srv_dict = {}
    for svc, recs in zip(srv_tasks.keys(), srv_results):
        if recs:
            srv_dict[svc] = recs
    ctx.state["srv_found"] = srv_dict
    if srv_dict:
        ctx.source("dig-srv")

    # ── Stringify dict fields for clean PDF rendering (the generic intel
    #    renderer would JSON.stringify a dict otherwise — ugly).
    if ptr_dict:
        ctx.state["ptr_display"] = "; ".join(
            f"{ip} -> {(names or ['?'])[0]}" for ip, names in ptr_dict.items()
        )
    if dnskey or ds:
        chain_status = "valid" if (dnskey and ds) else (
            "broken (DNSKEY only)" if dnskey else "broken (DS only)")
        ctx.state["dnssec_chain_display"] = (
            f"{len(dnskey)} DNSKEY + {len(ds)} DS — chain {chain_status}")
    else:
        ctx.state["dnssec_chain_display"] = "unsigned"
    # Resolver answer summary: "1.1.1.1=18.208.88.157 | 8.8.8.8=18.208.88.157 | ..."
    if resolver_answers:
        parts = []
        for name, ans in resolver_answers.items():
            short_name = name.split()[0]  # "1.1.1.1" from "1.1.1.1 (Cloudflare)"
            parts.append(f"{short_name}={','.join(ans) if ans else 'no answer'}")
        ctx.state["resolver_display"] = " | ".join(parts)
    if nsec_walkable:
        ctx.state["nsec_walk_display"] = (
            f"YES — sample hops: {', '.join(nsec_hops[:3])}")
    if srv_dict:
        ctx.state["srv_display"] = "; ".join(
            f"{svc.lstrip('_').split('.')[0]}({len(recs)})"
            for svc, recs in srv_dict.items()
        )

    # ── Build backwards-compat records[] (for the existing DNS Recon
    #    tile + the old App.js "DNS Recon" PDF section) ──
    records = []
    for ip, names in ptr_dict.items():
        for n in names:
            records.append({"type": "PTR", "name": ip, "address": n})
    for k in dnskey:
        records.append({"type": "DNSKEY", "name": host, "address": str(k)[:100]})
    for d in ds:
        records.append({"type": "DS", "name": host, "address": str(d)[:100]})
    for svc, recs in srv_dict.items():
        for r in recs:
            records.append({"type": "SRV", "name": f"{svc}.{host}", "address": str(r)})
    ctx.state["records"] = records


INTEL_FIELDS = [
    ("Resolved IPs",          "ips"),
    ("DNSSEC chain",          "dnssec_chain_display"),
    ("PTR records",            "ptr_display"),
    ("Resolver consistency",  "resolver_consistent"),
    ("Resolver answers",       "resolver_display"),
    ("NSEC walk possible",    "nsec_walk_display"),
    ("SRV services",           "srv_display"),
]


@router.post("/api/recon/dnsrecon")
async def recon_dnsrecon(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(
        host=host,
        tool="dnsrecon",
        gather_func=gather,
        finding_rules=DNSRECON_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        # Backwards-compat: frontend tile expects records[] at top level
        flat_field_keys=["records", "ips"],
    )


def register(app):
    app.include_router(router)

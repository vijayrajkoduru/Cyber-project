"""dc_discovery - Domain Controller discovery via DNS SRV (playbook §1 #7).

Queries _ldap._tcp.dc._msdcs.<domain> + _kerberos._tcp.<domain> + _gc._tcp.
<domain> SRV records to enumerate every DC + Global Catalog server in the
forest. Pre-auth recon — no creds needed. Identifies multi-DC topology and
spots stale DCs in DNS.

Customer input: ScanRequest.target = domain DNS name (e.g. corp.example.com)
OR a DC IP from which we'll reverse-resolve domain.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.dc_discovery_findings import DC_DISCOVERY_FINDING_RULES

router = APIRouter()


async def gather(ctx: ScanContext):
    target = (ctx.host or "").strip()
    if not target:
        ctx.state["dc_discovery_total"] = 0
        ctx.source("no-target")
        return
    try:
        import dns.resolver
        import dns.reversename
    except ImportError:
        ctx.state["dc_discovery_error"] = "dnspython not installed"
        ctx.source("dnspython missing")
        return

    # Determine the domain to query
    domain = target
    # If target is an IP, try reverse-DNS to find domain
    is_ip = all(p.isdigit() for p in target.replace(".", " ").split() if p)
    if is_ip:
        try:
            rev = dns.reversename.from_address(target)
            answers = dns.resolver.resolve(rev, "PTR", lifetime=5)
            ptr_name = str(answers[0])
            # Strip the hostname part to get domain
            parts = ptr_name.rstrip(".").split(".", 1)
            if len(parts) > 1:
                domain = parts[1]
        except Exception:
            ctx.state["dc_discovery_error"] = f"reverse DNS for {target} failed; pass domain name as target"
            ctx.source(f"reverse DNS {target} failed")
            return

    srv_queries = [
        ("dc", f"_ldap._tcp.dc._msdcs.{domain}"),
        ("kdc", f"_kerberos._tcp.{domain}"),
        ("gc", f"_gc._tcp.{domain}"),
        ("ldap_general", f"_ldap._tcp.{domain}"),
        ("kpasswd", f"_kpasswd._tcp.{domain}"),
    ]
    discovered = {}
    discovery_count = 0
    for role, q in srv_queries:
        try:
            answers = dns.resolver.resolve(q, "SRV", lifetime=6)
            hosts = []
            for a in answers:
                hosts.append({
                    "host": str(a.target).rstrip("."),
                    "port": int(a.port),
                    "priority": int(a.priority),
                    "weight": int(a.weight),
                })
            if hosts:
                discovered[role] = hosts
                discovery_count += len(hosts)
        except Exception:
            continue

    # Resolve each unique DC hostname to IPs
    all_hosts = set()
    for role, hosts in discovered.items():
        for h in hosts:
            all_hosts.add(h["host"])
    dc_ips = {}
    for h in list(all_hosts)[:20]:
        try:
            answers = dns.resolver.resolve(h, "A", lifetime=4)
            dc_ips[h] = [str(a) for a in answers]
        except Exception:
            continue

    ctx.state["dc_discovery_domain"] = domain
    ctx.state["dc_discovery_records"] = discovered
    ctx.state["dc_discovery_resolved"] = dc_ips
    ctx.state["dc_discovery_total"] = discovery_count
    ctx.source(f"{discovery_count} SRV records, {len(dc_ips)} resolved")


INTEL_FIELDS = [("Domain queried", "dc_discovery_domain"),
                ("SRV records", "dc_discovery_records"),
                ("Resolved DC IPs", "dc_discovery_resolved")]


@router.post("/api/ad/dc_discovery")
async def ad_dc_discovery(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="dc_discovery",
        gather_func=gather, finding_rules=DC_DISCOVERY_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)

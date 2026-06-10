"""DNS Records v2 — VL-FORGE multi-resolver cross-check.
Route: /api/recon/dns_records
8 record types × 3 resolvers (Cloudflare/Google/Quad9) in parallel.
"""
import asyncio
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner

router = APIRouter()
_RESOLVERS = [("Cloudflare","1.1.1.1"),("Google","8.8.8.8"),("Quad9","9.9.9.9")]
_TYPES = ["A","AAAA","MX","NS","TXT","CNAME","SOA","CAA"]

async def _resolve(host, rtype, resolver_ip):
    r = dns.asyncresolver.Resolver(); r.timeout=4; r.lifetime=6
    r.nameservers = [resolver_ip]
    try:
        ans = await r.resolve(host, rtype)
        return [str(x).rstrip(".") for x in ans]
    except Exception:
        return []

async def gather(ctx: ScanContext):
    host = ctx.host
    tasks = []
    for name, ip in _RESOLVERS:
        for t in _TYPES:
            tasks.append((name, t, _resolve(host, t, ip)))
    results = await asyncio.gather(*[t[2] for t in tasks])
    by_resolver = {n:{t:[] for t in _TYPES} for n,_ in _RESOLVERS}
    for (name, rtype, _), recs in zip(tasks, results):
        by_resolver[name][rtype] = recs
    # Aggregate via majority union
    merged = {t: sorted(set(sum([by_resolver[n][t] for n,_ in _RESOLVERS], []))) for t in _TYPES}
    for rtype, recs in merged.items():
        ctx.state[rtype.lower()+"_records"] = recs
        if recs: ctx.source(f"dns-{rtype.lower()}")
    # SPF/DMARC parse
    txts = merged["TXT"]
    spf = next((t for t in txts if t.lower().startswith('"v=spf1') or t.lower().startswith('v=spf1')), None)
    ctx.state["spf_record"] = spf
    ctx.state["spf_strict"] = bool(spf and (' -all' in spf or '-all"' in spf))
    # DMARC at _dmarc subdomain
    dmarc_recs = await _resolve(f"_dmarc.{host}", "TXT", "1.1.1.1")
    dmarc = next((t for t in dmarc_recs if 'v=DMARC1' in t), None)
    ctx.state["dmarc_record"] = dmarc
    ctx.state["dmarc_policy"] = "none" if dmarc and "p=none" in dmarc else \
                                ("quarantine" if dmarc and "p=quarantine" in dmarc else \
                                ("reject" if dmarc and "p=reject" in dmarc else None))
    if dmarc: ctx.source("dmarc-record")
    # Cross-resolver consistency.
    # VL-VERIFY (zero-FP): the previous version flagged any A-record disagreement
    # as HIGH "possible DNS hijack". That mis-fired on every geo-DNS / CDN
    # target (google.com - 192.178.x range from all resolvers, AWS, Cloudflare).
    # Now: only treat as suspicious when the differing IPs span DIFFERENT /16
    # networks. If all IPs share /16 (or /8 for cloud edges), it is geo-DNS,
    # not a hijack.
    a_sets = [tuple(sorted(by_resolver[n]["A"])) for n,_ in _RESOLVERS]
    ctx.state["resolver_consistent"] = len(set(a_sets)) <= 1
    # Compute /16 network span across all resolver responses
    all_ips = sorted({ip for s in a_sets for ip in s if ip})
    def _net16(ip):
        try:
            parts = ip.split(".")
            if len(parts) >= 2: return f"{parts[0]}.{parts[1]}"
        except Exception: pass
        return ""
    net16_set = {_net16(ip) for ip in all_ips if _net16(ip)}
    ctx.state["resolver_a_networks"] = sorted(net16_set)[:8]
    # geo-DNS: more than 1 distinct answer set BUT all IPs in same /16 (or /8)
    nets8 = {n.split(".")[0] for n in net16_set if n}
    ctx.state["resolver_geo_dns_likely"] = (
        not ctx.state["resolver_consistent"]
        and (len(net16_set) <= 2 or len(nets8) == 1)
    )
    ctx.source("multi-resolver-check")

def r_no_spf(s):
    if s.get("spf_record"): return None
    if not (s.get("mx_records") or []): return None
    return {"name":"No SPF record published","severity":"HIGH","cvss":7.0,"cwe":"CWE-290",
            "owasp":"A07:2021","evidence":"Domain has MX but no SPF — email can be spoofed",
            "remediation":"Publish 'v=spf1 mx -all' TXT record at apex."}

def r_weak_spf(s):
    spf = s.get("spf_record");
    if not spf or s.get("spf_strict"): return None
    return {"name":"SPF uses weak policy (no -all)","severity":"MEDIUM","cwe":"CWE-290",
            "evidence":f"SPF: {spf[:120]}","remediation":"Tighten to '-all' or '~all'."}

def r_no_dmarc(s):
    if s.get("dmarc_record"): return None
    if not (s.get("mx_records") or []): return None
    return {"name":"No DMARC record","severity":"MEDIUM","cwe":"CWE-290","owasp":"A07:2021",
            "evidence":f"_dmarc.{s.get('host','target')} returned no TXT","remediation":"Add 'v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>'."}

def r_dmarc_none(s):
    if s.get("dmarc_policy") != "none": return None
    return {"name":"DMARC policy is 'none' (monitor-only)","severity":"MEDIUM","cwe":"CWE-290",
            "evidence":s.get("dmarc_record","")[:120],"remediation":"Move to p=quarantine after 30-day rua review."}

def r_dmarc_strict(s):
    if s.get("dmarc_policy") not in ("quarantine","reject"): return None
    return {"name":f"DMARC policy: {s['dmarc_policy']}","severity":"POSITIVE",
            "evidence":"Anti-spoofing enforced"}

def r_caa_missing(s):
    if (s.get("caa_records") or []): return None
    return {"name":"No CAA records","severity":"LOW","cwe":"CWE-295",
            "evidence":"Any CA can issue cert for this domain",
            "remediation":"Add CAA: '0 issue \"letsencrypt.org\"' restricting cert issuance."}

def r_caa_present(s):
    if not (s.get("caa_records") or []): return None
    return {"name":f"CAA records present ({len(s['caa_records'])})","severity":"POSITIVE",
            "evidence":", ".join(s["caa_records"][:3])}

def r_resolver_inconsistent(s):
    if s.get("resolver_consistent"): return None
    # Geo-DNS likely - same /16 or /8 - downgrade to INFO, this is expected.
    if s.get("resolver_geo_dns_likely"):
        nets = s.get("resolver_a_networks") or []
        return {"name":"Geo-DNS / multi-region routing detected",
                "severity":"INFO",
                "evidence":f"Resolver responses differed but all IPs share network space "
                           f"({', '.join(nets[:4])}{'+' if len(nets) > 4 else ''}). "
                           f"Expected behaviour for CDN / cloud-fronted services."}
    # Different /16 networks across resolvers - genuinely suspicious.
    return {"name":"DNS resolvers return A records in DIFFERENT networks","severity":"HIGH","cwe":"CWE-345",
            "evidence":f"Cloudflare/Google/Quad9 returned IPs in distinct networks "
                       f"({', '.join((s.get('resolver_a_networks') or [])[:4])}) "
                       f"- could indicate DNS hijack, cache poisoning, or split-horizon DNS.",
            "remediation":"Verify each resolver's answer manually; check authoritative NS records."}

def r_resolver_consistent(s):
    if not s.get("resolver_consistent"): return None
    return {"name":"DNS resolvers agree (no hijack indicators)","severity":"POSITIVE",
            "evidence":"Cloudflare + Google + Quad9 returned same A records"}

def r_records_summary(s):
    counts = {t.upper(): len(s.get(t.lower()+"_records") or []) for t in _TYPES}
    nonzero = [f"{k}={v}" for k,v in counts.items() if v]
    if not nonzero: return None
    return {"name":f"DNS records: {', '.join(nonzero)}","severity":"INFO",
            "evidence":"From 3-resolver merged query"}

FINDING_RULES = [
                 r_caa_missing, r_caa_present, r_resolver_inconsistent, r_resolver_consistent,
                 r_records_summary]

INTEL_FIELDS = [("A records","a_records"),("AAAA records","aaaa_records"),
                ("MX records","mx_records"),("NS records","ns_records"),
                ("TXT records","txt_records"),("CNAME","cname_records"),
                ("CAA","caa_records"),("SPF","spf_record"),("DMARC policy","dmarc_policy")]

@router.post("/api/recon/dns_records")
async def recon_dns_records(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="dns_records",
        gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS,
        flat_field_keys=["a_records","mx_records","ns_records","txt_records",
                         "spf_record","dmarc_record","caa_records"])

def register(app): app.include_router(router)

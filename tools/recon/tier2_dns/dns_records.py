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
    # Cross-resolver consistency
    a_sets = [tuple(sorted(by_resolver[n]["A"])) for n,_ in _RESOLVERS]
    ctx.state["resolver_consistent"] = len(set(a_sets)) <= 1
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
    return {"name":"DNS resolvers return inconsistent A records","severity":"HIGH","cwe":"CWE-345",
            "evidence":"Cloudflare/Google/Quad9 disagreed — possible DNS hijack",
            "remediation":"Investigate DNS poisoning. Check at all 3 resolvers manually."}

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

def _r_chain_handoff(s):
    """VL-METHOD Stage 7: map DNS record types to follow-up scanners."""
    chain_next = []
    detected = []
    mx = s.get("mx_records") or []
    if mx:
        for sc in ("mail_server_cve", "email_security", "mx_enum"):
            if sc not in chain_next: chain_next.append(sc)
        detected.append(f"MX({len(mx)})")
    txts = s.get("txt_records") or []
    txt_blob = " ".join(txts).lower()
    has_spf = bool(s.get("spf_record")) or "v=spf1" in txt_blob
    has_dmarc = bool(s.get("dmarc_record")) or "v=dmarc1" in txt_blob
    has_dkim = "v=dkim1" in txt_blob or "dkim" in txt_blob
    if has_spf or has_dmarc or has_dkim:
        for sc in ("email_security", "phishing_email_posture"):
            if sc not in chain_next: chain_next.append(sc)
        tags = []
        if has_spf: tags.append("SPF")
        if has_dmarc: tags.append("DMARC")
        if has_dkim: tags.append("DKIM")
        detected.append("TXT(" + "/".join(tags) + ")")
    srv = s.get("srv_records") or []
    if srv:
        if "tcp_port_scan" not in chain_next: chain_next.append("tcp_port_scan")
        detected.append(f"SRV({len(srv)})")
    ns = s.get("ns_records") or []
    if ns and len(ns) >= 2:
        if "zone_transfer" not in chain_next: chain_next.append("zone_transfer")
        detected.append(f"NS({len(ns)})")
    cname = s.get("cname_records") or []
    if cname:
        if "subdomain_takeover" not in chain_next: chain_next.append("subdomain_takeover")
        detected.append(f"CNAME({len(cname)})")
    a_blob = " ".join(s.get("a_records") or []).lower()
    cname_blob = " ".join(cname).lower()
    cloud_blob = a_blob + " " + cname_blob
    cloud_hits = []
    if any(k in cloud_blob for k in ("amazonaws", "aws", "cloudfront", "s3.")):
        cloud_hits.append("AWS")
    if any(k in cloud_blob for k in ("azure", "windows.net", "azureedge")):
        cloud_hits.append("Azure")
    if any(k in cloud_blob for k in ("googleusercontent", "googleapis", "gcp", "appspot")):
        cloud_hits.append("GCP")
    if cloud_hits:
        for sc in ("cloudfront_disco", "s3_bucket_enum"):
            if sc not in chain_next: chain_next.append(sc)
        detected.append("Cloud(" + "/".join(cloud_hits) + ")")
    if not chain_next:
        return None
    return {
        "name": f"Cross-module chain handoff - DNS surface maps to {len(chain_next)} scanners",
        "severity": "INFO",
        "evidence": f"Detected records: {', '.join(detected)}; suggests {len(chain_next)} follow-up scanner(s)",
        "remediation": "Each record type opens a different attack surface. Run chained scanners.",
        "cwe": "CWE-1006",
        "chain_next": chain_next,
        "discovery_method": "dns_records_to_surface_chain",
        "source_stage": "chain_handoff",
        "confidence": "INFO",
    }

FINDING_RULES = [
                 r_caa_missing, r_caa_present, r_resolver_inconsistent, r_resolver_consistent,
                 r_records_summary, _r_chain_handoff]

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


# ════════════════════════════════════════════════════════════════════
#  Chain registry registration - upstream scanners trigger us via
#  _chain_callable.
# ════════════════════════════════════════════════════════════════════


async def _chain_callable(target, options, jwt=None) -> dict:
    return {"tool": "dns_records", "target": target, "_skipped": True,
            "skipped_reason": "Use orchestrator for full chain execution", "findings": []}


from tools._methodology import chain_registry
chain_registry.register("dns_records", _chain_callable)

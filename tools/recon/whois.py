"""WHOIS Intelligence v2 — multi-source async intel engine.

Route: /api/recon/whois

Gathers data from ~8 sources in parallel:
  1. `whois <domain>` CLI                    — registry data
  2. `whois <each-resolved-IP>` CLI          — netblock/ASN/hosting
  3. RDAP HTTP for domain                    — JSON cross-check
  4. RDAP HTTP for each IP                   — JSON IP cross-check
  5. DNS A/AAAA/NS resolution                — populate IPs + NS list
  6. crt.sh certificate transparency         — subdomain hint count
  7. Team Cymru WHOIS for ASN enrichment     — peering / country
  8. python-whois library                    — fallback only

Then runs a 30-rule findings engine (tools/_payloads/whois_findings.py)
against the collected state and emits only USEFUL, NAMED findings with
severity + evidence + remediation.

Output:
  ok, tool, target, findings[] (named items), intel{} (distilled facts),
  raw_excerpt (whois text), sources_used[] (which gatherers fired).
"""
import asyncio
import datetime
import json
import re
import shutil
from typing import Optional
from urllib.parse import urlparse

import dns.asyncresolver
import dns.resolver
import requests
import whois as whois_lib_fallback
from fastapi import APIRouter, Depends

from tools._shared import (ScanRequest, verify_scan_quota, recon_host,
                            wrap_finding, standard_response)
from tools._payloads.whois_findings import (WHOIS_FINDING_RULES,
                                             detect_cdn_from_nameservers,
                                             detect_cloud_from_org)

router = APIRouter()

_WHOIS_BIN = shutil.which("whois")
_REQ_TIMEOUT = 10


# ───────────────────────── PARSING HELPERS ─────────────────────────

def _grab(text: str, *labels) -> Optional[str]:
    for label in labels:
        pat = re.compile(rf"^\s*{re.escape(label)}\s*:\s*(.+?)\s*$",
                          re.IGNORECASE | re.MULTILINE)
        m = pat.search(text or "")
        if m and m.group(1).strip():
            return m.group(1).strip()
    return None


def _grab_all(text: str, *labels) -> list:
    seen, out = set(), []
    for label in labels:
        pat = re.compile(rf"^\s*{re.escape(label)}\s*:\s*(.+?)\s*$",
                          re.IGNORECASE | re.MULTILINE)
        for m in pat.finditer(text or ""):
            v = m.group(1).strip()
            if v and v.lower() not in seen:
                seen.add(v.lower())
                out.append(v)
    return out


def _parse_iso(date_str: str) -> Optional[datetime.datetime]:
    if not date_str: return None
    s = date_str.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d", "%d-%b-%Y", "%d.%m.%Y"):
        try:
            return datetime.datetime.strptime(s.split("+")[0].rstrip("Z"), fmt.rstrip("Z"))
        except ValueError:
            continue
    # ISO fromisoformat fallback
    try:
        return datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        return None


def _days_between(d1: datetime.datetime, d2: datetime.datetime) -> int:
    return (d2 - d1).days


# ───────────────────────── ASYNC SUBPROCESS ─────────────────────────

async def _whois_cli(target: str, timeout: int = 12, server: str | None = None,
                      query_prefix: str = "") -> str:
    """Async subprocess to system `whois`. Returns raw text or empty.

    server: optional WHOIS server (passed via -h flag)
    query_prefix: optional prefix prepended to the query (e.g. " -v" for
                  Team Cymru verbose output)
    """
    if not _WHOIS_BIN:
        return ""
    args = [_WHOIS_BIN]
    if server:
        args += ["-h", server]
    args.append(f"{query_prefix}{target}" if query_prefix else target)
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return ""
        out = (stdout or b"").decode("utf-8", errors="replace")
        err = (stderr or b"").decode("utf-8", errors="replace")
        return out + err
    except Exception:
        return ""


async def _team_cymru_asn(ip: str) -> dict:
    """Authoritative ASN lookup via Team Cymru WHOIS service.

    Returns dict {asn, bgp_prefix, country, registry, allocated, info}.
    Always more reliable than ARIN's OriginAS field which is often empty
    for AWS / large-cloud direct allocations.

    Output format (after header):
        AS      | IP                | BGP Prefix          | CC | Registry | Allocated  | AS Name
        14618   | 18.208.88.157     | 18.208.0.0/13       | US | arin     | 2017-06-23 | AMAZON-AES, US
    """
    raw = await _whois_cli(ip, timeout=10, server="whois.cymru.com",
                            query_prefix=" -v ")
    if not raw:
        return {}
    # Parse the data line (skip header that starts with "Bulk mode" or "AS  |")
    for line in raw.splitlines():
        if "|" not in line: continue
        if line.strip().lower().startswith("as ") or "bulk mode" in line.lower():
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 7 and parts[0].isdigit():
            return {
                "asn":        f"AS{parts[0]}",
                "ip":         parts[1],
                "bgp_prefix": parts[2],
                "country":    parts[3].upper(),
                "registry":   parts[4],
                "allocated":  parts[5],
                "info":       parts[6],
            }
    return {}


# ───────────────────────── HTTP HELPERS ─────────────────────────

def _http_get_json(url: str, headers: dict | None = None) -> Optional[dict]:
    try:
        r = requests.get(url, headers=headers or {}, timeout=_REQ_TIMEOUT, verify=False)
        if r.status_code != 200: return None
        return r.json()
    except Exception:
        return None


async def _fetch_rdap_domain(domain: str) -> Optional[dict]:
    return await asyncio.to_thread(_http_get_json,
                                     f"https://rdap.org/domain/{domain}")


async def _fetch_rdap_ip(ip: str) -> Optional[dict]:
    return await asyncio.to_thread(_http_get_json, f"https://rdap.org/ip/{ip}")


async def _fetch_crt_sh(domain: str) -> int:
    """Return count of unique subdomains seen in cert-transparency logs.

    Strict match: domain must equal `domain` itself OR end with ".domain" —
    prevents "supervulnuslab.com" counting as a vulnuslab.com subdomain.
    Tries wildcard query first; if 0 results, tries bare-domain query
    (catches base cert without SANs). Longer timeout (30s) because crt.sh
    can be slow.
    """
    def _do(query_url):
        try:
            r = requests.get(query_url, timeout=30, verify=False,
                              headers={"User-Agent": "VulnusLab/1.0"})
            if r.status_code != 200: return set()
            data = r.json()
            names = set()
            for row in data[:1000]:
                nv = (row.get("name_value") or "").lower()
                for part in nv.split("\n"):
                    part = part.strip().lstrip("*.")
                    if not part: continue
                    # Strict suffix match: equals domain OR endswith ".domain"
                    if part == domain or part.endswith("." + domain):
                        names.add(part)
            return names
        except Exception:
            return set()

    def _run():
        d = domain.lower().strip()
        # Wildcard query: any cert covering *.<domain> or sub.<domain>
        names = _do(f"https://crt.sh/?q=%25.{d}&output=json")
        if not names:
            # Bare-domain query: cert for the apex domain itself
            names = _do(f"https://crt.sh/?q={d}&output=json")
        return len(names)

    return await asyncio.to_thread(_run)


# ───────────────────────── DNS RESOLUTION ─────────────────────────

async def _resolve_records(host: str) -> dict:
    """Return {a:[], aaaa:[], ns:[]} — empty lists on failure."""
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 6
    resolver.timeout = 3
    out = {"a": [], "aaaa": [], "ns": []}
    async def _q(rtype):
        try:
            ans = await resolver.resolve(host, rtype)
            return [str(r).rstrip(".") for r in ans]
        except Exception:
            return []
    a, aaaa, ns = await asyncio.gather(_q("A"), _q("AAAA"), _q("NS"))
    out["a"], out["aaaa"], out["ns"] = a, aaaa, ns
    return out


# ───────────────────────── RDAP PARSER ─────────────────────────

def _parse_rdap_domain(rdap: dict) -> dict:
    """Extract registrar + status from an RDAP domain response."""
    if not rdap: return {}
    out = {}
    # Registrar nested in entities[].roles == ["registrar"]
    for ent in (rdap.get("entities") or []):
        if "registrar" in (ent.get("roles") or []):
            vcard = ent.get("vcardArray", [None, []])[1]
            for entry in (vcard or []):
                if isinstance(entry, list) and entry[0] == "fn":
                    out["rdap_registrar"] = entry[3]
                    break
    out["rdap_status"] = rdap.get("status") or []
    out["rdap_secure_dns"] = (rdap.get("secureDNS") or {}).get("delegationSigned")
    # Events: registration, expiration, last changed
    for ev in (rdap.get("events") or []):
        action = ev.get("eventAction", "")
        if action == "registration": out["rdap_created"] = ev.get("eventDate")
        if action == "expiration":   out["rdap_expires"] = ev.get("eventDate")
        if action == "last changed": out["rdap_updated"] = ev.get("eventDate")
    return out


def _parse_rdap_ip(rdap: dict) -> dict:
    if not rdap: return {}
    out = {}
    out["rdap_ip_handle"] = rdap.get("handle")
    out["rdap_ip_name"] = rdap.get("name")
    out["rdap_ip_country"] = rdap.get("country")
    for ent in (rdap.get("entities") or []):
        vcard = ent.get("vcardArray", [None, []])[1]
        for entry in (vcard or []):
            if isinstance(entry, list) and entry[0] == "fn":
                out["rdap_ip_org"] = entry[3]
                break
    return out


# ───────────────────────── WHOIS-TEXT PARSERS ─────────────────────────

def _parse_domain_whois(text: str) -> dict:
    raw_status = _grab_all(text, "Domain Status")
    statuses = []
    for s in raw_status:
        code = s.split()[0] if s else s
        if code and code not in statuses:
            statuses.append(code)
    return {
        "registry_domain_id": _grab(text, "Registry Domain ID"),
        "registrar":          _grab(text, "Registrar"),
        "registrar_url":      _grab(text, "Registrar URL"),
        "registrar_iana_id":  _grab(text, "Registrar IANA ID"),
        "registrar_whois":    _grab(text, "Registrar WHOIS Server"),
        "abuse_email":        _grab(text, "Registrar Abuse Contact Email"),
        "abuse_phone":        _grab(text, "Registrar Abuse Contact Phone"),
        "created_raw":        _grab(text, "Creation Date", "Created On", "Created Date"),
        "updated_raw":        _grab(text, "Updated Date", "Last Updated On", "Last Modified"),
        "expires_raw":        _grab(text, "Registry Expiry Date",
                                          "Registrar Registration Expiration Date",
                                          "Expiration Date", "Expiry Date"),
        "name_servers":       [n.lower().rstrip(".") for n in _grab_all(text, "Name Server",
                                                                          "Nameserver", "nserver")],
        "status_codes":       statuses,
        "dnssec":             _grab(text, "DNSSEC"),
        "registrant_org":     _grab(text, "Registrant Organization", "Registrant Org",
                                          "Registrant"),
        "registrant_country": _grab(text, "Registrant Country", "Country"),
        "registrant_state":   _grab(text, "Registrant State/Province", "Registrant State"),
    }


def _parse_ip_whois(text: str) -> dict:
    """Extract ASN + netblock owner + country from an IP whois response.

    Handles ARIN/RIPE/APNIC/AFRINIC/LACNIC quirks. Earlier version was
    parsing "AS88" from OrgId "AT-88-Z" — the new logic requires AS
    followed by 3+ digits OR a 4+ digit number after the OriginAS label.
    """
    if not text: return {}

    # ── Org name: prefer OrgName, fall back to others. Strip any label leak. ──
    org = (_grab(text, "OrgName", "org-name", "owner", "Organization",
                 "descr", "netname") or "")
    # Sometimes the grab catches a follow-up line — keep only the first line
    org = (org.split("\n")[0] or "").strip()
    # Remove redundant "Organization:" / "OrgName:" prefix if it leaked in
    org = re.sub(r"^(Organization|OrgName|Owner|Org|descr|netname)\s*:\s*",
                  "", org, flags=re.IGNORECASE)
    org = org.strip().rstrip(";").rstrip(",").strip()

    # ── ASN extraction with stricter validation ──
    # Step 1: try the labelled field
    asn_raw = (_grab(text, "OriginAS", "origin", "aut-num", "ASNumber") or "")
    asn = ""
    if asn_raw:
        # Require AS-prefix with 3+ digits, OR a bare 3+ digit number
        m = re.search(r"\bAS\s*(\d{3,7})\b", asn_raw, re.IGNORECASE)
        if m:
            asn = f"AS{m.group(1)}"
        else:
            m2 = re.fullmatch(r"\s*(\d{3,7})\s*", asn_raw)
            if m2:
                asn = f"AS{m2.group(1)}"
    # Step 2: scan whole text as fallback (Amazon IPs sometimes have empty OriginAS)
    if not asn:
        for line_re in (r"^\s*OriginAS\s*:\s*AS?\s*(\d{3,7})\s*$",
                        r"^\s*origin\s*:\s*AS?\s*(\d{3,7})\s*$",
                        r"^\s*aut-num\s*:\s*AS?\s*(\d{3,7})\s*$"):
            m = re.search(line_re, text, re.IGNORECASE | re.MULTILINE)
            if m:
                asn = f"AS{m.group(1)}"
                break

    country = (_grab(text, "Country", "country") or "").strip().upper()
    # Country can sometimes have explanatory text — keep only first 2-letter ISO code
    m = re.match(r"^([A-Z]{2})\b", country)
    if m: country = m.group(1)

    netblock = (_grab(text, "NetRange", "CIDR", "inetnum", "route") or "").strip()
    abuse = _grab(text, "OrgAbuseEmail", "abuse-mailbox", "abuse-c")

    return {"org": org, "asn": asn, "country": country,
            "netblock": netblock, "abuse": abuse}


# ───────────────────────── PYTHON-WHOIS FALLBACK ─────────────────────────

def _python_whois_fallback(host: str) -> dict:
    """Used only if `whois` CLI returned nothing — limited fields."""
    try:
        w = whois_lib_fallback.whois(host)
    except Exception:
        return {}

    def _first(v): return v[0] if isinstance(v, list) and v else v

    def _iso(d):
        d = _first(d)
        if isinstance(d, datetime.datetime): return d.isoformat()
        return str(d) if d else None

    return {
        "registrar":     _first(w.registrar),
        "created_raw":   _iso(w.creation_date),
        "expires_raw":   _iso(w.expiration_date),
        "updated_raw":   _iso(w.updated_date),
        "name_servers":  sorted({str(n).lower().rstrip(".") for n in (w.name_servers or [])}),
        "registrant_org": _first(w.registrant_name) or _first(w.org),
        "registrant_country": _first(w.country),
        "status_codes":  list({str(s).split()[0] for s in (w.status or []) if s})
                          if hasattr(w, "status") and w.status else [],
        "dnssec":        getattr(w, "dnssec", None),
    }


# ───────────────────────── ORCHESTRATION ─────────────────────────

@router.post("/api/recon/whois")
async def recon_whois(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    sources_used = []

    # 1+5. Domain whois + DNS resolution in parallel
    raw_whois, dns_rec = await asyncio.gather(
        _whois_cli(host, timeout=15),
        _resolve_records(host),
    )
    if raw_whois: sources_used.append("system-whois-cli")

    parsed = _parse_domain_whois(raw_whois) if raw_whois else {}

    # Fall back to python-whois if CLI returned almost nothing
    if not parsed.get("registrar"):
        fb = await asyncio.to_thread(_python_whois_fallback, host)
        if fb.get("registrar"):
            sources_used.append("python-whois-fallback")
            for k, v in fb.items():
                if not parsed.get(k):
                    parsed[k] = v

    if not parsed.get("registrar") and not parsed.get("name_servers"):
        return standard_response(tool="whois", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"WHOIS returned no data for {host} (likely restricted TLD or rate-limited)",
            raw_data={"whois_raw_excerpt": (raw_whois[:500] if raw_whois else None)})

    # Augment NS list with DNS-resolved NS if WHOIS didn't return any
    if not parsed.get("name_servers") and dns_rec.get("ns"):
        parsed["name_servers"] = [n.lower() for n in dns_rec["ns"]]

    # 2. IP whois + Team Cymru ASN lookup for each resolved IP (parallel)
    #
    # Team Cymru is authoritative for ASN data. ARIN's OriginAS field is
    # often empty for AWS/large-cloud direct allocations, leaving us with
    # "?" in the ASN column. Team Cymru always returns the real announced AS.
    ips = (dns_rec.get("a") or []) + (dns_rec.get("aaaa") or [])
    ips = list(dict.fromkeys(ips))[:4]  # dedupe, cap at 4 to bound time
    ip_whois_list = []
    if ips:
        # Fire ARIN/RIPE whois AND Team Cymru in parallel for every IP
        arin_tasks  = [_whois_cli(ip, timeout=10) for ip in ips]
        cymru_tasks = [_team_cymru_asn(ip)         for ip in ips]
        ip_raws, cymru_results = await asyncio.gather(
            asyncio.gather(*arin_tasks),
            asyncio.gather(*cymru_tasks),
        )
        seen_combo = set()  # (asn, org) — dedupe duplicate hosting entries
        for ip, raw, cymru in zip(ips, ip_raws, cymru_results):
            entry = _parse_ip_whois(raw) if raw else {"org": "", "asn": "",
                                                       "country": "", "netblock": ""}
            entry["ip"] = ip
            # Team Cymru wins for ASN (authoritative) and fills gaps
            if cymru.get("asn"):
                entry["asn"] = cymru["asn"]
            if not entry.get("country") and cymru.get("country"):
                entry["country"] = cymru["country"]
            if not entry.get("org") and cymru.get("info"):
                # Cymru "info" looks like "AMAZON-AES, US" — strip trailing country
                info = cymru["info"]
                m = re.match(r"^(.+?),\s*[A-Z]{2}\s*$", info)
                entry["org"] = m.group(1) if m else info
            if not entry.get("netblock") and cymru.get("bgp_prefix"):
                entry["netblock"] = cymru["bgp_prefix"]
            # Dedupe: only add if this (asn, org) combo is new
            combo = (entry.get("asn", ""), entry.get("org", ""))
            if combo in seen_combo and combo != ("", ""):
                continue
            seen_combo.add(combo)
            ip_whois_list.append(entry)
        if ip_whois_list: sources_used.append("ip-whois-cli")
        if any(c.get("asn") for c in cymru_results): sources_used.append("team-cymru-asn")

    # 3. RDAP domain (parallel with everything below)
    # 6. crt.sh subdomain count
    rdap_dom, crt_count = await asyncio.gather(
        _fetch_rdap_domain(host),
        _fetch_crt_sh(host),
    )
    rdap_parsed = _parse_rdap_domain(rdap_dom) if rdap_dom else {}
    if rdap_dom: sources_used.append("rdap-domain")
    if crt_count > 0: sources_used.append("crt.sh")

    # ── BUILD STATE DICT FOR FINDINGS ENGINE ──
    now = datetime.datetime.utcnow()

    def _iso_or_none(s):
        d = _parse_iso(s) if s else None
        return d.isoformat() if d else (s if s else None)

    created_dt = _parse_iso(parsed.get("created_raw") or rdap_parsed.get("rdap_created"))
    expires_dt = _parse_iso(parsed.get("expires_raw") or rdap_parsed.get("rdap_expires"))
    updated_dt = _parse_iso(parsed.get("updated_raw") or rdap_parsed.get("rdap_updated"))

    domain_age_days   = _days_between(created_dt, now) if created_dt else None
    expires_in_days   = _days_between(now, expires_dt) if expires_dt else None

    # CDN + cloud detection
    cdn = detect_cdn_from_nameservers(parsed.get("name_servers"))
    cloud = None
    for ipw in ip_whois_list:
        c = detect_cloud_from_org(ipw.get("org"))
        if c:
            cloud = c
            break

    privacy_proxied = bool(re.search(
        r"privacy|redacted|withheld|whoisguard|domainsbyproxy|protected|proxy",
        (parsed.get("registrant_org") or "") + " " + (raw_whois or ""), re.I))

    is_idn = host.startswith("xn--") or ".xn--" in host
    tld = host.rsplit(".", 1)[-1] if "." in host else ""

    state = {
        "domain": host,
        "tld": tld,
        "raw_whois": raw_whois,
        "raw_rdap": rdap_dom,
        "registrar":           parsed.get("registrar"),
        "registry_domain_id":  parsed.get("registry_domain_id"),
        "registrar_url":       parsed.get("registrar_url"),
        "registrar_iana_id":   parsed.get("registrar_iana_id"),
        "registrar_whois":     parsed.get("registrar_whois"),
        "abuse_email":         parsed.get("abuse_email"),
        "abuse_phone":         parsed.get("abuse_phone"),
        "created":             _iso_or_none(parsed.get("created_raw") or rdap_parsed.get("rdap_created")),
        "updated":             _iso_or_none(parsed.get("updated_raw") or rdap_parsed.get("rdap_updated")),
        "expires":             _iso_or_none(parsed.get("expires_raw") or rdap_parsed.get("rdap_expires")),
        "domain_age_days":     domain_age_days,
        "expires_in_days":     expires_in_days,
        "status_codes":        parsed.get("status_codes") or [],
        "dnssec":              parsed.get("dnssec"),
        "name_servers":        parsed.get("name_servers") or [],
        "registrant_org":      parsed.get("registrant_org"),
        "registrant_country":  parsed.get("registrant_country"),
        "registrant_state":    parsed.get("registrant_state"),
        "ips":                 ips,
        "ip_whois":            ip_whois_list,
        "cdn_detected":        cdn,
        "cloud_provider":      cloud,
        "privacy_proxied":     privacy_proxied,
        "is_idn":              is_idn,
        "crt_sh_subdomains":   crt_count,
        "rdap_registrar":      rdap_parsed.get("rdap_registrar"),
    }

    # ── RUN FINDINGS ENGINE ──
    findings = []
    for rule in WHOIS_FINDING_RULES:
        try:
            res = rule(state)
        except Exception:
            continue
        if not res: continue
        findings.append(wrap_finding(
            res["name"], res["severity"],
            cwe=res.get("cwe", "N/A"),
            remediation=res.get("remediation", ""),
            evidence_marker=res.get("evidence", "")))

    # ── INTEL (distilled facts for the report) ──
    intel = {
        "registrar":           state["registrar"],
        "registrar_iana_id":   state["registrar_iana_id"],
        "registrar_url":       state["registrar_url"],
        "abuse_email":         state["abuse_email"],
        "abuse_phone":         state["abuse_phone"],
        "created":             state["created"],
        "updated":             state["updated"],
        "expires":             state["expires"],
        "domain_age_days":     state["domain_age_days"],
        "expires_in_days":     state["expires_in_days"],
        "name_servers":        state["name_servers"],
        "status_codes":        state["status_codes"],
        "dnssec":              state["dnssec"],
        "registrant_org":      state["registrant_org"],
        "registrant_country":  state["registrant_country"],
        "resolved_ips":        state["ips"],
        "hosting": [
            {"ip": w.get("ip"), "asn": w.get("asn"), "org": w.get("org"),
             "country": w.get("country"), "netblock": w.get("netblock")}
            for w in ip_whois_list
        ],
        "cdn":                 state["cdn_detected"],
        "cloud_provider":      state["cloud_provider"],
        "is_idn":              state["is_idn"],
        "privacy_proxied":     state["privacy_proxied"],
        "crt_sh_subdomains":   state["crt_sh_subdomains"],
    }

    return standard_response(
        tool="whois", target=req.target,
        findings=findings,
        tests_performed=len(WHOIS_FINDING_RULES),
        tests_summary=(f"WHOIS Intelligence v2: gathered {len(sources_used)} sources "
                       f"({', '.join(sources_used) or 'none'}); "
                       f"{len(WHOIS_FINDING_RULES)} rules evaluated; "
                       f"{len(findings)} findings emitted."),
        raw_data={
            # ── Backwards-compat: PDF generator + dashboard tile readers
            # expect these as top-level fields on the whois response.
            "domain":             host,
            "registrar":          state["registrar"],
            "created":            state["created"],
            "updated":            state["updated"],
            "expires":            state["expires"],
            "name_servers":       state["name_servers"],
            "registrant":         state["registrant_org"],
            "country":            state["registrant_country"],
            "status_codes":       state["status_codes"],
            "dnssec":             state["dnssec"],
            "abuse_email":        state["abuse_email"],
            "raw_output":         (raw_whois[:2000] if raw_whois else None),
            # ── New v2 fields (richer + the engine output) ──
            "intel":              intel,
            "sources_used":       sources_used,
            "whois_raw_excerpt":  (raw_whois[:2000] if raw_whois else None),
            "rdap_raw":           rdap_parsed,
        })


def register(app):
    app.include_router(router)

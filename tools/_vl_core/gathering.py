"""Async data-gathering helpers for recon scanners.

All helpers are async-safe and timeout-aware. They never raise on
network/process failure — they return empty results (str=""/list=[]/
dict={}/None) so callers can keep gathering from other sources without
try/except boilerplate.

Categories:
  CLI:      cli_run(args)                       — generic subprocess
            whois_cli(target, server, prefix)   — system whois with -h flag
            team_cymru_asn(ip)                  — authoritative ASN lookup
  HTTP:     http_json(url)                      — sync GET → parsed JSON
            http_json_async(url)                — async wrapper
  DNS:      dns_resolve(host, rtype)            — one record type
            dns_resolve_many(host, [rtypes])    — many in parallel
"""
import asyncio
import shutil
from typing import Optional

import requests
import dns.asyncresolver

# Disable noisy verify=False warnings (we explicitly verify=False on probes)
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass


_DEFAULT_TIMEOUT = 10


# ───────────────────────── CLI HELPERS ─────────────────────────

async def cli_run(args: list, timeout: int = 12) -> str:
    """Run a CLI command, return stdout+stderr as text. Empty str on failure.

    Skips entirely if the binary isn't on PATH. No exceptions raised.
    """
    if not args:
        return ""
    if not shutil.which(args[0]):
        return ""
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(),
                                                      timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return ""
        out = (stdout or b"").decode("utf-8", errors="replace")
        err = (stderr or b"").decode("utf-8", errors="replace")
        return out + err
    except Exception:
        return ""


async def whois_cli(target: str, server: str | None = None,
                     query_prefix: str = "", timeout: int = 12) -> str:
    """Async wrapper around the system `whois` binary.

    server: optional WHOIS server (passed via -h flag)
    query_prefix: prepended to the query (e.g. " -v " for Team Cymru)

        whois_cli("vulnuslab.com")                  → registry WHOIS
        whois_cli("8.8.8.8")                        → IP-block WHOIS
        whois_cli("8.8.8.8", server="whois.cymru.com",
                  query_prefix=" -v ")              → Team Cymru ASN
    """
    args = ["whois"]
    if server: args += ["-h", server]
    args.append(f"{query_prefix}{target}" if query_prefix else target)
    return await cli_run(args, timeout=timeout)


async def team_cymru_asn(ip: str) -> dict:
    """Authoritative ASN lookup via Team Cymru WHOIS service.

    Returns {asn, ip, bgp_prefix, country, registry, allocated, info} or
    empty dict on failure. More reliable than ARIN's OriginAS field
    which is often empty for AWS / large-cloud direct allocations.

        team_cymru_asn("8.8.8.8")
        → {"asn": "AS15169", "ip": "8.8.8.8",
           "bgp_prefix": "8.8.8.0/24", "country": "US",
           "registry": "arin", "allocated": "2014-03-14",
           "info": "GOOGLE, US"}
    """
    raw = await whois_cli(ip, server="whois.cymru.com",
                           query_prefix=" -v ", timeout=10)
    if not raw:
        return {}
    for line in raw.splitlines():
        if "|" not in line: continue
        low = line.strip().lower()
        if low.startswith("as ") or "bulk mode" in low:
            continue  # skip header / mode-line
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

def http_json(url: str, headers: dict | None = None,
               timeout: int = _DEFAULT_TIMEOUT) -> Optional[dict]:
    """Sync HTTP GET returning parsed JSON. None on any failure.
    Use http_json_async() inside async gatherers."""
    try:
        r = requests.get(url, headers=headers or {}, timeout=timeout, verify=False)
        if r.status_code != 200:
            return None
        return r.json()
    except Exception:
        return None


async def http_json_async(url: str, headers: dict | None = None,
                            timeout: int = _DEFAULT_TIMEOUT) -> Optional[dict]:
    """Async wrapper around http_json (uses asyncio.to_thread)."""
    return await asyncio.to_thread(http_json, url, headers, timeout)


# ───────────────────────── DNS HELPERS ─────────────────────────

async def dns_resolve(host: str, rtype: str, timeout: float = 3) -> list:
    """Async DNS query. Returns list of string answers, empty on failure.

        dns_resolve("example.com", "A")     → ["93.184.216.34"]
        dns_resolve("example.com", "MX")    → ["0 ."]
        dns_resolve("example.com", "TXT")   → ['"v=spf1 -all"', ...]
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout * 2
    resolver.timeout = timeout
    try:
        ans = await resolver.resolve(host, rtype)
        return [str(r).rstrip(".") for r in ans]
    except Exception:
        return []


async def dns_resolve_many(host: str, rtypes: list) -> dict:
    """Resolve multiple record types in parallel. Returns {rtype: [...]}.
    Empty list per rtype on individual failure (no exceptions raised).

        dns_resolve_many("example.com", ["A", "MX", "NS", "TXT"])
        → {"A": [...], "MX": [...], "NS": [...], "TXT": [...]}
    """
    tasks = [dns_resolve(host, rt) for rt in rtypes]
    results = await asyncio.gather(*tasks)
    return dict(zip(rtypes, results))

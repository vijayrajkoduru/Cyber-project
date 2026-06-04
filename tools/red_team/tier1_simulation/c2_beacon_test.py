"""c2_beacon_test - simulated C2 beaconing to customer-owned receiver
   (playbook §4 #43 manual C2 channel design + §6 #59 Sigma coverage).

Generates a deterministic C2 beacon pattern toward customer-supplied
endpoints. Tests detection of:
  - Jittered HTTPS POST beacons (httpx)
  - DNS TXT-record C2 queries (dnspython)
  - Encrypted payload pattern (Fernet, AES-128-CBC + HMAC-SHA256)

Customer input via ScanRequest.options (ALL targets are customer-owned):
  - options.c2_callback_url   - HTTPS endpoint to receive beacons (required)
  - options.c2_dns_domain     - DNS zone the customer monitoring owns (optional)
  - options.c2_dns_resolver   - resolver IP to send DNS C2 to (default 1.1.1.1)
  - options.c2_beacon_count   - number of beacons (default 8, max 16)
  - options.c2_interval_sec   - base interval seconds (default 7, max 30)
  - options.c2_jitter_pct     - jitter ±% (default 15, max 50)
  - options.c2_timeout_sec    - overall wall-clock cap (default 90, max 240)

The probe sends signals only to customer-controlled receivers. Customer
must verify their SIEM caught the pattern (high-frequency POSTs from
single source + DNS TXT bursts to same FQDN).

MITRE techniques: T1071.001 (Web Protocols), T1071.004 (DNS),
                  T1572 (Protocol Tunneling), T1573.001 (Symmetric Crypto).
"""
from __future__ import annotations
import asyncio
import base64
import os
import random
import secrets
import string
import time
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.c2_beacon_test_findings import C2_BEACON_TEST_FINDING_RULES

router = APIRouter()
DEFAULT_BEACONS = 8
HARD_MAX_BEACONS = 16
DEFAULT_INTERVAL = 7
HARD_MAX_INTERVAL = 30
DEFAULT_JITTER_PCT = 15
HARD_MAX_JITTER = 50
DEFAULT_OVERALL_TIMEOUT = 90
HARD_MAX_OVERALL = 240


class C2BeaconTestRequest(ScanRequest):
    options: Optional[dict] = None


def _gen_beacon_id() -> str:
    return secrets.token_hex(8)


def _encrypt_payload(key_b64: str, payload: bytes) -> str:
    """Fernet (AES-128-CBC + HMAC-SHA256). Falls back to xor-base64 if cryptography missing."""
    try:
        from cryptography.fernet import Fernet  # type: ignore
        f = Fernet(key_b64.encode("ascii"))
        return f.encrypt(payload).decode("ascii")
    except Exception:
        # Fallback - simple XOR + base64 so we still send "encrypted-looking" bytes
        seed = base64.urlsafe_b64decode(key_b64.encode("ascii"))
        xored = bytes(b ^ seed[i % len(seed)] for i, b in enumerate(payload))
        return base64.urlsafe_b64encode(xored).decode("ascii")


def _gen_key() -> str:
    """Generate Fernet key (32 url-safe-base64 bytes)."""
    try:
        from cryptography.fernet import Fernet  # type: ignore
        return Fernet.generate_key().decode("ascii")
    except Exception:
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")


async def _send_https_beacon(http_client, url: str, beacon_id: str,
                              seq: int, encrypted_payload: str, timeout: int) -> dict:
    """Send a single HTTPS POST beacon. Returns dict with status + latency."""
    start = time.time()
    try:
        # User-Agent rotating between 3 common values to look "stealthy"
        ua_pool = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/121.0",
        ]
        headers = {
            "User-Agent": ua_pool[seq % len(ua_pool)],
            "X-Beacon-Id": beacon_id,
            "X-Beacon-Seq": str(seq),
            "Content-Type": "application/octet-stream",
        }
        body = encrypted_payload.encode("ascii")
        resp = await http_client.post(url, content=body, headers=headers, timeout=timeout)
        elapsed = round((time.time() - start) * 1000, 1)
        return {
            "seq": seq,
            "ok": resp.status_code < 500,
            "status_code": resp.status_code,
            "elapsed_ms": elapsed,
            "ua": headers["User-Agent"][:40],
            "body_bytes": len(body),
        }
    except Exception as e:
        return {
            "seq": seq,
            "ok": False,
            "status_code": -1,
            "elapsed_ms": round((time.time() - start) * 1000, 1),
            "error": f"{type(e).__name__}: {str(e)[:140]}",
            "body_bytes": 0,
        }


def _send_dns_txt_beacon(resolver: str, fqdn: str, timeout: int) -> dict:
    """Send a TXT query for fqdn via resolver. Returns dict with status."""
    try:
        import dns.resolver  # type: ignore
        import dns.exception  # type: ignore
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [resolver]
        r.lifetime = timeout
        r.timeout = timeout
        try:
            answers = r.resolve(fqdn, "TXT")
            return {"fqdn": fqdn, "ok": True, "rcode": "NOERROR",
                     "answers": len(list(answers))}
        except dns.resolver.NXDOMAIN:
            return {"fqdn": fqdn, "ok": True, "rcode": "NXDOMAIN", "answers": 0}
        except dns.resolver.NoAnswer:
            return {"fqdn": fqdn, "ok": True, "rcode": "NOANSWER", "answers": 0}
        except dns.exception.Timeout:
            return {"fqdn": fqdn, "ok": False, "rcode": "TIMEOUT", "answers": 0}
    except Exception as e:
        return {"fqdn": fqdn, "ok": False,
                 "rcode": f"ERR:{type(e).__name__}",
                 "error": str(e)[:140], "answers": 0}


async def gather(ctx: ScanContext):
    opts = ctx.state.get("_options") or {}
    callback_url = (opts.get("c2_callback_url") or "").strip()
    dns_domain = (opts.get("c2_dns_domain") or "").strip()
    dns_resolver = (opts.get("c2_dns_resolver") or "1.1.1.1").strip()

    if not callback_url:
        ctx.state["c2_beacon_total"] = 0
        ctx.state["c2_input_missing"] = True
        ctx.source("missing c2_callback_url")
        return
    if not (callback_url.startswith("http://") or callback_url.startswith("https://")):
        ctx.state["c2_beacon_total"] = 0
        ctx.state["c2_input_invalid"] = "c2_callback_url must start with http(s)://"
        ctx.source("invalid c2_callback_url scheme")
        return

    beacons = min(int(opts.get("c2_beacon_count") or DEFAULT_BEACONS), HARD_MAX_BEACONS)
    base_interval = min(int(opts.get("c2_interval_sec") or DEFAULT_INTERVAL),
                          HARD_MAX_INTERVAL)
    jitter_pct = min(int(opts.get("c2_jitter_pct") or DEFAULT_JITTER_PCT),
                       HARD_MAX_JITTER)
    overall_to = min(int(opts.get("c2_timeout_sec") or DEFAULT_OVERALL_TIMEOUT),
                       HARD_MAX_OVERALL)
    per_req_to = 8

    beacon_id = _gen_beacon_id()
    fernet_key = _gen_key()

    https_results: list[dict] = []
    dns_results: list[dict] = []

    overall_deadline = time.time() + overall_to

    try:
        import httpx
    except Exception as e:
        ctx.state["c2_beacon_total"] = 0
        ctx.state["c2_lib_missing"] = f"httpx import failed: {e}"
        ctx.source("httpx missing")
        return

    async with httpx.AsyncClient(verify=False, follow_redirects=False) as client:
        for seq in range(1, beacons + 1):
            if time.time() >= overall_deadline:
                break
            # Build encrypted payload: includes beacon_id + seq + 64B random
            payload_raw = (f"id={beacon_id};seq={seq};ts={int(time.time())};"
                            + secrets.token_hex(32)).encode("ascii")
            payload_enc = _encrypt_payload(fernet_key, payload_raw)

            res = await _send_https_beacon(client, callback_url, beacon_id, seq,
                                            payload_enc, per_req_to)
            https_results.append(res)

            # DNS C2 (TXT) if customer supplied a zone
            if dns_domain:
                sub = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
                fqdn = f"{sub}.{seq}.{beacon_id[:8]}.{dns_domain.lstrip('.')}"
                d = await asyncio.to_thread(_send_dns_txt_beacon, dns_resolver, fqdn, per_req_to)
                dns_results.append(d)

            # Jittered sleep between beacons (skip after last)
            if seq < beacons and time.time() < overall_deadline:
                jitter = base_interval * (jitter_pct / 100.0)
                sleep_for = max(0.0, base_interval + random.uniform(-jitter, jitter))
                # Don't sleep past the deadline
                sleep_for = min(sleep_for, max(0.0, overall_deadline - time.time()))
                if sleep_for > 0:
                    await asyncio.sleep(sleep_for)

    https_ok = sum(1 for r in https_results if r.get("ok"))
    dns_ok = sum(1 for r in dns_results if r.get("ok"))

    ctx.state["c2_beacon_id"]            = beacon_id
    ctx.state["c2_beacon_callback_url"]  = callback_url
    ctx.state["c2_beacon_dns_domain"]    = dns_domain or None
    ctx.state["c2_beacon_https_results"] = https_results
    ctx.state["c2_beacon_dns_results"]   = dns_results
    ctx.state["c2_beacon_https_sent"]    = len(https_results)
    ctx.state["c2_beacon_https_ok"]      = https_ok
    ctx.state["c2_beacon_dns_sent"]      = len(dns_results)
    ctx.state["c2_beacon_dns_ok"]        = dns_ok
    ctx.state["c2_beacon_total"]         = len(https_results) + len(dns_results)
    ctx.state["c2_beacon_interval_sec"]  = base_interval
    ctx.state["c2_beacon_jitter_pct"]    = jitter_pct
    ctx.source(f"c2 beacon test -> beacon_id={beacon_id}; "
                f"https={https_ok}/{len(https_results)} dns={dns_ok}/{len(dns_results)}")


INTEL_FIELDS = [
    ("Beacon ID",            "c2_beacon_id"),
    ("HTTPS callback URL",   "c2_beacon_callback_url"),
    ("DNS C2 zone",          "c2_beacon_dns_domain"),
    ("HTTPS beacons sent",   "c2_beacon_https_sent"),
    ("HTTPS beacons OK",     "c2_beacon_https_ok"),
    ("DNS beacons sent",     "c2_beacon_dns_sent"),
    ("DNS beacons OK",       "c2_beacon_dns_ok"),
    ("Base interval (sec)",  "c2_beacon_interval_sec"),
    ("Jitter (+/-%)",        "c2_beacon_jitter_pct"),
]


@router.post("/api/red_team/c2_beacon_test")
async def red_team_c2_beacon_test(req: C2BeaconTestRequest,
                                    _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="c2_beacon_test",
        gather_func=_gather_with_options,
        finding_rules=C2_BEACON_TEST_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)

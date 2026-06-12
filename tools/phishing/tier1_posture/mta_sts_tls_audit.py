"""mta_sts_tls_audit - MTA-STS / TLS-RPT / DANE inbound-TLS posture probe
(playbook §1 cross-ref #5/#6, §2 — the second-layer mail-transport fence
that backs up SPF/DKIM/DMARC).

SPF/DKIM/DMARC stop *forged-sender* phishing. MTA-STS + DANE + TLS-RPT
stop the *transport downgrade* that lets an active network attacker strip
STARTTLS and read (or rewrite) inbound mail in transit — including the
DMARC/DKIM headers themselves and any password-reset / MFA links. This
probe checks, for the target email domain, whether those records are
PUBLISHED — a purely read-only DNS + HTTPS inspection of public records.

What the probe does (all read-only, all on PUBLIC records):
  1. MTA-STS policy:
       - TXT on `_mta-sts.<domain>` looking for `v=STSv1; id=...`
       - GET https://mta-sts.<domain>/.well-known/mta-sts.txt and parse
         `version: STSv1`, `mode: enforce|testing|none`, `mx:` lines,
         `max_age:`
  2. TLS-RPT:
       - TXT on `_smtp._tls.<domain>` looking for `v=TLSRPTv1; rua=...`
  3. DANE TLSA (opportunistic):
       - For the top-priority MX host, TLSA query on `_25._tcp.<mxhost>`

Severity model — these are DETECTED CONDITIONS (record present/absent is
a fact established by DNS/HTTP, not an inference), so graded severities
are allowed ONLY when the absence/weakness is actually observed:

  MEDIUM   - MTA-STS policy absent (TXT + well-known both missing) AND
             the domain has an MX (i.e. it really does receive mail)
  LOW      - MTA-STS policy mode is `testing` or `none` (published but
             not enforcing — downgrade still succeeds)
  LOW      - TLS-RPT record absent (no visibility into TLS failures)
  INFO     - MTA-STS enforce present but DANE TLSA absent (informational —
             either mechanism is acceptable; advisory only)
  INFO     - dnspython missing / domain has no MX (nothing to assess)
  POSITIVE - MTA-STS mode=enforce published (TXT + valid well-known)

ZERO-FP guard: a graded finding fires ONLY when the MX exists (domain
receives mail) AND the relevant record was actually queried and found
absent/weak. No MX -> INFO only.

Customer input via ScanRequest.target = email domain (e.g. "acme.com").
Optional ScanRequest.options:
  - timeout_sec   = per-lookup / per-HTTP timeout (default 10, cap 30)

References:
  - RFC 8461 (SMTP MTA Strict Transport Security)
  - RFC 8460 (SMTP TLS Reporting)
  - RFC 7672 (DANE for SMTP) / RFC 6698 (TLSA)
"""
from __future__ import annotations
import asyncio
import re
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.mta_sts_tls_audit_findings import (
    MTA_STS_TLS_AUDIT_FINDING_RULES,
)

router = APIRouter()


class MtaStsRequest(ScanRequest):
    options: Optional[dict] = None


def _normalize_domain(target: str) -> str:
    d = (target or "").strip()
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split("?", 1)[0]
    if d.lower().startswith("www."):
        d = d[4:]
    return d.lower().rstrip(".")


def _resolve_txt_sync(domain: str, dns_module, timeout: float) -> list[str]:
    try:
        ans = dns_module.resolver.resolve(domain, "TXT", lifetime=timeout)
    except Exception:
        return []
    out = []
    for r in ans:
        try:
            parts = []
            for s in getattr(r, "strings", []) or []:
                parts.append(s.decode("utf-8", errors="ignore")
                             if isinstance(s, (bytes, bytearray)) else str(s))
            out.append("".join(parts) if parts else str(r).strip('"'))
        except Exception:
            try:
                out.append(str(r).strip('"'))
            except Exception:
                continue
    return out


def _resolve_mx_sync(domain: str, dns_module, timeout: float) -> Optional[str]:
    try:
        ans = dns_module.resolver.resolve(domain, "MX", lifetime=timeout)
    except Exception:
        return None
    best = None
    best_pref = 10_000
    for r in ans:
        try:
            pref = int(getattr(r, "preference", 9999))
            host = str(getattr(r, "exchange", "")).rstrip(".")
            if host and pref < best_pref:
                best, best_pref = host, pref
        except Exception:
            continue
    return best


def _query_tlsa_sync(name: str, dns_module, timeout: float) -> bool:
    """Return True if at least one TLSA record exists at `name`."""
    try:
        ans = dns_module.resolver.resolve(name, "TLSA", lifetime=timeout)
        return len(list(ans)) > 0
    except Exception:
        return False


def _parse_mta_sts_policy(body: str) -> dict:
    """Parse a /.well-known/mta-sts.txt body (RFC 8461 §3.2)."""
    out: dict = {"version": None, "mode": None, "mx": [], "max_age": None}
    for line in (body or "").splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip().lower(); v = v.strip()
        if k == "version":
            out["version"] = v
        elif k == "mode":
            out["mode"] = v.lower()
        elif k == "mx":
            out["mx"].append(v.lower())
        elif k == "max_age":
            out["max_age"] = v
    return out


async def gather(ctx: ScanContext):
    domain = _normalize_domain(ctx.host or "")
    if not domain:
        ctx.source("no-target")
        return
    try:
        import dns.resolver  # noqa: F401
        import dns
    except ImportError:
        ctx.state["mta_sts_error"] = (
            "dnspython not installed (pip install dnspython)"
        )
        ctx.source("dnspython missing")
        return

    opts = ctx.state.get("_options") or {}
    try:
        timeout = min(max(int(opts.get("timeout_sec") or 10), 3), 30)
    except (TypeError, ValueError):
        timeout = 10
    loop = asyncio.get_event_loop()

    ctx.state["mta_sts_target_domain"] = domain

    # ---- MX (does the domain actually receive mail?) ---------------
    mx = await loop.run_in_executor(None, _resolve_mx_sync, domain, dns, float(timeout))
    ctx.state["mta_sts_mx_host"] = mx
    ctx.state["mta_sts_has_mx"] = bool(mx)
    if not mx:
        ctx.source(f"no MX for {domain} -> mail-transport posture N/A")
        # Still report TXT records if present, but no graded MX-gated finding.

    # ---- MTA-STS TXT signpost --------------------------------------
    sts_txt = await loop.run_in_executor(
        None, _resolve_txt_sync, f"_mta-sts.{domain}", dns, float(timeout))
    sts_signpost = None
    for rec in sts_txt:
        if re.match(r"^\s*v=STSv1\b", rec, re.IGNORECASE):
            sts_signpost = rec.strip()
            break
    ctx.state["mta_sts_txt_present"] = bool(sts_signpost)
    ctx.state["mta_sts_txt_record"] = sts_signpost
    ctx.source(f"TXT _mta-sts.{domain} -> "
               f"{'present' if sts_signpost else 'absent'}")

    # ---- MTA-STS well-known policy ---------------------------------
    policy = None
    policy_err = None
    try:
        import httpx
        url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        async with httpx.AsyncClient(
            verify=True, timeout=timeout, follow_redirects=False,
            headers={"User-Agent": "VulnusLab-MTA-STS-audit/1.0"},
        ) as client:
            r = await client.get(url)
        if r.status_code == 200 and "stsv1" in (r.text or "").lower():
            policy = _parse_mta_sts_policy(r.text)
            ctx.state["mta_sts_policy_url"] = url
            ctx.state["mta_sts_policy_status"] = r.status_code
        else:
            policy_err = f"HTTP {r.status_code} / not a valid STSv1 policy"
    except ImportError:
        policy_err = "httpx not installed"
    except Exception as e:
        policy_err = f"{type(e).__name__}: {str(e)[:100]}"
    ctx.state["mta_sts_policy"] = policy
    if policy_err:
        ctx.state["mta_sts_policy_error"] = policy_err
    ctx.state["mta_sts_policy_mode"] = (policy or {}).get("mode")
    # The whole MTA-STS mechanism is "deployed" only when BOTH the TXT
    # signpost AND a valid well-known policy are present (RFC 8461 §2).
    ctx.state["mta_sts_deployed"] = bool(sts_signpost and policy)
    ctx.source(f"GET well-known mta-sts.txt -> "
               f"{(policy or {}).get('mode') if policy else (policy_err or 'absent')}")

    # ---- TLS-RPT ---------------------------------------------------
    tlsrpt_txt = await loop.run_in_executor(
        None, _resolve_txt_sync, f"_smtp._tls.{domain}", dns, float(timeout))
    tlsrpt = None
    for rec in tlsrpt_txt:
        if re.match(r"^\s*v=TLSRPTv1\b", rec, re.IGNORECASE):
            tlsrpt = rec.strip()
            break
    ctx.state["tlsrpt_present"] = bool(tlsrpt)
    ctx.state["tlsrpt_record"] = tlsrpt
    ctx.source(f"TXT _smtp._tls.{domain} -> "
               f"{'present' if tlsrpt else 'absent'}")

    # ---- DANE TLSA on the top MX (informational) -------------------
    dane_present = False
    if mx:
        dane_present = await loop.run_in_executor(
            None, _query_tlsa_sync, f"_25._tcp.{mx}", dns, float(timeout))
    ctx.state["dane_tlsa_present"] = dane_present
    if mx:
        ctx.source(f"TLSA _25._tcp.{mx} -> "
                   f"{'present' if dane_present else 'absent'}")


INTEL_FIELDS = [
    ("Target domain",          "mta_sts_target_domain"),
    ("Top MX host",            "mta_sts_mx_host"),
    ("MTA-STS TXT signpost",   "mta_sts_txt_record"),
    ("MTA-STS policy mode",    "mta_sts_policy_mode"),
    ("MTA-STS policy",         "mta_sts_policy"),
    ("MTA-STS deployed",       "mta_sts_deployed"),
    ("TLS-RPT record",         "tlsrpt_record"),
    ("DANE TLSA present",      "dane_tlsa_present"),
]


@router.post("/api/phishing/mta_sts_tls_audit")
async def phishing_mta_sts_tls_audit(req: MtaStsRequest,
                                      _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="mta_sts_tls_audit",
        gather_func=_gather_with_options,
        finding_rules=MTA_STS_TLS_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)

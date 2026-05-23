"""DNS Records Intelligence — first tool built through tools/_framework.

Route: /api/recon/dns

Multi-source async gathering (11 sources in parallel):
  1. A records          5. TXT records          9.  DMARC (_dmarc.<host>)
  2. AAAA records       6. CNAME records        10. DKIM (9 common selectors)
  3. MX records         7. SOA records          11. Wildcard probe
  4. NS records         8. CAA records

Then runs ~22 findings rules (tools/_payloads/dns_findings.py) against
the collected data. Returns named findings + intel + sources_used.

Replaces the previous sequential implementation. Same checks, but:
- All DNS queries fire in parallel via asyncio.gather (10x faster)
- More findings (SPF strict-policy, DKIM detection, mail provider ID,
  CDN detection from A IPs, verification-debt tracking, etc.)
- Uses the scanner framework (30 lines of scanner-specific code)
"""
import re
import secrets

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import (
    ScanContext, run_scanner,
    dns_resolve, dns_resolve_many,
)
from tools._payloads.dns_findings import (
    DNS_FINDING_RULES, COMMON_DKIM_SELECTORS,
)

router = APIRouter()


# Skip non-public targets — SPF/DMARC/CAA checks are meaningless for
# internal hostnames, RFC-1918 IPs, lab containers, etc.
def _is_internal_target(t: str) -> bool:
    t = (t or "").strip().lower()
    return (
        re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", t) is not None
        or t in ("localhost", "")
        or "." not in t
        or t.endswith((".local", ".internal", ".test", ".lan",
                        ".home", ".localhost", ".example"))
        or t.startswith(("10.", "127.", "192.168.", "169.254."))
        or re.match(r"^172\.(1[6-9]|2\d|3[01])\.", t) is not None
    )


async def gather(ctx: ScanContext):
    """Populate state with parallel DNS queries + DMARC + DKIM + wildcard."""
    host = ctx.host

    # Phase 1: base records (parallel via dns_resolve_many)
    base = await dns_resolve_many(host, ["A", "AAAA", "MX", "NS", "TXT",
                                          "CNAME", "SOA", "CAA"])
    ctx.state.update(base)
    # Granular sources — each record type that actually returned data counts
    # as a discrete data source. Surfaces in the report's Sources Gathered
    # footer as "dig-A, dig-MX, dig-NS, dig-TXT" instead of one bulk "dig".
    for rtype, vals in base.items():
        if vals:
            ctx.source(f"dig-{rtype}")

    # Phase 2: DMARC + DKIM probes + wildcard probe — all parallel
    import asyncio
    async def _dmarc():
        return await dns_resolve(f"_dmarc.{host}", "TXT")

    async def _dkim():
        # Probe common selectors, collect which ones return v=DKIM1 TXT
        found = []
        tasks = [dns_resolve(f"{sel}._domainkey.{host}", "TXT")
                  for sel in COMMON_DKIM_SELECTORS]
        results = await asyncio.gather(*tasks)
        for sel, recs in zip(COMMON_DKIM_SELECTORS, results):
            for r in (recs or []):
                if "v=dkim1" in r.lower():
                    found.append(sel)
                    break
        return found

    async def _wildcard():
        # Random subdomain that should NOT exist — if it resolves, wildcard is set
        rand = f"vlcanary-{secrets.token_hex(6)}.{host}"
        resp = await dns_resolve(rand, "A")
        return rand, resp

    dmarc_recs, dkim_found, (wc_name, wc_resp) = await asyncio.gather(
        _dmarc(), _dkim(), _wildcard()
    )

    # Extract SPF (from main TXT records at apex)
    txt_lower = [str(t).lower() for t in (ctx.state.get("TXT") or [])]
    spf = next((t for t in (ctx.state.get("TXT") or [])
                if "v=spf1" in str(t).lower()), None)
    ctx.state["spf"] = spf

    # Extract DMARC from _dmarc TXT
    dmarc = next((t for t in (dmarc_recs or [])
                  if "v=dmarc1" in str(t).lower()), None)
    ctx.state["dmarc"] = dmarc
    if dmarc_recs:
        ctx.source("dig-dmarc")

    # DKIM
    ctx.state["dkim_selectors_found"] = dkim_found
    if dkim_found:
        ctx.source("dig-dkim")

    # Wildcard
    ctx.state["wildcard_detected"] = bool(wc_resp)
    if wc_resp:
        ctx.state["wildcard_evidence"] = f"{wc_name} resolved to {wc_resp[0]}"

    # Verification debt — count TXT records that look like verification tokens.
    # Only surfaces as intel when >0 (filtered out in INTEL_FIELDS via 0 -> falsy).
    verification_patterns = [
        r"google-site-verification=",
        r"facebook-domain-verification=",
        r"atlassian-domain-verification=",
        r"docusign=",
        r"adobe-idp-site-verification=",
        r"apple-domain-verification=",
        r"mailru-verification:",
        r"yandex-verification:",
        r"slack-verification=",
        r"stripe-verification=",
        r"shopify-verification=",
        r"webex-domain-verification=",
        r"_domain-verification=",
        r"openai-domain-verification=",
        r"github-verification=",
    ]
    count = 0
    for t in (ctx.state.get("TXT") or []):
        for p in verification_patterns:
            if re.search(p, str(t), re.I):
                count += 1
                break
    # Only surface in intel when there ARE verification tokens — a "0"
    # row in the Intel table is just noise.
    if count > 0:
        ctx.state["verification_count"] = count

    # Build a unified records[] list at top level for backwards-compat with
    # the existing dashboard tile + PDF renderer.
    records = []
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"):
        for v in (ctx.state.get(rtype) or []):
            records.append({"type": rtype, "value": str(v)})
    ctx.state["records"] = records


INTEL_FIELDS = [
    ("A records",         "A"),
    ("AAAA records",      "AAAA"),
    ("MX servers",        "MX"),
    ("Nameservers",       "NS"),
    ("SOA",               "SOA"),
    ("CAA",               "CAA"),
    ("SPF record",        "spf"),
    ("DMARC record",      "dmarc"),
    ("DKIM selectors",    "dkim_selectors_found"),
    ("Wildcard DNS",      "wildcard_detected"),
    ("Verification tokens", "verification_count"),
]


@router.post("/api/recon/dns")
async def recon_dns(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    # Skip non-public targets cleanly — SPF/DMARC/CAA checks don't apply
    # to internal hostnames or RFC-1918 IPs.
    if _is_internal_target(host):
        from tools._shared import standard_response
        return standard_response(
            tool="dns", target=host, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=(f"Target {host!r} is not a public internet domain "
                           "(internal/private/reserved); DNS email-auth checks "
                           "only apply to publicly routed domains."),
        )

    return await run_scanner(
        host=host,
        tool="dns",
        gather_func=gather,
        finding_rules=DNS_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        # Backwards-compat: frontend "DNS Records" tile + PDF Section 4
        # (around App.js:7367) read these at top level.
        flat_field_keys=["records", "A", "AAAA", "MX", "NS", "TXT",
                          "CNAME", "SOA", "CAA", "spf", "dmarc"],
    )


def register(app):
    app.include_router(router)

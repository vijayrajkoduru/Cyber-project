"""gws_email_spoofing_audit - Google Workspace / Gmail spoofing-protection
audit (playbook §2 #25 "Gmail spoofing protection (SPF/DKIM/DMARC)").

This is the externally-visible slice of Google Workspace posture: a domain's
inbound/outbound spoofing protection is published in DNS and can be read by
anyone WITHOUT any tenant credential. We query, over DNS only:

  - SPF   : TXT on <domain> for `v=spf1 ...`, and whether it `include:`s
            Google (`_spf.google.com`) — the Workspace SPF anchor.
  - DMARC : TXT on `_dmarc.<domain>` for `v=DMARC1 ...` + policy (p=).
  - DKIM  : TXT on <selector>._domainkey.<domain> for Google's default
            selectors (google, google2048, default) plus common SaaS ones.

A weak posture here means anyone can spoof mail "from" the org's Workspace
domain. Findings are graded ONLY when the actual DNS record proves the
weakness (CONFIRMED, read straight off DNS). Anything we could not resolve
degrades to INFO — never a false positive.

This performs READ-ONLY DNS lookups. No mail is sent, no spoof is attempted,
nothing is authenticated. Detection-only (VA), not exploitation (PT).

Severity model (all CONFIRMED off DNS):
  HIGH    - no DMARC record at all (open to spoofing, no reporting)
  HIGH    - SPF ends in `+all` (anyone may send as the domain)
  HIGH    - DMARC p=none (monitor-only: spoofed mail still delivered)
  MEDIUM  - no SPF record present
  MEDIUM  - SPF present but does NOT include Google while domain is a
            confirmed Workspace MX (mis-scoped SPF -> Google mail may fail
            alignment). Only fires when MX actually points to Google.
  LOW     - no DKIM selector found for any probed selector
  POSITIVE- DMARC p=reject/quarantine + SPF -all/~all + >=1 DKIM selector
  INFO    - dnspython missing / nothing resolvable

Customer input:
  - ScanRequest.target = the Workspace email domain (e.g. "acme.com").
  - options.dkim_selectors = optional newline-separated extra selectors.
"""
from __future__ import annotations
import re
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner

router = APIRouter()

# Google Workspace's own DKIM selectors first, then common providers.
GWS_DKIM_SELECTORS = [
    "google", "google2048", "default", "selector1", "selector2",
    "k1", "mail", "dkim", "s1", "s2",
]
GOOGLE_SPF_INCLUDE = "_spf.google.com"
GOOGLE_MX_SUFFIXES = ("google.com", "googlemail.com", "aspmx.l.google.com")


class GwsEmailSpoofingRequest(ScanRequest):
    options: Optional[dict] = None


def _normalize_domain(target: str) -> str:
    d = (target or "").strip()
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split("?", 1)[0].split("@")[-1]
    if d.lower().startswith("www."):
        d = d[4:]
    return d.lower().rstrip(".")


async def _resolve_txt(domain: str, dns_module) -> list[str]:
    try:
        ans = dns_module.resolver.resolve(domain, "TXT", lifetime=8.0)
    except Exception:
        return []
    out = []
    for r in ans:
        try:
            parts = []
            for sp in r.strings:
                parts.append(sp.decode("utf-8", errors="ignore")
                             if isinstance(sp, (bytes, bytearray)) else str(sp))
            out.append("".join(parts))
        except Exception:
            try:
                out.append(str(r).strip('"'))
            except Exception:
                continue
    return out


async def _resolve_mx(domain: str, dns_module) -> list[str]:
    try:
        ans = dns_module.resolver.resolve(domain, "MX", lifetime=8.0)
    except Exception:
        return []
    out = []
    for r in ans:
        try:
            out.append(str(r.exchange).rstrip(".").lower())
        except Exception:
            continue
    return out


async def _domain_resolves(domain: str, dns_module) -> bool:
    """True only if the domain authoritatively exists in DNS (has NS, A, or
    MX). Distinguishes a real 'no DMARC' (NXDOMAIN-clean zone exists) from a
    transient resolver failure — prevents false 'missing record' findings.
    Returns False on NXDOMAIN AND on total resolver failure (be conservative:
    if we cannot confirm the zone exists, we do not grade absence)."""
    for rtype in ("NS", "A", "MX"):
        try:
            ans = dns_module.resolver.resolve(domain, rtype, lifetime=8.0)
            if ans and len(ans) > 0:
                return True
        except dns_module.resolver.NoAnswer:
            # Record type absent but the zone exists -> domain resolves.
            return True
        except dns_module.resolver.NXDOMAIN:
            return False
        except Exception:
            continue
    return False


def _parse_spf(record: str) -> dict:
    out = {"raw": record, "all_qualifier": None, "includes": []}
    for tok in record.strip().split():
        low = tok.lower()
        if low.startswith("include:"):
            out["includes"].append(tok.split(":", 1)[1])
        if low.endswith("all"):
            if tok[:1] in ("+", "-", "~", "?"):
                out["all_qualifier"] = tok[:1]
            elif low == "all":
                out["all_qualifier"] = "+"
    return out


def _parse_dmarc(record: str) -> dict:
    out = {"raw": record, "p": None, "sp": None, "rua": None}
    for part in record.split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        k = k.strip().lower(); v = v.strip()
        if k in out:
            out[k] = v
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
        ctx.state["gws_email_spoofing_error"] = "dnspython not installed"
        ctx.source("dnspython missing")
        return

    opts = ctx.state.get("_options") or {}
    extra_raw = (opts.get("dkim_selectors") or "").strip()
    selectors = list(GWS_DKIM_SELECTORS)
    if extra_raw:
        for line in extra_raw.splitlines():
            v = line.strip()
            if v and v not in selectors:
                selectors.append(v)
    selectors = selectors[:20]

    # Authoritative existence check FIRST — only grade record-absence when the
    # zone provably exists (prevents false 'missing DMARC/SPF' on a transient
    # resolver failure or a typo'd domain).
    resolves = await _domain_resolves(domain, dns)
    ctx.source(f"DNS zone exists for {domain}: {resolves}")

    # MX — to know if this is genuinely a Google Workspace mail domain.
    mx_hosts = await _resolve_mx(domain, dns)
    is_google_mx = any(
        any(h.endswith(suf) or suf in h for suf in GOOGLE_MX_SUFFIXES)
        for h in mx_hosts
    )
    ctx.source(f"dig MX {domain} -> {len(mx_hosts)} host(s); google_mx={is_google_mx}")

    # SPF
    spf_records = []
    for rec in await _resolve_txt(domain, dns):
        if re.match(r"^\s*v=spf1\b", rec, re.IGNORECASE):
            spf_records.append(_parse_spf(rec))
    ctx.source(f"dig TXT {domain} -> {len(spf_records)} SPF record(s)")

    # DMARC
    dmarc_records = []
    for rec in await _resolve_txt(f"_dmarc.{domain}", dns):
        if re.match(r"^\s*v=DMARC1\b", rec, re.IGNORECASE):
            dmarc_records.append(_parse_dmarc(rec))
    ctx.source(f"dig TXT _dmarc.{domain} -> {len(dmarc_records)} DMARC record(s)")

    # DKIM
    dkim_found = []
    for sel in selectors:
        for rec in await _resolve_txt(f"{sel}._domainkey.{domain}", dns):
            low = rec.lower()
            if "k=" in low or "p=" in low or low.startswith("v=dkim1"):
                dkim_found.append({"selector": sel,
                                   "preview": rec[:100]})
                break
    ctx.source(f"DKIM selectors probed: {len(selectors)}, found: {len(dkim_found)}")

    spf_all = spf_records[0].get("all_qualifier") if spf_records else None
    spf_includes_google = any(
        GOOGLE_SPF_INCLUDE in inc.lower()
        for r in spf_records for inc in r.get("includes", [])
    )
    dmarc_p = (dmarc_records[0].get("p") or "").lower() if dmarc_records else ""

    ctx.state["gws_spoof_domain"] = domain
    ctx.state["gws_spoof_resolves"] = resolves
    ctx.state["gws_spoof_mx_hosts"] = mx_hosts
    ctx.state["gws_spoof_is_google_mx"] = is_google_mx
    ctx.state["gws_spoof_spf_records"] = spf_records
    ctx.state["gws_spoof_spf_all"] = spf_all
    ctx.state["gws_spoof_spf_includes_google"] = spf_includes_google
    ctx.state["gws_spoof_dmarc_records"] = dmarc_records
    ctx.state["gws_spoof_dmarc_p"] = dmarc_p
    ctx.state["gws_spoof_dkim_found"] = dkim_found
    ctx.state["gws_spoof_spf_present"] = bool(spf_records)
    ctx.state["gws_spoof_dmarc_present"] = bool(dmarc_records)
    ctx.state["gws_spoof_dkim_present"] = bool(dkim_found)
    ctx.state["gws_spoof_evaluated"] = True


def rule_error(s):
    if not s.get("gws_email_spoofing_error"):
        return None
    return {
        "name": "Workspace email-spoofing audit could not run",
        "severity": "INFO",
        "evidence": str(s.get("gws_email_spoofing_error")),
        "remediation": "Install dnspython on the scanner host and re-run.",
        "cwe": "N/A", "iso27001": "A.5.23",
    }


def rule_unresolvable(s):
    if not s.get("gws_spoof_evaluated"):
        return None
    if s.get("gws_spoof_resolves"):
        return None
    return {
        "name": f"Domain {s.get('gws_spoof_domain')} did not resolve — "
                f"spoofing audit inconclusive",
        "severity": "INFO",
        "evidence": (
            "The domain has no authoritative NS/A/MX record (NXDOMAIN or the "
            "resolver could not confirm the zone). Record-absence is NOT "
            "graded to avoid a false positive — re-run with a resolvable "
            "email domain."
        ),
        "remediation": (
            "Confirm the target is the org's real email domain (the part after "
            "@ in user mailboxes), then re-run."
        ),
        "cwe": "N/A", "iso27001": "A.5.23",
    }


def rule_no_dmarc(s):
    if not s.get("gws_spoof_evaluated"):
        return None
    if not s.get("gws_spoof_resolves"):
        return None
    if s.get("gws_spoof_dmarc_present"):
        return None
    return {
        "name": f"No DMARC record on {s.get('gws_spoof_domain')} — domain is "
                f"spoofable",
        "severity": "HIGH",
        "evidence": (
            f"DNS query for _dmarc.{s.get('gws_spoof_domain')} returned no "
            "v=DMARC1 record. Without DMARC, receivers cannot reject forged "
            "mail and the org gets no spoofing-report visibility. CONFIRMED "
            "directly from DNS."
        ),
        "remediation": (
            "Publish a DMARC record starting at p=none with rua= reporting, "
            "monitor, then move to p=quarantine and p=reject. In Google "
            "Admin > Apps > Gmail > Authenticate email, confirm SPF/DKIM "
            "align first."
        ),
        "cwe": "CWE-290", "owasp": "A07:2021", "iso27001": "A.8.5",
        "verified_exploit": True,
    }


def rule_dmarc_p_none(s):
    if not s.get("gws_spoof_evaluated"):
        return None
    if not s.get("gws_spoof_dmarc_present"):
        return None
    if s.get("gws_spoof_dmarc_p") != "none":
        return None
    return {
        "name": f"DMARC policy is p=none on {s.get('gws_spoof_domain')} "
                f"(monitor-only)",
        "severity": "HIGH",
        "evidence": (
            "The published DMARC record sets p=none. Spoofed mail is still "
            "delivered to recipients — the policy only collects reports. "
            "CONFIRMED from the live DNS record."
        ),
        "remediation": (
            "After confirming legitimate senders pass alignment (review the "
            "rua aggregate reports), raise the policy to p=quarantine and "
            "then p=reject."
        ),
        "cwe": "CWE-290", "owasp": "A07:2021", "iso27001": "A.8.5",
        "verified_exploit": True,
    }


def rule_spf_plus_all(s):
    if not s.get("gws_spoof_evaluated"):
        return None
    if s.get("gws_spoof_spf_all") != "+":
        return None
    return {
        "name": f"SPF ends in +all on {s.get('gws_spoof_domain')} — anyone "
                f"may send as this domain",
        "severity": "HIGH",
        "evidence": (
            "The SPF record terminates with `+all`, which authorises ANY IP "
            "to send mail as the domain — equivalent to having no SPF. "
            "CONFIRMED from the live DNS TXT record."
        ),
        "remediation": (
            "Change the trailing mechanism to `-all` (hard fail) or `~all` "
            "(soft fail) once all legitimate senders (include:_spf.google.com "
            "for Workspace) are enumerated."
        ),
        "cwe": "CWE-290", "owasp": "A07:2021", "iso27001": "A.8.5",
        "verified_exploit": True,
    }


def rule_no_spf(s):
    if not s.get("gws_spoof_evaluated"):
        return None
    if not s.get("gws_spoof_resolves"):
        return None
    if s.get("gws_spoof_spf_present"):
        return None
    return {
        "name": f"No SPF record on {s.get('gws_spoof_domain')}",
        "severity": "MEDIUM",
        "evidence": (
            f"No v=spf1 TXT record was found for {s.get('gws_spoof_domain')}. "
            "Receivers have no authorised-sender list, weakening anti-spoofing "
            "and DMARC alignment. CONFIRMED from DNS."
        ),
        "remediation": (
            "Publish an SPF record. For Google Workspace: "
            "`v=spf1 include:_spf.google.com ~all`."
        ),
        "cwe": "CWE-290", "owasp": "A07:2021", "iso27001": "A.8.5",
        "verified_exploit": True,
    }


def rule_spf_missing_google(s):
    # Only fires when MX genuinely points to Google but SPF doesn't include it.
    if not s.get("gws_spoof_evaluated"):
        return None
    if not s.get("gws_spoof_is_google_mx"):
        return None
    if not s.get("gws_spoof_spf_present"):
        return None
    if s.get("gws_spoof_spf_includes_google"):
        return None
    return {
        "name": f"SPF on {s.get('gws_spoof_domain')} omits Google while MX "
                f"points to Workspace",
        "severity": "MEDIUM",
        "evidence": (
            "MX records resolve to Google Workspace mail servers, but the "
            "SPF record does not include:_spf.google.com. Outbound Workspace "
            "mail may fail SPF alignment at receivers. CONFIRMED from the "
            "live MX + SPF records."
        ),
        "remediation": (
            "Add `include:_spf.google.com` to the SPF record so Google's "
            "sending ranges are authorised."
        ),
        "cwe": "CWE-290", "owasp": "A07:2021", "iso27001": "A.8.5",
        "verified_exploit": True,
    }


def rule_no_dkim(s):
    if not s.get("gws_spoof_evaluated"):
        return None
    if not s.get("gws_spoof_resolves"):
        return None
    if s.get("gws_spoof_dkim_present"):
        return None
    return {
        "name": f"No DKIM selector found for {s.get('gws_spoof_domain')}",
        "severity": "LOW",
        "evidence": (
            "None of the probed DKIM selectors (google, google2048, default, "
            "and common SaaS selectors) resolved a key for the domain. DKIM "
            "may be unconfigured or use a non-standard selector. CONFIRMED "
            "from DNS (absence of common selectors)."
        ),
        "remediation": (
            "In Google Admin > Apps > Gmail > Authenticate email, generate "
            "and publish the DKIM key, then verify the `google._domainkey` "
            "TXT record resolves. If using a custom selector, add it to "
            "options.dkim_selectors."
        ),
        "cwe": "CWE-290", "owasp": "A07:2021", "iso27001": "A.8.5",
        "verified_exploit": True,
    }


def rule_positive(s):
    if not s.get("gws_spoof_evaluated"):
        return None
    if not s.get("gws_spoof_resolves"):
        return None
    p = s.get("gws_spoof_dmarc_p")
    if p not in ("reject", "quarantine"):
        return None
    if s.get("gws_spoof_spf_all") not in ("-", "~"):
        return None
    if not s.get("gws_spoof_dkim_present"):
        return None
    return {
        "name": f"Email spoofing protection is strong on "
                f"{s.get('gws_spoof_domain')}",
        "severity": "POSITIVE",
        "evidence": (
            f"DMARC p={p}, SPF terminates `{s.get('gws_spoof_spf_all')}all`, "
            f"and {len(s.get('gws_spoof_dkim_found') or [])} DKIM selector(s) "
            "resolve. Inbound spoofing is actively rejected."
        ),
        "remediation": (
            "Maintain this baseline; review DMARC rua reports monthly for new "
            "legitimate senders before they are blocked."
        ),
        "cwe": "N/A", "iso27001": "A.8.5",
    }


def rule_creds_gated_advisory(s):
    if not s.get("gws_spoof_evaluated"):
        return None
    return {
        "name": "[ADVISORY-BY-DESIGN] Deep Workspace posture needs admin API access",
        "severity": "INFO",
        "evidence": (
            "Admin-role audit, 2-Step Verification enforcement, Advanced "
            "Protection enrolment, OAuth marketplace apps, Drive/Calendar "
            "external-sharing, context-aware access, and Vault retention are "
            "TENANT-INTERNAL settings. They cannot be read from public DNS "
            "and are NOT a forge gap — they require an Admin SDK service "
            "account with domain-wide delegation."
        ),
        "remediation": (
            "Run the gworkspace_admin_audit probe with "
            "options.gcp_service_account_json + options.delegated_admin to "
            "grade the internal controls. See module_playbooks/29_sspm.md §2."
        ),
        "cwe": "N/A", "iso27001": "A.5.23",
    }


GWS_EMAIL_SPOOFING_AUDIT_FINDING_RULES = [
    rule_error,
    rule_unresolvable,
    rule_no_dmarc,
    rule_dmarc_p_none,
    rule_spf_plus_all,
    rule_no_spf,
    rule_spf_missing_google,
    rule_no_dkim,
    rule_positive,
    rule_creds_gated_advisory,
]


INTEL_FIELDS = [
    ("Domain",                    "gws_spoof_domain"),
    ("Domain resolves",           "gws_spoof_resolves"),
    ("MX hosts",                  "gws_spoof_mx_hosts"),
    ("MX points to Google",       "gws_spoof_is_google_mx"),
    ("SPF records",               "gws_spoof_spf_records"),
    ("SPF 'all' qualifier",       "gws_spoof_spf_all"),
    ("SPF includes Google",       "gws_spoof_spf_includes_google"),
    ("DMARC records",             "gws_spoof_dmarc_records"),
    ("DMARC policy",              "gws_spoof_dmarc_p"),
    ("DKIM selectors found",      "gws_spoof_dkim_found"),
]


@router.post("/api/sspm/gws_email_spoofing_audit")
async def sspm_gws_email_spoofing_audit(req: GwsEmailSpoofingRequest,
                                        _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="gws_email_spoofing_audit",
        gather_func=_gather_with_options,
        finding_rules=GWS_EMAIL_SPOOFING_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)

"""ct_log_lookalike_scan - findings rules.

Certificate Transparency logs are the earliest public signal that someone
has stood up HTTPS infrastructure for a brand-impersonating hostname - the
final step before a phishing landing page goes live. A non-owned domain
that contains the brand keyword AND has a publicly-trusted cert is an
active impersonation surface.

ZERO-FALSE-POSITIVE rule: a graded finding fires ONLY when crt.sh actually
returned parseable rows (ctlog_queried) AND at least one covered name contains
the brand keyword on a domain outside the customer's owned set
(ctlog_lookalike_count > 0). crt.sh being unreachable, the keyword being
too short, or zero hits is INFO / POSITIVE - never graded.

A cert issued on a lookalike domain is NOT proof of a live phishing page —
it is impersonation *capability*. Without content confirmation (we never
fetch the lookalike host) the strongest claim is "HTTPS infra exists". When
the issuer is a well-known free/automated CA (Let's Encrypt, ZeroSSL,
Google Trust, etc.) the cert alone carries no extra signal, so we cap it at
LOW. Only when an issuer is unrecognised / non-standard do we raise to
MEDIUM for triage priority.

Severity model:
  MEDIUM   - >=1 brand-keyword cert on a non-owned domain from an
             UNRECOGNISED issuer (warrants priority triage)
  LOW      - >=1 brand-keyword cert on a non-owned domain, all from
             well-known CAs (cert issuance only; no live-page confirmation)
  INFO     - crt.sh unreachable / httpx missing / keyword too short / bad
             target
  POSITIVE - query succeeded and found NO non-owned brand-keyword certs
"""

_CWE_SPOOF = "CWE-290"   # Authentication Bypass by Spoofing
_NIST = "NIST 800-53 SC-8 / SI-4 (Information System Monitoring)"

# Well-known publicly-trusted CAs. A cert from one of these on a lookalike
# domain is routine (free/automated) and is NOT additional evidence of an
# active phishing page — so it caps the finding at LOW.
_WELL_KNOWN_CAS = (
    "let's encrypt", "lets encrypt", "letsencrypt", "r3", "r10", "r11", "e1",
    "e5", "e6", "zerossl", "google trust", "gts ", "digicert", "sectigo",
    "comodo", "globalsign", "amazon", "cloudflare", "buypass", "ssl.com",
    "certum", "actalis", "entrust", "godaddy", "starfield",
)


def _all_well_known(domains) -> bool:
    """True only when EVERY listed lookalike cert came from a recognised CA."""
    saw_issuer = False
    for d in domains:
        issuer = (d.get("issuer") or "").lower()
        if not issuer:
            return False  # unknown issuer -> cannot claim "well-known only"
        saw_issuer = True
        if not any(ca in issuer for ca in _WELL_KNOWN_CAS):
            return False
    return saw_issuer


def rule_dep_or_error(s):
    err = s.get("ctlog_error") or ""
    if not err:
        return None
    if "not installed" in err.lower():
        return {
            "name": "CT-log lookalike scan skipped - httpx not installed",
            "severity": "INFO",
            "evidence": err,
            "remediation": "Install httpx on the scanner host: pip install httpx.",
            "cwe": "CWE-1006",
        }
    return {
        "name": "CT-log lookalike scan could not run",
        "severity": "INFO",
        "evidence": err,
        "remediation": (
            "crt.sh may be rate-limiting or temporarily unavailable. Re-run "
            "later, or query a CT-log mirror (Censys, Cloudflare CT-Streamer, "
            "Facebook CT Monitor) for the same brand keyword."
        ),
        "cwe": "CWE-1006",
    }


def rule_keyword_too_short(s):
    kw = s.get("ctlog_keyword_too_short")
    if not kw:
        return None
    return {
        "name": (f"CT-log lookalike scan skipped - brand keyword '{kw}' too "
                 "short to query safely"),
        "severity": "INFO",
        "evidence": (
            f"The brand keyword derived from {s.get('ctlog_target_domain', '?')} "
            f"is '{kw}' (<4 chars). A keyword this short matches an enormous "
            "volume of unrelated certificates in CT logs and would produce "
            "false attributions, so the probe declined to query."
        ),
        "remediation": (
            "Re-run with options.brand_keyword set to a distinctive, "
            ">=4-character brand string (e.g. your company name or a unique "
            "product mark) for an accurate lookalike search."
        ),
        "cwe": "CWE-1006",
    }


def rule_lookalikes_found(s):
    if not s.get("ctlog_queried"):
        return None
    domains = s.get("ctlog_lookalike_domains") or []
    if not domains:
        return None
    sample = domains[:8]
    listing = "; ".join(
        f"{d['registered_domain']} ({', '.join(d['hostnames'][:3])}"
        f"{'...' if len(d['hostnames']) > 3 else ''}"
        f"{', last cert ' + d['last_seen'] if d.get('last_seen') else ''})"
        for d in sample
    )
    more = f" (+{len(domains) - len(sample)} more)" if len(domains) > len(sample) else ""
    well_known_only = _all_well_known(domains)
    if well_known_only:
        sev, cvss = "LOW", "3.1"
        sev_note = (
            " All listed certs were issued by well-known CAs (routine free/"
            "automated issuance); the cert alone is NOT evidence of a live "
            "phishing page — this is impersonation capability pending content "
            "review."
        )
    else:
        sev, cvss = "MEDIUM", "5.3"
        sev_note = (
            " One or more certs came from an unrecognised issuer — prioritise "
            "these for triage (still cert-issuance evidence only, not a "
            "confirmed live phishing page)."
        )
    return {
        "name": (f"{len(domains)} brand-impersonating domain(s) with valid "
                 f"HTTPS certs found in CT logs for "
                 f"'{s.get('ctlog_brand_keyword')}'"),
        "severity": sev,
        "cvss": cvss,
        "cwe": _CWE_SPOOF,
        "cwe_name": "Authentication Bypass by Spoofing",
        "owasp": "A07:2021",
        "evidence": (
            sev_note.strip() + " "
            f"crt.sh returned {s.get('ctlog_rows_seen', '?')} certificate "
            f"rows for `%{s.get('ctlog_brand_keyword')}%`. After excluding "
            f"your owned domains ({', '.join(s.get('ctlog_owned_domains') or [])}), "
            f"{len(domains)} non-owned domain(s) carry the brand keyword in a "
            f"publicly-trusted certificate: {listing}{more}. Each is "
            "infrastructure capable of serving a convincing HTTPS phishing "
            "landing page that impersonates your brand (the green padlock "
            "lends false legitimacy). NOTE: some of these may be partners, "
            "resellers, or news/parody sites - triage each before takedown."
        ),
        "remediation": (
            "1. Triage the listed domains: confirm which are genuinely "
            "malicious vs. legitimate (partners, your own shadow-IT). "
            "2. For malicious lookalikes, file a registrar/host abuse report "
            "and (for IDN homographs) a UDRP/URS complaint. "
            "3. Stand up CONTINUOUS CT monitoring (crt.sh RSS, Cloudflare "
            "CT-Streamer, Censys, or a managed brand-protection service) "
            "filtered to your brand keyword so a new lookalike cert pages your "
            "SOC within minutes of issuance - that is the window to act before "
            "the phishing page goes live. "
            "4. Pair with phishing-resistant MFA (FIDO2/passkeys) so even a "
            f"pixel-perfect clone cannot replay a session. Compliance: {_NIST}, "
            "MITRE ATT&CK T1583.001."
        ),
    }


def rule_clean(s):
    if not s.get("ctlog_queried"):
        return None
    if s.get("ctlog_lookalike_count"):
        return None
    return {
        "name": (f"No non-owned brand-keyword certificates found in CT logs "
                 f"for '{s.get('ctlog_brand_keyword')}'"),
        "severity": "POSITIVE",
        "evidence": (
            f"crt.sh returned {s.get('ctlog_rows_seen', 0)} certificate rows "
            f"for `%{s.get('ctlog_brand_keyword')}%`; after excluding your "
            "owned domains, none covered a brand-keyword hostname on a domain "
            "you do not control. No active HTTPS impersonation infrastructure "
            "was visible in CT logs at scan time."
        ),
        "remediation": (
            "Maintain CONTINUOUS CT monitoring (this scan is a point-in-time "
            "snapshot) so a newly-issued lookalike cert alerts you within "
            "minutes. Re-run this probe on a weekly cadence at minimum."
        ),
        "cwe": _CWE_SPOOF,
        "owasp": "A07:2021",
    }


CT_LOG_LOOKALIKE_SCAN_FINDING_RULES = [
    rule_dep_or_error,
    rule_keyword_too_short,
    rule_lookalikes_found,
    rule_clean,
]

"""_targeting — apex / eTLD+1 / org-name extraction for recon scanners.

ZERO-FP-V1 (2026-06-06): the OSINT scanners (Docker Hub, npm, Sherlock,
Sec EDGAR, Apple Store, etc.) were using `ctx.host.split('.')[0]` which
returns the SUBDOMAIN — so `app.vulnuslab.com` got searched as org "app",
hitting WhatsApp / TikTok / Minecraft random matches and reporting them
as customer's assets.

This module fixes that:

    get_apex("app.vulnuslab.com")   -> "vulnuslab.com"
    get_org_name("app.vulnuslab.com") -> "vulnuslab"     # for org search
    get_org_name("acme.co.uk")        -> "acme"          # handles 2-part TLDs

All recon scanners MUST use get_org_name() for org-name-based searches.
Never split host on '.' and take [0] — that's how we got the FPs.

Uses tldextract if available (correct in all edge cases); falls back to a
built-in suffix list for the common cases (.com / .net / .org / .io / .ai /
the major 2-part TLDs). Customer scans almost always fall in the fallback
path so the missing-dep is not a blocker.
"""
import re
from urllib.parse import urlparse

# ─── Two-part TLDs (eTLDs where the org is at position -3) ─────────────
# Not exhaustive — but covers the cases customers actually scan. If
# tldextract is installed, that fully-correct lookup is used instead.
_TWO_PART_TLDS = frozenset({
    "co.uk", "ac.uk", "org.uk", "net.uk", "gov.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.in", "net.in", "org.in", "ac.in", "gov.in",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.nz", "net.nz", "org.nz", "ac.nz", "govt.nz",
    "com.br", "net.br", "org.br", "gov.br",
    "co.za", "ac.za", "gov.za", "org.za",
    "com.mx", "com.ar", "com.sg", "com.hk", "com.tw",
    "com.tr", "com.cn", "com.my", "com.ph",
    "co.id", "co.kr", "co.il", "co.th",
})

try:
    import tldextract as _tldx
    _HAS_TLDX = True
except Exception:
    _HAS_TLDX = False


def _normalize_host(target: str) -> str:
    """Strip scheme + path + port; lowercase."""
    if not target:
        return ""
    t = str(target).strip().lower()
    if "://" in t:
        try:
            t = urlparse(t).hostname or t
        except Exception:
            t = t.split("://", 1)[1].split("/", 1)[0]
    # strip port
    if ":" in t:
        t = t.split(":", 1)[0]
    # strip path (in case input was a bare host/path)
    t = t.split("/", 1)[0]
    # strip trailing dot
    return t.rstrip(".")


def get_apex(target: str) -> str:
    """Return the registrable domain (eTLD+1).

    Examples:
      app.vulnuslab.com    -> vulnuslab.com
      api.staging.acme.io  -> acme.io
      shop.acme.co.uk      -> acme.co.uk
      vulnuslab.com        -> vulnuslab.com
      10.0.0.1             -> 10.0.0.1  (IP returned as-is)
      localhost            -> localhost
    """
    host = _normalize_host(target)
    if not host:
        return ""
    # IPs / single-label hosts return as-is
    if _is_ip(host) or "." not in host:
        return host

    if _HAS_TLDX:
        try:
            ext = _tldx.extract(host)
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}"
            # No suffix recognized (e.g., 'lab_juiceshop') — return as-is
            return host
        except Exception:
            pass

    # Fallback: built-in suffix logic
    parts = host.split(".")
    if len(parts) < 2:
        return host
    last_two = ".".join(parts[-2:])
    last_three = ".".join(parts[-3:]) if len(parts) >= 3 else None
    if last_three and last_two in _TWO_PART_TLDS:
        return last_three
    return last_two


def get_org_name(target: str) -> str:
    """Return the org/brand name — the apex without the TLD suffix.

    This is the string you use for org-name-based searches (Docker Hub,
    npm, GitHub, Sec EDGAR, Apple Store, etc.).

    Examples:
      app.vulnuslab.com    -> vulnuslab
      api.staging.acme.io  -> acme
      shop.acme.co.uk      -> acme
      10.0.0.1             -> ''  (IPs have no org name; caller should skip OSINT)
      lab_juiceshop        -> lab_juiceshop
    """
    host = _normalize_host(target)
    if not host or _is_ip(host):
        return ""

    apex = get_apex(host)
    if not apex or "." not in apex:
        return apex or ""

    if _HAS_TLDX:
        try:
            ext = _tldx.extract(host)
            if ext.domain:
                return ext.domain
        except Exception:
            pass

    # Fallback: strip the last segment(s) of the apex
    parts = apex.split(".")
    last_two = ".".join(parts[-2:])
    if last_two in _TWO_PART_TLDS and len(parts) >= 3:
        return parts[-3]
    return parts[0]


_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+$", re.I)
def _is_ip(host: str) -> bool:
    return bool(_IP_RE.match(host))


def can_do_osint(target: str) -> bool:
    """Does this target support OSINT-style org-name searches?

    Returns False for IPs, internal Docker hosts, single-label hosts —
    targets that have no real-world brand identity. OSINT scanners should
    early-return SKIPPED with a clear reason when this returns False.
    """
    host = _normalize_host(target)
    if not host or _is_ip(host) or "." not in host:
        return False
    # Internal Docker hostnames look like 'lab_juiceshop' — no real brand
    if "_" in host and "." not in host:
        return False
    return True

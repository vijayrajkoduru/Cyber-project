"""Reserved/special-use domain detection — RFC 2606 + RFC 6761.

The OSINT module produced ~50 FPs on example.com because most of its
scanners (dnstwist, hibp, otx, sherlock) treat the target as if it were a
real org. example.com is the IANA documentation domain — there is no real
brand, no real users, no real threat surface to defend.

Any scanner that consults this helper can short-circuit cleanly on
reserved targets:

    from tools._framework.reserved_domains import is_reserved

    if is_reserved(target):
        return standard_response(... skipped_reason="RFC 2606 reserved
        documentation domain — scanner not applicable")
"""
from __future__ import annotations

# RFC 2606: reserved second-level + TLD names
_RFC2606_EXACT = {
    "example.com",
    "example.net",
    "example.org",
    "example",
}
_RFC2606_TLDS = {"test", "invalid", "localhost", "example"}

# RFC 6761: additional special-use names
_RFC6761_EXACT = {"localhost"}


def _norm(host: str) -> str:
    host = (host or "").strip().lower()
    for prefix in ("http://", "https://"):
        if host.startswith(prefix):
            host = host[len(prefix):]
    host = host.split("/", 1)[0]
    host = host.split(":", 1)[0]
    if host.startswith("www."):
        host = host[4:]
    return host.rstrip(".")


def is_reserved(host: str) -> bool:
    """True for any RFC 2606 / RFC 6761 reserved domain or subdomain."""
    h = _norm(host)
    if not h:
        return False
    if h in _RFC2606_EXACT or h in _RFC6761_EXACT:
        return True
    parts = h.split(".")
    if not parts:
        return False
    tld = parts[-1]
    if tld in _RFC2606_TLDS:
        return True
    # apex match against reserved exact-set
    if len(parts) >= 2:
        apex = ".".join(parts[-2:])
        if apex in _RFC2606_EXACT:
            return True
    return False


def reason(host: str) -> str:
    """Human-readable skip reason for the report."""
    h = _norm(host)
    return (f"'{h}' is an RFC 2606 / RFC 6761 reserved documentation domain. "
            f"OSINT / brand-protection / threat-intel checks are not applicable "
            f"because there is no real organization, brand, or user behind it.")

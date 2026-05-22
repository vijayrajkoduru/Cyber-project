"""Regex / text / date parsers reused across recon tools.

Extracted from WHOIS Intelligence v2 (tools/recon/whois.py) so DNS, ASN,
TLS, and every other text-parsing scanner can reuse the same primitives.
"""
import datetime
import re
from typing import Optional


def grab(text: str, *labels) -> Optional[str]:
    """Extract value for the first matching 'Label: value' line in text.

    Case-insensitive, multi-line. Returns the first label that matches.
    Strips trailing whitespace from the value. Returns None if no match.

        grab(whois_text, "Registrar")               -> "GANDI SAS"
        grab(whois_text, "Created", "Creation Date") -> first one found
    """
    for label in labels:
        pat = re.compile(rf"^\s*{re.escape(label)}\s*:\s*(.+?)\s*$",
                          re.IGNORECASE | re.MULTILINE)
        m = pat.search(text or "")
        if m and m.group(1).strip():
            return m.group(1).strip()
    return None


def grab_all(text: str, *labels) -> list:
    """Extract ALL values for given labels. Deduplicated, order-preserved.

        grab_all(whois_text, "Name Server") -> ["ns1.cf.com", "ns2.cf.com"]
    """
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


def parse_iso_date(date_str) -> Optional[datetime.datetime]:
    """Parse various date formats into datetime (UTC naive). None on failure.

    Handles ISO 8601 (with/without Z), WHOIS legacy formats, and Python
    fromisoformat fallback. Used for created/expires/updated fields.
    """
    if not date_str: return None
    s = str(date_str).strip()
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d", "%d-%b-%Y", "%d.%m.%Y"):
        try:
            return datetime.datetime.strptime(s.split("+")[0].rstrip("Z"),
                                                 fmt.rstrip("Z"))
        except ValueError:
            continue
    try:
        return datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        return None


def days_between(d1, d2) -> int:
    """Days between two datetimes. d2 - d1 (positive if d2 is later)."""
    if d1 is None or d2 is None:
        return 0
    return (d2 - d1).days

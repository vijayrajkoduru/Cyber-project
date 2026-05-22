"""recon_whois -- isolated tool (Kali-style architecture).

Route: /api/recon/whois

Primary: subprocess to the system `whois` binary (Kali/Debian package).
The output matches what a pentester sees from CLI 1:1 — registrar, IANA ID,
domain status codes, DNSSEC, abuse contact, registry domain ID, etc.

Fallback: python-whois library if subprocess fails / binary missing.
"""
import datetime
import re
import shutil
import subprocess

from fastapi import APIRouter, Depends
import whois as whois_lib

from tools._shared import ScanRequest, verify_scan_quota, recon_host

router = APIRouter()

_WHOIS_BIN = shutil.which("whois")


def _run_whois_cli(host: str, timeout: int = 15) -> str:
    """Subprocess to system `whois`. Returns raw text or empty on error."""
    if not _WHOIS_BIN:
        return ""
    try:
        proc = subprocess.run(
            [_WHOIS_BIN, host],
            capture_output=True, text=True, timeout=timeout,
            errors="replace",
        )
        return (proc.stdout or "") + (proc.stderr or "")
    except (subprocess.TimeoutExpired, OSError):
        return ""


# Match "Field Name: value" (case-insensitive) — registry WHOIS uses this format.
def _grab(text: str, *labels) -> str | None:
    """Return value for the first label that matches. Strips trailing spaces."""
    for label in labels:
        pat = re.compile(rf"^\s*{re.escape(label)}\s*:\s*(.+?)\s*$",
                          re.IGNORECASE | re.MULTILINE)
        m = pat.search(text)
        if m and m.group(1).strip():
            return m.group(1).strip()
    return None


def _grab_all(text: str, *labels) -> list:
    """Return all values for given labels (deduplicated, order-preserved)."""
    seen, out = set(), []
    for label in labels:
        pat = re.compile(rf"^\s*{re.escape(label)}\s*:\s*(.+?)\s*$",
                          re.IGNORECASE | re.MULTILINE)
        for m in pat.finditer(text):
            v = m.group(1).strip()
            if v and v.lower() not in seen:
                seen.add(v.lower())
                out.append(v)
    return out


def _parse_cli_whois(text: str) -> dict:
    """Parse raw whois output into structured fields."""
    if not text:
        return {}
    # Registry uses "Domain Status: clientTransferProhibited https://..."
    # We want just the status code, not the URL.
    raw_status = _grab_all(text, "Domain Status")
    statuses = []
    for s in raw_status:
        code = s.split()[0] if s else s
        if code and code not in statuses:
            statuses.append(code)

    return {
        "registry_domain_id": _grab(text, "Registry Domain ID"),
        "registrar":          _grab(text, "Registrar"),
        "registrar_url":      _grab(text, "Registrar URL"),
        "registrar_iana_id":  _grab(text, "Registrar IANA ID"),
        "registrar_whois":    _grab(text, "Registrar WHOIS Server"),
        "abuse_email":        _grab(text, "Registrar Abuse Contact Email"),
        "abuse_phone":        _grab(text, "Registrar Abuse Contact Phone"),
        "created":            _grab(text, "Creation Date", "Created On", "Created Date"),
        "updated":            _grab(text, "Updated Date", "Last Updated On", "Last Modified"),
        "expires":            _grab(text, "Registry Expiry Date", "Registrar Registration Expiration Date",
                                          "Expiration Date", "Expiry Date"),
        "name_servers":       [n.lower().rstrip(".") for n in _grab_all(text, "Name Server", "Nameserver", "nserver")],
        "status_codes":       statuses,
        "dnssec":             _grab(text, "DNSSEC"),
        "registrant_org":     _grab(text, "Registrant Organization", "Registrant Org", "Registrant"),
        "registrant_country": _grab(text, "Registrant Country", "Country"),
        "registrant_state":   _grab(text, "Registrant State/Province", "Registrant State"),
    }


def _python_whois_fallback(host: str) -> dict:
    """Fallback when subprocess unavailable — Python whois lib (limited fields)."""
    try:
        w = whois_lib.whois(host)
    except Exception as e:
        return {"_fallback_error": f"python-whois: {e}"}

    def _first(v):
        return v[0] if isinstance(v, list) and v else v

    def _iso(d):
        d = _first(d)
        if isinstance(d, datetime.datetime):
            return d.isoformat()
        return str(d) if d else None

    return {
        "registrar":     _first(w.registrar),
        "created":       _iso(w.creation_date),
        "expires":       _iso(w.expiration_date),
        "updated":       _iso(w.updated_date),
        "name_servers":  sorted({str(n).lower().rstrip(".") for n in (w.name_servers or [])}),
        "registrant_org": _first(w.registrant_name) or _first(w.org),
        "registrant_country": _first(w.country),
        "status_codes":  list({str(s).split()[0] for s in (w.status or []) if s}) if hasattr(w, "status") else [],
    }


@router.post("/api/recon/whois")
async def recon_whois(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    raw = _run_whois_cli(host)
    parsed = _parse_cli_whois(raw) if raw else {}
    source = "system-whois-cli"

    # If CLI failed OR returned almost nothing, try Python fallback to fill gaps.
    if not parsed.get("registrar"):
        fallback = _python_whois_fallback(host)
        if fallback.get("registrar"):
            # Merge — prefer CLI fields where present, fill gaps from fallback.
            for k, v in fallback.items():
                if k.startswith("_"): continue
                if not parsed.get(k):
                    parsed[k] = v
            source = "python-whois-fallback" if not raw else "system-whois-cli+fallback"
        elif not raw:
            return {"ok": False,
                    "skipped_reason": "WHOIS query failed: system `whois` binary unavailable and python-whois also failed",
                    "tool": "whois"}

    # Did we actually get anything useful?
    if not parsed.get("registrar") and not parsed.get("name_servers"):
        return {"ok": False, "tool": "whois",
                "skipped_reason": f"WHOIS returned no data for {host} (likely a private/restricted TLD or rate-limited)",
                "raw_excerpt": (raw[:500] if raw else None)}

    # Security flags pentesters care about — distilled.
    sec_flags = {
        "transfer_locked":  any("clienttransferprohibited" in s.lower() for s in (parsed.get("status_codes") or [])),
        "update_locked":    any("clientupdateprohibited"   in s.lower() for s in (parsed.get("status_codes") or [])),
        "delete_locked":    any("clientdeleteprohibited"   in s.lower() for s in (parsed.get("status_codes") or [])),
        "dnssec_enabled":   (parsed.get("dnssec") or "").lower() in ("signed", "signeddelegation", "yes", "true", "active"),
        "privacy_proxied":  bool(re.search(r"privacy|redacted|withheld|whoisguard|domainsbyproxy|protected",
                                            (parsed.get("registrant_org") or "") + " " + raw, re.I)),
    }

    return {
        "ok": True,
        "tool": "whois",
        "domain": host,
        "source": source,
        "registry_domain_id":  parsed.get("registry_domain_id"),
        "registrar":           parsed.get("registrar"),
        "registrar_url":       parsed.get("registrar_url"),
        "registrar_iana_id":   parsed.get("registrar_iana_id"),
        "registrar_whois":     parsed.get("registrar_whois"),
        "abuse_email":         parsed.get("abuse_email"),
        "abuse_phone":         parsed.get("abuse_phone"),
        "created":             parsed.get("created"),
        "updated":             parsed.get("updated"),
        "expires":             parsed.get("expires"),
        "name_servers":        parsed.get("name_servers") or [],
        "status_codes":        parsed.get("status_codes") or [],
        "dnssec":              parsed.get("dnssec"),
        "registrant_org":      parsed.get("registrant_org"),
        "registrant_country":  parsed.get("registrant_country"),
        "registrant_state":    parsed.get("registrant_state"),
        "security_flags":      sec_flags,
        "raw_excerpt":         (raw[:2000] if raw else None),
    }


def register(app):
    app.include_router(router)

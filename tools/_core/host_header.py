"""UNDERSCORE-HOST-V4 — transport-level Host header fix for Docker lab names.

Apache (DVWA, bWAPP) and Tomcat (WebGoat) reject a Host header containing "_"
(invalid per RFC 9110/9112) with HTTP 400. Docker service names such as
`lab_dvwa` contain one, so any scanner that requested http://lab_dvwa/...
directly got a 400 on every probe and reported nothing: a false all-clear.

safe_get/safe_post already cleaned the header (V3), but ~90 scanners call
safe_request directly and ~100 use requests/httpx/aiohttp themselves, and
redirect hops bypass the helpers entirely. Fixing it in the transport hooks
(tools/_core/scope_guard.install_transport_guards) covers every Python HTTP
call, every redirect hop, in LAB and CUSTOMER mode alike.

The URL hostname is left intact (Docker DNS resolves it, and lab detection
keys off "dvwa"/"webgoat"/... in the target). Only the Host header changes,
and only when it is absent or equal to the raw underscore hostname: a scanner
that deliberately sends a different Host (host-header injection, cache
poisoning, vhost brute force) keeps its value. Real customer domains never
contain "_", so this is a no-op for them.
"""
from typing import Optional
from urllib.parse import urlsplit

_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}

# Cleaned name -> real Docker name. Servers that build absolute redirects from
# the Host header (Tomcat/WebGoat: "Location: http://labwebgoat:8080/...")
# point at the cleaned name, which Docker DNS cannot resolve, so the redirect
# hop failed and precheck_target reported "target unreachable". The transport
# hooks use restore_url() to send such a hop back to the real name.
# Pre-seeded with the bundled labs; extended by every cleaned_host() call.
_REVERSE = {n.replace("_", ""): n for n in (
    "lab_dvwa", "lab_bwapp", "lab_mutillidae", "lab_juiceshop", "lab_webgoat",
    "lab_metasploitable", "lab_pwd_web", "lab_pwd_ssh", "lab_pwd_smb")}


def restore_url(url: str) -> Optional[str]:
    """If `url` targets a cleaned lab name (e.g. labwebgoat), return the same
    URL with the real underscore hostname, else None."""
    try:
        p = urlsplit(url)
        hn = (p.hostname or "").lower()
        real = _REVERSE.get(hn)
        if not real or "_" in hn:
            return None
        netloc = p.netloc
        at = netloc.rfind("@") + 1
        hostport = netloc[at:]
        hostport = real + hostport[len(hn):] if hostport.lower().startswith(hn) else hostport
        return p._replace(netloc=netloc[:at] + hostport).geturl()
    except Exception:
        return None


def cleaned_host(url: str) -> Optional[str]:
    """Host header value with underscores removed, or None if not needed."""
    try:
        p = urlsplit(url if "://" in url else "http://" + url)
        hn = p.hostname
        if not hn or "_" not in hn:
            return None
        if len(_REVERSE) < 512:
            _REVERSE.setdefault(hn.replace("_", "").lower(), hn.lower())
        host = hn.replace("_", "")
        if p.port and p.port != _DEFAULT_PORTS.get(p.scheme):
            host = f"{host}:{p.port}"
        return host
    except Exception:
        return None


def should_replace(url: str, current: Optional[str]) -> Optional[str]:
    """Return the replacement Host value if `current` must be replaced,
    else None. `current` is the Host header the client is about to send
    (None when the client will derive it from the URL)."""
    new = cleaned_host(url)
    if new is None:
        return None
    if current is None or current == "":
        return new
    try:
        hn = urlsplit(url if "://" in url else "http://" + url).hostname or ""
    except Exception:
        return None
    # Only the auto-derived / echoed raw hostname is replaced; a deliberate
    # override (e.g. "evil.example") is preserved.
    if current.split(":", 1)[0].strip().lower() == hn.lower():
        return new
    return None

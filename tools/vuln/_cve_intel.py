"""Shared CVE-intelligence helpers for tier2 Vuln scanners (autoload-skipped via _ prefix)."""
import json, os, re, socket, ssl, time, urllib.parse, urllib.request

_UA = {"User-Agent": "VulnusLab-Scanner/1.0"}
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE
_KEV = {"t": 0.0, "data": None}


def _get_json(url, timeout=12, extra_headers=None):
    h = dict(_UA)
    if extra_headers:
        h.update(extra_headers)
    try:
        req = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return None


def nvd_cves(product, version, limit=20):
    q = urllib.parse.quote(f"{product} {version}")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={q}&resultsPerPage={limit}"
    key = os.environ.get("NVD_API_KEY")
    data = _get_json(url, timeout=15, extra_headers={"apiKey": key} if key else None)
    if not data:
        return []
    out = []
    for v in (data.get("vulnerabilities") or []):
        c = v.get("cve", {})
        score = 0.0
        for metric in (c.get("metrics", {}) or {}).values():
            for item in (metric or []):
                score = max(score, float((item.get("cvssData", {}) or {}).get("baseScore", 0) or 0))
        cid = c.get("id", "")
        if cid:
            out.append((cid, score))
    return out


def high_cves(product, version, threshold=7.0):
    return sorted([(c, s) for c, s in nvd_cves(product, version) if s >= threshold], key=lambda x: -x[1])


def epss_scores(cve_ids):
    cve_ids = [c for c in cve_ids if c][:50]
    if not cve_ids:
        return {}
    data = _get_json("https://api.first.org/data/v1/epss?cve=" + ",".join(cve_ids), timeout=12)
    out = {}
    for row in ((data or {}).get("data") or []):
        cid = row.get("cve")
        if cid:
            out[cid] = (float(row.get("epss", 0) or 0), float(row.get("percentile", 0) or 0))
    return out


def kev_catalog():
    now = time.time()
    if _KEV["data"] is not None and now - _KEV["t"] < 21600:
        return _KEV["data"]
    data = _get_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=20)
    entries = (data or {}).get("vulnerabilities") or []
    if entries:
        _KEV["data"] = entries
        _KEV["t"] = now
    return entries


TECH_ALIASES = {
    "apache": ["http server", "httpd"], "nginx": ["nginx"],
    "iis": ["internet information services"], "openssl": ["openssl"],
    "tomcat": ["tomcat"], "jboss": ["jboss"], "weblogic": ["weblogic"],
    "websphere": ["websphere"], "php": ["php"], "wordpress": ["wordpress"],
    "drupal": ["drupal"], "joomla": ["joomla"], "exchange": ["exchange server"],
    "fortinet": ["fortios", "fortigate"], "citrix": ["netscaler"],
    "ivanti": ["connect secure", "ivanti"], "spring": ["spring"],
    "struts": ["struts"], "jenkins": ["jenkins"], "gitlab": ["gitlab"],
    "confluence": ["confluence"], "jira": ["jira"],
}

# Edge/VPN/email appliance products are *heavily* false-positive-prone when
# matched against arbitrary HTML body text: a marketing or security-product
# site can mention "Ivanti"/"Fortinet"/"Exchange" in prose, a blog post, a
# scanner catalog, or a reflected route name without running that appliance.
# For these we demand a *strong* signal (server/x-powered-by banner, or a
# product-specific marker — not a bare keyword anywhere in <body>). General
# web stacks (apache/nginx/php/wordpress/...) keep the cheap body match.
_APPLIANCE_TECHS = {"ivanti", "fortinet", "citrix", "exchange"}

# Product-specific high-confidence markers. These are strings an appliance
# actually emits (login-portal paths, branded asset names, vendor cookies),
# NOT a word that could appear in editorial copy. Used to corroborate an
# appliance-class detection before it is allowed to cross-reference KEV.
_APPLIANCE_MARKERS = {
    "ivanti":   ["/dana-na/", "dsignin", "welcome.cgi", "/api/v1/totp/",
                 "pulse secure", "psal_", "x-frame-options: sameorigin\r\nset-cookie: dsid"],
    "fortinet": ["/remote/login", "fgt_lang", "sslvpn_login", "fortigate"],
    "citrix":   ["/vpn/index.html", "ns_af=", "citrix gateway", "/cgi/login"],
    "exchange": ["/owa/", "/ecp/", "x-owa-version", "outlook web app",
                 "x-aspnet-version"],
}


def _word_present(token, blob):
    """Word-boundary match so 'php' doesn't fire inside 'graphql' and a bare
    'ivanti' substring only counts as a real product token, never an
    incidental fragment. Multi-word aliases ('connect secure') are matched
    as exact phrases."""
    return re.search(r"(?<![a-z0-9])" + re.escape(token) + r"(?![a-z0-9])", blob) is not None


def detect_tech_tokens(banners, body=""):
    """Return the set of detected tech keys.

    Two precision layers:
      * General web stacks: word-boundary match anywhere in banner+body.
      * Appliance/edge products (ivanti/fortinet/citrix/exchange): match the
        key in the *banner* OR require a product-specific marker. A bare
        mention in body prose is NOT sufficient — that is the exact class of
        false positive that flagged 'Ivanti/Pulse Connect Secure' on a plain
        React+FastAPI marketing site.
    """
    banner_blob = (" ".join(banners)).lower()
    body_blob = (body or "")[:4000].lower()
    blob = banner_blob + " " + body_blob[:2000]
    out = set()
    for k in TECH_ALIASES:
        if k in _APPLIANCE_TECHS:
            in_banner = _word_present(k, banner_blob)
            has_marker = any(m in banner_blob or m in body_blob for m in _APPLIANCE_MARKERS.get(k, []))
            if in_banner or has_marker:
                out.add(k)
        elif _word_present(k, blob):
            out.add(k)
    return out


def tcp_banner(host, port, payload=b"", timeout=4, read=2048):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if payload:
                try:
                    s.sendall(payload)
                except Exception:
                    pass
            try:
                data = s.recv(read)
            except Exception:
                data = b""
            return True, data.decode("latin-1", "replace")
    except Exception:
        return False, ""

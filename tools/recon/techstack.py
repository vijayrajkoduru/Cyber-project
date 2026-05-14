"""Tech stack fingerprinting.

Active fingerprinting via response inspection: headers, cookies,
meta tags, HTML body markers. Returns detected stack plus
version-disclosure findings (CWE-200) when versions are exposed.
"""
import re
from fastapi import APIRouter, Depends

from tools._shared import (
    ScanRequest, verify_scan_quota, web_url,
    safe_get, wrap_finding, standard_response,
)

router = APIRouter()


RULES = [
    ("header", "server", r"^(apache)[\s/]+([\d.]+)", "Apache"),
    ("header", "server", r"^(nginx)[\s/]+([\d.]+)", "Nginx"),
    ("header", "server", r"^(microsoft-iis)[\s/]+([\d.]+)", "Microsoft IIS"),
    ("header", "server", r"^(litespeed)[\s/]+([\d.]+)", "LiteSpeed"),
    ("header", "server", r"^(caddy)", "Caddy"),
    ("header", "server", r"^(cloudflare)", "Cloudflare"),
    ("header", "server", r"^(envoy)", "Envoy proxy"),
    ("header", "x-powered-by", r"^(php)/([\d.]+)", "PHP"),
    ("header", "x-powered-by", r"^(asp\.net)\b", "ASP.NET"),
    ("header", "x-powered-by", r"^(express)$", "Express.js"),
    ("header", "x-powered-by", r"^(nextjs)\b", "Next.js"),
    ("header", "x-aspnet-version", r"^([\d.]+)$", "ASP.NET"),
    ("header", "x-generator", r"^drupal\s*([\d.]+)?", "Drupal"),
    ("header", "x-drupal-cache", r".*", "Drupal"),
    ("header", "x-pingback", r"/xmlrpc\.php", "WordPress"),
    ("header", "x-shopify-stage", r".*", "Shopify"),
    ("cookie", "PHPSESSID", r".*", "PHP"),
    ("cookie", "JSESSIONID", r".*", "Java (J2EE)"),
    ("cookie", "ASP.NET_SessionId", r".*", "ASP.NET"),
    ("cookie", "ASPSESSIONID", r".*", "Classic ASP"),
    ("cookie", "laravel_session", r".*", "Laravel"),
    ("cookie", "ci_session", r".*", "CodeIgniter"),
    ("cookie", "wordpress_logged_in", r".*", "WordPress"),
    ("cookie", "wp-settings", r".*", "WordPress"),
    ("body", None, r"/wp-content/|/wp-includes/", "WordPress"),
    ("body", None, r"Drupal\.settings|sites/default/files/", "Drupal"),
    ("body", None, r"Joomla!|/templates/system/css/", "Joomla"),
    ("body", None, r"Magento_Theme|var\s+BASE_URL\s*=", "Magento"),
    ("body", None, r"window\.shopify|Shopify\.theme", "Shopify"),
    ("body", None, r'data-react-helmet|id="__next"', "React"),
    ("body", None, r'<div id="root">\s*</div>', "React"),
    ("body", None, r'data-server-rendered="true"', "Vue.js"),
    ("body", None, r'ng-version="([\d.]+)"', "Angular"),
    ("body", None, r"/jquery[.-]([\d.]+)(?:\.min)?\.js", "jQuery"),
    ("body", None, r"bootstrap[.-]?([\d.]+)?(?:\.min)?\.css", "Bootstrap"),
    ("body", None, r"<!--\s*WordPress\s*([\d.]+)", "WordPress"),
    ("meta", "generator", r"^WordPress\s*([\d.]+)?", "WordPress"),
    ("meta", "generator", r"^Drupal\s*([\d.]+)?", "Drupal"),
    ("meta", "generator", r"^Joomla!\s*-\s*Open Source", "Joomla"),
    ("meta", "generator", r"^Hugo\s*([\d.]+)?", "Hugo"),
    ("meta", "generator", r"^Jekyll", "Jekyll"),
    ("meta", "generator", r"^Gatsby\s*([\d.]+)?", "Gatsby"),
]


def _meta_gen(text: str):
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', text, re.I)
    return m.group(1) if m else None


@router.post("/api/scan/techstack")
async def scan_techstack(req: ScanRequest, _=Depends(verify_scan_quota)):
    url = web_url(req.target)
    findings = []

    r = safe_get(url, req=req, allow_redirects=True)
    if r is None:
        return standard_response(
            tool="techstack", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Could not reach {url}",
        )

    headers = {k.lower(): v for k, v in r.headers.items()}
    try:
        body = r.text or ""
    except Exception:
        body = ""
    meta_gen = _meta_gen(body)
    cookie_names = {c.name for c in r.cookies}

    detected = []
    seen = set()

    def _add(name, version, evidence, source):
        key = (name, version or "")
        if key in seen:
            return
        seen.add(key)
        detected.append({"name": name, "version": version,
                         "evidence": evidence, "source": source})

    for kind, where, pattern, tech_name in RULES:
        if kind == "header":
            val = headers.get(where, "")
            if val:
                m = re.search(pattern, val, re.I)
                if m:
                    version = m.group(2) if (m.groups() and len(m.groups()) >= 2) else None
                    _add(tech_name, version, f"{where}: {val[:80]}", "header")
        elif kind == "cookie":
            if where in cookie_names:
                _add(tech_name, None, f"cookie: {where}", "cookie")
        elif kind == "body":
            m = re.search(pattern, body, re.I)
            if m:
                version = m.group(1) if m.groups() else None
                snip = body[max(0, m.start()-20):m.end()+20].replace("\n", " ")
                _add(tech_name, version, f"body: {snip[:80]}", "body")
        elif kind == "meta" and meta_gen:
            m = re.search(pattern, meta_gen, re.I)
            if m:
                version = m.group(1) if m.groups() else None
                _add(tech_name, version, f"meta generator: {meta_gen[:80]}", "meta")

    for tech in detected:
        if tech["version"]:
            findings.append(wrap_finding(
                f"{tech['name']} version disclosed: {tech['version']}",
                "LOW", cwe="CWE-200",
                evidence_marker=f"{tech['source']}: {tech['evidence'][:80]}",
                remediation=f"Suppress version info from {tech['name']} responses to reduce exploit-matching surface.",
                tests_performed=1,
            ))

    return standard_response(
        tool="techstack", target=req.target, findings=findings,
        tests_performed=len(RULES),
        tests_summary=f"Fingerprinted {len(RULES)} signatures; detected {len(detected)} technologies",
        raw_data={"techstack": {"url": str(r.url), "detected": detected}},
    )


def register(app):
    app.include_router(router)

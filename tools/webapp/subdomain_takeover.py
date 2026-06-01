"""Subdomain takeover detector - real DNS + HTTP fingerprint check.

Workflow:
  1. Resolve CNAME chain for the target hostname
  2. Match each CNAME hop against the known-vulnerable-service catalog
     (S3, Heroku, GitHub Pages, Azure Cloudapps, Shopify, Surge, etc.)
  3. If matched, HTTP-fetch the target and look for service-specific
     "resource not claimed" fingerprints (e.g., S3's "NoSuchBucket"
     XML, Heroku's "No such app" page, GitHub Pages' "There isn't a
     GitHub Pages site here")
  4. Match -> CRITICAL CWE-350 finding (subdomain hijack possible)
     CNAME without fingerprint match -> INFO
     no CNAME or no service match -> POSITIVE
"""
from __future__ import annotations

import re
import socket
from urllib.parse import urlparse

import dns.resolver
import dns.exception

from fastapi import APIRouter, Depends

from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                             wrap_finding, safe_get)
from tools.webapp._webapp_common import precheck_target, vuln_response

router = APIRouter()


# Curated takeover-vulnerable services - each entry has a CNAME pattern
# (regex against the dangling CNAME) + a fingerprint regex to look for
# in the HTTP response body that confirms the resource is unclaimed.
# Sourced from EdOverflow/can-i-take-over-xyz + Hacking-Notes 2024.
_TAKEOVER_SERVICES = [
    {
        "service": "AWS S3",
        "cname_re": r"\.s3([.-][a-z0-9-]+)?\.amazonaws\.com$",
        "body_re": r"<Code>NoSuchBucket</Code>|The specified bucket does not exist",
        "status": [404, 200],
    },
    {
        "service": "AWS CloudFront",
        "cname_re": r"\.cloudfront\.net$",
        "body_re": r"<title>404 Not Found</title>\s*<h1>404 Not Found</h1>|Bad request\.\s*We can't connect to the server",
        "status": [403, 404],
    },
    {
        "service": "Heroku",
        "cname_re": r"\.herokuapp\.com$|\.herokudns\.com$",
        "body_re": r"No such app|herokucdn\.com/error-pages/no-such-app\.html",
        "status": [404],
    },
    {
        "service": "GitHub Pages",
        "cname_re": r"\.github\.io$",
        "body_re": r"There isn't a GitHub Pages site here|Page not found.*looking for is no longer available",
        "status": [404],
    },
    {
        "service": "Azure Cloudapps",
        "cname_re": r"\.(cloudapp\.net|cloudapp\.azure\.com|trafficmanager\.net|"
                    r"azurewebsites\.net|blob\.core\.windows\.net|"
                    r"azurefd\.net|azureedge\.net)$",
        "body_re": r"Web App - Unavailable|404 Web Site not found",
        "status": [404],
    },
    {
        "service": "Shopify",
        "cname_re": r"\.myshopify\.com$",
        "body_re": r"Sorry, this shop is currently unavailable|Only one step left!",
        "status": [404, 200],
    },
    {
        "service": "Surge.sh",
        "cname_re": r"\.surge\.sh$",
        "body_re": r"project not found",
        "status": [404, 200],
    },
    {
        "service": "Tumblr",
        "cname_re": r"\.tumblr\.com$",
        "body_re": r"Whatever you were looking for doesn't currently exist at this address|There's nothing here",
        "status": [404, 200],
    },
    {
        "service": "Fastly",
        "cname_re": r"\.fastly\.net$",
        "body_re": r"Fastly error: unknown domain",
        "status": [500, 404],
    },
    {
        "service": "Netlify",
        "cname_re": r"\.netlify\.(com|app)$",
        "body_re": r"Not Found - Request ID:",
        "status": [404],
    },
    {
        "service": "Vercel / Now.sh",
        "cname_re": r"\.(now\.sh|vercel\.app)$",
        "body_re": r"The deployment could not be found|404: NOT_FOUND",
        "status": [404],
    },
    {
        "service": "Pantheon",
        "cname_re": r"\.pantheonsite\.io$",
        "body_re": r"The gods are wise, but do not know of the site which you seek",
        "status": [404],
    },
    {
        "service": "GitLab Pages",
        "cname_re": r"\.gitlab\.io$",
        "body_re": r"The page you're looking for could not be found",
        "status": [404],
    },
    {
        "service": "Bitbucket",
        "cname_re": r"\.bitbucket\.io$",
        "body_re": r"Repository not found",
        "status": [404],
    },
    {
        "service": "Webflow",
        "cname_re": r"\.webflow\.com$|proxy-ssl\.webflow\.com$",
        "body_re": r"The page you are looking for doesn't exist or has been moved",
        "status": [404],
    },
]


def _resolve_cnames(hostname: str, max_hops: int = 5) -> list[str]:
    """Walk CNAME chain. Returns ordered list of CNAME targets (excluding
    the original hostname). Empty list = no CNAMEs or resolution failed."""
    chain = []
    cur = hostname.rstrip(".")
    seen = set()
    for _ in range(max_hops):
        if cur in seen:
            break
        seen.add(cur)
        try:
            answers = dns.resolver.resolve(cur, "CNAME", lifetime=3.0)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.exception.Timeout, dns.resolver.NoNameservers):
            break
        except Exception:
            break
        next_targets = [str(rd.target).rstrip(".") for rd in answers]
        if not next_targets:
            break
        nxt = next_targets[0]
        chain.append(nxt)
        cur = nxt
    return chain


@router.post("/api/webapp/scan/subdomain_takeover")
def scan_subdomain_takeover(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target)
    parsed = urlparse(base)
    hostname = parsed.hostname or req.target

    # Apex domain check - apex CNAMEs are rare + usually intentional.
    # Skip if no subdomain (hostname has only 2 labels like example.com).
    if hostname.count(".") < 2:
        return vuln_response(
            tool="subdomain_takeover", target=req.target, findings=[],
            tested=1, skipped_reason=(
                "Apex domain detected (no subdomain). Subdomain takeover "
                "applies to subdomains with dangling CNAMEs. To test, "
                "scan a subdomain like 'blog.example.com'."),
            what_checked="Subdomain takeover (apex - skipped)",
        )

    # Resolve CNAME chain
    chain = _resolve_cnames(hostname)
    if not chain:
        return vuln_response(
            tool="subdomain_takeover", target=req.target,
            findings=[wrap_finding(
                f"{hostname}: no CNAME records - not eligible for takeover",
                "POSITIVE", cvss="0.0", cwe="N/A",
                remediation="Continue current DNS posture. Subdomain "
                            "points directly to A/AAAA records, no "
                            "external service dependency.",
                evidence_marker=f"DNS query for CNAME {hostname}: no records",
            )],
            tested=1,
            what_checked="CNAME chain walk + takeover-service fingerprint",
            tests_summary=f"{hostname}: 0 CNAMEs found",
        )

    # Check each CNAME hop against the catalog
    matched = []
    for cname in chain:
        for svc in _TAKEOVER_SERVICES:
            try:
                if re.search(svc["cname_re"], cname, re.IGNORECASE):
                    matched.append((cname, svc))
                    break
            except re.error:
                continue

    if not matched:
        return vuln_response(
            tool="subdomain_takeover", target=req.target,
            findings=[wrap_finding(
                f"{hostname}: CNAME chain present but no takeover-prone services",
                "POSITIVE", cvss="0.0", cwe="N/A",
                remediation="Continue. CNAMEs resolve to non-vulnerable infrastructure.",
                evidence_marker=f"CNAME chain: {' -> '.join(chain[:5])}",
            )],
            tested=len(chain),
            what_checked=f"CNAME-catalog match across {len(chain)} hop(s)",
            tests_summary=f"chain: {' -> '.join(chain[:3])}; 0 service matches",
        )

    # Got matches - now HTTP-fetch + look for the fingerprint
    findings = []
    for cname, svc in matched:
        try:
            r = safe_get(base, req=req, allow_redirects=True, timeout=8)
        except Exception as e:
            findings.append(wrap_finding(
                f"{hostname} CNAME -> {svc['service']}, HTTP probe error",
                "INFO", cvss="0.0", cwe="N/A",
                remediation="Manually verify the CNAME target is claimed.",
                evidence_marker=f"CNAME -> {cname}; HTTP error: {type(e).__name__}",
            ))
            continue
        if r is None:
            findings.append(wrap_finding(
                f"{hostname} CNAME -> {svc['service']} but target unreachable",
                "INFO", cvss="0.0", cwe="N/A",
                remediation="Verify the CNAME target is intentionally claimed "
                            "and not dangling.",
                evidence_marker=f"CNAME chain: {' -> '.join(chain)}; HTTP fetch returned None",
            ))
            continue

        body = (r.text or "")[:8000]
        status_match = r.status_code in (svc.get("status") or [])
        fp_match = bool(re.search(svc["body_re"], body, re.IGNORECASE))

        if fp_match or (status_match and "not found" in body.lower()):
            findings.append(wrap_finding(
                f"SUBDOMAIN TAKEOVER possible: {hostname} -> {svc['service']} (unclaimed)",
                "CRITICAL", cvss="9.5", cwe="CWE-350", owasp="A05:2021",
                remediation=(
                    f"Either reclaim the {svc['service']} resource that "
                    f"{cname} points to, OR remove the dangling CNAME from "
                    f"DNS. An attacker can claim {cname} on {svc['service']} "
                    f"and serve arbitrary content under your subdomain "
                    f"(cookie theft, phishing, brand damage)."
                ),
                evidence_marker=(
                    f"CNAME chain: {' -> '.join(chain)}; "
                    f"matched service: {svc['service']}; "
                    f"HTTP {r.status_code}; "
                    f"fingerprint in body: {fp_match}"
                ),
            ))
        else:
            findings.append(wrap_finding(
                f"{hostname} CNAME -> {svc['service']} (claimed - not vulnerable)",
                "POSITIVE", cvss="0.0", cwe="N/A",
                remediation=f"Continue. {svc['service']} resource is claimed "
                            "and serving content. Monitor for future drift.",
                evidence_marker=(
                    f"CNAME -> {cname}; HTTP {r.status_code}; "
                    f"no takeover fingerprint in body"
                ),
            ))

    return vuln_response(
        tool="subdomain_takeover", target=req.target, findings=findings,
        tested=max(len(chain) + len(matched), 1),
        what_checked=(f"CNAME walk ({len(chain)} hops) + "
                       f"{len(_TAKEOVER_SERVICES)}-service catalog match + "
                       "HTTP fingerprint confirm"),
        tests_summary=(f"chain: {' -> '.join(chain[:3])}; "
                        f"{len(matched)} service match(es); "
                        f"{sum(1 for f in findings if f.get('severity')=='CRITICAL')} takeover(s)"),
        raw_data={"subdomain_takeover": {
            "cname_chain": chain,
            "service_matches": [{"cname": c, "service": s["service"]} for c, s in matched],
        }},
    )


def register(app):
    app.include_router(router)

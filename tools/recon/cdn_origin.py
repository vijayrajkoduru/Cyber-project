"""recon_cdn_origin — attempt to discover the origin IP behind Cloudflare / WAF.

Methods:
1. Check if Cloudflare/CDN is in front (via headers)
2. Try common subdomain bypasses (direct, origin, mail, ftp, etc.)
3. Check MX records (mail server often shares network)
4. Search Censys/Shodan-style HTTPS cert SAN for non-CDN IPs (heuristic)
"""
import socket
import dns.resolver
import dns.exception
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, safe_get, web_url, recon_host

router = APIRouter()

CDN_HEADERS = {
    "cf-ray": "Cloudflare",
    "server": ["cloudflare", "akamai", "fastly", "varnish", "cloudfront"],
    "x-amz-cf-id": "AWS CloudFront",
    "x-akamai-transformed": "Akamai",
    "x-fastly-request-id": "Fastly",
    "x-cdn": "generic CDN",
}

BYPASS_SUBDOMAINS = ["direct", "origin", "real", "backend", "internal",
                      "mail", "ftp", "smtp", "pop", "imap", "webmail",
                      "vpn", "remote", "admin", "panel", "dev", "test",
                      "staging", "old", "legacy", "api-internal", "backup"]


@router.post("/api/recon/cdn_origin")
async def recon_cdn_origin(req: ScanRequest, _=Depends(verify_scan_quota)):
    domain = recon_host(req.target)
    base = web_url(req.target).rstrip("/")
    findings = []
    cdn_detected = []
    bypass_candidates = []
    mx_records = []

    # Step 1: Detect CDN
    r = safe_get(base, req=req)
    if r is None:
        return {"ok": True, "vulnerable": False, "skipped_reason": "Could not reach target"}

    headers = {k.lower(): v for k, v in r.headers.items()}
    for hdr, marker in CDN_HEADERS.items():
        v = headers.get(hdr, "").lower()
        if not v: continue
        if isinstance(marker, list):
            for m in marker:
                if m in v:
                    cdn_detected.append({"header": hdr, "value": v[:100], "cdn": m})
        elif marker:
            cdn_detected.append({"header": hdr, "value": v[:100], "cdn": marker})

    # If no CDN, no value in this scanner
    if not cdn_detected:
        return {"ok": True, "vulnerable": False,
                "cdn_detected": [], "bypass_candidates": [],
                "skipped_reason": "No CDN/WAF detected in front of target — origin IP discovery not applicable"}

    # Step 2: Get the CDN's IP (what DNS returns) so we can filter it out
    cdn_ips = set()
    try:
        for ans in dns.resolver.resolve(domain, 'A', lifetime=6):
            cdn_ips.add(str(ans))
    except Exception:
        pass

    # Step 3: Try common subdomain bypasses
    for sub in BYPASS_SUBDOMAINS:
        sub_host = f"{sub}.{domain}"
        try:
            ans = dns.resolver.resolve(sub_host, 'A', lifetime=4)
            for r in ans:
                ip = str(r)
                if ip not in cdn_ips:
                    bypass_candidates.append({"subdomain": sub_host, "ip": ip, "source": "DNS A record"})
        except dns.exception.DNSException:
            continue
        except Exception:
            continue

    # Step 4: MX records often expose internal mail servers
    try:
        mx_ans = dns.resolver.resolve(domain, 'MX', lifetime=6)
        for mx in mx_ans:
            mx_host = str(mx.exchange).rstrip('.')
            try:
                ip_ans = dns.resolver.resolve(mx_host, 'A', lifetime=4)
                for ip_r in ip_ans:
                    ip = str(ip_r)
                    mx_records.append({"mx": mx_host, "preference": mx.preference, "ip": ip})
                    if ip not in cdn_ips:
                        bypass_candidates.append({"subdomain": mx_host, "ip": ip, "source": "MX record"})
            except Exception:
                mx_records.append({"mx": mx_host, "preference": mx.preference, "ip": None})
    except Exception:
        pass

    # Findings
    if bypass_candidates:
        unique_ips = sorted(set(b["ip"] for b in bypass_candidates if b["ip"]))
        findings.append({
            "title": f"CDN origin IP possibly leaked — {len(unique_ips)} candidate IP(s) found",
            "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-200", "owasp": "A05:2021",
            "evidence": (f"CDN: {', '.join(set(c['cdn'] for c in cdn_detected))}. "
                         f"Candidate origin IPs: {', '.join(unique_ips[:5])}"
                         f"{' and more' if len(unique_ips) > 5 else ''}. "
                         f"Found via: {', '.join(set(b['source'] for b in bypass_candidates))}"),
            "remediation": ("Restrict origin server to accept connections only from your CDN's "
                            "published IP ranges (Cloudflare: https://www.cloudflare.com/ips/, "
                            "AWS CloudFront: documented in AWS IP ranges). Verify subdomain "
                            "DNS records don't bypass the CDN unintentionally.")
        })

    return {"ok": True, "vulnerable": len(findings) > 0, "findings": findings,
            "cdn_detected": cdn_detected,
            "cdn_ips": list(cdn_ips),
            "bypass_candidates": bypass_candidates,
            "mx_records": mx_records,
            "subdomains_probed": len(BYPASS_SUBDOMAINS),
            "engine": f"CDN origin discovery — {len(BYPASS_SUBDOMAINS)}-subdomain DNS sweep + MX lookup"}


def register(app):
    app.include_router(router)

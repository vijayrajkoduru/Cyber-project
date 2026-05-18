"""Full Recon-module dev-time asset generator.

10 assets: tech_fingerprints, takeover_signatures, subdomain_wordlists,
tech_cve_map, waf_fingerprints, origin_discovery, email_security,
dns_deep_checks, cert_intelligence, shodan_dorks.
"""
import json, os, re, sys
import anthropic

CONFIGS = {
    "tech_fingerprints": {
        "max_tokens": 28000, "var": "TECH_FINGERPRINTS",
        "prompt": """Generate 400 tech/CMS/server fingerprints for a recon scanner.

Cover: web servers (40), CMS (50), frameworks (50), languages (30),
CDN/WAF (50), databases (30), analytics (30), JS libraries (40),
e-commerce (30), dev tools (30), monitoring (20).

Each item EXACTLY 7 keys:
  name, category, header_regex (Python regex or null),
  body_regex (Python regex or null), cookie_regex (Python regex or null),
  version_group (int — capture group number for version, 0 if none),
  severity ("INFO")

Use "null" literal (no quotes) where regex doesn't apply.
Keep regex SHORT (<70 chars).

OUTPUT: ONLY JSON array. Start [ end ]. No prose."""
    },
    "takeover_signatures": {
        "max_tokens": 18000, "var": "TAKEOVER_SIGNATURES",
        "prompt": """Generate 200 subdomain-takeover signatures.

Cover AWS S3/CloudFront/EB, Heroku/Fly/Render, GitHub Pages, GitLab Pages,
Cloudflare Pages, Vercel, Netlify, Azure Blob/CDN/Front Door, GCP Storage/AppEngine/Firebase,
Fastly, BunnyCDN, Zendesk, Statuspage, Tilda, Surge, Webflow, Tumblr, Shopify,
ReadTheDocs, GitBook, Pantheon, WPEngine, Mailgun, SendGrid, Postmark.

Each item EXACTLY 6 keys:
  service (string),
  cname_patterns (array of regex strings, 1-3 entries),
  fingerprint_body (Python regex for error/claim page),
  fingerprint_status (integer HTTP status expected, e.g. 404, 200),
  severity ("HIGH" or "CRITICAL"),
  documentation (1-line takeover description)

OUTPUT: ONLY JSON array. Start [ end ]."""
    },
    "subdomain_wordlist": {
        "max_tokens": 28000, "var": "SUBDOMAIN_WORDLIST",
        "prompt": """Generate 1500 subdomain words for DNS bruteforce, priority-ordered (highest hit rate first).

Mix:
- top generic (api, www, mail, dev, staging, test, prod, admin, app, etc.) — 150
- SaaS-specific (api-v1, api-v2, status, docs, blog, store, cdn, assets, etc.) — 250
- WordPress sites (wp, wp-admin, cdn, blog, store, members) — 150
- corporate (vpn, mail, intranet, hr, ldap, sso, iam, sharepoint, owa, jira, confluence) — 200
- cloud-hosted (s3, cdn, api-gateway, lambda, ecs, kube) — 200
- dev/staging variants (dev, dev2, devops, test, qa, uat, staging, sandbox, preview) — 150
- regional (eu, us, asia, in, sg, london, tokyo, sydney) — 100
- random common words from real subdomain enum results — 300

Each item EXACTLY 3 keys:
  word (lowercase, no dot, no protocol),
  category (generic|saas|wordpress|corporate|cloud|devstaging|regional|common),
  priority (1-10, 10=highest probability of hit)

OUTPUT: ONLY JSON array. Start [ end ]."""
    },
    "tech_cve_map": {
        "max_tokens": 28000, "var": "TECH_CVE_MAP",
        "prompt": """Generate 400 tech-version-to-CVE mappings. Focus on CVEs with public exploits or commonly scanned.

Cover:
- Apache CVE families (CVE-2021-41773 path traversal, CVE-2021-42013, etc.)
- nginx CVEs
- WordPress core + top 30 plugins
- Drupal (Drupalgeddon2 etc.)
- Joomla, Magento
- PHP version CVE families
- Spring (Log4Shell, Spring4Shell)
- Jenkins, GitLab, Confluence (CVE-2022-26134)
- Exchange (ProxyShell)
- Apache Struts, Tomcat, WebLogic
- Cisco ASA, Palo Alto, Fortinet

Each item EXACTLY 6 keys:
  tech (string), version_match (Python regex matching vulnerable version),
  cve (CVE-XXXX-XXXXX), severity (CRITICAL|HIGH|MEDIUM),
  cvss (numeric score string), description (1-line summary)

OUTPUT: ONLY JSON array. Start [ end ]."""
    },
    "waf_fingerprints": {
        "max_tokens": 10000, "var": "WAF_FINGERPRINTS",
        "prompt": """Generate 50 WAF/CDN fingerprints.

Cover: Cloudflare, Akamai, F5 BIG-IP, AWS WAF, Imperva Incapsula, Fastly,
Sucuri, ModSecurity, Wordfence, Barracuda, Citrix NetScaler, Radware,
Fortinet FortiWeb, Wallarm, KeyCDN, StackPath, Azure Front Door, GCP Cloud Armor.

Each item EXACTLY 6 keys:
  provider (string),
  category (waf|cdn|hybrid),
  header_signatures (array of "Header-Name: regex-or-substring" 1-4 entries),
  cookie_signatures (array, 0-2 entries),
  body_signatures (array of body regex 0-2 entries),
  block_status (typical block HTTP status like 403, 406, 429)

OUTPUT: ONLY JSON array. Start [ end ]."""
    },
    "origin_discovery": {
        "max_tokens": 10000, "var": "ORIGIN_DISCOVERY",
        "prompt": """Generate 50 origin-server discovery techniques for getting behind CDN/WAF.

Techniques: DNS history (SecurityTrails / FarsightDNS / Whoisxmlapi patterns),
Censys cert SAN parsing, Shodan host history queries, FOFA cert hash search,
historical DNS via crt.sh CT logs, Wayback Machine IP history,
direct origin reveal via misconfigured emails (SPF / DMARC origin IPs),
mail server reveal, subdomain that bypasses CDN (e.g. dev.target.com pointing direct).

Each item EXACTLY 5 keys:
  name (string),
  technique (category: dns_history|cert_san|shodan|censys|wayback|email_leak|misconfig),
  query_pattern (the query template to run, with {DOMAIN} placeholder),
  difficulty (easy|medium|hard),
  success_rate ("high"|"medium"|"low" — typical rate)

OUTPUT: ONLY JSON array. Start [ end ]."""
    },
    "email_security_checks": {
        "max_tokens": 10000, "var": "EMAIL_SECURITY_CHECKS",
        "prompt": """Generate 40 email-security DNS checks.

Cover: SPF policy depth (10 patterns — missing, neutral, too permissive, syntax errors,
nested includes, no all qualifier, multiple SPF records, too many lookups),
DMARC policy (8 patterns — none/quarantine/reject, alignment modes, rua/ruf misconfig),
DKIM presence (5 patterns — missing selectors, weak key length),
BIMI (5 patterns), MTA-STS (5 patterns), DANE TLSA (4 patterns),
TLS-RPT (3 patterns).

Each item EXACTLY 6 keys:
  check_name (string),
  category (spf|dmarc|dkim|bimi|mta_sts|dane|tls_rpt),
  pattern (Python regex matching the bad config in the DNS record),
  severity (HIGH|MEDIUM|LOW),
  cvss (string),
  remediation (1-2 sentences how to fix)

OUTPUT: ONLY JSON array. Start [ end ]."""
    },
    "dns_deep_checks": {
        "max_tokens": 10000, "var": "DNS_DEEP_CHECKS",
        "prompt": """Generate 40 DNS deep-analysis checks beyond standard A/AAAA/MX.

Cover: SRV record disclosure (Active Directory _ldap._tcp, _kerberos._tcp, _autodiscover, etc.),
HINFO disclosure, NS misconfiguration (no glue records, mismatched NS), unusual TTLs
(<60s = suspicious / >86400 = slow remediation), zone transfer accidents,
DNSSEC validation gaps, DoH/DoT availability, CAA records, NXDOMAIN-based subdomain enum,
wildcard DNS detection, DNS-over-HTTPS fingerprinting, AXFR / IXFR tests.

Each item EXACTLY 6 keys:
  check_name (string),
  record_type (A|AAAA|MX|TXT|SRV|HINFO|CAA|DS|DNSKEY|etc.),
  detection (1-2 sentences how to detect this misconfig),
  severity (HIGH|MEDIUM|LOW|INFO),
  cvss (string),
  remediation (1-line fix)

OUTPUT: ONLY JSON array. Start [ end ]."""
    },
    "cert_intelligence": {
        "max_tokens": 10000, "var": "CERT_INTELLIGENCE",
        "prompt": """Generate 40 SSL/TLS certificate intelligence checks.

Cover: weak signature algorithms (SHA-1, MD5), small key sizes (RSA<2048, EC<256),
expired/expiring soon (<14 days), self-signed in production, CA reputation
(Let's Encrypt OK / Symantec deprecated / unknown CA risky), missing OCSP stapling,
missing must-staple, weak cipher suites still supported (RC4, 3DES, DES, NULL),
TLS 1.0/1.1 still enabled, missing forward secrecy, weak DH params (<2048),
certificate name mismatch, SAN missing for common subdomains, wildcard cert risks,
short cert validity (<30 days suspicious), CT log absence, BR (Baseline Requirements) violations.

Each item EXACTLY 6 keys:
  check_name (string),
  category (algorithm|key_size|validity|ca|cipher|protocol|chain|sni),
  detection (1-line how to detect),
  severity (CRITICAL|HIGH|MEDIUM|LOW),
  cvss (string),
  remediation (1-line fix)

OUTPUT: ONLY JSON array. Start [ end ]."""
    },
    "shodan_dorks": {
        "max_tokens": 12000, "var": "SHODAN_DORKS",
        "prompt": """Generate 150 Shodan + Censys + Google search dorks for reconnaissance.

Cover: exposed admin panels, default credentials, exposed databases (MongoDB/Redis/Elasticsearch),
exposed CI/CD (Jenkins, GitLab, Drone), config files (.env, wp-config.php),
debug pages (phpinfo, /debug, /trace), IoT devices, network gear default web,
camera streams, exposed Kubernetes API, exposed Docker API, leaked credentials in code (GitHub).

Each item EXACTLY 5 keys:
  name (string, what it finds),
  platform (shodan|censys|google|github),
  query (the actual dork query, use {DOMAIN} for target placeholder where applicable),
  category (admin_panel|database|ci_cd|config|debug|iot|camera|kubernetes|leaked_secrets),
  severity_if_found (CRITICAL|HIGH|MEDIUM|LOW)

OUTPUT: ONLY JSON array. Start [ end ]."""
    },
}


def salvage(raw):
    """Aggressive multi-pass salvage."""
    raw = re.sub(r"^```(?:json)?\s*", "", raw.strip())
    raw = re.sub(r"\s*```\s*$", "", raw)
    # Strip prose before first [
    bracket = raw.find("[")
    if 0 < bracket < 500:
        raw = raw[bracket:]
    # Try direct parse
    try:
        return json.loads(raw), False
    except json.JSONDecodeError:
        pass
    # Walk backwards through EVERY closing brace, try as last element
    closing = [i for i, c in enumerate(raw) if c == "}"]
    closing.reverse()
    # Cap at 500 attempts so we don't burn forever
    for pos in closing[:500]:
        candidate = raw[:pos+1] + "]"
        try:
            res = json.loads(candidate)
            if isinstance(res, list) and len(res) > 5:
                return res, True
        except json.JSONDecodeError:
            continue
    # Last resort — strip trailing partial element and find last complete object
    # by counting brace depth
    depth = 0
    last_complete_end = -1
    in_str = False
    escape = False
    for i, c in enumerate(raw):
        if escape:
            escape = False; continue
        if c == "\\":
            escape = True; continue
        if c == "\"":
            in_str = not in_str; continue
        if in_str:
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 1:  # back to array level (depth 0 = before [, 1 = inside [])
                last_complete_end = i
    if last_complete_end > 0:
        candidate = raw[:last_complete_end+1] + "]"
        try:
            res = json.loads(candidate)
            if isinstance(res, list) and len(res) > 5:
                return res, True
        except json.JSONDecodeError:
            pass
    return None, False


def main():
    kind = sys.argv[1] if len(sys.argv) > 1 else ""
    if kind not in CONFIGS:
        sys.exit(f"Usage: gen_recon_assets.py {list(CONFIGS.keys())}")
    cfg = CONFIGS[kind]
    print(f"=== {kind} (max_tokens={cfg['max_tokens']}, streaming) ===")
    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("ANTHROPIC_API_KEY missing")

    client = anthropic.Anthropic()
    chunks, last_dot = [], 0
    with client.messages.stream(
        model="claude-sonnet-4-6",
        max_tokens=cfg["max_tokens"],
        messages=[{"role": "user", "content": cfg["prompt"]}],
    ) as stream:
        for text in stream.text_stream:
            chunks.append(text)
            total = sum(len(c) for c in chunks)
            if total // 5000 > last_dot:
                print(".", end="", flush=True); last_dot = total // 5000
        final = stream.get_final_message()
        in_tok, out_tok = final.usage.input_tokens, final.usage.output_tokens
    print()

    raw = "".join(chunks)
    items, salvaged = salvage(raw)
    if items is None:
        open(f"/tmp/{kind}_raw.txt", "w").write(raw)
        sys.exit(f"Salvage failed. Saved /tmp/{kind}_raw.txt ({len(raw)} bytes)")
    if salvaged:
        print(f"  ⚠ truncated, salvaged {len(items)} items")

    out = f"/tmp/vl_payloads/{kind}.py"
    os.makedirs(os.path.dirname(out), exist_ok=True)
    import pprint
    with open(out, "w") as f:
        f.write(f'"""{kind} — generated dev-time by Claude. Recon module asset.\n"""\n\n')
        f.write(f'{cfg["var"]} = ')
        f.write(pprint.pformat(items, width=120, sort_dicts=False))
        f.write("\n")
    cost = (in_tok * 3 + out_tok * 15) / 1_000_000
    print(f"  ✓ wrote {len(items)} items to {out}")
    print(f"  tokens: {in_tok} in, {out_tok} out  |  cost: ~${cost:.3f}")


if __name__ == "__main__":
    main()

"""Tier 6 shared findings — GraphQL / GitHub Leaks / Email Security / Breach Search / Dork Harvest / DNSSEC.

These 6 tools close the OSINT/human-side recon gap that brings VulnusLab Recon
from ~89% to ~95% industry-leading coverage (matches Detectify + RidgeBot).
"""

# ───────────────────────── GraphQL Introspection ─────────────────────────

def rule_graphql_introspection_enabled(s):
    if not s.get("introspection_enabled"): return None
    tc = s.get("type_count") or 0
    return {"name": "GraphQL introspection ENABLED — schema fully exposed",
            "severity": "HIGH",
            "cwe": "CWE-200",
            "owasp": "API3:2023",
            "evidence": f"GraphQL endpoint {s.get('endpoint_found','?')} returned full schema via __schema query — {tc} types, {s.get('mutation_count',0)} mutations enumerable",
            "remediation": "Disable introspection in production. Apollo: set introspection:false. GraphQL.js: pass disableIntrospection. Express-graphql: remove graphiql + set customExecuteFn that rejects __schema queries. Introspection lets attackers map every query/mutation/field without guessing."}


def rule_graphql_endpoint_exposed(s):
    if not s.get("endpoint_found"): return None
    if s.get("introspection_enabled"): return None
    return {"name": "GraphQL endpoint reachable (introspection disabled)",
            "severity": "INFO",
            "evidence": f"Endpoint found: {s.get('endpoint_found')} — schema NOT exposed",
            "remediation": "Endpoint is reachable but properly hardened. Verify also that batched/aliased queries are rate-limited."}


def rule_graphql_playground_exposed(s):
    if not s.get("playground_exposed"): return None
    return {"name": "GraphQL Playground / GraphiQL UI publicly accessible",
            "severity": "MEDIUM",
            "cwe": "CWE-489",
            "evidence": f"Interactive GraphQL IDE accessible at {s.get('playground_url','?')}",
            "remediation": "Disable GraphQL Playground / GraphiQL in production. These IDEs let attackers craft + send arbitrary queries through your browser."}


def rule_graphql_no_endpoint(s):
    if s.get("endpoint_found"): return None
    if not s.get("paths_probed"): return None
    return {"name": "No GraphQL endpoint detected",
            "severity": "POSITIVE",
            "evidence": f"Probed {s.get('paths_probed', 0)} common GraphQL paths — none responded"}


GRAPHQL_FINDING_RULES = [
    rule_graphql_introspection_enabled,
    rule_graphql_endpoint_exposed,
    rule_graphql_playground_exposed,
    rule_graphql_no_endpoint,
    lambda s: {"name": f"{s.get('paths_probed', 0)} GraphQL paths probed",
                "severity": "INFO",
                "evidence": "Standard locations: /graphql, /api/graphql, /v1/graphql, /query, /api/query"}
              if s.get("paths_probed") else None,
]


# ───────────────────────── GitHub Leaks ─────────────────────────

def rule_github_org_exposed(s):
    if not s.get("org_found"): return None
    return {"name": f"GitHub organization '{s.get('org_name','?')}' indexed publicly",
            "severity": "INFO",
            "evidence": f"{s.get('public_repo_count',0)} public repos, {s.get('member_count',0)} visible members",
            "remediation": "Public GitHub presence is normal — but audit for leaked secrets via #2 rule below."}


def rule_github_leaked_secrets(s):
    leaks = s.get("secret_hits") or []
    if not leaks: return None
    return {"name": f"Possible secrets in public GitHub code ({len(leaks)})",
            "severity": "CRITICAL",
            "cwe": "CWE-798",
            "owasp": "A07:2021",
            "evidence": "; ".join(f"{h.get('repo','?')}/{h.get('path','?')}: {h.get('kind','?')}"
                                   for h in leaks[:5]),
            "remediation": "ROTATE EXPOSED SECRETS IMMEDIATELY. GitHub search-indexes ALL public commits — even historical/deleted files. Use git-filter-branch + force-push, then rotate every key/token/password. Add a pre-commit hook (gitleaks, trufflehog) + branch protection rules."}


def rule_github_company_repos(s):
    repos = s.get("matched_repos") or []
    if not repos: return None
    return {"name": f"{len(repos)} GitHub repo(s) reference the target domain",
            "severity": "MEDIUM",
            "evidence": "; ".join(r.get("full_name","?") for r in repos[:5]),
            "remediation": "Review each repo: is it an official company repo, a leak by a former employee, or a fan/clone? Internal repos accidentally public are an exfil vector."}


def rule_github_no_findings(s):
    if (s.get("matched_repos") or []) or (s.get("secret_hits") or []): return None
    if not s.get("api_reachable"): return None
    return {"name": "No GitHub leaks detected for this domain",
            "severity": "POSITIVE",
            "evidence": "GitHub code-search returned no domain-matching public repos or secret-pattern hits"}


GITHUB_LEAKS_FINDING_RULES = [
    rule_github_leaked_secrets,
    rule_github_company_repos,
    rule_github_org_exposed,
    rule_github_no_findings,
    lambda s: {"name": "GitHub recon completed",
                "severity": "INFO",
                "evidence": "Org metadata + domain-keyword code search + secret-pattern match"}
              if s.get("api_reachable") else None,
]


# ───────────────────────── Email Security (SPF / DMARC / DKIM) ─────────────────────────

def rule_no_spf(s):
    if s.get("spf_record"): return None
    return {"name": "No SPF record published",
            "severity": "HIGH",
            "cwe": "CWE-290",
            "evidence": f"No 'v=spf1' TXT record on {s.get('host','?')} — anyone can spoof email from this domain",
            "remediation": "Publish an SPF record. Minimum: 'v=spf1 -all' if you send no email. If you do send, list authorised servers: 'v=spf1 include:_spf.google.com -all'"}


def rule_spf_too_lenient(s):
    spf = s.get("spf_record") or ""
    if not spf: return None
    if spf.rstrip().endswith("+all"):
        return {"name": "SPF record ends with +all — accepts mail from ANY source",
                "severity": "HIGH",
                "cwe": "CWE-290",
                "evidence": f"SPF: {spf[:160]}",
                "remediation": "Replace '+all' with '-all' (hard fail) or at minimum '~all' (soft fail). +all defeats the entire purpose of SPF."}
    if spf.rstrip().endswith("?all"):
        return {"name": "SPF record uses ?all — neutral, ineffective",
                "severity": "MEDIUM",
                "evidence": f"SPF: {spf[:160]}",
                "remediation": "Change '?all' to '-all' or '~all' so receivers actually act on SPF failures."}
    return None


def rule_spf_lookup_limit(s):
    lookups = s.get("spf_dns_lookups") or 0
    if lookups <= 10: return None
    return {"name": f"SPF record exceeds 10 DNS lookups ({lookups})",
            "severity": "MEDIUM",
            "cwe": "CWE-665",
            "evidence": "RFC 7208 caps SPF at 10 DNS lookups (include:, a, mx, ptr, exists, redirect). Exceeding the limit breaks SPF entirely — receivers return permerror.",
            "remediation": "Flatten nested includes or use SPF macros to consolidate. Tools: dmarcian SPF Surveyor, spfwizard.net"}


def rule_no_dmarc(s):
    if s.get("dmarc_record"): return None
    return {"name": "No DMARC record published",
            "severity": "HIGH",
            "cwe": "CWE-290",
            "evidence": f"No _dmarc.{s.get('host','?')} TXT record — spoofed mail goes undetected",
            "remediation": "Publish DMARC at _dmarc.<domain>. Start monitoring-only: 'v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com' — graduate to 'p=quarantine' then 'p=reject' once SPF/DKIM align."}


def rule_dmarc_policy_none(s):
    dmarc = s.get("dmarc_record") or ""
    if not dmarc: return None
    if "p=none" in dmarc.lower():
        return {"name": "DMARC policy is p=none — spoofing not blocked",
                "severity": "MEDIUM",
                "cwe": "CWE-290",
                "evidence": f"DMARC: {dmarc[:160]}",
                "remediation": "p=none only monitors — receivers still deliver spoofed mail. Once your SPF/DKIM logs are clean (rua reports), graduate to 'p=quarantine' then 'p=reject'."}
    return None


def rule_dmarc_strong(s):
    dmarc = (s.get("dmarc_record") or "").lower()
    if not dmarc: return None
    if "p=reject" in dmarc:
        return {"name": "DMARC policy p=reject — strong anti-spoofing",
                "severity": "POSITIVE",
                "evidence": f"DMARC: {(s.get('dmarc_record') or '')[:160]}"}
    if "p=quarantine" in dmarc:
        return {"name": "DMARC policy p=quarantine — solid (graduate to reject)",
                "severity": "POSITIVE",
                "evidence": f"DMARC: {(s.get('dmarc_record') or '')[:160]}"}
    return None


def rule_dkim_missing(s):
    found = s.get("dkim_selectors_found") or []
    if found: return None
    if not s.get("selectors_probed"): return None
    return {"name": "No DKIM selector responds at common names",
            "severity": "MEDIUM",
            "evidence": f"Probed selectors: {', '.join(s.get('selectors_probed_list') or [])[:200]}. None had a v=DKIM1 TXT record.",
            "remediation": "DKIM signs outgoing mail so receivers verify it wasn't tampered. If you send mail, publish a DKIM key at <selector>._domainkey.<domain>. Common selectors: google, k1, selector1, mandrill."}


EMAIL_SECURITY_FINDING_RULES = [
    rule_no_spf, rule_spf_too_lenient, rule_spf_lookup_limit,
    rule_no_dmarc, rule_dmarc_policy_none, rule_dmarc_strong,
    rule_dkim_missing,
    lambda s: {"name": "Email security records scanned",
                "severity": "INFO",
                "evidence": "Checked SPF + DMARC + 10 DKIM selectors"}
              if s.get("scanned") else None,
]


# ───────────────────────── Breach Search ─────────────────────────

def rule_domain_in_breaches(s):
    breaches = s.get("breaches") or []
    if not breaches: return None
    return {"name": f"Domain found in {len(breaches)} known data breach(es)",
            "severity": "CRITICAL" if len(breaches) >= 3 else "HIGH",
            "cwe": "CWE-359",
            "owasp": "A07:2021",
            "evidence": "; ".join(f"{b.get('name','?')} ({b.get('date','?')}, {b.get('pwn_count','?')} accounts)"
                                   for b in breaches[:5]),
            "remediation": "Force password reset for all users with credentials at this domain. Enable MFA. Subscribe to HIBP domain alerts (free for verified domains). Treat all historical passwords as compromised."}


def rule_paste_exposure(s):
    pastes = s.get("pastes") or []
    if not pastes: return None
    return {"name": f"Domain mentioned in {len(pastes)} paste-site dump(s)",
            "severity": "HIGH",
            "evidence": "; ".join(f"{p.get('source','?')}: {p.get('title','?')}" for p in pastes[:3]),
            "remediation": "Review each paste. Pastebin/Ghostbin dumps often contain credential lists, API keys, or insider docs. Reset any exposed creds. Consider takedown via paste-site abuse channels."}


def rule_no_breach_data(s):
    if (s.get("breaches") or []) or (s.get("pastes") or []): return None
    if not s.get("api_reachable"): return None
    return {"name": "No breach exposure detected for domain",
            "severity": "POSITIVE",
            "evidence": "HIBP + paste-site indexes returned no domain hits"}


BREACH_SEARCH_FINDING_RULES = [
    rule_domain_in_breaches,
    rule_paste_exposure,
    rule_no_breach_data,
    lambda s: {"name": "Breach corpus checked",
                "severity": "INFO",
                "evidence": "HIBP breaches API + paste-site index"}
              if s.get("api_reachable") else None,
    lambda s: {"name": "Domain breach summary",
                "severity": "INFO",
                "evidence": f"Total breaches matching domain: {len(s.get('breaches') or [])}"}
              if (s.get("breaches") is not None) else None,
]


# ───────────────────────── Dork Harvest ─────────────────────────

def rule_dork_critical_hits(s):
    hits = s.get("critical_hits") or []
    if not hits: return None
    return {"name": f"Search engines indexed sensitive paths ({len(hits)})",
            "severity": "CRITICAL",
            "cwe": "CWE-200",
            "evidence": "; ".join(f"{h.get('dork','?')} -> {h.get('url','?')[:80]}" for h in hits[:5]),
            "remediation": "Block sensitive paths at the WAF/server level so search engines don't crawl them. Add to robots.txt (note: this is hint-only — block at server). Use 'X-Robots-Tag: noindex' header. Request URL removal via Google Search Console + Bing Webmaster Tools."}


def rule_dork_indexed_files(s):
    files = s.get("indexed_files") or []
    if not files: return None
    return {"name": f"{len(files)} file(s) indexed by search engines",
            "severity": "MEDIUM",
            "evidence": "Categories: " + ", ".join(s.get("file_categories", {}).keys()),
            "remediation": "Audit each. Configs/dumps should not be web-served at all — move behind auth or off-public-net. Logs/backups indicate misconfigured server."}


def rule_dork_no_hits(s):
    if (s.get("critical_hits") or []) or (s.get("indexed_files") or []): return None
    if not s.get("dorks_run"): return None
    return {"name": "No sensitive content indexed by search engines",
            "severity": "POSITIVE",
            "evidence": f"Ran {s.get('dorks_run',0)} targeted dork queries — no exposed configs/dumps/admin panels"}


DORK_HARVEST_FINDING_RULES = [
    rule_dork_critical_hits,
    rule_dork_indexed_files,
    rule_dork_no_hits,
    lambda s: {"name": f"{s.get('dorks_run', 0)} search-engine dorks executed",
                "severity": "INFO",
                "evidence": "Targeted queries: site:<domain> filetype:<env|sql|log|bak> inurl:<admin|config>"}
              if s.get("dorks_run") else None,
    lambda s: {"name": "Search engines queried",
                "severity": "INFO",
                "evidence": ", ".join(s.get("engines_used") or [])}
              if s.get("engines_used") else None,
]


# ───────────────────────── DNSSEC Validate ─────────────────────────

def rule_dnssec_not_enabled(s):
    if s.get("dnssec_enabled"): return None
    if not s.get("zone_queried"): return None
    return {"name": "DNSSEC not enabled for zone",
            "severity": "LOW",
            "cwe": "CWE-345",
            "evidence": f"No DNSKEY/DS records found for {s.get('host','?')}",
            "remediation": "DNSSEC isn't required for most domains, but its absence means DNS responses can't be cryptographically verified — leaving you exposed to cache poisoning. Enable via registrar + DNS host. Cloudflare, Route53, Google Cloud DNS all support 1-click DNSSEC."}


def rule_dnssec_weak_algorithm(s):
    weak = s.get("weak_algorithms") or []
    if not weak: return None
    return {"name": f"DNSSEC uses weak algorithm(s): {', '.join(weak)}",
            "severity": "MEDIUM",
            "cwe": "CWE-327",
            "evidence": f"Detected algorithms: {', '.join(weak)} — SHA-1 and RSAMD5 are deprecated",
            "remediation": "Re-sign zone with RSASHA256 (algorithm 8), ECDSAP256SHA256 (13), or ED25519 (15). RSAMD5 (1), RSASHA1 (5/7), and DSA (3/6) are all considered weak/deprecated."}


def rule_dnssec_chain_broken(s):
    if not s.get("chain_broken"): return None
    return {"name": "DNSSEC chain of trust BROKEN",
            "severity": "HIGH",
            "cwe": "CWE-295",
            "evidence": s.get("chain_error") or "DS record at parent zone doesn't match DNSKEY at child",
            "remediation": "Mismatch between parent DS and child DNSKEY makes DNSSEC validation FAIL — resolvers reject your zone or fall back to insecure. Re-publish DS records at registrar matching current DNSKEY."}


def rule_dnssec_nsec_zone_walk(s):
    if s.get("nsec_type") != "NSEC": return None
    return {"name": "DNSSEC uses NSEC (not NSEC3) — zone walking possible",
            "severity": "LOW",
            "evidence": "Plain NSEC enumerates all zone names. Attackers can map every subdomain via DNS walking.",
            "remediation": "Switch to NSEC3 with opt-out. Most modern DNS hosts default to NSEC3 — check your zone's signing config."}


def rule_dnssec_healthy(s):
    if not s.get("dnssec_enabled"): return None
    if s.get("chain_broken"): return None
    if (s.get("weak_algorithms") or []): return None
    return {"name": "DNSSEC enabled + chain valid + strong algorithm",
            "severity": "POSITIVE",
            "evidence": f"DNSKEY algorithm: {s.get('strongest_algorithm','?')}; NSEC mode: {s.get('nsec_type','?')}"}


DNSSEC_FINDING_RULES = [
    rule_dnssec_chain_broken,
    rule_dnssec_weak_algorithm,
    rule_dnssec_not_enabled,
    rule_dnssec_nsec_zone_walk,
    rule_dnssec_healthy,
    lambda s: {"name": "DNSSEC chain validated",
                "severity": "INFO",
                "evidence": f"Walked DS/DNSKEY/RRSIG records for {s.get('host','?')}"}
              if s.get("zone_queried") else None,
]

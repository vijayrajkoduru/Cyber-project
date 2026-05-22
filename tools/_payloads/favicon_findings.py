"""Favicon Fingerprint — findings rules library."""

# Common framework favicon MurmurHash3 values (well-known signatures)
FAVICON_HASHES = {
    # Web frameworks
    -1010452349:  "WordPress (default)",
    1052003943:   "Drupal (default)",
    99441111:     "Joomla (default)",
    -2018239108:  "Magento (default)",
    # Admin panels
    -871422638:   "Atlassian Jira",
    -297069170:   "Atlassian Confluence",
    81586312:     "Grafana",
    1499876162:   "Kibana",
    -2026545134:  "Jenkins",
    -1623021725:  "GitLab",
    1968207505:   "Gitea",
    -1923708088:  "phpMyAdmin",
    # Network devices
    99441111:     "Cisco IOS",
    # SaaS
    803199233:    "Notion",
    -1968635377:  "Slack",
    -1437930006:  "GitHub",
    # Cloud panels
    -2102403468:  "cPanel",
    -1666184624:  "Plesk",
}


def rule_tech_identified(s):
    tech = s.get("identified_tech")
    if not tech: return None
    return {"name": f"Technology identified via favicon: {tech}",
            "severity": "INFO",
            "evidence": f"MurmurHash3 of favicon matches {tech} signature"}


def rule_favicon_found(s):
    if not s.get("favicon_found"): return None
    return {"name": "Favicon present",
            "severity": "INFO",
            "evidence": f"Hash: {s.get('mmh3_hash', '?')}"}


def rule_no_favicon(s):
    if s.get("favicon_found"): return None
    if not s.get("base_reachable"): return None
    return {"name": "No favicon found",
            "severity": "INFO",
            "evidence": "/favicon.ico returned 404 or non-image"}


def rule_known_vulnerable_stack(s):
    tech = s.get("identified_tech") or ""
    # Stacks with frequent CVE history
    risky = ["phpMyAdmin", "Jenkins", "GitLab", "Atlassian Jira",
             "Atlassian Confluence", "Drupal", "Magento", "WordPress"]
    for r in risky:
        if r in tech:
            return {"name": f"Identified stack has frequent CVEs: {tech}",
                    "severity": "MEDIUM",
                    "cwe": "CWE-1104",
                    "evidence": f"Favicon hash matched {tech}",
                    "remediation": f"Confirm version + cross-reference NVD for {tech} CVEs. Default-cred panels (phpMyAdmin, Jenkins) are high-priority targets."}
    return None


def rule_default_favicon(s):
    tech = s.get("identified_tech") or ""
    if "default" not in tech.lower(): return None
    return {"name": f"Default uncustomized favicon ({tech})",
            "severity": "LOW",
            "evidence": "Default framework favicon hash matched — site hasn't customized branding",
            "remediation": "Replace default favicon. Default favicons leak the underlying tech stack to attackers via fingerprinting tools (Shodan favicon query)."}


FAVICON_FINDING_RULES = [
    rule_tech_identified, rule_favicon_found, rule_no_favicon,
    rule_known_vulnerable_stack, rule_default_favicon,
]

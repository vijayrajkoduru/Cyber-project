"""bundler_audit_scanner - findings rules (Ruby SCA via bundler-audit).

Matches Gemfile.lock against the ruby-advisory-db (curated -> zero false
positives). Also flags insecure (http) gem sources.
"""


def rule_no_input(s):
    if not s.get("bun_no_input"):
        return None
    return {"name": "bundler_audit_scanner: repo_url or local path required",
            "severity": "INFO",
            "evidence": "bundler-audit needs a Ruby project (Gemfile.lock) via repo_url or local path.",
            "remediation": "Re-run with repo_url=<ruby repo> or target=<local dir with Gemfile.lock>.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_binary_missing(s):
    err = s.get("bun_error") or ""
    if "bundler-audit binary not installed" not in err:
        return None
    return {"name": "bundler-audit binary not installed",
            "severity": "INFO", "evidence": err,
            "remediation": "Install with `gem install bundler-audit` or add it to the scanner image.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_no_gemfile(s):
    if not s.get("bun_no_gemfile"):
        return None
    return {"name": "No Gemfile.lock found (not a Ruby project, or lock not committed)",
            "severity": "INFO",
            "evidence": "bundler-audit requires a committed Gemfile.lock; none was found in the target.",
            "remediation": "Commit Gemfile.lock so gem versions are reproducible and auditable.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_vulns(s):
    n = s.get("bun_vuln_count") or 0
    if n <= 0:
        return None
    top = s.get("bun_top_vulns") or []
    sample = ", ".join(f"{v['id']} ({v['gem']})" for v in top[:5])
    gems = s.get("bun_vuln_gem_count") or 0
    return {"name": f"bundler-audit: {n} vulnerable Ruby gem advisory(ies) across {gems} gem(s)",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-1395", "owasp": "A06:2021",
            "evidence": f"bundler-audit matched {n} ruby-advisory-db advisory(ies). Top: {sample}",
            "remediation": ("Update each gem to a patched version (`bundle update <gem>`). "
                            "Gate CI with `bundler-audit check`.")}


def rule_insecure_source(s):
    sources = s.get("bun_insecure_sources") or []
    if not sources:
        return None
    return {"name": f"Insecure gem source(s) in Gemfile ({len(sources)})",
            "severity": "MEDIUM", "cvss": "5.9",
            "cwe": "CWE-319", "owasp": "A08:2021",
            "evidence": f"Gems fetched over an insecure source (http): {', '.join(sources)}",
            "remediation": "Use https:// gem sources (e.g. https://rubygems.org) to prevent dependency tampering."}


def rule_clean(s):
    if s.get("bun_no_input") or s.get("bun_error") or s.get("bun_no_gemfile"):
        return None
    if not s.get("bun_input_value"):
        return None
    if (s.get("bun_vuln_count") or 0) > 0 or (s.get("bun_insecure_sources") or []):
        return None
    return {"name": "bundler-audit clean (no ruby-advisory-db matches)",
            "severity": "POSITIVE",
            "evidence": "bundler-audit found 0 vulnerable gems and no insecure sources.",
            "remediation": "Keep `bundler-audit check` in CI; refresh the DB with `bundler-audit update`.",
            "cwe": "N/A", "owasp": "N/A"}


BUNDLER_AUDIT_SCANNER_FINDING_RULES = [
    rule_no_input,
    rule_binary_missing,
    rule_no_gemfile,
    rule_vulns,
    rule_insecure_source,
    rule_clean,
]

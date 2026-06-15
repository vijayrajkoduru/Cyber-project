"""install_script_audit - findings rules (playbook §3, install/build-time behavior).

ADVISORY-ONLY: the curated install_script_patterns.json holds heuristics for
suspicious install/build-time script behavior (curl|bash, base64->exec, npm
pre/postinstall shell-outs, env-var exfil shapes, etc.). MANY legitimate
packages match these patterns, so every hit is "worth a human look", NOT
"compromised". Severity is INFO or LOW ONLY and is taken from the pattern's own
declared severity; this rule set NEVER emits HIGH/CRITICAL — any unexpected
severity is hard-capped down to LOW. Zero-FP class: we report only that a
known-suspicious *pattern* literally matched, never that exploitation occurred.
"""

# Hard allow-list of severities advisory install-script findings may carry.
_ADVISORY_SEVERITIES = {"INFO", "LOW"}


def rule_no_input(s):
    if not s.get("isa_no_input"):
        return None
    return {"name": "install_script_audit: repo_url or local path required",
            "severity": "INFO",
            "evidence": "Needs a source tree containing setup.py / setup.cfg / pyproject.toml / "
                        "package.json to read install/build-time scripts.",
            "remediation": "Re-run with repo_url=<repo> or target=<local dir>.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_clone_failed(s):
    err = s.get("isa_clone_error")
    if not err:
        return None
    return {"name": "install_script_audit: could not fetch source",
            "severity": "INFO",
            "evidence": f"Source fetch failed: {err}",
            "remediation": "Provide a reachable public repo_url, or a local path the scanner can read.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_patterns_missing(s):
    if not s.get("isa_patterns_missing"):
        return None
    return {"name": "install_script_audit: curated pattern set missing",
            "severity": "INFO",
            "evidence": "tools/_payloads/supply_chain/install_script_patterns.json could not be loaded; "
                        "no advisory matching performed.",
            "remediation": "Ensure the curated install_script_patterns.json is deployed.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_no_manifests(s):
    if not s.get("isa_no_manifests"):
        return None
    return {"name": "No install/build manifest found",
            "severity": "INFO",
            "evidence": "No setup.py / setup.cfg / pyproject.toml / package.json with an install/build "
                        "script was found to audit.",
            "remediation": "If the project has build hooks, ensure the manifest is present in the scanned tree.",
            "cwe": "N/A", "owasp": "N/A"}


def _grade_hits(hits, want_severity):
    """Build one advisory finding for all hits whose (capped) severity == want_severity."""
    sel = []
    for h in hits or []:
        sev = (h.get("severity") or "INFO").upper()
        if sev not in _ADVISORY_SEVERITIES:   # hard advisory cap — never HIGH/CRITICAL
            sev = "LOW"
        if sev == want_severity:
            sel.append(h)
    if not sel:
        return None
    # de-dupe by (pattern name, file) for a clean sample
    seen = set()
    parts = []
    for h in sel:
        key = (h.get("pattern"), h.get("file"))
        if key in seen:
            continue
        seen.add(key)
        parts.append(f"{h.get('pattern')} in {h.get('file')}")
    sample = "; ".join(parts[:8])
    return sel, sample, len(seen)


def rule_low(s):
    res = _grade_hits(s.get("isa_hits"), "LOW")
    if not res:
        return None
    _sel, sample, n = res
    return {"name": f"Advisory: {n} suspicious install/build-script behavior(s) (review)",
            "severity": "LOW", "cvss": "0.0",
            "cwe": "CWE-829", "owasp": "A08:2021",
            "evidence": f"Install/build manifests contain patterns associated with risky install-time "
                        f"behavior (heuristic, NOT confirmed malicious — many legitimate packages match): "
                        f"{sample}. Each is a human-review hint, not an exploit.",
            "remediation": "Manually review each flagged location: confirm what code runs at install/build "
                           "time, pin/verify any downloaded content (hashes), and prefer build steps that "
                           "do not fetch-and-execute remote code."}


def rule_info(s):
    res = _grade_hits(s.get("isa_hits"), "INFO")
    if not res:
        return None
    _sel, sample, n = res
    return {"name": f"Advisory: {n} install/build-script construct(s) flagged for review",
            "severity": "INFO",
            "evidence": f"Install/build manifests use constructs commonly worth a reviewer's glance "
                        f"(heuristic, frequently legitimate): {sample}.",
            "remediation": "Confirm the intent of each construct; ensure no untrusted input reaches a shell "
                           "or deserializer at install/build time.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_clean(s):
    if s.get("isa_no_input") or s.get("isa_clone_error") or s.get("isa_patterns_missing"):
        return None
    if s.get("isa_no_manifests"):
        return None
    if (s.get("isa_manifest_count") or 0) <= 0:
        return None
    if s.get("isa_hits"):
        return None
    n = s.get("isa_manifest_count") or 0
    return {"name": "No suspicious install/build-script behavior detected",
            "severity": "POSITIVE",
            "evidence": f"Audited {n} install/build manifest(s); none matched the curated suspicious "
                        f"install-script patterns.",
            "remediation": "Keep build steps free of fetch-and-execute and obfuscated dynamic execution; "
                           "re-scan when build tooling changes.",
            "cwe": "N/A", "owasp": "N/A"}


INSTALL_SCRIPT_AUDIT_FINDING_RULES = [
    rule_no_input,
    rule_clone_failed,
    rule_patterns_missing,
    rule_no_manifests,
    rule_low,
    rule_info,
    rule_clean,
]

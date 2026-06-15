"""npm_typosquat_scan - findings rules (playbook §3, npm sibling of #32).

A declared npm dependency whose name is Damerau-distance EXACTLY 1 from a
popular package (but is not itself that package) is a classic typosquat vector.
Driven by exact edit-distance + a curated popular-name list (zero-FP class:
only flags genuine near-misses, never exact popular names). Advisory/medium —
a near-miss may be intentional (e.g. a legitimate fork or scoped variant), so
the finding is graded MEDIUM and worded as "possible / verify", mirroring the
pypi typosquat scanner's grading shape.
"""


def rule_no_input(s):
    if not s.get("npmtypo_no_input"):
        return None
    return {"name": "npm_typosquat_scan: repo_url or target required",
            "severity": "INFO",
            "evidence": "Provide repo_url (github) or a target serving /package.json to read declared deps.",
            "remediation": "Re-run with repo_url=<github repo> or a host that serves package.json.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_client_missing(s):
    if not s.get("npmtypo_client_missing"):
        return None
    return {"name": "npm_typosquat_scan: HTTP client unavailable",
            "severity": "INFO",
            "evidence": "The `requests` library is unavailable in the scanner environment.",
            "remediation": "Install the `requests` library so the package.json can be fetched.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_no_manifest(s):
    if not s.get("npmtypo_no_manifest"):
        return None
    return {"name": "npm_typosquat_scan: no package.json reachable",
            "severity": "INFO",
            "evidence": f"Could not read a package.json ({s.get('npmtypo_manifest_source', 'none')}).",
            "remediation": "Point repo_url at a public GitHub repo whose default branch contains "
                           "package.json, or scan a host that serves it.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_list_missing(s):
    if not s.get("npmtypo_list_missing"):
        return None
    return {"name": "npm_typosquat_scan: curated npm top-list missing",
            "severity": "INFO",
            "evidence": "The curated npm popular-package list could not be loaded; typosquat comparison skipped.",
            "remediation": "Ensure tools/_payloads/supply_chain/npm_top_packages.txt is deployed.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_typo(s):
    hits = s.get("npmtypo_candidates") or []
    if not hits:
        return None
    sample = "; ".join(f"'{h['declared']}' ~ '{h['near']}'" for h in hits[:6])
    return {"name": f"Possible npm typosquat dependency: {len(hits)} package(s)",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-427", "owasp": "A06:2021",
            "evidence": f"Declared npm dependencies are Damerau-edit-distance 1 from popular packages "
                        f"(single substitution or adjacent transposition): {sample}. A near-miss can be "
                        f"a typosquat that ships malicious code, but it may also be intentional (a fork, "
                        f"a scoped variant, or a genuinely similar legitimate name) — verify each.",
            "remediation": ("Verify each flagged package is the one you intended. Replace any typosquat with "
                            "the correct package name, pin exact versions + integrity hashes "
                            "(package-lock.json / npm ci), and enforce a private-registry allowlist to block "
                            "unknown names.")}


def rule_clean(s):
    if s.get("npmtypo_no_input") or s.get("npmtypo_no_manifest") or s.get("npmtypo_list_missing"):
        return None
    if s.get("npmtypo_client_missing"):
        return None
    if (s.get("npmtypo_declared_count") or 0) <= 0:
        return None
    if s.get("npmtypo_candidates"):
        return None
    n = s.get("npmtypo_declared_count") or 0
    return {"name": "No npm typosquat candidates among declared dependencies",
            "severity": "POSITIVE",
            "evidence": f"All {n} declared npm dependency name(s) are either exact popular packages or not "
                        f"distance-1 near-misses of one.",
            "remediation": "Keep pinning exact versions + integrity hashes; add a name allowlist for "
                           "defence in depth.",
            "cwe": "N/A", "owasp": "N/A"}


NPM_TYPOSQUAT_SCAN_FINDING_RULES = [
    rule_no_input,
    rule_client_missing,
    rule_no_manifest,
    rule_list_missing,
    rule_typo,
    rule_clean,
]

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
    # Only CONFIRMED candidates reach here: the declared name is a distance-1
    # near-miss of a popular package AND does NOT resolve on the public npm
    # registry (404). A non-resolving near-miss is genuine typo/confusion risk.
    hits = s.get("npmtypo_candidates") or []
    if not hits:
        return None
    sample = "; ".join(f"'{h['declared']}' ~ '{h['near']}'" for h in hits[:6])
    return {"name": f"Possible npm typosquat dependency: {len(hits)} package(s)",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-427", "owasp": "A06:2021",
            "evidence": f"Declared npm dependencies are Damerau-edit-distance 1 from popular packages "
                        f"(single substitution or adjacent transposition) AND do NOT resolve on the "
                        f"public npm registry (HTTP 404): {sample}. A non-resolving near-miss is a "
                        f"typo/dependency-confusion risk — the intended package may differ, or an "
                        f"attacker could register the mistyped name. Verify each.",
            "remediation": ("Verify each flagged package is the one you intended. Replace any typosquat with "
                            "the correct package name, pin exact versions + integrity hashes "
                            "(package-lock.json / npm ci), and enforce a private-registry allowlist to block "
                            "unknown names.")}


def rule_typo_resolving(s):
    # Near-misses whose DECLARED name DOES resolve on npm (200): a genuinely
    # published package (legit fork / similarly named project). Advisory only —
    # not graded, since there is no proven confusion primitive.
    hits = s.get("npmtypo_resolving_near_misses") or []
    if not hits:
        return None
    sample = "; ".join(f"'{h['declared']}' ~ '{h['near']}'" for h in hits[:6])
    return {"name": f"npm dependency name(s) similar to a popular package: {len(hits)} (advisory)",
            "severity": "INFO",
            "cwe": "CWE-427", "owasp": "A06:2021",
            "evidence": f"These declared dependencies are Damerau-distance 1 from a popular package but "
                        f"DO resolve on the public npm registry, so they are real published packages "
                        f"(legitimate fork / scoped variant / similarly named project): {sample}. "
                        f"Informational only — no typosquat/confusion primitive was confirmed.",
            "remediation": "Confirm each is the package you intended; if so, no action is required. "
                           "Pin exact versions + integrity hashes regardless."}


def rule_clean(s):
    if s.get("npmtypo_no_input") or s.get("npmtypo_no_manifest") or s.get("npmtypo_list_missing"):
        return None
    if s.get("npmtypo_client_missing"):
        return None
    if (s.get("npmtypo_declared_count") or 0) <= 0:
        return None
    # Suppress POSITIVE if any near-miss surfaced (confirmed, resolving, or
    # unknown) — those carry their own MEDIUM/INFO finding.
    if (s.get("npmtypo_candidates") or s.get("npmtypo_resolving_near_misses")
            or s.get("npmtypo_unknown_near_misses")):
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
    rule_typo_resolving,
    rule_clean,
]

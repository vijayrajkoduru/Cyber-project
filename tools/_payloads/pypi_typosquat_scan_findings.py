"""pypi_typosquat_scan - findings rules (playbook §3 #32).

A declared dependency whose name is edit-distance 1 from a popular package
(but is not itself that package) is a classic typosquat vector. Severity:
  - candidate name EXISTS on PyPI as a different package -> HIGH (live squat)
  - candidate name does NOT resolve (404)               -> LOW  (likely a typo,
                                                                  or not yet
                                                                  registered)
Driven by exact edit-distance + a curated popular-name list -> zero FP class
(only flags genuine near-misses, never exact popular names).
"""


def rule_no_input(s):
    if not s.get("typo_no_input"):
        return None
    return {"name": "pypi_typosquat_scan: repo_url or local path required",
            "severity": "INFO",
            "evidence": "Needs a source tree containing requirements.txt / pyproject to read declared deps.",
            "remediation": "Re-run with repo_url=<repo> or target=<local dir>.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_no_requirements(s):
    if not s.get("typo_no_requirements"):
        return None
    return {"name": "No Python dependency manifest found",
            "severity": "INFO",
            "evidence": "No requirements*.txt / pyproject.toml / setup.py with declared dependencies was found.",
            "remediation": "Pin Python deps in requirements.txt or pyproject for auditability.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_live_squat(s):
    hits = [h for h in (s.get("typo_candidates") or []) if h.get("exists_on_pypi")]
    if not hits:
        return None
    sample = "; ".join(f"'{h['declared']}' ~ '{h['near']}'" for h in hits[:6])
    return {"name": f"Possible PyPI typosquat dependency: {len(hits)} package(s)",
            "severity": "HIGH", "cvss": "8.1",
            "cwe": "CWE-427", "owasp": "A06:2021",
            "evidence": f"Declared dependencies are edit-distance 1 from popular packages and EXIST on "
                        f"PyPI as separate projects (live squat risk): {sample}",
            "remediation": ("Verify each flagged package is the one you intended. Replace typosquats with "
                            "the correct package name, pin exact versions + hashes (pip --require-hashes), "
                            "and enable a private-index/allowlist to block unknown names.")}


def rule_typo(s):
    hits = [h for h in (s.get("typo_candidates") or []) if not h.get("exists_on_pypi")]
    if not hits:
        return None
    sample = "; ".join(f"'{h['declared']}' ~ '{h['near']}'" for h in hits[:6])
    return {"name": f"Likely dependency typo / unregistered name: {len(hits)} package(s)",
            "severity": "LOW", "cvss": "0.0",
            "cwe": "CWE-427", "owasp": "A06:2021",
            "evidence": f"Declared names are 1 character off a popular package but did not resolve on "
                        f"PyPI: {sample}. Either a typo, or a name an attacker could register (squat-ready).",
            "remediation": "Correct the spelling, or pre-register internal names to prevent future squatting."}


def rule_clean(s):
    if s.get("typo_no_input") or s.get("typo_no_requirements"):
        return None
    if (s.get("typo_declared_count") or 0) <= 0:
        return None
    if s.get("typo_candidates"):
        return None
    n = s.get("typo_declared_count") or 0
    return {"name": "No PyPI typosquat candidates among declared dependencies",
            "severity": "POSITIVE",
            "evidence": f"All {n} declared dependency name(s) are either exact popular packages or not "
                        f"near-misses of one.",
            "remediation": "Keep pinning exact versions + hashes; add a name allowlist for defence in depth.",
            "cwe": "N/A", "owasp": "N/A"}


PYPI_TYPOSQUAT_SCAN_FINDING_RULES = [
    rule_no_input,
    rule_no_requirements,
    rule_live_squat,
    rule_typo,
    rule_clean,
]

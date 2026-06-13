"""transitive_dependency_depth - findings rules (playbook §2 #28).

A risk-surface metric, not a vulnerability. Deep / heavily-transitive
dependency trees mean most installed code is never directly chosen by the
developer, which is exactly where dependency-confusion and typosquatting
hide. All findings are INFO/LOW (advisory), driven by pure counts -> zero FP.
"""


def rule_no_input(s):
    if not s.get("depth_no_input"):
        return None
    return {"name": "transitive_dependency_depth: repo_url or local path required",
            "severity": "INFO",
            "evidence": "Needs a source tree with a committed lockfile to compute the dependency graph.",
            "remediation": "Re-run with repo_url=<repo> or target=<local dir>.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_no_lockfile(s):
    if not s.get("depth_no_lockfile"):
        return None
    return {"name": "No recognised lockfile found",
            "severity": "INFO",
            "evidence": "No package-lock.json / yarn.lock / go.mod / Gemfile.lock / poetry.lock / "
                        "Cargo.lock was found, so the transitive graph cannot be computed.",
            "remediation": "Commit a lockfile so the full (incl. transitive) dependency set is auditable.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_high_ratio(s):
    direct = s.get("depth_direct") or 0
    transitive = s.get("depth_transitive") or 0
    if direct <= 0 or transitive <= 0:
        return None
    ratio = transitive / direct
    if ratio < 10:
        return None
    return {"name": f"Large transitive footprint: {transitive} transitive vs {direct} direct ({ratio:.0f}x)",
            "severity": "LOW", "cvss": "0.0",
            "cwe": "CWE-1357", "owasp": "A06:2021",
            "evidence": f"{transitive} indirect dependencies are pulled in by only {direct} directly-chosen "
                        f"packages ({ratio:.0f}x). Most installed code is never directly vetted.",
            "remediation": ("Audit transitive packages with `npm ls` / `go mod graph` / `cargo tree`. "
                            "Pin and review high-fan-in transitive deps; enable lockfile-integrity checks in CI.")}


def rule_deep_tree(s):
    depth = s.get("depth_max_nesting") or 0
    if depth < 7:
        return None
    return {"name": f"Deep dependency nesting: {depth} levels",
            "severity": "INFO", "cvss": "0.0",
            "cwe": "CWE-1357", "owasp": "A06:2021",
            "evidence": f"The dependency tree nests {depth} levels deep. Deep chains slow patch "
                        f"propagation and obscure provenance.",
            "remediation": "Flatten/de-duplicate where possible; track deep chains in your SBOM."}


def rule_summary(s):
    if s.get("depth_no_input") or s.get("depth_no_lockfile"):
        return None
    total = s.get("depth_total") or 0
    if total <= 0:
        return None
    # Only emit the neutral summary when no risk rule already fired.
    direct = s.get("depth_direct") or 0
    transitive = s.get("depth_transitive") or 0
    ratio = (transitive / direct) if direct else 0
    if ratio >= 10 or (s.get("depth_max_nesting") or 0) >= 7:
        return None
    ecos = ", ".join(s.get("depth_ecosystems") or [])
    return {"name": f"Dependency graph: {total} total ({direct} direct, {transitive} transitive)",
            "severity": "POSITIVE",
            "evidence": f"Ecosystems: {ecos}. Transitive footprint is proportionate to direct usage.",
            "remediation": "Keep lockfiles committed and run periodic `npm ls`/`go mod graph` reviews.",
            "cwe": "N/A", "owasp": "N/A"}


TRANSITIVE_DEPENDENCY_DEPTH_FINDING_RULES = [
    rule_no_input,
    rule_no_lockfile,
    rule_high_ratio,
    rule_deep_tree,
    rule_summary,
]

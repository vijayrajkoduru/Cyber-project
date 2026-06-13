"""cargo_audit_scanner - findings rules (playbook §2 #21).

RustSec advisory DB matches against a Cargo.lock. RUSTSEC IDs are curated,
authoritative advisories, so any match is a confirmed vulnerable dependency
(zero false positives). Warnings (unmaintained / yanked) are lower severity.
"""


def rule_no_input(s):
    if not s.get("cargo_no_input"):
        return None
    return {"name": "cargo_audit_scanner: image_ref, repo_url, or local path required",
            "severity": "INFO",
            "evidence": "cargo-audit needs a Rust project (Cargo.lock) via repo_url or local path.",
            "remediation": "Re-run with repo_url=<rust repo> or target=<local dir with Cargo.lock>.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_binary_missing(s):
    err = s.get("cargo_error") or ""
    if "cargo-audit binary not installed" not in err:
        return None
    return {"name": "cargo-audit binary not installed",
            "severity": "INFO",
            "evidence": err,
            "remediation": "Install with `cargo install cargo-audit` or add the binary to the scanner image.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_no_lockfile(s):
    if not s.get("cargo_no_lockfile"):
        return None
    return {"name": "No Cargo.lock found (not a Rust project, or lock not committed)",
            "severity": "INFO",
            "evidence": "cargo-audit requires a committed Cargo.lock. None was found in the target.",
            "remediation": "Commit Cargo.lock for applications (recommended) so dependency versions are auditable.",
            "cwe": "N/A", "owasp": "N/A"}


def rule_vulns(s):
    n = s.get("cargo_vuln_count") or 0
    if n <= 0:
        return None
    top = s.get("cargo_top_vulns") or []
    sample = ", ".join(f"{v['id']} ({v['pkg']})" for v in top[:5])
    return {"name": f"RustSec: {n} vulnerable crate(s)",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-1395", "owasp": "A06:2021",
            "evidence": f"cargo-audit matched {n} RUSTSEC advisory(ies). Top: {sample}",
            "remediation": ("Run `cargo update -p <crate>` to the patched version listed in each "
                            "RUSTSEC advisory (https://rustsec.org/advisories/<ID>). Gate CI with "
                            "`cargo audit --deny warnings`.")}


def rule_unmaintained(s):
    n = s.get("cargo_unmaintained_count") or 0
    if n <= 0:
        return None
    crates = ", ".join(s.get("cargo_unmaintained") or [][:8])
    return {"name": f"RustSec: {n} unmaintained crate(s)",
            "severity": "LOW", "cvss": "0.0",
            "cwe": "CWE-1104", "owasp": "A06:2021",
            "evidence": f"Unmaintained dependencies (no security fixes expected): {crates}",
            "remediation": "Migrate to actively-maintained alternatives before a CVE lands with no fix."}


def rule_yanked(s):
    n = s.get("cargo_yanked_count") or 0
    if n <= 0:
        return None
    return {"name": f"RustSec: {n} yanked crate version(s) in lockfile",
            "severity": "LOW", "cvss": "0.0",
            "cwe": "CWE-1104", "owasp": "A06:2021",
            "evidence": f"{n} locked crate version(s) were yanked from crates.io (pulled by the author).",
            "remediation": "Run `cargo update` to move off yanked versions."}


def rule_clean(s):
    if s.get("cargo_no_input") or s.get("cargo_error") or s.get("cargo_no_lockfile"):
        return None
    if not s.get("cargo_input_value"):
        return None
    if (s.get("cargo_vuln_count") or 0) > 0:
        return None
    deps = s.get("cargo_dependency_count") or 0
    return {"name": "cargo-audit clean (no RustSec advisories)",
            "severity": "POSITIVE",
            "evidence": f"cargo-audit matched 0 RUSTSEC advisories across {deps} locked dependency(ies).",
            "remediation": "Keep `cargo audit` in CI; the RustSec DB updates daily.",
            "cwe": "N/A", "owasp": "N/A"}


CARGO_AUDIT_SCANNER_FINDING_RULES = [
    rule_no_input,
    rule_binary_missing,
    rule_no_lockfile,
    rule_vulns,
    rule_unmaintained,
    rule_yanked,
    rule_clean,
]

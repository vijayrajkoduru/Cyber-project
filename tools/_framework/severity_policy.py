"""Global severity policy — one seam to suppress advisory-style FPs.

The user's pain: scanners that fire LOW/MEDIUM/HIGH on the mere PRESENCE of
a precondition ("HTTP/2 is on -> verify patch", "old wayback -> review for
secrets", "1 MX record -> consider redundancy"). These are RECOMMENDATIONS
dressed up as vulnerabilities. They produce per-target FPs that look like
"the scanner is wrong" but are really "the severity was calibrated for the
precondition, not for demonstrated exploit".

Policy: a finding whose name/evidence reads as ADVISORY language
("verify", "consider", "review", "could be", "may be", "manual audit") is
auto-capped to INFO unless the scanner explicitly stamps `verified_exploit`.

One pass at finding-assembly time. Zero per-scanner changes required for
the cap to apply. Scanners that have actively demonstrated the issue
opt out by setting `verified_exploit: True` on the finding dict.
"""
from __future__ import annotations

# Advisory phrases — case-insensitive substring match against name+evidence.
# Each phrase is a smoking-gun that the finding is "you should look at this"
# rather than "we proved this is exploitable".
_ADVISORY_PHRASES = (
    "verify",
    "verify your",
    "may be",
    "may be reflected",
    "could be",
    "consider",
    "manual audit",
    "manually verify",
    "review for",
    "review your",
    "audit early",
    "review historical",
    "ensure server",
    "ensure patched",
    "add backup",
    "add redundancy",
    "no fallback",
    "verify intentional",
    "suspected",
)

# Severity ranks for the cap. Anything ABOVE INFO gets clamped to INFO when
# advisory language is detected and verified_exploit is not set.
_RANK = {"POSITIVE": -1, "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def is_advisory(name: str, evidence: str) -> bool:
    """True if the finding text reads as an advisory (no demonstrated exploit)."""
    blob = f"{name or ''} {evidence or ''}".lower()
    return any(phrase in blob for phrase in _ADVISORY_PHRASES)


def cap_if_advisory(finding: dict) -> dict:
    """Mutate-and-return: cap severity at INFO if finding is advisory-style
    and the scanner has not stamped `verified_exploit: True`.

    Scanner opt-out: set finding["verified_exploit"] = True when the scanner
    has actively demonstrated the issue (canary echoed back, secret retrieved,
    exposed file served real content, etc.) - the cap will not apply.
    """
    if finding.get("verified_exploit"):
        return finding
    sev = str(finding.get("severity") or "INFO").upper()
    if _RANK.get(sev, 0) <= 0:
        return finding  # already INFO/POSITIVE
    if not is_advisory(finding.get("name", ""), finding.get("evidence", "")):
        return finding
    finding["_original_severity"] = sev
    finding["severity"] = "INFO"
    finding["_policy"] = "advisory-cap"
    if not finding.get("remediation"):
        finding["remediation"] = "Advisory only - manual review recommended."
    return finding


def apply_policy(findings: list) -> list:
    """Apply the cap to every finding in the list. In-place + return."""
    for f in findings:
        if isinstance(f, dict):
            cap_if_advisory(f)
    return findings

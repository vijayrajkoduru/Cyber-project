"""Central severity policy — Phase 1 of the scoring-engine architecture.

ONE place decides severity, so scanners stop hand-rolling keyword->severity and
the grading-bug class (public information graded as a MEDIUM exposure) cannot
recur. A scanner reports an OBSERVATION of a known kind; this module maps it to a
severity by a single, documented rubric (see docs/severity_methodology.md), which
an enterprise buyer's security team can audit.

Rubric:
  POSITIVE  a good / secure configuration was confirmed
  INFO      attack-surface INVENTORY, or advisory-by-design (knowing it != a risk)
  LOW       a hardening gap / weak-but-not-exploitable signal
  MEDIUM    a confirmed exposure that materially AIDS an attacker
  HIGH      a confirmed exposure that ENABLES compromise
  CRITICAL  a confirmed, directly exploitable, high-impact exposure

Usage in a scanner:
    from tools._core import grade
    sev = grade.inventory(n_subdomains, low_at=50)        # INFO, or LOW if large
    wrap_finding(detail, sev, cvss=grade.cvss_for(sev), ...)

    sev = grade.exposure(confirmed=True, impact="enables")  # HIGH
    sev = grade.protective()                                # POSITIVE (a good lock)
"""

ORDER = ["POSITIVE", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

_CVSS = {"CRITICAL": "9.1", "HIGH": "7.5", "MEDIUM": "5.3",
         "LOW": "3.1", "INFO": "0.0", "POSITIVE": "0.0"}

# One notch down — used to cap an UNCONFIRMED (signal-only, not proven) exposure.
_DOWN = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW",
         "LOW": "INFO", "INFO": "INFO", "POSITIVE": "POSITIVE"}

_IMPACT = {"aids": "MEDIUM", "enables": "HIGH", "critical": "CRITICAL"}


def cvss_for(severity: str) -> str:
    """Canonical CVSS band for a severity, so scanners don't hand-pick CVSS either."""
    return _CVSS.get(str(severity).upper(), "0.0")


def inventory(n=None, *, low_at=None) -> str:
    """Attack-surface INVENTORY — subdomains, SANs, crawled URLs, social handles,
    historical IPs, CT-logged names. Knowing it exists is NOT a vulnerability, so
    it is INFO; it becomes LOW only when the surface is large enough to be worth a
    hardening note (n >= low_at). It is NEVER MEDIUM+."""
    if low_at is not None and n is not None and n >= low_at:
        return "LOW"
    return "INFO"


def hardening() -> str:
    """A best-practice gap with no proven exploitability — a missing cookie flag /
    header, a weak-but-present policy, an internal-looking name in a public list, a
    secret-pattern URL that still needs manual confirmation. -> LOW."""
    return "LOW"


def protective() -> str:
    """A confirmed GOOD / defensive configuration — a registrar lock, a present
    hardening header, a strict policy enforced, no exposure found. -> POSITIVE."""
    return "POSITIVE"


def advisory() -> str:
    """Advisory-by-design — not detectable from an external SaaS probe, or it needs
    credentials / an input that was not supplied. Reported for awareness, never
    graded as a gap. -> INFO."""
    return "INFO"


def info() -> str:
    """A benign / expected observation that ran fine and revealed nothing risky
    (e.g. GeoDNS variance, a probe summary). -> INFO."""
    return "INFO"


def exposure(*, confirmed: bool, impact: str = "aids") -> str:
    """A real exposure.
      impact='aids'     -> MEDIUM   (materially helps an attacker)
      impact='enables'  -> HIGH     (enables compromise)
      impact='critical' -> CRITICAL (directly exploitable, high impact)
    An UNCONFIRMED observation (a signal, not proof) is capped one level down,
    enforcing 'prove, don't guess'."""
    sev = _IMPACT.get(impact, "MEDIUM")
    if not confirmed:
        sev = _DOWN[sev]
    return sev


def worst(*severities: str) -> str:
    """Highest severity among those given (for a module headline / risk band)."""
    idx = max((ORDER.index(s.upper()) for s in severities
               if s and s.upper() in ORDER), default=0)
    return ORDER[idx]

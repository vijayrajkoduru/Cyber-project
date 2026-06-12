"""ad_offensive_advisory - findings rules (advisory-by-design coverage map).

VulnusLab is a Vulnerability Assessment (VA) product, not a Penetration Test
(PT) framework. A large fraction of the AD playbook (module_playbooks/19_ad.md)
consists of techniques that, by design, CANNOT be safely or honestly checked
from an external SaaS scanner against a live target because they require one of:
  - valid domain credentials / a post-compromise foothold,
  - on-host or local code execution,
  - LAN adjacency (broadcast/multicast poisoning, IPv6 mitm),
  - active exploitation (forging tickets, relaying, coercion), or
  - actions that would be destructive (Zerologon resets the DC machine account).

These are emitted here as honest INFO advisories carrying an
[ADVISORY-BY-DESIGN] marker and vulnerable:false. They are NEVER graded
(no CRITICAL/HIGH/MEDIUM/LOW) because nothing was detected on the target —
this is the explicit fix for the "fake CRITICALs" failure mode.

Each rule reads `state["ad_advisory_catalogue"]` (a static list) and renders
one INFO per advisory technique group.
"""


def _advisory(item):
    title = item["title"]
    return {
        "name": f"[ADVISORY-BY-DESIGN] {title}",
        "severity": "INFO",
        "cvss": "0.0",
        "cwe": item.get("cwe", "CWE-1395"),
        "owasp": "N/A",
        "evidence": ("Advisory-by-design (NOT a forge gap). " + item.get("reason", "") +
                     " No live external probe can prove this condition without crossing the "
                     "VA->PT line; nothing was detected on the target."),
        "remediation": item.get("remediation", "See module_playbooks/19_ad.md for the manual / "
                                                "red-team procedure and the corresponding hardening."),
    }


def build_rules(catalogue):
    """Return a list of rule functions, one per advisory item, each closed
    over its catalogue entry. Every rule returns an INFO finding (or None if
    the catalogue was empty)."""
    rules = []
    for item in catalogue:
        def _mk(it):
            def _rule(s):
                if not s.get("ad_advisory_emit"):
                    return None
                return _advisory(it)
            return _rule
        rules.append(_mk(item))
    return rules

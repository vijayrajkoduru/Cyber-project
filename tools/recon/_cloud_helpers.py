"""_cloud_helpers — common name permutations + HTTP probes for §6 Cloud Asset Discovery.

ZERO-FP-V1 (2026-06-06): bucket candidate generation now uses the apex-domain
org name (e.g. 'vulnuslab' from 'app.vulnuslab.com') rather than the leftmost
label ('app'). The old behavior produced FPs like 'app-public', 'app-assets'
which collide with thousands of unrelated orgs' real public buckets.
"""
from tools.recon._targeting import get_org_name, can_do_osint

# Brand names too short/generic to safely permute into bucket names.
_GENERIC = frozenset({
    "app","api","www","web","dev","staging","test","demo","admin",
    "portal","site","shop","blog","mail","cdn","static","assets",
    "main","home","index","data","prod",
})


def bucket_candidates(domain):
    """Return bucket-name permutations for the customer's brand.

    Returns [] when:
      - target is an IP / internal hostname (no brand)
      - extracted brand is generic ('app', 'api', etc.)
      - brand is too short (< 4 chars) to safely permute
    """
    if not can_do_osint(domain):
        return []
    base = (get_org_name(domain) or "").lower()
    if not base or base in _GENERIC or len(base) < 4:
        return []
    suffixes = ["", "-backup", "-backups", "-prod", "-production", "-dev", "-staging",
                "-test", "-assets", "-static", "-uploads", "-media", "-data", "-logs",
                "-archive", "-private", "-public", "-www", "-api", "-cdn"]
    out = []
    for s in suffixes:
        out.append(f"{base}{s}")
        if s:
            out.append(f"{s.lstrip('-')}-{base}")
    return [b for b in out if b]

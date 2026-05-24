"""email_patterns — 30 common org email format patterns + extraction regex.

Generated 2026-05-24 — handcrafted from public format-research corpora
(Hunter.io blog stats + Lewis-Tylock 2024 patterns analysis).
Refresh cadence: quarterly.

EMAIL_PATTERNS feeds the harvester scanner — given a name, generate likely
work email addresses to check against breach databases / gravatar.

EMAIL_REGEX is the boundary-safe extractor used on all scraped HTML.
"""

# Canonical 30 most-common corporate email patterns (rank-ordered by frequency)
EMAIL_PATTERNS = [
    "{first}.{last}@{domain}",        # john.doe@acme.com — 35% of orgs
    "{first}@{domain}",               # john@acme.com — 14%
    "{f}{last}@{domain}",             # jdoe@acme.com — 12%
    "{first}{last}@{domain}",         # johndoe@acme.com — 8%
    "{last}.{first}@{domain}",        # doe.john@acme.com — 5%
    "{first}_{last}@{domain}",        # john_doe@acme.com — 4%
    "{first}-{last}@{domain}",        # john-doe@acme.com — 3%
    "{last}{f}@{domain}",             # doej@acme.com — 3%
    "{f}.{last}@{domain}",            # j.doe@acme.com — 3%
    "{last}@{domain}",                # doe@acme.com — 2%
    # Less common variants
    "{first}.{l}@{domain}",
    "{first}{l}@{domain}",
    "{f}_{last}@{domain}",
    "{f}-{last}@{domain}",
    "{f}{l}@{domain}",
    "{last}.{f}@{domain}",
    "{last}_{first}@{domain}",
    "{last}-{first}@{domain}",
    # Role-based addresses (always worth checking — most leaked)
    "info@{domain}",
    "admin@{domain}",
    "contact@{domain}",
    "support@{domain}",
    "sales@{domain}",
    "hr@{domain}",
    "careers@{domain}",
    "security@{domain}",
    "abuse@{domain}",
    "postmaster@{domain}",
    "webmaster@{domain}",
    "no-reply@{domain}",
]

# Boundary-safe email extraction regex.
# - Lookbehind/lookahead anchors avoid matching inside strings like
#   "foo@bar.com.example" (the regex engine grabs "foo@bar.com")
# - Allows + and . in local part; standard RFC 5322 simplified
EMAIL_REGEX = (
    r"(?<![\w.+-])"
    r"[a-zA-Z0-9_.+-]+"
    r"@"
    r"[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+"
    r"(?![\w.])"
)


def expand(first: str, last: str, domain: str) -> list[str]:
    """Generate every plausible email for a (first, last, domain) triple.

    Returns a deduped list, lowercased.
    """
    if not first or not domain:
        return []
    out = set()
    ctx = {
        "first": first.lower(), "last": (last or "").lower(),
        "f": first[:1].lower(), "l": (last or "")[:1].lower(),
        "domain": domain.lower(),
    }
    for pat in EMAIL_PATTERNS:
        try:
            out.add(pat.format(**ctx))
        except (KeyError, IndexError):
            continue
    return sorted(out)

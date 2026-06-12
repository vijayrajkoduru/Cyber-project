"""tier3_advisory — honest advisory-by-design coverage for the playbook's
post-compromise / payload-craft / red-team-infrastructure techniques.

These techniques (BeEF hook hosting, Office-macro / HTA / LNK payload
generation, browser 0-day / CVE exploitation, phishing-infra: GoPhish /
EvilGinx2 / SET, BitB, AiTM MFA bypass, manual analyst craft) CANNOT be
detected from an external SaaS VA scan — they require operator-side
payload delivery, victim execution, or red-team infrastructure. They are
emitted as INFO [ADVISORY-BY-DESIGN] findings so the customer sees the
technique is intentionally informational, NOT a forge gap, and never as a
fabricated CRITICAL/HIGH.
"""

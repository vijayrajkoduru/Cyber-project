"""tier3_c2_infra - REAL external exposure detection for adversary / C2
infrastructure (playbook §4 C2 Frameworks + §5 Initial-Access infra + §6
Detection-Engineering tooling exposure).

These scanners issue ONLY read-only, unauthenticated HTTP GET/HEAD requests
(and a TLS handshake inspection) against the customer-supplied target to
answer one safe question: is a known C2 framework's listener / team-server /
operator console, an attacker redirector default page, a phishing-kit admin
panel, or a detection console (SIEM/EDR) UNINTENTIONALLY exposed on the
public surface?

A graded finding is emitted ONLY when a UNIQUE framework/product signature is
actually observed on the target. No prompts, no payloads, no exploitation, no
default-credential attempts, no mutating verbs — VA, not PT. Everything
degrades safely on error to a clean INFO/POSITIVE.
"""

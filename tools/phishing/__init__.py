"""phishing module - Phishing-LITE: email security posture +
template + landing-page-clone audit
(per module_playbooks/26_phishing.md).

7 sections / 70 techniques in the full catalogue; this LITE starter
focuses on the safe, customer-self-service surface that requires no
actual outbound email or attacker infrastructure (no GoPhish, no
EvilGinx2, no SET — those are P1 follow-ons that need infra setup).

Probes shipped (5):

  - tier1_posture (email security posture for the target domain):
        spf_dkim_dmarc_audit   (DNS TXT records for SPF / DMARC / DKIM)
        lookalike_domain_scan  (typosquat + homoglyph + TLD-swap A-records)
        mailbox_security_audit (STARTTLS + cipher + cert on MX host)

  - tier2_simulation (artifact generation — NO sending, NO deployment):
        phishing_template_generate    (HTML email template with placeholders)
        landing_page_clone_test       (HTML clone of customer's login page)

Customer input via ScanRequest.target = customer email domain (e.g.
acme.com). Per-probe extras live in ScanRequest.options (dict). All
heavy artifacts (template HTML, cloned landing-page HTML) are returned
in the standard_response as INFO findings — VulnusLab never sends an
email or hosts a clone on behalf of the customer.

Backend dependencies (image-installed):
  - dnspython, httpx, requests, beautifulsoup4

All probes degrade gracefully on missing customer input / missing
library / unreachable target (return INFO with install hint instead
of crashing).
"""

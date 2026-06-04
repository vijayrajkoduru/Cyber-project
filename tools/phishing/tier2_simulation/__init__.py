"""tier2_simulation - Phishing artifact generation (NO sending / NO deployment).

Covers:
  - phishing_template_generate (HTML email template with %TARGET_DOMAIN% /
                                %SENDER_DOMAIN% / %CALLBACK_URL% placeholders)
  - landing_page_clone_test    (HTML clone of a customer's login page —
                                returned as text artifact only)

Both probes are read-only: they generate a string the customer can use
in their own controlled, authorized phishing simulation infrastructure.
VulnusLab never sends an email or hosts a clone on behalf of the
customer.
"""

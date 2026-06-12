"""tier2_simulation - Login-page surface probes + inert artifact generation
(NO sending / NO deployment / NO exploitation).

Covers:
  - phishing_template_generate (HTML email template with %TARGET_DOMAIN% /
                                %SENDER_DOMAIN% / %CALLBACK_URL% placeholders)
  - landing_page_clone_test    (structural HTML clone of a customer's login
                                page — returned as text artifact only)
  - bitb_frameability_check    (REAL: reads X-Frame-Options / CSP
                                frame-ancestors on the login page to detect
                                Browser-in-the-Browser / clickjacking surface)
  - open_redirect_probe        (REAL: tests a customer-supplied redirect URL
                                with a non-routable .invalid canary and reads
                                the 3xx Location — confirms off-site redirect
                                capability without following it)

The artifact probes are read-only string generators for the customer's own
authorized simulation infra. The two detection probes only inspect response
headers / a single 3xx Location — they exploit nothing and chain nowhere.
VulnusLab never sends an email or hosts a clone on behalf of the customer.
"""

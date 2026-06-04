"""tier2_flow - OAuth + session flow attacks.

Probes target the multi-step auth flows where state is passed between
parties (browser <-> IdP <-> RP):
  - oauth_redirect_audit:  redirect_uri validation bypass (subdomain takeover,
                           open-redirect chain, path traversal, userinfo bypass)
  - session_fixation_test: session ID not regenerated after authentication
"""

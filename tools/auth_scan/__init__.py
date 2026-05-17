"""auth_scan -- helpers that let scanners authenticate to customer targets.

Distinct from tools/auth/ which is the VulnusLab app's own user auth.
This package is about logging the SCANNER into the CUSTOMER's web app so
that downstream scanners (XSS, IDOR, priv-esc, etc.) can hit post-login
attack surface.
"""

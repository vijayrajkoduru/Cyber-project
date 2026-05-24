# VL-FOUNDRY Layer 9 — Compliance Mapping

Concrete finding → compliance-control mapping. Auditors need the exact
wording. This file is the single source of truth.

The PDF "Compliance Coverage" section automatically pulls from this mapping
based on finding `cwe` + `owasp` fields.

---

## Frameworks covered

| Framework | Version | Scope |
|---|---|---|
| **PCI-DSS** | v4.0 | Payment card industry |
| **SOC 2** | 2017 + 2024 Trust Services Criteria | Service-org controls |
| **ISO 27001** | 2022 | Information security management |
| **HIPAA Security Rule** | 45 CFR 164.308/312 | Healthcare PHI |
| **GDPR** | 2018 | EU personal data |
| **NIST 800-53** | Rev 5 | US federal controls |
| **NIST CSF** | 2.0 | Cybersecurity framework |
| **CIS Controls** | v8 | Critical Security Controls |

---

## Module → Primary controls

### Recon module → satisfies discovery/inventory requirements

| Control | Framework | What our scan provides |
|---|---|---|
| 2.4 | PCI-DSS v4.0 | Asset inventory (subdomains + IPs discovered) |
| A.5.9 | ISO 27001 | Asset register (resolved IPs + tech stack) |
| CC7.1 | SOC 2 | Detection of unauthorized changes (via cert transparency monitoring) |
| ID.AM-1 | NIST CSF | Hardware/software inventory |
| CIS 1.1 | CIS v8 | Detailed enterprise asset inventory |

### Vuln module → satisfies vulnerability management requirements

| Control | Framework | What our scan provides |
|---|---|---|
| 11.2.1 | PCI-DSS | Internal vulnerability scan (quarterly minimum) |
| 11.2.2 | PCI-DSS | External vulnerability scan (quarterly by ASV) |
| 11.2.3 | PCI-DSS | Rescan after significant change |
| 6.3.3 | PCI-DSS | Identify and patch security vulnerabilities |
| A.8.8 | ISO 27001 | Management of technical vulnerabilities |
| CC7.1 | SOC 2 | Vulnerability detection in production systems |
| RA-5 | NIST 800-53 | Vulnerability monitoring and scanning |
| SI-2 | NIST 800-53 | Flaw remediation |
| 164.308(a)(1)(ii)(A) | HIPAA | Risk analysis (technical vulnerabilities) |
| CIS 7.1, 7.3 | CIS v8 | Vulnerability management process |

### Webapp module → satisfies secure development testing

| Control | Framework | What our scan provides |
|---|---|---|
| 6.5 | PCI-DSS | Common coding vulnerabilities testing |
| 6.5.1 | PCI-DSS | Injection flaws (SQLi, OSCi, LDAPi, NoSQLi) |
| 6.5.7 | PCI-DSS | Cross-site scripting (XSS) |
| 6.5.8 | PCI-DSS | Improper access control |
| 6.5.10 | PCI-DSS | Broken authentication |
| 11.3.1 | PCI-DSS | Internal penetration testing |
| 11.3.2 | PCI-DSS | External penetration testing |
| A.8.28 | ISO 27001 | Secure coding |
| A.14.2.8 | ISO 27001 | System security testing |
| CC8.1 | SOC 2 | Change management (deployment-time testing) |
| SA-11 | NIST 800-53 | Developer security testing |
| 164.312(e)(1) | HIPAA | Transmission security (TLS scanning) |

---

## Finding-class → Control map (used by PDF generator)

The PDF "Compliance Coverage" section maps each finding to controls via
this dict. Generated automatically — keep this file in sync.

```python
# CWE → list of (framework, control_id, severity_threshold)
COMPLIANCE_MAP = {
    "CWE-79": [   # XSS
        ("PCI-DSS", "6.5.7", "HIGH"),
        ("ISO 27001", "A.8.28", "MEDIUM"),
        ("OWASP", "A03:2021", "ANY"),
    ],
    "CWE-89": [   # SQL Injection
        ("PCI-DSS", "6.5.1", "ANY"),
        ("ISO 27001", "A.8.28", "ANY"),
        ("OWASP", "A03:2021", "ANY"),
    ],
    "CWE-22": [   # Path Traversal
        ("PCI-DSS", "6.5.8", "MEDIUM"),
        ("OWASP", "A01:2021", "ANY"),
    ],
    "CWE-78": [   # Command Injection
        ("PCI-DSS", "6.5.1", "ANY"),
        ("OWASP", "A03:2021", "ANY"),
    ],
    "CWE-352": [  # CSRF
        ("PCI-DSS", "6.5.9", "MEDIUM"),
        ("OWASP", "A01:2021", "ANY"),
    ],
    "CWE-326": [  # Weak Crypto (SSLv3 / weak ciphers / weak JWT)
        ("PCI-DSS", "4.2.1", "HIGH"),
        ("ISO 27001", "A.8.24", "MEDIUM"),
        ("HIPAA", "164.312(e)(1)", "HIGH"),
    ],
    "CWE-200": [  # Information Disclosure
        ("PCI-DSS", "3.4.1", "LOW"),
        ("GDPR", "Art. 32", "MEDIUM"),
    ],
    "CWE-538": [  # Sensitive file exposure (.env, .git, etc.)
        ("PCI-DSS", "3.4.1", "HIGH"),
        ("ISO 27001", "A.8.10", "HIGH"),
    ],
    "CWE-693": [  # Missing security headers
        ("PCI-DSS", "6.5.7", "MEDIUM"),
        ("OWASP", "A05:2021", "ANY"),
    ],
    "CWE-1004": [ # Missing HttpOnly cookie
        ("PCI-DSS", "6.5.10", "MEDIUM"),
    ],
    "CWE-614": [  # Missing Secure cookie flag
        ("PCI-DSS", "4.2.1", "MEDIUM"),
    ],
    "CWE-345": [  # JWT alg=none
        ("PCI-DSS", "6.5.10", "CRITICAL"),
        ("OWASP", "A02:2021", "ANY"),
    ],
    "CWE-918": [  # SSRF
        ("OWASP", "A10:2021", "ANY"),
    ],
    "CWE-611": [  # XXE
        ("OWASP", "A05:2021", "ANY"),
    ],
    "CWE-306": [  # Missing auth (DB exposure etc)
        ("PCI-DSS", "8.2", "CRITICAL"),
        ("HIPAA", "164.308(a)(3)", "CRITICAL"),
    ],
    "CWE-285": [  # Improper auth (fresh domain phishing risk)
        ("OWASP", "A07:2021", "MEDIUM"),
    ],
    "CWE-345-ssl": [  # DNSSEC missing
        ("PCI-DSS", "4.2.1", "MEDIUM"),
    ],
    "CWE-290": [  # DMARC/SPF/DKIM missing
        ("ISO 27001", "A.8.23", "MEDIUM"),
    ],
}
```

---

## Auditor-friendly artifacts the PDF generates

Per finding, the PDF includes:

```
Finding: SQL Injection at /api/users
Severity: HIGH
CVSS: 9.8
CWE: CWE-89
OWASP: A03:2021 - Injection

Compliance impact:
  ✓ PCI-DSS 6.5.1 — Injection flaws (REMEDIATE BEFORE NEXT QSA)
  ✓ ISO 27001 A.8.28 — Secure coding violation
  ✓ OWASP Top 10 — A03:2021

Auditor evidence:
  • Scan ID: VL-20260524-A1B2C3
  • Scanner: webapp/sqli
  • Probe sent: GET /api/users?id=1%27%20OR%20%271%27%3D%271
  • Response indicator: SQL error in body (line 47 of vendor/db.py)
  • Confidence: HIGH (replayed 3 times, consistent timing)

Remediation evidence required to close:
  1. Code change in commit (link)
  2. Re-scan with VL-FOUNDRY showing CLEAN (this finding gone)
  3. Date of remediation
```

This is **exactly** the artifact a SOC2 / PCI auditor accepts.

---

## SOC 2 evidence pack (Enterprise tier feature)

For Enterprise customers, the PDF additionally generates:

- **CSV export** of all findings with timestamps
- **Trend report** (findings opened / closed per month)
- **Remediation tracker** (with assignee + due date fields)
- **Audit log** (every scan-target / scanner / finding)
- **Re-scan delta** (what's new since last scan)

Filename pattern: `<scan_id>-SOC2-evidence.zip`

---

## How to add a new framework

1. Add it to the table at top of this file
2. Add CWE entries to `COMPLIANCE_MAP` in this file
3. Update `src/App.js::COMPLIANCE_FRAMEWORKS` dict
4. Re-test PDF generation
5. Have a customer's auditor review (the real test)

Don't add a framework you can't reliably map at least 5 findings to —
that signals "we don't actually support it."

"""cert_intelligence — generated dev-time by Claude. Recon module asset.
"""

CERT_INTELLIGENCE = [
  {
    "check_name": "MD5 Signature Algorithm Detected",
    "category": "algorithm",
    "detection": "Parse certificate and check signatureAlgorithm OID for md5WithRSAEncryption (1.2.840.113549.1.1.4)",
    "severity": "CRITICAL",
    "cvss": "9.1",
    "remediation": "Immediately reissue certificate using SHA-256 or stronger signature algorithm"
  },
  {
    "check_name": "SHA-1 Signature Algorithm Detected",
    "category": "algorithm",
    "detection": "Parse certificate signatureAlgorithm field and flag any OID matching sha1WithRSAEncryption (1.2.840.113549.1.1.5)",
    "severity": "HIGH",
    "cvss": "7.5",
    "remediation": "Reissue certificate using SHA-256 (sha256WithRSAEncryption) or SHA-384 minimum"
  },
  {
    "check_name": "RSA Key Size Below 2048 Bits",
    "category": "key_size",
    "detection": "Extract RSA public key modulus bit length from certificate SubjectPublicKeyInfo and flag if less than 2048",
    "severity": "CRITICAL",
    "cvss": "9.1",
    "remediation": "Generate a new RSA key pair with minimum 2048-bit modulus, preferably 4096-bit for long-lived certs"
  },
  {
    "check_name": "EC Key Size Below 256 Bits",
    "category": "key_size",
    "detection": "Extract EC public key curve OID from SubjectPublicKeyInfo and verify curve order is at least 256 bits",
    "severity": "HIGH",
    "cvss": "7.4",
    "remediation": "Reissue certificate using P-256, P-384, or P-521 NIST curve (minimum 256-bit EC key)"
  },
  {
    "check_name": "RSA Key Size Below 1024 Bits",
    "category": "key_size",
    "detection": "Extract RSA modulus length from SubjectPublicKeyInfo and flag any key with modulus bits strictly less than 1024",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "remediation": "Immediately replace with minimum 2048-bit RSA key or EC P-256 equivalent as emergency priority"
  },
  {
    "check_name": "Certificate Already Expired",
    "category": "validity",
    "detection": "Compare certificate notAfter field against current UTC timestamp and flag if notAfter is in the past",
    "severity": "CRITICAL",
    "cvss": "9.1",
    "remediation": "Renew certificate immediately and implement automated renewal monitoring with alerting"
  },
  {
    "check_name": "Certificate Expiring Within 14 Days",
    "category": "validity",
    "detection": "Calculate days remaining by subtracting current UTC time from certificate notAfter and flag if result is 14 or fewer days",
    "severity": "HIGH",
    "cvss": "7.5",
    "remediation": "Renew certificate immediately and configure automated renewal at 30-day threshold using ACME or similar"
  },
  {
    "check_name": "Certificate Expiring Within 30 Days",
    "category": "validity",
    "detection": "Calculate days until certificate notAfter expiry and flag if result is between 15 and 30 days",
    "severity": "MEDIUM",
    "cvss": "5.3",
    "remediation": "Initiate certificate renewal process and ensure automated monitoring alerts fire at 30-day mark"
  },
  {
    "check_name": "Suspiciously Short Certificate Validity Period",
    "category": "validity",
    "detection": "Calculate total certificate validity window (notAfter minus notBefore) and flag if total lifespan is less than 30 days without ACME justification",
    "severity": "MEDIUM",
    "cvss": "4.3",
    "remediation": "Investigate certificate issuance process; ensure validity period aligns with CA policy and operational requirements"
  },
  {
    "check_name": "Self-Signed Certificate in Production",
    "category": "ca",
    "detection": "Compare certificate Subject and Issuer DN fields; if identical and no trusted CA chain exists, classify as self-signed",
    "severity": "HIGH",
    "cvss": "7.4",
    "remediation": "Replace self-signed certificate with one issued by a publicly trusted CA for all production-facing endpoints"
  },
  {
    "check_name": "Deprecated Symantec-Issued Certificate",
    "category": "ca",
    "detection": "Inspect certificate Issuer DN and AIA extension for Symantec, GeoTrust, RapidSSL, Thawte, or VeriSign root lineage issued before 2018",
    "severity": "HIGH",
    "cvss": "7.5",
    "remediation": "Reissue certificate from a currently trusted CA as Symantec roots were distrust by major browsers in 2018"
  },
  {
    "check_name": "Unknown or Untrusted CA Issuer",
    "category": "ca",
    "detection": "Validate certificate chain against Mozilla, Apple, Microsoft, and Google trusted root stores and flag any issuer not present",
    "severity": "HIGH",
    "cvss": "7.4",
    "remediation": "Replace certificate with one issued by a CA present in all major browser and OS trusted root stores"
  },
  {
    "check_name": "Missing OCSP Stapling",
    "category": "chain",
    "detection": "Perform TLS handshake with status_request extension (RFC 6066) and verify server returns a valid OCSP response in CertificateStatus message",
    "severity": "MEDIUM",
    "cvss": "4.3",
    "remediation": "Enable OCSP stapling on the web server (ssl_stapling on in Nginx; SSLUseStapling On in Apache)"
  },
  {
    "check_name": "Missing TLS Must-Staple Extension",
    "category": "chain",
    "detection": "Check certificate TLS Feature extension (OID 1.3.6.1.5.5.7.1.24) for status_request (value 5) indicating must-staple requirement",
    "severity": "LOW",
    "cvss": "3.7",
    "remediation": "Request new certificate with TLS Must-Staple extension and ensure OCSP stapling is correctly configured before deploying"
  },
  {
    "check_name": "RC4 Cipher Suite Still Supported",
    "category": "cipher",
    "detection": "Enumerate supported cipher suites via TLS ClientHello scanning and flag any suite containing RC4 (TLS_RSA_WITH_RC4_128_SHA etc.)",
    "severity": "CRITICAL",
    "cvss": "9.1",
    "remediation": "Remove all RC4 cipher suites from server configuration; RC4 is broken and prohibited by RFC 7465"
  },
  {
    "check_name": "3DES (Triple-DES) Cipher Suite Still Supported",
    "category": "cipher",
    "detection": "Scan TLS cipher suite negotiation and flag presence of TLS_RSA_WITH_3DES_EDE_CBC_SHA or any 3DES variant (SWEET32 exposure)",
    "severity": "HIGH",
    "cvss": "7.5",
    "remediation": "Disable 3DES cipher suites to mitigate SWEET32 attack; prohibited in TLS 1.3 and should be removed from all profiles"
  },
  {
    "check_name": "DES Cipher Suite Still Supported",
    "category": "cipher",
    "detection": "Enumerate server cipher suites and flag any DES-based suite (TLS_RSA_WITH_DES_CBC_SHA) with 56-bit key strength",
    "severity": "CRITICAL",
    "cvss": "9.1",
    "remediation": "Immediately remove all single-DES cipher suites from server TLS configuration as DES is cryptographically broken"
  },
  {
    "check_name": "NULL Cipher Suite Accepted",
    "category": "cipher",
    "detection": "Test TLS handshake offering NULL encryption suites (TLS_RSA_WITH_NULL_SHA etc.) and flag if server accepts any NULL cipher",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "remediation": "Remove all NULL cipher suites from server configuration immediately; NULL ciphers provide zero confidentiality protection"
  },
  {
    "check_name": "NULL Authentication Cipher Suite Accepted",
    "category": "cipher",
    "detection": "Offer anonymous DH and NULL authentication cipher suites in ClientHello and flag if server negotiates TLS_DH_anon or similar",
    "severity": "CRITICAL",
    "cvss": "9.1",
    "remediation": "Disable all anonymous and NULL authentication cipher suites to prevent MITM attacks with no server authentication"
  },
  {
    "check_name": "TLS 1.0 Still Enabled",
    "category": "protocol",
    "detection": "Send ClientHello with version field set to TLS 1.0 (0x0301) and flag if server responds with ServerHello accepting TLS 1.0",
    "severity": "HIGH",
    "cvss": "7.4",
    "remediation": "Disable TLS 1.0 in server configuration; PCI-DSS 3.2+ requires TLS 1.0 disabled and only TLS 1.2+ be supported"
  },
  {
    "check_name": "TLS 1.1 Still Enabled",
    "category": "protocol",
    "detection": "Send ClientHello with maximum version TLS 1.1 (0x0302) and flag if server negotiates TLS 1.1 session successfully",
    "severity": "MEDIUM",
    "cvss": "5.9",
    "remediation": "Disable TLS 1.1 and enforce TLS 1.2 minimum; TLS 1.1 deprecated by RFC 8996 and removed by all major browsers"
  },
  {
    "check_name": "SSL 3.0 Still Enabled (POODLE)",
    "category": "protocol",
    "detection": "Send ClientHello with SSL 3.0 version byte (0x0300) and flag if server accepts and completes SSL 3.0 handshake",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "remediation": "Immediately disable SSL 3.0 across all servers; SSL 3.0 is vulnerable to POODLE and deprecated by RFC 7568"
  },
  {
    "check_name": "Missing Forward Secrecy (No ECDHE/DHE)",
    "category": "cipher",
    "detection": "Analyze negotiated cipher suite key exchange and flag if RSA key exchange (non-ephemeral) is used without ECDHE or DHE prefix",
    "severity": "HIGH",
    "cvss": "7.5",
    "remediation": "Prioritize ECDHE and DHE cipher suites in server configuration to ensure perfect forward secrecy for all sessions"
  },
  {
    "check_name": "Weak Diffie-Hellman Parameters Below 2048 Bits",
    "category": "key_size",
    "detection": "During TLS handshake capture ServerKeyExchange message and extract DH prime (p) bit length; flag if less than 2048 bits (Logjam risk)",
    "severity": "HIGH",
    "cvss": "7.4",
    "remediation": "Generate new DH parameters with minimum 2048-bit prime using openssl dhparam 2048 and update server configuration"
  },
  {
    "check_name": "Certificate Common Name Mismatch",
    "category": "sni",
    "detection": "Compare the hostname used in TLS SNI extension and HTTP Host header against certificate CN and all SAN DNS entries",
    "severity": "HIGH",
    "cvss": "7.5",
    "remediation": "Reissue certificate with correct CN and SAN entries that exactly match all hostnames used to access the service"
  },
  {
    "check_name": "Subject Alternative Name (SAN) Extension Missing",
    "category": "sni",
    "detection": "Parse certificate extensions and flag absence of Subject Alternative Name (OID 2.5.29.17) extension required by CA/B BR since 2012",
    "severity": "HIGH",
    "cvss": "7.5",
    "remediation": "Reissue certificate with proper SAN extension listing all valid hostnames; CN-only certs are rejected by modern browsers"
  },
  {
    "check_name": "Common Subdomain Not Listed in SAN",
    "category": "sni",
    "detection": "Enumerate common subdomains (www, mail, api, dev, staging) via DNS and verify each resolves to the server but is absent from certificate SAN",
    "severity": "MEDIUM",
    "cvss": "5.3",
    "remediation": "Reissue certificate with all required subdomains explicitly listed in the SAN extension or use a wildcard appropriately"
  },
  {
    "check_name": "Wildcard Certificate on High-Value Domain",
    "category": "sni",
    "detection": "Detect wildcard character (*) in certificate SAN DNS entries and flag if used on root or high-value domains with many subdomains",
    "severity": "MEDIUM",
    "cvss": "6.5",
    "remediation": "Replace broad wildcard certificates with specific multi-SAN certificates to limit blast radius if private key is compromised"
  },
  {
    "check_name": "Wildcard Certificate Covering Multiple Subdomains Levels",
    "category": "sni",
    "detection": "Check if wildcard SAN (e.g., *.example.com) is being reused across many unrelated services sharing the same private key",
    "severity": "MEDIUM",
    "cvss": "5.9",
    "remediation": "Issue service-specific certificates to reduce key sharing risk; rotate wildcard if private key exposure is suspected"
  },
  {
    "check_name": "Certificate Not Present in CT Logs",
    "category": "ca",
    "detection": "Query Certificate Transparency log APIs (crt.sh, Google Transparency Report) for certificate fingerprint and flag if no matching SCT is found",
    "severity": "MEDIUM",
    "cvss": "5.3",
    "remediation": "Ensure CA submits certificate to at least two CT logs and that SCT list extension is embedded in certificate per Chrome policy"
  },
  {
    "check_name": "Missing Signed Certificate Timestamp (SCT) Extension",
    "category": "chain",
    "detection": "Parse certificate for SCT List extension (OID 1.3.6.1.4.1.11129.2.4.2) and flag if absent or contains fewer than two SCTs",
    "severity": "MEDIUM",
    "cvss": "4.3",
    "remediation": "Request reissuance from a CA that embeds SCTs from at least two independent CT logs as required by Chrome CT policy"
  },
  {
    "check_name": "Baseline Requirements Violation: Missing CRL or OCSP AIA",
    "category": "chain",
    "detection": "Parse Authority Information Access (AIA) extension (OID 1.3.6.1.5.5.7.1.1) and CRL Distribution Points; flag if both are absent from non-root certs",
    "severity": "HIGH",
    "cvss": "6.5",
    "remediation": "Reissue certificate from a compliant CA ensuring AIA OCSP URL and CRL Distribution Points are properly populated per CA/B BR §7.1.2"
  },
  {
    "check_name": "Baseline Requirements Violation: Validity Exceeds 398 Days",
    "category": "validity",
    "detection": "Calculate certificate validity duration (notAfter minus notBefore in days) and flag if it exceeds 398 days per Apple/Google policy",
    "severity": "HIGH",
    "cvss": "6.5",
    "remediation": "Reissue certificate with maximum 397-day validity; certs exceeding 398 days are distrusted by Safari and Chrome since 2020"
  },
  {
    "check_name": "Certificate Chain Incomplete (Missing Intermediate)",
    "category": "chain",
    "detection": "Verify complete chain construction from end-entity to trusted root during TLS handshake and flag if intermediate CA certificates are not served",
    "severity": "HIGH",
    "cvss": "7.5",
    "remediation": "Configure server to send full certificate chain including all intermediate CA certificates in the TLS handshake"
  },
  {
    "check_name": "Certificate Chain Contains Untrusted Root",
    "category": "chain",
    "detection": "Walk the certificate chain and validate each issuer signature against the next certificate until root; flag if root is absent from OS/browser trust stores",
    "severity": "HIGH",
    "cvss": "7.4",
    "remediation": "Replace certificate with one issued by a CA whose root is present in all major platform trusted root programs"
  },
  {
    "check_name": "EXPORT-Grade Cipher Suite Supported (FREAK)",
    "category": "cipher",
    "detection": "Offer EXPORT cipher suites in ClientHello and flag if server accepts any TLS_RSA_EXPORT or EXP- prefixed cipher (512-bit key limit)",
    "severity": "CRITICAL",
    "cvss": "9.1",
    "remediation": "Remove all EXPORT cipher suites immediately; these 512-bit ciphers are trivially breakable and enable FREAK attacks"
  },
  {
    "check_name": "Private Key Length Mismatch with Security Level",
    "category": "key_size",
    "detection": "Compare RSA key size against certificate validity period and target security level; flag RSA-2048 certs with notAfter beyond 2030 as under-strength",
    "severity": "MEDIUM",
    "cvss": "5.3",
    "remediation": "Use RSA-3072 or RSA-4096 for certificates with long validity periods or migrate to EC P-256/P-384 for equivalent security"
  },
  {
    "check_name": "Certificate Issued with Reserved IP Address or Internal Name",
    "category": "ca",
    "detection": "Check SAN and CN for RFC 1918 IP addresses, .local, .internal, .corp domains or unqualified hostnames prohibited by CA/B BR since Nov 2015",
    "severity": "HIGH",
    "cvss": "6.8",
    "remediation": "Reissue certificate using only publicly resolvable FQDNs; use internal PKI for certificates covering internal-only hostnames"
  },
  {
    "check_name": "OCSP Response Unavailable or Revoked",
    "category": "chain",
    "detection": "Fetch OCSP response from AIA OCSP URL using certificate serial number and issuer hash; flag if response status is revoked or request times out",
    "severity": "CRITICAL",
    "cvss": "9.1",
    "remediation": "Immediately investigate revocation cause; if revoked due to compromise, rotate private key and reissue certificate without delay"
  },
  {
    "check_name": "Weak ECDSA Nonce Reuse Risk (Low Entropy PRNG)",
    "category": "algorithm",
    "detection": "Collect multiple ECDSA signatures from TLS handshakes and test for nonce (k-value) reuse or bias using lattice-based statistical analysis tools",
    "severity": "CRITICAL",
    "cvss": "9.1",
    "remediation": "Ensure server uses RFC 6979 deterministic ECDSA or a cryptographically secure PRNG; update OpenSSL/BoringSSL to a current patched version"
  },
  {
    "check_name": "Certificate Key Usage Extension Mismatch",
    "category": "chain",
    "detection": "Parse Key Usage (OID 2.5.29.15) and Extended Key Usage (OID 2.5.29.37) extensions and flag if server auth EKU is absent or keyEncipherment/digitalSignature bits are misaligned with key type",
    "severity": "MEDIUM",
    "cvss": "5.3",
    "remediation": "Reissue certificate ensuring Key Usage and Extended Key Usage extensions correctly reflect intended purpose per RFC 5280 and CA/B BR"
  }
]

"""cert_intelligence — generated dev-time by Claude. Recon module asset.
"""

CERT_INTELLIGENCE = [{'check_name': 'MD5 Signature Algorithm in Certificate',
  'category': 'algorithm',
  'detection': 'Parse certificate SignatureAlgorithm OID and flag if it equals md5WithRSAEncryption '
               '(1.2.840.113549.1.1.4)',
  'severity': 'CRITICAL',
  'cvss': '9.1',
  'remediation': 'Reissue the certificate using SHA-256 or SHA-384 as the signature hash algorithm immediately'},
 {'check_name': 'SHA-1 Signature Algorithm in Certificate',
  'category': 'algorithm',
  'detection': 'Parse certificate SignatureAlgorithm OID and flag if it equals sha1WithRSAEncryption '
               '(1.2.840.113549.1.1.5)',
  'severity': 'HIGH',
  'cvss': '7.4',
  'remediation': 'Reissue the certificate using SHA-256 or stronger; SHA-1 is deprecated by all major browsers and '
                 'CAs'},
 {'check_name': 'RSA Key Size Below 2048 Bits',
  'category': 'key_size',
  'detection': 'Extract the RSA public key modulus length from SubjectPublicKeyInfo and flag if bit length is less '
               'than 2048',
  'severity': 'CRITICAL',
  'cvss': '8.1',
  'remediation': 'Generate a new RSA key pair of at least 2048 bits (preferably 4096) and reissue the certificate'},
 {'check_name': 'EC Key Size Below 256 Bits',
  'category': 'key_size',
  'detection': 'Extract the elliptic curve OID from SubjectPublicKeyInfo and flag any curve with field size under 256 '
               'bits',
  'severity': 'HIGH',
  'cvss': '7.4',
  'remediation': 'Use NIST P-256, P-384, or P-521 curves; regenerate key and reissue the certificate'},
 {'check_name': 'RSA Key Size Below 1024 Bits',
  'category': 'key_size',
  'detection': 'Extract RSA modulus bit length and flag if strictly less than 1024 bits as factorization is '
               'computationally feasible',
  'severity': 'CRITICAL',
  'cvss': '9.8',
  'remediation': 'Immediately revoke and reissue with a minimum 2048-bit RSA key; 1024-bit keys are practically '
                 'broken'},
 {'check_name': 'Certificate Already Expired',
  'category': 'validity',
  'detection': 'Compare certificate notAfter field against current UTC time and flag if notAfter is in the past',
  'severity': 'CRITICAL',
  'cvss': '9.1',
  'remediation': 'Renew the certificate immediately and implement automated renewal monitoring to prevent future '
                 'expiry'},
 {'check_name': 'Certificate Expiring Within 14 Days',
  'category': 'validity',
  'detection': 'Compare certificate notAfter field to current UTC time and flag if remaining validity is 14 days or '
               'fewer',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Renew the certificate now and configure automated renewal triggers at 30 days before expiry'},
 {'check_name': 'Suspiciously Short Certificate Validity Under 30 Days',
  'category': 'validity',
  'detection': 'Calculate total validity period as notAfter minus notBefore and flag if the span is less than 30 days',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Investigate the issuing CA; request certificates with standard 90-day or longer validity periods'},
 {'check_name': 'Self-Signed Certificate in Production',
  'category': 'ca',
  'detection': 'Check if certificate Subject DN equals Issuer DN and AuthorityKeyIdentifier matches '
               'SubjectKeyIdentifier',
  'severity': 'CRITICAL',
  'cvss': '8.6',
  'remediation': "Replace with a certificate issued by a publicly trusted CA; use Let's Encrypt for free DV "
                 'certificates'},
 {'check_name': 'Symantec-Distrust Legacy CA',
  'category': 'ca',
  'detection': 'Check issuer chain for Symantec, GeoTrust, Thawte, or RapidSSL root/intermediate CA OIDs deprecated by '
               'browsers in 2018',
  'severity': 'HIGH',
  'cvss': '7.4',
  'remediation': 'Replace the certificate with one issued by a currently trusted CA such as DigiCert, Sectigo, or '
                 "Let's Encrypt"},
 {'check_name': 'Unknown or Untrusted CA',
  'category': 'ca',
  'detection': 'Verify root CA fingerprint against Mozilla NSS, Chrome CTL, and Microsoft Root Program trust stores; '
               'flag if absent from all',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Obtain a certificate from a CA included in major OS and browser trust stores to ensure universal '
                 'client acceptance'},
 {'check_name': 'Missing OCSP Stapling',
  'category': 'chain',
  'detection': 'During TLS handshake check for OCSPResponse in Certificate Status extension (RFC 6066 status_request); '
               'flag if absent',
  'severity': 'MEDIUM',
  'cvss': '5.9',
  'remediation': 'Enable OCSP stapling in the web server configuration (e.g., ssl_stapling on in Nginx) and cache OCSP '
                 'responses'},
 {'check_name': 'Missing TLS Must-Staple Extension',
  'category': 'chain',
  'detection': 'Parse certificate for TLS Feature extension (OID 1.3.6.1.5.5.7.1.24) containing status_request (5); '
               'flag if absent',
  'severity': 'LOW',
  'cvss': '3.7',
  'remediation': 'Request a new certificate with the must-staple flag enabled and ensure OCSP stapling is fully '
                 'operational before deployment'},
 {'check_name': 'RC4 Cipher Suite Still Supported',
  'category': 'cipher',
  'detection': 'Enumerate server cipher suites via TLS ClientHello and flag any suite containing RC4 (cipher IDs '
               '0x0004, 0x0005, 0xC011, 0xC012)',
  'severity': 'CRITICAL',
  'cvss': '9.1',
  'remediation': 'Disable all RC4 cipher suites in the TLS configuration and restart the service; RC4 is '
                 'cryptographically broken'},
 {'check_name': '3DES (Triple-DES) Cipher Suite Still Supported',
  'category': 'cipher',
  'detection': 'Enumerate server cipher suites and flag any suite containing 3DES_EDE (cipher IDs 0x000A, 0xC012) due '
               'to SWEET32 vulnerability',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Remove all 3DES cipher suites from the TLS configuration and replace with AES-GCM or '
                 'ChaCha20-Poly1305 suites'},
 {'check_name': 'DES Cipher Suite Still Supported',
  'category': 'cipher',
  'detection': 'Enumerate server cipher suites and flag any suite with DES (56-bit) cipher IDs such as 0x0009, 0x0015, '
               '0x0019',
  'severity': 'CRITICAL',
  'cvss': '9.1',
  'remediation': 'Disable all DES cipher suites immediately; replace with AES-128-GCM or AES-256-GCM authenticated '
                 'encryption'},
 {'check_name': 'NULL Cipher Suite Supported',
  'category': 'cipher',
  'detection': 'Enumerate server cipher suites and flag any suite with NULL encryption component (cipher IDs 0x002C, '
               '0x002D, 0x002E, 0x003B)',
  'severity': 'CRITICAL',
  'cvss': '9.8',
  'remediation': 'Immediately disable NULL cipher suites; they provide authentication with zero confidentiality '
                 'protection'},
 {'check_name': 'EXPORT Cipher Suite Still Supported',
  'category': 'cipher',
  'detection': 'Enumerate server cipher suites and flag any suite containing EXPORT keyword or 40/56-bit key lengths '
               '(FREAK/LOGJAM risk)',
  'severity': 'CRITICAL',
  'cvss': '9.4',
  'remediation': 'Disable all EXPORT-grade cipher suites; these were intentionally weakened and are exploitable via '
                 'FREAK attacks'},
 {'check_name': 'TLS 1.0 Still Enabled',
  'category': 'protocol',
  'detection': 'Send TLS ClientHello with version 0x0301 and record if server responds with ServerHello accepting TLS '
               '1.0',
  'severity': 'HIGH',
  'cvss': '7.4',
  'remediation': 'Disable TLS 1.0 in the server configuration; it is deprecated by PCI-DSS and IETF RFC 8996'},
 {'check_name': 'TLS 1.1 Still Enabled',
  'category': 'protocol',
  'detection': 'Send TLS ClientHello with version 0x0302 and record if server responds with ServerHello accepting TLS '
               '1.1',
  'severity': 'HIGH',
  'cvss': '6.5',
  'remediation': 'Disable TLS 1.1 in the server configuration; configure minimum protocol version to TLS 1.2'},
 {'check_name': 'SSL 3.0 Still Enabled',
  'category': 'protocol',
  'detection': 'Send SSLv3 ClientHello (version 0x0300) and flag if server completes handshake; POODLE vulnerability '
               'applies',
  'severity': 'CRITICAL',
  'cvss': '9.3',
  'remediation': 'Disable SSL 3.0 globally in server configuration; it has been deprecated since RFC 7568 and is '
                 'exploitable via POODLE'},
 {'check_name': 'SSL 2.0 Still Enabled',
  'category': 'protocol',
  'detection': 'Send SSLv2 ClientHello and detect if server issues a ServerHello with SSLv2 version bytes in the '
               'record layer',
  'severity': 'CRITICAL',
  'cvss': '9.8',
  'remediation': 'Disable SSL 2.0 immediately; it has fundamental cryptographic flaws and enables DROWN attacks on '
                 'co-hosted TLS'},
 {'check_name': 'Missing Forward Secrecy',
  'category': 'cipher',
  'detection': 'Check that at least one of the negotiated cipher suites uses ephemeral key exchange (ECDHE or DHE); '
               'flag if only RSA/DH static key exchange is offered',
  'severity': 'HIGH',
  'cvss': '7.4',
  'remediation': 'Prioritize ECDHE cipher suites in server configuration to ensure forward secrecy protects recorded '
                 'traffic'},
 {'check_name': 'Weak Diffie-Hellman Parameters Below 2048 Bits',
  'category': 'key_size',
  'detection': 'During DHE handshake capture ServerKeyExchange message and measure the DH prime p bit length; flag if '
               'under 2048 bits',
  'severity': 'HIGH',
  'cvss': '7.4',
  'remediation': 'Generate new DH parameters of at least 2048 bits using openssl dhparam 2048 and configure the server '
                 'to use them'},
 {'check_name': 'Certificate Common Name Mismatch',
  'category': 'sni',
  'detection': 'Compare the requested hostname against certificate CN and all SAN dNSName entries; flag if no match '
               'found',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Reissue the certificate with correct CN and SAN entries matching all hostnames served by the '
                 'endpoint'},
 {'check_name': 'Subject Alternative Name Extension Missing',
  'category': 'sni',
  'detection': 'Parse certificate extensions and flag if the subjectAltName extension (OID 2.5.29.17) is entirely '
               'absent',
  'severity': 'HIGH',
  'cvss': '6.5',
  'remediation': 'Reissue certificate with a SAN extension; modern browsers ignore CN and require SAN per CA/B Forum '
                 'Baseline Requirements'},
 {'check_name': 'Common Subdomain Not Listed in SAN',
  'category': 'sni',
  'detection': 'Enumerate common subdomains (www, mail, api, ftp, vpn) via DNS and cross-check each against '
               'certificate SAN dNSName list',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Reissue certificate with all active subdomains listed in SAN or use a wildcard for domains with many '
                 'subdomains'},
 {'check_name': 'Wildcard Certificate Used for High-Value Domain',
  'category': 'sni',
  'detection': 'Check SAN entries for wildcard pattern (*.) and assess if the domain is classified as high-value or '
               'PCI/HIPAA scoped',
  'severity': 'MEDIUM',
  'cvss': '5.9',
  'remediation': 'Limit wildcard certificates to low-sensitivity subdomains; use individual SAN certificates for '
                 'high-value services'},
 {'check_name': 'Wildcard Certificate Covers Too Many Levels',
  'category': 'sni',
  'detection': 'Parse SAN entries for multi-level wildcard patterns (e.g., *.*.example.com); flag as BAS Baseline '
               'Requirements violation',
  'severity': 'HIGH',
  'cvss': '7.4',
  'remediation': 'Replace with a single-level wildcard or individual SAN entries; multi-level wildcards violate CA/B '
                 'Forum BR section 3.2.2.6'},
 {'check_name': 'Certificate Not Logged in CT Log',
  'category': 'chain',
  'detection': 'Check certificate for embedded SCTs (Signed Certificate Timestamps) in extension OID '
               '1.3.6.1.4.1.11129.2.4.2 or via OCSP/TLS extension',
  'severity': 'HIGH',
  'cvss': '6.8',
  'remediation': 'Request certificate from a CA that automatically submits to multiple CT logs; Chrome requires at '
                 'least two embedded SCTs'},
 {'check_name': 'Insufficient SCT Count in Certificate',
  'category': 'chain',
  'detection': 'Count embedded Signed Certificate Timestamps in the CT precertificate poison extension and flag if '
               'fewer than two are present',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Reissue certificate ensuring the CA embeds SCTs from at least two independent CT logs to meet Chrome '
                 'policy requirements'},
 {'check_name': 'CA/B Forum Baseline Requirements Violation: Missing CAA Check Evidence',
  'category': 'ca',
  'detection': 'Query DNS CAA records for the certificate domain and verify CA performed CAA validation before '
               'issuance per BR section 3.2.2.8',
  'severity': 'HIGH',
  'cvss': '6.5',
  'remediation': 'Add DNS CAA records explicitly authorizing your CA and report non-compliant issuance to the CA and '
                 'relevant browser programs'},
 {'check_name': 'Certificate Validity Period Exceeds 398 Days',
  'category': 'validity',
  'detection': 'Calculate certificate validity span in days from notBefore to notAfter and flag if greater than 398 '
               'days',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Reissue certificate with validity not exceeding 397 days to comply with Apple/Mozilla/Chrome policy '
                 'enforced since Sept 2020'},
 {'check_name': 'Intermediate CA Certificate Not Served in Chain',
  'category': 'chain',
  'detection': 'Perform TLS handshake and verify that all intermediate CA certificates are included in the Certificate '
               'message chain',
  'severity': 'HIGH',
  'cvss': '6.5',
  'remediation': 'Configure the web server to send the full chain file including all intermediate certificates '
                 'required to build to a trusted root'},
 {'check_name': 'Root CA Certificate Served in TLS Handshake',
  'category': 'chain',
  'detection': 'Inspect the TLS Certificate message chain and flag if the final certificate matches a known root CA '
               '(self-signed Issuer=Subject in root store)',
  'severity': 'LOW',
  'cvss': '3.1',
  'remediation': 'Remove the root CA certificate from the served chain; clients already have it in their trust store '
                 'and serving it wastes bandwidth'},
 {'check_name': 'OCSP Responder URL Unreachable',
  'category': 'chain',
  'detection': 'Extract OCSP URL from certificate AIA extension and perform an HTTP GET/POST OCSP request; flag '
               'non-200 or timeout responses',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Enable OCSP stapling so the server caches the response, removing client dependency on CA OCSP '
                 'infrastructure availability'},
 {'check_name': 'Certificate Revoked via CRL or OCSP',
  'category': 'validity',
  'detection': 'Fetch CRL from CRL Distribution Points extension and check serial number presence; also query OCSP for '
               'revoked status',
  'severity': 'CRITICAL',
  'cvss': '9.1',
  'remediation': 'Immediately replace the revoked certificate with a newly issued one and investigate the reason for '
                 'revocation'},
 {'check_name': 'Weak RSA Exponent (e=3) in Certificate Public Key',
  'category': 'algorithm',
  'detection': 'Extract RSA public exponent from SubjectPublicKeyInfo and flag if e equals 3 which is vulnerable to '
               'Coppersmith attacks when padding is weak',
  'severity': 'HIGH',
  'cvss': '7.4',
  'remediation': 'Regenerate RSA key pair using public exponent e=65537 (F4) and reissue the certificate from the CA'},
 {'check_name': 'Certificate Key Usage Does Not Match Extended Key Usage',
  'category': 'chain',
  'detection': 'Cross-validate KeyUsage bits (e.g., digitalSignature) against ExtendedKeyUsage OIDs (e.g., serverAuth '
               '1.3.6.1.5.5.7.3.1); flag contradictions',
  'severity': 'MEDIUM',
  'cvss': '5.4',
  'remediation': "Reissue certificate with consistent KU and EKU extensions that accurately reflect the certificate's "
                 'intended purpose'},
 {'check_name': 'TLS Compression Enabled (CRIME Attack Risk)',
  'category': 'protocol',
  'detection': 'Negotiate TLS handshake requesting DEFLATE compression (RFC 3749) and flag if server accepts a '
               'non-null CompressionMethod',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Disable TLS-level compression in server configuration; HTTP-level compression for sensitive cookies '
                 'should also be reviewed'},
 {'check_name': 'TLS Renegotiation Not Disabled or Secured',
  'category': 'protocol',
  'detection': 'Initiate a TLS session then send a ClientHello renegotiation request and flag if server accepts '
               'insecure renegotiation without RFC 5746 extension',
  'severity': 'HIGH',
  'cvss': '7.4',
  'remediation': 'Disable client-initiated renegotiation or enforce secure renegotiation extension per RFC 5746 in the '
                 'TLS server configuration'}]

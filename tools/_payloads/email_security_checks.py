"""email_security_checks — generated dev-time by Claude. Recon module asset.
"""

EMAIL_SECURITY_CHECKS = [{'check_name': 'SPF Record Missing',
  'category': 'spf',
  'pattern': '^(?!.*v=spf1).*$',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': "Add a TXT record to your DNS zone with a valid SPF policy, e.g., 'v=spf1 include:_spf.yourdomain.com "
                 "~all'. Ensure it covers all legitimate sending sources for your domain."},
 {'check_name': 'SPF Neutral Qualifier',
  'category': 'spf',
  'pattern': 'v=spf1.*\\?all',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': "Replace the '?all' neutral qualifier with '~all' (softfail) or '-all' (fail) to enforce stronger "
                 'sender validation. A neutral qualifier provides no meaningful protection against spoofing.'},
 {'check_name': 'SPF Too Permissive (Pass All)',
  'category': 'spf',
  'pattern': 'v=spf1.*\\+all',
  'severity': 'HIGH',
  'cvss': '8.6',
  'remediation': "Remove the '+all' qualifier and replace it with '-all' or '~all' to restrict which servers are "
                 "authorised to send email on behalf of your domain. '+all' allows any server to send mail as your "
                 'domain.'},
 {'check_name': 'SPF Syntax Error (Invalid Mechanism)',
  'category': 'spf',
  'pattern': 'v=spf1.*(?:ip[^46]:|includ[^e]:|redirects?=|all\\s+[^$])',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Validate your SPF record against RFC 7208 syntax rules and correct any malformed mechanisms or '
                 'modifiers. Use an SPF record checker tool to identify and fix specific syntax errors.'},
 {'check_name': 'SPF Nested Includes Too Deep',
  'category': 'spf',
  'pattern': 'v=spf1(?:.*include:[^\\s]+){5,}',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Flatten nested SPF includes by consolidating sending sources or using macros to reduce DNS lookup '
                 'depth. Deeply nested includes risk exceeding the 10-lookup limit causing SPF to return PermError.'},
 {'check_name': 'SPF Missing All Qualifier',
  'category': 'spf',
  'pattern': 'v=spf1(?:(?!all).)*$',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': "Append an 'all' qualifier (e.g., '-all' or '~all') to your SPF record to define the default policy "
                 "for unlisted senders. Omitting 'all' leaves the policy undefined and ineffective."},
 {'check_name': 'Multiple SPF Records',
  'category': 'spf',
  'pattern': '(?:v=spf1.*\\n.*v=spf1|v=spf1.*v=spf1)',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Merge all SPF directives into a single TXT record, as having multiple SPF records causes a PermError '
                 'per RFC 7208. Delete duplicate records and consolidate all mechanisms into one.'},
 {'check_name': 'SPF Too Many DNS Lookups',
  'category': 'spf',
  'pattern': 'v=spf1(?:.*(?:include:|a:|mx:|exists:|redirect=)[^\\s]+){10,}',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Reduce the number of DNS-querying mechanisms (include, a, mx, exists, redirect) to stay within the '
                 'RFC 7208 limit of 10 lookups. Use SPF flattening tools or replace mechanisms with explicit IP '
                 'ranges.'},
 {'check_name': 'SPF Overly Broad IP Range',
  'category': 'spf',
  'pattern': 'v=spf1.*ip4:(?:0\\.0\\.0\\.0/[0-9]|(?:\\d+\\.){3}\\d+/[0-9](?![0-9]))',
  'severity': 'HIGH',
  'cvss': '8.1',
  'remediation': 'Replace overly broad CIDR blocks (e.g., /8 or /16) with specific IP ranges that correspond only to '
                 'your legitimate mail servers. Broad ranges allow unauthorised servers to send mail as your domain.'},
 {'check_name': 'SPF Uses PTR Mechanism',
  'category': 'spf',
  'pattern': 'v=spf1.*\\bptr\\b',
  'severity': 'MEDIUM',
  'cvss': '4.3',
  'remediation': "Remove the 'ptr' mechanism from your SPF record, as it is deprecated in RFC 7208 due to reliability "
                 "and performance issues. Replace it with explicit 'ip4', 'ip6', or 'include' mechanisms."},
 {'check_name': 'DMARC Record Missing',
  'category': 'dmarc',
  'pattern': '^(?!.*v=DMARC1).*$',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': "Publish a DMARC TXT record at _dmarc.yourdomain.com, e.g., 'v=DMARC1; p=quarantine; "
                 "rua=mailto:dmarc@yourdomain.com'. Start with p=none for monitoring and gradually move to quarantine "
                 'or reject.'},
 {'check_name': 'DMARC Policy Set to None',
  'category': 'dmarc',
  'pattern': 'v=DMARC1.*p=none',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': "Upgrade the DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject' after analysing aggregate "
                 'reports. A none policy provides visibility only and does not protect against domain abuse.'},
 {'check_name': 'DMARC Policy Set to Quarantine',
  'category': 'dmarc',
  'pattern': 'v=DMARC1.*p=quarantine',
  'severity': 'LOW',
  'cvss': '3.1',
  'remediation': "Consider upgrading from 'p=quarantine' to 'p=reject' once you have validated all legitimate sending "
                 'sources via DMARC aggregate reports. Quarantine reduces but does not eliminate domain spoofing '
                 'risk.'},
 {'check_name': 'DMARC Subdomain Policy Missing',
  'category': 'dmarc',
  'pattern': 'v=DMARC1.*p=(?:reject|quarantine)(?!.*sp=)',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': "Add the 'sp=' tag to explicitly define the DMARC policy for subdomains, e.g., 'sp=reject'. Without "
                 'it, subdomains inherit the organisational domain policy which may not be the desired behaviour.'},
 {'check_name': 'DMARC Relaxed SPF Alignment',
  'category': 'dmarc',
  'pattern': 'v=DMARC1.*aspf=r',
  'severity': 'LOW',
  'cvss': '3.7',
  'remediation': "Consider changing SPF alignment to strict mode ('aspf=s') to require an exact match between the SPF "
                 'authenticated domain and the From header domain. Relaxed alignment increases spoofing risk from '
                 'organisational subdomains.'},
 {'check_name': 'DMARC Relaxed DKIM Alignment',
  'category': 'dmarc',
  'pattern': 'v=DMARC1.*adkim=r',
  'severity': 'LOW',
  'cvss': '3.7',
  'remediation': "Consider setting DKIM alignment to strict ('adkim=s') to require the DKIM d= domain to exactly match "
                 'the From header domain. Relaxed DKIM alignment may allow subdomain-based spoofing attacks.'},
 {'check_name': 'DMARC Missing RUA Aggregate Report URI',
  'category': 'dmarc',
  'pattern': 'v=DMARC1(?!.*rua=).*',
  'severity': 'MEDIUM',
  'cvss': '4.3',
  'remediation': "Add the 'rua=' tag with a valid mailto URI to receive DMARC aggregate reports, e.g., "
                 "'rua=mailto:dmarc-reports@yourdomain.com'. Aggregate reports are essential for monitoring and tuning "
                 'your DMARC policy.'},
 {'check_name': 'DMARC RUF Forensic Report URI Missing',
  'category': 'dmarc',
  'pattern': 'v=DMARC1(?!.*ruf=).*',
  'severity': 'LOW',
  'cvss': '3.1',
  'remediation': "Add the 'ruf=' tag with a valid mailto URI to receive DMARC forensic failure reports, e.g., "
                 "'ruf=mailto:dmarc-forensic@yourdomain.com'. Forensic reports assist in diagnosing individual "
                 'authentication failures.'},
 {'check_name': 'DMARC External RUA Domain Not Authorised',
  'category': 'dmarc',
  'pattern': 'v=DMARC1.*rua=mailto:[^@]+@(?!yourdomain\\.com)[^\\s;]+',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Ensure the external domain receiving DMARC reports has published a DMARC authorisation record at '
                 'yourdomain.com._report._dmarc.externalreporter.com. Without this, report receivers may reject '
                 'incoming DMARC reports.'},
 {'check_name': 'DMARC Percentage Tag Below 100',
  'category': 'dmarc',
  'pattern': 'v=DMARC1.*pct=(?:[0-9]|[1-9][0-9])(?![0-9])',
  'severity': 'MEDIUM',
  'cvss': '4.3',
  'remediation': "Increase the 'pct=' tag to 100 once you have confirmed all legitimate email flows pass DMARC "
                 'authentication. A pct value below 100 means a portion of failing messages bypass enforcement.'},
 {'check_name': 'DKIM Selector Missing',
  'category': 'dkim',
  'pattern': '^(?!.*v=DKIM1).*$',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Generate a DKIM key pair and publish the public key as a TXT record at '
                 "selector._domainkey.yourdomain.com with 'v=DKIM1; k=rsa; p=<pubkey>'. Configure your mail server to "
                 'sign outbound messages with the corresponding private key.'},
 {'check_name': 'DKIM Weak RSA Key (512-bit)',
  'category': 'dkim',
  'pattern': 'v=DKIM1.*p=[A-Za-z0-9+/]{32,88}={0,2}(?![A-Za-z0-9+/=])',
  'severity': 'HIGH',
  'cvss': '8.1',
  'remediation': 'Rotate the DKIM key to a minimum of 2048-bit RSA or an Ed25519 key, and publish the new public key '
                 'in DNS. Short RSA keys are computationally feasible to factor, allowing attackers to forge email '
                 'signatures.'},
 {'check_name': 'DKIM Weak RSA Key (1024-bit)',
  'category': 'dkim',
  'pattern': 'v=DKIM1.*p=[A-Za-z0-9+/]{120,172}={0,2}(?![A-Za-z0-9+/=])',
  'severity': 'MEDIUM',
  'cvss': '5.9',
  'remediation': 'Upgrade the DKIM key to a minimum of 2048-bit RSA or switch to Ed25519 for better security and '
                 'performance. 1024-bit RSA keys are considered insufficiently secure per current NIST guidelines.'},
 {'check_name': 'DKIM Key Revoked (Empty p= Tag)',
  'category': 'dkim',
  'pattern': 'v=DKIM1.*p=\\s*(?:;|$)',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': "Replace the empty 'p=' tag with a valid public key or remove the selector record if it is "
                 'intentionally revoked and deploy a new active selector. An empty p= tag signals key revocation and '
                 'will cause all signed messages to fail verification.'},
 {'check_name': 'DKIM Hash Algorithm Restricted to SHA-1',
  'category': 'dkim',
  'pattern': 'v=DKIM1.*h=sha1(?!\\s*:sha256)',
  'severity': 'MEDIUM',
  'cvss': '5.9',
  'remediation': "Update the 'h=' tag to include 'sha256' or remove the restriction so that both SHA-1 and SHA-256 are "
                 'accepted. SHA-1 is cryptographically weak and should not be used as the sole permitted hashing '
                 'algorithm.'},
 {'check_name': 'BIMI Record Missing',
  'category': 'bimi',
  'pattern': '^(?!.*v=BIMI1).*$',
  'severity': 'LOW',
  'cvss': '2.6',
  'remediation': "Publish a BIMI TXT record at default._bimi.yourdomain.com with 'v=BIMI1; l=<SVG URL>; a=<VMC URL>' "
                 'to enable brand logo display in supporting email clients. Ensure DMARC is set to p=quarantine or '
                 'p=reject as a prerequisite.'},
 {'check_name': 'BIMI Missing Logo URL',
  'category': 'bimi',
  'pattern': 'v=BIMI1(?!.*l=https?://)',
  'severity': 'LOW',
  'cvss': '2.6',
  'remediation': "Add a valid 'l=' tag pointing to a publicly accessible Tiny SVG 1.2 formatted logo URL, e.g., "
                 "'l=https://yourdomain.com/logo.svg'. Without a logo URL, BIMI cannot display your brand indicator in "
                 'email clients.'},
 {'check_name': 'BIMI Missing VMC Certificate',
  'category': 'bimi',
  'pattern': 'v=BIMI1.*l=https?://[^\\s;]+(?!.*a=https?://)',
  'severity': 'LOW',
  'cvss': '2.6',
  'remediation': "Obtain a Verified Mark Certificate (VMC) from an authorised CA and add the 'a=' tag pointing to the "
                 'hosted PEM file. Without a VMC, major email providers like Gmail will not display the BIMI logo.'},
 {'check_name': 'BIMI Logo Not Served Over HTTPS',
  'category': 'bimi',
  'pattern': 'v=BIMI1.*l=http://',
  'severity': 'MEDIUM',
  'cvss': '4.3',
  'remediation': "Update the 'l=' tag to use an HTTPS URL for the logo file to ensure integrity and confidentiality "
                 'during retrieval. HTTP URLs are rejected by BIMI-compliant email clients and providers.'},
 {'check_name': 'BIMI VMC Not Served Over HTTPS',
  'category': 'bimi',
  'pattern': 'v=BIMI1.*a=http://',
  'severity': 'MEDIUM',
  'cvss': '4.3',
  'remediation': "Update the 'a=' VMC tag to reference an HTTPS-hosted PEM certificate URL to ensure secure "
                 'certificate retrieval. Non-HTTPS VMC URLs will cause BIMI verification to fail at the receiving mail '
                 'provider.'},
 {'check_name': 'MTA-STS Policy Record Missing',
  'category': 'mta_sts',
  'pattern': '^(?!.*v=STSv1).*$',
  'severity': 'HIGH',
  'cvss': '7.4',
  'remediation': "Publish an MTA-STS DNS TXT record at _mta-sts.yourdomain.com with 'v=STSv1; id=<timestamp>' and host "
                 'the policy file at https://mta-sts.yourdomain.com/.well-known/mta-sts.txt. MTA-STS prevents SMTP '
                 'downgrade and MITM attacks.'},
 {'check_name': 'MTA-STS Policy Mode Set to Testing',
  'category': 'mta_sts',
  'pattern': 'mode:\\s*testing',
  'severity': 'MEDIUM',
  'cvss': '5.9',
  'remediation': "Change the MTA-STS policy mode from 'testing' to 'enforce' after confirming all inbound mail flows "
                 'function correctly under the policy. Testing mode reports failures but does not block insecure '
                 'connections.'},
 {'check_name': 'MTA-STS Policy Mode Set to None',
  'category': 'mta_sts',
  'pattern': 'mode:\\s*none',
  'severity': 'HIGH',
  'cvss': '7.4',
  'remediation': "Update the MTA-STS policy mode from 'none' to 'enforce' to actively require TLS for inbound SMTP "
                 "connections. A mode of 'none' effectively disables MTA-STS protection."},
 {'check_name': 'MTA-STS Policy Missing MX Entry',
  'category': 'mta_sts',
  'pattern': 'version:\\s*STSv1[\\s\\S]*?(?!mx:)',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': "Add at least one 'mx:' line to the MTA-STS policy file listing all authorised inbound MX hostnames, "
                 "e.g., 'mx: mail.yourdomain.com'. Without MX entries, the policy cannot validate inbound mail server "
                 'identities.'},
 {'check_name': 'MTA-STS Short Max Age',
  'category': 'mta_sts',
  'pattern': 'max_age:\\s*(?:[0-9]{1,4})(?![0-9])',
  'severity': 'LOW',
  'cvss': '3.7',
  'remediation': "Increase the 'max_age' value to at least 604800 seconds (7 days), with a recommended value of "
                 '31557600 (1 year) for stable deployments. A very short max_age reduces caching effectiveness and '
                 'increases DNS query frequency.'},
 {'check_name': 'DANE TLSA Record Missing',
  'category': 'dane',
  'pattern': '^(?!.*TLSA).*$',
  'severity': 'HIGH',
  'cvss': '7.4',
  'remediation': 'Publish a DANE TLSA record at _25._tcp.mail.yourdomain.com specifying your mail server certificate '
                 'or public key hash, e.g., usage 3, selector 1, matching type 2. DANE with DNSSEC prevents '
                 'certificate substitution attacks on SMTP.'},
 {'check_name': 'DANE TLSA Weak Matching Type (Full Certificate)',
  'category': 'dane',
  'pattern': '\\bTLSA\\b.*\\s+[0-3]\\s+[01]\\s+0\\s+',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': "Replace matching type '0' (full certificate) with matching type '1' (SHA-256) or '2' (SHA-512) to "
                 'use a cryptographic hash instead of the raw certificate. Full certificate matching requires DNS '
                 'record updates every time the certificate is renewed.'},
 {'check_name': 'DANE TLSA Usage Mode 1 (Trust Anchor without PKIX)',
  'category': 'dane',
  'pattern': '\\bTLSA\\b.*\\s+1\\s+[01]\\s+[012]\\s+',
  'severity': 'MEDIUM',
  'cvss': '5.9',
  'remediation': 'Evaluate whether DANE usage mode 1 (PKIX-TA) is appropriate and ensure DNSSEC is properly configured '
                 'to prevent spoofing of the TLSA record. Usage mode 3 (DANE-EE) is generally preferred for SMTP as it '
                 'does not rely on public CA trust chains.'},
 {'check_name': 'DANE TLSA Mismatched Certificate Hash',
  'category': 'dane',
  'pattern': '\\bTLSA\\b.*\\s+[0-3]\\s+[01]\\s+[12]\\s+(?!(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{128})$)[0-9a-fA-F]+',
  'severity': 'HIGH',
  'cvss': '8.1',
  'remediation': 'Recompute the certificate or public key hash using the correct algorithm (SHA-256 for type 1, '
                 'SHA-512 for type 2) and update the TLSA record. A mismatched hash will cause DANE-aware clients to '
                 'refuse connections to your mail server.'},
 {'check_name': 'TLS-RPT Record Missing',
  'category': 'tls_rpt',
  'pattern': '^(?!.*v=TLSRPTv1).*$',
  'severity': 'MEDIUM',
  'cvss': '4.3',
  'remediation': "Publish a TLS-RPT TXT record at _smtp._tls.yourdomain.com with 'v=TLSRPTv1; "
                 "rua=mailto:tls-reports@yourdomain.com' to receive TLS failure reports from sending MTAs. TLS-RPT "
                 'reports are essential for monitoring MTA-STS and DANE enforcement.'},
 {'check_name': 'TLS-RPT Missing RUA Tag',
  'category': 'tls_rpt',
  'pattern': 'v=TLSRPTv1(?!.*rua=)',
  'severity': 'MEDIUM',
  'cvss': '4.3',
  'remediation': "Add the 'rua=' tag with a valid mailto or HTTPS endpoint URI to your TLS-RPT record, e.g., "
                 "'rua=mailto:tls-reports@yourdomain.com'. Without an RUA, senders have nowhere to send TLS failure "
                 'reports.'},
 {'check_name': 'TLS-RPT RUA Uses Non-HTTPS and Non-Mailto URI',
  'category': 'tls_rpt',
  'pattern': 'v=TLSRPTv1.*rua=(?!mailto:|https://)[^\\s;]+',
  'severity': 'MEDIUM',
  'cvss': '4.3',
  'remediation': "Update the 'rua=' URI to use either a 'mailto:' address or an 'https://' endpoint as defined in RFC "
                 '8460. Invalid URI schemes will cause sending MTAs to discard TLS failure reports.'}]

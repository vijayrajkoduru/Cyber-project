"""email_security_checks — generated dev-time by Claude. Recon module asset.
"""

EMAIL_SECURITY_CHECKS = [{'check_name': 'SPF Record Missing',
  'category': 'spf',
  'pattern': '^(?!.*v=spf1).*$',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': "Add a TXT record to your DNS zone containing a valid SPF policy such as 'v=spf1 "
                 "include:your-mail-provider.com ~all'. Ensure it covers all legitimate sending sources for your "
                 'domain.'},
 {'check_name': 'SPF Neutral Qualifier',
  'category': 'spf',
  'pattern': 'v=spf1\\s+.*\\?all',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': "Replace the '?all' neutral qualifier with '-all' (fail) or at minimum '~all' (softfail) to "
                 'explicitly reject unauthorized senders. A neutral qualifier provides no protective value against '
                 'spoofing.'},
 {'check_name': 'SPF Too Permissive with +all',
  'category': 'spf',
  'pattern': 'v=spf1\\s+.*\\+all',
  'severity': 'HIGH',
  'cvss': '8.6',
  'remediation': "Remove the '+all' mechanism immediately and replace it with '-all' to block all unauthorized "
                 "senders. '+all' effectively allows any server on the internet to send mail on behalf of your "
                 'domain.'},
 {'check_name': 'SPF Syntax Error Missing Version',
  'category': 'spf',
  'pattern': '^(?!v=spf1)spf.*',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': "Ensure the SPF record begins exactly with 'v=spf1' followed by a space and the policy mechanisms. "
                 'Malformed version strings cause the record to be ignored by receiving mail servers.'},
 {'check_name': 'SPF Nested Include Depth',
  'category': 'spf',
  'pattern': 'v=spf1(?:.*include:[^\\s]+){4,}',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Flatten nested SPF includes by consolidating sending sources or using an SPF flattening service to '
                 'reduce include chain depth. Deeply nested includes risk exceeding the 10-lookup limit and causing '
                 'permerror.'},
 {'check_name': 'SPF No All Qualifier',
  'category': 'spf',
  'pattern': 'v=spf1(?:(?!~all)(?!-all)(?!\\+all)(?!\\?all).)*$',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': "Always terminate your SPF record with an explicit 'all' mechanism such as '-all' or '~all'. Omitting "
                 'it leaves the policy incomplete and allows unauthorized senders to pass SPF checks by default.'},
 {'check_name': 'Multiple SPF Records Detected',
  'category': 'spf',
  'pattern': '(v=spf1[^\\n]*\\n){2,}',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': "Remove all duplicate SPF TXT records and consolidate all sending sources into a single 'v=spf1' "
                 'record. RFC 7208 specifies that multiple SPF records result in a permanent error (permerror).'},
 {'check_name': 'SPF Too Many DNS Lookups',
  'category': 'spf',
  'pattern': 'v=spf1(?:.*(?:include:|a:|mx:|ptr:|exists:)[^\\s]+){10,}',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Reduce the number of DNS-querying mechanisms (include, a, mx, ptr, exists) to stay under the RFC '
                 '7208 limit of 10 lookups. Use SPF flattening tools to inline IP addresses and eliminate unnecessary '
                 'include chains.'},
 {'check_name': 'SPF Uses Deprecated PTR Mechanism',
  'category': 'spf',
  'pattern': 'v=spf1.*\\bptr\\b',
  'severity': 'MEDIUM',
  'cvss': '4.3',
  'remediation': "Remove the 'ptr' mechanism from your SPF record as it is deprecated per RFC 7208 due to poor "
                 "performance and reliability. Replace it with 'ip4', 'ip6', or 'include' mechanisms for equivalent "
                 'coverage.'},
 {'check_name': 'SPF Overly Broad IP Range',
  'category': 'spf',
  'pattern': 'v=spf1.*ip4:\\d{1,3}\\.\\d{1,3}\\.0\\.0/1[0-5]\\b',
  'severity': 'HIGH',
  'cvss': '8.1',
  'remediation': 'Replace broad CIDR ranges (e.g., /8, /12, /15) with the specific IP addresses or tighter subnets '
                 'actually used for mail delivery. Authorizing large IP blocks allows any host in that range to send '
                 'mail as your domain.'},
 {'check_name': 'DMARC Policy None',
  'category': 'dmarc',
  'pattern': 'v=DMARC1;.*p=none',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': "Upgrade the DMARC policy from 'p=none' (monitor only) to 'p=quarantine' or 'p=reject' after "
                 "reviewing aggregate reports. A 'none' policy provides visibility but no protection against domain "
                 'spoofing.'},
 {'check_name': 'DMARC Policy Quarantine',
  'category': 'dmarc',
  'pattern': 'v=DMARC1;.*p=quarantine',
  'severity': 'LOW',
  'cvss': '3.1',
  'remediation': "Consider graduating your DMARC policy from 'p=quarantine' to 'p=reject' once you have confirmed all "
                 "legitimate mail streams are passing alignment checks. 'p=reject' provides full enforcement against "
                 'spoofed messages.'},
 {'check_name': 'DMARC Record Missing',
  'category': 'dmarc',
  'pattern': '^(?!.*v=DMARC1).*$',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': "Create a DMARC TXT record at '_dmarc.yourdomain.com' with at minimum 'v=DMARC1; p=none; "
                 "rua=mailto:dmarc-reports@yourdomain.com'. Progress to 'p=reject' after analyzing the aggregate "
                 'report data.'},
 {'check_name': 'DMARC Subdomain Policy Missing',
  'category': 'dmarc',
  'pattern': 'v=DMARC1;(?!.*sp=).*p=(?:quarantine|reject)',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': "Add an explicit 'sp=' tag to your DMARC record to define the policy for subdomains (e.g., "
                 "'sp=reject'). Without it, subdomains inherit the organizational domain policy which may not match "
                 'your intended enforcement.'},
 {'check_name': 'DMARC Relaxed SPF Alignment',
  'category': 'dmarc',
  'pattern': 'v=DMARC1;.*aspf=r',
  'severity': 'LOW',
  'cvss': '3.1',
  'remediation': "Consider tightening SPF alignment to strict mode ('aspf=s') if your infrastructure allows it, "
                 'ensuring the RFC5321.MailFrom domain exactly matches the header From domain. Relaxed mode may permit '
                 'organizational domain spoofing in some scenarios.'},
 {'check_name': 'DMARC Relaxed DKIM Alignment',
  'category': 'dmarc',
  'pattern': 'v=DMARC1;.*adkim=r',
  'severity': 'LOW',
  'cvss': '3.1',
  'remediation': "Evaluate whether strict DKIM alignment ('adkim=s') is feasible for your mail flow, requiring the "
                 "DKIM 'd=' tag to exactly match the header From domain. Relaxed alignment ('adkim=r') accepts any "
                 'subdomain match which reduces security posture.'},
 {'check_name': 'DMARC Missing RUA Tag',
  'category': 'dmarc',
  'pattern': 'v=DMARC1;(?!.*rua=).*',
  'severity': 'MEDIUM',
  'cvss': '4.3',
  'remediation': "Add an 'rua=' tag specifying a valid mailto URI to receive aggregate DMARC reports (e.g., "
                 "'rua=mailto:dmarc-agg@yourdomain.com'). Without aggregate reports you have no visibility into "
                 'authentication failures and spoofing attempts.'},
 {'check_name': 'DMARC RUF Tag Exposes Sensitive Data',
  'category': 'dmarc',
  'pattern': 'v=DMARC1;.*ruf=mailto:[^;\\s]+',
  'severity': 'MEDIUM',
  'cvss': '4.3',
  'remediation': "Ensure the forensic report destination ('ruf=') is a securely controlled internal mailbox as "
                 'forensic reports may contain full message headers and partial body content. Consider whether '
                 'forensic reporting is necessary given the privacy implications.'},
 {'check_name': 'DMARC Policy Reject No Reporting',
  'category': 'dmarc',
  'pattern': 'v=DMARC1;\\s*p=reject;(?!.*rua=)(?!.*ruf=).*',
  'severity': 'MEDIUM',
  'cvss': '4.3',
  'remediation': "Add 'rua=' and optionally 'ruf=' tags to your DMARC record even at 'p=reject' to maintain visibility "
                 'into authentication failures and potential spoofing attempts. Operating at reject without reporting '
                 'creates a blind spot for ongoing monitoring.'},
 {'check_name': 'DKIM Selector Missing',
  'category': 'dkim',
  'pattern': '^(?!.*v=DKIM1).*$',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Generate a DKIM key pair for each sending mail service and publish the public key as a TXT record at '
                 "'selector._domainkey.yourdomain.com' with 'v=DKIM1; k=rsa; p=<pubkey>'. Configure your mail server "
                 'to sign outbound messages with the corresponding private key.'},
 {'check_name': 'DKIM Weak RSA Key 512-bit',
  'category': 'dkim',
  'pattern': 'v=DKIM1;.*k=rsa;.*p=[A-Za-z0-9+/]{60,88}={0,2}(?!\\S)',
  'severity': 'HIGH',
  'cvss': '8.1',
  'remediation': 'Rotate the DKIM key to a minimum of 2048-bit RSA or an Ed25519 key, as 512-bit keys are trivially '
                 'factorable with modern hardware. Publish the new public key in DNS, update your signing '
                 'configuration, and retire the old key after verifying mail flow.'},
 {'check_name': 'DKIM Weak RSA Key 1024-bit',
  'category': 'dkim',
  'pattern': 'v=DKIM1;.*k=rsa;.*p=[A-Za-z0-9+/]{172,216}={0,2}(?!\\S)',
  'severity': 'MEDIUM',
  'cvss': '5.9',
  'remediation': 'Upgrade 1024-bit DKIM keys to 2048-bit RSA or Ed25519, as 1024-bit RSA is considered insufficient by '
                 'current NIST guidance. Generate a new key pair, publish the public key in DNS, and update your mail '
                 'server signing configuration.'},
 {'check_name': 'DKIM Key Revoked Empty P Tag',
  'category': 'dkim',
  'pattern': 'v=DKIM1;.*p=\\s*;',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': "An empty 'p=' tag signals a revoked DKIM key, which will cause all messages signed with the "
                 'associated private key to fail verification. Generate and publish a new valid DKIM public key and '
                 "update your mail server's signing configuration immediately."},
 {'check_name': 'DKIM Missing Key Type Tag',
  'category': 'dkim',
  'pattern': 'v=DKIM1;(?!.*k=).*p=',
  'severity': 'LOW',
  'cvss': '3.1',
  'remediation': "Explicitly include the 'k=' tag in your DKIM DNS record (e.g., 'k=rsa' or 'k=ed25519') to avoid "
                 "ambiguity in key type interpretation by receiving mail servers. While 'rsa' is the default, explicit "
                 'declaration ensures compatibility and clarity.'},
 {'check_name': 'BIMI Record Missing',
  'category': 'bimi',
  'pattern': '^(?!.*v=BIMI1).*$',
  'severity': 'LOW',
  'cvss': '2.6',
  'remediation': "Publish a BIMI TXT record at 'default._bimi.yourdomain.com' with 'v=BIMI1; "
                 "l=https://yourdomain.com/logo.svg; a=https://yourdomain.com/cert.pem' to enable brand indicator "
                 "display. BIMI requires a DMARC policy of at least 'p=quarantine' to function."},
 {'check_name': 'BIMI Invalid SVG Logo URL',
  'category': 'bimi',
  'pattern': 'v=BIMI1;.*l=(?!https://)\\S+',
  'severity': 'MEDIUM',
  'cvss': '4.3',
  'remediation': 'Ensure the BIMI logo URL uses HTTPS and points to a publicly accessible, properly formatted SVG Tiny '
                 'PS file. HTTP or unreachable URLs will cause BIMI to fail silently in supporting mail clients.'},
 {'check_name': 'BIMI Missing VMC Authority Certificate',
  'category': 'bimi',
  'pattern': 'v=BIMI1;.*l=https://[^;]+;(?!.*a=https://).*',
  'severity': 'MEDIUM',
  'cvss': '4.3',
  'remediation': "Obtain a Verified Mark Certificate (VMC) from an accredited authority and add the 'a=' tag pointing "
                 'to the PEM file URL in your BIMI record. Without a VMC, major mailbox providers like Google and '
                 'Yahoo will not display the brand indicator.'},
 {'check_name': 'BIMI Record at Wrong DNS Location',
  'category': 'bimi',
  'pattern': 'v=BIMI1;.*l=',
  'severity': 'LOW',
  'cvss': '2.6',
  'remediation': "Verify that the BIMI TXT record is published specifically at 'default._bimi.yourdomain.com' and not "
                 'at the apex or another subdomain. Incorrect placement will prevent mail clients and receivers from '
                 'locating the BIMI assertion.'},
 {'check_name': 'BIMI Policy Below Quarantine',
  'category': 'bimi',
  'pattern': 'v=BIMI1;.*l=https://',
  'severity': 'MEDIUM',
  'cvss': '4.3',
  'remediation': "BIMI requires an accompanying DMARC policy of 'p=quarantine' or 'p=reject' to be honored by "
                 'receiving mail providers. Ensure your DMARC record enforces at least quarantine before expecting '
                 'BIMI to activate logo display.'},
 {'check_name': 'MTA-STS Policy Missing',
  'category': 'mta_sts',
  'pattern': '^(?!.*v=STSv1).*$',
  'severity': 'HIGH',
  'cvss': '7.4',
  'remediation': "Publish an MTA-STS DNS TXT record at '_mta-sts.yourdomain.com' (e.g., 'v=STSv1; id=20240101000000Z') "
                 "and host a policy file at 'https://mta-sts.yourdomain.com/.well-known/mta-sts.txt' specifying "
                 "'enforce' mode and allowed MX hosts."},
 {'check_name': 'MTA-STS Policy Mode Testing',
  'category': 'mta_sts',
  'pattern': 'mode:\\s*testing',
  'severity': 'MEDIUM',
  'cvss': '5.9',
  'remediation': "Transition the MTA-STS policy mode from 'testing' to 'enforce' after validating that all inbound MX "
                 'hosts present valid TLS certificates matching the policy. Testing mode reports failures but does not '
                 'prevent unauthenticated delivery.'},
 {'check_name': 'MTA-STS Policy Mode None',
  'category': 'mta_sts',
  'pattern': 'mode:\\s*none',
  'severity': 'HIGH',
  'cvss': '7.4',
  'remediation': "Change the MTA-STS policy mode from 'none' (which signals revocation) to 'enforce' after ensuring "
                 "your MX TLS configuration is valid. A 'none' mode tells senders to disable any previously cached "
                 'MTA-STS enforcement for your domain.'},
 {'check_name': 'MTA-STS Short Max Age',
  'category': 'mta_sts',
  'pattern': 'max_age:\\s*([1-9]\\d{0,4})(?!\\d)',
  'severity': 'LOW',
  'cvss': '3.7',
  'remediation': "Increase the MTA-STS policy 'max_age' to the recommended value of 604800 seconds (7 days) or higher "
                 '(up to 31557600). A very short max_age reduces the effectiveness of cached policy enforcement '
                 'between sending server refreshes.'},
 {'check_name': 'MTA-STS Missing MX Entry',
  'category': 'mta_sts',
  'pattern': 'mode:\\s*enforce(?!.*mx:)',
  'severity': 'HIGH',
  'cvss': '7.4',
  'remediation': "Add at least one 'mx:' line to your MTA-STS policy file listing each MX hostname (or wildcard) that "
                 'is authorized to receive mail for your domain. Without MX entries, the policy file is invalid and '
                 'enforcement cannot occur.'},
 {'check_name': 'DANE TLSA Record Missing',
  'category': 'dane',
  'pattern': '^(?!.*\\d \\d \\d [0-9A-Fa-f]{64,}).*$',
  'severity': 'HIGH',
  'cvss': '7.4',
  'remediation': "Publish a DANE TLSA record at '_25._tcp.mail.yourdomain.com' referencing your MX host's TLS "
                 'certificate or public key (e.g., usage 3, selector 1, matching type 1). DANE requires DNSSEC to be '
                 'enabled on the zone to provide security guarantees.'},
 {'check_name': 'DANE TLSA Weak Matching Type MD5',
  'category': 'dane',
  'pattern': '\\d \\d 0 [0-9A-Fa-f]+',
  'severity': 'HIGH',
  'cvss': '8.1',
  'remediation': 'Replace TLSA records using matching type 0 (full certificate/key data without hashing) or any '
                 'MD5-based approach with matching type 1 (SHA-256) or type 2 (SHA-512). Matching type 1 or 2 are the '
                 'standards recommended by RFC 7671.'},
 {'check_name': 'DANE TLSA Usage Mode 0 PKIX-TA',
  'category': 'dane',
  'pattern': '^0 [12] [12] [0-9A-Fa-f]{64}',
  'severity': 'MEDIUM',
  'cvss': '5.9',
  'remediation': 'Consider migrating TLSA records from usage type 0 (PKIX-TA) to usage type 3 (DANE-EE) which pins the '
                 'end-entity certificate directly and removes the dependency on the public CA hierarchy. DANE-EE '
                 'provides stronger guarantees for SMTP security.'},
 {'check_name': 'DANE TLSA Record Stale After Certificate Renewal',
  'category': 'dane',
  'pattern': '3 1 1 [0-9A-Fa-f]{64}',
  'severity': 'HIGH',
  'cvss': '7.4',
  'remediation': 'After renewing a TLS certificate, update the corresponding DANE TLSA record with the new '
                 "certificate's public key hash before deploying the new certificate. Stale TLSA records will cause "
                 'DANE-validating senders to reject TLS connections entirely.'},
 {'check_name': 'TLS-RPT Record Missing',
  'category': 'tls_rpt',
  'pattern': '^(?!.*v=TLSRPTv1).*$',
  'severity': 'MEDIUM',
  'cvss': '4.3',
  'remediation': "Publish a TLS-RPT TXT record at '_smtp._tls.yourdomain.com' with 'v=TLSRPTv1; "
                 "rua=mailto:tls-reports@yourdomain.com' to receive JSON reports on TLS negotiation failures. TLS-RPT "
                 'is required for MTA-STS and DANE deployments to enable failure visibility.'},
 {'check_name': 'TLS-RPT Missing RUA Tag',
  'category': 'tls_rpt',
  'pattern': 'v=TLSRPTv1;(?!.*rua=).*',
  'severity': 'MEDIUM',
  'cvss': '4.3',
  'remediation': "Add a valid 'rua=' tag to your TLS-RPT record pointing to either a mailto URI or an HTTPS endpoint "
                 'that accepts JSON report submissions. Without a reporting URI the TLS-RPT record is non-functional '
                 'and provides no operational benefit.'},
 {'check_name': 'TLS-RPT RUA Using HTTP Instead of HTTPS',
  'category': 'tls_rpt',
  'pattern': 'v=TLSRPTv1;.*rua=https?://(?!.*https://)',
  'severity': 'MEDIUM',
  'cvss': '4.3',
  'remediation': "Ensure any HTTPS reporting endpoint specified in the 'rua=' tag uses a valid TLS certificate and "
                 "strictly HTTPS (not HTTP). Replace any 'http://' report URIs with 'https://' equivalents to protect "
                 'the integrity and confidentiality of submitted TLS failure reports.'}]

"""dns_deep_checks — generated dev-time by Claude. Recon module asset.
"""

DNS_DEEP_CHECKS = [{'check_name': 'Active Directory LDAP SRV Record Disclosure',
  'record_type': 'SRV',
  'detection': 'Query _ldap._tcp.<domain> and _ldap._tcp.dc._msdcs.<domain> for SRV records; presence exposes internal '
               'DC hostnames, ports, and AD forest structure to unauthenticated requestors.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Restrict SRV record visibility via split-horizon DNS so internal AD SRV records are only resolvable '
                 'from internal networks.'},
 {'check_name': 'Active Directory Kerberos SRV Record Disclosure',
  'record_type': 'SRV',
  'detection': 'Query _kerberos._tcp.<domain> and _kerberos._udp.<domain>; returned records reveal KDC hostnames and '
               'ports, enabling targeted Kerberoasting or AS-REP roasting reconnaissance.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Implement split-horizon DNS to prevent external resolution of _kerberos SRV records.'},
 {'check_name': 'Autodiscover SRV Record Disclosure',
  'record_type': 'SRV',
  'detection': 'Query _autodiscover._tcp.<domain> for SRV records; exposed records reveal internal mail server '
               'infrastructure and Exchange/O365 endpoints usable in credential-harvesting attacks.',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Remove or restrict _autodiscover SRV records to internal DNS views; use HTTPS-only autodiscover with '
                 'certificate pinning.'},
 {'check_name': 'SIP/VoIP SRV Record Disclosure',
  'record_type': 'SRV',
  'detection': 'Query _sip._tcp, _sip._udp, _sips._tcp, and _sipfederationtls._tcp for SRV records; exposed records '
               'disclose VoIP infrastructure endpoints enabling toll fraud and MITM attacks.',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Limit SIP SRV records to authenticated internal resolvers and enforce TLS on all SIP '
                 'communications.'},
 {'check_name': 'HINFO Record CPU/OS Disclosure',
  'record_type': 'HINFO',
  'detection': 'Query HINFO records for target hostnames; presence of HINFO records discloses CPU architecture and '
               'operating system strings, directly aiding OS-targeted exploit selection.',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Remove all HINFO records from public-facing DNS zones immediately.'},
 {'check_name': 'Missing Glue Records for Delegated Zones',
  'record_type': 'NS',
  'detection': 'For each delegated child zone, verify that glue A/AAAA records exist in the parent zone for '
               'in-bailiwick name servers; missing glue causes resolution failures and can be exploited for lame '
               'delegation attacks.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Add glue records for all in-bailiwick name servers in the parent zone delegation.'},
 {'check_name': 'Mismatched NS Records (Parent vs Child)',
  'record_type': 'NS',
  'detection': 'Compare NS records returned by the parent zone (TLD/registrar) with those returned by the '
               'authoritative servers themselves; discrepancies indicate stale delegation or hijackable orphaned NS '
               'entries.',
  'severity': 'HIGH',
  'cvss': '8.1',
  'remediation': 'Synchronize NS records between registrar delegation and authoritative zone file; remove any orphaned '
                 'or stale NS entries.'},
 {'check_name': 'Lame DNS Delegation',
  'record_type': 'NS',
  'detection': "Query each listed NS server directly for the zone's SOA record; if an NS server does not return an "
               'authoritative answer, it is lame and can be hijacked if the domain registration lapses.',
  'severity': 'HIGH',
  'cvss': '8.1',
  'remediation': 'Remove non-authoritative NS entries from the zone and ensure all listed name servers are properly '
                 'configured and authoritative.'},
 {'check_name': 'Suspiciously Low TTL Detection (<60 seconds)',
  'record_type': 'A',
  'detection': 'Retrieve TTL values for all A, AAAA, MX, and CNAME records; TTLs below 60 seconds suggest active '
               'fast-flux DNS infrastructure commonly used in botnet C2 or phishing campaigns.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Investigate records with sub-60s TTLs for compromise indicators; set minimum TTL to 300 seconds for '
                 'legitimate infrastructure.'},
 {'check_name': 'Excessively High TTL Detection (>86400 seconds)',
  'record_type': 'A',
  'detection': 'Check TTL values across all record types; TTLs exceeding 86400 seconds (24 hours) mean DNS changes '
               'propagate slowly, extending the impact window of DNS hijacking or misconfiguration incidents.',
  'severity': 'LOW',
  'cvss': '3.7',
  'remediation': 'Set TTLs to 3600–86400 seconds for stable records and lower TTLs to 300 seconds before planned '
                 'infrastructure changes.'},
 {'check_name': 'Zone Transfer via AXFR (Full Zone Transfer)',
  'record_type': 'AXFR',
  'detection': 'Send an AXFR query (dig axfr @<nameserver> <zone>) to each authoritative name server; a successful '
               'response dumps the entire zone, exposing all hostnames, IPs, and internal network topology.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Restrict AXFR queries to authorized secondary name servers by IP ACL in the DNS server '
                 'configuration.'},
 {'check_name': 'Incremental Zone Transfer via IXFR',
  'record_type': 'IXFR',
  'detection': 'Send an IXFR query with a low serial number to each authoritative NS; if allowed, an attacker can '
               'enumerate all recent zone changes and track infrastructure modifications over time.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Apply the same IP-based ACL restrictions to IXFR as to AXFR; allow only from legitimate secondary '
                 'resolvers.'},
 {'check_name': 'DNSSEC Missing DS Record',
  'record_type': 'DS',
  'detection': "Query the parent zone for DS records corresponding to the child zone's DNSKEY; absence of a DS record "
               'means DNSSEC validation chain is broken and the zone is vulnerable to DNS spoofing.',
  'severity': 'HIGH',
  'cvss': '7.4',
  'remediation': "Publish DS records at the parent/registrar level matching the child zone's KSK DNSKEY to complete "
                 'the chain of trust.'},
 {'check_name': 'DNSSEC DNSKEY Algorithm Weakness',
  'record_type': 'DNSKEY',
  'detection': 'Retrieve DNSKEY records and check algorithm numbers; algorithms 1 (RSA/MD5), 3 (DSA/SHA1), and 5 '
               '(RSA/SHA1) are deprecated and vulnerable to collision attacks.',
  'severity': 'HIGH',
  'cvss': '7.4',
  'remediation': 'Migrate to DNSKEY algorithm 13 (ECDSA P-256/SHA-256) or 14 (ECDSA P-384/SHA-384) per RFC 8624.'},
 {'check_name': 'DNSSEC Signature Expiry (RRSIG Expiration Check)',
  'record_type': 'RRSIG',
  'detection': 'Query RRSIG records for all signed RRsets and compare signature expiration timestamps against current '
               'time; expired or near-expiry signatures cause SERVFAIL for validating resolvers, effectively causing '
               'DoS.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Automate DNSSEC key rollover and signature refresh; ensure ZSK signatures are renewed with at least '
                 '7 days validity buffer.'},
 {'check_name': 'DNSSEC Validation Gap (Zone Signed but Insecure Delegation)',
  'record_type': 'DS',
  'detection': 'Verify that all subdomains delegated from a DNSSEC-signed parent also have DS records published; '
               'unsigned delegated subdomains create validation gaps exploitable for spoofing attacks against those '
               'subdomains.',
  'severity': 'MEDIUM',
  'cvss': '6.8',
  'remediation': 'Ensure all delegated child zones are either DNSSEC-signed with DS records in the parent or '
                 'explicitly marked as opt-out in NSEC3.'},
 {'check_name': 'NSEC Zone Walking (DNSSEC Enumeration)',
  'record_type': 'NSEC',
  'detection': 'Query for NSEC records starting from the zone apex and walk the chain by querying non-existent names; '
               'NSEC allows complete enumeration of all zone labels without requiring zone transfer.',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Migrate from NSEC to NSEC3 with opt-out and a non-predictable salt to prevent zone walking '
                 'enumeration.'},
 {'check_name': 'CAA Record Missing (Certificate Authority Authorization)',
  'record_type': 'CAA',
  'detection': 'Query CAA records for the target domain; absence of CAA records permits any trusted CA to issue '
               'certificates for the domain, enabling misissued certificate attacks.',
  'severity': 'MEDIUM',
  'cvss': '5.9',
  'remediation': 'Publish CAA records specifying only authorized CAs (e.g., 0 issue "letsencrypt.org") and include an '
                 'iodef contact for misissuance reports.'},
 {'check_name': 'CAA Record Wildcard Issuance Unrestricted',
  'record_type': 'CAA',
  'detection': "Check CAA records for the presence of an 'issuewild' tag; if absent while 'issue' is present, wildcard "
               'certificate issuance policy may be ambiguous or permissive depending on CA interpretation.',
  'severity': 'LOW',
  'cvss': '3.7',
  'remediation': "Explicitly add a CAA 'issuewild' record either permitting a specific CA or set to '0 issuewild "
                 '";"\' to deny all wildcard certificate issuance.'},
 {'check_name': 'Wildcard DNS Record Detection',
  'record_type': 'A',
  'detection': 'Query random non-existent subdomains (e.g., randomstring123.<domain>); if an A or AAAA record is '
               'returned, a wildcard DNS entry exists, masking subdomain enumeration and potentially hosting malicious '
               'content.',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Remove wildcard DNS entries unless operationally required; implement explicit subdomain records and '
                 'monitor for unexpected wildcard-matched traffic.'},
 {'check_name': 'DNS-based Subdomain Enumeration via NXDOMAIN Analysis',
  'record_type': 'A',
  'detection': 'Compare responses to known-valid vs known-invalid subdomains; inconsistent NXDOMAIN responses, custom '
               'NXDOMAIN pages, or NOERROR with empty answers indicate subdomain probing mitigations are absent.',
  'severity': 'INFO',
  'cvss': '3.7',
  'remediation': 'Implement DNS rate-limiting (RRL), deploy a DNS firewall, and return consistent NXDOMAIN for '
                 'non-existent names to hinder enumeration.'},
 {'check_name': 'DNS-over-HTTPS (DoH) Endpoint Detection',
  'record_type': 'HTTPS',
  'detection': 'Query for HTTPS/SVCB records and probe /.well-known/dns-query endpoint via HTTP GET; an exposed DoH '
               'resolver may bypass corporate DNS controls and audit logging infrastructure.',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Restrict DoH resolver access to authorized clients only; log all DoH queries and block unauthorized '
                 'DoH endpoints at the network perimeter.'},
 {'check_name': 'DNS-over-TLS (DoT) Port 853 Exposure',
  'record_type': 'A',
  'detection': "Attempt a TLS connection on port 853 to the target's authoritative or recursive resolvers; open DoT "
               'without proper access controls allows external recursive queries that bypass DNS filtering.',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Restrict DoT (port 853) to authorized client IP ranges and enforce mutual TLS authentication where '
                 'possible.'},
 {'check_name': 'DNS-over-HTTPS Fingerprinting via SVCB/HTTPS Record',
  'record_type': 'HTTPS',
  'detection': 'Query HTTPS/SVCB records for _dns.<domain> or the apex; returned records may disclose DoH endpoint '
               'paths, supported HTTP versions, and ALPN protocols, fingerprinting resolver software and version.',
  'severity': 'INFO',
  'cvss': '3.1',
  'remediation': 'Minimize information exposed in HTTPS/SVCB records to only operationally necessary parameters.'},
 {'check_name': 'SOA Serial Number Disclosure and Enumeration',
  'record_type': 'SOA',
  'detection': 'Query SOA records from all authoritative name servers; sequential date-based serials reveal zone '
               'update frequency and timing patterns, while inconsistent serials across NS servers indicate '
               'synchronization failures.',
  'severity': 'LOW',
  'cvss': '3.7',
  'remediation': "Use monotonically increasing non-date-based serials or implement BIND's timestamp format to obscure "
                 'update patterns.'},
 {'check_name': 'SPF Record Missing or Permissive (+all)',
  'record_type': 'TXT',
  'detection': "Query TXT records for SPF policy; absence of SPF or presence of '+all' (pass all) allows unrestricted "
               'email spoofing from any source on behalf of the domain.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': "Publish a restrictive SPF record ending in '-all' or '~all' listing only authorized mail-sending IP "
                 'ranges and includes.'},
 {'check_name': 'Multiple SPF Records (RFC 7208 Violation)',
  'record_type': 'TXT',
  'detection': 'Retrieve all TXT records for the domain apex; RFC 7208 forbids more than one SPF record per name, and '
               'multiple SPF TXT records cause undefined behavior in receiving mail server validation.',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Merge all SPF mechanisms into a single TXT record and remove duplicate SPF entries.'},
 {'check_name': 'SPF DNS Lookup Limit Exceeded (>10 Lookups)',
  'record_type': 'TXT',
  'detection': 'Recursively count SPF DNS-querying mechanisms (include, a, mx, ptr, exists, redirect); exceeding 10 '
               'DNS lookups causes SPF PermError, resulting in SPF validation failures and potential spam filter '
               'bypass.',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Flatten SPF records by replacing include chains with explicit IP4/IP6 ranges to stay within the 10 '
                 'DNS lookup limit.'},
 {'check_name': 'DMARC Record Missing',
  'record_type': 'TXT',
  'detection': 'Query TXT records at _dmarc.<domain>; absence means no policy enforcement for SPF/DKIM alignment '
               'failures, allowing email spoofing with no aggregate or forensic reporting.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Publish a DMARC record at _dmarc.<domain> with at minimum p=quarantine and an rua address for '
                 'aggregate reports.'},
 {'check_name': 'DMARC Policy Set to None (p=none)',
  'record_type': 'TXT',
  'detection': "Query _dmarc.<domain> TXT record and parse the 'p' tag; p=none provides monitoring only with zero "
               'enforcement, allowing spoofed emails to reach inboxes without rejection or quarantine.',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Transition DMARC policy from p=none to p=quarantine and ultimately p=reject after validating '
                 'legitimate mail flows.'},
 {'check_name': 'DKIM Selector Public Key Exposure and Weak Key',
  'record_type': 'TXT',
  'detection': 'Query known DKIM selectors (default._domainkey, google._domainkey, etc.) for TXT records containing '
               'RSA public keys; keys shorter than 2048 bits are vulnerable to factorization attacks.',
  'severity': 'HIGH',
  'cvss': '7.4',
  'remediation': 'Rotate DKIM keys to minimum 2048-bit RSA or Ed25519; remove deprecated selectors no longer in use.'},
 {'check_name': 'Dangling CNAME to Expired/Unclaimed Resource (Subdomain Takeover)',
  'record_type': 'CNAME',
  'detection': 'Resolve all CNAME records and check if the canonical target resolves to NXDOMAIN or returns a '
               "service-specific 'unclaimed' page; dangling CNAMEs to cloud providers (GitHub Pages, Heroku, etc.) "
               'allow takeover.',
  'severity': 'HIGH',
  'cvss': '8.1',
  'remediation': 'Remove or update CNAME records pointing to decommissioned resources; audit all CNAME targets '
                 'periodically against active service registrations.'},
 {'check_name': 'NS Record Pointing to Unregistered Domain',
  'record_type': 'NS',
  'detection': 'Resolve each NS hostname; if any NS record points to a domain that returns NXDOMAIN or has an '
               'available registration status, the entire zone is vulnerable to hostile takeover by registering that '
               'domain.',
  'severity': 'CRITICAL',
  'cvss': '9.8',
  'remediation': 'Immediately register or reclaim any unregistered NS hostnames and update NS records to point to '
                 'controlled, registered name servers.'},
 {'check_name': 'PTR Record Reverse DNS Mismatch',
  'record_type': 'PTR',
  'detection': 'Perform reverse DNS lookups on all A/AAAA records and verify forward-confirmed reverse DNS (FCrDNS); '
               'mismatches indicate misconfiguration and may cause mail delivery failures or security control '
               'bypasses.',
  'severity': 'LOW',
  'cvss': '3.7',
  'remediation': 'Configure PTR records in reverse DNS zones to match forward A/AAAA records for all public-facing IP '
                 'addresses.'},
 {'check_name': 'TXT Record Sensitive Data Leakage',
  'record_type': 'TXT',
  'detection': 'Enumerate all TXT records at the apex and common subdomains; TXT records may inadvertently expose '
               'internal service verification tokens, API keys, internal network details, or legacy service '
               'credentials.',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Audit all TXT records and remove any containing sensitive verification tokens, legacy service keys, '
                 'or internal infrastructure information no longer in use.'},
 {'check_name': 'MX Record Pointing to CNAME (RFC 2181 Violation)',
  'record_type': 'MX',
  'detection': 'Resolve MX record hostnames and check if any resolve as CNAMEs rather than directly to A/AAAA records; '
               'RFC 2181 prohibits MX targets from being CNAMEs, causing unpredictable mail delivery behavior.',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Replace CNAME-targeted MX records with direct A/AAAA record hostnames as required by RFC 2181.'},
 {'check_name': 'Open DNS Resolver Detection',
  'record_type': 'A',
  'detection': "Send a recursive query for an external domain (e.g., google.com) to the target's DNS server IPs; if a "
               'full answer is returned, the server is an open recursive resolver usable for DNS amplification DDoS '
               'attacks.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Disable recursion on authoritative DNS servers or restrict recursive queries to authorized client IP '
                 'ranges only.'},
 {'check_name': 'DNS Amplification DDoS Vector (ANY Query Response Size)',
  'record_type': 'ANY',
  'detection': "Send DNS ANY queries to the target's name servers and measure response size vs query size; "
               'amplification factors above 10x indicate the server can be abused as a DDoS reflector/amplifier.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Implement Response Rate Limiting (RRL) on all authoritative name servers and return minimal '
                 'responses to ANY queries per RFC 8482.'},
 {'check_name': 'DNS Cache Poisoning Vulnerability (Source Port Randomization Check)',
  'record_type': 'A',
  'detection': 'Send multiple DNS queries and observe source port variation; predictable or sequential source ports '
               'indicate inadequate port randomization, making the resolver vulnerable to Kaminsky-style cache '
               'poisoning attacks.',
  'severity': 'HIGH',
  'cvss': '8.1',
  'remediation': 'Enable full source port randomization (0–65535 range) on all recursive resolvers and deploy DNSSEC '
                 'validation to cryptographically prevent cache poisoning.'},
 {'check_name': 'TLSA / DANE Record Misconfiguration',
  'record_type': 'TLSA',
  'detection': 'Query TLSA records at _<port>._<proto>.<hostname> and validate certificate usage, selector, and '
               'matching type fields against the actual TLS certificate served; mismatches cause DANE validation '
               'failures in supporting clients.',
  'severity': 'MEDIUM',
  'cvss': '5.9',
  'remediation': 'Regenerate TLSA records after any certificate renewal and automate TLSA record updates as part of '
                 'the certificate lifecycle management process.'},
 {'check_name': 'Global Traffic Manager / Anycast DNS Health Check Bypass',
  'record_type': 'A',
  'detection': 'Query the target domain from multiple geographically distributed vantage points and compare responses; '
               'inconsistent A/AAAA responses may reveal failed health checks returning offline node IPs, causing '
               'service unavailability.',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Configure DNS health check thresholds appropriately and ensure failed nodes are promptly removed '
                 'from DNS rotation with adequate TTL management.'}]

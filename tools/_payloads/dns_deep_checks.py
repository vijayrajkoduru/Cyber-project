"""dns_deep_checks — generated dev-time by Claude. Recon module asset.
"""

DNS_DEEP_CHECKS = [{'check_name': 'Active Directory LDAP SRV Record Disclosure',
  'record_type': 'SRV',
  'detection': 'Query _ldap._tcp.<domain> and _ldap._tcp.dc._msdcs.<domain> for SRV records; presence exposes internal '
               'DC hostnames, ports, and priorities to unauthenticated requesters.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Restrict SRV record visibility to internal DNS zones and block external recursive resolution of '
                 '_msdcs subtrees at the authoritative nameserver.'},
 {'check_name': 'Kerberos SRV Record Disclosure',
  'record_type': 'SRV',
  'detection': 'Query _kerberos._tcp.<domain> and _kerberos._udp.<domain>; exposed records reveal KDC hostnames and '
               'ports enabling targeted Kerberoasting or AS-REP roasting reconnaissance.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Limit _kerberos SRV records to internal split-horizon DNS and deny external authoritative answers '
                 'for Kerberos service locators.'},
 {'check_name': 'Autodiscover SRV Record Exposure',
  'record_type': 'SRV',
  'detection': 'Query _autodiscover._tcp.<domain> for SRV records; a publicly visible record discloses internal '
               'Exchange or Office 365 hybrid mail infrastructure endpoints.',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Point _autodiscover SRV records only to cloud endpoints or remove them if Autodiscover redirect via '
                 'HTTPS CNAME is sufficient.'},
 {'check_name': 'Global Catalog SRV Record Disclosure',
  'record_type': 'SRV',
  'detection': 'Query _gc._tcp.<domain> and _gc._tcp.<site>._sites.<domain>; exposed Global Catalog SRV records reveal '
               'forest topology and DC port 3268/3269 services.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Segregate Global Catalog SRV records to an internal-only DNS zone inaccessible from external '
                 'resolvers.'},
 {'check_name': 'HINFO Record Hardware/OS Disclosure',
  'record_type': 'HINFO',
  'detection': 'Query HINFO record type for the target domain and subdomains; presence returns CPU architecture and OS '
               'string, directly aiding attacker target profiling.',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Delete all HINFO records from public-facing DNS zones as they serve no operational purpose in modern '
                 'infrastructure.'},
 {'check_name': 'Missing Glue Records for Delegated Zones',
  'record_type': 'NS',
  'detection': 'Enumerate NS records for delegated subdomains and verify whether corresponding A/AAAA glue records are '
               'present at the parent zone; absence causes lame delegation and potential hijack via re-registration.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Add glue A/AAAA records for all in-bailiwick nameservers at the parent registrar or TLD registry.'},
 {'check_name': 'Mismatched NS Records Between Registrar and Authoritative Zone',
  'record_type': 'NS',
  'detection': 'Compare NS records returned by the TLD/registrar delegation with NS records returned by the '
               'authoritative servers themselves; discrepancies indicate lame delegation or hijack risk.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Synchronize NS records at the registrar with the actual authoritative nameservers configured in the '
                 'zone file immediately.'},
 {'check_name': 'Suspiciously Low TTL Detection (<60 seconds)',
  'record_type': 'A',
  'detection': 'Inspect TTL values on A, AAAA, and CNAME records; TTLs below 60 seconds suggest active fast-flux '
               'networks, ongoing DNS hijacking operations, or misconfigured automation.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Set minimum TTL to at least 300 seconds for production records and investigate records with TTL < 60 '
                 'for compromise indicators.'},
 {'check_name': 'Excessively High TTL Detection (>86400 seconds)',
  'record_type': 'A',
  'detection': 'Check TTL values across all record types; TTLs exceeding 86400 seconds (24 hours) mean that after a '
               'compromise or misconfiguration, stale records persist in resolver caches for extended periods.',
  'severity': 'MEDIUM',
  'cvss': '4.3',
  'remediation': 'Cap TTL values at 3600–86400 seconds and reduce TTLs to 300 seconds before any planned '
                 'infrastructure changes.'},
 {'check_name': 'Zone Transfer via AXFR Allowed',
  'record_type': 'AXFR',
  'detection': 'Send a DNS AXFR request (dig AXFR @<ns> <domain>) to each authoritative nameserver; a successful '
               'transfer dumps the entire zone file, exposing all hostnames and IP addresses.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Restrict AXFR transfers using TSIG authentication and ACLs limited strictly to known secondary '
                 'nameserver IP addresses.'},
 {'check_name': 'Incremental Zone Transfer via IXFR Allowed',
  'record_type': 'IXFR',
  'detection': 'Attempt an IXFR query against authoritative nameservers; if permitted without authentication, an '
               'attacker can track incremental zone changes and map infrastructure evolution over time.',
  'severity': 'HIGH',
  'cvss': '6.5',
  'remediation': 'Apply the same TSIG-based ACL restrictions to IXFR as applied to AXFR on all authoritative '
                 'nameservers.'},
 {'check_name': 'DNSSEC Missing or Not Deployed',
  'record_type': 'DS',
  'detection': 'Query the parent zone for DS records and query the domain for DNSKEY records; absence of both '
               'indicates DNSSEC is not deployed, leaving responses vulnerable to cache poisoning.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Generate KSK/ZSK keypairs, sign the zone, publish DNSKEY records, and submit DS records to the '
                 'parent zone via the registrar.'},
 {'check_name': 'DNSSEC Signature Expiry (RRSIG Expiration)',
  'record_type': 'RRSIG',
  'detection': 'Query RRSIG records for all signed record sets and compare the signature expiration timestamp to the '
               'current date; expired RRSIGs cause SERVFAIL for validating resolvers, effectively a denial of service.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Automate RRSIG renewal with a re-signing cron job or DNS provider feature ensuring signatures are '
                 'renewed at least 7 days before expiry.'},
 {'check_name': 'DNSSEC Algorithm Weakness (MD5/SHA-1 DNSKEY)',
  'record_type': 'DNSKEY',
  'detection': 'Inspect DNSKEY record algorithm field; algorithm values 1 (RSA/MD5) or 5 (RSA/SHA-1) indicate '
               'cryptographically weak signing algorithms susceptible to collision attacks.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Migrate to ECDSA P-256 (algorithm 13) or Ed25519 (algorithm 15) DNSKEY records and perform a '
                 'controlled key rollover.'},
 {'check_name': 'Missing NSEC3 Opt-Out Leading to Zone Enumeration',
  'record_type': 'NSEC',
  'detection': 'Query for NSEC records in a DNSSEC-signed zone; if NSEC (not NSEC3) is used, walking the chain '
               'enumerates all zone labels, revealing the complete subdomain inventory.',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Replace NSEC with NSEC3 using opt-out and a sufficiently high iteration count (minimum 10) with a '
                 'random salt to prevent zone walking.'},
 {'check_name': 'DNS-over-HTTPS (DoH) Endpoint Fingerprinting',
  'record_type': 'HTTPS',
  'detection': 'Query the HTTPS DNS record type for the domain and probe /.well-known/dns-query over HTTPS; a '
               'misconfigured or overly verbose DoH endpoint may expose server software versions or internal resolver '
               'topology.',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Harden DoH endpoints by suppressing server headers, using a reverse proxy with WAF, and validating '
                 'that only DNS wire-format queries are accepted.'},
 {'check_name': 'DNS-over-TLS (DoT) Availability and Certificate Check',
  'record_type': 'TLSA',
  'detection': 'Attempt a TLS connection to port 853 on the resolver/nameserver; verify the certificate is valid, '
               'matches the hostname, and uses TLS 1.2 or higher — a missing or invalid cert disables DoT security.',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Deploy a valid TLS certificate on port 853, enforce TLS 1.3, and publish a matching TLSA DANE record '
                 'for the nameserver hostname.'},
 {'check_name': 'CAA Record Missing (Certificate Authority Authorization)',
  'record_type': 'CAA',
  'detection': 'Query CAA records for the apex domain and all subdomains hosting services; absence means any CA can '
               'issue certificates for the domain, dramatically increasing mis-issuance risk.',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Publish CAA records restricting issuance to authorized CAs (e.g., 0 issue "letsencrypt.org") '
                 'including an iodef reporting address.'},
 {'check_name': 'CAA Record Wildcard Issuance Permitted Without Restriction',
  'record_type': 'CAA',
  'detection': 'Check whether CAA records include an unrestricted issuewild tag (0 issuewild ";") or omit issuewild '
               'entirely; this allows any CA to issue wildcard certificates for the domain.',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Add an explicit 0 issuewild "<ca>" CAA record limiting wildcard certificate issuance to a single '
                 'trusted CA, or set 0 issuewild ";" to prohibit all wildcard issuance.'},
 {'check_name': 'Wildcard DNS Record Detection',
  'record_type': 'A',
  'detection': 'Query random non-existent subdomains (e.g., zz9rand123.<domain>); if responses return valid A/AAAA '
               'records, a wildcard DNS entry exists, masking subdomain enumeration and potentially routing phishing '
               'traffic.',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Remove wildcard DNS entries unless explicitly required, and use specific host records with '
                 'monitoring for unexpected new subdomain traffic.'},
 {'check_name': 'NXDOMAIN Hijacking by Registrar or ISP',
  'record_type': 'A',
  'detection': 'Query intentionally nonexistent subdomains; if NXDOMAIN is replaced by a redirect A record pointing to '
               'a search/ad page, resolver-level NXDOMAIN hijacking is active, breaking DNSSEC and privacy.',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Configure DNS resolver settings to use NXDOMAIN-clean resolvers (e.g., 1.1.1.1, 9.9.9.9) or operate '
                 'your own recursive resolver with DNSSEC validation enabled.'},
 {'check_name': 'Subdomain Enumeration via NXDOMAIN Differential Timing',
  'record_type': 'A',
  'detection': 'Measure response times between NXDOMAIN responses for known-missing and potentially existing '
               'subdomains; statistically significant timing differences can confirm subdomain existence despite '
               'non-disclosure.',
  'severity': 'LOW',
  'cvss': '3.7',
  'remediation': 'Deploy response rate limiting (RRL) and consistent response timing on authoritative nameservers to '
                 'eliminate timing oracle side channels.'},
 {'check_name': 'Dangling CNAME to Unregistered Domain (Subdomain Takeover)',
  'record_type': 'CNAME',
  'detection': 'Resolve all CNAME records and verify the ultimate target domain is registered and actively responding; '
               'a CNAME pointing to an unregistered or expired domain is takeover-vulnerable.',
  'severity': 'HIGH',
  'cvss': '8.1',
  'remediation': 'Audit all CNAME records regularly, remove or update CNAMEs pointing to decommissioned services, and '
                 'monitor for target domain expiry.'},
 {'check_name': 'SPF Record Permissive +all Directive',
  'record_type': 'TXT',
  'detection': 'Retrieve SPF TXT records and parse for the +all or ~all mechanism; +all allows any host to send mail '
               'on behalf of the domain, enabling trivial email spoofing.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Replace +all or ~all with -all (hard fail) and enumerate all legitimate sending sources explicitly '
                 'in the SPF record.'},
 {'check_name': 'SPF Too Many DNS Lookups (>10 Limit)',
  'record_type': 'TXT',
  'detection': 'Recursively count all DNS lookups required to evaluate the SPF record chain (include, a, mx, ptr, '
               'exists mechanisms); exceeding 10 lookups causes PermError, causing SPF to be ignored by receivers.',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Flatten the SPF record by replacing include chains with explicit IP4/IP6 ranges and reduce total '
                 'DNS-querying mechanisms to 10 or fewer.'},
 {'check_name': 'DMARC Record Missing',
  'record_type': 'TXT',
  'detection': 'Query _dmarc.<domain> for a TXT record; absence means no DMARC policy is enforced, allowing domain '
               'spoofing in email with no aggregate reporting or rejection.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Publish a DMARC TXT record at _dmarc.<domain> with at minimum p=quarantine and an rua address, then '
                 'escalate to p=reject after validating legitimate mail flows.'},
 {'check_name': 'DMARC Policy Set to None (No Enforcement)',
  'record_type': 'TXT',
  'detection': 'Parse the DMARC TXT record at _dmarc.<domain>; a p=none policy means spoofed emails are delivered '
               'without restriction, providing visibility only with no protective action.',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Escalate the DMARC policy from p=none to p=quarantine and ultimately p=reject after reviewing '
                 'aggregate reports to ensure no legitimate mail is blocked.'},
 {'check_name': 'DKIM Key Exposure or Weak Key Length',
  'record_type': 'TXT',
  'detection': 'Query known DKIM selector TXT records (e.g., default._domainkey, google._domainkey); inspect the p= '
               'field and decode the public key — keys under 1024 bits are cryptographically broken.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Rotate all DKIM keys to RSA-2048 or Ed25519, update selector TXT records, and retire old selectors '
                 'after confirming mail pipeline adoption.'},
 {'check_name': 'MTA-STS DNS Record Missing',
  'record_type': 'TXT',
  'detection': 'Query _mta-sts.<domain> for a TXT record and attempt HTTPS fetch of '
               'https://mta-sts.<domain>/.well-known/mta-sts.txt; absence leaves inbound SMTP vulnerable to downgrade '
               'and MITM attacks.',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Publish an _mta-sts TXT record and host a valid MTA-STS policy file specifying mx hostnames and '
                 'mode: enforce to mandate TLS for inbound mail.'},
 {'check_name': 'TLSA / DANE Record Missing for Mail Server',
  'record_type': 'TLSA',
  'detection': 'Query _25._tcp.<mx-hostname> for TLSA records; absence means DANE is not configured for the mail '
               'server, allowing certificate substitution attacks against SMTP TLS connections.',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Generate TLSA records for all MX hostnames using DANE-TA or DANE-EE usage types and publish them in '
                 'the DNSSEC-signed zone.'},
 {'check_name': 'NS Record Pointing to Unregistered Domain (NS Takeover)',
  'record_type': 'NS',
  'detection': 'Resolve each NS record hostname and verify the domain is registered; NS records pointing to expired or '
               'unregistered nameserver domains allow complete DNS zone hijacking via domain re-registration.',
  'severity': 'HIGH',
  'cvss': '9.1',
  'remediation': 'Immediately re-register or replace any unregistered nameserver domain referenced by NS records and '
                 'update the registrar delegation accordingly.'},
 {'check_name': 'Recursive Query Allowed on Authoritative Nameserver',
  'record_type': 'ANY',
  'detection': 'Send a recursive query (RD bit set) for an external domain to the authoritative nameserver; if it '
               'resolves external names, it is an open recursive resolver enabling cache poisoning and amplification '
               'attacks.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Disable recursion on all authoritative nameservers using the allow-recursion none directive and '
                 'separate recursive and authoritative resolver roles.'},
 {'check_name': 'DNS Amplification via ANY Query',
  'record_type': 'ANY',
  'detection': 'Send a UDP ANY query to the nameserver and measure the response size relative to the query size; a '
               'ratio exceeding 10:1 indicates the server is usable as a DNS amplification reflector.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Configure the nameserver to return minimal responses to ANY queries (minimal-any) and enforce '
                 'response rate limiting (RRL) on UDP responses.'},
 {'check_name': 'SOA Serial Number Information Leakage',
  'record_type': 'SOA',
  'detection': 'Query the SOA record and inspect the serial number format; date-based serials (YYYYMMDDNN) reveal zone '
               'update frequency and timing, while incremental serials expose deployment cadence.',
  'severity': 'LOW',
  'cvss': '3.1',
  'remediation': 'Switch to Unix epoch-based or opaque SOA serial numbers and avoid formats that disclose operational '
                 'patterns or zone update schedules.'},
 {'check_name': 'SOA MNAME Exposing Internal Nameserver',
  'record_type': 'SOA',
  'detection': 'Query the SOA record and resolve the MNAME field; if it resolves to an internal or private IP address, '
               'internal network topology is inadvertently disclosed to external attackers.',
  'severity': 'MEDIUM',
  'cvss': '5.3',
  'remediation': 'Set the SOA MNAME to an externally routable nameserver hostname or a placeholder that does not '
                 'resolve to internal infrastructure.'},
 {'check_name': 'Open DNS Resolver Detection',
  'record_type': 'A',
  'detection': 'Query the nameserver for a domain it is not authoritative for with recursion enabled; successful '
               'external resolution confirms an open recursive resolver accessible for abuse.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Restrict recursive queries using allow-query and allow-recursion ACLs to only trusted internal IP '
                 'ranges on all resolver deployments.'},
 {'check_name': 'DNSSEC Chain of Trust Broken (Missing DS at Parent)',
  'record_type': 'DS',
  'detection': "Query the parent zone for the DS record corresponding to the child zone's KSK; absence breaks the "
               'chain of trust and causes DNSSEC-validating resolvers to return SERVFAIL for all child zone queries.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Submit the correct DS record to the registrar immediately and verify chain-of-trust continuity using '
                 'a DNSSEC debugger such as dnsviz.net.'},
 {'check_name': 'Negative Cache TTL Excessively Long (SOA Minimum)',
  'record_type': 'SOA',
  'detection': 'Inspect the SOA MINIMUM field (negative caching TTL per RFC 2308); values above 3600 seconds mean '
               'NXDOMAIN responses are cached for extended periods, delaying recovery from misconfigurations.',
  'severity': 'LOW',
  'cvss': '3.1',
  'remediation': 'Set the SOA MINIMUM field to 300–900 seconds to allow timely propagation of corrections to negative '
                 'cache entries across resolvers.'},
 {'check_name': 'SRV Record Exposing SIP/VoIP Infrastructure',
  'record_type': 'SRV',
  'detection': 'Query _sip._tcp, _sip._udp, _sips._tcp, and _sipfederationtls._tcp records; exposure reveals VoIP '
               'gateway hostnames, ports, and priorities enabling targeted toll fraud or interception attacks.',
  'severity': 'HIGH',
  'cvss': '7.5',
  'remediation': 'Move SIP SRV records to a private DNS zone, restrict UDP/TCP 5060 and 5061 at the network perimeter, '
                 'and require mutual TLS for all SIP federation.'},
 {'check_name': 'PTR Record Mismatch (Forward-Confirmed Reverse DNS Failure)',
  'record_type': 'PTR',
  'detection': 'Resolve PTR records for all published A/AAAA addresses and verify forward resolution of the returned '
               'hostname matches the original IP; mismatches indicate misconfiguration and cause mail delivery '
               'failures or trust degradation.',
  'severity': 'MEDIUM',
  'cvss': '4.3',
  'remediation': 'Ensure every public-facing IP has a matching PTR record and that the corresponding A/AAAA record '
                 'resolves back to the same IP (FCrDNS compliance).'},
 {'check_name': 'DNS Response Lacking QNAME Minimisation (Privacy Leak)',
  'record_type': 'A',
  'detection': 'Use a controlled authoritative server to observe inbound queries; if the full query name is sent to '
               'each delegation level rather than minimal labels, resolver software lacks QNAME minimisation (RFC '
               '7816), leaking query details.',
  'severity': 'LOW',
  'cvss': '3.7',
  'remediation': 'Enable qname-minimization in the recursive resolver configuration (BIND: qname-minimization strict; '
                 'Unbound: qname-minimisation: yes) to limit label disclosure at each delegation hop.'}]

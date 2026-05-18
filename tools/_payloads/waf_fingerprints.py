"""waf_fingerprints — generated dev-time by Claude. Recon module asset.
"""

WAF_FINGERPRINTS = [
  {
    "provider": "Cloudflare",
    "category": "hybrid",
    "header_signatures": [
      "Server: cloudflare",
      "CF-RAY: [0-9a-f]+-[A-Z]+",
      "CF-Cache-Status: (HIT|MISS|EXPIRED|BYPASS)",
      "CF-Request-ID: [0-9a-f]+"
    ],
    "cookie_signatures": [
      "__cflb=[A-Za-z0-9]+",
      "__cf_bm=[A-Za-z0-9_\\-]+"
    ],
    "body_signatures": [
      "Attention Required\\! \\| Cloudflare",
      "Ray ID: [0-9a-f]+"
    ],
    "block_status": 403
  },
  {
    "provider": "Cloudflare",
    "category": "hybrid",
    "header_signatures": [
      "CF-RAY: [0-9a-f]{16}-[A-Z]{3}",
      "CF-Cache-Status: DYNAMIC",
      "Server: cloudflare"
    ],
    "cookie_signatures": [
      "__cfduid=[a-z0-9]+"
    ],
    "body_signatures": [
      "cloudflare\\.com/5xx-errors",
      "DDoS protection by Cloudflare"
    ],
    "block_status": 429
  },
  {
    "provider": "Akamai",
    "category": "hybrid",
    "header_signatures": [
      "X-Check-Cacheable: (YES|NO)",
      "X-Akamai-Request-ID: [a-z0-9]+",
      "X-Cache: TCP_(HIT|MISS)_from_akamai",
      "Server: AkamaiGHost"
    ],
    "cookie_signatures": [
      "ak_bmsc=[A-Za-z0-9%+/]+"
    ],
    "body_signatures": [
      "Reference #[0-9]+\\.[0-9a-f]+\\.[0-9]+",
      "Access Denied.*akamai"
    ],
    "block_status": 403
  },
  {
    "provider": "Akamai",
    "category": "hybrid",
    "header_signatures": [
      "X-Akamai-Transformed: 9 [0-9]+ 0 pmb=[A-Z]+",
      "Akamai-Cache-Status: (Hit|Miss)",
      "Server: AkamaiNetStorage"
    ],
    "cookie_signatures": [
      "bm_sz=[A-Za-z0-9%]+"
    ],
    "body_signatures": [
      "You don't have permission to access",
      "Akamai Technologies"
    ],
    "block_status": 403
  },
  {
    "provider": "F5 BIG-IP",
    "category": "waf",
    "header_signatures": [
      "X-Cnection: close",
      "Server: BigIP",
      "X-WA-Info: [A-Za-z0-9+/=]+"
    ],
    "cookie_signatures": [
      "BIGipServer[A-Za-z0-9_\\-]+=\\d+\\.\\d+\\.\\d+",
      "TS[a-z0-9]{8}=[a-z0-9]+"
    ],
    "body_signatures": [
      "The requested URL was rejected",
      "F5 Networks"
    ],
    "block_status": 403
  },
  {
    "provider": "F5 BIG-IP",
    "category": "waf",
    "header_signatures": [
      "X-TS-CORRELATION-ID: [0-9a-f\\-]+",
      "Server: BigIP",
      "X-Frame-Options: SAMEORIGIN"
    ],
    "cookie_signatures": [
      "TS[a-f0-9]{8}=[a-f0-9]{80,}"
    ],
    "body_signatures": [
      "Request Rejected",
      "illegal request"
    ],
    "block_status": 406
  },
  {
    "provider": "AWS WAF",
    "category": "waf",
    "header_signatures": [
      "X-AMZ-CF-ID: [A-Za-z0-9_\\-=]+",
      "X-AMZ-RequestId: [A-Z0-9\\-]+",
      "Via: [0-9.]+ [a-z0-9]+\\.cloudfront\\.net \\(CloudFront\\)"
    ],
    "cookie_signatures": [
      "aws-waf-token=[a-z0-9\\-]+"
    ],
    "body_signatures": [
      "AWS WAF could not forward your request",
      "<Code>ForbiddenByWAF</Code>"
    ],
    "block_status": 403
  },
  {
    "provider": "AWS WAF",
    "category": "waf",
    "header_signatures": [
      "X-Cache: Error from cloudfront",
      "X-AMZ-CF-POP: [A-Z0-9]+",
      "Server: awselb/[0-9.]+"
    ],
    "cookie_signatures": [],
    "body_signatures": [
      "Request blocked\\. We can't connect to the server",
      "AWSAlb=[A-Za-z0-9+/=]+"
    ],
    "block_status": 403
  },
  {
    "provider": "Imperva Incapsula",
    "category": "hybrid",
    "header_signatures": [
      "X-Iinfo: [0-9\\-]+",
      "X-CDN: Incapsula",
      "Server: Incapsula"
    ],
    "cookie_signatures": [
      "incap_ses_[0-9]+_[0-9]+=[A-Za-z0-9+/=]+",
      "visid_incap_[0-9]+=[A-Za-z0-9+/=]+"
    ],
    "body_signatures": [
      "Incapsula incident ID",
      "Request unsuccessful\\. Incapsula"
    ],
    "block_status": 403
  },
  {
    "provider": "Imperva Incapsula",
    "category": "hybrid",
    "header_signatures": [
      "X-Iinfo: [0-9]+-[0-9]+-[0-9]+ [0-9A-Z]+",
      "X-CDN: Incapsula"
    ],
    "cookie_signatures": [
      "___utmvc=[A-Za-z0-9+/=]+"
    ],
    "body_signatures": [
      "/_Incapsula_Resource\\?",
      "Powered by Incapsula"
    ],
    "block_status": 403
  },
  {
    "provider": "Fastly",
    "category": "cdn",
    "header_signatures": [
      "X-Served-By: cache-[a-z0-9]+-[A-Z]+",
      "X-Cache: (HIT|MISS)",
      "X-Cache-Hits: [0-9]+",
      "Fastly-Debug-Digest: [a-f0-9]+"
    ],
    "cookie_signatures": [],
    "body_signatures": [
      "Fastly error: unknown domain",
      "Error [0-9]+ [A-Za-z]+ Fastly"
    ],
    "block_status": 403
  },
  {
    "provider": "Fastly",
    "category": "cdn",
    "header_signatures": [
      "X-Fastly-Request-ID: [a-f0-9]+",
      "Via: [0-9.]+ varnish",
      "X-Timer: S[0-9]+\\.[0-9]+,VS[0-9]+,VE[0-9]+"
    ],
    "cookie_signatures": [],
    "body_signatures": [
      "Fastly CDN",
      "varnish"
    ],
    "block_status": 429
  },
  {
    "provider": "Sucuri",
    "category": "hybrid",
    "header_signatures": [
      "X-Sucuri-ID: [0-9]+",
      "Server: Sucuri/Cloudproxy",
      "X-Sucuri-Cache: (HIT|MISS)"
    ],
    "cookie_signatures": [
      "sucuri_cloudproxy_uuid_[a-f0-9]+=deleted"
    ],
    "body_signatures": [
      "Sucuri WebSite Firewall",
      "Access Denied - Sucuri Website Firewall"
    ],
    "block_status": 403
  },
  {
    "provider": "Sucuri",
    "category": "hybrid",
    "header_signatures": [
      "X-Sucuri-Block: Sucuri Website Firewall",
      "Server: Sucuri/Cloudproxy"
    ],
    "cookie_signatures": [],
    "body_signatures": [
      "sucuri\\.net",
      "CloudProxy WAF"
    ],
    "block_status": 403
  },
  {
    "provider": "ModSecurity",
    "category": "waf",
    "header_signatures": [
      "Server: (Apache|nginx).*mod_security",
      "X-Mod-Security: [0-9]+",
      "X-Powered-By: mod_security"
    ],
    "cookie_signatures": [],
    "body_signatures": [
      "ModSecurity Action",
      "This error was generated by Mod_Security"
    ],
    "block_status": 403
  },
  {
    "provider": "ModSecurity",
    "category": "waf",
    "header_signatures": [
      "Server: Apache.*\\(.*\\)",
      "X-Content-Type-Options: nosniff"
    ],
    "cookie_signatures": [],
    "body_signatures": [
      "Not Acceptable!.*mod_security",
      "406 Not Acceptable"
    ],
    "block_status": 406
  },
  {
    "provider": "Wordfence",
    "category": "waf",
    "header_signatures": [
      "X-Wordfence-Cache: (hit|miss)",
      "Server: nginx",
      "X-Frame-Options: SAMEORIGIN"
    ],
    "cookie_signatures": [
      "wfvt_[0-9]+=[a-f0-9]+",
      "wordfence_verifiedHuman=[0-9a-f]+"
    ],
    "body_signatures": [
      "Generated by Wordfence",
      "Your access to this site has been limited.*Wordfence"
    ],
    "block_status": 403
  },
  {
    "provider": "Wordfence",
    "category": "waf",
    "header_signatures": [
      "X-Wordfence-Blocked: yes",
      "Content-Type: text/html; charset=UTF-8"
    ],
    "cookie_signatures": [
      "wf_loginalerted_[a-f0-9]+=[01]"
    ],
    "body_signatures": [
      "Wordfence Security",
      "This response was generated by Wordfence"
    ],
    "block_status": 403
  },
  {
    "provider": "Barracuda",
    "category": "waf",
    "header_signatures": [
      "Server: BarracudaHTTP",
      "X-Barracuda-WAF: [A-Za-z0-9]+",
      "X-Barracuda-Start-Time: [0-9]+"
    ],
    "cookie_signatures": [
      "barra_counter_session=[A-Za-z0-9+/=]+",
      "BNI__BARRACUDA_LB_COOKIE=[A-Za-z0-9]+"
    ],
    "body_signatures": [
      "Barracuda Application Firewall",
      "You have been blocked"
    ],
    "block_status": 403
  },
  {
    "provider": "Barracuda",
    "category": "waf",
    "header_signatures": [
      "X-Barracuda-WAF-Version: [0-9.]+",
      "Server: BarracudaHTTP"
    ],
    "cookie_signatures": [
      "BNI_persistence=[a-f0-9]+"
    ],
    "body_signatures": [
      "barracudanetworks\\.com",
      "Request has been blocked"
    ],
    "block_status": 403
  },
  {
    "provider": "Citrix NetScaler",
    "category": "waf",
    "header_signatures": [
      "Via: NS-CACHE-[0-9.]+: [0-9]+",
      "X-Citrix-Via: [a-z0-9]+",
      "Server: NetScaler"
    ],
    "cookie_signatures": [
      "NSC_[a-zA-Z0-9_\\-]+=\\d+\\.\\d+\\.\\d+",
      "citrix_ns_id=[a-f0-9]+"
    ],
    "body_signatures": [
      "NetScaler Application Delivery Controller",
      "Citrix Application Firewall"
    ],
    "block_status": 403
  },
  {
    "provider": "Citrix NetScaler",
    "category": "waf",
    "header_signatures": [
      "X-NS-Proxy: [a-zA-Z0-9]+",
      "Set-Cookie: NSC_[A-Za-z0-9_]+=",
      "Server: Apache"
    ],
    "cookie_signatures": [
      "NSC_waf=[a-f0-9]+"
    ],
    "body_signatures": [
      "ns_af_error",
      "NetScaler Gateway"
    ],
    "block_status": 403
  },
  {
    "provider": "Radware",
    "category": "waf",
    "header_signatures": [
      "X-SL-CompState: [0-9]+",
      "X-Redirected-By: Radware",
      "Server: Radware-AppWall/[0-9.]+"
    ],
    "cookie_signatures": [
      "rdwr_[a-z]+=[A-Za-z0-9+/=]+"
    ],
    "body_signatures": [
      "Radware AppWall",
      "The request has been blocked by Radware"
    ],
    "block_status": 403
  },
  {
    "provider": "Radware",
    "category": "waf",
    "header_signatures": [
      "X-AppWall-Data: [A-Za-z0-9+/=]+",
      "Server: Radware-AppWall"
    ],
    "cookie_signatures": [
      "Rdwr[A-Za-z]+=[A-Za-z0-9%]+"
    ],
    "body_signatures": [
      "rdwr\\.com",
      "Illegal request blocked"
    ],
    "block_status": 403
  },
  {
    "provider": "Fortinet FortiWeb",
    "category": "waf",
    "header_signatures": [
      "X-Powered-By-Fortiweb: [0-9]+",
      "Server: FortiWeb",
      "X-Fw-Malicious-Score: [0-9]+"
    ],
    "cookie_signatures": [
      "FORTIWAFSID=[A-Za-z0-9]+",
      "cookiesession1=[A-Za-z0-9]+"
    ],
    "body_signatures": [
      "FortiWeb Application Firewall",
      "FortiGuard.*blocked this request"
    ],
    "block_status": 403
  },
  {
    "provider": "Fortinet FortiWeb",
    "category": "waf",
    "header_signatures": [
      "X-FortiWeb-ID: [0-9]+",
      "Server: FortiWeb-[0-9.]+"
    ],
    "cookie_signatures": [
      "FWSESID=[A-Za-z0-9]+"
    ],
    "body_signatures": [
      "fortinet\\.com",
      "Web Application Firewall by Fortinet"
    ],
    "block_status": 403
  },
  {
    "provider": "Wallarm",
    "category": "waf",
    "header_signatures": [
      "X-Wallarm-Action: block",
      "Server: nginx.*wallarm",
      "X-Wallarm-Node: [a-f0-9\\-]+"
    ],
    "cookie_signatures": [
      "wallarm_[a-z]+=[a-f0-9]+"
    ],
    "body_signatures": [
      "Wallarm.*blocked",
      "The request was blocked by Wallarm"
    ],
    "block_status": 403
  },
  {
    "provider": "Wallarm",
    "category": "waf",
    "header_signatures": [
      "X-Wallarm-Block-Reason: [a-z_]+",
      "X-Wallarm-Request-ID: [a-f0-9\\-]+"
    ],
    "cookie_signatures": [],
    "body_signatures": [
      "wallarm\\.com",
      "request has been blocked for security reasons"
    ],
    "block_status": 403
  },
  {
    "provider": "KeyCDN",
    "category": "cdn",
    "header_signatures": [
      "X-Cache: (MISS|HIT) from KeyCDN",
      "Server: keycdn-engine",
      "X-Edge-Location: [a-z]{3}[0-9]+"
    ],
    "cookie_signatures": [],
    "body_signatures": [
      "keycdn\\.com",
      "KeyCDN - Forbidden"
    ],
    "block_status": 403
  },
  {
    "provider": "KeyCDN",
    "category": "cdn",
    "header_signatures": [
      "X-Pull: KeyCDN",
      "X-Cache: EXPIRED from KeyCDN",
      "Server: keycdn-engine"
    ],
    "cookie_signatures": [],
    "body_signatures": [
      "Access to this resource has been denied",
      "keycdn\\.com/support"
    ],
    "block_status": 403
  },
  {
    "provider": "StackPath",
    "category": "hybrid",
    "header_signatures": [
      "X-SP-URL: https://[a-z0-9\\-\\.]+",
      "Server: StackPath",
      "X-Cache: (HIT|MISS) StackPath"
    ],
    "cookie_signatures": [
      "__stuid=[a-f0-9]+"
    ],
    "body_signatures": [
      "StackPath.*blocked",
      "Blocked by StackPath WAF"
    ],
    "block_status": 403
  },
  {
    "provider": "StackPath",
    "category": "hybrid",
    "header_signatures": [
      "X-StackPath-Trace: [a-f0-9\\-]+",
      "Via: StackPath"
    ],
    "cookie_signatures": [
      "sp_lit=[A-Za-z0-9+/=]+"
    ],
    "body_signatures": [
      "stackpath\\.com",
      "Request Has Been Blocked"
    ],
    "block_status": 403
  },
  {
    "provider": "Azure Front Door",
    "category": "hybrid",
    "header_signatures": [
      "X-Azure-Ref: [A-Za-z0-9+/=]+",
      "X-FD-HealthProbe: [01]",
      "Server: ECAcc \\([a-z]{3}/[A-F0-9]+\\)"
    ],
    "cookie_signatures": [
      "ASLBSA=[a-f0-9]+",
      "ASLBSACORS=[a-f0-9]+"
    ],
    "body_signatures": [
      "Microsoft Azure Application Gateway",
      "Our services aren't available right now.*Azure"
    ],
    "block_status": 403
  },
  {
    "provider": "Azure Front Door",
    "category": "hybrid",
    "header_signatures": [
      "X-Azure-Ref: [0-9a-zA-Z+/=]+",
      "X-MSEdge-Ref: Ref A: [A-F0-9]+ Ref B:",
      "Server: Windows-Azure-Blob/[0-9.]+"
    ],
    "cookie_signatures": [],
    "body_signatures": [
      "Azure WAF.*blocked",
      "RequestDisallowedByPolicy"
    ],
    "block_status": 403
  },
  {
    "provider": "GCP Cloud Armor",
    "category": "waf",
    "header_signatures": [
      "Via: [0-9.]+ google",
      "X-Google-Cache-Control: (remote-fetch|no-cache)",
      "Server: Google Frontend"
    ],
    "cookie_signatures": [],
    "body_signatures": [
      "The request was blocked by Google Cloud Armor",
      "\\{\"error\": \\{\"code\": 403.*Google\\}"
    ],
    "block_status": 403
  },
  {
    "provider": "GCP Cloud Armor",
    "category": "waf",
    "header_signatures": [
      "X-GFE-Request-Trace: [a-f0-9]+",
      "Server: gws",
      "X-Cloud-Trace-Context: [a-f0-9]+"
    ],
    "cookie_signatures": [],
    "body_signatures": [
      "Cloud Armor has blocked",
      "Response generated by Cloud Armor"
    ],
    "block_status": 403
  },
  {
    "provider": "Cloudflare",
    "category": "hybrid",
    "header_signatures": [
      "CF-RAY: [0-9a-f]+-[A-Z]{3}",
      "NEL: \\{\"success_fraction\"",
      "Server: cloudflare"
    ],
    "cookie_signatures": [
      "__cflb=[A-Za-z0-9]+"
    ],
    "body_signatures": [
      "Enable JavaScript and cookies to continue",
      "cf-browser-verification"
    ],
    "block_status": 403
  },
  {
    "provider": "Akamai",
    "category": "hybrid",
    "header_signatures": [
      "X-True-Cache-Key: [^\\s]+",
      "X-Serial: [0-9]+",
      "Server: Apache.*Akamai"
    ],
    "cookie_signatures": [
      "AKA_A2=[A-Za-z0-9+/=]+"
    ],
    "body_signatures": [
      "akamai.*error",
      "Please enable cookies"
    ],
    "block_status": 403
  },
  {
    "provider": "Imperva Incapsula",
    "category": "hybrid",
    "header_signatures": [
      "X-Iinfo: [0-9]+ [0-9]+ [0-9]+ [0-9]+ [A-Z]+ [A-Z]+",
      "Server: Incapsula"
    ],
    "cookie_signatures": [
      "nlbi_[0-9]+=[A-Za-z0-9+/=]+"
    ],
    "body_signatures": [
      "_incap_[0-9]+",
      "incapsula\\.com"
    ],
    "block_status": 403
  },
  {
    "provider": "F5 BIG-IP",
    "category": "waf",
    "header_signatures": [
      "X-Forwarded-For: [0-9.]+",
      "Server: BigIP",
      "X-WA-Info: [A-Za-z0-9]+"
    ],
    "cookie_signatures": [
      "BIGipServerPool[A-Za-z0-9_]+=rd[0-9]+o[0-9]+s[0-9]+"
    ],
    "body_signatures": [
      "The requested URL was rejected\\. Please consult with your administrator",
      "Your support ID is"
    ],
    "block_status": 403
  },
  {
    "provider": "ModSecurity",
    "category": "waf",
    "header_signatures": [
      "Server: Apache/[0-9.]+ \\(.*\\) mod_security/[0-9.]+",
      "X-Content-Type-Options: nosniff"
    ],
    "cookie_signatures": [],
    "body_signatures": [
      "You don't have permission to access.*on this server",
      "Mod_Security"
    ],
    "block_status": 403
  },
  {
    "provider": "AWS WAF",
    "category": "waf",
    "header_signatures": [
      "X-AMZ-CF-ID: [A-Za-z0-9\\-_=]+",
      "X-Amz-Cf-Pop: [A-Z0-9]+",
      "Via: 1.1 [a-z0-9]+\\.cloudfront\\.net \\(CloudFront\\)"
    ],
    "cookie_signatures": [
      "AWSALBCORS=[A-Za-z0-9+/=]+"
    ],
    "body_signatures": [
      "<title>403 Forbidden</title>",
      "Request Blocked"
    ],
    "block_status": 403
  },
  {
    "provider": "Fastly",
    "category": "cdn",
    "header_signatures": [
      "Surrogate-Key: [a-zA-Z0-9 ]+",
      "X-Served-By: cache-[a-z]{3}[0-9]+-[A-Z]{3}",
      "X-Cache-Hits: [0-9]+"
    ],
    "cookie_signatures": [],
    "body_signatures": [
      "Fastly error:",
      "Error [0-9]+ [A-Za-z-]+"
    ],
    "block_status": 403
  },
  {
    "provider": "Sucuri",
    "category": "hybrid",
    "header_signatures": [
      "X-Sucuri-ID: [0-9]{10}",
      "X-Sucuri-Cache: MISS"
    ],
    "cookie_signatures": [],
    "body_signatures": [
      "sucuri\\.net/website-firewall",
      "Your IP [0-9.]+ has been blocked"
    ],
    "block_status": 403
  },
  {
    "provider": "Barracuda",
    "category": "waf",
    "header_signatures": [
      "X-Barracuda-Connect: [0-9.]+",
      "Server: BarracudaHTTP",
      "X-Barracuda-Protection-Level: [0-9]+"
    ],
    "cookie_signatures": [
      "BNI__BARRACUDA_LB_COOKIE=[a-f0-9]+"
    ],
    "body_signatures": [
      "barracudanetworks\\.com/bnblogout",
      "Request Has Been Blocked.*Barracuda"
    ],
    "block_status": 403
  },
  {
    "provider": "Radware",
    "category": "waf",
    "header_signatures": [
      "X-SL-CompState: [0-9]+",
      "Server: Radware-AppWall",
      "X-AppWall-Version: [0-9.]+"
    ],
    "cookie_signatures": [
      "rdwr_id=[a-f0-9]+"
    ],
    "body_signatures": [
      "appwall\\.radware\\.com",
      "Security Policy Violation"
    ],
    "block_status": 403
  },
  {
    "provider": "Fortinet FortiWeb",
    "category": "waf",
    "header_signatures": [
      "X-FortiWeb-Rule-ID: [0-9]+",
      "Server: FortiWeb",
      "X-FortiWeb-Signature: [0-9]+"
    ],
    "cookie_signatures": [
      "FW_cookie=[A-Za-z0-9]+"
    ],
    "body_signatures": [
      "FortiWeb.*violation detected",
      "forticare\\.fortinet\\.com"
    ],
    "block_status": 403
  },
  {
    "provider": "Azure Front Door",
    "category": "hybrid",
    "header_signatures": [
      "X-Azure-Ref: [0-9A-Za-z+/=]+",
      "x-ms-request-id: [a-f0-9\\-]+",
      "Server: Microsoft-IIS/[0-9.]+"
    ],
    "cookie_signatures": [
      "ARRAffinity=[a-f0-9]+"
    ],
    "body_signatures": [
      "Application Gateway",
      "403 - Forbidden: Access is denied"
    ],
    "block_status": 403
  },
  {
    "provider": "GCP Cloud Armor",
    "category": "waf",
    "header_signatures": [
      "Via: 1.1 google",
      "Alt-Svc: h3=\".*\\.google\\.com:[0-9]+\"",
      "Server: Google Frontend"
    ],
    "cookie_signatures": [],
    "body_signatures": [
      "access blocked by your organization",
      "Sorry, you have been blocked.*Google"
    ],
    "block_status": 403
  },
  {
    "provider": "Wallarm",
    "category": "waf",
    "header_signatures": [
      "X-Wallarm-Request-UUID: [a-f0-9\\-]+",
      "Server: nginx",
      "X-Wallarm-Instance: [a-z0-9\\-]+"
    ],
    "cookie_signatures": [],
    "body_signatures": [
      "wallarm\\.com/product",
      "The request was blocked.*security policy"
    ],
    "block_status": 403
  },
  {
    "provider": "Citrix NetScaler",
    "category": "waf",
    "header_signatures": [
      "Via: NS-CACHE-[0-9.]+",
      "X-NS-Transaction-ID: [0-9a-f]+",
      "Server: NetScaler"
    ],
    "cookie_signatures": [
      "NSC_[A-Za-z0-9_]+=ffffffffc[a-f0-9]+",
      "NSC_aha=[A-Za-z0-9+/=]+"
    ],
    "body_signatures": [
      "Citrix NetScaler has detected",
      "ns_error_page"
    ],
    "block_status": 403
  }
]

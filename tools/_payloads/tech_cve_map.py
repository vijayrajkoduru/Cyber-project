"""tech_cve_map — generated dev-time by Claude. Recon module asset.
"""

TECH_CVE_MAP = [
  {
    "tech": "Apache HTTP Server",
    "version_match": "^2\\.4\\.49$",
    "cve": "CVE-2021-41773",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Path traversal and RCE vulnerability allowing unauthenticated attackers to map URLs outside document root."
  },
  {
    "tech": "Apache HTTP Server",
    "version_match": "^2\\.4\\.(49|50)$",
    "cve": "CVE-2021-42013",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Incomplete fix for CVE-2021-41773 allowing further path traversal and remote code execution."
  },
  {
    "tech": "Apache HTTP Server",
    "version_match": "^2\\.4\\.(1[7-9]|2[0-9]|3[0-9]|4[0-8])$",
    "cve": "CVE-2017-7679",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "mod_mime buffer overread allows remote attackers to cause heap buffer overflow."
  },
  {
    "tech": "Apache HTTP Server",
    "version_match": "^2\\.4\\.(1[0-9]|2[0-9]|3[0-7])$",
    "cve": "CVE-2017-9798",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "Optionsbleed vulnerability leaking memory contents via HTTP OPTIONS method."
  },
  {
    "tech": "Apache HTTP Server",
    "version_match": "^2\\.4\\.(1[0-9]|2[0-9]|3[0-9]|4[0-6])$",
    "cve": "CVE-2019-0211",
    "severity": "HIGH",
    "cvss": "7.8",
    "description": "Local privilege escalation via exploitation of Apache prefork MPM worker processes."
  },
  {
    "tech": "Apache HTTP Server",
    "version_match": "^2\\.4\\.(1[0-9]|2[0-9]|3[0-9]|4[0-3])$",
    "cve": "CVE-2018-17199",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "mod_session_cookie does not respect expiry time allowing session fixation."
  },
  {
    "tech": "Apache HTTP Server",
    "version_match": "^2\\.2\\.([0-9]|1[0-9]|2[0-9]|3[0-4])$",
    "cve": "CVE-2011-3192",
    "severity": "HIGH",
    "cvss": "7.8",
    "description": "Range header denial of service attack known as Apache Killer."
  },
  {
    "tech": "Apache HTTP Server",
    "version_match": "^2\\.4\\.(2[0-9]|3[0-9]|4[0-9]|5[0-1])$",
    "cve": "CVE-2021-40438",
    "severity": "CRITICAL",
    "cvss": "9.0",
    "description": "Server-side request forgery vulnerability in mod_proxy allowing forwarding to arbitrary servers."
  },
  {
    "tech": "Apache HTTP Server",
    "version_match": "^2\\.4\\.(1[0-9]|2[0-9]|3[0-9]|4[0-9]|5[0-2])$",
    "cve": "CVE-2022-22720",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "HTTP request smuggling vulnerability due to improper handling of incomplete request bodies."
  },
  {
    "tech": "nginx",
    "version_match": "^1\\.(1[0-9]|20)\\.",
    "cve": "CVE-2021-23017",
    "severity": "HIGH",
    "cvss": "7.7",
    "description": "Off-by-one error in DNS resolver allows remote code execution via crafted DNS response."
  },
  {
    "tech": "nginx",
    "version_match": "^1\\.(0|1|2|3|4|5|6|7|8|9)\\.",
    "cve": "CVE-2013-2028",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Stack-based buffer overflow in nginx chunked transfer encoding handling allows RCE."
  },
  {
    "tech": "nginx",
    "version_match": "^1\\.(1[0-9]|20|21)\\.",
    "cve": "CVE-2022-41741",
    "severity": "HIGH",
    "cvss": "7.8",
    "description": "Memory corruption vulnerability in nginx mp4 module allows local privilege escalation."
  },
  {
    "tech": "nginx",
    "version_match": "^1\\.(1[0-9]|20|21)\\.",
    "cve": "CVE-2022-41742",
    "severity": "HIGH",
    "cvss": "7.1",
    "description": "Memory disclosure vulnerability in nginx mp4 module exposes sensitive memory contents."
  },
  {
    "tech": "nginx",
    "version_match": "^1\\.(9|1[0-9])\\.",
    "cve": "CVE-2017-7529",
    "severity": "MEDIUM",
    "cvss": "5.3",
    "description": "Integer overflow in nginx range filter module may expose sensitive memory information."
  },
  {
    "tech": "WordPress",
    "version_match": "^[3-5]\\.",
    "cve": "CVE-2019-8942",
    "severity": "HIGH",
    "cvss": "8.8",
    "description": "WordPress remote code execution via image crop function path traversal allowing PHP file upload."
  },
  {
    "tech": "WordPress",
    "version_match": "^[3-5]\\.",
    "cve": "CVE-2019-8943",
    "severity": "HIGH",
    "cvss": "8.8",
    "description": "WordPress path traversal in image crop functionality enabling arbitrary file overwrite."
  },
  {
    "tech": "WordPress",
    "version_match": "^[3-4]\\.",
    "cve": "CVE-2017-9061",
    "severity": "MEDIUM",
    "cvss": "6.1",
    "description": "Reflected cross-site scripting in WordPress file upload error handling."
  },
  {
    "tech": "WordPress",
    "version_match": "^[3-5]\\.",
    "cve": "CVE-2018-6389",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "Unauthenticated denial of service via load-scripts.php script concatenation endpoint."
  },
  {
    "tech": "WordPress",
    "version_match": "^[3-5]\\.",
    "cve": "CVE-2020-28032",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "PHP object injection in WordPress login allows unauthenticated RCE via deserialization."
  },
  {
    "tech": "WordPress",
    "version_match": "^[3-5]\\.",
    "cve": "CVE-2021-29447",
    "severity": "MEDIUM",
    "cvss": "6.5",
    "description": "XXE vulnerability in WordPress media library allows server-side request forgery and file disclosure."
  },
  {
    "tech": "WordPress",
    "version_match": "^[34]\\.",
    "cve": "CVE-2015-5623",
    "severity": "MEDIUM",
    "cvss": "5.4",
    "description": "WordPress allows remote authenticated users to bypass intended access restrictions via crafted requests."
  },
  {
    "tech": "WordPress Elementor Plugin",
    "version_match": "^3\\.[0-5]\\.",
    "cve": "CVE-2022-1329",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Elementor WordPress plugin allows remote code execution via template import functionality."
  },
  {
    "tech": "WordPress WooCommerce Plugin",
    "version_match": "^[2-5]\\.",
    "cve": "CVE-2021-32789",
    "severity": "HIGH",
    "cvss": "8.8",
    "description": "WooCommerce plugin SQL injection vulnerability allows attackers to extract sensitive data."
  },
  {
    "tech": "WordPress Contact Form 7 Plugin",
    "version_match": "^5\\.[0-3]\\.",
    "cve": "CVE-2020-35489",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Contact Form 7 unrestricted file upload allows remote attackers to execute arbitrary code."
  },
  {
    "tech": "WordPress Yoast SEO Plugin",
    "version_match": "^([0-9]|1[0-5])\\.",
    "cve": "CVE-2021-25118",
    "severity": "MEDIUM",
    "cvss": "5.3",
    "description": "Yoast SEO plugin exposes sensitive server environment information to unauthenticated users."
  },
  {
    "tech": "WordPress All in One SEO Plugin",
    "version_match": "^4\\.[0-1]\\.",
    "cve": "CVE-2021-25036",
    "severity": "CRITICAL",
    "cvss": "9.9",
    "description": "All in One SEO plugin authenticated SQL injection and privilege escalation vulnerability."
  },
  {
    "tech": "WordPress Wordfence Plugin",
    "version_match": "^7\\.[0-4]\\.",
    "cve": "CVE-2020-24186",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Wordfence plugin RCE through bypass of file upload restrictions via polyglot files."
  },
  {
    "tech": "WordPress File Manager Plugin",
    "version_match": "^6\\.[0-8]\\.",
    "cve": "CVE-2020-25213",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "File Manager WordPress plugin unauthenticated arbitrary file upload leading to RCE."
  },
  {
    "tech": "WordPress Ninja Forms Plugin",
    "version_match": "^3\\.[0-5]\\.",
    "cve": "CVE-2022-1386",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Ninja Forms plugin unauthenticated code injection vulnerability via serialized data."
  },
  {
    "tech": "WordPress WPBakery Plugin",
    "version_match": "^6\\.[0-6]\\.",
    "cve": "CVE-2021-34643",
    "severity": "HIGH",
    "cvss": "8.8",
    "description": "WPBakery page builder plugin stored XSS leading to privilege escalation."
  },
  {
    "tech": "WordPress Divi Theme",
    "version_match": "^4\\.[0-9]\\.",
    "cve": "CVE-2020-13699",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Divi theme file upload vulnerability allows unauthenticated arbitrary file upload and RCE."
  },
  {
    "tech": "WordPress Slider Revolution Plugin",
    "version_match": "^[45]\\.",
    "cve": "CVE-2014-9734",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Slider Revolution plugin arbitrary file download vulnerability exposing wp-config.php."
  },
  {
    "tech": "WordPress TimThumb",
    "version_match": "^2\\.[0-8]\\.",
    "cve": "CVE-2011-4106",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "TimThumb script allows remote code execution via malicious image URL processing."
  },
  {
    "tech": "WordPress W3 Total Cache Plugin",
    "version_match": "^(0|1)\\.",
    "cve": "CVE-2021-24507",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "W3 Total Cache plugin server-side request forgery allowing internal network access."
  },
  {
    "tech": "WordPress WP Super Cache Plugin",
    "version_match": "^1\\.[0-6]\\.",
    "cve": "CVE-2021-24869",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "WP Super Cache plugin path traversal allowing unauthenticated cache manipulation."
  },
  {
    "tech": "WordPress Duplicator Plugin",
    "version_match": "^1\\.[0-3]\\.",
    "cve": "CVE-2020-11738",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "Duplicator plugin unauthenticated arbitrary file read vulnerability exposing sensitive files."
  },
  {
    "tech": "WordPress WPML Plugin",
    "version_match": "^4\\.[0-4]\\.",
    "cve": "CVE-2021-24931",
    "severity": "HIGH",
    "cvss": "8.8",
    "description": "WPML plugin authenticated SQL injection vulnerability in translation management."
  },
  {
    "tech": "WordPress Popup Builder Plugin",
    "version_match": "^3\\.[0-6]\\.",
    "cve": "CVE-2021-34621",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Popup Builder plugin privilege escalation vulnerability allows subscriber-level user account creation."
  },
  {
    "tech": "WordPress Advanced Custom Fields Plugin",
    "version_match": "^5\\.[0-9]\\.",
    "cve": "CVE-2023-30777",
    "severity": "HIGH",
    "cvss": "7.1",
    "description": "Advanced Custom Fields plugin reflected XSS vulnerability in field group management."
  },
  {
    "tech": "WordPress Jetpack Plugin",
    "version_match": "^[1-9]\\.",
    "cve": "CVE-2019-20041",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Jetpack plugin deserialization of untrusted data allows unauthenticated remote code execution."
  },
  {
    "tech": "WordPress Gravity Forms Plugin",
    "version_match": "^2\\.[0-5]\\.",
    "cve": "CVE-2021-39215",
    "severity": "HIGH",
    "cvss": "8.8",
    "description": "Gravity Forms plugin PHP object injection via unserialize allowing RCE for authenticated users."
  },
  {
    "tech": "WordPress Ultimate Member Plugin",
    "version_match": "^2\\.[0-5]\\.",
    "cve": "CVE-2023-3460",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Ultimate Member plugin privilege escalation via user meta manipulation during registration."
  },
  {
    "tech": "Drupal",
    "version_match": "^[67]\\.",
    "cve": "CVE-2014-3704",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Drupalgeddon SQL injection in Drupal core allows unauthenticated remote code execution."
  },
  {
    "tech": "Drupal",
    "version_match": "^[67]\\.(0|[1-9][0-9]?)$",
    "cve": "CVE-2018-7600",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Drupalgeddon2 remote code execution vulnerability in Drupal core form API."
  },
  {
    "tech": "Drupal",
    "version_match": "^[78]\\.([0-9]|[1-9][0-9])$",
    "cve": "CVE-2018-7602",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Drupalgeddon3 remote code execution via request forgery in Drupal core."
  },
  {
    "tech": "Drupal",
    "version_match": "^[78]\\.([0-9]|[1-9][0-9])$",
    "cve": "CVE-2019-6340",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Drupal REST module remote code execution via JSON deserialization."
  },
  {
    "tech": "Drupal",
    "version_match": "^[89]\\.([0-9]|[1-9][0-9])$",
    "cve": "CVE-2022-25271",
    "severity": "HIGH",
    "cvss": "8.1",
    "description": "Drupal improper input validation in core allowing access bypass and data manipulation."
  },
  {
    "tech": "Joomla",
    "version_match": "^[123]\\.",
    "cve": "CVE-2015-8562",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Joomla PHP object injection via HTTP User-Agent header allows unauthenticated RCE."
  },
  {
    "tech": "Joomla",
    "version_match": "^[123]\\.",
    "cve": "CVE-2017-8917",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Joomla SQL injection in com_fields component allows unauthenticated data extraction."
  },
  {
    "tech": "Joomla",
    "version_match": "^[23]\\.",
    "cve": "CVE-2016-8869",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Joomla improper access control in user registration allows privilege escalation to admin."
  },
  {
    "tech": "Joomla",
    "version_match": "^3\\.",
    "cve": "CVE-2021-26027",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "Joomla information disclosure via media manager allowing path traversal attacks."
  },
  {
    "tech": "Magento",
    "version_match": "^2\\.[0-3]\\.",
    "cve": "CVE-2021-21024",
    "severity": "CRITICAL",
    "cvss": "9.1",
    "description": "Magento blind SQL injection vulnerability in REST API allowing data extraction."
  },
  {
    "tech": "Magento",
    "version_match": "^2\\.[0-3]\\.",
    "cve": "CVE-2022-24086",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Magento improper input validation allows unauthenticated RCE via crafted email templates."
  },
  {
    "tech": "Magento",
    "version_match": "^1\\.",
    "cve": "CVE-2019-7139",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Magento 1 SQL injection in search functionality allowing unauthenticated database access."
  },
  {
    "tech": "Magento",
    "version_match": "^2\\.[0-4]\\.",
    "cve": "CVE-2020-24407",
    "severity": "CRITICAL",
    "cvss": "9.1",
    "description": "Magento arbitrary code execution via malicious file upload in admin area."
  },
  {
    "tech": "Magento",
    "version_match": "^2\\.[0-4]\\.",
    "cve": "CVE-2020-24400",
    "severity": "HIGH",
    "cvss": "8.1",
    "description": "Magento SQL injection in media gallery grid allowing data exfiltration."
  },
  {
    "tech": "PHP",
    "version_match": "^7\\.[0-3]\\.",
    "cve": "CVE-2019-11043",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "PHP-FPM buffer underflow vulnerability in env_path_info allows remote code execution."
  },
  {
    "tech": "PHP",
    "version_match": "^[57]\\.",
    "cve": "CVE-2012-1823",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "PHP CGI argument injection vulnerability allowing unauthenticated remote code execution."
  },
  {
    "tech": "PHP",
    "version_match": "^[567]\\.",
    "cve": "CVE-2015-7545",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "PHP remote code execution via unserialize() function and crafted serialized objects."
  },
  {
    "tech": "PHP",
    "version_match": "^[56]\\.",
    "cve": "CVE-2016-5385",
    "severity": "HIGH",
    "cvss": "8.1",
    "description": "PHP HTTPOXY vulnerability allows remote server-side request forgery via proxy header."
  },
  {
    "tech": "PHP",
    "version_match": "^[56789]\\.",
    "cve": "CVE-2021-21708",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "PHP use-after-free vulnerability in filter functions allowing remote code execution."
  },
  {
    "tech": "PHP",
    "version_match": "^8\\.[01]\\.",
    "cve": "CVE-2022-31625",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "PHP uninitialized array pointer in Postgres extension allows remote code execution."
  },
  {
    "tech": "PHP",
    "version_match": "^[5-8]\\.",
    "cve": "CVE-2022-31628",
    "severity": "HIGH",
    "cvss": "7.8",
    "description": "PHP stack overflow vulnerability in phar extension allows denial of service."
  },
  {
    "tech": "PHP",
    "version_match": "^7\\.[0-4]\\.",
    "cve": "CVE-2020-7064",
    "severity": "MEDIUM",
    "cvss": "5.4",
    "description": "PHP improper input validation in exif extension allows out-of-bounds read."
  },
  {
    "tech": "Log4j",
    "version_match": "^2\\.([0-9]|1[0-4])\\.",
    "cve": "CVE-2021-44228",
    "severity": "CRITICAL",
    "cvss": "10.0",
    "description": "Log4Shell JNDI injection in Log4j2 allows unauthenticated remote code execution via log messages."
  },
  {
    "tech": "Log4j",
    "version_match": "^2\\.([0-9]|1[0-5])\\.",
    "cve": "CVE-2021-45046",
    "severity": "CRITICAL",
    "cvss": "9.0",
    "description": "Log4j2 JNDI injection bypass via thread context map pattern allowing RCE in certain configurations."
  },
  {
    "tech": "Log4j",
    "version_match": "^2\\.([0-9]|1[0-4])\\.",
    "cve": "CVE-2021-45105",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "Log4j2 infinite recursion denial of service via crafted log message with self-referential lookup."
  },
  {
    "tech": "Log4j",
    "version_match": "^2\\.([0-9]|1[0-6])\\.",
    "cve": "CVE-2021-44832",
    "severity": "MEDIUM",
    "cvss": "6.6",
    "description": "Log4j2 RCE via attacker-controlled JDBC Appender in crafted configuration files."
  },
  {
    "tech": "Spring Framework",
    "version_match": "^5\\.[23]\\.",
    "cve": "CVE-2022-22965",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Spring4Shell RCE vulnerability via data binding on JDK 9+ via ClassLoader manipulation."
  },
  {
    "tech": "Spring Framework",
    "version_match": "^5\\.[01]\\.",
    "cve": "CVE-2018-1270",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Spring Framework remote code execution via STOMP over WebSocket messaging."
  },
  {
    "tech": "Spring Framework",
    "version_match": "^5\\.[0-2]\\.",
    "cve": "CVE-2018-1271",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "Spring MVC path traversal vulnerability in Windows filesystem via specially crafted URL."
  },
  {
    "tech": "Spring Boot",
    "version_match": "^2\\.[0-6]\\.",
    "cve": "CVE-2022-22963",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Spring Cloud Function SpEL injection allows remote code execution via routing functionality."
  },
  {
    "tech": "Spring Security",
    "version_match": "^5\\.[0-5]\\.",
    "cve": "CVE-2022-22978",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Spring Security authorization bypass via RegexRequestMatcher with dotall flag."
  },
  {
    "tech": "Jenkins",
    "version_match": "^2\\.(2[0-9][0-9]|1[0-9][0-9])$",
    "cve": "CVE-2019-1003000",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Jenkins sandbox bypass in Script Security plugin allowing unauthenticated RCE."
  },
  {
    "tech": "Jenkins",
    "version_match": "^2\\.(1[0-9][0-9]|2[0-8][0-9])$",
    "cve": "CVE-2018-1000861",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Jenkins remote code execution via Stapler URL routing bypassing access controls."
  },
  {
    "tech": "Jenkins",
    "version_match": "^2\\.([0-9]|[1-9][0-9]|[12][0-9][0-9]|3[0-2][0-9])$",
    "cve": "CVE-2023-27898",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Jenkins XSS vulnerability in update center leading to code execution in administrative UI."
  },
  {
    "tech": "Jenkins",
    "version_match": "^[12]\\.",
    "cve": "CVE-2016-0792",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Jenkins CLI deserialization vulnerability allowing unauthenticated remote code execution."
  },
  {
    "tech": "Jenkins",
    "version_match": "^2\\.(1[0-9][0-9]|2[0-9][0-9]|3[0-5][0-9])$",
    "cve": "CVE-2022-34177",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "Jenkins Pipeline Build Step plugin arbitrary file write vulnerability."
  },
  {
    "tech": "GitLab",
    "version_match": "^1[0-3]\\.",
    "cve": "CVE-2021-22205",
    "severity": "CRITICAL",
    "cvss": "10.0",
    "description": "GitLab unauthenticated RCE via ExifTool image parsing in file upload processing."
  },
  {
    "tech": "GitLab",
    "version_match": "^1[0-4]\\.",
    "cve": "CVE-2022-2884",
    "severity": "CRITICAL",
    "cvss": "9.9",
    "description": "GitLab RCE via GitHub import functionality allows code execution as authenticated user."
  },
  {
    "tech": "GitLab",
    "version_match": "^1[0-4]\\.",
    "cve": "CVE-2022-1162",
    "severity": "CRITICAL",
    "cvss": "9.1",
    "description": "GitLab hardcoded password for OmniAuth-based accounts allows account takeover."
  },
  {
    "tech": "GitLab",
    "version_match": "^([89]|1[0-3])\\.",
    "cve": "CVE-2021-22214",
    "severity": "HIGH",
    "cvss": "8.6",
    "description": "GitLab SSRF via import from URL allowing access to internal services."
  },
  {
    "tech": "GitLab",
    "version_match": "^1[0-5]\\.",
    "cve": "CVE-2023-7028",
    "severity": "CRITICAL",
    "cvss": "10.0",
    "description": "GitLab account takeover via password reset email delivery to unverified email addresses."
  },
  {
    "tech": "Confluence",
    "version_match": "^[78]\\.([0-9]|[1-9][0-9])$",
    "cve": "CVE-2022-26134",
    "severity": "CRITICAL",
    "cvss": "10.0",
    "description": "Atlassian Confluence OGNL injection allows unauthenticated remote code execution."
  },
  {
    "tech": "Confluence",
    "version_match": "^[56789]\\.",
    "cve": "CVE-2021-26084",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Atlassian Confluence OGNL injection in WebWork actions allows unauthenticated RCE."
  },
  {
    "tech": "Confluence",
    "version_match": "^[5-8]\\.",
    "cve": "CVE-2022-26138",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Hardcoded credentials in Confluence Questions app allow full application access."
  },
  {
    "tech": "Confluence",
    "version_match": "^[5-8]\\.",
    "cve": "CVE-2023-22515",
    "severity": "CRITICAL",
    "cvss": "10.0",
    "description": "Broken access control in Confluence Data Center allows attacker to create admin accounts."
  },
  {
    "tech": "Confluence",
    "version_match": "^[5-8]\\.",
    "cve": "CVE-2023-22518",
    "severity": "CRITICAL",
    "cvss": "10.0",
    "description": "Improper authorization in Confluence Data Center and Server allows destructive actions."
  },
  {
    "tech": "Microsoft Exchange",
    "version_match": "^15\\.(1|2)\\.",
    "cve": "CVE-2021-34473",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "ProxyShell pre-auth path confusion in Exchange Server allows remote code execution."
  },
  {
    "tech": "Microsoft Exchange",
    "version_match": "^15\\.(1|2)\\.",
    "cve": "CVE-2021-34523",
    "severity": "HIGH",
    "cvss": "9.0",
    "description": "ProxyShell Exchange Server elevation of privilege allows backend access with lower privileges."
  },
  {
    "tech": "Microsoft Exchange",
    "version_match": "^15\\.(1|2)\\.",
    "cve": "CVE-2021-31207",
    "severity": "MEDIUM",
    "cvss": "7.2",
    "description": "ProxyShell post-auth Exchange Server arbitrary file write via malicious PowerShell cmdlet."
  },
  {
    "tech": "Microsoft Exchange",
    "version_match": "^15\\.(0|1|2)\\.",
    "cve": "CVE-2021-26855",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "ProxyLogon SSRF in Exchange Server allows unauthenticated authentication bypass."
  },
  {
    "tech": "Microsoft Exchange",
    "version_match": "^15\\.(0|1|2)\\.",
    "cve": "CVE-2021-27065",
    "severity": "HIGH",
    "cvss": "7.8",
    "description": "ProxyLogon Exchange Server post-auth arbitrary file write via OAB virtual directory."
  },
  {
    "tech": "Microsoft Exchange",
    "version_match": "^15\\.(1|2)\\.",
    "cve": "CVE-2022-41082",
    "severity": "HIGH",
    "cvss": "8.8",
    "description": "ProxyNotShell Exchange Server post-auth RCE via PowerShell remoting."
  },
  {
    "tech": "Apache Struts",
    "version_match": "^2\\.(0|1|2|3)\\.",
    "cve": "CVE-2017-5638",
    "severity": "CRITICAL",
    "cvss": "10.0",
    "description": "Apache Struts 2 RCE via Jakarta Multipart parser Content-Type header OGNL injection."
  },
  {
    "tech": "Apache Struts",
    "version_match": "^2\\.[0-5]\\.",
    "cve": "CVE-2018-11776",
    "severity": "CRITICAL",
    "cvss": "10.0",
    "description": "Apache Struts 2 namespace-based RCE without alwaysSelectFullNamespace allowing OGNL injection."
  },
  {
    "tech": "Apache Struts",
    "version_match": "^2\\.[0-5]\\.",
    "cve": "CVE-2019-0230",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Apache Struts 2 OGNL injection via forced OGNL evaluation of raw user input."
  },
  {
    "tech": "Apache Struts",
    "version_match": "^2\\.[0-4]\\.",
    "cve": "CVE-2016-4438",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Apache Struts 2 REST plugin XStream deserialization allows RCE via crafted XML."
  },
  {
    "tech": "Apache Struts",
    "version_match": "^2\\.[0-3]\\.",
    "cve": "CVE-2013-4316",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Apache Struts 2 dynamic method invocation allows remote code execution without access controls."
  },
  {
    "tech": "Apache Tomcat",
    "version_match": "^[89]\\.",
    "cve": "CVE-2019-0232",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Apache Tomcat CGI Servlet RCE via newline injection on Windows systems."
  },
  {
    "tech": "Apache Tomcat",
    "version_match": "^[7-9]\\.",
    "cve": "CVE-2017-12617",
    "severity": "HIGH",
    "cvss": "8.1",
    "description": "Apache Tomcat JSP upload via HTTP PUT method allows remote code execution."
  },
  {
    "tech": "Apache Tomcat",
    "version_match": "^[6-9]\\.",
    "cve": "CVE-2016-8735",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Apache Tomcat JMX deserialization via JmxRemoteLifecycleListener allows RCE."
  },
  {
    "tech": "Apache Tomcat",
    "version_match": "^[6-9]\\.",
    "cve": "CVE-2020-1938",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Ghostcat AJP file inclusion/read vulnerability allowing unauthenticated file read and RCE."
  },
  {
    "tech": "Apache Tomcat",
    "version_match": "^(10\\.0|9\\.(0\\.([0-9]|[1-7][0-9]|8[0-4])))",
    "cve": "CVE-2021-25122",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "Apache Tomcat partial HTTP/2 request data exposure via h2c upgrade request."
  },
  {
    "tech": "Apache Tomcat",
    "version_match": "^(10|9|8)\\.",
    "cve": "CVE-2022-34305",
    "severity": "MEDIUM",
    "cvss": "6.1",
    "description": "Apache Tomcat XSS vulnerability in the examples web application."
  },
  {
    "tech": "Oracle WebLogic",
    "version_match": "^1[012]\\.",
    "cve": "CVE-2019-2725",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Oracle WebLogic deserialization RCE via wls9_async_response and wls-wsat components."
  },
  {
    "tech": "Oracle WebLogic",
    "version_match": "^1[012]\\.",
    "cve": "CVE-2020-14882",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Oracle WebLogic console authentication bypass and RCE via crafted HTTP requests."
  },
  {
    "tech": "Oracle WebLogic",
    "version_match": "^1[012]\\.",
    "cve": "CVE-2020-14750",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Oracle WebLogic console unauthenticated bypass allowing privileged access."
  },
  {
    "tech": "Oracle WebLogic",
    "version_match": "^1[012]\\.",
    "cve": "CVE-2021-2109",
    "severity": "HIGH",
    "cvss": "7.2",
    "description": "Oracle WebLogic LDAP injection in admin console allows remote code execution."
  },
  {
    "tech": "Oracle WebLogic",
    "version_match": "^1[012]\\.",
    "cve": "CVE-2023-21839",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Oracle WebLogic Server unauthenticated JNDI injection allowing remote code execution."
  },
  {
    "tech": "Oracle WebLogic",
    "version_match": "^10\\.",
    "cve": "CVE-2017-10271",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "Oracle WebLogic WLS-WSAT XMLDecoder deserialization RCE without authentication."
  },
  {
    "tech": "Cisco ASA",
    "version_match": "^9\\.(1[0-4]|[0-9])\\.",
    "cve": "CVE-2018-0101",
    "severity": "CRITICAL",
    "cvss": "10.0",
    "description": "Cisco ASA double free in SSL VPN allows unauthenticated remote code execution."
  },
  {
    "tech": "Cisco ASA",
    "version_match": "^9\\.(1[0-6]|[0-9])\\.",
    "cve": "CVE-2020-3452",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "Cisco ASA web services directory traversal allows unauthenticated file read from WebVPN."
  },
  {
    "tech": "Cisco ASA",
    "version_match": "^9\\.(1[0-9]|[0-9])\\.",
    "cve": "CVE-2023-20269",
    "severity": "HIGH",
    "cvss": "9.1",
    "description": "Cisco ASA VPN brute force vulnerability allowing unauthorized VPN session establishment."
  },
  {
    "tech": "Cisco ASA",
    "version_match": "^9\\.[0-9]\\.",
    "cve": "CVE-2014-3393",
    "severity": "HIGH",
    "cvss": "7.8",
    "description": "Cisco ASA Clientless SSL VPN portal customization frame injection vulnerability."
  },
  {
    "tech": "Cisco ASA",
    "version_match": "^(9\\.(1[0-6])|8\\.)\\.",
    "cve": "CVE-2018-15454",
    "severity": "HIGH",
    "cvss": "8.6",
    "description": "Cisco ASA SIP inspection denial of service via crafted SIP traffic."
  },
  {
    "tech": "Palo Alto PAN-OS",
    "version_match": "^([0-9]|10)\\.",
    "cve": "CVE-2020-2021",
    "severity": "CRITICAL",
    "cvss": "10.0",
    "description": "Palo Alto PAN-OS SAML authentication bypass allows unauthenticated access to GlobalProtect."
  },
  {
    "tech": "Palo Alto PAN-OS",
    "version_match": "^(8|9|10)\\.",
    "cve": "CVE-2019-1579",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Palo Alto GlobalProtect RCE via format string vulnerability in the portal login page."
  },
  {
    "tech": "Palo Alto PAN-OS",
    "version_match": "^(9|10|11)\\.",
    "cve": "CVE-2021-3064",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Palo Alto PAN-OS buffer overflow in GlobalProtect portal allows unauthenticated RCE."
  },
  {
    "tech": "Palo Alto PAN-OS",
    "version_match": "^(10|11)\\.",
    "cve": "CVE-2022-0028",
    "severity": "HIGH",
    "cvss": "8.6",
    "description": "Palo Alto PAN-OS URL filtering policy misconfiguration enables reflected amplification DoS."
  },
  {
    "tech": "Palo Alto PAN-OS",
    "version_match": "^(10|11)\\.",
    "cve": "CVE-2024-3400",
    "severity": "CRITICAL",
    "cvss": "10.0",
    "description": "Palo Alto PAN-OS GlobalProtect OS command injection allowing unauthenticated RCE."
  },
  {
    "tech": "Fortinet FortiOS",
    "version_match": "^[56]\\.([0-9]|[1-9][0-9])$",
    "cve": "CVE-2018-13379",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Fortinet FortiOS SSL VPN path traversal allowing unauthenticated credential file read."
  },
  {
    "tech": "Fortinet FortiOS",
    "version_match": "^6\\.[024]\\.",
    "cve": "CVE-2019-11510",
    "severity": "CRITICAL",
    "cvss": "10.0",
    "description": "Fortinet FortiOS SSL-VPN arbitrary file read without authentication via path traversal."
  },
  {
    "tech": "Fortinet FortiOS",
    "version_match": "^(6|7)\\.",
    "cve": "CVE-2022-40684",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Fortinet FortiOS authentication bypass via alternative path in admin interface."
  },
  {
    "tech": "Fortinet FortiOS",
    "version_match": "^(6|7)\\.",
    "cve": "CVE-2023-27997",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Fortinet FortiOS SSL-VPN heap buffer overflow allows unauthenticated RCE."
  },
  {
    "tech": "Fortinet FortiOS",
    "version_match": "^[67]\\.",
    "cve": "CVE-2024-21762",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Fortinet FortiOS out-of-bounds write in SSL VPN allows unauthenticated remote code execution."
  },
  {
    "tech": "Fortinet FortiGate",
    "version_match": "^[56]\\.([0-9]|[1-9][0-9])$",
    "cve": "CVE-2020-12812",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Fortinet FortiOS SSL VPN improper authentication allows bypass of two-factor authentication."
  },
  {
    "tech": "Apache Solr",
    "version_match": "^[56789]\\.",
    "cve": "CVE-2019-0193",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Apache Solr DataImportHandler RCE via JNDI injection in DIH configuration."
  },
  {
    "tech": "Apache Solr",
    "version_match": "^[5-8]\\.",
    "cve": "CVE-2017-12629",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Apache Solr XML External Entity injection and SSRF in RunExecutableListener."
  },
  {
    "tech": "Apache Solr",
    "version_match": "^[6-9]\\.",
    "cve": "CVE-2019-17558",
    "severity": "HIGH",
    "cvss": "8.1",
    "description": "Apache Solr Velocity template injection allows remote code execution via template parameter."
  },
  {
    "tech": "Apache Kafka",
    "version_match": "^[23]\\.",
    "cve": "CVE-2023-25194",
    "severity": "HIGH",
    "cvss": "8.8",
    "description": "Apache Kafka Connect SSRF and RCE via JNDI injection in connector configuration."
  },
  {
    "tech": "Atlassian JIRA",
    "version_match": "^[78]\\.",
    "cve": "CVE-2019-8449",
    "severity": "MEDIUM",
    "cvss": "5.3",
    "description": "Atlassian JIRA information disclosure via user enumeration in /rest/api endpoint."
  },
  {
    "tech": "Atlassian JIRA",
    "version_match": "^[78]\\.",
    "cve": "CVE-2019-8451",
    "severity": "HIGH",
    "cvss": "8.6",
    "description": "Atlassian JIRA SSRF vulnerability in IconUriServlet allowing access to internal resources."
  },
  {
    "tech": "Atlassian JIRA",
    "version_match": "^8\\.",
    "cve": "CVE-2022-26135",
    "severity": "HIGH",
    "cvss": "6.5",
    "description": "Atlassian JIRA full read SSRF in Mobile plugin via batch endpoint."
  },
  {
    "tech": "Atlassian JIRA",
    "version_match": "^8\\.",
    "cve": "CVE-2021-26086",
    "severity": "MEDIUM",
    "cvss": "5.3",
    "description": "Atlassian JIRA path traversal in WorkflowDesignerComponent allows limited file read."
  },
  {
    "tech": "VMware vCenter",
    "version_match": "^[67]\\.",
    "cve": "CVE-2021-21985",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "VMware vCenter Server RCE via Virtual SAN Health Check plugin enabled by default."
  },
  {
    "tech": "VMware vCenter",
    "version_match": "^[67]\\.",
    "cve": "CVE-2021-22005",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "VMware vCenter Server arbitrary file upload in Analytics service allowing unauthenticated RCE."
  },
  {
    "tech": "VMware vCenter",
    "version_match": "^[67]\\.",
    "cve": "CVE-2021-21972",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "VMware vCenter vSphere Client RCE via exposed vRealize Operations plugin endpoint."
  },
  {
    "tech": "VMware ESXi",
    "version_match": "^[67]\\.",
    "cve": "CVE-2021-21974",
    "severity": "HIGH",
    "cvss": "8.8",
    "description": "VMware ESXi OpenSLP heap overflow allows remote code execution by network-adjacent attackers."
  },
  {
    "tech": "F5 BIG-IP",
    "version_match": "^1[0-6]\\.",
    "cve": "CVE-2020-5902",
    "severity": "CRITICAL",
    "cvss": "10.0",
    "description": "F5 BIG-IP TMUI RCE via path traversal allows unauthenticated command execution."
  },
  {
    "tech": "F5 BIG-IP",
    "version_match": "^1[0-6]\\.",
    "cve": "CVE-2022-1388",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "F5 BIG-IP iControl REST authentication bypass allows unauthenticated command execution."
  },
  {
    "tech": "F5 BIG-IP",
    "version_match": "^1[0-5]\\.",
    "cve": "CVE-2021-22986",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "F5 BIG-IP iControl REST unauthenticated RCE via SSRF and iControl SOAP endpoints."
  },
  {
    "tech": "OpenSSL",
    "version_match": "^1\\.0\\.",
    "cve": "CVE-2014-0160",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "Heartbleed OpenSSL TLS heartbeat extension buffer over-read exposing server memory."
  },
  {
    "tech": "OpenSSL",
    "version_match": "^1\\.(0|1)\\.",
    "cve": "CVE-2016-0800",
    "severity": "HIGH",
    "cvss": "5.9",
    "description": "DROWN attack allows decryption of TLS via SSLv2 cross-protocol Bleichenbacher attack."
  },
  {
    "tech": "OpenSSL",
    "version_match": "^[13]\\.",
    "cve": "CVE-2022-0778",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "OpenSSL infinite loop in BN_mod_sqrt allowing denial of service via crafted certificates."
  },
  {
    "tech": "OpenSSL",
    "version_match": "^3\\.0\\.[0-6]$",
    "cve": "CVE-2022-3786",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "OpenSSL X.509 email address buffer overflow in certificate verification."
  },
  {
    "tech": "OpenSSL",
    "version_match": "^3\\.0\\.[0-6]$",
    "cve": "CVE-2022-3602",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "OpenSSL X.509 certificate verification buffer overflow potentially allowing RCE."
  },
  {
    "tech": "SolarWinds Orion",
    "version_match": "^2019\\.",
    "cve": "CVE-2020-10148",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "SolarWinds Orion API authentication bypass allowing unauthenticated access."
  },
  {
    "tech": "SolarWinds Orion",
    "version_match": "^(2019|2020)\\.",
    "cve": "CVE-2020-14005",
    "severity": "HIGH",
    "cvss": "8.8",
    "description": "SolarWinds Orion Platform deserialization allows privilege escalation to admin."
  },
  {
    "tech": "Apache Cassandra",
    "version_match": "^(3|4)\\.",
    "cve": "CVE-2021-44521",
    "severity": "CRITICAL",
    "cvss": "9.1",
    "description": "Apache Cassandra user-defined functions RCE via script engine sandbox escape."
  },
  {
    "tech": "Redis",
    "version_match": "^[567]\\.",
    "cve": "CVE-2022-0543",
    "severity": "CRITICAL",
    "cvss": "10.0",
    "description": "Redis Lua sandbox escape due to packaging flaw in Debian/Ubuntu allows RCE."
  },
  {
    "tech": "Redis",
    "version_match": "^[2-7]\\.",
    "cve": "CVE-2015-4335",
    "severity": "CRITICAL",
    "cvss": "10.0",
    "description": "Redis Lua eval sandbox escape allows remote code execution with server privileges."
  },
  {
    "tech": "Elasticsearch",
    "version_match": "^[12]\\.",
    "cve": "CVE-2014-3120",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Elasticsearch dynamic script execution allows unauthenticated RCE via MVEL or Groovy scripts."
  },
  {
    "tech": "Elasticsearch",
    "version_match": "^[12]\\.",
    "cve": "CVE-2015-1427",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Elasticsearch Groovy sandbox bypass allows remote code execution via crafted script."
  },
  {
    "tech": "Apache Hadoop",
    "version_match": "^[23]\\.",
    "cve": "CVE-2023-26031",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "Apache Hadoop YARN unauthenticated RCE via ResourceManager REST API class path injection."
  },
  {
    "tech": "Apache Hadoop YARN",
    "version_match": "^[23]\\.",
    "cve": "CVE-2021-25642",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Apache Hadoop YARN RCE via ResourceManager REST API without authentication on default config."
  },
  {
    "tech": "Docker",
    "version_match": "^(1[0-9]|20)\\.",
    "cve": "CVE-2019-5736",
    "severity": "HIGH",
    "cvss": "8.6",
    "description": "runc container escape vulnerability allows overwriting host runc binary from inside container."
  },
  {
    "tech": "Kubernetes",
    "version_match": "^1\\.(1[0-2])\\.",
    "cve": "CVE-2018-1002105",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Kubernetes API server privilege escalation via specially crafted network request bypass."
  },
  {
    "tech": "Kubernetes",
    "version_match": "^1\\.(1[0-9]|2[01])\\.",
    "cve": "CVE-2020-8558",
    "severity": "HIGH",
    "cvss": "8.8",
    "description": "Kubernetes incorrect handling of localhost routing allowing SSRF to localhost services."
  },
  {
    "tech": "GitLab",
    "version_match": "^1[1-3]\\.",
    "cve": "CVE-2020-10977",
    "severity": "MEDIUM",
    "cvss": "6.5",
    "description": "GitLab arbitrary file read via project export functionality path traversal."
  },
  {
    "tech": "Roundcube",
    "version_match": "^1\\.[0-4]\\.",
    "cve": "CVE-2020-35730",
    "severity": "MEDIUM",
    "cvss": "6.1",
    "description": "Roundcube XSS in HTML email body allowing code execution in browser context."
  },
  {
    "tech": "Roundcube",
    "version_match": "^1\\.[0-4]\\.",
    "cve": "CVE-2023-43770",
    "severity": "MEDIUM",
    "cvss": "6.1",
    "description": "Roundcube cross-site scripting via linkrefs in plain text messages."
  },
  {
    "tech": "Zimbra",
    "version_match": "^8\\.",
    "cve": "CVE-2022-27925",
    "severity": "HIGH",
    "cvss": "7.2",
    "description": "Zimbra Collaboration mboximport RCE via directory traversal allowing arbitrary file write."
  },
  {
    "tech": "Zimbra",
    "version_match": "^(8|9)\\.",
    "cve": "CVE-2022-37042",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Zimbra mboximport authentication bypass allowing unauthenticated arbitrary file upload."
  },
  {
    "tech": "Zimbra",
    "version_match": "^(8|9)\\.",
    "cve": "CVE-2023-27925",
    "severity": "HIGH",
    "cvss": "8.8",
    "description": "Zimbra Collaboration Cross-site request forgery leading to account takeover."
  },
  {
    "tech": "Microsoft SharePoint",
    "version_match": "^1[56]\\.",
    "cve": "CVE-2019-0604",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Microsoft SharePoint deserialization RCE allowing unauthenticated code execution."
  },
  {
    "tech": "Microsoft SharePoint",
    "version_match": "^1[56]\\.",
    "cve": "CVE-2020-0646",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Microsoft SharePoint server-side script injection allowing unauthenticated RCE."
  },
  {
    "tech": "Citrix ADC",
    "version_match": "^1[023]\\.",
    "cve": "CVE-2019-19781",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Citrix ADC path traversal allows unauthenticated code execution on the appliance."
  },
  {
    "tech": "Citrix ADC",
    "version_match": "^1[023]\\.",
    "cve": "CVE-2020-8193",
    "severity": "HIGH",
    "cvss": "8.2",
    "description": "Citrix ADC improper access control allowing unauthenticated access to admin endpoints."
  },
  {
    "tech": "Citrix ADC",
    "version_match": "^1[234]\\.",
    "cve": "CVE-2022-27510",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Citrix ADC authentication bypass via specially crafted HTTP request to gateway functions."
  },
  {
    "tech": "Citrix ADC",
    "version_match": "^1[234]\\.",
    "cve": "CVE-2023-3519",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Citrix ADC unauthenticated RCE via stack buffer overflow in HTTP/2 multiplexing."
  },
  {
    "tech": "Pulse Secure VPN",
    "version_match": "^[89]\\.",
    "cve": "CVE-2019-11510",
    "severity": "CRITICAL",
    "cvss": "10.0",
    "description": "Pulse Secure VPN arbitrary file read allowing unauthenticated credential exposure."
  },
  {
    "tech": "Pulse Secure VPN",
    "version_match": "^[89]\\.",
    "cve": "CVE-2021-22893",
    "severity": "CRITICAL",
    "cvss": "10.0",
    "description": "Pulse Secure Connect VPN authentication bypass and RCE via arbitrary file read."
  },
  {
    "tech": "SonicWall SMA",
    "version_match": "^10\\.",
    "cve": "CVE-2021-20016",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "SonicWall SMA SQL injection allows unauthenticated credential access and session hijacking."
  },
  {
    "tech": "ProFTPD",
    "version_match": "^1\\.[23]\\.",
    "cve": "CVE-2019-12815",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "ProFTPD mod_copy unauthenticated arbitrary file copy allowing code execution."
  },
  {
    "tech": "vsftpd",
    "version_match": "^2\\.3\\.4$",
    "cve": "CVE-2011-2523",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "vsftpd 2.3.4 backdoor allows unauthenticated command shell via smiley face username."
  },
  {
    "tech": "OpenSSH",
    "version_match": "^[12345678]\\.",
    "cve": "CVE-2016-0777",
    "severity": "MEDIUM",
    "cvss": "6.5",
    "description": "OpenSSH client roaming feature information leak exposing private key material."
  },
  {
    "tech": "OpenSSH",
    "version_match": "^[34567]\\.",
    "cve": "CVE-2018-15473",
    "severity": "MEDIUM",
    "cvss": "5.3",
    "description": "OpenSSH user enumeration via timing difference in authentication responses."
  },
  {
    "tech": "OpenSSH",
    "version_match": "^(8\\.([0-8])|[1-7]\\.).*",
    "cve": "CVE-2023-38408",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "OpenSSH ssh-agent RCE via forwarded agent exploitation of loaded PKCS11 libraries."
  },
  {
    "tech": "OpenSSH",
    "version_match": "^(9\\.[0-7]|[1-8]\\.).*",
    "cve": "CVE-2024-6387",
    "severity": "CRITICAL",
    "cvss": "8.1",
    "description": "OpenSSH regreSSHion race condition in signal handler allows unauthenticated RCE as root."
  },
  {
    "tech": "Apache Tomcat",
    "version_match": "^9\\.0\\.([0-9]|[1-7][0-9]|8[0-6])$",
    "cve": "CVE-2019-17563",
    "severity": "HIGH",
    "cvss": "8.1",
    "description": "Apache Tomcat session fixation vulnerability via FORM authentication mechanism."
  },
  {
    "tech": "phpMyAdmin",
    "version_match": "^4\\.",
    "cve": "CVE-2018-12613",
    "severity": "HIGH",
    "cvss": "8.8",
    "description": "phpMyAdmin file inclusion vulnerability allowing authenticated RCE via crafted URL."
  },
  {
    "tech": "phpMyAdmin",
    "version_match": "^4\\.[0-8]\\.",
    "cve": "CVE-2019-18622",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "phpMyAdmin SQL injection via the Designer feature allowing unauthenticated data access."
  },
  {
    "tech": "Exim",
    "version_match": "^4\\.([0-9][0-9])$",
    "cve": "CVE-2019-10149",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Exim SMTP server RCE via malicious recipient address exploiting deliver_message function."
  },
  {
    "tech": "Exim",
    "version_match": "^4\\.([0-8][0-9]|9[0-2])$",
    "cve": "CVE-2020-28017",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Exim heap buffer overflow in receive_add_recipient allowing unauthenticated RCE."
  },
  {
    "tech": "Exim",
    "version_match": "^4\\.([0-9][0-9])$",
    "cve": "CVE-2021-38371",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "Exim SMTP smuggling vulnerability enabling bypass of email authentication mechanisms."
  },
  {
    "tech": "Postfix",
    "version_match": "^[23]\\.",
    "cve": "CVE-2023-51764",
    "severity": "MEDIUM",
    "cvss": "5.3",
    "description": "Postfix SMTP smuggling vulnerability allows email spoofing bypassing sender authentication."
  },
  {
    "tech": "Samba",
    "version_match": "^[34]\\.",
    "cve": "CVE-2017-7494",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "SambaCry RCE via shared library loading in writable share with Samba."
  },
  {
    "tech": "Samba",
    "version_match": "^[34]\\.",
    "cve": "CVE-2021-44142",
    "severity": "CRITICAL",
    "cvss": "9.9",
    "description": "Samba out-of-bounds heap write in vfs_fruit module allowing RCE as root."
  },
  {
    "tech": "MySQL",
    "version_match": "^[567]\\.",
    "cve": "CVE-2016-6662",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "MySQL remote code execution via rogue MySQL server or SQL injection and config file write."
  },
  {
    "tech": "MySQL",
    "version_match": "^[567]\\.",
    "cve": "CVE-2012-2122",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "MySQL authentication bypass via memcmp timing attack allowing root access."
  },
  {
    "tech": "PostgreSQL",
    "version_match": "^1[0-5]\\.",
    "cve": "CVE-2019-9193",
    "severity": "CRITICAL",
    "cvss": "7.2",
    "description": "PostgreSQL COPY TO/FROM PROGRAM allows superuser RCE via OS command execution."
  },
  {
    "tech": "PostgreSQL",
    "version_match": "^(9|1[0-4])\\.",
    "cve": "CVE-2022-1552",
    "severity": "HIGH",
    "cvss": "8.8",
    "description": "PostgreSQL Autovacuum superuser privilege escalation via extension injection."
  },
  {
    "tech": "Apache Airflow",
    "version_match": "^[12]\\.",
    "cve": "CVE-2020-11978",
    "severity": "HIGH",
    "cvss": "8.8",
    "description": "Apache Airflow remote code execution via template injection in task commands."
  },
  {
    "tech": "Apache Airflow",
    "version_match": "^[12]\\.",
    "cve": "CVE-2022-40127",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Apache Airflow Example DAG RCE allowing unauthenticated code execution if example DAGs enabled."
  },
  {
    "tech": "HashiCorp Vault",
    "version_match": "^1\\.[0-9]\\.",
    "cve": "CVE-2021-3024",
    "severity": "MEDIUM",
    "cvss": "5.0",
    "description": "HashiCorp Vault HTTP proxy configuration bypass exposing request credentials."
  },
  {
    "tech": "Node.js",
    "version_match": "^(10|12|14)\\.",
    "cve": "CVE-2021-22959",
    "severity": "MEDIUM",
    "cvss": "6.5",
    "description": "Node.js HTTP request smuggling via improper parsing of Transfer-Encoding header."
  },
  {
    "tech": "Node.js",
    "version_match": "^(12|14|16)\\.",
    "cve": "CVE-2022-32212",
    "severity": "CRITICAL",
    "cvss": "8.1",
    "description": "Node.js DNS rebinding vulnerability via IsAllowedHost check bypass."
  },
  {
    "tech": "Apache Maven",
    "version_match": "^[23]\\.",
    "cve": "CVE-2021-26291",
    "severity": "CRITICAL",
    "cvss": "9.1",
    "description": "Apache Maven HTTP to HTTPS dependency download downgrade enabling man-in-the-middle."
  },
  {
    "tech": "Gradle",
    "version_match": "^[567]\\.",
    "cve": "CVE-2021-32751",
    "severity": "HIGH",
    "cvss": "7.4",
    "description": "Gradle build tool arbitrary code execution via malicious build metadata injection."
  },
  {
    "tech": "Apache ActiveMQ",
    "version_match": "^5\\.(1[0-5])\\.",
    "cve": "CVE-2016-3088",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Apache ActiveMQ Fileserver RCE via HTTP PUT to upload and execute arbitrary files."
  },
  {
    "tech": "Apache ActiveMQ",
    "version_match": "^5\\.(1[0-5]|[0-9])\\.",
    "cve": "CVE-2023-46604",
    "severity": "CRITICAL",
    "cvss": "10.0",
    "description": "Apache ActiveMQ OpenWire protocol deserialization RCE via ClassInfo command."
  },
  {
    "tech": "Apache NiFi",
    "version_match": "^1\\.(1[0-4]|[0-9])\\.",
    "cve": "CVE-2023-34468",
    "severity": "CRITICAL",
    "cvss": "8.8",
    "description": "Apache NiFi H2 database driver allows authenticated JDBC deserialization RCE."
  },
  {
    "tech": "Grafana",
    "version_match": "^[78]\\.",
    "cve": "CVE-2021-43798",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "Grafana path traversal allows unauthenticated arbitrary file read via plugin endpoints."
  },
  {
    "tech": "Grafana",
    "version_match": "^[5-8]\\.",
    "cve": "CVE-2022-21703",
    "severity": "HIGH",
    "cvss": "8.8",
    "description": "Grafana CSRF vulnerability allows unauthorized modification of user data and admin actions."
  },
  {
    "tech": "Grafana",
    "version_match": "^[5-9]\\.",
    "cve": "CVE-2021-27358",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "Grafana snapshot authentication bypass allowing unauthenticated access to snapshots."
  },
  {
    "tech": "Kibana",
    "version_match": "^[67]\\.",
    "cve": "CVE-2019-7609",
    "severity": "CRITICAL",
    "cvss": "10.0",
    "description": "Kibana prototype pollution leading to arbitrary code execution via Timelion visualizer."
  },
  {
    "tech": "Kibana",
    "version_match": "^[567]\\.",
    "cve": "CVE-2018-17246",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Kibana local file inclusion vulnerability allows reading arbitrary files on server."
  },
  {
    "tech": "Apache Cassandra",
    "version_match": "^[23]\\.",
    "cve": "CVE-2020-17516",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "Apache Cassandra inter-node authentication bypass allows MITM attacks on cluster."
  },
  {
    "tech": "Liferay Portal",
    "version_match": "^[67]\\.",
    "cve": "CVE-2020-7961",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Liferay Portal JSON Web Services deserialization allows unauthenticated RCE."
  },
  {
    "tech": "Apache OFBiz",
    "version_match": "^1[0-7]\\.",
    "cve": "CVE-2021-26295",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Apache OFBiz Java deserialization allows unauthenticated remote code execution."
  },
  {
    "tech": "Apache OFBiz",
    "version_match": "^1[0-8]\\.",
    "cve": "CVE-2023-49070",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Apache OFBiz pre-authentication RCE via deprecated XML-RPC endpoint."
  },
  {
    "tech": "Adobe ColdFusion",
    "version_match": "^(2016|2018|2021)\\.",
    "cve": "CVE-2023-26360",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Adobe ColdFusion deserialization and RCE via improper access control on admin endpoints."
  },
  {
    "tech": "Adobe ColdFusion",
    "version_match": "^(2016|2018)\\.",
    "cve": "CVE-2019-7816",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Adobe ColdFusion unrestricted file upload vulnerability allowing arbitrary file write."
  },
  {
    "tech": "Microsoft IIS",
    "version_match": "^[678]\\.",
    "cve": "CVE-2017-7269",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "IIS 6.0 WebDAV buffer overflow in ScStoragePathFromUrl allowing unauthenticated RCE."
  },
  {
    "tech": "Microsoft IIS",
    "version_match": "^[567]\\.",
    "cve": "CVE-2010-2730",
    "severity": "CRITICAL",
    "cvss": "9.3",
    "description": "Microsoft IIS FastCGI extension buffer overflow allowing remote code execution."
  },
  {
    "tech": "Cisco IOS",
    "version_match": "^1[2-6]\\.",
    "cve": "CVE-2018-0171",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Cisco IOS Smart Install client RCE via unauthenticated message processing."
  },
  {
    "tech": "Cisco IOS",
    "version_match": "^1[2-6]\\.",
    "cve": "CVE-2017-6736",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Cisco IOS SNMP remote code execution via buffer overflow in SNMP subsystem."
  },
  {
    "tech": "Cisco RV",
    "version_match": "^[0-9]+\\.",
    "cve": "CVE-2021-1472",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Cisco RV router series command injection allowing unauthenticated RCE."
  },
  {
    "tech": "Cisco Hyperflex",
    "version_match": "^[34]\\.",
    "cve": "CVE-2021-1497",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Cisco HyperFlex HX cluster management command injection allowing unauthenticated RCE."
  },
  {
    "tech": "WordPress WP Statistics Plugin",
    "version_match": "^1[0-3]\\.",
    "cve": "CVE-2022-0952",
    "severity": "HIGH",
    "cvss": "8.8",
    "description": "WP Statistics plugin SQL injection allowing unauthorized data extraction."
  },
  {
    "tech": "WordPress LoginPress Plugin",
    "version_match": "^1\\.[0-6]\\.",
    "cve": "CVE-2022-0949",
    "severity": "HIGH",
    "cvss": "8.8",
    "description": "LoginPress plugin stored XSS allows admin session hijacking."
  },
  {
    "tech": "WordPress Social Warfare Plugin",
    "version_match": "^3\\.[0-5]\\.",
    "cve": "CVE-2019-9978",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "Social Warfare plugin XSS via stored payload in remote payload file."
  },
  {
    "tech": "WordPress Essential Addons Plugin",
    "version_match": "^5\\.[0-6]\\.",
    "cve": "CVE-2023-32243",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Essential Addons for Elementor privilege escalation via unauthenticated password reset."
  },
  {
    "tech": "Apache HTTP Server",
    "version_match": "^2\\.4\\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17)$",
    "cve": "CVE-2014-0226",
    "severity": "MEDIUM",
    "cvss": "6.8",
    "description": "Apache HTTP Server race condition in mod_status allows heap buffer overflow."
  },
  {
    "tech": "Apache HTTP Server",
    "version_match": "^2\\.4\\.(4[1-9]|50|51)$",
    "cve": "CVE-2022-30522",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "Apache HTTP Server mod_sed denial of service via excessively large input data."
  },
  {
    "tech": "HAProxy",
    "version_match": "^[12]\\.",
    "cve": "CVE-2021-40346",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "HAProxy HTTP request smuggling via integer overflow in header content-length parsing."
  },
  {
    "tech": "Varnish Cache",
    "version_match": "^[456]\\.",
    "cve": "CVE-2021-36740",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "Varnish Cache HTTP/2 request smuggling via improper header handling."
  },
  {
    "tech": "Squid Proxy",
    "version_match": "^[345]\\.",
    "cve": "CVE-2021-28651",
    "severity": "HIGH",
    "cvss": "7.4",
    "description": "Squid cache buffer overflow in URN processing allows denial of service."
  },
  {
    "tech": "Squid Proxy",
    "version_match": "^[345]\\.",
    "cve": "CVE-2020-25097",
    "severity": "HIGH",
    "cvss": "8.6",
    "description": "Squid SSRF vulnerability via improper URL authority component parsing."
  },
  {
    "tech": "Plex Media Server",
    "version_match": "^1\\.(2[0-5])\\.",
    "cve": "CVE-2020-5741",
    "severity": "HIGH",
    "cvss": "7.2",
    "description": "Plex Media Server deserialization RCE via malicious media library update."
  },
  {
    "tech": "Webmin",
    "version_match": "^1\\.(88|89|90|91|92)$",
    "cve": "CVE-2019-15107",
    "severity": "CRITICAL",
    "cvss": "10.0",
    "description": "Webmin backdoor in password_change.cgi allows unauthenticated remote code execution."
  },
  {
    "tech": "Webmin",
    "version_match": "^1\\.",
    "cve": "CVE-2022-36446",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Webmin command injection in package update module allows RCE with root privileges."
  },
  {
    "tech": "Nagios",
    "version_match": "^[45]\\.",
    "cve": "CVE-2021-37344",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Nagios XI command injection in switch.php allows unauthenticated RCE."
  },
  {
    "tech": "Zabbix",
    "version_match": "^[56]\\.",
    "cve": "CVE-2022-23131",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Zabbix SAML SSO authentication bypass allows unauthenticated access to admin panel."
  },
  {
    "tech": "Zabbix",
    "version_match": "^[456]\\.",
    "cve": "CVE-2021-27927",
    "severity": "HIGH",
    "cvss": "8.8",
    "description": "Zabbix CSRF vulnerability in user management allows privilege escalation."
  },
  {
    "tech": "ManageEngine",
    "version_match": "^[89][0-9][0-9][0-9]$",
    "cve": "CVE-2022-47966",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "ManageEngine SAML authentication RCE via Apache Santuario xmlsec library deserialization."
  },
  {
    "tech": "ManageEngine ServiceDesk",
    "version_match": "^1[01]\\.",
    "cve": "CVE-2021-44077",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "ManageEngine ServiceDesk Plus unauthenticated RCE via file upload in REST API."
  },
  {
    "tech": "SugarCRM",
    "version_match": "^1[12]\\.",
    "cve": "CVE-2023-22952",
    "severity": "CRITICAL",
    "cvss": "8.8",
    "description": "SugarCRM PHP injection via template engine allowing authenticated RCE."
  },
  {
    "tech": "vBulletin",
    "version_match": "^[45]\\.",
    "cve": "CVE-2019-16759",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "vBulletin pre-auth RCE via PHP object instantiation in routestring parameter."
  },
  {
    "tech": "vBulletin",
    "version_match": "^[45]\\.",
    "cve": "CVE-2020-17496",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "vBulletin widget template code execution bypass of CVE-2019-16759 patch."
  },
  {
    "tech": "OpenCart",
    "version_match": "^[23]\\.",
    "cve": "CVE-2022-27176",
    "severity": "MEDIUM",
    "cvss": "6.1",
    "description": "OpenCart reflected XSS in search functionality leading to session hijacking."
  },
  {
    "tech": "PrestaShop",
    "version_match": "^1\\.[67]\\.",
    "cve": "CVE-2022-31101",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "PrestaShop SQL injection via blindly injected search parameters allowing RCE."
  },
  {
    "tech": "PrestaShop",
    "version_match": "^1\\.[67]\\.",
    "cve": "CVE-2023-30149",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "PrestaShop SQL injection in blockwishlist module allowing unauthenticated data theft."
  },
  {
    "tech": "Kentico CMS",
    "version_match": "^1[012]\\.",
    "cve": "CVE-2019-10068",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Kentico CMS deserialization allows unauthenticated remote code execution."
  },
  {
    "tech": "DotNetNuke",
    "version_match": "^[789]\\.",
    "cve": "CVE-2018-15811",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "DotNetNuke weak encryption allowing attackers to decrypt sensitive profile fields."
  },
  {
    "tech": "Oracle E-Business Suite",
    "version_match": "^12\\.",
    "cve": "CVE-2022-21587",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Oracle E-Business Suite unauthenticated arbitrary file upload leading to RCE."
  },
  {
    "tech": "SAP NetWeaver",
    "version_match": "^7\\.[0-5]\\.",
    "cve": "CVE-2020-6287",
    "severity": "CRITICAL",
    "cvss": "10.0",
    "description": "SAP RECON vulnerability allows unauthenticated creation of admin accounts via LM Config wizard."
  },
  {
    "tech": "SAP NetWeaver",
    "version_match": "^7\\.[0-5]\\.",
    "cve": "CVE-2022-22536",
    "severity": "CRITICAL",
    "cvss": "10.0",
    "description": "SAP ICMAD request smuggling vulnerability allows session hijacking and RCE."
  },
  {
    "tech": "Ivanti Connect Secure",
    "version_match": "^9\\.",
    "cve": "CVE-2023-46805",
    "severity": "HIGH",
    "cvss": "8.2",
    "description": "Ivanti Connect Secure authentication bypass via path traversal in web component."
  },
  {
    "tech": "Ivanti Connect Secure",
    "version_match": "^(9|22)\\.",
    "cve": "CVE-2024-21887",
    "severity": "CRITICAL",
    "cvss": "9.1",
    "description": "Ivanti Connect Secure command injection in web components allowing authenticated RCE."
  },
  {
    "tech": "MobileIron",
    "version_match": "^1[01]\\.",
    "cve": "CVE-2021-22937",
    "severity": "CRITICAL",
    "cvss": "9.1",
    "description": "MobileIron Core SSRF and RCE via malicious server request forgery."
  },
  {
    "tech": "Microsoft Outlook",
    "version_match": "^1[5-6]\\.",
    "cve": "CVE-2023-23397",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Microsoft Outlook zero-click credential theft via specially crafted calendar item."
  },
  {
    "tech": "Apache James",
    "version_match": "^[23]\\.",
    "cve": "CVE-2017-12197",
    "severity": "MEDIUM",
    "cvss": "6.5",
    "description": "Apache James server deserialization issue in user provisioning module."
  },
  {
    "tech": "Apache Log4j 1.x",
    "version_match": "^1\\.",
    "cve": "CVE-2022-23302",
    "severity": "HIGH",
    "cvss": "8.8",
    "description": "Log4j 1.x JMSSink deserialization vulnerability allows RCE with network access to sink."
  },
  {
    "tech": "Apache Log4j 1.x",
    "version_match": "^1\\.",
    "cve": "CVE-2019-17571",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Log4j 1.x SocketServer deserialization of untrusted data allows RCE."
  },
  {
    "tech": "Pip/PyPI setuptools",
    "version_match": "^([0-5][0-9])\\.",
    "cve": "CVE-2022-40897",
    "severity": "MEDIUM",
    "cvss": "5.9",
    "description": "Python setuptools ReDoS vulnerability via specially crafted package version string."
  },
  {
    "tech": "Laravel Framework",
    "version_match": "^[56789]\\.",
    "cve": "CVE-2021-3129",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Laravel Ignition debug mode RCE via log file poisoning and PHP deserialization."
  },
  {
    "tech": "Laravel Framework",
    "version_match": "^[56]\\.",
    "cve": "CVE-2018-15133",
    "severity": "HIGH",
    "cvss": "8.1",
    "description": "Laravel deserialization vulnerability via crafted encrypted cookie value."
  },
  {
    "tech": "Symfony Framework",
    "version_match": "^[234]\\.",
    "cve": "CVE-2017-16653",
    "severity": "MEDIUM",
    "cvss": "5.9",
    "description": "Symfony CSRF token fixation vulnerability via remember-me functionality."
  },
  {
    "tech": "Symfony Framework",
    "version_match": "^[34]\\.",
    "cve": "CVE-2021-41268",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "Symfony Security Core access decision leak in firewall security context."
  },
  {
    "tech": "Strapi CMS",
    "version_match": "^[34]\\.",
    "cve": "CVE-2023-22621",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Strapi CMS template injection allowing unauthenticated remote code execution."
  },
  {
    "tech": "Ghost CMS",
    "version_match": "^[34]\\.",
    "cve": "CVE-2022-41697",
    "severity": "MEDIUM",
    "cvss": "5.3",
    "description": "Ghost CMS user enumeration via difference in error responses during login."
  },
  {
    "tech": "Moodle LMS",
    "version_match": "^[23]\\.",
    "cve": "CVE-2020-1754",
    "severity": "MEDIUM",
    "cvss": "5.4",
    "description": "Moodle stored XSS in SCORM activity allowing session hijacking attacks."
  },
  {
    "tech": "Moodle LMS",
    "version_match": "^[23456789]\\.",
    "cve": "CVE-2021-36394",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Moodle RCE via unrestricted file upload in lesson activity with teacher permissions."
  },
  {
    "tech": "Nextcloud",
    "version_match": "^(1[0-9]|20|21|22)\\.",
    "cve": "CVE-2021-32679",
    "severity": "MEDIUM",
    "cvss": "6.5",
    "description": "Nextcloud insufficient restriction on shared file access leading to data leakage."
  },
  {
    "tech": "ownCloud",
    "version_match": "^([0-9]|10)\\.",
    "cve": "CVE-2023-49103",
    "severity": "CRITICAL",
    "cvss": "10.0",
    "description": "ownCloud graphapi app information disclosure exposes admin password and PHP config."
  },
  {
    "tech": "GitLab",
    "version_match": "^(11|12|13|14)\\.",
    "cve": "CVE-2021-4191",
    "severity": "MEDIUM",
    "cvss": "5.3",
    "description": "GitLab GraphQL API user enumeration via unauthenticated queries."
  },
  {
    "tech": "Sonatype Nexus",
    "version_match": "^3\\.(1[0-9]|2[0-9]|30)\\.",
    "cve": "CVE-2020-10199",
    "severity": "CRITICAL",
    "cvss": "8.8",
    "description": "Sonatype Nexus Repository Manager EL injection allowing authenticated RCE."
  },
  {
    "tech": "Sonatype Nexus",
    "version_match": "^2\\.",
    "cve": "CVE-2019-7238",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Sonatype Nexus Repository Manager deserialization RCE without authentication."
  },
  {
    "tech": "JFrog Artifactory",
    "version_match": "^[67]\\.",
    "cve": "CVE-2020-7931",
    "severity": "HIGH",
    "cvss": "8.8",
    "description": "JFrog Artifactory Server-Side Template Injection allows RCE with authenticated access."
  },
  {
    "tech": "Bamboo",
    "version_match": "^[56789]\\.",
    "cve": "CVE-2022-26133",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Atlassian Bamboo deserialization vulnerability allows RCE via inter-process communication."
  },
  {
    "tech": "Bitbucket",
    "version_match": "^[5-8]\\.",
    "cve": "CVE-2022-36804",
    "severity": "CRITICAL",
    "cvss": "9.9",
    "description": "Atlassian Bitbucket command injection in multiple API endpoints allowing RCE."
  },
  {
    "tech": "Spring Cloud Gateway",
    "version_match": "^3\\.[01]\\.",
    "cve": "CVE-2022-22947",
    "severity": "CRITICAL",
    "cvss": "10.0",
    "description": "Spring Cloud Gateway code injection via actuator endpoint SpEL expression evaluation."
  },
  {
    "tech": "Apache Dubbo",
    "version_match": "^[23]\\.",
    "cve": "CVE-2021-25641",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Apache Dubbo deserialization via Hessian2 protocol allows unauthenticated RCE."
  },
  {
    "tech": "Apache Shiro",
    "version_match": "^1\\.(0|1|2|3|4|5|6|7|8|9)\\.",
    "cve": "CVE-2016-4437",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Apache Shiro deserialization via remember-me cookie allows unauthenticated RCE."
  },
  {
    "tech": "Apache Shiro",
    "version_match": "^1\\.(1[0-3])\\.",
    "cve": "CVE-2023-34478",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Apache Shiro authentication bypass via path traversal in URL pattern matching."
  },
  {
    "tech": "JBoss AS",
    "version_match": "^[45678]\\.",
    "cve": "CVE-2017-7504",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "JBoss JMXInvokerServlet deserialization allows unauthenticated remote code execution."
  },
  {
    "tech": "JBoss AS",
    "version_match": "^[45678]\\.",
    "cve": "CVE-2015-7501",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "JBoss Java deserialization via Apache Commons Collections allowing unauthenticated RCE."
  },
  {
    "tech": "WildFly",
    "version_match": "^(1[0-9]|2[0-9])\\.",
    "cve": "CVE-2020-25640",
    "severity": "MEDIUM",
    "cvss": "5.0",
    "description": "WildFly info disclosure of class path entries via exposed management interface."
  },
  {
    "tech": "GlassFish",
    "version_match": "^[45]\\.",
    "cve": "CVE-2017-1000030",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "GlassFish directory traversal in admin console allows unauthenticated file read."
  },
  {
    "tech": "Zend Framework",
    "version_match": "^[123]\\.",
    "cve": "CVE-2021-3007",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Zend Framework deserialization vulnerability allows RCE via crafted cookie."
  },
  {
    "tech": "CodeIgniter",
    "version_match": "^[23]\\.",
    "cve": "CVE-2019-10916",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "CodeIgniter cookie-based session insecure deserialization allowing RCE."
  },
  {
    "tech": "CakePHP",
    "version_match": "^[23]\\.",
    "cve": "CVE-2021-22820",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "CakePHP SQL injection via improper input validation in database conditions."
  },
  {
    "tech": "Yii Framework",
    "version_match": "^[12]\\.",
    "cve": "CVE-2020-15148",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Yii2 deserialization of untrusted data via destructure method gadget chains."
  },
  {
    "tech": "Ruby on Rails",
    "version_match": "^[345]\\.",
    "cve": "CVE-2019-5420",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Ruby on Rails remote code execution via file content guessing in development mode."
  },
  {
    "tech": "Ruby on Rails",
    "version_match": "^[345]\\.",
    "cve": "CVE-2020-8163",
    "severity": "HIGH",
    "cvss": "8.8",
    "description": "Ruby on Rails render path code injection via user-controlled values in template rendering."
  },
  {
    "tech": "Ruby on Rails",
    "version_match": "^[23456]\\.",
    "cve": "CVE-2013-0156",
    "severity": "CRITICAL",
    "cvss": "10.0",
    "description": "Ruby on Rails XML parameter parsing RCE via YAML or XML deserialization gadgets."
  },
  {
    "tech": "Django",
    "version_match": "^[23]\\.",
    "cve": "CVE-2021-35042",
    "severity": "CRITICAL",
    "cvss": "9.8",
    "description": "Django SQL injection in QuerySet.order_by() when using unsanitized user input."
  },
  {
    "tech": "Django",
    "version_match": "^[23]\\.",
    "cve": "CVE-2022-36359",
    "severity": "HIGH",
    "cvss": "8.8",
    "description": "Django open redirect via FileResponse content-disposition header manipulation."
  },
  {
    "tech": "Flask",
    "version_match": "^[01]\\.",
    "cve": "CVE-2018-1000656",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "Flask denial of service via memory exhaustion by sending large multipart/form-data."
  },
  {
    "tech": "Werkzeug",
    "version_match": "^[01]\\.",
    "cve": "CVE-2023-25577",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "Werkzeug multipart parsing denial of service via excessive resource consumption."
  },
  {
    "tech": "Werkzeug",
    "version_match": "^[012]\\.(0|1|2)\\.",
    "cve": "CVE-2023-46136",
    "severity": "HIGH",
    "cvss": "7.5",
    "description": "Werkzeug multipart content-type header parsing remote denial of service attack."
  }
]

# Vulnerable Test Targets — VulnusLab

A curated list of **legally scannable** vulnerable websites you can use to:
- Test new scanner features without risking unauthorized scans
- Take screenshots for marketing / landing page
- Demo the product to potential customers
- Train your eye on real vulnerability patterns

**All targets here are explicitly authorized for security testing.** Scanning anything NOT on this list = legal risk (CFAA / IT Act 2000).

---

## Top picks (best for demos)

| URL | Tech Stack | Why it's good |
|---|---|---|
| `http://demo.testfire.net` | Java / Apache Tomcat | **Confirmed works from your VPS.** IBM AppScan demo (Altoro Mutual bank). Clean modern-looking finding output. |
| `http://testphp.vulnweb.com` | PHP / MySQL / Apache | Most popular pentest target. Has SQLi, XSS, command injection, LFI, RFI. (Was blocked from your VPS once — retry.) |
| `http://lab_juiceshop:3000` | Node.js / Angular | **Internal lab** — modern OWASP Top 10. Best for showing OTP, GraphQL, IDOR findings. |
| `http://lab_dvwa` | PHP / MySQL | **Internal lab** — most vulnerable, every classic web vuln. Default creds: `admin / password` |
| `http://lab_bwapp` | PHP / MySQL | **Internal lab** — 100+ bugs. Creds: `bee / bug` |

---

## Public vulnerable targets (Acunetix demo set)

Different tech stacks — useful for showing your scanner works across languages:

| URL | Tech |
|---|---|
| `http://testphp.vulnweb.com` | PHP / MySQL |
| `http://testasp.vulnweb.com` | Classic ASP / SQL Server |
| `http://testaspnet.vulnweb.com` | ASP.NET / SQL Server |
| `http://testhtml5.vulnweb.com` | HTML5 / JavaScript modern |
| `http://rest.vulnweb.com` | REST API |

Direct vulnerable paths:
- `http://testphp.vulnweb.com/listproducts.php?cat=1` — SQLi on `cat` param
- `http://testphp.vulnweb.com/search.php?test=query` — XSS on `test` param
- `http://testphp.vulnweb.com/showimage.php?file=` — LFI on `file` param

---

## Other public vulnerable demos

| URL | What it has | Notes |
|---|---|---|
| `http://demo.testfire.net` | XSS, SQLi, broken auth | IBM Altoro Mutual bank |
| `http://zero.webappsecurity.com` | XSS, SQLi, IDOR, session | Micro Focus demo bank |
| `http://www.webscantest.com` | XSS, SQLi, IDOR | NTOObjectives demo |
| `http://hackazon.webscantest.com` | E-commerce vulns | Multi-page app |
| `https://juice-shop.herokuapp.com` | OWASP Top 10 modern | Public Juice Shop |

---

## SSL / TLS test targets

For testing your SSL scanner:

| URL | Purpose |
|---|---|
| `https://badssl.com` | Index of all SSL test cases |
| `https://expired.badssl.com` | Expired certificate |
| `https://self-signed.badssl.com` | Self-signed certificate |
| `https://wrong.host.badssl.com` | Wrong hostname on cert |
| `https://untrusted-root.badssl.com` | Untrusted CA |
| `https://revoked.badssl.com` | Revoked certificate |
| `https://no-common-name.badssl.com` | Missing Common Name |
| `https://sha1-intermediate.badssl.com` | Weak SHA-1 in chain |
| `https://1000-sans.badssl.com` | Cert with 1000 SANs |
| `https://rsa8192.badssl.com` | 8192-bit RSA (slow handshake) |

---

## CTF-style targets (require registration / interactive)

| URL | What | Notes |
|---|---|---|
| `https://www.hackthissite.org` | CTF challenges | Free, requires account |
| `https://portswigger.net/web-security/all-labs` | 200+ labs (XSS, SQLi, JWT, GraphQL, OAuth) | Free with Burp Community account. Each lab has unique short URL like `https://0a1b2c3d.web-security-academy.net` |
| `https://overthewire.org/wargames/natas/` | Web wargame | SSH-based |
| `https://crackmes.one` | Reverse engineering | Less relevant for web pentest |

---

## Your built-in lab containers (always work, no internet needed)

These run in your Docker compose stack — guaranteed reachable:

| Container | Internal URL | External URL | Credentials |
|---|---|---|---|
| DVWA | `http://lab_dvwa` | `http://YOUR_VPS:8001` | `admin / password` |
| WebGoat | `http://lab_webgoat:8080` | `http://YOUR_VPS:8002` | Self-register |
| Mutillidae | `http://lab_mutillidae` | `http://YOUR_VPS:8003` | `admin / admin` |
| bWAPP | `http://lab_bwapp` | `http://YOUR_VPS:8004` | `bee / bug` |
| Juice Shop | `http://lab_juiceshop:3000` | `http://YOUR_VPS:3000` | self-register |

**Use internal URLs** (`http://lab_dvwa`) when scanning from the dashboard — they're faster and not rate-limited.

---

## Important legal rules

### You CAN scan:
- Any URL listed in this file (all explicitly authorized)
- Your own websites and infrastructure
- Sites where you have **written permission** from the owner

### You CANNOT scan:
- Random websites you don't own
- Competitors' sites
- Banks, government sites, hospitals, schools
- Sites of your friends/family without their written consent
- Any "interesting-looking" target you found

**Unauthorized scanning is a criminal offense:**
- India: IT Act 2000 Section 66 — fine + 3 years prison
- USA: CFAA — fines + up to 10 years prison
- EU: GDPR + national cybercrime laws

Even passive scans can be considered hostile reconnaissance.

---

## Quick test script

To verify all public targets are reachable from your VPS:

```bash
for url in \
  "http://demo.testfire.net" \
  "http://testphp.vulnweb.com" \
  "http://testasp.vulnweb.com" \
  "http://zero.webappsecurity.com" \
  "http://www.webscantest.com" \
  "https://badssl.com"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$url" || echo "TIMEOUT")
  printf "%-45s %s\n" "$url" "$code"
done
```

Run on VPS — anything that returns 200/301/302 is reachable. TIMEOUT or 000 means blocked.

---

## Recommended scan rotation for marketing screenshots

Best targets to show variety in your reports:

1. **`http://demo.testfire.net`** — Java/Tomcat, shows JSESSIONID issues
2. **`http://testphp.vulnweb.com`** — PHP/MySQL, shows classic web vulns
3. **`http://lab_juiceshop:3000`** — Modern Node.js, shows OTP/GraphQL
4. **`http://lab_dvwa`** — Most vulnerabilities, biggest report

Take one PDF from each → use as marketing assets / case studies.

---

## Need more targets?

Open a feature request or just add to this file. Other places to find vulnerable hosts:

- https://github.com/vavkamil/awesome-vulnerable-apps (huge curated list)
- https://owasp.org/www-project-vulnerable-web-applications-directory/
- https://github.com/topics/vulnerable-web-application

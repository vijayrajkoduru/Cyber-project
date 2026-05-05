# OSCP Dashboard — Full Scan Audit Report
**Date:** 5 May 2026 | **Project:** Cyber-project

---

## WHY YOU ARE NOT GETTING REAL FINDINGS

The core problem is **two types of failures** across the project:

1. **Tool uses API-key sources without keys** → tool starts, prints banner, exits with zero results
2. **Tool runs correctly but output parsing is wrong** → real data is there but not extracted into findings

---

## MODULE-BY-MODULE STATUS

### ✅ WORKING — Gives Real Findings

| Module | Tool | Why It Works |
|--------|------|-------------|
| Network Scanning → Nmap | `nmap` | Fully working. Parser extracts ports, services, versions. |
| Network Scanning → Gobuster | `gobuster` | Working. Parser extracts paths and status codes. |
| Network Scanning → Nikto | `nikto` | Working. Finds real web vulnerabilities. |
| Network Scanning → Hydra | `hydra` | Working. Extracts cracked login credentials. |
| Network Scanning → SQLMap | `sqlmap` | Working. Detects real SQL injection. |
| Network Scanning → WafW00f | `wafw00f` | Working. Detects WAF presence. |
| Network Scanning → WhatWeb | `whatweb` | Working. Fingerprints CMS, frameworks, headers. |
| Network Attacks → MITM Setup | `/proc/sys/net/ipv4/ip_forward` | Reads real kernel value. Real finding. |
| Network Attacks → Network Scan | `nmap` | Real port scan results. |
| DNS Recon | `dig` | Real DNS records (A, MX, NS, TXT, SOA). |
| WHOIS | `whois` | Real registration data. |

---

### ❌ BROKEN — Returns Empty or Fake Findings

| Module | Tool | Root Cause | Fix |
|--------|------|-----------|-----|
| **OSINT → Email Harvesting** | `theHarvester` | Uses `google,bing,linkedin,hunter` — ALL need paid API keys | Changed to free sources (`crtsh,dnsdumpster,hackertarget,anubis,certspotter`). Add API keys for real emails. |
| **OSINT → Recon-ng** | `recon-cli` | Module `recon/domains-hosts/google_site_web` does not exist → "Invalid module name" | **Already fixed:** replaced with `dnsrecon` + `whois` + `crt.sh` |
| **OSINT → SpiderFoot** | `spiderfoot` | SpiderFoot CLI not installed on Kali by default; needs `pip3 install spiderfoot` | Install it OR use the web UI on port 5001 |
| **OSINT → Maltego Guide** | None | This is intentional — Maltego is GUI-only, no CLI | No fix needed — it generates manual instructions |
| **Nuclei** | `nuclei` | New versions output JSON; parser reads plain text → all lines treated as raw output | Needs `-json` flag + JSON parser |
| **Recon → theHarvester** (route `/api/scan/theharvester`) | `theHarvester` | Uses `bing,duckduckgo,crtsh` — duckduckgo removed from theHarvester in v4+ | Change source to `bing,crtsh,dnsdumpster` |
| **Masscan** | `masscan` | Requires `sudo` — will fail unless passwordless sudo is configured on Kali | Run: `echo 'kali ALL=(ALL) NOPASSWD: /usr/bin/masscan' >> /etc/sudoers` |
| **theHarvester binary name** | `theHarvester` (capital H) | On some Kali versions the binary is `theharvester` (lowercase) | Use `theharvester` lowercase in commands |

---

### ⚠️ WORKING BUT RESULTS DEPEND ON TARGET

| Module | Notes |
|--------|-------|
| **OSINT on test domains** (e.g. `testphp.vulnweb.com`) | Test servers have no real email footprint — free OSINT sources will always return nothing. Use a real company domain to get real results. |
| **Recon-ng subdomains** | Only finds what's in crt.sh certificate logs — good for real domains, empty for test servers. |
| **Nikto** | Needs a running HTTP server. If target is down or blocking, returns nothing. |
| **Gobuster** | Needs a wordlist file at `/usr/share/wordlists/dirb/common.txt` on Kali. If missing, run: `apt install dirb` |

---

## FIXES ALREADY APPLIED

| Fix | Status |
|-----|--------|
| OSINT email harvesting — changed to free sources (crtsh, hackertarget, anubis, certspotter, rapiddns, otx, urlscan) | ✅ Done |
| Recon-ng — replaced broken `recon-cli` with `dnsrecon + whois + crt.sh` | ✅ Done |
| PDF — removed tool descriptions from report (only real findings shown) | ✅ Done |
| PDF — black text, bright red for HIGH/CRITICAL | ✅ Done |
| Session persistence (logins survive backend restart) | ✅ Done |
| Admin 401 fix | ✅ Done |
| Plan locking with UpgradeWall | ✅ Done |
| All dim text made readable in UI | ✅ Done |
| API keys backend support (Shodan, Hunter, VirusTotal, HIBP, SecurityTrails) | ✅ Done |
| API key settings panel in UI | ✅ Done |

---

## FIXES STILL NEEDED

### Fix 1 — Nuclei JSON parsing (5 min fix)
**File:** `main.py` → `/api/scan/nuclei`
**Change:** Add `-jsonl` flag and parse JSON lines instead of raw text.

### Fix 2 — Masscan passwordless sudo (Kali terminal, 1 command)
```bash
echo 'kali ALL=(ALL) NOPASSWD: /usr/bin/masscan' | sudo tee -a /etc/sudoers
```

### Fix 3 — SpiderFoot install (Kali terminal, 5 min)
```bash
pip3 install spiderfoot
# Then run: spiderfoot -l 127.0.0.1:5001
```

### Fix 4 — Ensure wordlists exist (Kali terminal)
```bash
sudo apt install -y dirb wordlists seclists
sudo gzip -d /usr/share/wordlists/rockyou.txt.gz
```

---

## API KEYS — WHAT THEY UNLOCK & COST

### Why API Keys Matter
Free OSINT sources (crt.sh, dnsdumpster, hackertarget) only find **subdomains and DNS records**.
API keys unlock **emails, breached passwords, open ports with CVEs, full org infrastructure maps**.

---

### API Key Pricing Table (INR)

| Service | What You Get | Free Tier | Paid Plans | Get Key |
|---------|-------------|-----------|-----------|---------|
| **Shodan** | Open ports, banners, CVEs on any IP worldwide. Most powerful OSINT tool. | 100 queries/month | **₹840/month** (Freelancer) · **₹8,400/month** (Small Business) | shodan.io |
| **Hunter.io** | Email addresses for any company domain. Finds CEO, CTO, developer emails. | 25 searches/month | **₹1,680/month** (Starter, 500 searches) · **₹4,200/month** (Growth) | hunter.io/api-keys |
| **VirusTotal** | Domain reputation, passive DNS history, malware associations, WHOIS. | 4 requests/minute, 500/day | **₹0** (free is sufficient for most scans) · Premium: ~₹25,000/month | virustotal.com/gui/my-apikey |
| **HaveIBeenPwned** | Breached email addresses for a domain. Shows which employees' passwords are leaked. | None (paid only) | **₹290/month** (£3.50/month) | haveibeenpwned.com/API/Key |
| **SecurityTrails** | Full subdomain history, DNS changes over time, reverse DNS. | 50 requests/month | **₹3,360/month** (Basic) · **₹16,800/month** (Advanced) | securitytrails.com |
| **Censys** | Similar to Shodan — internet-wide port/certificate scanning. | 250 queries/month | **₹0** (community) · **₹8,400+/month** (Teams) | search.censys.io |
| **FullHunt** | Attack surface discovery — finds all assets of a company. | 10 searches/day | **₹1,680/month** | fullhunt.io |

---

### Recommended Starter Package (Minimum Cost for Real Findings)

| Service | Plan | Monthly Cost (INR) |
|---------|------|-------------------|
| **Shodan** | Freelancer (100 queries → upgrade to paid) | **₹840** |
| **Hunter.io** | Free (25 searches/month) | **₹0** |
| **VirusTotal** | Free (500 req/day) | **₹0** |
| **HaveIBeenPwned** | Basic | **₹290** |
| **TOTAL** | | **₹1,130/month** |

With this setup, for any real company domain you scan, you will get:
- All employee email addresses
- Which emails were in data breaches
- All open ports and running services with CVE numbers
- Domain reputation and malware history
- All subdomains

---

### Professional Package (For Client Pentests)

| Service | Plan | Monthly Cost (INR) |
|---------|------|-------------------|
| Shodan | Small Business | ₹8,400 |
| Hunter.io | Growth (10,000 searches) | ₹4,200 |
| VirusTotal | Premium | ₹25,000 |
| HaveIBeenPwned | Basic | ₹290 |
| SecurityTrails | Basic | ₹3,360 |
| **TOTAL** | | **₹41,250/month** |

---

## HOW TO ADD API KEYS (Step by Step)

### Method 1 — Via Dashboard Settings (Recommended)
1. Open the dashboard → click **Settings** in the sidebar
2. Scroll to **OSINT API Keys**
3. Paste each key and click **Save API Keys to Backend**
4. Keys are saved to Kali in `.env` file — active immediately
5. Re-run OSINT scans

### Method 2 — Directly on Kali Terminal
```bash
# Edit or create the .env file in your project folder
nano ~/Cyber-project/.env

# Add these lines:
SHODAN_KEY=your_shodan_key_here
HUNTER_KEY=your_hunter_key_here
VIRUSTOTAL_KEY=your_vt_key_here
HIBP_KEY=your_hibp_key_here
SECTRAILS_KEY=your_sectrails_key_here

# Then restart the backend:
pkill -f uvicorn
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

---

## QUICK START — GET REAL FINDINGS TODAY (Free)

These steps cost ₹0 and give real results on any real company domain:

1. **Register for free API keys:**
   - Go to `shodan.io` → Register → Copy your API key (free: 100 queries/month)
   - Go to `hunter.io/api-keys` → Register → Copy key (free: 25 searches/month)
   - Go to `virustotal.com/gui/my-apikey` → Register → Copy key (free: 500 req/day)

2. **Add keys in Dashboard → Settings → OSINT API Keys**

3. **Scan a real target** (not `testphp.vulnweb.com` — it's a test server with no real footprint):
   - Try: `acunetix.com` (their own company), or any real company you're authorized to test

4. **Run Email Harvesting + Recon-ng scans** → you will now see:
   - Real email addresses
   - Open ports with CVEs
   - Subdomain list
   - Domain reputation

---

## TEST DOMAINS THAT GIVE REAL OSINT RESULTS

| Domain | What You'll Find |
|--------|-----------------|
| `acunetix.com` | Real emails, subdomains, open ports |
| `vulnweb.com` (parent domain) | More data than `testphp.vulnweb.com` |
| `hackthebox.com` | Good for testing — real org with real footprint |
| Any company you're authorized to test | Full results with API keys |

> ⚠️ **Only scan domains you own or have written authorization to test.**

---

*Generated by OSCP Dashboard Audit — 5 May 2026*

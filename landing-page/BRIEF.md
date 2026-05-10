# Landing Page — Full Project Brief

## What We Are Building

A high-end marketing/landing page website that presents and sells access
to our CyberSecurity Dashboard (cyber-project).

This is a SEPARATE website from the actual dashboard.

---

## Two Websites Explained

### Website 1 — CyberSecurity Dashboard (already built)
- Private tool — only paying customers access this
- 51 security scanners (XSS, SQLi, Nmap, Nikto, etc.)
- Multi-user accounts with JWT login
- PDF/JSON/CSV reports
- Runs on VPS (Kali Linux + FastAPI + React)
- URL: your VPS IP / domain

### Website 2 — Landing Page (to be built)
- Public marketing site — anyone can visit
- Shows what the tool does
- Pricing plans
- Buy Now button
- After payment → system creates account → sends credentials by email
- Host FREE on Netlify or Vercel (no new server needed)

---

## Customer Flow

```
1. Customer visits Landing Page (Website 2)
2. Reads features, use cases, pricing
3. Clicks "Buy Now" on a plan
4. Pays via Razorpay or Stripe
5. Payment webhook hits our FastAPI backend
6. System auto-creates their account in SQLite
7. Email sent to customer: username + password
8. Customer opens Dashboard (Website 1) and logs in
9. Customer scans their targets
```

---

## Landing Page Sections (in order)

### 1. Hero Section
- Big bold headline
- Subheadline explaining the tool
- "Start Now" / "Buy Now" CTA button
- Screenshot or animated demo of the dashboard
- Background: dark, cyber themed, particle effects or grid

### 2. What Is It?
- 3-4 sentences explaining the product
- Enterprise-grade cybersecurity scanning platform
- 51 automated security tools in one dashboard
- Used by pentesters, security teams, developers

### 3. Features Section
- 51 Web Application Scanners
- XSS, SQL Injection, Port Scan, SSL Analysis
- PDF / JSON / CSV Reports
- Built-in Vulnerable Labs (DVWA, WebGoat, Juice Shop)
- Multi-user accounts
- Kali Linux powered backend
- Real tools: Nmap, Nikto, Metasploit, Hydra

### 4. Use Cases
#### Enterprise
- Security audits for company infrastructure
- Compliance scanning (OWASP Top 10)
- Team accounts — multiple security engineers
- Automated scheduled scans
- Professional PDF reports for management

#### Individual
- Penetration tester / freelancer
- OSCP / CEH exam preparation
- Bug bounty hunters
- Security students and researchers
- CTF (Capture The Flag) competitions

### 5. How It Works (3 Steps)
- Step 1: Choose your plan and pay
- Step 2: Receive credentials by email instantly
- Step 3: Login and start scanning

### 6. Pricing Plans
(TO BE DECIDED — fill in your prices)

| Plan        | Price      | Users | Features                        |
|-------------|------------|-------|---------------------------------|
| Individual  | ??? /month | 1     | All 51 scanners, PDF reports    |
| Team        | ??? /month | 5     | Everything + team management    |
| Enterprise  | ??? /month | ∞     | Everything + priority support   |

### 7. Tech Stack / Powered By
- Kali Linux
- OWASP Tools
- FastAPI
- React
- Nmap, Metasploit, Hydra, Nikto, SQLMap

### 8. FAQ
- Is this legal? (Yes — for authorized testing only)
- What targets can I scan? (Your own systems or with permission)
- Do I need to install anything? (No — fully cloud based)
- How do I get my credentials? (By email after payment)
- Can I upgrade my plan? (Yes — contact support)

### 9. Footer
- Contact email
- Terms of use
- Privacy policy
- Social links

---

## Technical Stack for Landing Page

| Thing              | Technology         | Cost  |
|--------------------|--------------------|-------|
| Frontend           | React + Tailwind   | Free  |
| Hosting            | Netlify or Vercel  | Free  |
| Payment            | Razorpay or Stripe | %/txn |
| Email (credentials)| Gmail SMTP / SendGrid | Free |
| Backend (webhook)  | Existing FastAPI   | Free  |
| Database (users)   | Existing SQLite    | Free  |

---

## Payment → Email Flow (Backend)

When customer pays:
1. Razorpay/Stripe sends webhook to: `https://YOUR_VPS/api/payment/webhook`
2. FastAPI verifies payment
3. Creates user account in SQLite (auto username + password)
4. Sends email with credentials using Gmail SMTP or SendGrid
5. Customer gets email within 30 seconds of payment

---

## Design Style

- Dark theme (matching the dashboard)
- Colors: #020617 background, #3b82f6 blue accent, #f1f5f9 text
- Font: DM Sans / Segoe UI
- High-end, professional, cybersecurity aesthetic
- Animated sections on scroll
- Glowing effects, gradient buttons
- Mobile responsive

---

## Additional Sections To Include When Building

### 10. Testimonials
- 2-3 customer reviews showing real value
- Example: "As a pentester this saved me hours of manual work" — John, Security Engineer
- Example: "Perfect for OSCP prep — all tools in one place" — Sarah, Student
- Example: "Our security team uses this for weekly audits" — Mike, IT Manager

### 11. Comparison Section
- Your tool vs hiring a manual pentester
- Your tool vs buying separate tools
- Shows value for money — why pay us instead

| | Manual Pentester | Separate Tools | Our Dashboard |
|---|---|---|---|
| Cost | $5000+/audit | $500+/month | ??? /month |
| Setup time | Days | Hours | 0 — instant |
| 51 tools | No | No | Yes |
| Reports | Extra cost | Manual | Auto PDF |
| Available 24/7 | No | No | Yes |

### 12. Free Trial
- TO BE DECIDED: Will you offer a free trial?
- Option A: 7-day free trial (limited scans)
- Option B: Paid only — no free trial
- Option C: Free individual plan with limited features

### 13. Video / Demo Section
- TO BE DECIDED: Do you want a demo video?
- Option A: Embedded YouTube video showing the dashboard
- Option B: Animated GIF/screenshot slideshow
- Option C: Live demo link

### 14. Trust Badges / Powered By
- Kali Linux logo
- OWASP logo
- Metasploit logo
- "Used by 500+ security professionals" (or real number)

---

## Decisions Still Needed From You

Fill these in before building:

1. PRICING
   - Individual plan: ₹___/month or $___/month
   - Team plan: ₹___/month or $___/month
   - Enterprise plan: ₹___/month or $___/month

2. PAYMENT GATEWAY
   - [ ] Razorpay (India — UPI, cards, netbanking)
   - [ ] Stripe (International — USD, EUR, cards)

3. EMAIL SERVICE
   - [ ] Gmail SMTP (free, simple)
   - [ ] SendGrid (professional, 100 emails/day free)

4. DOMAIN
   - Do you have a domain? YES / NO
   - If yes: _______________
   - If no: buy one at GoDaddy/Namecheap (~$10/year)

5. CURRENCY
   - [ ] INR (Indian Rupees)
   - [ ] USD (US Dollars)
   - [ ] Both

6. BRAND NAME
   - What is the product called?
   - Example: CyberScan Pro / PenTest Dashboard / RedOps
   - Your answer: _______________

7. CONTACT EMAIL
   - Support email for customers
   - Example: support@yourdomain.com
   - Your answer: _______________

8. TESTIMONIALS
   - Do you have real customer reviews? YES / NO
   - If no: I will create realistic example reviews

9. FREE TRIAL
   - [x] 7-day free trial — DECIDED AND BUILT
   - Trial includes: 5 scans/day, Section 1 recon tools only
   - After 7 days: account locked until payment
   - Show this on landing page as a selling point

10. DEMO VIDEO
    - [ ] Yes — I will record/embed a YouTube demo
    - [ ] No — use screenshots only

11. LOGO
    - [ ] Use same shield logo from the dashboard
    - [ ] I have a different logo (attach it)

---

## Files To Build

### Landing Page (Website 2)
- src/App.js — main landing page
- src/index.js — entry point
- public/index.html
- package.json
- netlify.toml — auto deploy config

### Backend Additions (Website 1 — main.py)
- POST /api/payment/webhook — handle payment confirmation
- POST /api/payment/create-order — create Razorpay/Stripe order
- Email sending function — send credentials after payment

---

## Hosting on Netlify (Free)

1. Push landing-page folder to GitHub
2. Go to netlify.com
3. Connect GitHub repo
4. Select landing-page folder
5. Deploy — done
6. Custom domain: point your domain to Netlify

---

## Summary

No new server needed.
Landing page = Netlify (free).
Payment webhook = existing VPS FastAPI.
Email = Gmail SMTP (free).
Total extra monthly cost = $0 + payment gateway % per transaction.

---

## Subscription Strategy (BUILT — show this on landing page)

### Trial Plan (Free — 7 days)
- 7 days free access automatically on register
- 5 scans per day maximum
- Access to: Vulnerability Scanning + Web App Recon (Section 1 only)
- Banner shows days remaining + scans left today
- After 7 days: account locked, upgrade prompt shown

### Pro Plan (Paid)
- Unlimited scans per day
- All 51 scanners unlocked
- All 8 sections: Injection, Auth, File Attacks, Network, Modern Web, Infrastructure
- PDF / JSON / CSV reports
- Multi-target scanning
- Priority support

### Enterprise Plan (Paid)
- Everything in Pro
- Multiple user accounts (team access)
- Admin panel access
- Custom wordlists
- Dedicated support

---

## Key Selling Points To Highlight On Landing Page

1. **"Start Free — No Credit Card"**
   - 7-day trial, register instantly
   - 5 scans/day to explore the tool

2. **"51 Real Security Tools In One Dashboard"**
   - Not simulated — real Kali Linux tools running
   - Nmap, Metasploit, SQLMap, Nikto, Hydra, Gobuster

3. **"Enterprise-Grade — OSCP/OSWE Level"**
   - Same tools used in real penetration testing certifications
   - OWASP Top 10 coverage

4. **"Instant Access After Payment"**
   - Credentials sent by email in 30 seconds
   - No installation — fully cloud based

5. **"Professional PDF Reports"**
   - Auto-generated after every scan
   - Ready to present to management/clients

6. **"Built-In Vulnerable Labs"**
   - DVWA, WebGoat, Juice Shop, Mutillidae, bWAPP
   - Practice safely without external targets

7. **"Your Data Is Private"**
   - Each user sees only their own scans
   - Scan history never shared

---

## What ADMIN Can Do (NOT shown on landing page — internal only)

- See all users, their plan, expiry date, scan count
- Extend subscription (after payment received)
- Change plan: trial → pro → enterprise
- Suspend account if abuse detected
- Delete account
- Full renewal history log
- See all users' scan history

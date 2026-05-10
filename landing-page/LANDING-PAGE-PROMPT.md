# Complete Landing Page Build Prompt

When the user says "build the landing page" — read this file completely
and build the entire landing page from scratch as a single React file.

---

## What To Build

A high-end, dark-themed, professional cybersecurity product landing page.
This is a MARKETING website — not the actual tool. Anyone can visit it.
The actual tool (dashboard) is separate and runs on the VPS.

---

## Customer Journey On This Page

```
Visit → Read → Impressed → Start Free Trial OR Pay → Get credentials by email → Use dashboard
```

---

## Updated Customer Flow (MANUAL credential delivery)

```
1. Customer visits landing page
2. Reads features, pricing, use cases
3. Clicks "Start Free Trial" → goes to dashboard register page
   OR clicks "Buy Now" → fills contact form (Name, Email, Phone, Plan)
4. For paid plans: customer pays via Razorpay/Stripe
5. YOU (ADMIN) get notified by email
6. YOU create account in Admin Panel with strong password
7. YOU email customer: URL + Username + Password + expiry date
8. Customer logs in and starts scanning
```

---

## Design Requirements

- **Theme**: Dark cyber — #020617 background, #3b82f6 blue accent
- **Font**: Inter or DM Sans — clean, modern, readable
- **Style**: High-end SaaS product — like Vercel, Linear, or Stripe
- **Effects**: Glowing borders, gradient buttons, particle/grid background
- **Animation**: Fade in on scroll, number counters, typing effect in hero
- **Mobile**: Fully responsive — works on phone and tablet
- **Colors**:
  - Background: #020617
  - Card background: #0a0f1e
  - Primary accent: #3b82f6 (blue)
  - Secondary accent: #8b5cf6 (purple)
  - Text primary: #f1f5f9
  - Text secondary: #94a3b8
  - Border: #1e293b
  - Success: #22c55e
  - Warning: #f59e0b
  - Danger: #ef4444

---

## Page Sections (Build ALL of these in order)

### SECTION 1 — Navigation Bar (sticky top)
- Logo: shield icon + "CYBER" in white + "SECURITY" in blue
- Nav links: Features | Pricing | Use Cases | FAQ
- Right side: "Start Free Trial" button (outlined) + "Sign In" link
- Mobile: hamburger menu
- Scrolled state: blur background + border bottom

---

### SECTION 2 — Hero
- **Badge**: "🔒 Trusted by Security Professionals" (small pill at top)
- **Headline**: "The Most Powerful Cybersecurity Dashboard Ever Built"
- **Sub-headline**: "51 real Kali Linux tools in one cloud dashboard. Scan, exploit, report — no installation needed. Used by pentesters, bug bounty hunters, and enterprise security teams."
- **CTA Buttons**:
  - Primary: "Start Free Trial — 7 Days Free" (blue gradient)
  - Secondary: "Watch Demo" (outlined)
- **Stats row** (animated counters):
  - 51+ Security Tools
  - 8 Attack Categories
  - OWASP Top 10 Coverage
  - 100% Cloud Based
- **Hero visual**: Dark terminal/dashboard mockup showing scan results with VULNERABLE/SECURE badges
- **Background**: Animated dot grid + blue glow in center

---

### SECTION 3 — Trust Bar
- "Powered by real professional tools:"
- Logos/badges: Kali Linux | OWASP | Metasploit | Nmap | Burp Suite | SQLMap
- All in grey, muted — not colorful

---

### SECTION 4 — What Is It?
- Section title: "One Dashboard. 51 Real Security Tools."
- 3 feature cards side by side:
  1. **Real Tools** — Not simulated. Real Kali Linux tools running on our cloud servers. Same tools used in OSCP, OSWE, CEH certifications.
  2. **Instant Reports** — Professional PDF reports auto-generated after every scan. Ready to present to clients or management.
  3. **Built-in Labs** — Practice on DVWA, WebGoat, Juice Shop, Mutillidae, bWAPP — safely and legally. No setup needed.

---

### SECTION 5 — 51 Scanners Showcase
- Section title: "Everything You Need In One Place"
- 8 category cards in a grid:
  1. 🔍 Reconnaissance & Fingerprinting — WAF Detection, Tech Stack, CMS, Port Scan, SSL, DNS, Subdomains
  2. 📁 Discovery & Fuzzing — Directory Enumeration, Web Fuzzing
  3. 💉 Injection Attacks — XSS, SQL Injection, NoSQL, Command Injection, XXE, SSTI, Host Header
  4. 🔐 Authentication & Session — Header Security, Cookie Analysis, Hydra Brute Force, JWT, CSRF, IDOR, OAuth, 2FA Bypass
  5. 📂 File & Path Attacks — LFI, RFI, File Upload Testing
  6. 🌐 Network & Protocol — CORS, SSRF, HTTP Smuggling, Verb Tampering, Clickjacking, Open Redirect
  7. ⚡ Modern Web (OSWE) — Deserialization, Prototype Pollution, GraphQL, Race Condition
  8. 🖥 Infrastructure (OSCP) — SMB, FTP, SMTP, SNMP
- Each card shows: icon + category name + tool count + 3-4 example tools

---

### SECTION 6 — Use Cases (2 columns)

**Enterprise / Business** (left):
- Security audits for company infrastructure
- Compliance scanning (OWASP Top 10, PCI-DSS)
- Multiple security engineers on one account
- Professional PDF reports for management and auditors
- Monthly security posture tracking

**Individual / Student** (right):
- OSCP / OSWE / CEH exam preparation
- Bug bounty hunting — find vulnerabilities faster
- Penetration testing freelancers
- Security research and CTF competitions
- Learning ethical hacking hands-on

---

### SECTION 7 — How It Works (3 steps)
- Step 1: **Choose Your Plan** — Select trial or paid plan. Fill your name and email.
- Step 2: **Receive Credentials** — We create your account and email your username + password within minutes.
- Step 3: **Start Scanning** — Login to the dashboard. Enter any target URL. Run all 51 tools with one click.

---

### SECTION 8 — Comparison Table
Title: "Why Choose Us Over Alternatives?"

| | Manual Pentester | Separate Tools | **Our Dashboard** |
|---|---|---|---|
| Cost | $5,000+/audit | $500+/month | Affordable monthly |
| Setup Time | Days | Hours | **0 — Instant** |
| 51 Security Tools | ❌ | ❌ | **✅** |
| Auto PDF Reports | ❌ Extra cost | ❌ Manual | **✅ Automatic** |
| Available 24/7 | ❌ | Partial | **✅ Always** |
| Built-in Labs | ❌ | ❌ | **✅ 5 Labs** |
| No Installation | ❌ | ❌ | **✅ Cloud** |

Highlight "Our Dashboard" column in blue.

---

### SECTION 9 — Pricing Plans
Title: "Simple, Transparent Pricing"
Sub: "Start free. Upgrade when ready."

3 cards:

**Trial (Free)**
- 7 days free
- 5 tool calls per day
- Section 1: Recon tools only (5 tools)
- PDF reports
- 1 user
- CTA: "Start Free Trial"

**Pro (Paid — price TBD)**
- All 51 scanners
- Unlimited scans
- PDF + JSON + CSV reports
- Priority support
- 1 user
- CTA: "Get Pro Access"
- Badge: "Most Popular"

**Enterprise (Paid — price TBD)**
- Everything in Pro
- Multiple user accounts
- Custom wordlists
- Dedicated support
- Team management
- CTA: "Contact Us"

Note below cards: "💳 Secure payment via Razorpay. Credentials delivered by email within 30 minutes."

---

### SECTION 10 — Testimonials
3 cards:

1. "As a penetration tester, this dashboard saves me 4-5 hours per engagement. The automated PDF report alone is worth the price."
   — **Rahul S.**, Senior Penetration Tester

2. "Perfect for OSCP prep. Having all the tools in one place without setting up a full Kali lab is a game changer."
   — **Priya M.**, Security Student

3. "Our security team runs weekly scans on our infrastructure. The OWASP Top 10 coverage gives our management the confidence they need."
   — **Arjun K.**, IT Security Manager

---

### SECTION 11 — FAQ
Accordion style (click to expand):

1. **Is this legal?**
   Yes — for authorized testing only. You must have permission to scan any target. We are not responsible for misuse.

2. **What targets can I scan?**
   Your own websites, servers, and systems, or any target you have written permission to test.

3. **Do I need to install anything?**
   No. Everything runs on our cloud servers powered by Kali Linux. Just open your browser and login.

4. **How do I get my credentials?**
   After payment, we manually create your account and email your username and password within 30 minutes.

5. **Can I try before paying?**
   Yes — start a 7-day free trial instantly. No credit card required. Limited to recon tools only.

6. **Can I upgrade my plan?**
   Yes — contact us at any time and we will upgrade your account immediately.

7. **Is my scan data private?**
   Yes — each user only sees their own scan history. Your data is never shared.

8. **What payment methods are accepted?**
   UPI, credit card, debit card, net banking via Razorpay (India). International cards via Stripe.

---

### SECTION 12 — Contact / Get Access Form
Title: "Ready To Get Started?"
Sub: "Fill the form below. We'll create your account and email credentials within 30 minutes."

Form fields:
- Full Name (required)
- Email Address (required)
- Phone Number (required)
- Company / Organization (optional)
- Plan Selection: Trial (Free) | Pro | Enterprise
- Message (optional)
- Submit button: "Request Access"

Below form: "📧 Or email us directly: vijayrajkoduruai@gmail.com"

---

### SECTION 13 — Footer
- Logo + tagline: "PROTECT | DETECT | RESPOND"
- Links: Features | Pricing | FAQ | Privacy Policy | Terms of Use
- Social: GitHub | LinkedIn
- Copyright: "© 2026 CyberSecurity Dashboard. All rights reserved."
- Small text: "For authorized security testing only."

---

## Technical Requirements

- Single React file: `src/App.js`
- No external UI libraries (no Material UI, no Ant Design)
- Use inline styles only (no CSS files, no Tailwind)
- Google Fonts: Inter font
- Smooth scroll between sections
- Scroll animation: fade up on enter viewport (Intersection Observer)
- Counter animation: numbers count up when visible
- Mobile responsive using flexbox and media queries via CSS-in-JS
- Form submission: `mailto:` link OR fetch to contact endpoint

---

## Files To Create

```
landing-page/
├── public/
│   └── index.html
├── src/
│   ├── App.js        ← entire landing page
│   └── index.js      ← React entry point
├── package.json
└── netlify.toml      ← for Netlify auto-deploy
```

---

## Hosting

Deploy FREE on Netlify:
1. Push `landing-page/` folder to GitHub
2. Connect to Netlify
3. Set build command: `npm run build`
4. Set publish directory: `build`
5. Done — live at `yoursite.netlify.app`

---

## Dashboard URL To Link To

When customer clicks "Start Free Trial" or "Sign In":
- Link to: `http://YOUR_VPS_IP` (the actual dashboard)
- Replace with real domain when available

---

## Important Notes

- Do NOT add a register form on landing page — customers fill contact form, YOU create their account manually
- Show "7-day free trial" prominently — it's a key selling point
- Emphasize "no installation" — cloud based is a major advantage
- Show "credentials by email" — reassure customers the process is personal and secure
- The comparison table is very powerful — use it to justify the price
- Mobile first — many customers will view on phone

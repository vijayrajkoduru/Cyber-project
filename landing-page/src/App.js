import React, { useState, useEffect, useRef } from "react";

const DASHBOARD_URL = "http://YOUR_VPS_IP"; // Replace with your actual VPS IP or domain
const CONTACT_EMAIL = "vijayrajkoduruai@gmail.com";

const C = {
  bg: "#020617", card: "#0a0f1e", card2: "#0f172a",
  blue: "#3b82f6", purple: "#8b5cf6", green: "#22c55e",
  text: "#f1f5f9", muted: "#94a3b8", border: "#1e293b",
  red: "#ef4444", yellow: "#f59e0b",
};

function useVisible(threshold = 0.15) {
  const ref = useRef(null);
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    const obs = new IntersectionObserver(([e]) => { if (e.isIntersecting) { setVisible(true); obs.disconnect(); } }, { threshold });
    if (ref.current) obs.observe(ref.current);
    return () => obs.disconnect();
  }, [threshold]);
  return [ref, visible];
}

function Counter({ target, suffix = "" }) {
  const [val, setVal] = useState(0);
  const [ref, visible] = useVisible(0.3);
  useEffect(() => {
    if (!visible) return;
    let start = 0;
    const step = Math.ceil(target / 50);
    const t = setInterval(() => {
      start += step;
      if (start >= target) { setVal(target); clearInterval(t); } else setVal(start);
    }, 30);
    return () => clearInterval(t);
  }, [visible, target]);
  return <span ref={ref}>{val}{suffix}</span>;
}

function FadeIn({ children, delay = 0, style = {} }) {
  const [ref, visible] = useVisible();
  return (
    <div ref={ref} style={{ opacity: visible ? 1 : 0, transform: visible ? "translateY(0)" : "translateY(28px)", transition: `opacity 0.7s ease ${delay}s, transform 0.7s ease ${delay}s`, ...style }}>
      {children}
    </div>
  );
}

function Btn({ children, primary, onClick, href, style = {} }) {
  const base = { display: "inline-flex", alignItems: "center", gap: 8, padding: "14px 28px", borderRadius: 10, fontSize: 15, fontWeight: 700, cursor: "pointer", textDecoration: "none", border: "none", transition: "all 0.2s", fontFamily: "Inter,sans-serif", letterSpacing: 0.3, ...style };
  const s = primary
    ? { ...base, background: "linear-gradient(135deg,#1d4ed8,#3b82f6,#6366f1)", color: "#fff", boxShadow: "0 4px 24px rgba(59,130,246,0.4)" }
    : { ...base, background: "transparent", color: C.blue, border: `1.5px solid ${C.blue}` };
  if (href) return <a href={href} style={s}>{children}</a>;
  return <button onClick={onClick} style={s}>{children}</button>;
}

function Badge({ children, color = C.blue }) {
  return <span style={{ background: color + "15", border: `1px solid ${color}40`, color, fontSize: 12, fontWeight: 700, padding: "4px 14px", borderRadius: 20, letterSpacing: 0.5 }}>{children}</span>;
}

// ── NAV ──────────────────────────────────────────────────────────
function Nav() {
  const [scrolled, setScrolled] = useState(false);
  const [menu, setMenu] = useState(false);
  useEffect(() => {
    const fn = () => setScrolled(window.scrollY > 40);
    window.addEventListener("scroll", fn);
    return () => window.removeEventListener("scroll", fn);
  }, []);
  const links = ["Features", "Pricing", "Use Cases", "FAQ"];
  return (
    <nav style={{ position: "fixed", top: 0, left: 0, right: 0, zIndex: 100, background: scrolled ? "rgba(2,6,23,0.92)" : "transparent", backdropFilter: scrolled ? "blur(12px)" : "none", borderBottom: scrolled ? `1px solid ${C.border}` : "none", transition: "all 0.3s", padding: "0 24px" }}>
      <div style={{ maxWidth: 1200, margin: "0 auto", display: "flex", alignItems: "center", height: 68, gap: 16 }}>
        <a href="#" style={{ display: "flex", alignItems: "center", gap: 10, textDecoration: "none", flexShrink: 0 }}>
          <div style={{ width: 36, height: 36, background: "linear-gradient(135deg,#1d4ed8,#3b82f6)", borderRadius: 8, display: "flex", alignItems: "center", justifyContent: "center" }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          </div>
          <span style={{ fontSize: 18, fontWeight: 900, letterSpacing: 1 }}>
            <span style={{ color: C.text }}>CYBER</span><span style={{ color: C.blue }}>SECURITY</span>
          </span>
        </a>
        <div style={{ flex: 1 }} />
        <div style={{ display: "flex", gap: 32, alignItems: "center", display: menu ? "none" : "flex" }}>
          {links.map(l => (
            <a key={l} href={`#${l.toLowerCase().replace(" ", "-")}`} style={{ color: C.muted, textDecoration: "none", fontSize: 14, fontWeight: 500, transition: "color 0.2s" }}
              onMouseEnter={e => e.target.style.color = C.text} onMouseLeave={e => e.target.style.color = C.muted}>{l}</a>
          ))}
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "center", marginLeft: 24 }}>
          <a href={DASHBOARD_URL} style={{ color: C.muted, fontSize: 14, fontWeight: 500, textDecoration: "none" }}>Sign In</a>
          <Btn primary href="#contact" style={{ padding: "10px 20px", fontSize: 13 }}>Start Free Trial</Btn>
        </div>
      </div>
    </nav>
  );
}

// ── HERO ─────────────────────────────────────────────────────────
function Hero() {
  const [typed, setTyped] = useState("");
  const words = ["XSS Testing", "SQL Injection", "Port Scanning", "SSL Analysis", "Directory Fuzzing"];
  const [wi, setWi] = useState(0);
  useEffect(() => {
    let i = 0, deleting = false;
    const t = setInterval(() => {
      const word = words[wi % words.length];
      if (!deleting) { setTyped(word.slice(0, ++i)); if (i === word.length) { deleting = true; setTimeout(() => {}, 1200); } }
      else { setTyped(word.slice(0, --i)); if (i === 0) { deleting = false; setWi(p => p + 1); } }
    }, 80);
    return () => clearInterval(t);
  }, [wi]);

  return (
    <section style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", position: "relative", overflow: "hidden", padding: "120px 24px 80px" }}>
      {/* Grid background */}
      <div style={{ position: "absolute", inset: 0, backgroundImage: "radial-gradient(rgba(59,130,246,0.15) 1px,transparent 1px)", backgroundSize: "36px 36px", pointerEvents: "none" }} />
      <div style={{ position: "absolute", top: "20%", left: "50%", transform: "translateX(-50%)", width: 600, height: 600, background: "radial-gradient(circle,rgba(59,130,246,0.12) 0%,transparent 70%)", pointerEvents: "none", filter: "blur(40px)" }} />

      <div style={{ maxWidth: 860, margin: "0 auto", textAlign: "center", position: "relative", zIndex: 1 }}>
        <div style={{ animation: "fadeUp 0.6s ease", marginBottom: 20 }}>
          <Badge>🔒 Trusted by Security Professionals</Badge>
        </div>

        <h1 style={{ fontSize: "clamp(36px,5vw,68px)", fontWeight: 900, lineHeight: 1.1, marginBottom: 24, animation: "fadeUp 0.7s ease 0.1s both" }}>
          The Most Powerful<br />
          <span style={{ background: "linear-gradient(135deg,#3b82f6,#8b5cf6)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>Cybersecurity Dashboard</span><br />
          Ever Built
        </h1>

        <p style={{ fontSize: "clamp(15px,2vw,20px)", color: C.muted, lineHeight: 1.7, marginBottom: 16, animation: "fadeUp 0.7s ease 0.2s both", maxWidth: 640, margin: "0 auto 16px" }}>
          51 real Kali Linux tools in one cloud dashboard. Scan, exploit, report — no installation needed.
        </p>

        <div style={{ fontSize: 18, fontWeight: 600, color: C.blue, marginBottom: 40, fontFamily: "JetBrains Mono,monospace", minHeight: 32, animation: "fadeUp 0.7s ease 0.3s both" }}>
          $ running <span style={{ color: C.green }}>{typed}</span><span style={{ animation: "pulse 1s infinite" }}>|</span>
        </div>

        <div style={{ display: "flex", gap: 14, justifyContent: "center", flexWrap: "wrap", marginBottom: 60, animation: "fadeUp 0.7s ease 0.4s both" }}>
          <Btn primary href="#contact">🚀 Start Free Trial — 7 Days Free</Btn>
          <Btn href="#features">Explore Features →</Btn>
        </div>

        {/* Stats */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 16, maxWidth: 700, margin: "0 auto", animation: "fadeUp 0.7s ease 0.5s both" }}>
          {[
            { n: 51, s: "+", label: "Security Tools" },
            { n: 8, s: "", label: "Attack Categories" },
            { n: 10, s, label: "OWASP Top 10" },
            { n: 100, s: "%", label: "Cloud Based" },
          ].map((st, i) => (
            <div key={i} style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, padding: "20px 12px", textAlign: "center" }}>
              <div style={{ fontSize: 32, fontWeight: 900, color: C.blue }}>
                <Counter target={st.n} suffix={st.s} />
              </div>
              <div style={{ fontSize: 12, color: C.muted, fontWeight: 500, marginTop: 4 }}>{st.label}</div>
            </div>
          ))}
        </div>

        {/* Terminal mockup */}
        <FadeIn delay={0.6} style={{ marginTop: 60 }}>
          <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 16, overflow: "hidden", maxWidth: 700, margin: "0 auto", boxShadow: "0 0 60px rgba(59,130,246,0.1)" }}>
            <div style={{ background: "#0f172a", padding: "12px 16px", display: "flex", alignItems: "center", gap: 8, borderBottom: `1px solid ${C.border}` }}>
              {["#ef4444","#f59e0b","#22c55e"].map((c,i) => <div key={i} style={{ width: 12, height: 12, borderRadius: "50%", background: c }} />)}
              <span style={{ fontSize: 12, color: C.muted, fontFamily: "JetBrains Mono,monospace", marginLeft: 8 }}>terminal — kali@cybersec</span>
            </div>
            <div style={{ padding: 20, fontFamily: "JetBrains Mono,monospace", fontSize: 13, textAlign: "left" }}>
              {[
                { t: "cmd", text: "$ scanning http://target.com — 51 phases" },
                { t: "ok", text: "✓ WAF Detection — SECURE" },
                { t: "ok", text: "✓ SSL/TLS Analysis — Grade A" },
                { t: "vuln", text: "✗ XSS Testing — VULNERABLE (CRITICAL)" },
                { t: "vuln", text: "✗ SQL Injection — VULNERABLE (CRITICAL)" },
                { t: "ok", text: "✓ Header Security — 6 findings" },
                { t: "info", text: "→ Generating PDF report..." },
                { t: "done", text: "✓ Pentest complete — 51 phases done" },
              ].map((line, i) => (
                <div key={i} style={{ marginBottom: 6, color: line.t === "vuln" ? "#f87171" : line.t === "ok" ? "#4ade80" : line.t === "cmd" ? C.blue : line.t === "done" ? "#22c55e" : C.muted }}>
                  {line.text}
                </div>
              ))}
            </div>
          </div>
        </FadeIn>
      </div>
    </section>
  );
}

// ── TRUST BAR ────────────────────────────────────────────────────
function TrustBar() {
  const tools = ["Kali Linux", "OWASP", "Metasploit", "Nmap", "SQLMap", "Nikto", "Hydra", "Gobuster"];
  return (
    <section style={{ borderTop: `1px solid ${C.border}`, borderBottom: `1px solid ${C.border}`, padding: "24px", background: C.card }}>
      <div style={{ maxWidth: 1200, margin: "0 auto", display: "flex", alignItems: "center", gap: 32, flexWrap: "wrap", justifyContent: "center" }}>
        <span style={{ fontSize: 12, color: "#475569", fontWeight: 600, letterSpacing: 2, textTransform: "uppercase", whiteSpace: "nowrap" }}>Powered by</span>
        {tools.map(t => (
          <span key={t} style={{ fontSize: 14, color: "#475569", fontWeight: 600, fontFamily: "JetBrains Mono,monospace" }}>{t}</span>
        ))}
      </div>
    </section>
  );
}

// ── WHAT IS IT ───────────────────────────────────────────────────
function WhatIsIt() {
  const cards = [
    { icon: "⚡", title: "Real Tools, Real Results", desc: "Not simulated. Real Kali Linux tools running on our cloud servers. Same tools used in OSCP, OSWE, CEH certifications. Every scan runs actual penetration testing commands." },
    { icon: "📄", title: "Instant PDF Reports", desc: "Professional penetration test reports auto-generated after every scan. Detailed findings with CVSS scores, OWASP mapping, CVE references, and remediation steps. Ready to present to clients or management." },
    { icon: "🧪", title: "Built-In Vulnerable Labs", desc: "Practice on DVWA, WebGoat, Juice Shop, Mutillidae, and bWAPP — safely and legally. All labs run inside our infrastructure. No setup, no downloads, no VMs required." },
  ];
  return (
    <section id="features" style={{ padding: "100px 24px" }}>
      <div style={{ maxWidth: 1100, margin: "0 auto" }}>
        <FadeIn style={{ textAlign: "center", marginBottom: 60 }}>
          <Badge color={C.purple}>Platform Overview</Badge>
          <h2 style={{ fontSize: "clamp(28px,4vw,48px)", fontWeight: 800, marginTop: 16, marginBottom: 16 }}>One Dashboard.<br />51 Real Security Tools.</h2>
          <p style={{ fontSize: 17, color: C.muted, maxWidth: 560, margin: "0 auto" }}>Everything a professional penetration tester needs — in one cloud platform.</p>
        </FadeIn>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(300px,1fr))", gap: 24 }}>
          {cards.map((c, i) => (
            <FadeIn key={i} delay={i * 0.1}>
              <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 16, padding: 32, height: "100%", transition: "border-color 0.3s", cursor: "default" }}
                onMouseEnter={e => e.currentTarget.style.borderColor = C.blue} onMouseLeave={e => e.currentTarget.style.borderColor = C.border}>
                <div style={{ fontSize: 40, marginBottom: 20 }}>{c.icon}</div>
                <h3 style={{ fontSize: 20, fontWeight: 700, marginBottom: 12, color: C.text }}>{c.title}</h3>
                <p style={{ fontSize: 15, color: C.muted, lineHeight: 1.7 }}>{c.desc}</p>
              </div>
            </FadeIn>
          ))}
        </div>
      </div>
    </section>
  );
}

// ── SCANNERS ─────────────────────────────────────────────────────
function Scanners() {
  const cats = [
    { icon: "🔍", title: "Reconnaissance", count: 11, tools: ["WAF Detection","Tech Stack","CMS Detection","Port Scan","SSL/TLS","DNS","Subdomains"], color: "#3b82f6" },
    { icon: "📁", title: "Discovery & Fuzzing", count: 2, tools: ["Directory Enum","Web Fuzzing (ffuf)"], color: "#06b6d4" },
    { icon: "💉", title: "Injection Attacks", count: 7, tools: ["XSS Testing","SQL Injection","NoSQL","Command Injection","XXE","SSTI","Host Header"], color: "#ef4444" },
    { icon: "🔐", title: "Auth & Session", count: 9, tools: ["Header Security","Cookie Analysis","Hydra BruteForce","JWT Attacks","CSRF","IDOR","OAuth","2FA Bypass"], color: "#a855f7" },
    { icon: "📂", title: "File & Path Attacks", count: 3, tools: ["LFI / Path Traversal","Remote File Inclusion","File Upload"], color: "#f97316" },
    { icon: "🌐", title: "Network & Protocol", count: 10, tools: ["CORS Testing","SSRF","HTTP Smuggling","Verb Tampering","Clickjacking","Open Redirect"], color: "#0891b2" },
    { icon: "⚡", title: "Modern Web (OSWE)", count: 5, tools: ["Deserialization","Prototype Pollution","GraphQL","Race Condition","PHP Juggling"], color: "#22c55e" },
    { icon: "🖥", title: "Infrastructure (OSCP)", count: 4, tools: ["SMB Enum","FTP Enum","SMTP User Enum","SNMP Scanner"], color: "#eab308" },
  ];
  return (
    <section style={{ padding: "100px 24px", background: C.card }}>
      <div style={{ maxWidth: 1200, margin: "0 auto" }}>
        <FadeIn style={{ textAlign: "center", marginBottom: 60 }}>
          <Badge>51 Scanners</Badge>
          <h2 style={{ fontSize: "clamp(28px,4vw,48px)", fontWeight: 800, marginTop: 16, marginBottom: 16 }}>Everything You Need In One Place</h2>
          <p style={{ fontSize: 17, color: C.muted }}>Full OWASP Top 10 coverage across 8 attack categories.</p>
        </FadeIn>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(260px,1fr))", gap: 20 }}>
          {cats.map((cat, i) => (
            <FadeIn key={i} delay={i * 0.07}>
              <div style={{ background: C.bg, border: `1px solid ${C.border}`, borderTop: `3px solid ${cat.color}`, borderRadius: 12, padding: 24, height: "100%" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
                  <span style={{ fontSize: 24 }}>{cat.icon}</span>
                  <div>
                    <div style={{ fontSize: 15, fontWeight: 700, color: C.text }}>{cat.title}</div>
                    <div style={{ fontSize: 12, color: cat.color, fontWeight: 600 }}>{cat.count} scanners</div>
                  </div>
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                  {cat.tools.slice(0, 4).map(t => (
                    <span key={t} style={{ fontSize: 11, background: cat.color + "15", color: cat.color, padding: "2px 8px", borderRadius: 4, fontWeight: 600 }}>{t}</span>
                  ))}
                  {cat.tools.length > 4 && <span style={{ fontSize: 11, color: C.muted }}>+{cat.tools.length - 4} more</span>}
                </div>
              </div>
            </FadeIn>
          ))}
        </div>
      </div>
    </section>
  );
}

// ── USE CASES ────────────────────────────────────────────────────
function UseCases() {
  const enterprise = [
    "Security audits for company infrastructure",
    "Compliance scanning — OWASP Top 10, PCI-DSS",
    "Multiple security engineers on one account",
    "Professional PDF reports for management and auditors",
    "Monthly security posture tracking and comparison",
  ];
  const individual = [
    "OSCP / OSWE / CEH exam preparation",
    "Bug bounty hunting — find vulnerabilities faster",
    "Penetration testing freelancers and consultants",
    "Security research and CTF competitions",
    "Learning ethical hacking hands-on with real tools",
  ];
  return (
    <section id="use-cases" style={{ padding: "100px 24px" }}>
      <div style={{ maxWidth: 1100, margin: "0 auto" }}>
        <FadeIn style={{ textAlign: "center", marginBottom: 60 }}>
          <Badge color={C.green}>Use Cases</Badge>
          <h2 style={{ fontSize: "clamp(28px,4vw,48px)", fontWeight: 800, marginTop: 16 }}>Built For Everyone In Security</h2>
        </FadeIn>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(300px,1fr))", gap: 32 }}>
          {[
            { title: "Enterprise & Business", icon: "🏢", color: C.blue, items: enterprise },
            { title: "Individual & Student", icon: "👤", color: C.purple, items: individual },
          ].map((col, ci) => (
            <FadeIn key={ci} delay={ci * 0.15}>
              <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 16, padding: 36 }}>
                <div style={{ fontSize: 40, marginBottom: 12 }}>{col.icon}</div>
                <h3 style={{ fontSize: 22, fontWeight: 700, color: col.color, marginBottom: 24 }}>{col.title}</h3>
                {col.items.map((item, i) => (
                  <div key={i} style={{ display: "flex", gap: 12, alignItems: "flex-start", marginBottom: 14 }}>
                    <span style={{ color: col.color, fontSize: 16, flexShrink: 0, marginTop: 2 }}>✓</span>
                    <span style={{ fontSize: 15, color: C.muted, lineHeight: 1.5 }}>{item}</span>
                  </div>
                ))}
              </div>
            </FadeIn>
          ))}
        </div>
      </div>
    </section>
  );
}

// ── HOW IT WORKS ─────────────────────────────────────────────────
function HowItWorks() {
  const steps = [
    { n: "01", icon: "📋", title: "Choose Your Plan", desc: "Select trial or paid plan. Fill your name, email, and phone. No technical knowledge required." },
    { n: "02", icon: "📧", title: "Receive Credentials", desc: "We create your account manually and email your username and password within 30 minutes of payment." },
    { n: "03", icon: "🚀", title: "Start Scanning", desc: "Login to the dashboard. Enter any target URL. Run all 51 security tools with one click." },
  ];
  return (
    <section style={{ padding: "100px 24px", background: C.card }}>
      <div style={{ maxWidth: 1000, margin: "0 auto" }}>
        <FadeIn style={{ textAlign: "center", marginBottom: 60 }}>
          <Badge color={C.yellow}>Simple Process</Badge>
          <h2 style={{ fontSize: "clamp(28px,4vw,48px)", fontWeight: 800, marginTop: 16, marginBottom: 16 }}>Up and Running in Minutes</h2>
          <p style={{ fontSize: 17, color: C.muted }}>No installation. No configuration. Just login and scan.</p>
        </FadeIn>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(260px,1fr))", gap: 32, position: "relative" }}>
          {steps.map((s, i) => (
            <FadeIn key={i} delay={i * 0.15}>
              <div style={{ textAlign: "center", padding: 32 }}>
                <div style={{ width: 64, height: 64, borderRadius: "50%", background: "linear-gradient(135deg,#1d4ed8,#3b82f6)", display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 20px", fontSize: 28 }}>
                  {s.icon}
                </div>
                <div style={{ fontSize: 12, color: C.blue, fontWeight: 700, fontFamily: "JetBrains Mono,monospace", letterSpacing: 2, marginBottom: 8 }}>STEP {s.n}</div>
                <h3 style={{ fontSize: 20, fontWeight: 700, marginBottom: 12 }}>{s.title}</h3>
                <p style={{ fontSize: 15, color: C.muted, lineHeight: 1.7 }}>{s.desc}</p>
              </div>
            </FadeIn>
          ))}
        </div>
      </div>
    </section>
  );
}

// ── COMPARISON ───────────────────────────────────────────────────
function Comparison() {
  const rows = [
    ["Cost", "$5,000+/audit", "$500+/month", "Affordable monthly"],
    ["Setup Time", "Days", "Hours", "0 — Instant"],
    ["51 Security Tools", "❌", "❌", "✅"],
    ["Auto PDF Reports", "❌ Extra cost", "❌ Manual", "✅ Automatic"],
    ["Available 24/7", "❌", "Partial", "✅ Always"],
    ["Built-in Labs", "❌", "❌", "✅ 5 Labs"],
    ["No Installation", "❌", "❌", "✅ Cloud"],
  ];
  return (
    <section style={{ padding: "100px 24px" }}>
      <div style={{ maxWidth: 900, margin: "0 auto" }}>
        <FadeIn style={{ textAlign: "center", marginBottom: 60 }}>
          <Badge color={C.red}>Why Choose Us</Badge>
          <h2 style={{ fontSize: "clamp(28px,4vw,48px)", fontWeight: 800, marginTop: 16 }}>Why Choose Us Over Alternatives?</h2>
        </FadeIn>
        <FadeIn>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 14 }}>
              <thead>
                <tr>
                  {["Feature", "Manual Pentester", "Separate Tools", "Our Dashboard"].map((h, i) => (
                    <th key={h} style={{ padding: "14px 16px", textAlign: i === 0 ? "left" : "center", background: i === 3 ? "linear-gradient(135deg,#1d4ed8,#3b82f6)" : "#0f172a", color: "#fff", fontWeight: 700, fontSize: 13, border: `1px solid ${C.border}`, borderRadius: i === 0 ? "8px 0 0 0" : i === 3 ? "0 8px 0 0" : 0 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((row, ri) => (
                  <tr key={ri}>
                    {row.map((cell, ci) => (
                      <td key={ci} style={{ padding: "13px 16px", textAlign: ci === 0 ? "left" : "center", background: ci === 3 ? "rgba(59,130,246,0.08)" : ri % 2 === 0 ? C.card : C.bg, color: ci === 3 ? C.blue : ci === 0 ? C.text : C.muted, fontWeight: ci === 3 ? 700 : ci === 0 ? 600 : 400, border: `1px solid ${C.border}`, fontSize: 14 }}>{cell}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </FadeIn>
      </div>
    </section>
  );
}

// ── PRICING ──────────────────────────────────────────────────────
function Pricing() {
  const plans = [
    {
      name: "Trial", price: "Free", period: "7 days", color: C.muted, badge: null,
      features: ["7 days free access", "Recon tools only (5 scanners)", "5 scans per day", "PDF reports included", "1 user account"],
      cta: "Start Free Trial", ctaHref: "#contact", primary: false,
    },
    {
      name: "Pro", price: "Contact Us", period: "per month", color: C.blue, badge: "Most Popular",
      features: ["All 51 scanners unlocked", "Unlimited scans per day", "PDF + JSON + CSV reports", "Priority support", "1 user account", "Built-in vulnerable labs"],
      cta: "Get Pro Access", ctaHref: "#contact", primary: true,
    },
    {
      name: "Enterprise", price: "Contact Us", period: "per month", color: C.purple, badge: null,
      features: ["Everything in Pro", "Multiple user accounts", "Team management", "Custom wordlists", "Dedicated support", "Admin panel access"],
      cta: "Contact Us", ctaHref: "#contact", primary: false,
    },
  ];
  return (
    <section id="pricing" style={{ padding: "100px 24px", background: C.card }}>
      <div style={{ maxWidth: 1100, margin: "0 auto" }}>
        <FadeIn style={{ textAlign: "center", marginBottom: 60 }}>
          <Badge>Pricing</Badge>
          <h2 style={{ fontSize: "clamp(28px,4vw,48px)", fontWeight: 800, marginTop: 16, marginBottom: 12 }}>Simple, Transparent Pricing</h2>
          <p style={{ fontSize: 17, color: C.muted }}>Start free. Upgrade when ready. No hidden fees.</p>
        </FadeIn>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(280px,1fr))", gap: 24, alignItems: "start" }}>
          {plans.map((plan, i) => (
            <FadeIn key={i} delay={i * 0.1}>
              <div style={{ background: C.bg, border: `2px solid ${plan.primary ? C.blue : C.border}`, borderRadius: 20, padding: 36, position: "relative", boxShadow: plan.primary ? "0 0 40px rgba(59,130,246,0.15)" : "none" }}>
                {plan.badge && <div style={{ position: "absolute", top: -14, left: "50%", transform: "translateX(-50%)", background: "linear-gradient(135deg,#1d4ed8,#3b82f6)", color: "#fff", fontSize: 12, fontWeight: 700, padding: "4px 16px", borderRadius: 20, whiteSpace: "nowrap" }}>{plan.badge}</div>}
                <div style={{ marginBottom: 8 }}><Badge color={plan.color}>{plan.name}</Badge></div>
                <div style={{ fontSize: 36, fontWeight: 900, color: plan.color, margin: "16px 0 4px" }}>{plan.price}</div>
                <div style={{ fontSize: 13, color: C.muted, marginBottom: 28 }}>{plan.period}</div>
                <div style={{ borderTop: `1px solid ${C.border}`, paddingTop: 24, marginBottom: 28 }}>
                  {plan.features.map((f, fi) => (
                    <div key={fi} style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 12 }}>
                      <span style={{ color: plan.color, fontSize: 14, flexShrink: 0 }}>✓</span>
                      <span style={{ fontSize: 14, color: C.muted }}>{f}</span>
                    </div>
                  ))}
                </div>
                <Btn primary={plan.primary} href={plan.ctaHref} style={{ width: "100%", justifyContent: "center", borderColor: plan.color, color: plan.primary ? "#fff" : plan.color }}>{plan.cta}</Btn>
              </div>
            </FadeIn>
          ))}
        </div>
        <FadeIn>
          <p style={{ textAlign: "center", fontSize: 14, color: C.muted, marginTop: 32 }}>
            💳 Secure payment via Razorpay · Credentials delivered by email within 30 minutes · No auto-renewal
          </p>
        </FadeIn>
      </div>
    </section>
  );
}

// ── TESTIMONIALS ─────────────────────────────────────────────────
function Testimonials() {
  const reviews = [
    { text: "As a penetration tester, this dashboard saves me 4–5 hours per engagement. The automated PDF report alone is worth the price. My clients are always impressed.", name: "Rahul S.", role: "Senior Penetration Tester", stars: 5 },
    { text: "Perfect for OSCP prep. Having all the tools in one place without setting up a full Kali lab is a game changer. Passed my exam on the first attempt.", name: "Priya M.", role: "Security Student & OSCP", stars: 5 },
    { text: "Our security team runs weekly scans on our infrastructure. The OWASP Top 10 coverage gives our management the confidence they need for compliance audits.", name: "Arjun K.", role: "IT Security Manager", stars: 5 },
  ];
  return (
    <section style={{ padding: "100px 24px" }}>
      <div style={{ maxWidth: 1100, margin: "0 auto" }}>
        <FadeIn style={{ textAlign: "center", marginBottom: 60 }}>
          <Badge color={C.yellow}>Testimonials</Badge>
          <h2 style={{ fontSize: "clamp(28px,4vw,48px)", fontWeight: 800, marginTop: 16 }}>Trusted By Security Professionals</h2>
        </FadeIn>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(300px,1fr))", gap: 24 }}>
          {reviews.map((r, i) => (
            <FadeIn key={i} delay={i * 0.1}>
              <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 16, padding: 32 }}>
                <div style={{ color: C.yellow, fontSize: 18, marginBottom: 16 }}>{"★".repeat(r.stars)}</div>
                <p style={{ fontSize: 15, color: C.muted, lineHeight: 1.8, marginBottom: 24, fontStyle: "italic" }}>"{r.text}"</p>
                <div>
                  <div style={{ fontSize: 15, fontWeight: 700, color: C.text }}>{r.name}</div>
                  <div style={{ fontSize: 13, color: C.muted }}>{r.role}</div>
                </div>
              </div>
            </FadeIn>
          ))}
        </div>
      </div>
    </section>
  );
}

// ── FAQ ──────────────────────────────────────────────────────────
function FAQ() {
  const [open, setOpen] = useState(null);
  const faqs = [
    { q: "Is this legal?", a: "Yes — for authorized testing only. You must have permission to scan any target. We are not responsible for misuse. Always get written authorization before testing." },
    { q: "What targets can I scan?", a: "Your own websites, servers, and systems, or any target you have written permission to test. We also provide 5 built-in vulnerable labs for safe practice." },
    { q: "Do I need to install anything?", a: "No. Everything runs on our cloud servers powered by Kali Linux. Just open your browser, login, and start scanning. Works on any device." },
    { q: "How do I get my credentials?", a: "After payment or trial registration, we manually create your account and email your username and password within 30 minutes. You'll also receive the dashboard URL." },
    { q: "Can I try before paying?", a: "Yes — start a 7-day free trial instantly by filling the contact form. No credit card required. Trial includes recon tools and 50 tool calls per day." },
    { q: "Can I upgrade my plan?", a: "Yes — contact us at any time via email and we will upgrade your account immediately. Your scan history and reports are preserved." },
    { q: "Is my scan data private?", a: "Yes — each user only sees their own scan history. Your data is never shared with other users or third parties." },
    { q: "What payment methods are accepted?", a: "UPI, credit card, debit card, and net banking via Razorpay (India). International cards via Stripe. We'll confirm payment before creating your account." },
  ];
  return (
    <section id="faq" style={{ padding: "100px 24px", background: C.card }}>
      <div style={{ maxWidth: 780, margin: "0 auto" }}>
        <FadeIn style={{ textAlign: "center", marginBottom: 60 }}>
          <Badge color={C.purple}>FAQ</Badge>
          <h2 style={{ fontSize: "clamp(28px,4vw,48px)", fontWeight: 800, marginTop: 16 }}>Frequently Asked Questions</h2>
        </FadeIn>
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {faqs.map((f, i) => (
            <FadeIn key={i} delay={i * 0.04}>
              <div style={{ background: C.bg, border: `1px solid ${open === i ? C.blue : C.border}`, borderRadius: 12, overflow: "hidden", transition: "border-color 0.2s" }}>
                <button onClick={() => setOpen(open === i ? null : i)} style={{ width: "100%", background: "none", border: "none", padding: "20px 24px", display: "flex", justifyContent: "space-between", alignItems: "center", cursor: "pointer", textAlign: "left", gap: 16 }}>
                  <span style={{ fontSize: 16, fontWeight: 600, color: open === i ? C.blue : C.text }}>{f.q}</span>
                  <span style={{ fontSize: 20, color: C.blue, flexShrink: 0, transform: open === i ? "rotate(45deg)" : "none", transition: "transform 0.2s" }}>+</span>
                </button>
                {open === i && <div style={{ padding: "0 24px 20px", fontSize: 15, color: C.muted, lineHeight: 1.8 }}>{f.a}</div>}
              </div>
            </FadeIn>
          ))}
        </div>
      </div>
    </section>
  );
}

// ── CONTACT ──────────────────────────────────────────────────────
function Contact() {
  const [form, setForm] = useState({ name: "", email: "", phone: "", company: "", plan: "trial", message: "" });
  const [sent, setSent] = useState(false);
  const set = (k, v) => setForm(p => ({ ...p, [k]: v }));
  const inp = { width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "13px 16px", color: C.text, fontSize: 14, outline: "none", fontFamily: "Inter,sans-serif", boxSizing: "border-box" };
  const submit = (e) => {
    e.preventDefault();
    const subject = `CyberSecurity Dashboard — ${form.plan.toUpperCase()} Access Request`;
    const body = `Name: ${form.name}\nEmail: ${form.email}\nPhone: ${form.phone}\nCompany: ${form.company}\nPlan: ${form.plan}\nMessage: ${form.message}`;
    window.location.href = `mailto:${CONTACT_EMAIL}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
    setSent(true);
  };
  return (
    <section id="contact" style={{ padding: "100px 24px" }}>
      <div style={{ maxWidth: 640, margin: "0 auto" }}>
        <FadeIn style={{ textAlign: "center", marginBottom: 48 }}>
          <Badge color={C.green}>Get Access</Badge>
          <h2 style={{ fontSize: "clamp(28px,4vw,48px)", fontWeight: 800, marginTop: 16, marginBottom: 12 }}>Ready To Get Started?</h2>
          <p style={{ fontSize: 16, color: C.muted }}>Fill the form below. We'll create your account and email credentials within 30 minutes.</p>
        </FadeIn>
        {sent ? (
          <FadeIn>
            <div style={{ background: "#052e16", border: "1px solid #166534", borderRadius: 16, padding: 48, textAlign: "center" }}>
              <div style={{ fontSize: 48, marginBottom: 16 }}>✅</div>
              <h3 style={{ fontSize: 24, fontWeight: 700, color: "#4ade80", marginBottom: 12 }}>Request Sent!</h3>
              <p style={{ color: C.muted, fontSize: 15 }}>We'll create your account and email your credentials within 30 minutes. Check your inbox.</p>
            </div>
          </FadeIn>
        ) : (
          <FadeIn>
            <form onSubmit={submit} style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 20, padding: 40, display: "flex", flexDirection: "column", gap: 16 }}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
                <div>
                  <label style={{ fontSize: 12, color: C.muted, fontWeight: 600, letterSpacing: 1, textTransform: "uppercase", display: "block", marginBottom: 8 }}>Full Name *</label>
                  <input style={inp} value={form.name} onChange={e => set("name", e.target.value)} placeholder="John Smith" required />
                </div>
                <div>
                  <label style={{ fontSize: 12, color: C.muted, fontWeight: 600, letterSpacing: 1, textTransform: "uppercase", display: "block", marginBottom: 8 }}>Email *</label>
                  <input style={inp} type="email" value={form.email} onChange={e => set("email", e.target.value)} placeholder="john@company.com" required />
                </div>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
                <div>
                  <label style={{ fontSize: 12, color: C.muted, fontWeight: 600, letterSpacing: 1, textTransform: "uppercase", display: "block", marginBottom: 8 }}>Phone *</label>
                  <input style={inp} value={form.phone} onChange={e => set("phone", e.target.value)} placeholder="+91 98765 43210" required />
                </div>
                <div>
                  <label style={{ fontSize: 12, color: C.muted, fontWeight: 600, letterSpacing: 1, textTransform: "uppercase", display: "block", marginBottom: 8 }}>Company</label>
                  <input style={inp} value={form.company} onChange={e => set("company", e.target.value)} placeholder="Optional" />
                </div>
              </div>
              <div>
                <label style={{ fontSize: 12, color: C.muted, fontWeight: 600, letterSpacing: 1, textTransform: "uppercase", display: "block", marginBottom: 8 }}>Plan *</label>
                <select style={{ ...inp, cursor: "pointer" }} value={form.plan} onChange={e => set("plan", e.target.value)}>
                  <option value="trial">Trial — 7 Days Free</option>
                  <option value="pro">Pro — All 51 Scanners</option>
                  <option value="enterprise">Enterprise — Team Access</option>
                </select>
              </div>
              <div>
                <label style={{ fontSize: 12, color: C.muted, fontWeight: 600, letterSpacing: 1, textTransform: "uppercase", display: "block", marginBottom: 8 }}>Message</label>
                <textarea style={{ ...inp, minHeight: 100, resize: "vertical" }} value={form.message} onChange={e => set("message", e.target.value)} placeholder="Tell us about your use case (optional)" />
              </div>
              <Btn primary style={{ justifyContent: "center", padding: "16px", fontSize: 16 }}>🚀 Request Access</Btn>
              <p style={{ textAlign: "center", fontSize: 13, color: C.muted }}>Or email directly: <a href={`mailto:${CONTACT_EMAIL}`} style={{ color: C.blue }}>{CONTACT_EMAIL}</a></p>
            </form>
          </FadeIn>
        )}
      </div>
    </section>
  );
}

// ── FOOTER ───────────────────────────────────────────────────────
function Footer() {
  return (
    <footer style={{ borderTop: `1px solid ${C.border}`, padding: "48px 24px 32px", background: C.card }}>
      <div style={{ maxWidth: 1100, margin: "0 auto" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 32, marginBottom: 40 }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
              <div style={{ width: 32, height: 32, background: "linear-gradient(135deg,#1d4ed8,#3b82f6)", borderRadius: 7, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              </div>
              <span style={{ fontSize: 16, fontWeight: 900 }}><span style={{ color: C.text }}>CYBER</span><span style={{ color: C.blue }}>SECURITY</span></span>
            </div>
            <p style={{ fontSize: 13, color: C.muted, maxWidth: 260, lineHeight: 1.7 }}>Professional penetration testing platform powered by Kali Linux. For authorized security testing only.</p>
          </div>
          <div style={{ display: "flex", gap: 48, flexWrap: "wrap" }}>
            <div>
              <div style={{ fontSize: 12, color: "#475569", fontWeight: 700, letterSpacing: 1.5, textTransform: "uppercase", marginBottom: 16 }}>Platform</div>
              {["Features", "Pricing", "Use Cases", "FAQ"].map(l => (
                <div key={l} style={{ marginBottom: 10 }}>
                  <a href={`#${l.toLowerCase().replace(" ", "-")}`} style={{ fontSize: 14, color: C.muted, textDecoration: "none" }}
                    onMouseEnter={e => e.target.style.color = C.text} onMouseLeave={e => e.target.style.color = C.muted}>{l}</a>
                </div>
              ))}
            </div>
            <div>
              <div style={{ fontSize: 12, color: "#475569", fontWeight: 700, letterSpacing: 1.5, textTransform: "uppercase", marginBottom: 16 }}>Contact</div>
              <div style={{ marginBottom: 10 }}><a href={`mailto:${CONTACT_EMAIL}`} style={{ fontSize: 14, color: C.muted, textDecoration: "none" }}>{CONTACT_EMAIL}</a></div>
              <div style={{ marginBottom: 10 }}><a href="#contact" style={{ fontSize: 14, color: C.blue, textDecoration: "none", fontWeight: 600 }}>Get Access →</a></div>
            </div>
          </div>
        </div>
        <div style={{ borderTop: `1px solid ${C.border}`, paddingTop: 24, display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
          <span style={{ fontSize: 13, color: "#475569" }}>© 2026 CyberSecurity Dashboard. All rights reserved.</span>
          <span style={{ fontSize: 12, color: "#334155" }}>For authorized security testing only. PROTECT | DETECT | RESPOND</span>
        </div>
      </div>
    </footer>
  );
}

// ── APP ──────────────────────────────────────────────────────────
export default function App() {
  return (
    <div style={{ background: C.bg, minHeight: "100vh" }}>
      <Nav />
      <Hero />
      <TrustBar />
      <WhatIsIt />
      <Scanners />
      <UseCases />
      <HowItWorks />
      <Comparison />
      <Pricing />
      <Testimonials />
      <FAQ />
      <Contact />
      <Footer />
    </div>
  );
}

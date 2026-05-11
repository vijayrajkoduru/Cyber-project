import React, { useState, useEffect, useRef } from "react";

const DASHBOARD_URL = "https://app.vulnuslab.com";
const CONTACT_EMAIL = "vijayrajkoduruai@gmail.com";

const C = {
  bg: "#020617", card: "#0a0f1e", card2: "#0f172a",
  blue: "#3b82f6", purple: "#8b5cf6", green: "#22c55e",
  cyan: "#06b6d4", text: "#f1f5f9", muted: "#94a3b8",
  border: "#1e293b", red: "#ef4444", yellow: "#f59e0b",
  orange: "#f97316",
};

const CSS = `
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap');
  *{box-sizing:border-box;margin:0;padding:0;}
  html{scroll-behavior:smooth;}
  body{font-family:'Inter',sans-serif;background:#020617;color:#f1f5f9;overflow-x:hidden;-webkit-font-smoothing:antialiased;}
  ::-webkit-scrollbar{width:5px;}
  ::-webkit-scrollbar-track{background:#020617;}
  ::-webkit-scrollbar-thumb{background:#334155;border-radius:6px;}
  @keyframes fadeUp{from{opacity:0;transform:translateY(28px)}to{opacity:1;transform:translateY(0)}}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.3}}
  @keyframes glow{0%,100%{box-shadow:0 0 20px rgba(59,130,246,0.3)}50%{box-shadow:0 0 60px rgba(59,130,246,0.7)}}
  @keyframes scan{0%{top:0}100%{top:100%}}
  @keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
  @keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-12px)}}
  @keyframes spin{to{transform:rotate(360deg)}}
  @keyframes slideIn{from{transform:translateX(-100%);opacity:0}to{transform:translateX(0);opacity:1}}
  @keyframes ping{0%{transform:scale(1);opacity:1}75%,100%{transform:scale(2);opacity:0}}
  @keyframes gradientShift{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}}
  @keyframes typewriter{from{width:0}to{width:100%}}
  @keyframes borderGlow{0%,100%{border-color:rgba(59,130,246,0.3)}50%{border-color:rgba(59,130,246,0.9)}}
  @keyframes countUp{from{opacity:0;transform:scale(0.5)}to{opacity:1;transform:scale(1)}}
  .nav-link:hover{color:#f1f5f9!important;}
  .feature-card:hover{transform:translateY(-6px);border-color:rgba(59,130,246,0.5)!important;}
  .feature-card{transition:all 0.3s ease;}
  .scanner-card:hover{transform:scale(1.03);border-color:rgba(59,130,246,0.4)!important;}
  .scanner-card{transition:all 0.25s ease;}
  .btn-primary:hover{transform:translateY(-2px);box-shadow:0 8px 40px rgba(59,130,246,0.6)!important;}
  .btn-primary{transition:all 0.2s ease;}
  .btn-outline:hover{background:rgba(59,130,246,0.1)!important;}
  .btn-outline{transition:all 0.2s ease;}
  .faq-btn:hover{background:rgba(59,130,246,0.05)!important;}
`;

function useVisible(threshold = 0.1) {
  const ref = useRef(null);
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    const obs = new IntersectionObserver(([e]) => { if (e.isIntersecting) { setVisible(true); obs.disconnect(); } }, { threshold });
    if (ref.current) obs.observe(ref.current);
    return () => obs.disconnect();
  }, [threshold]);
  return [ref, visible];
}

function Counter({ target, suffix = "", prefix = "" }) {
  const [val, setVal] = useState(0);
  const [ref, visible] = useVisible(0.3);
  useEffect(() => {
    if (!visible) return;
    let start = 0;
    const dur = 1500;
    const step = target / (dur / 16);
    const t = setInterval(() => {
      start += step;
      if (start >= target) { setVal(target); clearInterval(t); } else setVal(Math.floor(start));
    }, 16);
    return () => clearInterval(t);
  }, [visible, target]);
  return <span ref={ref}>{prefix}{val}{suffix}</span>;
}

function FadeIn({ children, delay = 0, style = {} }) {
  const [ref, visible] = useVisible();
  return (
    <div ref={ref} style={{ opacity: visible ? 1 : 0, transform: visible ? "translateY(0)" : "translateY(32px)", transition: `opacity 0.7s ease ${delay}s, transform 0.7s ease ${delay}s`, ...style }}>
      {children}
    </div>
  );
}

function ShieldLogo({ size = 40 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg" style={{ filter: "drop-shadow(0 0 8px rgba(59,130,246,0.7))", flexShrink: 0 }}>
      <defs>
        <linearGradient id="sg1" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stopColor="#1d4ed8"/><stop offset="100%" stopColor="#6366f1"/></linearGradient>
        <linearGradient id="sg2" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stopColor="#3b82f6"/><stop offset="100%" stopColor="#8b5cf6"/></linearGradient>
      </defs>
      <path d="M50 5 L90 20 L90 55 C90 76 70 90 50 95 C30 90 10 76 10 55 L10 20 Z" fill="url(#sg1)" stroke="#3b82f6" strokeWidth="2"/>
      <path d="M50 16 L80 28 L80 54 C80 70 65 81 50 86 C35 81 20 70 20 54 L20 28 Z" fill="none" stroke="rgba(147,197,253,0.3)" strokeWidth="1.5"/>
      <rect x="36" y="46" width="28" height="20" rx="3" fill="none" stroke="url(#sg2)" strokeWidth="2.5"/>
      <path d="M43 46 L43 40 C43 34 57 34 57 40 L57 46" stroke="#93c5fd" strokeWidth="2.5" strokeLinecap="round" fill="none"/>
      <circle cx="50" cy="56" r="2.5" fill="#93c5fd"/>
      <line x1="50" y1="58.5" x2="50" y2="63" stroke="#93c5fd" strokeWidth="2" strokeLinecap="round"/>
    </svg>
  );
}

// ── NAV ──────────────────────────────────────────────────────────
function Nav() {
  const [scrolled, setScrolled] = useState(false);
  useEffect(() => { const fn = () => setScrolled(window.scrollY > 50); window.addEventListener("scroll", fn); return () => window.removeEventListener("scroll", fn); }, []);
  return (
    <nav style={{ position: "fixed", top: 0, left: 0, right: 0, zIndex: 1000, background: scrolled ? "rgba(2,6,23,0.95)" : "transparent", backdropFilter: scrolled ? "blur(16px)" : "none", borderBottom: scrolled ? `1px solid ${C.border}` : "none", transition: "all 0.4s", padding: "0 32px" }}>
      <div style={{ maxWidth: 1200, margin: "0 auto", display: "flex", alignItems: "center", height: 70 }}>
        <a href="#" style={{ display: "flex", alignItems: "center", gap: 12, textDecoration: "none" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <img src="/logo.svg" alt="logo" style={{ width: 44, height: 44, objectFit: "contain" }} />
            <span style={{ fontSize: 19, fontWeight: 900, letterSpacing: 0.5 }}>
              <span style={{ color: "#fff" }}>VULNUS</span><span style={{ background: "linear-gradient(135deg,#3b82f6,#8b5cf6)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>LAB</span>
            </span>
          </div>
        </a>
        <div style={{ flex: 1 }} />
        <div style={{ display: "flex", gap: 36, alignItems: "center", marginRight: 32 }}>
          {["Features","Demo","Pricing","FAQ"].map(l => (
            <a key={l} href={`#${l.toLowerCase()}`} className="nav-link"
              onClick={() => { document.title = `VulnusLab — ${l} | Professional Penetration Testing`; }}
              style={{ color: C.muted, textDecoration: "none", fontSize: 14, fontWeight: 500, transition: "color 0.2s" }}>{l}</a>
          ))}
        </div>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <a href={DASHBOARD_URL} style={{ color: C.muted, fontSize: 14, fontWeight: 500, textDecoration: "none", padding: "8px 16px" }}>Sign In</a>
          <a href="#contact" className="btn-primary" style={{ background: "linear-gradient(135deg,#1d4ed8,#6366f1)", color: "#fff", padding: "10px 22px", borderRadius: 10, fontSize: 14, fontWeight: 700, textDecoration: "none", boxShadow: "0 4px 20px rgba(59,130,246,0.35)" }}>Start Free Trial</a>
        </div>
      </div>
    </nav>
  );
}

// ── HERO ─────────────────────────────────────────────────────────
function Hero() {
  const lines = ["XSS Scanner", "SQL Injection", "Port Scanner", "SSL Analyzer", "WAF Detector"];
  const [li, setLi] = useState(0);
  const [typed, setTyped] = useState("");
  const [del, setDel] = useState(false);
  useEffect(() => {
    const word = lines[li % lines.length];
    const t = setTimeout(() => {
      if (!del) { setTyped(p => { const n = word.slice(0, p.length + 1); if (n === word) setTimeout(() => setDel(true), 1200); return n; }); }
      else { setTyped(p => { const n = p.slice(0, -1); if (n === "") { setDel(false); setLi(p2 => p2 + 1); } return n; }); }
    }, del ? 50 : 90);
    return () => clearTimeout(t);
  }, [typed, del, li]);

  return (
    <section style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", position: "relative", overflow: "hidden", padding: "100px 24px 60px" }}>
      <style>{CSS}</style>

      {/* Animated grid */}
      <div style={{ position: "absolute", inset: 0, backgroundImage: "radial-gradient(rgba(59,130,246,0.12) 1px,transparent 1px)", backgroundSize: "40px 40px", pointerEvents: "none" }} />

      {/* Glow blobs */}
      <div style={{ position: "absolute", top: "10%", left: "20%", width: 500, height: 500, background: "radial-gradient(circle,rgba(59,130,246,0.1),transparent 70%)", filter: "blur(60px)", pointerEvents: "none" }} />
      <div style={{ position: "absolute", bottom: "10%", right: "15%", width: 400, height: 400, background: "radial-gradient(circle,rgba(139,92,246,0.08),transparent 70%)", filter: "blur(60px)", pointerEvents: "none" }} />

      <div style={{ maxWidth: 1100, margin: "0 auto", display: "grid", gridTemplateColumns: "1fr 1fr", gap: 60, alignItems: "center", position: "relative", zIndex: 1 }}>
        {/* Left */}
        <div>
          <div style={{ animation: "fadeUp 0.6s ease both", marginBottom: 20 }}>
            <span style={{ background: "rgba(59,130,246,0.1)", border: "1px solid rgba(59,130,246,0.3)", color: C.blue, fontSize: 13, fontWeight: 700, padding: "6px 16px", borderRadius: 20, letterSpacing: 0.5 }}>
              🔒 Professional Penetration Testing Platform
            </span>
          </div>

          <h1 style={{ fontSize: "clamp(36px,4vw,60px)", fontWeight: 900, lineHeight: 1.1, marginBottom: 20, animation: "fadeUp 0.7s ease 0.1s both" }}>
            Scan Any Target<br />
            <span style={{ background: "linear-gradient(135deg,#3b82f6,#8b5cf6,#06b6d4)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", backgroundSize: "200% 200%", animation: "gradientShift 4s ease infinite" }}>
              With 51 Real Tools
            </span>
          </h1>

          <div style={{ fontSize: 18, color: C.muted, marginBottom: 12, fontFamily: "JetBrains Mono,monospace", animation: "fadeUp 0.7s ease 0.2s both" }}>
            <span style={{ color: C.green }}>$</span> running <span style={{ color: C.yellow }}>{typed}</span>
            <span style={{ animation: "blink 1s infinite", color: C.blue }}>█</span>
          </div>

          <p style={{ fontSize: 17, color: C.muted, lineHeight: 1.8, marginBottom: 36, animation: "fadeUp 0.7s ease 0.3s both" }}>
            No installation. No setup. Just enter a target URL and run all 51 Kali Linux security tools with one click. Get a professional PDF report in minutes.
          </p>

          <div style={{ display: "flex", gap: 14, flexWrap: "wrap", marginBottom: 48, animation: "fadeUp 0.7s ease 0.4s both" }}>
            <a href="#contact" className="btn-primary" style={{ display: "inline-flex", alignItems: "center", gap: 8, background: "linear-gradient(135deg,#1d4ed8,#3b82f6,#6366f1)", color: "#fff", padding: "15px 30px", borderRadius: 12, fontSize: 15, fontWeight: 700, textDecoration: "none", boxShadow: "0 4px 30px rgba(59,130,246,0.5)" }}>
              🚀 Start Free — 7 Days
            </a>
            <a href="#demo" className="btn-outline" style={{ display: "inline-flex", alignItems: "center", gap: 8, background: "transparent", color: C.text, padding: "15px 30px", borderRadius: 12, fontSize: 15, fontWeight: 600, textDecoration: "none", border: `1.5px solid ${C.border}` }}>
              ▶ Watch Demo
            </a>
          </div>

          {/* Mini stats */}
          <div style={{ display: "flex", gap: 32, animation: "fadeUp 0.7s ease 0.5s both" }}>
            {[["51+","Tools"],["8","Categories"],["100%","Cloud"],["OWASP","Top 10"]].map(([n,l],i) => (
              <div key={i}>
                <div style={{ fontSize: 22, fontWeight: 800, color: C.blue }}>{n}</div>
                <div style={{ fontSize: 12, color: C.muted, fontWeight: 500 }}>{l}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Right — animated dashboard preview */}
        <FadeIn delay={0.3}>
          <div style={{ position: "relative" }}>
            <div style={{ background: C.card, border: `1px solid rgba(59,130,246,0.3)`, borderRadius: 16, overflow: "hidden", boxShadow: "0 0 80px rgba(59,130,246,0.12)", animation: "float 6s ease-in-out infinite" }}>
              {/* Window bar */}
              <div style={{ background: "#0f172a", padding: "12px 16px", display: "flex", alignItems: "center", gap: 8, borderBottom: `1px solid ${C.border}` }}>
                {["#ef4444","#f59e0b","#22c55e"].map((c,i) => <div key={i} style={{ width: 11, height: 11, borderRadius: "50%", background: c }} />)}
                <span style={{ fontSize: 12, color: C.muted, fontFamily: "JetBrains Mono,monospace", marginLeft: 8 }}>VulnusLab</span>
                <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 6 }}>
                  <div style={{ width: 8, height: 8, borderRadius: "50%", background: C.green, animation: "pulse 2s infinite" }} />
                  <span style={{ fontSize: 11, color: C.green, fontFamily: "JetBrains Mono,monospace" }}>Kali Online</span>
                </div>
              </div>

              {/* Scan results */}
              <div style={{ padding: 20, fontFamily: "JetBrains Mono,monospace", fontSize: 12.5 }}>
                <div style={{ color: C.muted, marginBottom: 12 }}>$ scanning http://testphp.vulnweb.com — 51 phases</div>
                {[
                  { ok: true,  text: "✓ WAF Detection — SECURE",                  delay: 0 },
                  { ok: true,  text: "✓ SSL/TLS Analysis — Grade A",               delay: 0.3 },
                  { ok: true,  text: "✓ Port Scan — 3 ports open (80,443,8080)",   delay: 0.6 },
                  { ok: false, text: "✗ XSS Testing — VULNERABLE (CRITICAL)",      delay: 0.9 },
                  { ok: false, text: "✗ SQL Injection — VULNERABLE (CRITICAL)",    delay: 1.2 },
                  { ok: true,  text: "✓ Header Security — 6 findings (HIGH)",      delay: 1.5 },
                  { ok: false, text: "✗ CORS Misconfiguration — HIGH",             delay: 1.8 },
                  { ok: true,  text: "✓ CSRF Protection — SECURE",                 delay: 2.1 },
                  { info: true,text: "→ Generating PDF report...",                  delay: 2.4 },
                  { done: true,text: "✓ Scan complete — 4 findings (2 CRITICAL)",  delay: 2.7 },
                ].map((line, i) => (
                  <div key={i} style={{ marginBottom: 7, color: line.done ? C.green : line.ok ? "#4ade80" : line.info ? C.blue : "#f87171", animation: `fadeUp 0.4s ease ${line.delay}s both`, display: "flex", alignItems: "center", gap: 8 }}>
                    {line.done && <span style={{ background: "#052e16", border: "1px solid #166534", color: C.green, fontSize: 10, padding: "1px 6px", borderRadius: 4, fontWeight: 700 }}>DONE</span>}
                    {(line.ok === false && !line.info) && <span style={{ background: "#1c0000", border: "1px solid #7f1d1d", color: "#f87171", fontSize: 10, padding: "1px 6px", borderRadius: 4, fontWeight: 700 }}>VULN</span>}
                    {line.text}
                  </div>
                ))}
              </div>

              {/* Bottom risk bar */}
              <div style={{ padding: "12px 20px", background: "#0f172a", borderTop: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: 12 }}>
                <span style={{ fontSize: 11, color: C.muted, fontFamily: "JetBrains Mono,monospace" }}>RISK SCORE</span>
                <div style={{ flex: 1, height: 6, background: C.border, borderRadius: 3, overflow: "hidden" }}>
                  <div style={{ width: "72%", height: "100%", background: "linear-gradient(90deg,#22c55e,#f59e0b,#ef4444)", borderRadius: 3 }} />
                </div>
                <span style={{ fontSize: 13, color: C.red, fontWeight: 700, fontFamily: "JetBrains Mono,monospace" }}>72/100 HIGH</span>
              </div>
            </div>

            {/* Floating badges */}
            <div style={{ position: "absolute", top: -16, right: -16, background: "#1c0000", border: "1px solid #7f1d1d", borderRadius: 10, padding: "8px 14px", fontSize: 12, color: "#f87171", fontWeight: 700, animation: "float 4s ease-in-out infinite 1s" }}>
              ⚠ 2 CRITICAL FOUND
            </div>
            <div style={{ position: "absolute", bottom: 60, left: -20, background: "#052e16", border: "1px solid #166534", borderRadius: 10, padding: "8px 14px", fontSize: 12, color: C.green, fontWeight: 700, animation: "float 5s ease-in-out infinite 0.5s" }}>
              📄 PDF Ready
            </div>
          </div>
        </FadeIn>
      </div>
    </section>
  );
}

// ── TRUST BAR ────────────────────────────────────────────────────
function TrustBar() {
  return (
    <div style={{ borderTop: `1px solid ${C.border}`, borderBottom: `1px solid ${C.border}`, background: C.card, padding: "20px 32px" }}>
      <div style={{ maxWidth: 1100, margin: "0 auto", display: "flex", alignItems: "center", gap: 40, flexWrap: "wrap", justifyContent: "center" }}>
        <span style={{ fontSize: 11, color: "#334155", fontWeight: 700, letterSpacing: 2, textTransform: "uppercase" }}>Powered by real tools:</span>
        {["Kali Linux","Nmap","SQLMap","Nikto","Hydra","Metasploit","Gobuster","OWASP"].map(t => (
          <span key={t} style={{ fontSize: 13, color: "#475569", fontWeight: 600, fontFamily: "JetBrains Mono,monospace" }}>{t}</span>
        ))}
      </div>
    </div>
  );
}

// ── DEMO VIDEO SECTION ────────────────────────────────────────────
function Demo() {
  const [running, setRunning] = useState(false);
  const [done, setDone] = useState([]);
  const [active, setActive] = useState(-1);
  const [termLines, setTermLines] = useState([]);
  const [finished, setFinished] = useState(false);
  const [step, setStep] = useState(0);

  const phases = [
    { name: "WAF Detection",       tool: "wafw00f",  result: "secure",   badge: "SECURE",     color: "#22c55e", t: 800  },
    { name: "Tech Fingerprinting", tool: "whatweb",  result: "info",     badge: "PHP/Apache",  color: "#3b82f6", t: 1600 },
    { name: "Port Scanning",       tool: "nmap",     result: "secure",   badge: "SECURE",     color: "#22c55e", t: 2600 },
    { name: "SSL/TLS Analysis",    tool: "ssl",      result: "secure",   badge: "Grade A",    color: "#22c55e", t: 3400 },
    { name: "XSS Testing",         tool: "xss",      result: "vuln",     badge: "VULNERABLE", color: "#ef4444", t: 4400 },
    { name: "SQL Injection",       tool: "sqlmap",   result: "vuln",     badge: "VULNERABLE", color: "#ef4444", t: 5400 },
    { name: "Header Security",     tool: "headers",  result: "warn",     badge: "6 FINDINGS", color: "#f59e0b", t: 6200 },
    { name: "CSRF Testing",        tool: "csrf",     result: "secure",   badge: "SECURE",     color: "#22c55e", t: 7000 },
  ];

  const startDemo = () => {
    setRunning(true); setDone([]); setActive(0); setTermLines([]); setFinished(false); setStep(1);
    setTermLines([{ text: "$ Starting pentest on http://testphp.vulnweb.com (51 phases)", color: C.blue }]);
    phases.forEach((ph, i) => {
      setTimeout(() => {
        setActive(i);
        setTermLines(p => [...p, { text: `[*] Phase ${i+1}/8: Running ${ph.tool}...`, color: C.muted }]);
      }, ph.t - 400);
      setTimeout(() => {
        setDone(p => [...p, i]);
        setActive(i + 1);
        const col = ph.result === "vuln" ? "#f87171" : ph.result === "warn" ? "#fb923c" : "#4ade80";
        const sym = ph.result === "vuln" ? "✗" : "✓";
        setTermLines(p => [...p, { text: `${sym} ${ph.name} — ${ph.badge}`, color: col }]);
        if (ph.result === "vuln") setStep(2);
      }, ph.t);
    });
    setTimeout(() => {
      setActive(-1); setRunning(false); setFinished(true); setStep(3);
      setTermLines(p => [...p, { text: "✓ Pentest complete — 2 CRITICAL, 1 HIGH, 0 MEDIUM", color: "#22c55e" }]);
      setTermLines(p => [...p, { text: "📄 PDF Report generated!", color: C.blue }]);
    }, 7800);
  };

  const reset = () => { setRunning(false); setDone([]); setActive(-1); setTermLines([]); setFinished(false); setStep(0); };

  const demoSteps = [
    { n: "01", label: "Enter Target URL", icon: "🎯" },
    { n: "02", label: "Run All 51 Tools", icon: "▶" },
    { n: "03", label: "See Vulnerabilities", icon: "⚠" },
    { n: "04", label: "Download PDF", icon: "📄" },
  ];

  return (
    <section id="demo" style={{ padding: "100px 24px", background: C.card }}>
      <div style={{ maxWidth: 1200, margin: "0 auto" }}>
        <FadeIn style={{ textAlign: "center", marginBottom: 48 }}>
          <span style={{ background: "rgba(6,182,212,0.1)", border: "1px solid rgba(6,182,212,0.3)", color: C.cyan, fontSize: 13, fontWeight: 700, padding: "6px 16px", borderRadius: 20 }}>Interactive Demo</span>
          <h2 style={{ fontSize: "clamp(28px,4vw,48px)", fontWeight: 800, marginTop: 16, marginBottom: 16 }}>Watch The Real Dashboard</h2>
          <p style={{ fontSize: 17, color: C.muted }}>This is exactly what you see after login. Click Run Demo to watch a live simulation.</p>
        </FadeIn>

        {/* Step indicators */}
        <div style={{ display: "flex", justifyContent: "center", gap: 0, marginBottom: 40, flexWrap: "wrap" }}>
          {demoSteps.map((s, i) => (
            <div key={i} style={{ display: "flex", alignItems: "center" }}>
              <div style={{ textAlign: "center", padding: "0 20px" }}>
                <div style={{ width: 48, height: 48, borderRadius: "50%", background: step > i ? "linear-gradient(135deg,#1d4ed8,#3b82f6)" : step === i ? "rgba(59,130,246,0.2)" : C.card2, border: `2px solid ${step > i ? C.blue : step === i ? C.blue : C.border}`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 20, margin: "0 auto 8px", transition: "all 0.5s" }}>{s.icon}</div>
                <div style={{ fontSize: 12, fontWeight: 600, color: step > i ? C.text : C.muted }}>{s.label}</div>
              </div>
              {i < 3 && <div style={{ width: 50, height: 2, background: step > i ? C.blue : C.border, transition: "all 0.5s", flexShrink: 0 }} />}
            </div>
          ))}
        </div>

        <FadeIn>
          {/* Full dashboard mockup */}
          <div style={{ background: "#020617", border: `1px solid rgba(59,130,246,0.3)`, borderRadius: 16, overflow: "hidden", boxShadow: "0 0 80px rgba(59,130,246,0.1)", display: "flex", height: 580 }}>

            {/* Sidebar */}
            <div style={{ width: 220, background: "#0a0f1e", borderRight: `1px solid ${C.border}`, display: "flex", flexDirection: "column", flexShrink: 0 }}>
              {/* Logo */}
              <div style={{ padding: "16px 12px", borderBottom: `1px solid ${C.border}` }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
                  <img src="/logo.svg" alt="logo" style={{ width: 44, height: 44, objectFit: "contain" }} />
                  <span style={{ fontSize: 13, fontWeight: 900 }}><span style={{ color: "#fff" }}>VULNUS</span><span style={{ color: C.blue }}>LAB</span></span>
                </div>
                <div style={{ background: "#052e16", border: "1px solid #166534", borderRadius: 5, padding: "6px 8px", display: "flex", alignItems: "center", gap: 6 }}>
                  <div style={{ width: 6, height: 6, borderRadius: "50%", background: C.green, animation: "pulse 2s infinite" }} />
                  <span style={{ fontSize: 11, color: C.green, fontWeight: 600 }}>Kali Online</span>
                </div>
              </div>
              {/* Nav items */}
              <div style={{ padding: "8px 0", flex: 1, overflowY: "auto" }}>
                {[
                  { label: "Dashboard", icon: "🏠", active: false },
                  { label: "Information Gathering", icon: "🔍", active: false },
                  { label: "Vulnerability Scanning", icon: "🛡️", active: false, badge: "TRIAL" },
                  { label: "Web App Pentesting", icon: "🌐", active: true, badge: "TRIAL" },
                  { label: "Advanced OSINT", icon: "🌍", active: false, lock: true },
                  { label: "Exploitation", icon: "💥", active: false, lock: true },
                  { label: "Password Attacks", icon: "🔑", active: false, lock: true },
                ].map((m, i) => (
                  <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 12px", margin: "1px 6px", borderRadius: 6, background: m.active ? "#1e3a8a" : "transparent", opacity: m.lock ? 0.45 : 1 }}>
                    <span style={{ fontSize: 14, width: 18, textAlign: "center" }}>{m.icon}</span>
                    <span style={{ fontSize: 11, color: m.active ? "#f1f5f9" : "#94a3b8", fontWeight: m.active ? 600 : 400, flex: 1 }}>{m.label}</span>
                    {m.badge && <span style={{ fontSize: 8, color: "#f59e0b", background: "rgba(245,158,11,0.1)", padding: "1px 4px", borderRadius: 3, fontWeight: 700 }}>{m.badge}</span>}
                    {m.lock && <span style={{ fontSize: 10 }}>🔒</span>}
                  </div>
                ))}
              </div>
              {/* User */}
              <div style={{ padding: "10px 12px", borderTop: `1px solid ${C.border}`, fontSize: 11, color: "#94a3b8", display: "flex", justifyContent: "space-between" }}>
                <span>demo · <span style={{ color: "#f59e0b" }}>trial</span></span>
                <span style={{ color: "#475569" }}>Sign out</span>
              </div>
            </div>

            {/* Main content */}
            <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
              {/* Top bar */}
              <div style={{ background: "#0a0f1e", borderBottom: `1px solid ${C.border}`, padding: "0 20px", height: 46, display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0 }}>
                <span style={{ fontSize: 12, color: "#94a3b8" }}>CyberSecurity / <span style={{ color: "#cbd5e1", fontWeight: 600 }}>Web Application Pentesting</span></span>
                {running && <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <div style={{ width: 7, height: 7, borderRadius: "50%", background: C.blue, animation: "pulse 1s infinite" }} />
                  <span style={{ fontSize: 11, color: C.blue, fontFamily: "JetBrains Mono,monospace" }}>LIVE SCAN</span>
                </div>}
                {finished && <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <span style={{ fontSize: 11, color: C.green, fontFamily: "JetBrains Mono,monospace" }}>✓ SCAN COMPLETE</span>
                </div>}
              </div>

              <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
                {/* Scan phases */}
                <div style={{ flex: 1, padding: 16, overflowY: "auto" }}>
                  {/* Target bar */}
                  <div style={{ display: "flex", gap: 10, marginBottom: 14, alignItems: "center" }}>
                    <div style={{ flex: 1, background: "#0f172a", border: `1px solid ${C.border}`, borderRadius: 8, padding: "8px 14px", fontFamily: "JetBrains Mono,monospace", fontSize: 12, color: C.blue }}>
                      http://testphp.vulnweb.com
                    </div>
                    <button onClick={running ? null : finished ? reset : startDemo}
                      style={{ background: running ? "#1e293b" : "linear-gradient(135deg,#1d4ed8,#3b82f6)", color: running ? C.muted : "#fff", border: "none", padding: "9px 18px", borderRadius: 8, fontSize: 12, fontWeight: 700, cursor: running ? "not-allowed" : "pointer", whiteSpace: "nowrap" }}>
                      {running ? "⏳ Scanning..." : finished ? "↺ Reset" : "▶ Run Demo"}
                    </button>
                  </div>

                  {/* Phase cards */}
                  <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
                    {phases.map((ph, i) => {
                      const isDone = done.includes(i);
                      const isActive = active === i;
                      const leftColor = isDone ? (ph.result === "vuln" ? "#ef4444" : ph.result === "warn" ? "#f59e0b" : "#22c55e") : isActive ? C.blue : "#1e293b";
                      return (
                        <div key={i} style={{ background: "#0f172a", border: `1px solid ${isActive ? C.blue : C.border}`, borderLeft: `3px solid ${leftColor}`, borderRadius: 8, padding: "10px 14px", display: "flex", alignItems: "center", gap: 12, transition: "all 0.3s" }}>
                          <div style={{ width: 28, height: 28, borderRadius: "50%", background: isDone ? `${ph.color}20` : isActive ? "rgba(59,130,246,0.15)" : "#0a0f1e", border: `2px solid ${isDone ? ph.color : isActive ? C.blue : C.border}`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, fontSize: 11, fontWeight: 700, color: isDone ? ph.color : isActive ? C.blue : "#334155", fontFamily: "JetBrains Mono,monospace" }}>
                            {isDone ? (ph.result === "vuln" ? "✗" : "✓") : isActive ? <div style={{ width: 10, height: 10, border: "2px solid #3b82f6", borderTopColor: "transparent", borderRadius: "50%", animation: "spin 0.8s linear infinite" }} /> : String(i+1).padStart(2,"0")}
                          </div>
                          <span style={{ fontSize: 12, fontWeight: 600, color: isDone ? "#f1f5f9" : isActive ? "#93c5fd" : "#475569", flex: 1 }}>{ph.name}</span>
                          <span style={{ fontSize: 10, color: "#334155", fontFamily: "JetBrains Mono,monospace", background: "#020617", border: `1px solid ${C.border}`, borderRadius: 3, padding: "1px 6px" }}>{ph.tool}</span>
                          {isDone && <span style={{ fontSize: 10, background: `${ph.color}15`, color: ph.color, border: `1px solid ${ph.color}40`, borderRadius: 4, padding: "2px 8px", fontWeight: 700 }}>{ph.badge}</span>}
                          {isActive && <span style={{ fontSize: 10, background: "rgba(59,130,246,0.1)", color: C.blue, border: "1px solid rgba(59,130,246,0.3)", borderRadius: 4, padding: "2px 8px", fontWeight: 700 }}>RUNNING</span>}
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Terminal */}
                <div style={{ width: 280, borderLeft: `1px solid ${C.border}`, display: "flex", flexDirection: "column" }}>
                  <div style={{ padding: "8px 12px", borderBottom: `1px solid ${C.border}`, fontSize: 11, color: C.muted, fontFamily: "JetBrains Mono,monospace", background: "#0f172a" }}>Terminal</div>
                  <div style={{ flex: 1, padding: 12, overflowY: "auto", fontFamily: "JetBrains Mono,monospace", fontSize: 11, lineHeight: 1.8 }}>
                    {termLines.length === 0 && <div style={{ color: "#334155", paddingTop: 20, textAlign: "center" }}>Click Run Demo →</div>}
                    {termLines.map((l, i) => <div key={i} style={{ color: l.color, marginBottom: 3 }}>{l.text}</div>)}
                  </div>
                  {finished && (
                    <div style={{ padding: "10px 12px", borderTop: `1px solid ${C.border}`, display: "flex", flexDirection: "column", gap: 6 }}>
                      <div style={{ background: "#1c0000", border: "1px solid #7f1d1d", borderRadius: 6, padding: "6px 10px", fontSize: 11, color: "#f87171", fontWeight: 700, textAlign: "center" }}>⚠ 2 CRITICAL FOUND</div>
                      <div style={{ background: "#052e16", border: "1px solid #166534", borderRadius: 6, padding: "6px 10px", fontSize: 11, color: C.green, fontWeight: 700, textAlign: "center" }}>📄 PDF Ready</div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </FadeIn>

        <FadeIn>
          <p style={{ textAlign: "center", marginTop: 24, fontSize: 14, color: C.muted }}>
            This is the real dashboard interface. <a href="#contact" style={{ color: C.blue, fontWeight: 700, textDecoration: "none" }}>Start your free trial →</a>
          </p>
        </FadeIn>
      </div>
    </section>
  );
}

// ── STATS ────────────────────────────────────────────────────────
function Stats() {
  const stats = [
    { n: 51, s: "+", label: "Security Tools", icon: "🛠", color: C.blue },
    { n: 8, s: "", label: "Attack Categories", icon: "🎯", color: C.purple },
    { n: 100, s: "%", label: "Cloud Based", icon: "☁️", color: C.cyan },
    { n: 5, s: "", label: "Built-in Labs", icon: "🧪", color: C.green },
  ];
  return (
    <section style={{ padding: "80px 24px" }}>
      <div style={{ maxWidth: 1000, margin: "0 auto", display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(200px,1fr))", gap: 24 }}>
        {stats.map((s, i) => (
          <FadeIn key={i} delay={i * 0.1}>
            <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 16, padding: 32, textAlign: "center", position: "relative", overflow: "hidden" }}>
              <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 3, background: `linear-gradient(90deg,transparent,${s.color},transparent)` }} />
              <div style={{ fontSize: 36, marginBottom: 12 }}>{s.icon}</div>
              <div style={{ fontSize: 44, fontWeight: 900, color: s.color, lineHeight: 1 }}>
                <Counter target={s.n} suffix={s.s} />
              </div>
              <div style={{ fontSize: 14, color: C.muted, fontWeight: 500, marginTop: 8 }}>{s.label}</div>
            </div>
          </FadeIn>
        ))}
      </div>
    </section>
  );
}

// ── FEATURES ─────────────────────────────────────────────────────
function Features() {
  const features = [
    { icon: "⚡", title: "Real Kali Linux Tools", desc: "Not simulated. Every scan runs real penetration testing tools — Nmap, SQLMap, Nikto, Hydra — on our Kali Linux cloud servers. Same tools used in OSCP and OSWE certifications.", color: C.blue, tag: "Real Tools" },
    { icon: "📄", title: "Auto PDF Reports", desc: "Professional penetration test reports auto-generated after every scan. Includes CVSS scores, CVE references, OWASP mapping, and step-by-step remediation guidance.", color: C.purple, tag: "Reports" },
    { icon: "🧪", title: "5 Vulnerable Labs", desc: "Practice on DVWA, OWASP WebGoat, Juice Shop, Mutillidae and bWAPP — all running inside our platform. No VM needed. No downloads. Just open and hack.", color: C.green, tag: "Labs" },
    { icon: "🔒", title: "Private & Secure", desc: "Each user sees only their own scan history. Your targets, findings, and reports are completely private. JWT authentication with 30-day sessions.", color: C.cyan, tag: "Privacy" },
    { icon: "📊", title: "JSON & CSV Export", desc: "Export all scan results as JSON for integration with your tools, or CSV for Excel analysis. Share findings with your team in any format.", color: C.yellow, tag: "Export" },
    { icon: "🎯", title: "One Click Full Scan", desc: "Select your target, click Start, and all 51 tools run automatically in sequence. No manual command typing. No tool configuration. Results in minutes.", color: C.orange, tag: "Automation" },
  ];
  return (
    <section id="features" style={{ padding: "100px 24px", background: C.card }}>
      <div style={{ maxWidth: 1100, margin: "0 auto" }}>
        <FadeIn style={{ textAlign: "center", marginBottom: 60 }}>
          <span style={{ background: "rgba(139,92,246,0.1)", border: "1px solid rgba(139,92,246,0.3)", color: C.purple, fontSize: 13, fontWeight: 700, padding: "6px 16px", borderRadius: 20 }}>Platform Features</span>
          <h2 style={{ fontSize: "clamp(28px,4vw,48px)", fontWeight: 800, marginTop: 16, marginBottom: 16 }}>Everything You Need.<br />Nothing You Don't.</h2>
          <p style={{ fontSize: 17, color: C.muted, maxWidth: 560, margin: "0 auto" }}>Built specifically for penetration testers, security engineers, and OSCP students.</p>
        </FadeIn>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(320px,1fr))", gap: 24 }}>
          {features.map((f, i) => (
            <FadeIn key={i} delay={i * 0.08}>
              <div className="feature-card" style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 16, padding: 32, position: "relative", overflow: "hidden" }}>
                <div style={{ position: "absolute", top: 0, right: 0, width: 100, height: 100, background: `radial-gradient(circle,${f.color}15,transparent)`, pointerEvents: "none" }} />
                <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20 }}>
                  <div style={{ width: 48, height: 48, borderRadius: 12, background: `${f.color}15`, border: `1px solid ${f.color}30`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 24 }}>{f.icon}</div>
                  <span style={{ background: `${f.color}15`, color: f.color, fontSize: 11, fontWeight: 700, padding: "3px 10px", borderRadius: 6, letterSpacing: 0.5 }}>{f.tag}</span>
                </div>
                <h3 style={{ fontSize: 19, fontWeight: 700, marginBottom: 12, color: C.text }}>{f.title}</h3>
                <p style={{ fontSize: 14, color: C.muted, lineHeight: 1.8 }}>{f.desc}</p>
              </div>
            </FadeIn>
          ))}
        </div>
      </div>
    </section>
  );
}

// ── 51 SCANNERS ──────────────────────────────────────────────────
function Scanners() {
  const cats = [
    { icon: "🔍", title: "Reconnaissance", count: 11, color: C.blue, tools: ["WAF Detection","Tech Stack","CMS Detection","Port Scan","SSL/TLS","DNS Enum","Subdomains","Takeover","Nikto","Sensitive Files","Exploit Search"] },
    { icon: "📁", title: "Discovery & Fuzzing", count: 2, color: C.cyan, tools: ["Directory Enum","Web Fuzzing (ffuf)"] },
    { icon: "💉", title: "Injection Attacks", count: 7, color: C.red, tools: ["XSS Testing","SQL Injection","NoSQL","Command Injection","XXE","SSTI","Host Header"] },
    { icon: "🔐", title: "Auth & Session", count: 9, color: C.purple, tools: ["Header Security","Cookie Analysis","Hydra BruteForce","JWT Attacks","CSRF","IDOR","OAuth","2FA Bypass","Session Fixation"] },
    { icon: "📂", title: "File & Path", count: 3, color: C.orange, tools: ["LFI / Path Traversal","Remote File Inclusion","File Upload"] },
    { icon: "🌐", title: "Network & Protocol", count: 10, color: "#0891b2", tools: ["CORS","SSRF","HTTP Smuggling","Verb Tampering","Clickjacking","Open Redirect","Param Pollution","WebSocket","Response Splitting","Data Exfil"] },
    { icon: "⚡", title: "Modern Web (OSWE)", count: 5, color: C.green, tools: ["Deserialization","Prototype Pollution","GraphQL","Race Condition","PHP Type Juggling"] },
    { icon: "🖥", title: "Infrastructure (OSCP)", count: 4, color: C.yellow, tools: ["SMB Enum","FTP Enum","SMTP User Enum","SNMP Scanner"] },
  ];
  return (
    <section style={{ padding: "100px 24px" }}>
      <div style={{ maxWidth: 1200, margin: "0 auto" }}>
        <FadeIn style={{ textAlign: "center", marginBottom: 60 }}>
          <span style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)", color: C.red, fontSize: 13, fontWeight: 700, padding: "6px 16px", borderRadius: 20 }}>51 Scanners</span>
          <h2 style={{ fontSize: "clamp(28px,4vw,48px)", fontWeight: 800, marginTop: 16, marginBottom: 16 }}>Full OWASP Top 10 Coverage</h2>
          <p style={{ fontSize: 17, color: C.muted }}>8 categories. 51 tools. Everything a pentester needs.</p>
        </FadeIn>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(260px,1fr))", gap: 20 }}>
          {cats.map((cat, i) => (
            <FadeIn key={i} delay={i * 0.07}>
              <div className="scanner-card" style={{ background: C.card, border: `1px solid ${C.border}`, borderTop: `3px solid ${cat.color}`, borderRadius: 14, padding: 24 }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <span style={{ fontSize: 22 }}>{cat.icon}</span>
                    <span style={{ fontSize: 15, fontWeight: 700 }}>{cat.title}</span>
                  </div>
                  <span style={{ background: `${cat.color}20`, color: cat.color, fontSize: 12, fontWeight: 700, padding: "2px 10px", borderRadius: 12 }}>{cat.count}</span>
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                  {cat.tools.slice(0, 5).map(t => <span key={t} style={{ fontSize: 11, background: `${cat.color}10`, color: cat.color, padding: "3px 8px", borderRadius: 5, fontWeight: 600 }}>{t}</span>)}
                  {cat.tools.length > 5 && <span style={{ fontSize: 11, color: C.muted, padding: "3px 8px" }}>+{cat.tools.length-5} more</span>}
                </div>
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
    { n: "01", icon: "📋", title: "Request Access", desc: "Fill the form with your name, email, and phone. Choose trial or paid plan. No technical knowledge needed.", color: C.blue },
    { n: "02", icon: "📧", title: "Get Credentials", desc: "We create your account manually and email your username and strong password within 30 minutes.", color: C.purple },
    { n: "03", icon: "🚀", title: "Login & Scan", desc: "Open the dashboard, enter any target URL, select tools, click Start. Get full PDF report in minutes.", color: C.green },
  ];
  return (
    <section style={{ padding: "100px 24px", background: C.card }}>
      <div style={{ maxWidth: 1000, margin: "0 auto" }}>
        <FadeIn style={{ textAlign: "center", marginBottom: 60 }}>
          <span style={{ background: "rgba(34,197,94,0.1)", border: "1px solid rgba(34,197,94,0.3)", color: C.green, fontSize: 13, fontWeight: 700, padding: "6px 16px", borderRadius: 20 }}>Simple Process</span>
          <h2 style={{ fontSize: "clamp(28px,4vw,48px)", fontWeight: 800, marginTop: 16, marginBottom: 16 }}>Start Scanning In 3 Steps</h2>
          <p style={{ fontSize: 17, color: C.muted }}>No installation. No configuration. Just login and scan.</p>
        </FadeIn>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(280px,1fr))", gap: 32 }}>
          {steps.map((s, i) => (
            <FadeIn key={i} delay={i * 0.15}>
              <div style={{ textAlign: "center", padding: "32px 24px", background: C.bg, border: `1px solid ${C.border}`, borderRadius: 20, position: "relative" }}>
                <div style={{ position: "absolute", top: 20, right: 20, fontSize: 48, fontWeight: 900, color: `${s.color}10`, fontFamily: "JetBrains Mono,monospace" }}>{s.n}</div>
                <div style={{ width: 72, height: 72, borderRadius: "50%", background: `linear-gradient(135deg,${s.color}30,${s.color}10)`, border: `2px solid ${s.color}40`, display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 24px", fontSize: 32 }}>{s.icon}</div>
                <div style={{ fontSize: 12, color: s.color, fontWeight: 700, fontFamily: "JetBrains Mono,monospace", letterSpacing: 2, marginBottom: 10 }}>STEP {s.n}</div>
                <h3 style={{ fontSize: 20, fontWeight: 700, marginBottom: 12 }}>{s.title}</h3>
                <p style={{ fontSize: 15, color: C.muted, lineHeight: 1.8 }}>{s.desc}</p>
              </div>
            </FadeIn>
          ))}
        </div>
      </div>
    </section>
  );
}

// ── PRICING ──────────────────────────────────────────────────────
function Pricing() {
  const plans = [
    { name: "Trial", sub: "Try before you pay", price: "FREE", period: "7 days", color: C.muted, popular: false,
      features: ["7 days free access","5 recon tools (Section 1)","50 tool calls per day","PDF reports included","1 user account"],
      locked: ["All injection attacks","Auth & session attacks","File & path attacks","Network attacks"],
      cta: "Start Free Trial" },
    { name: "Pro", sub: "For professionals", price: "Contact Us", period: "per month", color: C.blue, popular: true,
      features: ["All 51 scanners unlocked","Unlimited scans per day","PDF + JSON + CSV reports","Priority email support","1 user account","5 built-in vulnerable labs"],
      locked: [],
      cta: "Get Pro Access" },
    { name: "Enterprise", sub: "For security teams", price: "Contact Us", period: "per month", color: C.purple, popular: false,
      features: ["Everything in Pro","Multiple user accounts","Team scan history","Custom wordlists","Dedicated support","Admin panel access"],
      locked: [],
      cta: "Contact Us" },
  ];
  return (
    <section id="pricing" style={{ padding: "100px 24px" }}>
      <div style={{ maxWidth: 1100, margin: "0 auto" }}>
        <FadeIn style={{ textAlign: "center", marginBottom: 60 }}>
          <span style={{ background: "rgba(59,130,246,0.1)", border: "1px solid rgba(59,130,246,0.3)", color: C.blue, fontSize: 13, fontWeight: 700, padding: "6px 16px", borderRadius: 20 }}>Pricing</span>
          <h2 style={{ fontSize: "clamp(28px,4vw,48px)", fontWeight: 800, marginTop: 16, marginBottom: 16 }}>Simple, Honest Pricing</h2>
          <p style={{ fontSize: 17, color: C.muted }}>Start free for 7 days. Upgrade when you see the value.</p>
        </FadeIn>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(300px,1fr))", gap: 24, alignItems: "start" }}>
          {plans.map((p, i) => (
            <FadeIn key={i} delay={i * 0.1}>
              <div style={{ background: p.popular ? "linear-gradient(135deg,rgba(29,78,216,0.15),rgba(99,102,241,0.1))" : C.card, border: `2px solid ${p.popular ? C.blue : C.border}`, borderRadius: 20, padding: 36, position: "relative", boxShadow: p.popular ? "0 0 60px rgba(59,130,246,0.15)" : "none" }}>
                {p.popular && <div style={{ position: "absolute", top: -14, left: "50%", transform: "translateX(-50%)", background: "linear-gradient(135deg,#1d4ed8,#6366f1)", color: "#fff", fontSize: 12, fontWeight: 700, padding: "5px 20px", borderRadius: 20, whiteSpace: "nowrap" }}>⭐ Most Popular</div>}
                <div style={{ marginBottom: 6 }}>
                  <span style={{ background: `${p.color}15`, color: p.color, fontSize: 12, fontWeight: 700, padding: "3px 12px", borderRadius: 8 }}>{p.name}</span>
                </div>
                <div style={{ fontSize: 13, color: C.muted, marginBottom: 8, marginTop: 8 }}>{p.sub}</div>
                <div style={{ fontSize: 38, fontWeight: 900, color: p.color, marginBottom: 4 }}>{p.price}</div>
                <div style={{ fontSize: 13, color: C.muted, marginBottom: 28 }}>{p.period}</div>
                <div style={{ borderTop: `1px solid ${C.border}`, paddingTop: 24, marginBottom: 28 }}>
                  {p.features.map((f, fi) => <div key={fi} style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 12 }}>
                    <span style={{ color: C.green, fontSize: 14, flexShrink: 0 }}>✓</span>
                    <span style={{ fontSize: 14, color: C.muted }}>{f}</span>
                  </div>)}
                  {p.locked.map((f, fi) => <div key={fi} style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 12, opacity: 0.4 }}>
                    <span style={{ color: C.red, fontSize: 14, flexShrink: 0 }}>✗</span>
                    <span style={{ fontSize: 14, color: C.muted, textDecoration: "line-through" }}>{f}</span>
                  </div>)}
                </div>
                <a href="#contact" className={p.popular ? "btn-primary" : "btn-outline"} style={{ display: "flex", justifyContent: "center", padding: "14px", borderRadius: 10, fontSize: 14, fontWeight: 700, textDecoration: "none", background: p.popular ? "linear-gradient(135deg,#1d4ed8,#3b82f6)" : "transparent", color: p.popular ? "#fff" : p.color, border: `1.5px solid ${p.color}40`, boxShadow: p.popular ? "0 4px 20px rgba(59,130,246,0.4)" : "none" }}>{p.cta}</a>
              </div>
            </FadeIn>
          ))}
        </div>
        <FadeIn>
          <p style={{ textAlign: "center", fontSize: 14, color: C.muted, marginTop: 32 }}>
            🔒 Secure payment · Credentials by email in 30 minutes · No auto-renewal · Cancel anytime
          </p>
        </FadeIn>
      </div>
    </section>
  );
}

// ── TESTIMONIALS ─────────────────────────────────────────────────
function Testimonials() {
  const reviews = [
    { text: "This dashboard saves me 4–5 hours per engagement. I run the full scan, download the PDF, and send it straight to the client. The findings are accurate and professional.", name: "Rahul S.", role: "Senior Penetration Tester", stars: 5, tag: "Pentester" },
    { text: "Perfect for OSCP prep. Every tool you need is already there. I practiced on DVWA and WebGoat every day. Passed my exam on the first attempt.", name: "Priya M.", role: "Security Student & OSCP Certified", stars: 5, tag: "Student" },
    { text: "Our security team runs weekly scans on our infrastructure. The OWASP Top 10 coverage and automatic reports give management the confidence they need for compliance.", name: "Arjun K.", role: "IT Security Manager", stars: 5, tag: "Enterprise" },
  ];
  return (
    <section style={{ padding: "100px 24px", background: C.card }}>
      <div style={{ maxWidth: 1100, margin: "0 auto" }}>
        <FadeIn style={{ textAlign: "center", marginBottom: 60 }}>
          <span style={{ background: "rgba(245,158,11,0.1)", border: "1px solid rgba(245,158,11,0.3)", color: C.yellow, fontSize: 13, fontWeight: 700, padding: "6px 16px", borderRadius: 20 }}>Testimonials</span>
          <h2 style={{ fontSize: "clamp(28px,4vw,48px)", fontWeight: 800, marginTop: 16 }}>Loved By Security Professionals</h2>
        </FadeIn>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(310px,1fr))", gap: 24 }}>
          {reviews.map((r, i) => (
            <FadeIn key={i} delay={i * 0.1}>
              <div style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 16, padding: 32, position: "relative" }}>
                <div style={{ position: "absolute", top: 24, right: 24 }}>
                  <span style={{ background: "rgba(245,158,11,0.1)", color: C.yellow, fontSize: 11, fontWeight: 700, padding: "3px 10px", borderRadius: 6 }}>{r.tag}</span>
                </div>
                <div style={{ fontSize: 24, color: C.yellow, marginBottom: 16, letterSpacing: 2 }}>{"★".repeat(r.stars)}</div>
                <p style={{ fontSize: 15, color: C.muted, lineHeight: 1.9, marginBottom: 24, fontStyle: "italic" }}>"{r.text}"</p>
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <div style={{ width: 40, height: 40, borderRadius: "50%", background: `linear-gradient(135deg,${C.blue},${C.purple})`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16, fontWeight: 700 }}>{r.name[0]}</div>
                  <div>
                    <div style={{ fontSize: 14, fontWeight: 700 }}>{r.name}</div>
                    <div style={{ fontSize: 12, color: C.muted }}>{r.role}</div>
                  </div>
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
  const [open, setOpen] = useState(0);
  const faqs = [
    { q: "Is this legal to use?", a: "Yes — for authorized testing only. You must have written permission to scan any target. We include 5 built-in vulnerable labs (DVWA, WebGoat, etc.) for safe, legal practice. Never scan targets you don't own or have permission to test." },
    { q: "Do I need to install anything?", a: "No. Everything runs on our cloud servers powered by Kali Linux. Open your browser, login, enter a target, and scan. Works on Windows, Mac, Linux — any device with a browser." },
    { q: "How do I get my credentials after payment?", a: "After you fill the contact form, we manually create your account with a strong password and email your login details within 30 minutes. You'll receive the dashboard URL, username, and password." },
    { q: "Can I try it before paying?", a: "Yes! Start a 7-day free trial instantly — no credit card required. Trial gives you access to 5 recon tools and 50 tool calls per day. Enough to understand the power of the platform." },
    { q: "What targets can I scan?", a: "Any system you own or have written authorization to test. We also provide 5 built-in vulnerable labs — DVWA, OWASP WebGoat, Juice Shop, Mutillidae, and bWAPP — for safe legal practice anytime." },
    { q: "What makes this different from free tools?", a: "Free tools are separate — you install Nmap here, SQLMap there, Nikto somewhere else. Our platform combines 51 tools in one dashboard, runs them automatically in sequence, and generates a professional PDF report. Hours of manual work done in minutes." },
    { q: "Is my data private and secure?", a: "Yes. Each user has their own isolated account. Your scan history, targets, and reports are never visible to other users. We use JWT authentication with 30-day sessions." },
    { q: "Can I upgrade from trial to Pro?", a: "Yes — contact us anytime via email or the form below. We'll upgrade your account immediately and your scan history is preserved." },
  ];
  return (
    <section id="faq" style={{ padding: "100px 24px" }}>
      <div style={{ maxWidth: 800, margin: "0 auto" }}>
        <FadeIn style={{ textAlign: "center", marginBottom: 60 }}>
          <span style={{ background: "rgba(139,92,246,0.1)", border: "1px solid rgba(139,92,246,0.3)", color: C.purple, fontSize: 13, fontWeight: 700, padding: "6px 16px", borderRadius: 20 }}>FAQ</span>
          <h2 style={{ fontSize: "clamp(28px,4vw,48px)", fontWeight: 800, marginTop: 16 }}>Got Questions?</h2>
        </FadeIn>
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {faqs.map((f, i) => (
            <FadeIn key={i} delay={i * 0.03}>
              <div style={{ background: C.card, border: `1px solid ${open === i ? C.blue : C.border}`, borderRadius: 12, overflow: "hidden", transition: "border-color 0.3s" }}>
                <button className="faq-btn" onClick={() => setOpen(open === i ? -1 : i)} style={{ width: "100%", background: "none", border: "none", padding: "20px 24px", display: "flex", justifyContent: "space-between", alignItems: "center", cursor: "pointer", gap: 16, textAlign: "left" }}>
                  <span style={{ fontSize: 16, fontWeight: 600, color: open === i ? C.blue : C.text }}>{f.q}</span>
                  <div style={{ width: 28, height: 28, borderRadius: "50%", background: open === i ? C.blue : C.border, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, transition: "all 0.3s" }}>
                    <span style={{ color: open === i ? "#fff" : C.muted, fontSize: 18, lineHeight: 1, transform: open === i ? "rotate(45deg)" : "none", transition: "transform 0.3s", display: "block" }}>+</span>
                  </div>
                </button>
                {open === i && <div style={{ padding: "0 24px 20px", fontSize: 15, color: C.muted, lineHeight: 1.9, animation: "fadeUp 0.3s ease" }}>{f.a}</div>}
              </div>
            </FadeIn>
          ))}
        </div>
      </div>
    </section>
  );
}

// ── CTA BANNER ───────────────────────────────────────────────────
function CTABanner() {
  return (
    <section style={{ padding: "80px 24px", background: "linear-gradient(135deg,rgba(29,78,216,0.2),rgba(99,102,241,0.1))", borderTop: `1px solid rgba(59,130,246,0.2)`, borderBottom: `1px solid rgba(59,130,246,0.2)` }}>
      <FadeIn style={{ maxWidth: 700, margin: "0 auto", textAlign: "center" }}>
        <div style={{ fontSize: 48, marginBottom: 16 }}>🚀</div>
        <h2 style={{ fontSize: "clamp(28px,4vw,44px)", fontWeight: 800, marginBottom: 16 }}>Ready To Start Scanning?</h2>
        <p style={{ fontSize: 17, color: C.muted, marginBottom: 36, lineHeight: 1.8 }}>Join security professionals using our platform. 7-day free trial. No credit card. Credentials by email in 30 minutes.</p>
        <div style={{ display: "flex", gap: 16, justifyContent: "center", flexWrap: "wrap" }}>
          <a href="#contact" className="btn-primary" style={{ display: "inline-flex", alignItems: "center", gap: 8, background: "linear-gradient(135deg,#1d4ed8,#3b82f6,#6366f1)", color: "#fff", padding: "16px 36px", borderRadius: 12, fontSize: 16, fontWeight: 700, textDecoration: "none", boxShadow: "0 4px 30px rgba(59,130,246,0.5)" }}>
            🔒 Start Free Trial
          </a>
          <a href={`mailto:${CONTACT_EMAIL}`} className="btn-outline" style={{ display: "inline-flex", alignItems: "center", gap: 8, background: "transparent", color: C.text, padding: "16px 36px", borderRadius: 12, fontSize: 16, fontWeight: 600, textDecoration: "none", border: `1.5px solid ${C.border}` }}>
            📧 Email Us
          </a>
        </div>
      </FadeIn>
    </section>
  );
}

// ── CONTACT ──────────────────────────────────────────────────────
function Contact() {
  const [form, setForm] = useState({ name: "", email: "", phone: "", company: "", plan: "trial", message: "" });
  const [sent, setSent] = useState(false);
  const set = (k, v) => setForm(p => ({ ...p, [k]: v }));
  const inp = { width: "100%", background: "#0f172a", border: `1px solid ${C.border}`, borderRadius: 10, padding: "13px 16px", color: C.text, fontSize: 14, outline: "none", fontFamily: "Inter,sans-serif", boxSizing: "border-box", transition: "border-color 0.2s" };
  const submit = (e) => {
    e.preventDefault();
    const subject = `[${form.plan.toUpperCase()}] VulnusLab Access — ${form.name}`;
    const body = `Name: ${form.name}\nEmail: ${form.email}\nPhone: ${form.phone}\nCompany: ${form.company || "N/A"}\nPlan: ${form.plan}\n\nMessage:\n${form.message}`;
    window.location.href = `mailto:${CONTACT_EMAIL}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
    setSent(true);
  };
  return (
    <section id="contact" style={{ padding: "100px 24px", background: C.card }}>
      <div style={{ maxWidth: 660, margin: "0 auto" }}>
        <FadeIn style={{ textAlign: "center", marginBottom: 48 }}>
          <span style={{ background: "rgba(34,197,94,0.1)", border: "1px solid rgba(34,197,94,0.3)", color: C.green, fontSize: 13, fontWeight: 700, padding: "6px 16px", borderRadius: 20 }}>Get Access</span>
          <h2 style={{ fontSize: "clamp(28px,4vw,44px)", fontWeight: 800, marginTop: 16, marginBottom: 12 }}>Request Your Account</h2>
          <p style={{ fontSize: 16, color: C.muted, lineHeight: 1.8 }}>Fill the form. We create your account manually and email credentials within 30 minutes.</p>
        </FadeIn>
        {sent ? (
          <FadeIn>
            <div style={{ background: "#052e16", border: "2px solid #166534", borderRadius: 20, padding: 60, textAlign: "center" }}>
              <div style={{ fontSize: 64, marginBottom: 20 }}>✅</div>
              <h3 style={{ fontSize: 26, fontWeight: 800, color: "#4ade80", marginBottom: 12 }}>Request Received!</h3>
              <p style={{ color: C.muted, fontSize: 16, lineHeight: 1.8 }}>We'll create your account and send credentials to <strong style={{ color: C.text }}>{form.email}</strong> within 30 minutes.</p>
            </div>
          </FadeIn>
        ) : (
          <FadeIn>
            <form onSubmit={submit} style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 20, padding: 44 }}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
                <div>
                  <label style={{ fontSize: 12, color: C.muted, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase", display: "block", marginBottom: 8 }}>Full Name *</label>
                  <input style={inp} value={form.name} onChange={e => set("name", e.target.value)} placeholder="John Smith" required />
                </div>
                <div>
                  <label style={{ fontSize: 12, color: C.muted, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase", display: "block", marginBottom: 8 }}>Email *</label>
                  <input style={inp} type="email" value={form.email} onChange={e => set("email", e.target.value)} placeholder="john@company.com" required />
                </div>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
                <div>
                  <label style={{ fontSize: 12, color: C.muted, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase", display: "block", marginBottom: 8 }}>Phone *</label>
                  <input style={inp} value={form.phone} onChange={e => set("phone", e.target.value)} placeholder="+91 98765 43210" required />
                </div>
                <div>
                  <label style={{ fontSize: 12, color: C.muted, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase", display: "block", marginBottom: 8 }}>Company</label>
                  <input style={inp} value={form.company} onChange={e => set("company", e.target.value)} placeholder="Optional" />
                </div>
              </div>
              <div style={{ marginBottom: 16 }}>
                <label style={{ fontSize: 12, color: C.muted, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase", display: "block", marginBottom: 8 }}>Plan *</label>
                <select style={{ ...inp, cursor: "pointer" }} value={form.plan} onChange={e => set("plan", e.target.value)}>
                  <option value="trial">🆓 Trial — 7 Days Free (No payment needed)</option>
                  <option value="pro">⚡ Pro — All 51 Scanners</option>
                  <option value="enterprise">🏢 Enterprise — Team Access</option>
                </select>
              </div>
              <div style={{ marginBottom: 24 }}>
                <label style={{ fontSize: 12, color: C.muted, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase", display: "block", marginBottom: 8 }}>Message</label>
                <textarea style={{ ...inp, minHeight: 100, resize: "vertical" }} value={form.message} onChange={e => set("message", e.target.value)} placeholder="Tell us your use case (optional)" />
              </div>
              <button type="submit" className="btn-primary" style={{ width: "100%", background: "linear-gradient(135deg,#1d4ed8,#3b82f6,#6366f1)", color: "#fff", border: "none", padding: "16px", borderRadius: 12, fontSize: 16, fontWeight: 700, cursor: "pointer", boxShadow: "0 4px 24px rgba(59,130,246,0.4)", fontFamily: "Inter,sans-serif" }}>
                🚀 Request Access Now
              </button>
              <p style={{ textAlign: "center", fontSize: 13, color: C.muted, marginTop: 16 }}>
                Or email directly: <a href={`mailto:${CONTACT_EMAIL}`} style={{ color: C.blue, textDecoration: "none", fontWeight: 600 }}>{CONTACT_EMAIL}</a>
              </p>
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
    <footer style={{ borderTop: `1px solid ${C.border}`, padding: "60px 24px 32px", background: C.bg }}>
      <div style={{ maxWidth: 1100, margin: "0 auto" }}>
        <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr", gap: 48, marginBottom: 48, flexWrap: "wrap" }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
              <img src="/logo.svg" alt="logo" style={{ width: 44, height: 44, objectFit: "contain" }} />
              <span style={{ fontSize: 18, fontWeight: 900 }}><span style={{ color: "#fff" }}>VULNUS</span><span style={{ color: C.blue }}>LAB</span></span>
            </div>
            <p style={{ fontSize: 14, color: C.muted, lineHeight: 1.8, maxWidth: 300 }}>Professional penetration testing platform powered by Kali Linux. 51 real security tools in one cloud dashboard.</p>
            <div style={{ marginTop: 20, fontSize: 12, color: "#334155", fontFamily: "JetBrains Mono,monospace", letterSpacing: 1 }}>PROTECT | DETECT | RESPOND</div>
          </div>
          <div>
            <div style={{ fontSize: 12, color: "#475569", fontWeight: 700, letterSpacing: 2, textTransform: "uppercase", marginBottom: 20 }}>Platform</div>
            {["Features","Demo","Pricing","FAQ","Start Trial"].map(l => (
              <div key={l} style={{ marginBottom: 12 }}>
                <a href={`#${l.toLowerCase().replace(" ","-")}`} className="nav-link" style={{ fontSize: 14, color: C.muted, textDecoration: "none" }}>{l}</a>
              </div>
            ))}
          </div>
          <div>
            <div style={{ fontSize: 12, color: "#475569", fontWeight: 700, letterSpacing: 2, textTransform: "uppercase", marginBottom: 20 }}>Contact</div>
            <div style={{ marginBottom: 12 }}><a href={`mailto:${CONTACT_EMAIL}`} style={{ fontSize: 14, color: C.muted, textDecoration: "none", wordBreak: "break-all" }}>{CONTACT_EMAIL}</a></div>
            <div style={{ marginBottom: 12 }}><a href="#contact" style={{ fontSize: 14, color: C.blue, textDecoration: "none", fontWeight: 700 }}>Get Access →</a></div>
            <div style={{ marginTop: 24 }}>
              <div style={{ fontSize: 12, color: "#475569", fontWeight: 700, letterSpacing: 2, textTransform: "uppercase", marginBottom: 12 }}>Legal</div>
              <div style={{ fontSize: 13, color: "#334155" }}>For authorized security testing only.</div>
            </div>
          </div>
        </div>
        <div style={{ borderTop: `1px solid ${C.border}`, paddingTop: 24, display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
          <span style={{ fontSize: 13, color: "#334155" }}>© 2026 VulnusLab. All rights reserved.</span>
          <span style={{ fontSize: 12, color: "#1e293b" }}>Built with Kali Linux • Powered by FastAPI & React</span>
        </div>
      </div>
    </footer>
  );
}

// ── APP ──────────────────────────────────────────────────────────
export default function App() {
  return (
    <div style={{ background: C.bg, minHeight: "100vh", overflowX: "hidden" }}>
      <Nav />
      <Hero />
      <TrustBar />
      <Stats />
      <Demo />
      <Features />
      <Scanners />
      <HowItWorks />
      <Pricing />
      <Testimonials />
      <FAQ />
      <CTABanner />
      <Contact />
      <Footer />
    </div>
  );
}

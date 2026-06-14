"""Ops Console — the founder's in-app mission control (superadmin only).

Two routes:
  GET /api/admin/ops            -> aggregate JSON (customers, plans, scan
                                   activity, estimated MRR, system health).
                                   Gated by verify_admin (admin/superadmin).
  GET /api/admin/ops/dashboard  -> a self-contained HTML page (no build step)
                                   that reads the JWT from localStorage
                                   ('cyberToken'), calls /api/admin/ops and
                                   renders it. Open it at
                                   https://app.vulnuslab.com/api/admin/ops/dashboard

It lives in the SAME app/deploy/auth as everything else (not a separate site),
and reads the data already produced by the auth + quota + consent modules:
  - users           (tools/auth/_db.py)        -> plans, subscriptions, signups
  - consent_audit   (tools/consent/consent_log)-> per-scan activity log
  - tools/_quota                                -> caps, prices, effective plan
"""
from __future__ import annotations

import datetime
import os
import shutil
import time

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse

from tools._shared import verify_admin
from tools.auth._db import get_db, DB_PATH
from tools import _quota
try:
    from tools._audit import recent as audit_recent
except Exception:  # pragma: no cover
    def audit_recent(n=15):
        return []

router = APIRouter()

_CONSENT_DB = os.environ.get("CONSENT_DB_PATH", "/app/data/consent_audit.db")


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _iso(dt):
    return dt.isoformat()


def _users_block(now):
    """Aggregate the users table + per-customer rows."""
    by_plan, by_status, by_role = {}, {}, {}
    signups_7d = signups_30d = 0
    active_paid = expiring_7d = expired = 0
    mrr = 0
    paying = 0
    customers = []
    at_risk = []
    d7 = _iso(now - datetime.timedelta(days=7))
    d30 = _iso(now - datetime.timedelta(days=30))
    soon = now + datetime.timedelta(days=7)
    period = now.strftime("%Y-%m")
    with get_db() as con:
        rows = con.execute(
            "SELECT username, email, role, plan, status, created_at, "
            "subscription_expires_at, scans_used, usage_period "
            "FROM users ORDER BY created_at DESC"
        ).fetchall()
    for r in rows:
        plan = (r["plan"] or "free")
        status = (r["status"] or "active")
        role = (r["role"] or "user")
        by_plan[plan] = by_plan.get(plan, 0) + 1
        by_status[status] = by_status.get(status, 0) + 1
        by_role[role] = by_role.get(role, 0) + 1
        created = r["created_at"] or ""
        if created >= d7:
            signups_7d += 1
        if created >= d30:
            signups_30d += 1
        eff = _quota._effective_plan(plan, r["subscription_expires_at"], now)
        cap = _quota.PLAN_CAPS.get(eff)
        exp = _quota._parse_ts(r["subscription_expires_at"])
        if eff in ("pro", "team", "enterprise"):
            active_paid += 1
            paying += 1
            mrr += _quota.PLAN_PRICE.get(eff, 0)
            if exp is not None and now < exp <= soon:
                expiring_7d += 1
        if exp is not None and exp < now:
            expired += 1
        used = (r["scans_used"] or 0) if (r["usage_period"] or "") == period else 0
        if cap is not None and used >= max(1, int(cap * 0.8)):
            at_risk.append({"username": r["username"], "effective_plan": eff, "used": used, "cap": cap})
        customers.append({
            "username": r["username"], "email": r["email"], "plan": plan,
            "effective_plan": eff, "status": status, "role": role,
            "scans_used": used, "cap": cap,
            "subscription_expires_at": r["subscription_expires_at"],
            "created_at": created,
        })
    nonadmin = len(rows) - by_role.get("admin", 0) - by_role.get("superadmin", 0)
    conversion_pct = round(100 * paying / nonadmin) if nonadmin else 0
    return {
        "users": {
            "total": len(rows), "by_plan": by_plan, "by_status": by_status,
            "by_role": by_role, "signups_7d": signups_7d, "signups_30d": signups_30d,
            "conversion_pct": conversion_pct,
            "subs": {"active_paid": active_paid, "expiring_7d": expiring_7d, "expired": expired},
        },
        "revenue": {"estimated_mrr": mrr, "paying_customers": paying, "currency": "USD",
                    "note": "estimate from list prices; enterprise is custom-quoted (counted as 0)"},
        "at_risk": at_risk,
        "customers": customers,
    }


def _scans_block(now):
    """Scan activity from the consent_audit log (one row per scan)."""
    import sqlite3
    out = {"this_month": 0, "today": 0, "last_7d": 0, "total": 0,
           "per_day_14d": [], "by_module_top": [], "recent": []}
    month = now.strftime("%Y-%m")
    today = now.strftime("%Y-%m-%d")
    d7 = _iso(now - datetime.timedelta(days=7))
    try:
        con = sqlite3.connect(f"file:{_CONSENT_DB}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
    except Exception:
        return out
    try:
        q = con.execute
        out["total"] = q("SELECT COUNT(*) c FROM consent_log").fetchone()["c"]
        out["this_month"] = q("SELECT COUNT(*) c FROM consent_log WHERE substr(ts,1,7)=?", (month,)).fetchone()["c"]
        out["today"] = q("SELECT COUNT(*) c FROM consent_log WHERE substr(ts,1,10)=?", (today,)).fetchone()["c"]
        out["last_7d"] = q("SELECT COUNT(*) c FROM consent_log WHERE ts>=?", (d7,)).fetchone()["c"]
        # 14-day daily counts, zero-filled
        raw = {row["d"]: row["c"] for row in q(
            "SELECT substr(ts,1,10) d, COUNT(*) c FROM consent_log WHERE ts>=? GROUP BY d",
            (_iso(now - datetime.timedelta(days=13)),)).fetchall()}
        for i in range(13, -1, -1):
            day = (now - datetime.timedelta(days=i)).strftime("%Y-%m-%d")
            out["per_day_14d"].append({"date": day, "count": raw.get(day, 0)})
        out["by_module_top"] = [{"module": r["module"], "count": r["c"]} for r in q(
            "SELECT module, COUNT(*) c FROM consent_log GROUP BY module ORDER BY c DESC LIMIT 8").fetchall()]
        out["recent"] = [{"ts": r["ts"], "user": r["user_email"], "target": r["target"], "module": r["module"]}
                         for r in q("SELECT ts, user_email, target, module FROM consent_log "
                                    "ORDER BY ts DESC LIMIT 25").fetchall()]
    except Exception:
        pass
    finally:
        try:
            con.close()
        except Exception:
            pass
    return out


def _system_block(now):
    sysd = {"server_time": _iso(now)}
    try:
        du = shutil.disk_usage(os.path.dirname(DB_PATH) or "/")
        sysd["disk"] = {"used_gb": round(du.used / 1e9, 1), "total_gb": round(du.total / 1e9, 1),
                        "pct": round(100 * du.used / du.total) if du.total else 0}
    except Exception:
        sysd["disk"] = None
    try:
        info = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, _, v = line.partition(":")
                info[k] = int(v.strip().split()[0])  # kB
        total = info.get("MemTotal", 0)
        avail = info.get("MemAvailable", info.get("MemFree", 0))
        used = total - avail
        sysd["memory"] = {"used_mb": round(used / 1024), "total_mb": round(total / 1024),
                          "pct": round(100 * used / total) if total else 0}
    except Exception:
        sysd["memory"] = None
    for label, path in (("users_db_mb", DB_PATH), ("consent_db_mb", _CONSENT_DB)):
        try:
            sysd[label] = round(os.path.getsize(path) / 1e6, 2)
        except Exception:
            sysd[label] = 0
    sysd["last_backup"] = None
    for d in ("/backups", "/root/backups"):
        try:
            files = [os.path.join(d, f) for f in os.listdir(d)]
            files = [f for f in files if os.path.isfile(f)]
            if files:
                newest = max(files, key=os.path.getmtime)
                sysd["last_backup"] = {"name": os.path.basename(newest),
                                       "age_hours": round((time.time() - os.path.getmtime(newest)) / 3600, 1)}
                break
        except Exception:
            pass
    return sysd


@router.get("/api/admin/ops")
async def ops_overview(_=Depends(verify_admin)):
    now = _now()
    data = {"generated_at": _iso(now)}
    data.update(_users_block(now))
    data["scans"] = _scans_block(now)
    data["system"] = _system_block(now)
    data["audit"] = audit_recent(15)
    data["plan_caps"] = _quota.PLAN_CAPS
    return data


def _user_detail(username, now):
    """Full per-user drill-down: account, plan/price, quota, what they scan,
    scan history, and their audit events."""
    import sqlite3
    with get_db() as con:
        row = con.execute(
            "SELECT username, email, role, plan, status, created_at, updated_at, "
            "subscription_expires_at, scans_used, usage_period "
            "FROM users WHERE username=? OR email=? LIMIT 1", (username, username)).fetchone()
    if not row:
        return None
    ident = row["username"]
    email = row["email"]
    plan = row["plan"] or "free"
    eff = _quota._effective_plan(plan, row["subscription_expires_at"], now)
    cap = _quota.PLAN_CAPS.get(eff)
    period = now.strftime("%Y-%m")
    used = (row["scans_used"] or 0) if (row["usage_period"] or "") == period else 0
    # keys this user's scans were logged under (sub=username, sometimes email)
    keys = tuple(x for x in (ident, email) if x) or (ident,)
    ph = ",".join("?" * len(keys))
    history, by_module = [], []
    try:
        c = sqlite3.connect(f"file:{_CONSENT_DB}?mode=ro", uri=True)
        c.row_factory = sqlite3.Row
        history = [dict(r) for r in c.execute(
            f"SELECT ts, target, module FROM consent_log WHERE user_email IN ({ph}) "
            f"ORDER BY ts DESC LIMIT 200", keys).fetchall()]
        by_module = [{"module": r["module"], "count": r["c"]} for r in c.execute(
            f"SELECT module, COUNT(*) c FROM consent_log WHERE user_email IN ({ph}) "
            f"GROUP BY module ORDER BY c DESC", keys).fetchall()]
        c.close()
    except Exception:
        pass
    audit = []
    try:
        adb = os.environ.get("AUDIT_DB_PATH", "/app/data/audit_log.db")
        c = sqlite3.connect(f"file:{adb}?mode=ro", uri=True)
        c.row_factory = sqlite3.Row
        audit = [dict(r) for r in c.execute(
            "SELECT ts, action, detail, client_ip FROM audit_log WHERE actor=? "
            "ORDER BY id DESC LIMIT 50", (ident,)).fetchall()]
        c.close()
    except Exception:
        pass
    # à-la-carte module entitlements (best-effort; system may not be present)
    modules_owned = []
    try:
        from tools._payments import entitlements as _ent
        for fn in ("list_modules", "user_modules", "list_user_modules"):
            f = getattr(_ent, fn, None)
            if callable(f):
                modules_owned = list(f(ident) or [])
                break
    except Exception:
        modules_owned = []
    return {
        "account": {k: row[k] for k in row.keys()},
        "effective_plan": eff, "cap": cap, "scans_used": used,
        "remaining": (None if cap is None else max(0, cap - used)),
        "monthly_price_usd": _quota.PLAN_PRICE.get(eff, 0), "period": period,
        "modules_owned": modules_owned,
        "total_scans": sum(m["count"] for m in by_module),
        "scans_by_module": by_module, "scan_history": history, "audit": audit,
    }


@router.get("/api/admin/ops/user/{username}")
async def ops_user_detail(username: str, _=Depends(verify_admin)):
    d = _user_detail(username, _now())
    if d is None:
        raise HTTPException(404, "user not found")
    return d


@router.get("/api/admin/ops/dashboard", response_class=HTMLResponse)
async def ops_dashboard():
    # Public shell only — it carries no data. It reads the JWT from
    # localStorage and calls the gated /api/admin/ops with it.
    return HTMLResponse(_DASHBOARD_HTML)


_DASHBOARD_HTML = r"""<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VulnusLab — Ops Console</title>
<style>
 :root{--bg:#0a0e17;--card:#0d1320;--line:#1c2435;--txt:#d8deea;--mut:#8a94a8;--acc:#3b9eff;--cy:#06b6d4;--ok:#1f9d57;--warn:#d98c1f;--bad:#e02347}
 *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}
 header{display:flex;align-items:center;justify-content:space-between;padding:16px 22px;border-bottom:1px solid var(--line)}
 h1{font-size:16px;margin:0;font-weight:700}h1 span{color:var(--acc)}
 .mut{color:var(--mut)}.wrap{padding:20px 22px;max-width:1280px;margin:0 auto}
 .grid{display:grid;gap:14px}.kpis{grid-template-columns:repeat(auto-fit,minmax(150px,1fr))}
 .card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}
 .kpi .v{font-size:26px;font-weight:800}.kpi .l{color:var(--mut);font-size:12px;margin-top:2px}
 .sec{margin-top:22px}.sec h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);margin:0 0 10px}
 table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line)}
 th{color:var(--mut);font-weight:600;font-size:11px;text-transform:uppercase}
 td.r,th.r{text-align:right}.tag{display:inline-block;padding:1px 8px;border-radius:20px;font-size:11px;font-weight:700;border:1px solid var(--line)}
 .bars{display:flex;align-items:flex-end;gap:4px;height:90px}.bar{flex:1;background:linear-gradient(180deg,var(--acc),var(--cy));border-radius:3px 3px 0 0;min-height:2px}
 .meter{height:8px;background:#0a0e17;border:1px solid var(--line);border-radius:6px;overflow:hidden}.meter>i{display:block;height:100%;background:var(--acc)}
 .row{display:flex;gap:14px;flex-wrap:wrap}.row>*{flex:1;min-width:240px}
 button{background:var(--acc);border:0;border-radius:7px;color:#fff;font-weight:700;padding:7px 14px;cursor:pointer}
 .err{background:#2a0e16;border:1px solid var(--bad);color:#ffd0d8;padding:14px;border-radius:10px;margin:20px 0}
 input{background:#0a0e17;border:1px solid var(--line);border-radius:6px;color:var(--txt);padding:8px 11px;width:360px;max-width:80vw}
 code{color:var(--cy)}
 .ab{background:#15203a;border:1px solid var(--line);color:var(--txt);border-radius:5px;padding:2px 7px;font-size:11px;cursor:pointer;margin-right:3px}.ab:hover{border-color:var(--acc)}
</style></head><body>
<header><h1>Vulnus<span>Lab</span> · Ops Console</h1>
<div class="mut" id="meta">loading…</div></header>
<div class="wrap" id="root"><p class="mut">Loading…</p></div>
<div id="umodal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.82);z-index:50;overflow:auto;padding:28px"><div id="ubody" style="max-width:1040px;margin:0 auto;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:22px"></div></div>
<script>
const $=(h)=>{const d=document.createElement('div');d.innerHTML=h;return d.firstElementChild;};
const esc=(s)=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const fmtAge=(h)=>h==null?'—':(h<1?Math.round(h*60)+'m':h<48?h.toFixed(1)+'h':Math.round(h/24)+'d')+' ago';
const planTag=(p)=>{const col={free:'#8a94a8',trial:'#3b9eff',pro:'#1f9d57',team:'#06b6d4',enterprise:'#d98c1f',superadmin:'#e02347',admin:'#e02347'}[p]||'#8a94a8';return `<span class="tag" style="color:${col};border-color:${col}">${esc(p)}</span>`;};
function actionBtns(c){const u=(c.username||'').replace(/'/g,'');const st=c.status||'active';return `<button class="ab" onclick="aExtend('${u}')">Extend</button><button class="ab" onclick="aPlan('${u}')">Plan</button><button class="ab" onclick="aStatus('${u}','${st}')">${st==='active'?'Suspend':'Activate'}</button><button class="ab" onclick="aReset('${u}')">Reset</button><button class="ab" onclick="aRole('${u}')">Role</button><button class="ab" onclick="aDelete('${u}')">Delete</button>`;}
async function adminAction(method,path,body){const t=token();if(!t){alert('No token');return;}try{const r=await fetch(path,{method,headers:{Authorization:'Bearer '+t,'Content-Type':'application/json'},body:body?JSON.stringify(body):null});const j=await r.json().catch(()=>({}));if(!r.ok||j.ok===false){alert('Failed: '+(j.detail||j.message||('HTTP '+r.status)));return;}load();}catch(e){alert('Error: '+e.message);}}
function aExtend(u){const d=prompt('Extend by how many days?','30');if(d===null)return;const p=prompt('Plan (trial/pro/team/enterprise):','pro');if(p===null)return;adminAction('POST','/api/admin/users/'+encodeURIComponent(u)+'/extend',{days:parseInt(d,10)||0,plan:p});}
function aPlan(u){const p=prompt('Set plan (trial/pro/team/enterprise/superadmin):','pro');if(p===null)return;adminAction('POST','/api/admin/users/'+encodeURIComponent(u)+'/plan',{plan:p});}
function aStatus(u,st){const a=st==='active'?'suspend':'activate';if(!confirm(a+' '+u+'?'))return;adminAction('POST','/api/admin/users/'+encodeURIComponent(u)+'/'+a);}
function aReset(u){if(!confirm('Reset monthly scan count for '+u+'?'))return;adminAction('POST','/api/admin/users/'+encodeURIComponent(u)+'/reset_quota');}
function aRole(u){const r=prompt('Set role (user / admin / superadmin):','user');if(r===null)return;adminAction('POST','/api/admin/users/'+encodeURIComponent(u)+'/role',{role:r.trim()});}
function aDelete(u){if(!confirm('DELETE account '+u+'? Removes the user and their data. Cannot be undone.'))return;adminAction('DELETE','/api/admin/users/'+encodeURIComponent(u));}
function token(){let t=localStorage.getItem('cyberToken');if(!t){t=sessionStorage.getItem('vl_ops_token');}return t;}
async function load(){
  const t=token();
  if(!t){return render_login();}
  let r;
  try{r=await fetch('/api/admin/ops',{headers:{Authorization:'Bearer '+t}});}catch(e){return showErr('Network error: '+e.message);}
  if(r.status===401||r.status===403){return render_login('Your token is missing/expired or not a superadmin account.');}
  if(!r.ok){return showErr('HTTP '+r.status);}
  render(await r.json());
}
function render_login(msg){
  document.getElementById('root').innerHTML=
   `<div class="err">${msg?esc(msg):'No session token found in this browser.'}</div>
    <p class="mut">Log into the dashboard first (so the token is in localStorage), then reload — or paste a superadmin JWT:</p>
    <input id="tk" placeholder="eyJhbGciOiJI..."> <button onclick="sessionStorage.setItem('vl_ops_token',document.getElementById('tk').value.trim());load()">Use token</button>`;
}
function showErr(m){document.getElementById('root').innerHTML=`<div class="err">${esc(m)}</div>`;}
function render(d){
  const u=d.users,rev=d.revenue,s=d.scans,sy=d.system;
  const kpi=(v,l)=>`<div class="card kpi"><div class="v">${v}</div><div class="l">${l}</div></div>`;
  const maxc=Math.max(1,...s.per_day_14d.map(x=>x.count));
  const bars=s.per_day_14d.map(x=>`<div class="bar" style="height:${Math.round(100*x.count/maxc)}%" title="${x.date}: ${x.count}"></div>`).join('');
  const meter=(lab,m)=>m?`<div style="margin:8px 0"><div class="mut" style="display:flex;justify-content:space-between"><span>${lab}</span><span>${m.pct}%</span></div><div class="meter"><i style="width:${m.pct}%;background:${m.pct>88?'var(--bad)':m.pct>70?'var(--warn)':'var(--acc)'}"></i></div></div>`:'';
  const planRows=Object.entries(u.by_plan).map(([p,n])=>`<tr><td>${planTag(p)}</td><td class="r">${n}</td></tr>`).join('');
  const modRows=s.by_module_top.map(m=>`<tr><td>${esc(m.module)}</td><td class="r">${m.count}</td></tr>`).join('')||'<tr><td class="mut" colspan=2>no scans yet</td></tr>';
  const recRows=s.recent.map(x=>`<tr><td class="mut">${esc((x.ts||'').replace('T',' ').slice(0,16))}</td><td>${esc(x.user||'—')}</td><td>${esc(x.module)}</td><td>${esc(x.target)}</td></tr>`).join('')||'<tr><td class="mut" colspan=4>no scans yet</td></tr>';
  const cust=d.customers.map(c=>`<tr><td><a onclick="openUser('${(c.username||'').replace(/'/g,'')}')" style="color:var(--acc);cursor:pointer;text-decoration:underline">${esc(c.username)}</a></td><td class="mut">${esc(c.email||'')}</td><td>${planTag(c.effective_plan)}${c.effective_plan!==c.plan?' <span class="mut" style="font-size:11px">(was '+esc(c.plan)+')</span>':''}</td><td>${esc(c.status)}</td><td class="r">${c.scans_used}${c.cap!=null?' / '+c.cap:' / ∞'}</td><td class="mut">${c.subscription_expires_at?esc(c.subscription_expires_at.slice(0,10)):'—'}</td><td class="mut">${esc((c.created_at||'').slice(0,10))}</td><td style="white-space:nowrap">${actionBtns(c)}</td></tr>`).join('');
  const atRisk=(d.at_risk||[]).map(x=>`<tr><td>${esc(x.username)}</td><td>${planTag(x.effective_plan)}</td><td class="r">${x.used} / ${x.cap}</td></tr>`).join('')||'<tr><td class="mut" colspan=3>none near quota</td></tr>';
  const aud=(d.audit||[]).map(a=>`<tr><td class="mut">${esc((a.ts||'').replace('T',' ').slice(0,16))}</td><td>${esc(a.action)}</td><td>${esc(a.actor||'')}</td><td class="mut">${esc(a.detail||a.target||'')}</td></tr>`).join('')||'<tr><td class="mut" colspan=4>no events</td></tr>';
  document.getElementById('meta').textContent='updated '+new Date(d.generated_at).toLocaleString();
  document.getElementById('root').innerHTML=`
   <div class="grid kpis">
    ${kpi(u.total,'Customers')}
    ${kpi('$'+rev.estimated_mrr+' <span class="mut" style="font-size:13px">est</span>','MRR ('+rev.paying_customers+' paying)')}
    ${kpi(u.signups_7d+' <span class="mut" style="font-size:13px">/7d</span>','Signups (30d: '+u.signups_30d+')')}
    ${kpi(s.this_month,'Scans this month')}
    ${kpi(s.today,'Scans today')}
    ${kpi(u.subs.expiring_7d,'Subs expiring 7d')}
    ${kpi((u.conversion_pct||0)+'%','Paid conversion')}
   </div>
   <div class="sec"><div class="row">
     <div class="card"><h2 style="margin-top:0">Scans — last 14 days</h2><div class="bars">${bars}</div><div class="mut" style="margin-top:6px">total ${s.total} · 7d ${s.last_7d}</div></div>
     <div class="card"><h2 style="margin-top:0">System health</h2>${meter('Disk',sy.disk)}${meter('Memory',sy.memory)}
       <div class="mut" style="margin-top:8px">users.db ${sy.users_db_mb}MB · consent.db ${sy.consent_db_mb}MB · last backup ${sy.last_backup?esc(sy.last_backup.name)+' ('+fmtAge(sy.last_backup.age_hours)+')':'<span style="color:var(--warn)">none found</span>'}</div></div>
   </div></div>
   <div class="sec"><div class="row">
     <div class="card"><h2 style="margin-top:0">Plans</h2><table>${planRows}</table></div>
     <div class="card"><h2 style="margin-top:0">Top modules</h2><table>${modRows}</table></div>
     <div class="card"><h2 style="margin-top:0">Subscriptions</h2><table>
        <tr><td>Active paid</td><td class="r">${u.subs.active_paid}</td></tr>
        <tr><td>Expiring in 7d</td><td class="r">${u.subs.expiring_7d}</td></tr>
        <tr><td>Expired</td><td class="r">${u.subs.expired}</td></tr></table></div>
   </div></div>
   <div class="sec card"><h2 style="margin-top:0">Recent scans</h2><table><tr><th>When</th><th>User</th><th>Module</th><th>Target</th></tr>${recRows}</table></div>
   <div class="sec"><div class="row">
     <div class="card"><h2 style="margin-top:0">At / near quota</h2><table><tr><th>User</th><th>Plan</th><th class="r">Used</th></tr>${atRisk}</table></div>
     <div class="card"><h2 style="margin-top:0">Audit log</h2><table><tr><th>When</th><th>Action</th><th>Actor</th><th>Detail</th></tr>${aud}</table></div>
   </div></div>
   <div class="sec card"><h2 style="margin-top:0">Customers (${u.total})</h2><table><tr><th>User</th><th>Email</th><th>Plan</th><th>Status</th><th class="r">Scans (mo)</th><th>Sub ends</th><th>Joined</th><th>Actions</th></tr>${cust}</table></div>
   <p class="mut" style="margin-top:20px">Auto-refreshes every 30s · superadmin only</p>`;
}
function ufmt(s){return esc((s||'').replace('T',' ').slice(0,16));}
function closeUser(){document.getElementById('umodal').style.display='none';}
async function openUser(u){
  const t=token(); if(!t){alert('No token');return;}
  const m=document.getElementById('umodal'), b=document.getElementById('ubody');
  b.innerHTML='<p class="mut">Loading '+esc(u)+'...</p>'; m.style.display='block';
  try{
    const r=await fetch('/api/admin/ops/user/'+encodeURIComponent(u),{headers:{Authorization:'Bearer '+t}});
    if(!r.ok){b.innerHTML='<div class="err">HTTP '+r.status+'</div><div style="text-align:right"><button class="ab" onclick="closeUser()">Close</button></div>';return;}
    renderUser(await r.json(), u);
  }catch(e){b.innerHTML='<div class="err">'+esc(e.message)+'</div>';}
}
function renderUser(d,u){
  const a=d.account||{};
  const mods=(d.scans_by_module||[]).map(m=>`<tr><td>${esc(m.module)}</td><td class="r">${m.count}</td></tr>`).join('')||'<tr><td class="mut" colspan=2>no scans</td></tr>';
  const hist=(d.scan_history||[]).map(h=>`<tr><td class="mut">${ufmt(h.ts)}</td><td>${esc(h.module)}</td><td class="mut">${esc(h.target)}</td></tr>`).join('')||'<tr><td class="mut" colspan=3>no scans</td></tr>';
  const aud=(d.audit||[]).map(x=>`<tr><td class="mut">${ufmt(x.ts)}</td><td>${esc(x.action)}</td><td class="mut">${esc(x.detail||'')}</td></tr>`).join('')||'<tr><td class="mut" colspan=3>no events</td></tr>';
  const owned=(d.modules_owned&&d.modules_owned.length)?d.modules_owned.map(esc).join(', '):'(plan-based)';
  document.getElementById('ubody').innerHTML=`
   <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
     <h2 style="margin:0">${esc(a.username||u)} ${planTag(d.effective_plan)}</h2>
     <button class="ab" onclick="closeUser()">Close ✕</button></div>
   <div class="row">
     <div class="card"><h2 style="margin-top:0">Account</h2><table>
       <tr><td class="mut">Email</td><td>${esc(a.email||'-')}</td></tr>
       <tr><td class="mut">Role</td><td>${esc(a.role||'user')}</td></tr>
       <tr><td class="mut">Status</td><td>${esc(a.status||'')}</td></tr>
       <tr><td class="mut">Plan</td><td>${esc(a.plan)} (effective ${esc(d.effective_plan)})</td></tr>
       <tr><td class="mut">Monthly price</td><td>$${d.monthly_price_usd}</td></tr>
       <tr><td class="mut">Scans this month</td><td>${d.scans_used} / ${d.cap==null?'∞':d.cap}</td></tr>
       <tr><td class="mut">Sub ends</td><td>${a.subscription_expires_at?esc(a.subscription_expires_at.slice(0,10)):'-'}</td></tr>
       <tr><td class="mut">Joined</td><td>${esc((a.created_at||'').slice(0,10))}</td></tr>
       <tr><td class="mut">Modules owned</td><td>${owned}</td></tr>
     </table></div>
     <div class="card"><h2 style="margin-top:0">What they scan (${d.total_scans} total)</h2><table><tr><th>Module</th><th class="r">Scans</th></tr>${mods}</table></div>
   </div>
   <div class="sec card"><h2 style="margin-top:0">Scan history (${(d.scan_history||[]).length})</h2><div style="max-height:320px;overflow:auto"><table><tr><th>When</th><th>Module</th><th>Target</th></tr>${hist}</table></div></div>
   <div class="sec card"><h2 style="margin-top:0">Audit events</h2><table><tr><th>When</th><th>Action</th><th>Detail</th></tr>${aud}</table></div>
   <div style="text-align:right;margin-top:14px"><button class="ab" onclick="closeUser()">Close</button></div>`;
}
load();setInterval(load,30000);
</script></body></html>
"""


def register(app):
    app.include_router(router)

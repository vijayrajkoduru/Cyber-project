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

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse

from tools._shared import verify_admin
from tools.auth._db import get_db, DB_PATH
from tools import _quota

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
        customers.append({
            "username": r["username"], "email": r["email"], "plan": plan,
            "effective_plan": eff, "status": status, "role": role,
            "scans_used": used, "cap": cap,
            "subscription_expires_at": r["subscription_expires_at"],
            "created_at": created,
        })
    return {
        "users": {
            "total": len(rows), "by_plan": by_plan, "by_status": by_status,
            "by_role": by_role, "signups_7d": signups_7d, "signups_30d": signups_30d,
            "subs": {"active_paid": active_paid, "expiring_7d": expiring_7d, "expired": expired},
        },
        "revenue": {"estimated_mrr": mrr, "paying_customers": paying, "currency": "USD",
                    "note": "estimate from list prices; enterprise is custom-quoted (counted as 0)"},
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
    data["plan_caps"] = _quota.PLAN_CAPS
    return data


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
</style></head><body>
<header><h1>Vulnus<span>Lab</span> · Ops Console</h1>
<div class="mut" id="meta">loading…</div></header>
<div class="wrap" id="root"><p class="mut">Loading…</p></div>
<script>
const $=(h)=>{const d=document.createElement('div');d.innerHTML=h;return d.firstElementChild;};
const esc=(s)=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const fmtAge=(h)=>h==null?'—':(h<1?Math.round(h*60)+'m':h<48?h.toFixed(1)+'h':Math.round(h/24)+'d')+' ago';
const planTag=(p)=>{const col={free:'#8a94a8',trial:'#3b9eff',pro:'#1f9d57',team:'#06b6d4',enterprise:'#d98c1f',superadmin:'#e02347',admin:'#e02347'}[p]||'#8a94a8';return `<span class="tag" style="color:${col};border-color:${col}">${esc(p)}</span>`;};
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
  const cust=d.customers.map(c=>`<tr><td>${esc(c.username)}</td><td class="mut">${esc(c.email||'')}</td><td>${planTag(c.effective_plan)}${c.effective_plan!==c.plan?' <span class="mut" style="font-size:11px">(was '+esc(c.plan)+')</span>':''}</td><td>${esc(c.status)}</td><td class="r">${c.scans_used}${c.cap!=null?' / '+c.cap:' / ∞'}</td><td class="mut">${c.subscription_expires_at?esc(c.subscription_expires_at.slice(0,10)):'—'}</td><td class="mut">${esc((c.created_at||'').slice(0,10))}</td></tr>`).join('');
  document.getElementById('meta').textContent='updated '+new Date(d.generated_at).toLocaleString();
  document.getElementById('root').innerHTML=`
   <div class="grid kpis">
    ${kpi(u.total,'Customers')}
    ${kpi('$'+rev.estimated_mrr+' <span class="mut" style="font-size:13px">est</span>','MRR ('+rev.paying_customers+' paying)')}
    ${kpi(u.signups_7d+' <span class="mut" style="font-size:13px">/7d</span>','Signups (30d: '+u.signups_30d+')')}
    ${kpi(s.this_month,'Scans this month')}
    ${kpi(s.today,'Scans today')}
    ${kpi(u.subs.expiring_7d,'Subs expiring 7d')}
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
   <div class="sec card"><h2 style="margin-top:0">Customers (${u.total})</h2><table><tr><th>User</th><th>Email</th><th>Plan</th><th>Status</th><th class="r">Scans (mo)</th><th>Sub ends</th><th>Joined</th></tr>${cust}</table></div>
   <p class="mut" style="margin-top:20px">Auto-refreshes every 30s · superadmin only</p>`;
}
load();setInterval(load,30000);
</script></body></html>
"""


def register(app):
    app.include_router(router)

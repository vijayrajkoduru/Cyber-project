// Enterprise "Account & Security" settings — API keys, MFA/2FA, Organizations.
// Self-contained; receives the App's authed `api(path,method,body,token)` helper
// and `token` as props so it shares the exact auth/fetch convention.
import React, { useState, useEffect, useCallback } from "react";

const C = {
  wrap:   { padding: 24, color: "#e2e8f0", maxWidth: 920 },
  h1:     { fontSize: 20, fontWeight: 700, color: "#f1f5f9", marginBottom: 4 },
  sub:    { fontSize: 12, color: "#94a3b8", marginBottom: 18 },
  tabs:   { display: "flex", gap: 8, marginBottom: 18, borderBottom: "1px solid #1e293b" },
  tab:    (on) => ({ padding: "8px 14px", cursor: "pointer", fontSize: 13, fontWeight: 600,
            color: on ? "#22d3ee" : "#94a3b8", borderBottom: on ? "2px solid #22d3ee" : "2px solid transparent" }),
  card:   { background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8, padding: 16, marginBottom: 14 },
  btn:    { background: "#0891b2", border: "none", borderRadius: 6, padding: "8px 14px", color: "#fff",
            fontSize: 13, fontWeight: 600, cursor: "pointer" },
  btnGhost:{ background: "#1e293b", border: "1px solid #334155", borderRadius: 6, padding: "6px 12px",
            color: "#e2e8f0", fontSize: 12, cursor: "pointer" },
  btnDanger:{ background: "none", border: "1px solid #7f1d1d", borderRadius: 6, padding: "5px 10px",
            color: "#ef4444", fontSize: 12, cursor: "pointer" },
  input:  { background: "#1e293b", border: "1px solid #334155", borderRadius: 6, padding: "8px 10px",
            color: "#e2e8f0", fontSize: 13, outline: "none" },
  row:    { display: "flex", alignItems: "center", gap: 10, padding: "8px 0", borderBottom: "1px solid #1e293b" },
  mono:   { fontFamily: "monospace", fontSize: 12, color: "#fcd34d", wordBreak: "break-all" },
  err:    { color: "#ef4444", fontSize: 12, margin: "8px 0" },
  ok:     { color: "#34d399", fontSize: 12, margin: "8px 0" },
  pill:   (r) => ({ fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 10,
            background: r === "owner" ? "#7c2d12" : r === "admin" ? "#1e3a8a" : "#334155", color: "#e2e8f0" }),
};

export default function EnterpriseSettings({ api, token, role }) {
  const [tab, setTab] = useState("keys");
  const isAdmin = role === "admin" || role === "superadmin";
  return (
    <div style={C.wrap}>
      <div style={C.h1}>Account &amp; Security</div>
      <div style={C.sub}>API keys, two-factor authentication, and your organizations.</div>
      <div style={C.tabs}>
        <div style={C.tab(tab === "keys")} onClick={() => setTab("keys")}>API Keys</div>
        <div style={C.tab(tab === "mfa")} onClick={() => setTab("mfa")}>Two-Factor (MFA)</div>
        <div style={C.tab(tab === "orgs")} onClick={() => setTab("orgs")}>Organizations</div>
        {isAdmin && <div style={C.tab(tab === "audit")} onClick={() => setTab("audit")}>Audit Log</div>}
      </div>
      {tab === "keys" && <ApiKeys api={api} token={token} />}
      {tab === "mfa" && <Mfa api={api} token={token} />}
      {tab === "orgs" && <Orgs api={api} token={token} />}
      {tab === "audit" && isAdmin && <AuditLog api={api} token={token} />}
    </div>
  );
}

// ── Audit Log (admin) ───────────────────────────────────────────────
function AuditLog({ api, token }) {
  const [data, setData] = useState({ items: [], total: 0, offset: 0, limit: 50 });
  const [err, setErr] = useState("");
  const load = useCallback(async (offset = 0) => {
    setErr("");
    try { setData(await api(`/api/audit/log?limit=50&offset=${offset}`, "GET", null, token)); }
    catch (e) { setErr(e.message); }
  }, [api, token]);
  useEffect(() => { load(0); }, [load]);

  return (
    <div style={C.card}>
      {err && <div style={C.err}>{err}</div>}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
        <div style={C.sub}>{data.total} events</div>
        <div style={{ display: "flex", gap: 6 }}>
          <button style={C.btnGhost} disabled={data.offset === 0}
                  onClick={() => load(Math.max(0, data.offset - data.limit))}>Prev</button>
          <button style={C.btnGhost} disabled={data.offset + data.limit >= data.total}
                  onClick={() => load(data.offset + data.limit)}>Next</button>
        </div>
      </div>
      {(data.items || []).map((r) => (
        <div key={r.id} style={C.row}>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 13 }}>
              <span style={{ fontWeight: 600 }}>{r.action}</span>
              {r.status && r.status !== "ok" && <span style={{ color: "#f59e0b", marginLeft: 8 }}>{r.status}</span>}
            </div>
            <div style={C.sub}>{r.actor_name || r.actor_id || "—"} · {r.ip || "—"}
              {r.target ? ` · ${r.target}` : ""}{r.detail ? ` · ${r.detail}` : ""}</div>
          </div>
          <div style={{ ...C.sub, whiteSpace: "nowrap" }}>{String(r.ts).replace("T", " ").slice(0, 19)}</div>
        </div>
      ))}
      {(data.items || []).length === 0 && <div style={C.sub}>No events.</div>}
    </div>
  );
}

// ── API Keys ────────────────────────────────────────────────────────
function ApiKeys({ api, token }) {
  const [keys, setKeys] = useState([]);
  const [name, setName] = useState("");
  const [secret, setSecret] = useState("");
  const [err, setErr] = useState("");

  const load = useCallback(async () => {
    try { setKeys((await api("/api/auth/api-keys", "GET", null, token)).keys || []); }
    catch (e) { setErr(e.message); }
  }, [api, token]);
  useEffect(() => { load(); }, [load]);

  const create = async () => {
    setErr(""); setSecret("");
    try {
      const r = await api("/api/auth/api-keys", "POST", { name: name || "api-key" }, token);
      setSecret(r.secret); setName(""); load();
    } catch (e) { setErr(e.message); }
  };
  const revoke = async (id) => {
    if (!window.confirm("Revoke this API key? Anything using it will stop working.")) return;
    try { await api(`/api/auth/api-keys/${id}`, "DELETE", null, token); load(); }
    catch (e) { setErr(e.message); }
  };

  return (
    <div>
      {err && <div style={C.err}>{err}</div>}
      <div style={C.card}>
        <div style={{ display: "flex", gap: 8 }}>
          <input style={{ ...C.input, flex: 1 }} placeholder="Key name (e.g. ci-pipeline)"
                 value={name} onChange={(e) => setName(e.target.value)} />
          <button style={C.btn} onClick={create}>Create key</button>
        </div>
        {secret && (
          <div style={{ marginTop: 12 }}>
            <div style={C.ok}>Copy this now — it will not be shown again:</div>
            <div style={C.mono}>{secret}</div>
          </div>
        )}
      </div>
      <div style={C.card}>
        {keys.length === 0 && <div style={C.sub}>No API keys yet.</div>}
        {keys.map((k) => (
          <div key={k.id} style={C.row}>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 13, fontWeight: 600 }}>{k.name}</div>
              <div style={C.sub}>vlk_{k.prefix}… · created {String(k.created_at).slice(0, 10)}
                {k.revoked ? " · revoked" : ""}</div>
            </div>
            {!k.revoked && <button style={C.btnDanger} onClick={() => revoke(k.id)}>Revoke</button>}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── MFA / 2FA ───────────────────────────────────────────────────────
function Mfa({ api, token }) {
  const [enabled, setEnabled] = useState(null);
  const [enroll, setEnroll] = useState(null);   // {secret, otpauth_uri}
  const [code, setCode] = useState("");
  const [err, setErr] = useState(""); const [msg, setMsg] = useState("");

  const load = useCallback(async () => {
    try { setEnabled((await api("/api/auth/mfa/status", "GET", null, token)).enabled); }
    catch (e) { setErr(e.message); }
  }, [api, token]);
  useEffect(() => { load(); }, [load]);

  const begin = async () => {
    setErr(""); setMsg("");
    try { setEnroll(await api("/api/auth/mfa/enroll", "POST", {}, token)); }
    catch (e) { setErr(e.message); }
  };
  const verify = async () => {
    setErr("");
    try { await api("/api/auth/mfa/verify", "POST", { code }, token);
      setMsg("MFA enabled."); setEnroll(null); setCode(""); load(); }
    catch (e) { setErr(e.message); }
  };
  const disable = async () => {
    setErr("");
    try { await api("/api/auth/mfa/disable", "POST", { code }, token);
      setMsg("MFA disabled."); setCode(""); load(); }
    catch (e) { setErr(e.message); }
  };

  return (
    <div style={C.card}>
      {err && <div style={C.err}>{err}</div>}
      {msg && <div style={C.ok}>{msg}</div>}
      <div style={{ fontSize: 14, marginBottom: 10 }}>
        Status: {enabled === null ? "…" : enabled
          ? <span style={{ color: "#34d399", fontWeight: 700 }}>Enabled</span>
          : <span style={{ color: "#f59e0b", fontWeight: 700 }}>Disabled</span>}
      </div>
      {!enabled && !enroll && <button style={C.btn} onClick={begin}>Set up two-factor</button>}
      {!enabled && enroll && (
        <div>
          <div style={C.sub}>Add this secret to your authenticator app (Google Authenticator, Authy, 1Password):</div>
          <div style={C.mono}>{enroll.secret}</div>
          <div style={{ ...C.sub, marginTop: 6 }}>otpauth URI (for QR generation):</div>
          <div style={C.mono}>{enroll.otpauth_uri}</div>
          <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
            <input style={C.input} placeholder="6-digit code" value={code}
                   onChange={(e) => setCode(e.target.value)} />
            <button style={C.btn} onClick={verify}>Verify &amp; enable</button>
          </div>
        </div>
      )}
      {enabled && (
        <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
          <input style={C.input} placeholder="6-digit code to disable" value={code}
                 onChange={(e) => setCode(e.target.value)} />
          <button style={C.btnDanger} onClick={disable}>Disable MFA</button>
        </div>
      )}
    </div>
  );
}

// ── Organizations ───────────────────────────────────────────────────
function Orgs({ api, token }) {
  const [orgs, setOrgs] = useState([]);
  const [sel, setSel] = useState(null);
  const [members, setMembers] = useState([]);
  const [name, setName] = useState("");
  const [email, setEmail] = useState(""); const [role, setRole] = useState("member");
  const [err, setErr] = useState("");

  const loadOrgs = useCallback(async () => {
    try { setOrgs((await api("/api/orgs", "GET", null, token)).orgs || []); }
    catch (e) { setErr(e.message); }
  }, [api, token]);
  useEffect(() => { loadOrgs(); }, [loadOrgs]);

  const loadMembers = async (org) => {
    setSel(org); setErr("");
    try { setMembers((await api(`/api/orgs/${org.id}/members`, "GET", null, token)).members || []); }
    catch (e) { setErr(e.message); }
  };
  const createOrg = async () => {
    setErr("");
    try { await api("/api/orgs", "POST", { name }, token); setName(""); loadOrgs(); }
    catch (e) { setErr(e.message); }
  };
  const addMember = async () => {
    setErr("");
    try { await api(`/api/orgs/${sel.id}/members`, "POST", { email, role }, token);
      setEmail(""); loadMembers(sel); }
    catch (e) { setErr(e.message); }
  };
  const changeRole = async (uid, r) => {
    try { await api(`/api/orgs/${sel.id}/members/${uid}`, "PATCH", { role: r }, token); loadMembers(sel); }
    catch (e) { setErr(e.message); }
  };
  const removeMember = async (uid) => {
    if (!window.confirm("Remove this member?")) return;
    try { await api(`/api/orgs/${sel.id}/members/${uid}`, "DELETE", null, token); loadMembers(sel); }
    catch (e) { setErr(e.message); }
  };

  return (
    <div>
      {err && <div style={C.err}>{err}</div>}
      <div style={C.card}>
        <div style={{ display: "flex", gap: 8 }}>
          <input style={{ ...C.input, flex: 1 }} placeholder="New organization name"
                 value={name} onChange={(e) => setName(e.target.value)} />
          <button style={C.btn} onClick={createOrg}>Create org</button>
        </div>
      </div>
      <div style={C.card}>
        {orgs.length === 0 && <div style={C.sub}>You don't belong to any organization yet.</div>}
        {orgs.map((o) => (
          <div key={o.id} style={C.row}>
            <div style={{ flex: 1 }}>{o.name}</div>
            <span style={C.pill(o.role)}>{o.role}</span>
            <button style={C.btnGhost} onClick={() => loadMembers(o)}>Manage</button>
          </div>
        ))}
      </div>
      {sel && (
        <div style={C.card}>
          <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 10 }}>Members — {sel.name}</div>
          <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
            <input style={{ ...C.input, flex: 1 }} placeholder="invite by email"
                   value={email} onChange={(e) => setEmail(e.target.value)} />
            <select style={C.input} value={role} onChange={(e) => setRole(e.target.value)}>
              <option value="member">member</option>
              <option value="admin">admin</option>
            </select>
            <button style={C.btn} onClick={addMember}>Add</button>
          </div>
          {members.map((m) => (
            <div key={m.user_id} style={C.row}>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 13 }}>{m.username}</div>
                <div style={C.sub}>{m.email}</div>
              </div>
              {m.role === "owner"
                ? <span style={C.pill("owner")}>owner</span>
                : (
                  <>
                    <select style={{ ...C.input, padding: "4px 6px" }} value={m.role}
                            onChange={(e) => changeRole(m.user_id, e.target.value)}>
                      <option value="member">member</option>
                      <option value="admin">admin</option>
                    </select>
                    <button style={C.btnDanger} onClick={() => removeMember(m.user_id)}>Remove</button>
                  </>
                )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

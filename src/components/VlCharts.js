// ENTERPRISE-GRAPHICS-V1 — shared SVG chart components for VulnusLab.
// Plain SVG + CSS (no chart library). Colours come from the theme variables
// in src/theme.css, so every chart follows the Light/Dark toggle.
import React, { useEffect, useState } from "react";

export const SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
export const SEV_COLOR = { CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#eab308", LOW: "#3b82f6", INFO: "#6b7280" };
const SEV_LABEL = { CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low", INFO: "Info" };

export const emptySev = () => ({ CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 });

/** Count findings by severity. Anything that isn't C/H/M/L counts as INFO. */
export function sevFromFindings(list, into) {
  const c = into || emptySev();
  (list || []).forEach(f => {
    const s = String((f && f.severity) || "INFO").toUpperCase();
    if (s === "POSITIVE" || s === "PASS" || s === "SECURE") return;   // good news, not a finding
    c[c[s] !== undefined ? s : "INFO"]++;
  });
  return c;
}

/** Findings array of one phase/tool result, whatever shape the tool returned. */
export function findingsOf(res) {
  if (!res || typeof res !== "object") return [];
  if (Array.isArray(res.findings)) return res.findings;
  if (res.data && Array.isArray(res.data.findings)) return res.data.findings;
  return [];
}

export function sevOfResult(res) {
  const c = sevFromFindings(findingsOf(res));
  // sqlmap / xss report a boolean instead of findings
  if (res && res.vulnerable && !findingsOf(res).length && (res.tool === "sqlmap" || res.tool === "xss")) c.CRITICAL++;
  return c;
}

export const sevTotal = (c, withInfo) => SEVS.reduce((n, s) => n + (withInfo || s !== "INFO" ? (c[s] || 0) : 0), 0);
export const addSev = (a, b) => { const c = { ...a }; SEVS.forEach(s => { c[s] = (c[s] || 0) + (b[s] || 0); }); return c; };

/** Same risk formula as the PDF reports (Webapp/Vuln canon). */
export function riskFromSev(c) {
  const raw = (c.CRITICAL || 0) * 15 + (c.HIGH || 0) * 8 + (c.MEDIUM || 0) * 3 + (c.LOW || 0);
  const maxC = c.CRITICAL > 0 ? 30 : c.HIGH > 0 ? 22 : c.MEDIUM > 0 ? 12 : 5;
  const score = Math.round(Math.min(100, Math.max(5, Math.min(70, raw) + maxC)));
  const label = (score >= 80 && c.CRITICAL > 0) ? "Critical risk" : score >= 60 ? "High risk" : score >= 40 ? "Moderate risk" : score >= 20 ? "Low risk" : "Minimal risk";
  const color = score >= 70 ? "#ef4444" : score >= 40 ? "#eab308" : "#22c55e";
  return { score, label, color };
}

/** Web-app PDF risk formula (CVSS-based, same as the Web App report). */
export function riskFromFindingsCvss(findings) {
  const real = (findings || []).filter(f => f && ["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(String(f.severity).toUpperCase()));
  const lab = (score) => score >= 80 ? "Critical risk" : score >= 60 ? "High risk" : score >= 40 ? "Moderate risk" : score >= 20 ? "Low risk" : "Minimal risk";
  const col = (score) => score >= 70 ? "#ef4444" : score >= 40 ? "#eab308" : "#22c55e";
  if (!real.length) return { score: 5, label: lab(5), color: col(5) };
  const cv = f => { const c = parseFloat(f.cvss || "0"); return c > 0 ? c : ({ CRITICAL: 9.0, HIGH: 7.5, MEDIUM: 5.0, LOW: 3.0 }[String(f.severity).toUpperCase()] || 0); };
  let sum = 0, max = 0;
  real.forEach(f => { const c = cv(f); sum += c; if (c > max) max = c; });
  const score = Math.round(Math.min(100, Math.max(5, Math.min(70, sum * 2.5) + Math.min(30, max * 3))));
  return { score, label: lab(score), color: col(score) };
}

export const fmtDur = (ms) => {
  if (ms == null || isNaN(ms)) return "";
  const s = Math.max(0, Math.round(ms / 1000));
  return s >= 60 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${s}s`;
};

/** true one frame after mount, so CSS transitions animate from zero. */
export function useGrow(dep) {
  const [on, setOn] = useState(false);
  useEffect(() => {
    setOn(false);
    const id = requestAnimationFrame(() => requestAnimationFrame(() => setOn(true)));
    return () => cancelAnimationFrame(id);
  }, [dep]);
  return on;
}

// ───────────────────────── primitives ─────────────────────────

export function Sparkline({ values, color = "var(--vl-accent)", height = 26 }) {
  const v = (values && values.length ? values : [0, 0]);
  const max = Math.max(1, ...v);
  const pts = v.map((y, i) => `${(i / (v.length - 1 || 1)) * 100},${height - 3 - (y / max) * (height - 6)}`).join(" ");
  return (
    <svg className="vlc-spark" viewBox={`0 0 100 ${height}`} preserveAspectRatio="none" width="100%" height={height} aria-hidden="true">
      <polyline points={pts} fill="none" stroke={color} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

export function ColumnChart({ values, labels, height = 120, highlightLast = true }) {
  const grow = useGrow(values && values.join(","));
  const v = values || [];
  const max = Math.max(1, ...v);
  return (
    <div className="vlc-cols" style={{ height }} role="img" aria-label={`Column chart: ${v.join(", ")}`}>
      <div className="vlc-cols-grid"><i /><i /><i /></div>
      {v.map((n, i) => (
        <div key={i} className="vlc-col" title={`${labels ? labels[i] + ": " : ""}${n}`}>
          <span style={{ height: grow ? `${(n / max) * 100}%` : 0, background: highlightLast && i === v.length - 1 ? "var(--vl-accent-t)" : "var(--vl-accent)", transitionDelay: `${i * 25}ms` }} />
        </div>
      ))}
      {labels && <div className="vlc-cols-x"><span>{labels[0]}</span><span>{labels[labels.length - 1]}</span></div>}
    </div>
  );
}

/** Severity donut with total in the middle and an optional legend. */
export function SevDonut({ sev, size = 120, legend = true, caption = "findings", withInfo = true }) {
  const grow = useGrow(JSON.stringify(sev));
  const keys = SEVS.filter(s => withInfo || s !== "INFO");
  const total = keys.reduce((n, s) => n + (sev[s] || 0), 0);
  const r = 15.915, C = 100;
  let acc = 0;
  return (
    <div className="vlc-donut-wrap">
      <svg viewBox="0 0 42 42" width={size} height={size} role="img" aria-label={`${total} ${caption}: ` + keys.map(s => `${SEV_LABEL[s]} ${sev[s] || 0}`).join(", ")}>
        <circle cx="21" cy="21" r={r} fill="none" stroke="var(--vl-1e293b)" strokeWidth="5.5" />
        {total > 0 && keys.map(s => {
          const part = ((sev[s] || 0) / total) * C;
          if (!part) return null;
          const seg = (
            <circle key={s} cx="21" cy="21" r={r} fill="none" stroke={SEV_COLOR[s]} strokeWidth="5.5"
              strokeDasharray={`${grow ? Math.max(0, part - 0.6) : 0} ${C}`} strokeDashoffset={25 - acc}
              style={{ transition: "stroke-dasharray .8s cubic-bezier(.16,1,.3,1)" }} />
          );
          acc += part;
          return seg;
        })}
        <text x="21" y="21.5" textAnchor="middle" className="vlc-donut-n">{total}</text>
        <text x="21" y="27" textAnchor="middle" className="vlc-donut-c">{caption}</text>
      </svg>
      {legend && (
        <div className="vlc-legend">
          {keys.map(s => (
            <span key={s}><i style={{ background: SEV_COLOR[s] }} />{SEV_LABEL[s]} <b>{sev[s] || 0}</b></span>
          ))}
        </div>
      )}
    </div>
  );
}

/** Semicircle 0–100 gauge. */
export function RiskGauge({ score, label, color, sub }) {
  const grow = useGrow(score);
  const has = typeof score === "number";
  const len = 125.66; // half circumference, r = 40
  return (
    <div className="vlc-gauge">
      <svg viewBox="0 0 100 60" width="100%" height="110" role="img" aria-label={has ? `Risk score ${score} of 100, ${label}` : "No risk score yet"}>
        <path d="M10 52 A40 40 0 0 1 90 52" fill="none" stroke="var(--vl-1e293b)" strokeWidth="9" strokeLinecap="round" />
        {has && (
          <path d="M10 52 A40 40 0 0 1 90 52" fill="none" stroke={color} strokeWidth="9" strokeLinecap="round"
            strokeDasharray={`${grow ? (score / 100) * len : 0} ${len}`} style={{ transition: "stroke-dasharray .9s cubic-bezier(.16,1,.3,1)" }} />
        )}
        <text x="50" y="47" textAnchor="middle" className="vlc-gauge-n">{has ? score : "—"}</text>
        <text x="50" y="58" textAnchor="middle" className="vlc-gauge-l" style={{ fill: has ? color : undefined }}>{has ? label : "No scan yet"}</text>
      </svg>
      {sub && <div className="vlc-sub">{sub}</div>}
    </div>
  );
}

/** Circular progress ring. */
export function ProgressRing({ pct, size = 104, label, sub, color = "var(--vl-accent)" }) {
  const p = Math.max(0, Math.min(100, Math.round(pct || 0)));
  const C = 106.81; // r = 17
  return (
    <svg viewBox="0 0 42 42" width={size} height={size} role="img" aria-label={`${p}% complete`}>
      <circle cx="21" cy="21" r="17" fill="none" stroke="var(--vl-1e293b)" strokeWidth="3.6" />
      {p > 0 && <circle cx="21" cy="21" r="17" fill="none" stroke={color} strokeWidth="3.6" strokeLinecap="round"
        strokeDasharray={`${(p / 100) * C} ${C}`} transform="rotate(-90 21 21)" style={{ transition: "stroke-dasharray .6s ease" }} />}
      <text x="21" y={sub ? "22" : "24"} textAnchor="middle" className="vlc-ring-n">{label != null ? label : `${p}%`}</text>
      {sub && <text x="21" y="28" textAnchor="middle" className="vlc-ring-s">{sub}</text>}
    </svg>
  );
}

/** One horizontal stacked bar + legend, e.g. phase status mix. */
export function StackBar({ segments, legend = true, height = 12 }) {
  const grow = useGrow(segments.map(s => s.n).join(","));
  const total = segments.reduce((n, s) => n + (s.n || 0), 0) || 1;
  return (
    <div>
      <div className="vlc-stack" style={{ height }}>
        {segments.filter(s => s.n > 0).map(s => (
          <span key={s.label} title={`${s.label}: ${s.n}`} style={{ width: grow ? `${(s.n / total) * 100}%` : 0, background: s.color }} />
        ))}
      </div>
      {legend && (
        <div className="vlc-legend vlc-legend-row">
          {segments.map(s => <span key={s.label}><i style={{ background: s.color }} />{s.label} <b>{s.n}</b></span>)}
        </div>
      )}
    </div>
  );
}

/** Tiny per-phase severity bar. Empty grey track when there are no findings. */
export function MiniSev({ sev }) {
  const grow = useGrow(JSON.stringify(sev));
  const total = sevTotal(sev, true);
  const title = total ? SEVS.filter(s => sev[s]).map(s => `${SEV_LABEL[s]} ${sev[s]}`).join(" · ") : "No findings";
  return (
    <span className="vlc-mini" title={title} aria-label={title}>
      {total > 0 && SEVS.filter(s => sev[s]).map(s => (
        <i key={s} style={{ width: grow ? `${(sev[s] / total) * 100}%` : 0, background: SEV_COLOR[s] }} />
      ))}
    </span>
  );
}

/** Animated "running" bar for the active phase. */
export const RunningBar = () => <span className="vlc-mini vlc-run" aria-label="Running"><i /></span>;

/** Thin section progress bar: "3 / 5 done". */
export function SectionProgress({ done, total, color = "var(--vl-accent)" }) {
  if (!total) return null;
  return (
    <span className="vlc-secprog">
      <span className="vlc-secprog-t">{done} / {total} done</span>
      <span className="vlc-secprog-b"><i style={{ width: `${(done / total) * 100}%`, background: color }} /></span>
    </span>
  );
}

/** Horizontal bar list (e.g. most vulnerable targets). */
export function HBarList({ items }) {
  const grow = useGrow(items.map(i => i.value).join(","));
  const max = Math.max(1, ...items.map(i => i.value));
  return (
    <div className="vlc-hbars">
      {items.map((it, i) => (
        <div key={i} className="vlc-hbar">
          <div className="vlc-hbar-t"><span className="mono" title={it.label}>{it.label}</span><b>{it.value}</b></div>
          <div className="vlc-hbar-b"><i style={{ width: grow ? `${(it.value / max) * 100}%` : 0, background: it.color || "var(--vl-accent)", transitionDelay: `${i * 60}ms` }} /></div>
        </div>
      ))}
    </div>
  );
}

// ───────────────────────── module overview ─────────────────────────

/**
 * Header block shown on every module page: KPI cards, progress ring,
 * phase-status bar, severity donut and risk gauge.
 * props: total, done, running, current (name), startedAt (ms), finishedAt,
 *        sev {CRITICAL..INFO}, status [{label,n,color}], countLabel
 */
export function ModuleOverview({ total, done, running, current, startedAt, finishedAt, sev, status, hasRun, risk: riskIn }) {
  const [, tick] = useState(0);
  useEffect(() => {
    if (!running) return;
    const id = setInterval(() => tick(n => n + 1), 1000);
    return () => clearInterval(id);
  }, [running]);
  const pct = total ? (done / total) * 100 : 0;
  const elapsed = startedAt ? ((running ? Date.now() : (finishedAt || Date.now())) - startedAt) : null;
  const eta = running && done > 0 && elapsed ? (elapsed / done) * (total - done) : null;
  const findings = sevTotal(sev, false);
  const ch = (sev.CRITICAL || 0) + (sev.HIGH || 0);
  const risk = hasRun && !running && done > 0 ? (riskIn || riskFromSev(sev)) : null;

  return (
    <div className="vlc-overview">
      <div className="vlc-kpis">
        <div className="vlc-kpi"><div className="l">Phases done</div><div className="v">{done}<small> / {total || 0}</small></div></div>
        <div className="vlc-kpi"><div className="l">Findings</div><div className="v">{findings}</div></div>
        <div className="vlc-kpi"><div className="l">Critical + high</div><div className="v" style={{ color: ch ? "#ef4444" : undefined }}>{ch}</div></div>
        <div className="vlc-kpi"><div className="l">{running ? "Elapsed" : "Duration"}</div><div className="v">{elapsed != null ? fmtDur(elapsed) : "—"}</div></div>
      </div>
      <div className="vlc-ov-grid">
        <div className="vlc-card vlc-ov-ring">
          <ProgressRing pct={pct} sub={`${done} / ${total || 0}`} />
          <div className="vlc-ov-now">
            <div className="l">{running ? "Now running" : hasRun ? "Last run" : "Ready"}</div>
            <div className="n">{running ? (current || "Starting…") : hasRun ? (done >= total ? "All phases finished" : `${done} of ${total} phases ran`) : "Pick a target and start"}</div>
            {running && <div className="l">{eta != null ? `~${fmtDur(eta)} left` : "Estimating time…"}</div>}
          </div>
        </div>
        <div className="vlc-card vlc-ov-status">
          <div className="vlc-card-t">Phase status</div>
          <StackBar segments={status} />
        </div>
        <div className="vlc-card vlc-ov-donut">
          <SevDonut sev={sev} size={92} legend={false} caption="findings" withInfo={false} />
          <div className="vlc-legend">
            {SEVS.slice(0, 4).map(s => <span key={s}><i style={{ background: SEV_COLOR[s] }} />{SEV_LABEL[s]} <b>{sev[s] || 0}</b></span>)}
          </div>
        </div>
        <div className="vlc-card vlc-ov-gauge">
          <div className="vlc-card-t">Risk score</div>
          <RiskGauge score={risk ? risk.score : undefined} label={risk && risk.label} color={risk && risk.color} />
        </div>
      </div>
    </div>
  );
}

/** Per-phase right-hand meta: mini severity bar + "3 findings · 12s". */
export function PhaseMeta({ res, running, countText, elapsedMs, sev: sevIn }) {
  if (running) return <span className="vlc-pmeta"><RunningBar /><span className="t">running…</span></span>;
  if (!res) return <span className="vlc-pmeta"><span className="vlc-mini" /><span className="t">—</span></span>;
  const sev = sevIn || sevOfResult(res);
  const n = sevTotal(sev, true);
  const t = countText != null ? countText : `${n} finding${n === 1 ? "" : "s"}`;
  return (
    <span className="vlc-pmeta">
      <MiniSev sev={sev} />
      <span className="t">{t}{elapsedMs ? ` · ${fmtDur(elapsedMs)}` : ""}</span>
    </span>
  );
}

// ───────────────────────── dashboard scan log ─────────────────────────
// Completed scans from every module are recorded here so the dashboard can
// chart them. Stored in this browser only; sign-out wipes it (by design).
const LOG_KEY = "vl_dash_scans";

export function recordScan(entry) {
  try {
    const list = JSON.parse(localStorage.getItem(LOG_KEY) || "[]");
    list.unshift({ ts: Date.now(), ...entry });
    localStorage.setItem(LOG_KEY, JSON.stringify(list.slice(0, 200)));
    window.dispatchEvent(new Event("vl-scan-recorded"));
  } catch (e) { /* storage full or blocked — charts just won't include this scan */ }
}

export function readScans() {
  try { return JSON.parse(localStorage.getItem(LOG_KEY) || "[]") || []; } catch (e) { return []; }
}

#!/usr/bin/env python3
"""Generate the VulnusLab full-project SOP as a bordered, COLOURED, professional PDF.

Output: docs/VulnusLab_SOP.pdf
"""
from __future__ import annotations
import os
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle, PageBreak, ListFlowable, ListItem,
                                HRFlowable)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "VulnusLab_SOP.pdf")
os.makedirs(os.path.dirname(OUT), exist_ok=True)

# ---- palette (colourful but professional) --------------------------------
NAVY = colors.HexColor("#0b1f3a")     # deep brand navy (cover title)
HEADER = colors.HexColor("#11557a")   # section-band blue
HEADER2 = colors.HexColor("#0e6b7d")  # alt teal band
ACCENT = colors.HexColor("#00a8cc")   # bright cyan accent
TEAL = colors.HexColor("#0b6a8a")     # sub-heading teal
INK = colors.HexColor("#1b2336")      # body text
GREY = colors.HexColor("#5a6478")
THEAD = colors.HexColor("#14618a")    # table header blue
ROWALT = colors.HexColor("#eef6fb")   # zebra
LIGHT = colors.HexColor("#e7f2f8")
GREEN = colors.HexColor("#0c8a5a")
AMBER = colors.HexColor("#bf7d10")
RED = colors.HexColor("#b3261e")
GRID = colors.HexColor("#bcd3e2")

DOC_ID, VERSION, DATE, CLASS = "VL-SOP-001", "1.0", "2026-06-13", "CONFIDENTIAL"

ss = getSampleStyleSheet()
def S(name, **kw):
    base = kw.pop("parent", ss["Normal"])
    return ParagraphStyle(name, parent=base, **kw)

st_title = S("vt", fontName="Helvetica-Bold", fontSize=32, textColor=NAVY, leading=36, alignment=TA_CENTER)
st_sub = S("vs", fontName="Helvetica-Bold", fontSize=14, textColor=ACCENT, leading=18, alignment=TA_CENTER)
st_sub2 = S("vs2", fontName="Helvetica", fontSize=10.5, textColor=GREY, leading=15, alignment=TA_CENTER)
st_h1 = S("h1", fontName="Helvetica-Bold", fontSize=15.5, textColor=colors.white, leading=20,
          backColor=HEADER, borderPadding=(7, 9, 7, 9), spaceBefore=15, spaceAfter=2)
st_h2 = S("h2", fontName="Helvetica-Bold", fontSize=12.5, textColor=TEAL, leading=16,
          spaceBefore=11, spaceAfter=5)
st_body = S("bd", fontName="Helvetica", fontSize=10, textColor=INK, leading=15, alignment=TA_JUSTIFY, spaceAfter=7)
st_li = S("li", fontName="Helvetica", fontSize=10, textColor=INK, leading=14)
st_small = S("sm", fontName="Helvetica", fontSize=8.5, textColor=GREY, leading=12)
st_code = S("cd", fontName="Courier", fontSize=8.5, textColor=colors.HexColor("#08323f"),
            backColor=colors.HexColor("#e2f3f8"), borderPadding=(6, 7, 6, 7),
            borderColor=ACCENT, borderWidth=0.6, leading=12, spaceAfter=8)
st_th = S("th", fontName="Helvetica-Bold", fontSize=9, textColor=colors.white, leading=12)
st_td = S("td", fontName="Helvetica", fontSize=9, textColor=INK, leading=12)
st_tdb = S("tdb", fontName="Helvetica-Bold", fontSize=9, textColor=NAVY, leading=12)

story = []
A = story.append

def P(t, s=st_body): A(Paragraph(t, s))
def h1(t):
    A(Paragraph(t, st_h1))
    A(HRFlowable(width="100%", thickness=2, color=ACCENT, spaceBefore=2, spaceAfter=9))
def h2(t): A(Paragraph(t, st_h2))

def _color_gap(t):
    return (t.replace("<b>(gap)</b>", f'<font color="#b3261e"><b>(gap)</b></font>')
             .replace("(gap)", f'<font color="#b3261e"><b>(gap)</b></font>'))

def bullets(items, s=st_li):
    its = [ListItem(Paragraph(_color_gap(i), s), leftIndent=8) for i in items]
    A(ListFlowable(its, bulletType="bullet", start="square", bulletColor=ACCENT,
                   bulletFontSize=6, leftIndent=14, spaceAfter=9))

def status_cell(text):
    low = text.lower()
    if "gap" in low:
        c = RED
    elif "partial" in low or "recommend" in low or "formal" in low:
        c = AMBER
    elif any(k in low for k in ("implement", "aligned", "active", "done", "yes")):
        c = GREEN
    else:
        c = INK
    return Paragraph(f'<font color="{c.hexval()[2:] and ("#"+c.hexval()[4:])}"><b>{text}</b></font>'
                     if False else f'<b>{text}</b>', S("stx", fontName="Helvetica-Bold",
                                                       fontSize=9, textColor=c, leading=12))

def table(data, col_widths, header=True, status_col=None, hdr_color=THEAD):
    rows = []
    for ri, r in enumerate(data):
        row = []
        for ci, c in enumerate(r):
            if hasattr(c, "wrap"):
                row.append(c)
            elif header and ri == 0:
                row.append(Paragraph(str(c), st_th))
            elif status_col is not None and ci == status_col:
                row.append(status_cell(str(c)))
            else:
                row.append(Paragraph(str(c), st_td))
        rows.append(row)
    t = Table(rows, colWidths=col_widths, repeatRows=1 if header else 0)
    style = [("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
             ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
             ("LINEBELOW", (0, 0), (-1, -1), 0.4, GRID),
             ("BOX", (0, 0), (-1, -1), 0.8, HEADER)]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), hdr_color),
                  ("LINEBELOW", (0, 0), (-1, 0), 0.8, hdr_color)]
        for i in range(1, len(rows)):
            if i % 2 == 0:
                style.append(("BACKGROUND", (0, i), (-1, i), ROWALT))
    t.setStyle(TableStyle(style))
    A(t)

# ---- page border + header/footer -----------------------------------------
def decorate(canvas, doc):
    canvas.saveState()
    w, h = A4
    canvas.setStrokeColor(NAVY); canvas.setLineWidth(1.8)
    canvas.rect(12 * mm, 12 * mm, w - 24 * mm, h - 24 * mm)
    canvas.setStrokeColor(ACCENT); canvas.setLineWidth(0.9)
    canvas.rect(14 * mm, 14 * mm, w - 28 * mm, h - 28 * mm)
    # footer
    canvas.setFillColor(ACCENT)
    canvas.rect(14 * mm, 14 * mm, w - 28 * mm, 0.6 * mm, fill=1, stroke=0)
    canvas.setFont("Helvetica", 7.5); canvas.setFillColor(GREY)
    canvas.drawString(16 * mm, 15.6 * mm, f"{DOC_ID}  |  v{VERSION}  |  {DATE}")
    canvas.setFillColor(RED); canvas.drawCentredString(w / 2, 15.6 * mm, CLASS)
    canvas.setFillColor(GREY); canvas.drawRightString(w - 16 * mm, 15.6 * mm, f"Page {doc.page}")
    if doc.page > 1:
        canvas.setFillColor(HEADER)
        canvas.rect(14 * mm, h - 22 * mm, w - 28 * mm, 6.2 * mm, fill=1, stroke=0)
        canvas.setFillColor(ACCENT)
        canvas.rect(14 * mm, h - 22 * mm, 2.4 * mm, 6.2 * mm, fill=1, stroke=0)
        canvas.setFillColor(colors.white); canvas.setFont("Helvetica-Bold", 8)
        canvas.drawString(18 * mm, h - 20.2 * mm, "VulnusLab — Standard Operating Procedure")
        canvas.setFont("Helvetica", 7.5)
        canvas.drawRightString(w - 16 * mm, h - 20.2 * mm, "vulnuslab.com")
    canvas.restoreState()

# ---- cover ---------------------------------------------------------------
A(Spacer(1, 52 * mm))
A(Paragraph("VulnusLab", st_title))
A(Spacer(1, 3 * mm))
A(HRFlowable(width="42%", thickness=2.5, color=ACCENT, spaceBefore=2, spaceAfter=8, hAlign="CENTER"))
A(Paragraph("Standard Operating Procedure (SOP)", st_sub))
A(Paragraph("Vulnerability Assessment &amp; Penetration-Testing Platform", st_sub2))
A(Spacer(1, 28 * mm))
cover = [["Document ID", DOC_ID], ["Version", VERSION], ["Date", DATE],
         ["Owner", "VulnusLab (MSME UDYAM-AP-13-0090768)"],
         ["Classification", CLASS], ["Review cycle", "Quarterly"]]
ct = Table([[Paragraph(k, st_tdb), Paragraph(v, st_td)] for k, v in cover],
           colWidths=[45 * mm, 95 * mm])
ct.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 1.0, HEADER),
                        ("INNERGRID", (0, 0), (-1, -1), 0.4, GRID),
                        ("BACKGROUND", (0, 0), (0, -1), LIGHT),
                        ("LEFTPADDING", (0, 0), (-1, -1), 9),
                        ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]))
A(ct)
A(Spacer(1, 16 * mm))
A(Paragraph("This document is the authoritative operating procedure for building, deploying, "
            "operating, and securing the VulnusLab platform. It is confidential and intended for "
            "internal operators and authorized auditors only.", st_small))
A(PageBreak())

# ---- 1. Purpose & Scope --------------------------------------------------
h1("1. Purpose &amp; Scope")
P("This SOP defines the standard, repeatable procedures for operating VulnusLab — an automated "
  "security-testing platform that performs Vulnerability Assessment (VA) and, where explicitly "
  "authorized, Penetration Testing (PT) against customer-owned assets. It is the single source of "
  "truth for how the system is built, deployed, run, monitored, backed up, and secured.")
h2("Scope")
bullets([
    "The production platform: backend API, frontend dashboard, scanner modules, and engines.",
    "Operational tasks: deployment, scanning, backup/restore, health monitoring, module builds.",
    "Governance: access control, change management, incident response, and compliance.",
    "Out of scope: customer engagement contracts and per-customer rules of engagement (handled separately).",
])
h2("Authorized use only")
P("VulnusLab must only be pointed at assets the customer owns or has written authorization to test. "
  "The platform is VA-first (detect and report); active exploitation is confined to the single "
  "authorized autonomous PT module operating under a non-destructive safety contract.")

# ---- 2. System Overview --------------------------------------------------
h1("2. System Overview")
P("VulnusLab is a single-tenant-per-customer SaaS delivered as a containerized application on a VPS, "
  "with a browser dashboard. It bundles industry-standard open-source security engines behind a "
  "uniform API so a customer can run professional-grade assessments without assembling a toolchain.")
table([
    ["Metric", "Value"],
    ["Scan modules", "42 (plus a credential-vault service)"],
    ["Detection routines", "~1,572 (574 tier-style scanners + 998 pack probes)"],
    ["Security engines bundled", "51 binaries (nmap, nuclei, trivy, sqlmap, hydra, etc.)"],
    ["Finding rule-sets", "305 findings modules"],
    ["Curated wordlists", "40 lists (~156,000 entries)"],
    ["Delivery", "Docker on VPS; React dashboard at app.vulnuslab.com"],
], [55 * mm, 95 * mm])
h2("Design principles")
bullets([
    "<b>Kali-first, pure-Python fallback:</b> use the best engine where available; otherwise a "
    "self-contained Python probe.",
    "<b>Zero false positives:</b> every finding is actively verified; confidence is labelled "
    "(CONFIRMED vs SUSPECTED).",
    "<b>VA-not-PT by default:</b> post-compromise / exploitation techniques are emitted as advisory "
    "information, never as fake high-severity findings.",
    "<b>Module isolation:</b> each module owns its scanners, payload pool, orchestrator, and UI wiring.",
])

# ---- 3. Architecture -----------------------------------------------------
h1("3. How It Works — Architecture")
P("A scan flows from the dashboard through a per-module orchestrator that fans out to the module's "
  "scanners, streams results back live, and renders them into a customer PDF report.")
h2("Request flow")
bullets([
    "<b>Frontend</b> (React SPA, served by nginx): the operator selects a module, supplies the target "
    "and any inputs/credentials, and starts the scan.",
    "<b>nginx reverse proxy</b> forwards the request to the backend; streaming endpoints are configured "
    "un-buffered so each result reaches the browser immediately.",
    "<b>Backend</b> (FastAPI + Uvicorn, 4 workers): an autoloader registers every scanner at boot "
    "(currently ~897 tools, 0 failed) with a self-healing engine.",
    "<b>Orchestrator</b> (one per module): resolves the requested tiers to a tool list and runs them "
    "concurrently, emitting newline-delimited JSON (NDJSON) as each finishes.",
    "<b>Scanners</b>: each calls an engine (or a pure-Python probe), normalizes output into findings "
    "(severity, evidence, remediation), and returns a uniform response.",
    "<b>Report</b>: the dashboard aggregates, de-duplicates, and renders an industry-standard PDF.",
])
h2("Component layout")
table([
    ["Component", "Technology", "Role"],
    ["Frontend", "React SPA + nginx (Docker)", "Dashboard UI, PDF generation, auth"],
    ["Backend", "FastAPI + Uvicorn (Docker)", "API, autoloader, orchestrators, scanners"],
    ["Engines", "51 OSS binaries in the image", "Actual scanning (shared by all modules)"],
    ["Datastore", "SQLite (users, scans, plans)", "Persisted in a Docker volume"],
    ["Cred vault", "Encrypted per-user store", "Holds customer cloud/AD/K8s credentials"],
    ["Lab targets", "Vulnerable containers", "Internal test targets (DVWA, Juice Shop, k3s, etc.)"],
], [32 * mm, 52 * mm, 66 * mm])

# ---- 4. Prerequisites ----------------------------------------------------
h1("4. What You Need — Prerequisites")
P("To stand up and operate a VulnusLab instance, the following are required.")
h2("Infrastructure")
bullets([
    "<b>VPS</b>: Linux (Ubuntu/Debian 22.04+), minimum 4 vCPU / 8 GB RAM / 80 GB disk; swap enabled "
    "(the frontend build is memory-intensive).",
    "<b>Docker + Docker Compose</b> installed.",
    "<b>Domain + DNS</b>: an A record (e.g. app.vulnuslab.com) pointing at the VPS; TLS via nginx.",
    "<b>Outbound internet</b> for engine vulnerability databases (OSV, nuclei-templates, CVE feeds).",
])
h2("Configuration &amp; secrets")
bullets([
    "<b>.env file</b> (never committed): JWT secret, admin password, CORS origins, and API keys "
    "(VirusTotal, AbuseIPDB, payment processor when enabled).",
    "<b>Engine image</b>: the Docker image bundles all 51 engines and their databases (~5 GB).",
    "<b>Customer credentials</b>: stored only in the encrypted vault, never in code or .env.",
])
h2("People &amp; access")
bullets([
    "At least one super-admin operator account.",
    "SSH access to the VPS (key-based; root password login disabled — see Security).",
    "A GitHub repository for code (code only; never customer data or secrets).",
])

# ---- 5. SOPs -------------------------------------------------------------
h1("5. Standard Operating Procedures")
h2("5.1 Deploy / redeploy")
P("Code is committed and pushed from the build environment; the VPS pulls and rebuilds the affected "
  "service. Backend and frontend are rebuilt independently.")
P("git pull<br/>docker compose build backend   # or: frontend<br/>docker compose up -d backend", st_code)
h2("5.2 Run a scan")
bullets([
    "Select the module in the dashboard; complete the scan-setup form (target, inputs, credentials).",
    "Start the scan; results stream live per scanner (status, severity, count, elapsed).",
    "Review findings, then export the customer PDF report.",
])
h2("5.3 Build or extend a module (VL-FORGE)")
P("New modules are built to 100% of their playbook using the VL-FORGE process: delete any old module "
  "code, then forge scanners + payload pool + orchestrator + frontend wiring + PDF section, and "
  "validate against the 7-check Definition of Done.")
h2("5.4 Quality gate (VL-FOUNDRY)")
P("Every module is scored by the automated scorer across six layers (orchestrator coverage, "
  "AI-curation, 7-check quality bar, parallelism, frontend, UI integration). A module must score "
  ">= 85 to ship; the fleet target is 100. The score measures structural readiness, not real-world "
  "coverage — live validation is a separate step (VL-AUDIT).")
h2("5.5 Backup &amp; restore")
bullets([
    "Automated daily database backup at 03:00 (cron) to /root/backups, 14-day retention.",
    "Restore by stopping containers, copying the chosen backup over the live volume, and restarting.",
    "Off-VPS copies (private repo / object storage) are strongly recommended for disaster recovery.",
])
h2("5.6 Health monitoring")
P("The System Health view and /api/health report backend status, scanner load count, failed/healed "
  "scanners, and the healing-engine state. Container health is verified with "
  "<font face='Courier' size='8'>docker compose ps</font>.")

# ---- 6. VL framework -----------------------------------------------------
h1("6. Quality Framework — VL Processes")
P("VulnusLab uses a set of named, repeatable engineering processes. The first group is the "
  "build-to-ship pipeline applied to every module; the rest are selective enhancers.")
table([
    ["Process", "Type", "Purpose"],
    ["VL-FORGE", "Universal", "Build a module to 100% of its playbook"],
    ["VL-FOUNDRY", "Universal", "Automated 6-layer readiness scoring"],
    ["VL-FLOW", "Universal", "Frontend phase / sidebar wiring"],
    ["VL-STREAM", "Universal", "Live NDJSON result streaming"],
    ["VL-CORE", "Selective", "Per-module isolated payload pool"],
    ["VL-VERIFY", "Selective", "SPA-canary false-positive suppression"],
    ["VL-METHOD", "Selective", "7-step methodology for multi-step workflows"],
    ["VL-AUDIT", "Platform", "One-command live scan of every module"],
    ["VL-DEDUP", "Platform", "Cross-module finding de-duplication"],
    ["VL-PRIME", "Platform", "Encrypted master archive (vault)"],
], [32 * mm, 28 * mm, 90 * mm], status_col=1)

# ---- 7. Security & Compliance --------------------------------------------
A(PageBreak())
h1("7. Security &amp; Compliance")
P("As a security product handling sensitive customer data and powerful tooling, VulnusLab operations "
  "must meet the controls below. Items marked (gap) are recommended additions to reach industry standard.")
h2("7.1 Access control")
bullets([
    "Role-based accounts (super-admin, admin, operator); least privilege enforced.",
    "JWT-authenticated API; per-user scoping of scans and credentials.",
    "SSH to the VPS is key-based only; root password authentication disabled.",
])
h2("7.2 Secrets management")
bullets([
    "Secrets live only in .env (gitignored) and the encrypted credential vault — never in code.",
    "Customer credentials are encrypted per-user; plaintext never leaves the backend process.",
    "<b>Lesson learned:</b> a plaintext credential note was once committed to git history; affected "
    "credentials must be rotated and history treated as exposed. No secrets in the repo, ever.",
    "(gap) Adopt a managed secrets store and automated secret-scanning in CI.",
])
h2("7.3 Authorization of testing")
bullets([
    "Only scan assets the customer owns or is authorized to test; capture authorization per engagement.",
    "(gap) Enforce a signed scope/consent gate before high-impact modules can run.",
])
h2("7.4 Data protection &amp; retention")
bullets([
    "Scan results and reports are customer data; store the minimum necessary and define retention.",
    "TLS in transit (nginx); database on an encrypted-at-rest volume is recommended.",
    "(gap) Document a data-retention schedule and a customer data-deletion procedure (GDPR/DPDP).",
])
h2("7.5 Audit logging")
bullets([
    "Authentication, scan starts, and credential use are recorded.",
    "(gap) Centralize tamper-evident audit logs and alert on anomalies.",
])

# ---- 8. Roles ------------------------------------------------------------
h1("8. Roles &amp; Responsibilities")
table([
    ["Role", "Responsibilities"],
    ["Platform Owner", "Strategy, prioritization, compliance accountability, approvals"],
    ["Operator / Analyst", "Runs scans, reviews findings, produces customer reports"],
    ["Engineer", "Builds and maintains modules, deploys, fixes defects"],
    ["Security Officer", "Owns access control, incident response, secret hygiene"],
    ["Customer", "Provides authorization and scope; owns the tested assets"],
], [40 * mm, 110 * mm], hdr_color=HEADER2)

# ---- 9. Change mgmt ------------------------------------------------------
h1("9. Change Management")
bullets([
    "All changes flow through version control; commits are descriptive and attributable.",
    "Build in a non-production context, validate (compile + VL-FOUNDRY + live spot-check), then deploy.",
    "Backend and frontend are deployed independently to limit blast radius.",
    "Maintain a last-known-good snapshot and a documented rollback (revert + redeploy).",
    "(gap) Use pull-request review and a staging environment before production.",
])

# ---- 10. Incident response ----------------------------------------------
h1("10. Incident Response")
P("Triggers include: backend outage, credential exposure, scanner mass-failure, or abuse of the platform.")
table([
    ["Phase", "Action"],
    ["Detect", "Health checks, error logs, customer report"],
    ["Contain", "Isolate the affected service; revoke/rotate exposed credentials"],
    ["Eradicate", "Fix root cause; redeploy from known-good"],
    ["Recover", "Restore data from backup; verify health"],
    ["Review", "Post-incident write-up; update this SOP and add a regression check"],
], [32 * mm, 118 * mm], hdr_color=HEADER2)

# ---- 11. DR --------------------------------------------------------------
h1("11. Disaster Recovery &amp; Continuity")
bullets([
    "<b>Code:</b> recoverable from the Git remote at any time.",
    "<b>Data:</b> daily DB backups (14-day retention) + recommended off-VPS copies.",
    "<b>Full rebuild:</b> provision a new VPS, install Docker, clone the repo, restore .env and the "
    "latest database backup, deploy, then repoint DNS.",
    "(gap) Define RPO/RTO targets and rehearse the recovery at least annually.",
])

# ---- 12. Compliance ------------------------------------------------------
h1("12. Compliance Mapping")
P("The scanning content aligns to widely-recognized standards. Operational compliance (of running the "
  "business) has documented gaps to close for enterprise sales.")
table([
    ["Standard", "Relevance", "Status"],
    ["OWASP / MASVS / API Top 10", "Scan coverage frameworks", "Implemented"],
    ["NIST SP 800-115 / 800-218", "Testing &amp; secure-SDLC method", "Aligned"],
    ["SLSA, Sigstore, EU CRA, EO 14028", "Supply-chain assurance", "Partial"],
    ["SOC 2 / ISO 27001", "Operational security of the SaaS", "(gap) recommended"],
    ["GDPR / India DPDP", "Customer data handling", "(gap) to formalize"],
], [55 * mm, 60 * mm, 35 * mm], status_col=2)

# ---- 13. Recommended additions ------------------------------------------
h1("13. Recommended Additions (to reach industry standard)")
P("Consolidated list of the (gap) items above, in priority order:")
bullets([
    "Rotate any historically-exposed credentials; add CI secret-scanning.",
    "Add a signed scope/authorization gate before high-impact scans.",
    "Formalize data-retention and customer data-deletion procedures (GDPR / DPDP).",
    "Centralize tamper-evident audit logging with alerting.",
    "Introduce pull-request review + a staging environment.",
    "Define RPO/RTO and rehearse disaster recovery annually.",
    "Pursue SOC 2 / ISO 27001 readiness for enterprise customers.",
    "Add off-VPS encrypted backups as the default, not optional.",
])
A(Spacer(1, 5 * mm))
A(HRFlowable(width="100%", thickness=0.8, color=ACCENT))
P("End of document. Review quarterly or after any material architecture or process change. This SOP is "
  "maintained in version control alongside the platform.", st_small)

doc = SimpleDocTemplate(OUT, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm,
                        topMargin=26 * mm, bottomMargin=22 * mm, title="VulnusLab SOP", author="VulnusLab")
doc.build(story, onFirstPage=decorate, onLaterPages=decorate)
print("WROTE", OUT, os.path.getsize(OUT), "bytes")

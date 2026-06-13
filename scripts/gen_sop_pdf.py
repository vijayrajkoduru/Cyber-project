#!/usr/bin/env python3
"""Generate the VulnusLab full-project SOP as a bordered, professional PDF.

Output: docs/VulnusLab_SOP.pdf
"""
from __future__ import annotations
import os
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle, PageBreak, ListFlowable, ListItem,
                                HRFlowable, KeepTogether)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "VulnusLab_SOP.pdf")
os.makedirs(os.path.dirname(OUT), exist_ok=True)

# ---- palette -------------------------------------------------------------
NAVY = colors.HexColor("#0d1320")
INK = colors.HexColor("#1b2336")
ACCENT = colors.HexColor("#0090b8")
ACCENT2 = colors.HexColor("#0b7a52")
GREY = colors.HexColor("#5a6478")
LIGHT = colors.HexColor("#eef2f7")
ROWALT = colors.HexColor("#f4f7fb")
BORDER = colors.HexColor("#0d1320")
RED = colors.HexColor("#a11020")

DOC_ID = "VL-SOP-001"
VERSION = "1.0"
DATE = "2026-06-13"
CLASS = "CONFIDENTIAL"

# ---- styles --------------------------------------------------------------
ss = getSampleStyleSheet()
def S(name, **kw):
    base = kw.pop("parent", ss["Normal"])
    return ParagraphStyle(name, parent=base, **kw)

st_title = S("vt", fontName="Helvetica-Bold", fontSize=30, textColor=NAVY, leading=34, alignment=TA_CENTER)
st_sub = S("vs", fontName="Helvetica", fontSize=13, textColor=ACCENT, leading=18, alignment=TA_CENTER)
st_h1 = S("h1", fontName="Helvetica-Bold", fontSize=16, textColor=colors.white, leading=20,
          backColor=NAVY, borderPadding=(7, 8, 7, 8), spaceBefore=16, spaceAfter=10, leftIndent=0)
st_h2 = S("h2", fontName="Helvetica-Bold", fontSize=12.5, textColor=NAVY, leading=16,
          spaceBefore=12, spaceAfter=5)
st_body = S("bd", fontName="Helvetica", fontSize=10, textColor=INK, leading=15,
            alignment=TA_JUSTIFY, spaceAfter=7)
st_li = S("li", fontName="Helvetica", fontSize=10, textColor=INK, leading=14)
st_small = S("sm", fontName="Helvetica", fontSize=8.5, textColor=GREY, leading=11)
st_code = S("cd", fontName="Courier", fontSize=8.5, textColor=colors.HexColor("#0b2a3a"),
            backColor=colors.HexColor("#eaf4f8"), borderPadding=(5, 6, 5, 6), leading=12, spaceAfter=7)
st_th = S("th", fontName="Helvetica-Bold", fontSize=9, textColor=colors.white, leading=12)
st_td = S("td", fontName="Helvetica", fontSize=9, textColor=INK, leading=12)
st_tdb = S("tdb", fontName="Helvetica-Bold", fontSize=9, textColor=NAVY, leading=12)

def P(t, s=st_body): return Paragraph(t, s)
def bullets(items, s=st_li):
    return ListFlowable([ListItem(Paragraph(i, s), leftIndent=10, value="•") for i in items],
                        bulletType="bullet", start="•", leftIndent=12, spaceAfter=8)

def table(data, col_widths, header=True, alt=True):
    rows = []
    for r in data:
        rows.append([c if hasattr(c, "wrap") else Paragraph(str(c), st_td) for c in r])
    if header:
        rows[0] = [Paragraph(str(c), st_th) if not hasattr(c, "wrap") else c for c in data[0]]
    t = Table(rows, colWidths=col_widths, repeatRows=1 if header else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d4e0")),
        ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#94a3b8")),
    ]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), NAVY),
                  ("LINEBELOW", (0, 0), (-1, 0), 0.6, NAVY)]
    if alt and header:
        for i in range(1, len(rows)):
            if i % 2 == 0:
                style.append(("BACKGROUND", (0, i), (-1, i), ROWALT))
    t.setStyle(TableStyle(style))
    return t

# ---- page border + footer ------------------------------------------------
def decorate(canvas, doc):
    canvas.saveState()
    w, h = A4
    # outer border
    canvas.setStrokeColor(BORDER); canvas.setLineWidth(1.6)
    canvas.rect(12 * mm, 12 * mm, w - 24 * mm, h - 24 * mm)
    # thin inner accent border
    canvas.setStrokeColor(ACCENT); canvas.setLineWidth(0.5)
    canvas.rect(14 * mm, 14 * mm, w - 28 * mm, h - 28 * mm)
    # footer
    canvas.setFont("Helvetica", 7.5); canvas.setFillColor(GREY)
    canvas.drawString(16 * mm, 15.5 * mm, f"{DOC_ID}  |  v{VERSION}  |  {DATE}")
    canvas.drawCentredString(w / 2, 15.5 * mm, CLASS)
    canvas.drawRightString(w - 16 * mm, 15.5 * mm, f"Page {doc.page}")
    # header band (skip on cover, page 1)
    if doc.page > 1:
        canvas.setFillColor(NAVY)
        canvas.rect(14 * mm, h - 22 * mm, w - 28 * mm, 6 * mm, fill=1, stroke=0)
        canvas.setFillColor(colors.white); canvas.setFont("Helvetica-Bold", 8)
        canvas.drawString(16 * mm, h - 20.3 * mm, "VulnusLab — Standard Operating Procedure")
        canvas.setFont("Helvetica", 7.5)
        canvas.drawRightString(w - 16 * mm, h - 20.3 * mm, "vulnuslab.com")
    canvas.restoreState()

# ---- content -------------------------------------------------------------
story = []
A = story.append

# Cover
A(Spacer(1, 55 * mm))
A(P("VulnusLab", st_title))
A(Spacer(1, 4 * mm))
A(P("Standard Operating Procedure (SOP)", st_sub))
A(P("Vulnerability Assessment &amp; Penetration-Testing Platform", S("c2", parent=st_sub, fontSize=10, textColor=GREY)))
A(Spacer(1, 30 * mm))
cover = [["Document ID", DOC_ID], ["Version", VERSION], ["Date", DATE],
         ["Owner", "VulnusLab (MSME UDYAM-AP-13-0090768)"],
         ["Classification", CLASS], ["Review cycle", "Quarterly"]]
A(Table([[Paragraph(k, st_tdb), Paragraph(v, st_td)] for k, v in cover],
        colWidths=[45 * mm, 95 * mm],
        style=[("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#94a3b8")),
               ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d4e0")),
               ("BACKGROUND", (0, 0), (0, -1), LIGHT),
               ("LEFTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 6),
               ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
A(Spacer(1, 18 * mm))
A(P("This document is the authoritative operating procedure for building, deploying, "
    "operating, and securing the VulnusLab platform. It is confidential and intended for "
    "internal operators and authorized auditors only.", st_small))
A(PageBreak())

# 1. Purpose & Scope
A(P("1. Purpose &amp; Scope", st_h1))
A(P("This SOP defines the standard, repeatable procedures for operating VulnusLab — an "
    "automated security-testing platform that performs Vulnerability Assessment (VA) and, "
    "where explicitly authorized, Penetration Testing (PT) against customer-owned assets. "
    "It is the single source of truth for how the system is built, deployed, run, monitored, "
    "backed up, and secured."))
A(P("Scope", st_h2))
A(bullets([
    "The production platform: backend API, frontend dashboard, scanner modules, and engines.",
    "Operational tasks: deployment, scanning, backup/restore, health monitoring, module builds.",
    "Governance: access control, change management, incident response, and compliance.",
    "Out of scope: customer engagement contracts and per-customer rules of engagement (handled separately).",
]))
A(P("Authorized use only", st_h2))
A(P("VulnusLab must only be pointed at assets the customer owns or has written authorization "
    "to test. The platform is VA-first (detect and report); active exploitation is confined to "
    "the single authorized autonomous PT module operating under a non-destructive safety contract."))

# 2. System Overview
A(P("2. System Overview", st_h1))
A(P("VulnusLab is a single-tenant-per-customer SaaS delivered as a containerized application "
    "on a VPS, with a browser dashboard. It bundles industry-standard open-source security "
    "engines behind a uniform API so a customer can run professional-grade assessments without "
    "assembling a toolchain."))
A(table([
    ["Metric", "Value"],
    ["Scan modules", "42 (plus a credential-vault service)"],
    ["Detection routines", "~1,572 (574 tier-style scanners + 998 pack probes)"],
    ["Security engines bundled", "51 binaries (nmap, nuclei, trivy, sqlmap, hydra, etc.)"],
    ["Finding rule-sets", "305 findings modules"],
    ["Curated wordlists", "40 lists (~156,000 entries)"],
    ["Delivery", "Docker on VPS; React dashboard at app.vulnuslab.com"],
], [55 * mm, 95 * mm]))
A(P("Design principles", st_h2))
A(bullets([
    "<b>Kali-first, pure-Python fallback:</b> use the best engine where available; otherwise a "
    "self-contained Python probe.",
    "<b>Zero false positives:</b> every finding is actively verified; confidence is labelled "
    "(CONFIRMED vs SUSPECTED).",
    "<b>VA-not-PT by default:</b> post-compromise / exploitation techniques are emitted as "
    "advisory information, never as fake high-severity findings.",
    "<b>Module isolation:</b> each module owns its scanners, payload pool, orchestrator, and UI wiring.",
]))

# 3. How It Works (Architecture)
A(P("3. How It Works — Architecture", st_h1))
A(P("A scan flows from the dashboard through a per-module orchestrator that fans out to the "
    "module's scanners, streams results back live, and renders them into a customer PDF report."))
A(P("Request flow", st_h2))
A(bullets([
    "<b>Frontend</b> (React SPA, served by nginx): the operator selects a module, supplies the "
    "target and any inputs/credentials, and starts the scan.",
    "<b>nginx reverse proxy</b> forwards the request to the backend; streaming endpoints are "
    "configured un-buffered so each result reaches the browser immediately.",
    "<b>Backend</b> (FastAPI + Uvicorn, 4 workers): an autoloader registers every scanner at "
    "boot (currently ~897 tools, 0 failed) with a self-healing engine.",
    "<b>Orchestrator</b> (one per module): resolves the requested tiers to a tool list and runs "
    "them concurrently, emitting newline-delimited JSON (NDJSON) as each finishes.",
    "<b>Scanners</b>: each calls an engine (or a pure-Python probe), normalizes output into "
    "findings (severity, evidence, remediation), and returns a uniform response.",
    "<b>Report</b>: the dashboard aggregates, de-duplicates, and renders an industry-standard PDF.",
]))
A(P("Component layout", st_h2))
A(table([
    ["Component", "Technology", "Role"],
    ["Frontend", "React SPA + nginx (Docker)", "Dashboard UI, PDF generation, auth"],
    ["Backend", "FastAPI + Uvicorn (Docker)", "API, autoloader, orchestrators, scanners"],
    ["Engines", "51 OSS binaries in the image", "Actual scanning (shared by all modules)"],
    ["Datastore", "SQLite (users, scans, plans)", "Persisted in a Docker volume"],
    ["Cred vault", "Encrypted per-user store", "Holds customer cloud/AD/K8s credentials"],
    ["Lab targets", "Vulnerable containers", "Internal test targets (DVWA, Juice Shop, k3s, etc.)"],
], [32 * mm, 52 * mm, 66 * mm]))

# 4. What You Need (Prerequisites)
A(P("4. What You Need — Prerequisites", st_h1))
A(P("To stand up and operate a VulnusLab instance, the following are required."))
A(P("Infrastructure", st_h2))
A(bullets([
    "<b>VPS</b>: Linux (Ubuntu/Debian 22.04+), minimum 4 vCPU / 8 GB RAM / 80 GB disk; swap "
    "enabled (the frontend build is memory-intensive).",
    "<b>Docker + Docker Compose</b> installed.",
    "<b>Domain + DNS</b>: an A record (e.g. app.vulnuslab.com) pointing at the VPS; TLS via nginx.",
    "<b>Outbound internet</b> for engine vulnerability databases (OSV, nuclei-templates, CVE feeds).",
]))
A(P("Configuration &amp; secrets", st_h2))
A(bullets([
    "<b>.env file</b> (never committed): JWT secret, admin password, CORS origins, and API keys "
    "(VirusTotal, AbuseIPDB, payment processor when enabled).",
    "<b>Engine image</b>: the Docker image bundles all 51 engines and their databases (~5 GB).",
    "<b>Customer credentials</b>: stored only in the encrypted vault, never in code or .env.",
]))
A(P("People &amp; access", st_h2))
A(bullets([
    "At least one super-admin operator account.",
    "SSH access to the VPS (key-based; root password login disabled — see Security).",
    "A GitHub repository for code (code only; never customer data or secrets).",
]))

# 5. Standard Operating Procedures
A(P("5. Standard Operating Procedures", st_h1))
A(P("5.1 Deploy / redeploy", st_h2))
A(P("Code is committed and pushed from the build environment; the VPS pulls and rebuilds the "
    "affected service. Backend and frontend are rebuilt independently."))
A(P("git pull<br/>docker compose build backend   # or: frontend<br/>docker compose up -d backend", st_code))
A(P("5.2 Run a scan", st_h2))
A(bullets([
    "Select the module in the dashboard; complete the scan-setup form (target, inputs, credentials).",
    "Start the scan; results stream live per scanner (status, severity, count, elapsed).",
    "Review findings, then export the customer PDF report.",
]))
A(P("5.3 Build or extend a module (VL-FORGE)", st_h2))
A(P("New modules are built to 100% of their playbook using the VL-FORGE process: delete any old "
    "module code, then forge scanners + payload pool + orchestrator + frontend wiring + PDF "
    "section, and validate against the 7-check Definition of Done."))
A(P("5.4 Quality gate (VL-FOUNDRY)", st_h2))
A(P("Every module is scored by the automated scorer across six layers (orchestrator coverage, "
    "AI-curation, 7-check quality bar, parallelism, frontend, UI integration). A module must "
    "score >= 85 to ship; the fleet target is 100. The score measures structural readiness, not "
    "real-world coverage — live validation is a separate step (VL-AUDIT)."))
A(P("5.5 Backup &amp; restore", st_h2))
A(bullets([
    "Automated daily database backup at 03:00 (cron) to /root/backups, 14-day retention.",
    "Restore by stopping containers, copying the chosen backup over the live volume, and restarting.",
    "Off-VPS copies (private repo / object storage) are strongly recommended for disaster recovery.",
]))
A(P("5.6 Health monitoring", st_h2))
A(P("The System Health view and /api/health report backend status, scanner load count, failed/"
    "healed scanners, and the healing-engine state. Container health is verified with "
    "<font face='Courier' size='8'>docker compose ps</font>."))

# 6. Quality Framework (VL processes)
A(P("6. Quality Framework — VL Processes", st_h1))
A(P("VulnusLab uses a set of named, repeatable engineering processes. The first group is the "
    "build-to-ship pipeline applied to every module; the rest are selective enhancers."))
A(table([
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
], [32 * mm, 28 * mm, 90 * mm]))

# 7. Security & Compliance (industry-standard additions)
A(PageBreak())
A(P("7. Security &amp; Compliance", st_h1))
A(P("As a security product handling sensitive customer data and powerful tooling, VulnusLab "
    "operations must meet the controls below. Items marked (gap) are recommended additions to "
    "reach industry standard."))
A(P("7.1 Access control", st_h2))
A(bullets([
    "Role-based accounts (super-admin, admin, operator); least privilege enforced.",
    "JWT-authenticated API; per-user scoping of scans and credentials.",
    "SSH to the VPS is key-based only; root password authentication disabled.",
]))
A(P("7.2 Secrets management", st_h2))
A(bullets([
    "Secrets live only in .env (gitignored) and the encrypted credential vault — never in code.",
    "Customer credentials are encrypted per-user; plaintext never leaves the backend process.",
    "<b>Lesson learned:</b> a plaintext credential note was once committed to git history; "
    "affected credentials must be rotated and history treated as exposed. No secrets in the repo, ever.",
    "<b>(gap)</b> Adopt a managed secrets store and automated secret-scanning in CI.",
]))
A(P("7.3 Authorization of testing", st_h2))
A(bullets([
    "Only scan assets the customer owns or is authorized to test; capture authorization per engagement.",
    "<b>(gap)</b> Enforce a signed scope/consent gate before high-impact modules can run.",
]))
A(P("7.4 Data protection &amp; retention", st_h2))
A(bullets([
    "Scan results and reports are customer data; store the minimum necessary and define retention.",
    "TLS in transit (nginx); database on an encrypted-at-rest volume is recommended.",
    "<b>(gap)</b> Document a data-retention schedule and a customer data-deletion procedure (GDPR/DPDP).",
]))
A(P("7.5 Audit logging", st_h2))
A(bullets([
    "Authentication, scan starts, and credential use are recorded.",
    "<b>(gap)</b> Centralize tamper-evident audit logs and alert on anomalies.",
]))

# 8. Roles & Responsibilities (industry standard)
A(P("8. Roles &amp; Responsibilities", st_h1))
A(table([
    ["Role", "Responsibilities"],
    ["Platform Owner", "Strategy, prioritization, compliance accountability, approvals"],
    ["Operator / Analyst", "Runs scans, reviews findings, produces customer reports"],
    ["Engineer", "Builds and maintains modules, deploys, fixes defects"],
    ["Security Officer", "Owns access control, incident response, secret hygiene"],
    ["Customer", "Provides authorization and scope; owns the tested assets"],
], [40 * mm, 110 * mm]))

# 9. Change Management (industry standard)
A(P("9. Change Management", st_h1))
A(bullets([
    "All changes flow through version control; commits are descriptive and attributable.",
    "Build in a non-production context, validate (compile + VL-FOUNDRY + live spot-check), then deploy.",
    "Backend and frontend are deployed independently to limit blast radius.",
    "Maintain a last-known-good snapshot and a documented rollback (revert + redeploy).",
    "<b>(gap)</b> Use pull-request review and a staging environment before production.",
]))

# 10. Incident Response (industry standard)
A(P("10. Incident Response", st_h1))
A(P("Triggers include: backend outage, credential exposure, scanner mass-failure, or abuse of "
    "the platform."))
A(table([
    ["Phase", "Action"],
    ["Detect", "Health checks, error logs, customer report"],
    ["Contain", "Isolate the affected service; revoke/rotate exposed credentials"],
    ["Eradicate", "Fix root cause; redeploy from known-good"],
    ["Recover", "Restore data from backup; verify health"],
    ["Review", "Post-incident write-up; update this SOP and add a regression check"],
], [32 * mm, 118 * mm]))

# 11. Disaster Recovery / BCP (industry standard)
A(P("11. Disaster Recovery &amp; Continuity", st_h1))
A(bullets([
    "<b>Code:</b> recoverable from the Git remote at any time.",
    "<b>Data:</b> daily DB backups (14-day retention) + recommended off-VPS copies.",
    "<b>Full rebuild:</b> provision a new VPS, install Docker, clone the repo, restore .env and the "
    "latest database backup, deploy, then repoint DNS.",
    "<b>(gap)</b> Define RPO/RTO targets and rehearse the recovery at least annually.",
]))

# 12. Compliance Mapping (industry standard)
A(P("12. Compliance Mapping", st_h1))
A(P("The scanning content aligns to widely-recognized standards. Operational compliance "
    "(of running the business) has documented gaps to close for enterprise sales."))
A(table([
    ["Standard", "Relevance", "Status"],
    ["OWASP / MASVS / API Top 10", "Scan coverage frameworks", "Implemented in modules"],
    ["NIST SP 800-115 / 800-218", "Testing &amp; secure-SDLC method", "Aligned"],
    ["SLSA, Sigstore, EU CRA, EO 14028", "Supply-chain assurance", "Partial (building out)"],
    ["SOC 2 / ISO 27001", "Operational security of the SaaS", "(gap) recommended for enterprise"],
    ["GDPR / India DPDP", "Customer data handling", "(gap) retention + deletion to formalize"],
], [55 * mm, 60 * mm, 35 * mm]))

# 13. Recommended additions summary
A(P("13. Recommended Additions (to reach industry standard)", st_h1))
A(P("Consolidated list of the (gap) items above, in priority order:"))
A(bullets([
    "Rotate any historically-exposed credentials; add CI secret-scanning.",
    "Add a signed scope/authorization gate before high-impact scans.",
    "Formalize data-retention and customer data-deletion procedures (GDPR / DPDP).",
    "Centralize tamper-evident audit logging with alerting.",
    "Introduce pull-request review + a staging environment.",
    "Define RPO/RTO and rehearse disaster recovery annually.",
    "Pursue SOC 2 / ISO 27001 readiness for enterprise customers.",
    "Add off-VPS encrypted backups as the default, not optional.",
]))

A(Spacer(1, 6 * mm))
A(HRFlowable(width="100%", thickness=0.6, color=colors.HexColor("#94a3b8")))
A(P("End of document. Review quarterly or after any material architecture or process change. "
    "This SOP is maintained in version control alongside the platform.", st_small))

# ---- build ---------------------------------------------------------------
doc = SimpleDocTemplate(OUT, pagesize=A4,
                        leftMargin=20 * mm, rightMargin=20 * mm,
                        topMargin=26 * mm, bottomMargin=22 * mm,
                        title="VulnusLab SOP", author="VulnusLab")
doc.build(story, onFirstPage=decorate, onLaterPages=decorate)
print("WROTE", OUT, os.path.getsize(OUT), "bytes")

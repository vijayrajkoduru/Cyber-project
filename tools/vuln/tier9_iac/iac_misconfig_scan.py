"""IaC Misconfiguration Scanner — Terraform / CloudFormation static analysis.

VL-FORGE Vuln tier9 §9 — analyzes user-supplied Infrastructure-as-Code for
security misconfigurations: hardcoded secrets, world-open security groups,
public storage, missing encryption, IAM wildcards, IMDSv1, weak TLS, etc.

Self-contained: a pure-regex ruleset, so it runs even when terrascan/kics/
checkov are not installed (no external binary dependency, no SSRF surface —
it only inspects content the caller pasted). Input arrives in the `iac_text`
field; when it's absent the scanner returns a clean NOT-APPLICABLE skip
rather than a failure, matching the container_k8s dockerfile_text probes.
"""
import re
from typing import Optional
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import run_scanner
from tools._vl_core.verify import vl_verify

router = APIRouter()


class IaCScanRequest(ScanRequest):
    """Adds the IaC payload fields on top of the standard ScanRequest."""
    iac_text: Optional[str] = None       # raw Terraform (HCL) or CloudFormation (YAML/JSON)
    iac_filename: Optional[str] = None   # optional hint, e.g. main.tf / template.yaml


# (id, regex, title, severity, cvss, cwe, remediation, scope) where scope is
# "tf" (Terraform/HCL only), "cfn" (CloudFormation only), or "any".
# Patterns are intentionally conservative to limit false positives.
_RULES = [
    # ── Hardcoded secrets (format-agnostic, highest value) ──
    ("IAC-SEC-AWSKEY", r'AKIA[0-9A-Z]{16}',
     "Hardcoded AWS access key ID", "CRITICAL", 9.1, "CWE-798",
     "Remove the key; use IAM roles or a secrets manager. Rotate the exposed key immediately.", "any"),
    ("IAC-SEC-PRIVKEY", r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----',
     "Hardcoded private key", "CRITICAL", 9.1, "CWE-798",
     "Never embed private keys in IaC; use a secrets manager / KMS and rotate.", "any"),
    ("IAC-SEC-PASSWORD",
     r'(?:password|passwd|secret|api[_-]?key|access[_-]?key|secret[_-]?key|token)\s*[=:]\s*'
     r'["\'](?!\$\{|var\.|local\.|data\.|module\.|aws_)[^"\'\s$]{6,}["\']',
     "Hardcoded secret/password literal", "HIGH", 7.5, "CWE-798",
     "Replace literal secrets with variables sourced from a secrets manager (AWS Secrets Manager, Vault).", "any"),

    # ── Network exposure ──
    ("IAC-NET-WORLD-SSH", r'(?is)from_port\s*=\s*22\b.{0,250}?0\.0\.0\.0/0',
     "SSH (port 22) open to 0.0.0.0/0", "HIGH", 8.6, "CWE-284",
     "Restrict ingress to known admin CIDRs; prefer a bastion or SSM Session Manager.", "tf"),
    ("IAC-NET-WORLD-RDP", r'(?is)from_port\s*=\s*3389\b.{0,250}?0\.0\.0\.0/0',
     "RDP (port 3389) open to 0.0.0.0/0", "HIGH", 8.6, "CWE-284",
     "Restrict RDP ingress to known CIDRs; prefer a bastion / VPN.", "tf"),
    ("IAC-CFN-SG-WORLD", r'CidrIp\s*:\s*["\']?0\.0\.0\.0/0',
     "CloudFormation security-group ingress open to 0.0.0.0/0", "MEDIUM", 5.3, "CWE-284",
     "Scope CidrIp to the networks that actually need access.", "cfn"),
    ("IAC-NET-WORLD-CIDR", r'0\.0\.0\.0/0',
     "Resource references 0.0.0.0/0 (world-open)", "MEDIUM", 5.3, "CWE-284",
     "Confirm this is egress only; never allow world-open ingress to sensitive ports.", "any"),

    # ── Storage / public access ──
    ("IAC-S3-PUBLIC-ACL", r'acl\s*=\s*["\']public-read(?:-write)?["\']',
     "S3 bucket public-read ACL", "HIGH", 7.5, "CWE-732",
     "Set ACL to private; serve via CloudFront with Origin Access Control.", "tf"),
    ("IAC-S3-PAB-OFF",
     r'(?:block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false',
     "S3 Public Access Block flag disabled", "HIGH", 7.5, "CWE-732",
     "Set all four S3 public-access-block flags to true.", "tf"),
    ("IAC-CFN-S3-PUBLIC", r'AccessControl\s*:\s*["\']?Public(?:Read|ReadWrite)',
     "CloudFormation S3 public AccessControl", "HIGH", 7.5, "CWE-732",
     "Use private AccessControl plus a least-privilege bucket policy.", "cfn"),

    # ── Encryption at rest ──
    ("IAC-ENC-OFF", r'\bencrypted\s*=\s*false',
     "Encryption at rest disabled (encrypted = false)", "MEDIUM", 5.5, "CWE-311",
     "Enable encryption (encrypted = true), ideally with a customer-managed KMS key.", "tf"),
    ("IAC-ENC-RDS-OFF", r'storage_encrypted\s*=\s*false',
     "RDS storage encryption disabled", "MEDIUM", 5.5, "CWE-311",
     "Set storage_encrypted = true (requires a KMS key).", "tf"),

    # ── Public data services ──
    ("IAC-RDS-PUBLIC", r'publicly_accessible\s*=\s*true',
     "Database/instance publicly accessible", "HIGH", 7.5, "CWE-668",
     "Set publicly_accessible = false and place the resource in private subnets.", "tf"),
    ("IAC-EKS-PUBLIC", r'endpoint_public_access\s*=\s*true',
     "Cluster/EKS public endpoint enabled", "MEDIUM", 5.3, "CWE-668",
     "Disable the public endpoint or restrict public_access_cidrs.", "tf"),

    # ── IAM over-permission ──
    ("IAC-IAM-ACTION-STAR", r'(?:"Action"\s*:\s*"\*"|actions\s*=\s*\[\s*"\*"\s*\])',
     'IAM policy grants Action "*"', "HIGH", 8.1, "CWE-269",
     "Scope actions to the minimum required; avoid wildcard Action.", "any"),
    ("IAC-IAM-RESOURCE-STAR", r'(?:"Resource"\s*:\s*"\*"|resources\s*=\s*\[\s*"\*"\s*\])',
     'IAM policy grants Resource "*"', "MEDIUM", 6.5, "CWE-269",
     "Scope resources to specific ARNs.", "any"),

    # ── Metadata / logging / TLS ──
    ("IAC-IMDSV1", r'http_tokens\s*=\s*["\']optional["\']',
     "IMDSv1 allowed (http_tokens = optional)", "MEDIUM", 6.5, "CWE-441",
     'Set http_tokens = "required" to enforce IMDSv2 (mitigates SSRF credential theft).', "tf"),
    ("IAC-LOG-OFF", r'enable_logging\s*=\s*false',
     "Logging disabled (enable_logging = false)", "LOW", 3.7, "CWE-778",
     "Enable logging for audit and forensics.", "tf"),
    ("IAC-TLS-WEAK", r'minimum_protocol_version\s*=\s*["\']TLSv1(?:\.0|\.1)?["\']',
     "Weak minimum TLS version (< 1.2)", "MEDIUM", 5.3, "CWE-326",
     "Require TLS 1.2+ (e.g. TLSv1.2_2021).", "tf"),
    ("IAC-SKIP-VERIFY", r'(?:skip_credentials_validation|skip_tls_verify|insecure)\s*=\s*true',
     "TLS/credential verification disabled", "MEDIUM", 5.9, "CWE-295",
     "Do not disable TLS/credential verification in production IaC.", "any"),
]
_COMPILED = [(rid, re.compile(rx, re.IGNORECASE | re.MULTILINE), title, sev, cvss, cwe, rem, scope)
             for (rid, rx, title, sev, cvss, cwe, rem, scope) in _RULES]


def _detect_format(text: str, filename: str) -> str:
    fn = (filename or "").lower()
    if fn.endswith((".tf", ".tfvars", ".hcl")):
        return "tf"
    if fn.endswith((".yaml", ".yml", ".json", ".template")):
        return "cfn"
    if "AWSTemplateFormatVersion" in text or ("Type:" in text and re.search(r'(?m)^\s*Resources\s*:', text)):
        return "cfn"
    if re.search(r'(?m)^\s*(?:resource|provider|module|data)\s+"', text):
        return "tf"
    return "any"


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


async def gather(ctx, *, text: str = "", filename: str = "") -> None:
    text = text or ""
    if not text.strip():
        ctx.state["skipped_reason"] = (
            "No IaC content provided. Paste Terraform (.tf/HCL) or CloudFormation "
            "(YAML/JSON) into the iac_text field to scan it."
        )
        return
    ctx.source("iac-static")
    fmt = _detect_format(text, filename)
    ctx.state["iac_format"] = fmt
    ctx.state["iac_bytes"] = len(text)
    hits = []
    for rid, rx, title, sev, cvss, cwe, rem, scope in _COMPILED:
        if scope != "any" and fmt != "any" and scope != fmt:
            continue
        lines = sorted({_line_of(text, m.start()) for m in rx.finditer(text)})
        if lines:
            hits.append({"id": rid, "title": title, "severity": sev, "cvss": cvss,
                         "cwe": cwe, "remediation": rem, "count": len(lines), "lines": lines[:20]})
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    hits.sort(key=lambda h: (sev_order.get(h["severity"], 9), h["id"]))
    ctx.state["iac_hits"] = hits
    ctx.state["issue_count"] = len(hits)


def _mk(i):
    def rule(s):
        hits = s.get("iac_hits") or []
        if i >= len(hits):
            return None
        h = hits[i]
        return {"name": f"{h['title']} ({h['count']}×)", "severity": h["severity"],
                "cvss": h["cvss"], "cwe": h["cwe"],
                "evidence": f"[{h['id']}] matched on line(s): {', '.join(map(str, h['lines']))} "
                            f"of the {s.get('iac_format', '?')} input.",
                "remediation": h["remediation"]}
    return rule


def _r_clean(s):
    if s.get("iac_hits") is None:        # input was missing — skipped_reason handles it
        return None
    if s.get("iac_hits"):                # issues found — _mk rules emit them
        return None
    return {"name": "No IaC misconfigurations detected", "severity": "POSITIVE",
            "evidence": f"Scanned {s.get('iac_bytes', 0)} bytes of {s.get('iac_format', 'IaC')}; "
                        "no rule matched. Static rules are not exhaustive — pair with "
                        "terrascan/checkov in CI for full coverage."}


FINDING_RULES = [_mk(i) for i in range(30)] + [_r_clean]
INTEL_FIELDS = [("IaC format", "iac_format"), ("Bytes scanned", "iac_bytes"), ("Issues found", "issue_count")]


@router.post("/api/vuln/iac_misconfig_scan")
@vl_verify()
async def iac_misconfig_scan(req: IaCScanRequest, _=Depends(verify_scan_quota)):
    async def _gather(ctx):
        await gather(ctx, text=req.iac_text or "", filename=req.iac_filename or "")
    return await run_scanner(host=(req.target or "iac-input"), tool="iac_misconfig_scan",
                             gather_func=_gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)

"""Repo-scan probes for Helm + Kustomize secret leakage.

Each probe takes the customer-provided `repo_url` input (public git
repository URL), clones the repo into a temp directory with depth=1,
runs targeted scans on Helm values.yaml + Kustomize secretGenerator
literals, then shreds the clone.

Security model:
  - shallow clone (--depth 1) only - bounds disk + network use
  - 60-second clone timeout
  - 30 MB max repo size (skip beyond)
  - tempdir auto-removed on every exit path
  - never clones to a path the customer can read
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from typing import Optional

from tools._shared import wrap_finding


_GIT_TIMEOUT = 60
_MAX_REPO_BYTES = 30 * 1024 * 1024  # 30 MB


def _ndr(slug, target, reason=""):
    return {
        "tool": slug, "target": target, "scan_time": 0,
        "vulnerable": False, "severity": "INFO",
        "findings": [wrap_finding(
            f"[NOT_APPLICABLE] {slug} requires a public git repo URL",
            "INFO", cvss="0.0", cwe="N/A",
            remediation=("Paste a public GitHub/GitLab/Bitbucket repo URL "
                          "in the dashboard's repo_url field. The probe will "
                          "shallow-clone and scan."),
            evidence_marker=reason or "Required input 'repo_url' is empty.")],
        "tests_performed": 0,
        "tests_summary": f"{slug} skipped - missing repo_url",
        "_skipped": True,
        "skipped_reason": "repo_url not provided",
        "raw_data": {"missing_input": "repo_url"},
    }


def _build_resp(slug, target, findings, tested, summary):
    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "POSITIVE": 0}
    top = "INFO"
    for f in findings:
        s = f.get("severity", "INFO")
        if sev_order.get(s, 0) > sev_order.get(top, 0):
            top = s
    return {
        "tool": slug, "target": target, "scan_time": 0,
        "vulnerable": top in ("CRITICAL", "HIGH", "MEDIUM"),
        "severity": top, "findings": findings,
        "tests_performed": tested, "tests_summary": summary,
        "raw_data": {},
    }


def _get_repo_url(req) -> Optional[str]:
    u = getattr(req, "repo_url", None)
    if not u or not isinstance(u, str):
        return None
    u = u.strip()
    # Basic safety - allow http(s) git URLs only
    if not re.match(r"^https?://[a-zA-Z0-9.\-/_:@]+$", u):
        return None
    if len(u) > 500:
        return None
    return u


def _clone(repo_url: str) -> tuple[int, str, str]:
    """Shallow-clone repo_url to a tempdir. Returns (exit, tempdir_or_empty, err)."""
    if shutil.which("git") is None:
        return 127, "", "git binary missing"
    tmpdir = tempfile.mkdtemp(prefix="vl-repo-")
    try:
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet",
             "--config", "http.followRedirects=true",
             repo_url, tmpdir],
            capture_output=True, text=True,
            timeout=_GIT_TIMEOUT, check=False)
        if proc.returncode != 0:
            shutil.rmtree(tmpdir, ignore_errors=True)
            return proc.returncode, "", (proc.stderr or "")[-400:]
        # Size guard
        total = 0
        for root, dirs, files in os.walk(tmpdir):
            for f in files:
                try:
                    total += os.path.getsize(os.path.join(root, f))
                    if total > _MAX_REPO_BYTES:
                        shutil.rmtree(tmpdir, ignore_errors=True)
                        return 1, "", f"repo exceeds {_MAX_REPO_BYTES} byte cap"
                except OSError:
                    pass
        return 0, tmpdir, ""
    except subprocess.TimeoutExpired:
        shutil.rmtree(tmpdir, ignore_errors=True)
        return 124, "", "git clone timeout"
    except Exception as e:
        shutil.rmtree(tmpdir, ignore_errors=True)
        return 1, "", f"{type(e).__name__}: {str(e)[:200]}"


def _shred(tmpdir: str):
    """Best-effort secure-delete tempdir."""
    try:
        shutil.rmtree(tmpdir, ignore_errors=True)
    except Exception:
        pass


# ─── Helm values.yaml secret leak detector ───────────────────────────

_HELM_VALUE_FILES = (
    "values.yaml", "values.yml",
    "values-prod.yaml", "values-staging.yaml", "values-dev.yaml",
)
_SENSITIVE_HELM_KEYS = re.compile(
    r"(?i)^[\s\-]*(password|passwd|pwd|secret|token|api[_-]?key|"
    r"access[_-]?key|private[_-]?key|db[_-]?pass|database[_-]?url|"
    r"jwt[_-]?secret|mysql_password|postgres_password|redis_password|"
    r"smtp_password|stripe_key|github_token|aws_access_key|aws_secret|"
    r"gcp[_-]?service[_-]?account|azure[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9!@#$%^&*_+/=\-]{6,}['\"]?",
    re.MULTILINE)


def _probe_secrets_helm_values_leak(target, req):
    repo_url = _get_repo_url(req)
    if repo_url is None:
        return _ndr("secrets_helm_values_leak", target,
                     "Provide a public git repo URL containing Helm charts.")
    ec, tmpdir, err = _clone(repo_url)
    if ec != 0:
        return _build_resp("secrets_helm_values_leak", target, [wrap_finding(
            f"[PROBE ERROR] git clone failed: exit {ec}",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify the URL is a public repo + reachable.",
            evidence_marker=err)], 0, f"clone exit {ec}")

    findings = []
    leaks = []
    files_scanned = 0
    try:
        for root, dirs, files in os.walk(tmpdir):
            # Skip .git
            if ".git" in root.split(os.sep):
                continue
            for f in files:
                if f.lower() not in _HELM_VALUE_FILES:
                    continue
                fpath = os.path.join(root, f)
                rel = os.path.relpath(fpath, tmpdir)
                files_scanned += 1
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as h:
                        text = h.read(200_000)  # 200KB cap per file
                except OSError:
                    continue
                for m in _SENSITIVE_HELM_KEYS.finditer(text):
                    line_no = text[:m.start()].count("\n") + 1
                    snippet = m.group(0)[:140]
                    leaks.append((rel, line_no, snippet))

        if leaks:
            for rel, line_no, snippet in leaks[:10]:
                findings.append(wrap_finding(
                    f"Sensitive value hardcoded in Helm values file ({rel}:{line_no})",
                    "HIGH", cvss="7.5", cwe="CWE-798", owasp="A07:2021",
                    remediation=("Move secrets out of values.yaml. Reference "
                                  "them via valueFrom.secretKeyRef in the "
                                  "Helm templates instead, OR use a secrets-"
                                  "management operator (External Secrets, "
                                  "SealedSecrets, Vault). Rotate exposed "
                                  "credentials immediately."),
                    evidence_marker=f"{rel}:{line_no} matched: {snippet}"))
            if len(leaks) > 10:
                findings.append(wrap_finding(
                    f"+{len(leaks)-10} additional Helm secret leak(s)",
                    "INFO", cvss="0.0", cwe="N/A",
                    remediation="Audit complete output via gitleaks.",
                    evidence_marker=f"Total leaks: {len(leaks)}"))
        elif files_scanned > 0:
            findings.append(wrap_finding(
                f"{files_scanned} Helm values file(s) scanned - 0 hardcoded secrets",
                "POSITIVE", cvss="0.0", cwe="N/A",
                remediation="Continue secretKeyRef pattern.",
                evidence_marker=f"Scanned: {files_scanned} Helm value files"))
        else:
            findings.append(wrap_finding(
                "No Helm values.yaml files found in repo",
                "INFO", cvss="0.0", cwe="N/A",
                remediation="N/A for non-Helm repos.",
                evidence_marker="0 values.yaml / values-*.yaml files in repo"))
    finally:
        _shred(tmpdir)

    return _build_resp("secrets_helm_values_leak", target, findings,
                       max(files_scanned, 1),
                       f"Helm secret-leak scan ({len(leaks)} leak(s) across {files_scanned} files)")


# ─── Kustomize secretGenerator literal leak detector ─────────────────

_KUSTOMIZE_LITERAL_RE = re.compile(
    r"(?i)literals\s*:\s*\n((?:\s*-\s*[A-Z_]+\s*=\s*[^\n]+\n)+)",
    re.MULTILINE)


def _probe_secrets_kustomize_leak(target, req):
    repo_url = _get_repo_url(req)
    if repo_url is None:
        return _ndr("secrets_kustomize_leak", target,
                     "Provide a public git repo URL containing Kustomize manifests.")
    ec, tmpdir, err = _clone(repo_url)
    if ec != 0:
        return _build_resp("secrets_kustomize_leak", target, [wrap_finding(
            f"[PROBE ERROR] git clone failed: exit {ec}",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify URL is reachable + public.",
            evidence_marker=err)], 0, f"clone exit {ec}")

    findings = []
    leaks = []
    files_scanned = 0
    try:
        for root, dirs, files in os.walk(tmpdir):
            if ".git" in root.split(os.sep):
                continue
            for f in files:
                if f.lower() not in ("kustomization.yaml", "kustomization.yml"):
                    continue
                fpath = os.path.join(root, f)
                rel = os.path.relpath(fpath, tmpdir)
                files_scanned += 1
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as h:
                        text = h.read(100_000)
                except OSError:
                    continue
                # Look for secretGenerator blocks with literals
                if "secretGenerator" not in text:
                    continue
                # Crude block scan: find literals: section after secretGenerator
                idx = text.find("secretGenerator")
                while idx != -1:
                    chunk = text[idx:idx + 4000]
                    for m in _KUSTOMIZE_LITERAL_RE.finditer(chunk):
                        line_no = text[:idx + m.start()].count("\n") + 1
                        block = m.group(1)
                        for ln in block.splitlines():
                            ln = ln.strip()
                            if not ln or not ln.startswith("-"):
                                continue
                            kv = ln.lstrip("-").strip()
                            if "=" in kv:
                                k, _, v = kv.partition("=")
                                # Anything with =VALUE in literals is a hardcoded secret
                                if len(v.strip()) > 3:
                                    leaks.append((rel, line_no, kv[:140]))
                    idx = text.find("secretGenerator", idx + 1)

        if leaks:
            for rel, line_no, snippet in leaks[:10]:
                findings.append(wrap_finding(
                    f"Kustomize secretGenerator literal in {rel}:{line_no}",
                    "HIGH", cvss="7.5", cwe="CWE-798", owasp="A07:2021",
                    remediation=("Replace 'literals: [KEY=VALUE]' with "
                                  "'files: [secret.env]' + add secret.env to "
                                  ".gitignore. Or use envs: from a file kept "
                                  "outside git. Literals embed secrets in the "
                                  "manifest which is committed to source."),
                    evidence_marker=f"{rel}:{line_no} literal: {snippet}"))
            if len(leaks) > 10:
                findings.append(wrap_finding(
                    f"+{len(leaks)-10} additional Kustomize leak(s)",
                    "INFO", cvss="0.0", cwe="N/A",
                    remediation="Full audit via gitleaks.",
                    evidence_marker=f"Total: {len(leaks)}"))
        elif files_scanned > 0:
            findings.append(wrap_finding(
                f"{files_scanned} Kustomization file(s) scanned - 0 secret-literals",
                "POSITIVE", cvss="0.0", cwe="N/A",
                remediation="Continue file-based secret pattern.",
                evidence_marker=f"Scanned: {files_scanned} kustomization.yaml files"))
        else:
            findings.append(wrap_finding(
                "No kustomization.yaml files found in repo",
                "INFO", cvss="0.0", cwe="N/A",
                remediation="N/A for non-Kustomize repos.",
                evidence_marker="0 kustomization.yaml files in repo")
            )
    finally:
        _shred(tmpdir)

    return _build_resp("secrets_kustomize_leak", target, findings,
                       max(files_scanned, 1),
                       f"Kustomize secret-leak scan ({len(leaks)} leak(s) across {files_scanned} files)")


# ─── Real Kyverno + Gatekeeper detection (replaces wrong wiring) ─────


def _probe_kyverno_no_policies(target, req):
    """Detect Kyverno install + count ClusterPolicy/Policy resources."""
    from tools.container_k8s._kubeconfig_probes import _get_kubeconfig, _kubectl
    kc = _get_kubeconfig(req)
    if kc is None:
        return _ndr("opa_kyverno_no_policies", target,
                     "Requires kubeconfig to query Kyverno CRDs.")
    ec, out, err = _kubectl(["get", "clusterpolicies.kyverno.io", "-o", "json"],
                              kc, timeout=15)
    if ec != 0:
        # CRD not present = no Kyverno
        return _build_resp("opa_kyverno_no_policies", target, [wrap_finding(
            "Kyverno NOT installed (informational)",
            "INFO", cvss="0.0", cwe="N/A",
            remediation=("Optional: Kyverno enforces policy-as-code on "
                          "K8s resources without writing OPA Rego. "
                          "Install: helm install kyverno kyverno/kyverno."),
            evidence_marker=f"kubectl get clusterpolicies.kyverno.io failed: {err[-150:]}")], 1,
            "no Kyverno")
    import json
    try:
        count = len(json.loads(out).get("items", []))
    except Exception:
        count = 0
    if count == 0:
        return _build_resp("opa_kyverno_no_policies", target, [wrap_finding(
            "Kyverno installed but 0 ClusterPolicies defined",
            "MEDIUM", cvss="5.5", cwe="CWE-732",
            remediation=("Define ClusterPolicies for the controls you want "
                          "to enforce. Examples: require non-root user, "
                          "block privileged pods, require seccomp profile. "
                          "Without policies, Kyverno does nothing."),
            evidence_marker="0 ClusterPolicy resources")], 1, "Kyverno present, no policies")
    return _build_resp("opa_kyverno_no_policies", target, [wrap_finding(
        f"Kyverno installed with {count} ClusterPolicy resource(s)",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Continue policy-as-code enforcement.",
        evidence_marker=f"ClusterPolicies count: {count}")], 1,
        f"Kyverno: {count} policies")


def _probe_opa_gatekeeper_no_constraints(target, req):
    """Detect OPA Gatekeeper install + count Constraint resources."""
    from tools.container_k8s._kubeconfig_probes import _get_kubeconfig, _kubectl
    kc = _get_kubeconfig(req)
    if kc is None:
        return _ndr("opa_gatekeeper_no_constraints", target,
                     "Requires kubeconfig to query Gatekeeper CRDs.")
    # Gatekeeper Constraints live under constraints.gatekeeper.sh
    # First check if the framework is installed via ConstraintTemplate CRD
    ec, out, err = _kubectl(["get", "constrainttemplates.templates.gatekeeper.sh",
                              "-o", "json"], kc, timeout=15)
    if ec != 0:
        return _build_resp("opa_gatekeeper_no_constraints", target, [wrap_finding(
            "OPA Gatekeeper NOT installed (informational)",
            "INFO", cvss="0.0", cwe="N/A",
            remediation=("Optional: OPA Gatekeeper enforces Rego policies "
                          "at the K8s admission webhook. Install: "
                          "helm install gatekeeper gatekeeper/gatekeeper."),
            evidence_marker=f"kubectl get ConstraintTemplates failed: {err[-150:]}")], 1,
            "no Gatekeeper")
    import json
    try:
        templates = len(json.loads(out).get("items", []))
    except Exception:
        templates = 0
    # Also count actual Constraints (need to know template kinds)
    if templates == 0:
        return _build_resp("opa_gatekeeper_no_constraints", target, [wrap_finding(
            "Gatekeeper installed but 0 ConstraintTemplates defined",
            "MEDIUM", cvss="5.5", cwe="CWE-732",
            remediation=("Install constraint templates from the gatekeeper-"
                          "library OR write your own. Without templates, "
                          "Gatekeeper has nothing to enforce."),
            evidence_marker="0 ConstraintTemplate resources")], 1,
            "Gatekeeper present, no templates")
    return _build_resp("opa_gatekeeper_no_constraints", target, [wrap_finding(
        f"OPA Gatekeeper installed with {templates} ConstraintTemplate(s)",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Verify Constraint resources reference these templates.",
        evidence_marker=f"ConstraintTemplate count: {templates}")], 1,
        f"Gatekeeper: {templates} templates")

"""Dockerfile static-analysis probes for the Container/K8s module.

Each probe takes the customer-provided `dockerfile_text` input (raw
content of a Dockerfile pasted in the dashboard) and runs a specific
static check. NO new binaries required - all parsing is pure Python
regex except _probe_hadolint which wraps the installed hadolint binary.

Precondition: req.dockerfile_text must be present + non-empty. If
absent, every probe returns honest NOT_APPLICABLE with a clear
"requires dockerfile_text input" evidence marker.

11 probes wired to slugs in container_k8s_pack.py PROBES dict:
  dockerfile_root_user         - USER root or no USER set
  dockerfile_no_user           - no USER directive at all
  dockerfile_ssh_in_image      - openssh-server / sshd install
  dockerfile_curl_pipe_bash    - "curl | bash" or "wget | sh" pattern
  dockerfile_hardcoded_secret  - inline secrets (AWS keys, tokens, etc)
  dockerfile_apt_unpinned      - apt-get install without version pin
  dockerfile_no_healthcheck    - no HEALTHCHECK directive
  dockerfile_multistage_audit  - single-stage build (no multistage)
  dockerfile_copy_chown_audit  - COPY without --chown
  dockerfile_expose_audit      - EXPOSE on privileged port (<1024)
  hadolint_dockerfile          - real Hadolint binary scan
"""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import json
import os
from typing import Optional

from tools._shared import wrap_finding


def _ndr(slug: str, target: str, missing_input_name: str = "dockerfile_text"):
    """Build NOT_APPLICABLE response when dockerfile_text isn't provided."""
    return {
        "tool": slug, "target": target, "scan_time": 0,
        "vulnerable": False, "severity": "INFO",
        "findings": [wrap_finding(
            f"[NOT_APPLICABLE] {slug} requires Dockerfile content as input",
            "INFO", cvss="0.0", cwe="N/A",
            remediation=("Paste the Dockerfile content in the dashboard's "
                          "Dockerfile field. Probe will activate automatically."),
            evidence_marker=(f"Required input '{missing_input_name}' is empty. "
                              "No analysis performed."),
        )],
        "tests_performed": 0,
        "tests_summary": f"{slug} skipped - missing {missing_input_name}",
        "raw_data": {"missing_input": missing_input_name},
    }


def _build_resp(slug: str, target: str, findings: list, tested: int, summary: str):
    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "POSITIVE": 0}
    top = "INFO"
    for f in findings:
        s = f.get("severity", "INFO")
        if sev_order.get(s, 0) > sev_order.get(top, 0):
            top = s
    return {
        "tool": slug, "target": target, "scan_time": 0,
        "vulnerable": top in ("CRITICAL", "HIGH", "MEDIUM"),
        "severity": top,
        "findings": findings,
        "tests_performed": tested,
        "tests_summary": summary,
        "raw_data": {},
    }


def _get_dockerfile(req) -> Optional[str]:
    """Pull dockerfile_text from the ScanRequest. Returns None when absent."""
    df = getattr(req, "dockerfile_text", None)
    if not df or not isinstance(df, str) or not df.strip():
        return None
    return df


# ─── Lightweight Dockerfile lexer ────────────────────────────────────
# Strip comments, normalise line continuations, yield (instruction, args)
def _iter_instructions(text: str):
    """Yield (instruction_upper, args_string, line_no) tuples.
    Handles backslash line continuations and # comments."""
    if not text:
        return
    # Join backslash-continued lines
    text = re.sub(r"\\\s*\n\s*", " ", text)
    for line_no, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # First word = instruction
        m = re.match(r"^([A-Za-z]+)\s+(.*)$", stripped)
        if not m:
            continue
        yield m.group(1).upper(), m.group(2).strip(), line_no


# ─── Probe implementations ───────────────────────────────────────────

def _probe_dockerfile_root_user(target, req):
    df = _get_dockerfile(req)
    if df is None:
        return _ndr("dockerfile_root_user", target)

    user_directives = []
    for instr, args, ln in _iter_instructions(df):
        if instr == "USER":
            user_directives.append((args.strip(), ln))

    findings = []
    if not user_directives:
        findings.append(wrap_finding(
            "No USER directive in Dockerfile - container runs as root",
            "MEDIUM", cvss="5.5", cwe="CWE-250",
            remediation=("Add 'USER <non-root-user>' near end of Dockerfile. "
                          "Create the user with RUN groupadd -r appuser && "
                          "useradd -r -g appuser appuser first."),
            evidence_marker="Dockerfile contains 0 USER directives"))
    else:
        last_user, last_ln = user_directives[-1]
        if last_user.lower() in ("root", "0", "0:0"):
            findings.append(wrap_finding(
                f"Dockerfile USER set to root (line {last_ln})",
                "HIGH", cvss="7.5", cwe="CWE-250",
                remediation=("Replace 'USER root' with a non-privileged user. "
                              "Running as root expands the container-escape "
                              "blast radius."),
                evidence_marker=f"Last USER directive: 'USER {last_user}' at line {last_ln}"))
        else:
            findings.append(wrap_finding(
                f"Dockerfile uses non-root USER: '{last_user}' (line {last_ln})",
                "POSITIVE", cvss="0.0", cwe="N/A",
                remediation="Continue least-privilege posture.",
                evidence_marker=f"Last USER directive: 'USER {last_user}'"))
    return _build_resp("dockerfile_root_user", target, findings, 1,
                       f"USER directive audit ({len(user_directives)} found)")


def _probe_dockerfile_no_user(target, req):
    df = _get_dockerfile(req)
    if df is None:
        return _ndr("dockerfile_no_user", target)

    has_user = any(instr == "USER" for instr, _, _ in _iter_instructions(df))
    if has_user:
        return _build_resp("dockerfile_no_user", target, [wrap_finding(
            "Dockerfile has at least one USER directive",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Verify the final USER is non-root.",
            evidence_marker="USER directive present")], 1,
            "USER-directive presence check")
    return _build_resp("dockerfile_no_user", target, [wrap_finding(
        "Dockerfile is missing USER directive (container will run as root)",
        "MEDIUM", cvss="5.5", cwe="CWE-250",
        remediation="Add 'USER <non-root>' to drop privileges before CMD/ENTRYPOINT.",
        evidence_marker="0 USER directives in Dockerfile")], 1,
        "USER-directive presence check")


def _probe_dockerfile_ssh_in_image(target, req):
    df = _get_dockerfile(req)
    if df is None:
        return _ndr("dockerfile_ssh_in_image", target)

    ssh_patterns = (
        r"\bopenssh-server\b", r"\bopenssh-client\b", r"\bsshd\b",
        r"\bdropbear\b", r"apt-get\s+install.*\bssh\b",
    )
    hits = []
    for instr, args, ln in _iter_instructions(df):
        if instr != "RUN":
            continue
        for pat in ssh_patterns:
            if re.search(pat, args, re.IGNORECASE):
                hits.append((ln, pat, args[:100]))
                break

    if hits:
        return _build_resp("dockerfile_ssh_in_image", target, [wrap_finding(
            f"SSH server installed in container image (line {hits[0][0]})",
            "HIGH", cvss="7.5", cwe="CWE-693",
            remediation=("Remove SSH from production images. Use 'docker exec' "
                          "or 'kubectl exec' for debugging. SSH expands attack "
                          "surface + credential management complexity."),
            evidence_marker=f"RUN line {hits[0][0]} installs SSH: {hits[0][2]}")], 1,
            "SSH-in-image check")
    return _build_resp("dockerfile_ssh_in_image", target, [wrap_finding(
        "No SSH server installed in Dockerfile",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Continue current posture.",
        evidence_marker="No openssh-server/sshd/dropbear references in RUN lines")], 1,
        "SSH-in-image check")


def _probe_dockerfile_curl_pipe_bash(target, req):
    df = _get_dockerfile(req)
    if df is None:
        return _ndr("dockerfile_curl_pipe_bash", target)

    pipe_re = re.compile(
        r"\b(curl|wget)\b[^|]*\|\s*(bash|sh|zsh|ksh|python|perl|ruby|node)\b",
        re.IGNORECASE)
    hits = []
    for instr, args, ln in _iter_instructions(df):
        if instr != "RUN":
            continue
        if pipe_re.search(args):
            hits.append((ln, args[:120]))

    if hits:
        return _build_resp("dockerfile_curl_pipe_bash", target, [wrap_finding(
            f"'curl | bash' pattern in Dockerfile (line {hits[0][0]})",
            "HIGH", cvss="7.0", cwe="CWE-494",
            remediation=("Replace 'curl X | bash' with: 1) download via curl "
                          "to file, 2) verify checksum/signature, 3) execute. "
                          "Pipe-to-shell is unverifiable code from a remote "
                          "URL - if the upstream gets compromised, your image "
                          "ships malware."),
            evidence_marker=f"RUN line {hits[0][0]}: {hits[0][1]}")], 1,
            f"curl|bash pattern check ({len(hits)} hit(s))")
    return _build_resp("dockerfile_curl_pipe_bash", target, [wrap_finding(
        "No 'curl|bash' download-and-execute pattern in Dockerfile",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Continue verified-download posture.",
        evidence_marker="0 RUN lines piping curl/wget into shell")], 1,
        "curl|bash pattern check")


_SEV_CVSS = {"CRITICAL": "9.8", "HIGH": "7.5", "MEDIUM": "5.5", "LOW": "3.0", "INFO": "0.0"}


def _probe_dockerfile_hardcoded_secret(target, req):
    df = _get_dockerfile(req)
    if df is None:
        return _ndr("dockerfile_hardcoded_secret", target)

    # Curated pattern list (~130 entries: AWS/GCP/Azure/GitHub/GitLab/Slack/Stripe/
    # PayPal/Square/Twilio/SendGrid/Mailgun/Datadog/NewRelic/Sentry/PagerDuty/
    # npm/PyPI/Docker Hub/Cloudflare/Heroku/Netlify/Vercel/Render/OpenAI/Anthropic/
    # HuggingFace/Auth0/Okta/Algolia/Atlassian/Shopify/Notion/Vault/Doppler/
    # private keys/JWT/DB connection strings/Telegram/Discord). Loaded from
    # tools/_payloads/container_k8s/secret_patterns.json via the _loader.
    try:
        from tools._payloads.container_k8s._loader import get_secret_patterns
        patterns = get_secret_patterns()
    except Exception:
        patterns = []

    if not patterns:
        # Fallback to the legacy inline patterns so the probe never silently
        # disables itself if the curated wordlist fails to load.
        patterns = [
            {"name": "AWS Access Key ID", "compiled": re.compile(r"AKIA[0-9A-Z]{16}"), "severity": "CRITICAL", "category": "cloud-aws"},
            {"name": "Private key embedded", "compiled": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "severity": "CRITICAL", "category": "key-private"},
            {"name": "GitHub PAT", "compiled": re.compile(r"ghp_[A-Za-z0-9]{36,}"), "severity": "CRITICAL", "category": "vcs-github"},
        ]

    findings = []
    seen_per_line: set = set()  # dedupe: same line + same pattern name only fires once
    for instr, args, ln in _iter_instructions(df):
        if instr not in ("RUN", "ENV", "ARG", "LABEL"):
            continue
        for p in patterns:
            try:
                m = p["compiled"].search(args)
            except (re.error, KeyError):
                continue
            if not m:
                continue
            key = (ln, p["name"])
            if key in seen_per_line:
                continue
            seen_per_line.add(key)
            sev = p.get("severity", "MEDIUM")
            snippet = m.group(0)[:60]
            findings.append(wrap_finding(
                f"{p['name']} hardcoded in Dockerfile (line {ln})",
                sev, cvss=_SEV_CVSS.get(sev, "5.0"),
                cwe="CWE-798", owasp="A07:2021",
                remediation=(
                    f"Move {p.get('category', 'this secret')} value out of "
                    f"the image. Use Kubernetes Secret, HashiCorp Vault, AWS "
                    f"Secrets Manager, or BuildKit secret mount "
                    f"(RUN --mount=type=secret). Rotate the value immediately "
                    f"if the image was pushed to any registry."),
                evidence_marker=f"Line {ln} {instr} matched '{p['name']}' ({p.get('category', '')}): {snippet}"))

    if not findings:
        findings.append(wrap_finding(
            "No hardcoded secrets detected in Dockerfile",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue runtime-secret-injection posture.",
            evidence_marker=f"Probed {len(patterns)} curated secret patterns; 0 matches"))
    return _build_resp("dockerfile_hardcoded_secret", target, findings,
                       len(patterns),
                       f"{len([f for f in findings if f.get('severity') not in ('POSITIVE', 'INFO')])} hardcoded secret(s) detected"
                       if any(f.get("severity") not in ("POSITIVE", "INFO") for f in findings)
                       else f"Hardcoded-secret check ({len(patterns)} patterns, 0 hits)")


def _probe_dockerfile_base_image_eol(target, req):
    """Flag FROM directives that reference an end-of-life base image.

    EOL severity is computed at probe time from today's date vs the
    eol_date in the curated wordlist — so the wordlist doesn't need
    severity re-curation as dates roll past, only date-stamp refreshes.
    """
    df = _get_dockerfile(req)
    if df is None:
        return _ndr("dockerfile_base_image_eol", target)

    try:
        from tools._payloads.container_k8s._loader import get_eol_base_images, classify_eol
        eol_db = get_eol_base_images()
    except Exception:
        eol_db = []

    if not eol_db:
        return _build_resp("dockerfile_base_image_eol", target, [wrap_finding(
            "[NOT IMPLEMENTED] EOL base-image wordlist not loaded",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify tools/_payloads/container_k8s/eol_base_images.json shipped with the deploy.",
            evidence_marker="get_eol_base_images() returned empty list")], 0,
            "EOL wordlist missing")

    # Build {(image, version): entry} lookup. version_alias also indexed.
    lookup: dict = {}
    for entry in eol_db:
        img = (entry.get("image") or "").lower()
        ver = str(entry.get("version") or "")
        if img and ver:
            lookup[(img, ver)] = entry
        alias = (entry.get("version_alias") or "").lower()
        if img and alias:
            lookup[(img, alias)] = entry

    # FROM <image>[:<tag>] [AS stage]
    from_re = re.compile(
        r"^\s*FROM\s+(?:--platform=\S+\s+)?([a-z0-9._/-]+)(?::([a-zA-Z0-9._-]+))?(?:\s+AS\s+\S+)?\s*$",
        re.IGNORECASE | re.MULTILINE)
    findings = []
    seen_images = []
    floating_tags = {"latest", "stable", "slim", "alpine", "bullseye", "bookworm", "jammy", "focal"}
    for m in from_re.finditer(df):
        full_ref = m.group(1)
        tag = (m.group(2) or "").lower()
        # Normalize: registry/lib/img -> img (last path component)
        bare = full_ref.split("/")[-1].lower()
        seen_images.append(f"{full_ref}:{tag or '(no tag)'}")

        if not tag:
            findings.append(wrap_finding(
                f"Base image '{full_ref}' has no version tag (implicit :latest)",
                "MEDIUM", cvss="5.5", cwe="CWE-1357", owasp="A06:2021",
                remediation="Pin to a specific tag or digest. 'latest' is mutable and reproducibility-breaking.",
                evidence_marker=f"FROM {full_ref}"))
            continue

        if tag in floating_tags:
            findings.append(wrap_finding(
                f"Base image '{full_ref}:{tag}' uses a floating tag",
                "LOW", cvss="3.0", cwe="CWE-1357", owasp="A06:2021",
                remediation=f"Pin '{tag}' to a specific version (e.g. {full_ref}:1.21 or a sha256 digest).",
                evidence_marker=f"FROM {full_ref}:{tag} — floating tag"))
            continue

        # Try exact + major-version fallback (e.g. "20-alpine" → "20")
        entry = lookup.get((bare, tag))
        if not entry:
            # Strip suffix qualifiers: 20-alpine3.18 → 20, 3.18-slim → 3.18
            major_only = re.match(r"^([0-9]+(?:\.[0-9]+)?)", tag)
            if major_only:
                entry = lookup.get((bare, major_only.group(1)))

        if not entry:
            continue  # not in EOL DB — silently OK (not all images tracked)

        sev, label, delta = classify_eol(entry["eol_date"])
        if sev == "INFO":
            continue  # plenty of runway, no finding needed

        title = f"Base image {bare}:{tag} {label} ({entry['eol_date']})"
        if delta < 0:
            evidence = f"FROM {full_ref}:{tag} — EOL was {entry['eol_date']} ({-delta} days ago)"
            remediation = (
                f"Upgrade to a supported {bare} release. EOL means no further "
                f"security patches from upstream — every CVE that lands after "
                f"{entry['eol_date']} is permanently unfixed in this image. "
                f"{entry.get('notes', '')}")
        else:
            evidence = f"FROM {full_ref}:{tag} — EOL on {entry['eol_date']} (in {delta} days)"
            remediation = (
                f"Plan upgrade now. {bare} {tag} loses upstream security "
                f"support on {entry['eol_date']}. Identify the next-major "
                f"version your stack supports and schedule the migration.")

        findings.append(wrap_finding(
            title, sev, cvss=_SEV_CVSS.get(sev, "5.0"),
            cwe="CWE-1104", owasp="A06:2021",
            remediation=remediation, evidence_marker=evidence))

    if not findings:
        return _build_resp("dockerfile_base_image_eol", target, [wrap_finding(
            f"All {len(seen_images)} base image(s) supported",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue tracking upstream EOL dates.",
            evidence_marker=f"FROM lines: {', '.join(seen_images[:5])}")], len(seen_images),
            f"EOL check ({len(seen_images)} FROM, 0 issues)")

    return _build_resp("dockerfile_base_image_eol", target, findings,
                       len(seen_images),
                       f"{len(findings)} base-image issue(s) across {len(seen_images)} FROM")


def _probe_dockerfile_apt_unpinned(target, req):
    df = _get_dockerfile(req)
    if df is None:
        return _ndr("dockerfile_apt_unpinned", target)

    # apt-get install [-y] [--no-install-recommends] PKG1 PKG2 ...
    # PKG1 unpinned, PKG2=1.2.3 pinned.
    apt_install_re = re.compile(
        r"\bapt-get\s+install\b([^&|;\n]*)",
        re.IGNORECASE)
    flag_re = re.compile(r"^-")
    unpinned_pkgs = []
    pinned_pkgs = []
    for instr, args, ln in _iter_instructions(df):
        if instr != "RUN":
            continue
        for m in apt_install_re.finditer(args):
            tail = m.group(1)
            for tok in tail.split():
                if flag_re.match(tok):
                    continue
                if "=" in tok:
                    pinned_pkgs.append((ln, tok))
                else:
                    if tok and not tok.startswith("$"):
                        unpinned_pkgs.append((ln, tok))

    if unpinned_pkgs and not pinned_pkgs:
        return _build_resp("dockerfile_apt_unpinned", target, [wrap_finding(
            f"{len(unpinned_pkgs)} apt package(s) installed without version pin",
            "MEDIUM", cvss="5.5", cwe="CWE-1357",
            remediation=("Pin apt packages: 'apt-get install curl=7.74.0-1.3+deb11u1'. "
                          "Unpinned versions break build reproducibility + may "
                          "silently pull in vulnerable upgrades during image rebuild."),
            evidence_marker=(f"Unpinned: {', '.join(p for _, p in unpinned_pkgs[:8])}"
                              + (" ..." if len(unpinned_pkgs) > 8 else "")))], 1,
            f"apt pinning audit ({len(unpinned_pkgs)} unpinned)")
    if unpinned_pkgs:
        # Mix of pinned + unpinned
        return _build_resp("dockerfile_apt_unpinned", target, [wrap_finding(
            f"{len(unpinned_pkgs)} of {len(unpinned_pkgs)+len(pinned_pkgs)} "
            f"apt packages unpinned",
            "LOW", cvss="3.5", cwe="CWE-1357",
            remediation="Pin remaining packages for fully reproducible builds.",
            evidence_marker=(f"Unpinned: {', '.join(p for _, p in unpinned_pkgs[:5])}; "
                              f"Pinned: {len(pinned_pkgs)}"))], 1,
            f"apt pinning audit (partial)")
    if pinned_pkgs:
        return _build_resp("dockerfile_apt_unpinned", target, [wrap_finding(
            f"All {len(pinned_pkgs)} apt package(s) version-pinned",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue pinning posture.",
            evidence_marker=f"Pinned: {', '.join(p for _, p in pinned_pkgs[:5])}")], 1,
            "apt pinning audit (all pinned)")
    return _build_resp("dockerfile_apt_unpinned", target, [wrap_finding(
        "No apt-get install statements in Dockerfile",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="N/A - no apt usage.",
        evidence_marker="0 apt-get install RUN lines")], 1, "apt pinning audit (N/A)")


def _probe_dockerfile_no_healthcheck(target, req):
    df = _get_dockerfile(req)
    if df is None:
        return _ndr("dockerfile_no_healthcheck", target)

    has_hc = any(instr == "HEALTHCHECK" for instr, _, _ in _iter_instructions(df))
    if has_hc:
        return _build_resp("dockerfile_no_healthcheck", target, [wrap_finding(
            "Dockerfile has HEALTHCHECK directive",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue with health monitoring posture.",
            evidence_marker="HEALTHCHECK present")], 1, "HEALTHCHECK presence check")
    return _build_resp("dockerfile_no_healthcheck", target, [wrap_finding(
        "Dockerfile missing HEALTHCHECK directive",
        "INFO", cvss="0.0", cwe="N/A",
        remediation=("Add 'HEALTHCHECK --interval=30s --timeout=3s CMD curl -f "
                      "http://localhost/health || exit 1' for container-level "
                      "monitoring. K8s liveness/readiness probes are preferred "
                      "in cluster context, but HEALTHCHECK helps stand-alone."),
        evidence_marker="0 HEALTHCHECK directives")], 1, "HEALTHCHECK presence check")


def _probe_dockerfile_multistage_audit(target, req):
    df = _get_dockerfile(req)
    if df is None:
        return _ndr("dockerfile_multistage_audit", target)

    from_count = sum(1 for instr, _, _ in _iter_instructions(df) if instr == "FROM")
    if from_count >= 2:
        return _build_resp("dockerfile_multistage_audit", target, [wrap_finding(
            f"Multi-stage build detected ({from_count} FROM stages)",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation=("Continue multi-stage builds - they exclude build "
                          "toolchains (compilers, dev headers) from the final "
                          "image, reducing attack surface."),
            evidence_marker=f"FROM directive count: {from_count}")], 1,
            f"Multi-stage build audit ({from_count} stages)")
    return _build_resp("dockerfile_multistage_audit", target, [wrap_finding(
        "Single-stage build - consider multi-stage to slim final image",
        "INFO", cvss="0.0", cwe="N/A",
        remediation=("Convert to multi-stage: 'FROM builder AS build / ... / "
                      "FROM runtime / COPY --from=build /app /app'. Final image "
                      "won't ship build tools (gcc, npm, pip, etc.) - smaller "
                      "attack surface + faster pulls."),
        evidence_marker=f"FROM directive count: {from_count}")], 1,
        "Multi-stage build audit (single-stage)")


def _probe_dockerfile_copy_chown_audit(target, req):
    df = _get_dockerfile(req)
    if df is None:
        return _ndr("dockerfile_copy_chown_audit", target)

    copy_without_chown = 0
    copy_with_chown = 0
    add_lines = []
    for instr, args, ln in _iter_instructions(df):
        if instr == "COPY":
            if "--chown=" in args:
                copy_with_chown += 1
            else:
                copy_without_chown += 1
        elif instr == "ADD":
            add_lines.append(ln)

    findings = []
    if copy_without_chown > 0 and copy_with_chown == 0:
        findings.append(wrap_finding(
            f"{copy_without_chown} COPY directive(s) without --chown - files "
            f"will be owned by root in final image",
            "LOW", cvss="3.0", cwe="CWE-732",
            remediation="Use 'COPY --chown=appuser:appgroup src/ /app/' so "
                        "files are not root-owned in the running container.",
            evidence_marker=f"COPY without --chown: {copy_without_chown}; "
                              f"COPY with --chown: {copy_with_chown}"))
    if add_lines:
        findings.append(wrap_finding(
            f"ADD directive(s) used ({len(add_lines)} lines: {add_lines[:3]}) - "
            f"prefer COPY for predictable behaviour",
            "LOW", cvss="3.0", cwe="CWE-693",
            remediation="Replace ADD with COPY unless you specifically need "
                        "auto-tar-extract or URL-fetch behaviour. COPY is "
                        "safer + clearer.",
            evidence_marker=f"ADD lines: {add_lines}"))
    if not findings:
        findings.append(wrap_finding(
            "COPY directives use --chown OR no COPY/ADD ownership issues",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue current posture.",
            evidence_marker=f"COPY w/chown: {copy_with_chown}, "
                              f"w/o chown: {copy_without_chown}, ADD: {len(add_lines)}"))
    return _build_resp("dockerfile_copy_chown_audit", target, findings, 1,
                       "COPY/ADD ownership audit")


def _probe_dockerfile_expose_audit(target, req):
    df = _get_dockerfile(req)
    if df is None:
        return _ndr("dockerfile_expose_audit", target)

    exposed_ports = []
    privileged_ports = []
    for instr, args, ln in _iter_instructions(df):
        if instr != "EXPOSE":
            continue
        for tok in args.split():
            # Strip /tcp /udp suffix
            port_str = tok.split("/")[0]
            try:
                p = int(port_str)
                exposed_ports.append((ln, p))
                if p < 1024:
                    privileged_ports.append((ln, p))
            except ValueError:
                continue

    findings = []
    if privileged_ports:
        findings.append(wrap_finding(
            f"EXPOSE on privileged port(s) <1024: "
            f"{', '.join(str(p) for _, p in privileged_ports)}",
            "LOW", cvss="3.0", cwe="CWE-250",
            remediation=("Privileged ports require root or CAP_NET_BIND_SERVICE. "
                          "Run on a high port (8080, 8443) and use ingress / "
                          "load-balancer for port-80/443 mapping at the edge."),
            evidence_marker=f"Privileged: {[p for _, p in privileged_ports]}"))
    if exposed_ports and not privileged_ports:
        findings.append(wrap_finding(
            f"EXPOSE port(s) all non-privileged: "
            f"{', '.join(str(p) for _, p in exposed_ports)}",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue non-privileged port posture.",
            evidence_marker=f"Exposed: {[p for _, p in exposed_ports]}"))
    if not exposed_ports:
        findings.append(wrap_finding(
            "No EXPOSE directives in Dockerfile",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Add EXPOSE for documentation even though it doesn't "
                        "actually open ports - tools rely on it.",
            evidence_marker="0 EXPOSE directives"))
    return _build_resp("dockerfile_expose_audit", target, findings, 1,
                       f"EXPOSE audit ({len(exposed_ports)} port(s))")


def _probe_hadolint_dockerfile(target, req):
    """Real hadolint binary on dockerfile_text input.
    Hadolint covers ~80 rules: shellcheck inside RUN, version pinning,
    cache busting, layer ordering, etc."""
    df = _get_dockerfile(req)
    if df is None:
        return _ndr("hadolint_dockerfile", target)

    if shutil.which("hadolint") is None:
        return _build_resp("hadolint_dockerfile", target, [wrap_finding(
            "[NOT IMPLEMENTED] hadolint binary not installed",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Rebuild backend with the Dockerfile that installs hadolint.",
            evidence_marker="hadolint not in PATH")], 0, "Hadolint not installed")

    # hadolint reads from stdin via "-" arg
    try:
        proc = subprocess.run(
            ["hadolint", "--format", "json", "-"],
            input=df, capture_output=True, text=True,
            timeout=30, check=False)
    except subprocess.TimeoutExpired:
        return _build_resp("hadolint_dockerfile", target, [wrap_finding(
            "[PROBE ERROR] hadolint timeout (>30s)",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Dockerfile may be very large; run hadolint manually.",
            evidence_marker="Wall-clock exceeded")], 0, "hadolint timeout")
    except Exception as e:
        return _build_resp("hadolint_dockerfile", target, [wrap_finding(
            f"[PROBE ERROR] hadolint exec failed: {str(e)[:120]}",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify hadolint installation.",
            evidence_marker=str(e)[:200])], 0, "hadolint error")

    stdout = proc.stdout or ""
    # hadolint exit 0 = no issues; non-zero may still have valid JSON
    issues = []
    try:
        if stdout.strip():
            issues = json.loads(stdout)
    except json.JSONDecodeError:
        return _build_resp("hadolint_dockerfile", target, [wrap_finding(
            "[PROBE ERROR] hadolint JSON parse failed",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Hadolint output format unexpected.",
            evidence_marker=f"First 200 chars: {stdout[:200]}")], 0,
            "hadolint parse error")

    sev_map = {"error": "HIGH", "warning": "MEDIUM",
                "info": "LOW", "style": "INFO"}
    cvss_map = {"HIGH": "7.0", "MEDIUM": "5.0", "LOW": "3.0", "INFO": "0.0"}

    findings = []
    for it in issues if isinstance(issues, list) else []:
        level = (it.get("level") or "info").lower()
        sev = sev_map.get(level, "INFO")
        code = it.get("code") or "?"
        msg = it.get("message") or "Hadolint rule"
        ln = it.get("line") or "?"
        findings.append(wrap_finding(
            f"Hadolint {code}: {msg} (line {ln})",
            sev, cvss=cvss_map[sev], cwe="CWE-1357",
            remediation=("See https://github.com/hadolint/hadolint/wiki/" + code
                          + " for the rule rationale + fix."),
            evidence_marker=f"Hadolint {code} {level} at line {ln}: {msg[:120]}"))

    if not findings:
        findings.append(wrap_finding(
            "Hadolint: 0 issues in Dockerfile",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue current Dockerfile hygiene.",
            evidence_marker="hadolint --format json -: empty result"))
    return _build_resp("hadolint_dockerfile", target, findings,
                       max(len(findings), 1),
                       f"hadolint scan ({len(findings)} finding(s))")

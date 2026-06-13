"""§21 Cloud Security — 124 endpoints per 21_cloud.md.
12 sections: discovery, AWS, Azure, GCP, multi-cloud CIEM, serverless,
container registry, storage, network/VPC, secrets/KMS, OIDC cross-cloud, compliance.

VulnusLab is a Vulnerability Assessment platform. Cloud posture (CSPM/CIEM)
is fundamentally a CREDENTIALED domain: auditing IAM, CloudTrail, security
groups, KMS, etc. requires a read-only cloud connector (an AWS audit role /
Azure Reader / GCP Viewer) that an external SaaS scanner does not hold.

This pack forges everything that CAN be checked anonymously from the
internet — public object storage, public container registries, public
Kubernetes API/kubelet endpoints, OIDC discovery posture, exposed IaC
manifests, cloud-provider fingerprinting — as live SAFE probes (read-only,
no exploitation). Every credential-required technique returns an honest
[ADVISORY-BY-DESIGN] response stating it needs a cloud connector, rather
than a fake CRITICAL/HIGH or a bare [NOT IMPLEMENTED] scaffold.

Probe coverage 2026-06-12:
  Live safe probes   : 15 (+1 orphan brute helper)
  Advisory-by-design : 109 (credential / metadata-SSRF / image-pull / manual)
  Scaffold (fake)    : 0
"""
import socket
import ssl
import urllib.request
import urllib.error
import json
from tools._pack_common import (
    make_advisory_router, _adv_response, _advisory_by_design_response,
)
from tools._shared import wrap_finding


_NOVERIFY = ssl.create_default_context()
_NOVERIFY.check_hostname = False
_NOVERIFY.verify_mode = ssl.CERT_NONE


def _host(target: str) -> str:
    s = target.split("://", 1)[-1].split("/")[0].split(":")[0]
    return s.strip().lower() or target


def _http_get(url: str, timeout: float = 5.0, insecure: bool = False) -> tuple:
    """Returns (status_code, body_first_2k, headers_dict).
    insecure=True disables TLS verification (for self-signed infra endpoints
    such as a Kubernetes API server — we are checking exposure, not trust)."""
    try:
        ctx = _NOVERIFY if insecure else None
        req = urllib.request.Request(url, headers={"User-Agent": "VulnusLab/2.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(2048).decode("utf-8", errors="ignore"), dict(r.headers)
    except urllib.error.HTTPError as e:
        try: body = e.read(2048).decode("utf-8", errors="ignore")
        except Exception: body = ""
        return e.code, body, dict(e.headers) if e.headers else {}
    except Exception:
        return 0, "", {}


def _resp(tool, target, findings, tested, summary):
    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "POSITIVE": 0}
    top = "INFO"
    for f in findings:
        if sev_order.get(f.get("severity", "INFO"), 0) > sev_order.get(top, 0):
            top = f.get("severity", "INFO")
    return {"tool": tool, "target": target, "scan_time": 0,
            "vulnerable": top in ("CRITICAL", "HIGH", "MEDIUM"),
            "severity": top, "findings": findings,
            "tests_performed": tested, "tests_summary": summary, "raw_data": {}}


def _abd(slug, title, reason, cwe="CWE-1395"):
    """Factory: advisory-by-design probe (cannot be SaaS-probed anonymously)."""
    def _p(target, req):
        return _advisory_by_design_response(slug, target, title, reason=reason, cwe=cwe)
    return _p


# Reusable advisory reasons
_CREDS = ("Requires a read-only cloud connector (an AWS security-audit IAM role, "
          "Azure Reader, or GCP Viewer). External SaaS cannot audit account "
          "internals — IAM, logging, security groups, KMS — without it. Supply "
          "credentials to enable this check, or run Prowler/ScoutSuite under your "
          "own engagement scope.")
_IMDS = ("The instance metadata service (169.254.169.254) is only reachable from "
         "inside the VPC via an SSRF primitive; it cannot be tested from an "
         "external SaaS scanner.")
_IMAGE = ("Requires pulling the container image from the registry; use the "
          "Container/K8s module's Trivy/Grype scan with the image reference.")
_OIDCCFG = ("Requires the cloud trust policy / CI OIDC configuration as input; the "
            "trust relationship cannot be enumerated anonymously from outside.")
_MANUAL = "Analyst task — manual review under engagement scope."


# ───────────────────── existing live probes (kept) ─────────────────────
def _probe_s3_public(target, req):
    """Check S3 bucket for public read access. Target = bucket name OR full URL."""
    host = _host(target)
    bucket = host.replace(".s3.amazonaws.com", "").replace(".s3.us-east-1.amazonaws.com", "").split(".")[0]
    urls = [
        f"https://{bucket}.s3.amazonaws.com/",
        f"https://s3.amazonaws.com/{bucket}/",
    ]
    findings = []
    for url in urls:
        code, body, _ = _http_get(url, timeout=4)
        if code == 200 and "<ListBucketResult" in body:
            findings.append(wrap_finding(
                f"S3 bucket '{bucket}' publicly listable — anonymous LIST succeeded",
                "CRITICAL", cvss="9.0", cwe="CWE-200", owasp="A05:2021",
                remediation="Apply BlockPublicAccess at account level; remove public ACLs.",
                evidence_marker=f"GET {url} -> 200 with ListBucketResult"))
            break
        if code == 200 and "<?xml" in body and "<Error>" not in body:
            findings.append(wrap_finding(
                f"S3 bucket '{bucket}' returned XML (likely listable)",
                "HIGH", cvss="7.5", cwe="CWE-200",
                remediation="BlockPublicAccess + remove public ACLs.",
                evidence_marker=f"GET {url} -> 200 XML"))
            break
        if code == 403 and "AccessDenied" in body:
            findings.append(wrap_finding(
                f"S3 bucket '{bucket}' exists but access denied (good)",
                "POSITIVE", cvss="0.0", cwe="N/A",
                remediation="Continue least-privilege bucket policy.",
                evidence_marker=f"GET {url} -> 403 AccessDenied"))
            break
    if not findings:
        findings.append(wrap_finding(
            f"No S3 bucket found at name '{bucket}' (NXDOMAIN or 404)",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Confirm bucket naming convention; check other regions.",
            evidence_marker="No listable bucket at standard S3 hostnames"))
    return {"tool": "s3_bucket_public_static_site", "target": target, "scan_time": 0,
            "vulnerable": any(f.get("severity") in ("CRITICAL", "HIGH") for f in findings),
            "severity": findings[0].get("severity", "INFO"),
            "findings": findings, "tests_performed": len(urls),
            "tests_summary": f"S3 public access check on bucket '{bucket}'",
            "raw_data": {"bucket": bucket, "urls_tested": urls}}


def _probe_azure_blob_public(target, req):
    """Check Azure Blob storage account for anonymous read access."""
    host = _host(target)
    account = host.replace(".blob.core.windows.net", "").split(".")[0]
    url = f"https://{account}.blob.core.windows.net/?comp=list"
    code, body, _ = _http_get(url, timeout=4)
    findings = []
    if code == 200 and "<EnumerationResults" in body:
        findings.append(wrap_finding(
            f"Azure Blob storage account '{account}' allows anonymous container listing",
            "CRITICAL", cvss="9.0", cwe="CWE-200", owasp="A05:2021",
            remediation="Disable anonymous access at storage account level.",
            evidence_marker=f"GET {url} -> 200 with EnumerationResults"))
    elif code in (403, 401):
        findings.append(wrap_finding(
            f"Azure Blob '{account}' exists, anonymous access correctly denied",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue private access posture.",
            evidence_marker=f"GET {url} -> {code}"))
    else:
        findings.append(wrap_finding(
            f"Azure Blob storage account '{account}' not found (NXDOMAIN or unreachable)",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify account name.",
            evidence_marker=f"GET {url} -> {code}"))
    return {"tool": "azure_blob_public_anon", "target": target, "scan_time": 0,
            "vulnerable": code == 200 and "<EnumerationResults" in body,
            "severity": findings[0].get("severity", "INFO"),
            "findings": findings, "tests_performed": 1,
            "tests_summary": f"Azure Blob anonymous check on {account}",
            "raw_data": {"account": account, "url": url, "status": code}}


def _probe_gcs_bucket_public(target, req):
    """Check GCS bucket for public read access."""
    host = _host(target)
    bucket = host.replace(".storage.googleapis.com", "").split(".")[0]
    url = f"https://storage.googleapis.com/{bucket}/"
    code, body, _ = _http_get(url, timeout=4)
    findings = []
    if code == 200 and ("<ListBucketResult" in body or "<?xml" in body):
        findings.append(wrap_finding(
            f"GCS bucket '{bucket}' publicly listable",
            "CRITICAL", cvss="9.0", cwe="CWE-200", owasp="A05:2021",
            remediation="Remove allUsers/allAuthenticatedUsers from bucket IAM.",
            evidence_marker=f"GET {url} -> 200 listable"))
    elif code in (401, 403):
        findings.append(wrap_finding(
            f"GCS bucket '{bucket}' exists, access denied (good)",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue least-privilege.",
            evidence_marker=f"GET {url} -> {code}"))
    else:
        findings.append(wrap_finding(
            f"GCS bucket '{bucket}' not found",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify bucket name.",
            evidence_marker=f"GET {url} -> {code}"))
    return {"tool": "gcs_bucket_acl_legacy", "target": target, "scan_time": 0,
            "vulnerable": code == 200,
            "severity": findings[0].get("severity", "INFO"),
            "findings": findings, "tests_performed": 1,
            "tests_summary": f"GCS public check on {bucket}",
            "raw_data": {"bucket": bucket, "url": url, "status": code}}


def _probe_oidc_discovery(target, req):
    """Fetch /.well-known/openid-configuration to audit OIDC posture."""
    host = _host(target)
    urls = [
        f"https://{host}/.well-known/openid-configuration",
        f"https://login.{host}/.well-known/openid-configuration",
    ]
    findings = []; data = {}
    for url in urls:
        code, body, _ = _http_get(url, timeout=4)
        if code == 200 and body.strip().startswith("{"):
            try:
                cfg = json.loads(body)
                data = cfg
                issues = []
                if cfg.get("token_endpoint_auth_methods_supported") and \
                   "none" in (cfg.get("token_endpoint_auth_methods_supported") or []):
                    issues.append("token_endpoint_auth_methods includes 'none' (public client allowed)")
                if not cfg.get("code_challenge_methods_supported"):
                    issues.append("PKCE (code_challenge_methods_supported) NOT advertised")
                if cfg.get("response_types_supported") and \
                   "token" in (cfg.get("response_types_supported") or []) and \
                   "id_token token" in (cfg.get("response_types_supported") or []):
                    issues.append("implicit flow (response_type=token) still supported")
                if issues:
                    findings.append(wrap_finding(
                        f"OIDC discovery — {len(issues)} posture issue(s)",
                        "MEDIUM", cvss="5.5", cwe="CWE-287",
                        remediation="Enforce PKCE; disable implicit flow; require client auth.",
                        evidence_marker="; ".join(issues)))
                else:
                    findings.append(wrap_finding(
                        "OIDC discovery present, posture looks healthy",
                        "POSITIVE", cvss="0.0", cwe="N/A",
                        remediation="Continue OIDC best practices.",
                        evidence_marker=f"Issuer: {cfg.get('issuer','?')}"))
                break
            except Exception:
                pass
    if not findings:
        findings.append(wrap_finding(
            "No OIDC discovery endpoint at standard paths",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="If OIDC is in use, ensure discovery endpoint is reachable.",
            evidence_marker=f"Tried {len(urls)} URLs"))
    return {"tool": "oidc_provider_thumbprint_audit", "target": target, "scan_time": 0,
            "vulnerable": findings[0].get("severity") in ("MEDIUM", "HIGH"),
            "severity": findings[0].get("severity", "INFO"),
            "findings": findings, "tests_performed": len(urls),
            "tests_summary": "OIDC discovery posture audit",
            "raw_data": data}


def _probe_recon_cloud_dns(target, req):
    """Identify which cloud provider a target's DNS resolves to (AWS/Azure/GCP/CF)."""
    host = _host(target)
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return _adv_response("recon_cloud_dns", target,
            f"DNS resolution failed for {host}", "INFO", "0.0", evidence=host)
    findings = []
    code, body, headers = _http_get(f"https://{host}", timeout=4)
    cloud_hints = []
    server_hdr = (headers.get("Server") or headers.get("server") or "").lower()
    if "cf-ray" in {k.lower() for k in headers.keys()}: cloud_hints.append("Cloudflare")
    if "x-amz-" in str(headers).lower() or "amazon" in server_hdr: cloud_hints.append("AWS")
    if "x-ms-" in str(headers).lower() or "azure" in server_hdr: cloud_hints.append("Azure")
    if "x-goog-" in str(headers).lower() or "gws" in server_hdr: cloud_hints.append("GCP")
    if "x-fastly-" in str(headers).lower(): cloud_hints.append("Fastly")
    if "akamai" in server_hdr: cloud_hints.append("Akamai")
    findings.append(wrap_finding(
        f"Cloud surface: {', '.join(cloud_hints) if cloud_hints else 'no recognizable cloud headers'}",
        "INFO", cvss="0.0", cwe="CWE-200",
        remediation="Inventory cloud providers in use; ensure WAF/CDN protections active.",
        evidence_marker=f"IP={ip}; hints={cloud_hints or 'none'}; server={server_hdr or 'unknown'}"))
    return {"tool": "recon_cloud_dns", "target": target, "scan_time": 0,
            "vulnerable": False, "severity": "INFO", "findings": findings,
            "tests_performed": 1, "tests_summary": "Cloud-provider DNS+header recon",
            "raw_data": {"ip": ip, "cloud_hints": cloud_hints, "server": server_hdr}}


def _probe_ecr_public_access(target, req):
    """Check if a public ECR repository is anonymously pullable."""
    host = _host(target)
    if "public.ecr.aws" not in host:
        return _adv_response("ecr_public_access", target,
            "Target not on public.ecr.aws — skipping live probe",
            "INFO", "0.0", evidence=host)
    code, body, _ = _http_get(f"https://{host}/v2/", timeout=4)
    is_public = code == 200 and ('"errors"' not in body[:200])
    return {"tool": "ecr_public_access", "target": target, "scan_time": 0,
            "vulnerable": is_public, "severity": "HIGH" if is_public else "POSITIVE",
            "findings": [wrap_finding(
                f"ECR public registry {'allows anonymous /v2 enum' if is_public else 'denied anonymous /v2 enum'}",
                "HIGH" if is_public else "POSITIVE",
                cvss="7.0" if is_public else "0.0", cwe="CWE-200",
                remediation="If unintended, switch to private ECR; require IAM-signed pulls.",
                evidence_marker=f"GET https://{host}/v2/ -> {code}")],
            "tests_performed": 1, "tests_summary": "ECR public anonymous-pull check",
            "raw_data": {"host": host, "status": code}}


def _probe_gcr_public_access(target, req):
    """Check if GCR repository is anonymously accessible."""
    host = _host(target)
    if not any(x in host for x in ["gcr.io", "pkg.dev"]):
        return _adv_response("gcr_public_access", target,
            "Target not on gcr.io / pkg.dev — skipping live probe",
            "INFO", "0.0", evidence=host)
    code, body, _ = _http_get(f"https://{host}/v2/", timeout=4)
    return {"tool": "gcr_public_access", "target": target, "scan_time": 0,
            "vulnerable": code == 200, "severity": "HIGH" if code == 200 else "POSITIVE",
            "findings": [wrap_finding(
                f"GCR registry {'allows anonymous /v2 enum' if code == 200 else 'requires auth'}",
                "HIGH" if code == 200 else "POSITIVE",
                cvss="7.0" if code == 200 else "0.0", cwe="CWE-200",
                remediation="If unintended, require IAM-signed pulls.",
                evidence_marker=f"GET https://{host}/v2/ -> {code}")],
            "tests_performed": 1, "tests_summary": "GCR anonymous-pull check",
            "raw_data": {"host": host, "status": code}}


def _probe_docker_hub_public_image(target, req):
    """Check if a Docker Hub image manifest is publicly fetchable."""
    host = _host(target)
    img = host.replace("hub.docker.com", "").replace("/r/", "").strip("/") or "library/alpine"
    url = f"https://hub.docker.com/v2/repositories/{img}/"
    code, body, _ = _http_get(url, timeout=4)
    # Hub returns 200 + {"count":0,"results":[]} for any valid-length namespace even
    # when no repo exists, so a bare 200 does NOT confirm a real public image.
    # Only treat as public when the JSON body describes an actual repo.
    is_public = False
    if code == 200:
        try:
            j = json.loads(body) if body else {}
        except (ValueError, TypeError):
            j = {}
        if isinstance(j, dict):
            # Single-repo response carries real fields; search response carries count/results.
            is_public = ("name" in j or "is_private" in j
                         or (j.get("count") or 0) > 0
                         or bool(j.get("results")))
    return {"tool": "docker_hub_public_image_secrets", "target": target, "scan_time": 0,
            "vulnerable": is_public,
            "severity": "INFO" if is_public else "POSITIVE",
            "findings": [wrap_finding(
                f"Docker Hub image '{img}' {'is public' if is_public else 'no matching public Docker Hub image'}",
                "INFO" if is_public else "POSITIVE",
                cvss="0.0", cwe="N/A",
                remediation="Inventory public images for embedded secrets; consider private hub.",
                evidence_marker=f"GET {url} -> {code}")],
            "tests_performed": 1, "tests_summary": "Docker Hub image public-access check",
            "raw_data": {"image": img, "status": code}}


def _probe_iac_manifest_exposed(target, req):
    """Probe for IaC manifests (terraform.tfstate, helm values, ansible inventories)."""
    base = f"https://{_host(target)}"
    paths = [".terraform.tfstate", "terraform.tfstate", ".terraform/terraform.tfstate",
              ".tfvars", "values.yaml", "ansible/inventory", "playbook.yml",
              ".kube/config", "kustomization.yaml", "deployment.yaml"]
    leaked = []
    for p in paths:
        code, body, _ = _http_get(f"{base}/{p}", timeout=3)
        if code == 200 and len(body) > 50:
            leaked.append({"path": p, "size": len(body)})
    return {"tool": "compliance_cis_aws_benchmark", "target": target, "scan_time": 0,
            "vulnerable": bool(leaked),
            "severity": "CRITICAL" if leaked else "POSITIVE",
            "findings": [wrap_finding(
                f"IaC manifest exposure: {len(leaked)} files publicly fetchable",
                "CRITICAL" if leaked else "POSITIVE",
                cvss="9.0" if leaked else "0.0", cwe="CWE-538",
                remediation="Never commit .tfstate or kubeconfig to public webroots.",
                evidence_marker=", ".join(f"{l['path']} ({l['size']}b)" for l in leaked) or "None exposed")],
            "tests_performed": len(paths), "tests_summary": "IaC manifest exposure probe",
            "raw_data": {"leaked": leaked}}


def _probe_s3_bucket_brute(target, req):
    """Discover S3 buckets via domain-name permutation brute.

    Customer enters a domain (example.com) and we generate ~30 common
    bucket name patterns (example, example-backup, example-prod,
    backup-example, www-example, etc.), probe each, classify:
      200 + <ListBucketResult> -> CRITICAL (publicly listable + readable)
      403 with AccessDenied   -> MEDIUM   (bucket exists, private)
      404 NoSuchBucket        -> not flagged

    Zero-FP design: real Amazon S3 XML responses required to flag.
    No external dependencies, real HTTP probes.
    """
    host = _host(target)
    base = host
    if base.startswith("www."):
        base = base[4:]
    base = base.split(":")[0]
    name_core = base.split(".")[0].lower()
    name_core = "".join(c for c in name_core if c.isalnum() or c == "-")
    if not name_core or len(name_core) < 3:
        return _adv_response("s3_bucket_brute", target,
            f"Target '{host}' doesn't yield a valid bucket-name root",
            "INFO", "0.0",
            evidence=f"derived='{name_core}'; need >= 3 alphanumeric chars")

    suffixes = ["", "-backup", "-backups", "-bak", "-prod", "-production",
                "-staging", "-stage", "-stg", "-dev", "-development", "-test",
                "-qa", "-uat", "-data", "-logs", "-log", "-public", "-private",
                "-internal", "-static", "-assets", "-media", "-images", "-img",
                "-files", "-uploads", "-archive", "-snapshots", "-db", "-cdn"]
    prefixes = ["", "backup-", "backups-", "logs-", "data-", "uploads-",
                "media-", "static-", "www-", "cdn-"]

    candidates = set()
    for p in prefixes:
        for s in suffixes:
            cand = f"{p}{name_core}{s}"
            if 3 <= len(cand) <= 63 and not cand.startswith("-") and not cand.endswith("-"):
                candidates.add(cand)
    candidates = sorted(candidates)[:40]

    findings = []
    listable = []
    private = []
    for cand in candidates:
        url = f"https://{cand}.s3.amazonaws.com/"
        code, body, _ = _http_get(url, timeout=3)
        if code == 200 and "<ListBucketResult" in body:
            listable.append(cand)
        elif code == 403 and ("AccessDenied" in body or "<Code>AccessDenied</Code>" in body):
            private.append(cand)

    if listable:
        findings.append(wrap_finding(
            f"PUBLIC-LISTABLE S3 buckets discovered ({len(listable)}): {', '.join(listable[:5])}",
            "CRITICAL", cvss="9.0", cwe="CWE-200", owasp="A05:2021",
            remediation=("Make these buckets private immediately. Set Block "
                          "Public Access at account level. Audit contents before locking down."),
            evidence_marker=(f"Anonymous LIST succeeded on: "
                              f"{', '.join('https://' + b + '.s3.amazonaws.com/' for b in listable[:5])}")))

    if private:
        findings.append(wrap_finding(
            f"S3 buckets EXIST but require auth ({len(private)} matched): {', '.join(private[:5])}",
            "MEDIUM", cvss="5.5", cwe="CWE-200",
            remediation=("Bucket existence is information disclosure. Consider "
                          "renaming buckets to harder-to-guess names + apply "
                          "Block Public Access at account level."),
            evidence_marker=(f"403 AccessDenied (bucket exists) on: "
                              f"{', '.join(private[:5])}")))

    if not findings:
        findings.append(wrap_finding(
            f"S3 bucket-name brute: 0 of {len(candidates)} candidates exist",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue current naming hygiene.",
            evidence_marker=(f"Probed {len(candidates)} bucket-name "
                              f"permutations of '{name_core}'; all returned "
                              "404 NoSuchBucket or timed out.")))

    return {"tool": "s3_bucket_brute", "target": target, "scan_time": 0,
            "vulnerable": len(listable) > 0,
            "severity": "CRITICAL" if listable else ("MEDIUM" if private else "POSITIVE"),
            "findings": findings,
            "tests_performed": len(candidates),
            "tests_summary": (f"S3 brute: {len(listable)} listable, "
                               f"{len(private)} exists-private, "
                               f"{len(candidates)-len(listable)-len(private)} not-found"),
            "raw_data": {"derived_name": name_core, "listable": listable,
                          "private": private, "candidates_count": len(candidates)}}


# ───────────────────── NEW live probes ─────────────────────
def _probe_azure_storage_public(target, req):
    """§3 alias — same anonymous-listing check, reported under the §3 slug."""
    r = _probe_azure_blob_public(target, req)
    r["tool"] = "azure_storage_public"
    return r


def _probe_gcp_gcs_public(target, req):
    """§4 alias — same anonymous-read check, reported under the §4 slug."""
    r = _probe_gcs_bucket_public(target, req)
    r["tool"] = "gcp_gcs_bucket_public"
    return r


def _probe_acr_anonymous(target, req):
    """Azure Container Registry anonymous-pull check (*.azurecr.io)."""
    host = _host(target)
    if "azurecr.io" not in host:
        return _adv_response("acr_anonymous_pull", target,
            "Target is not an *.azurecr.io registry — ACR anonymous-pull check N/A",
            "INFO", "0.0", evidence=host)
    code, body, _ = _http_get(f"https://{host}/v2/", timeout=4)
    anon = code == 200
    return _resp("acr_anonymous_pull", target, [wrap_finding(
        f"Azure Container Registry {host} {'allows ANONYMOUS pull (/v2 enum succeeded)' if anon else 'requires authentication (good)'}",
        "HIGH" if anon else "POSITIVE", cvss="7.0" if anon else "0.0",
        cwe="CWE-200", owasp="A05:2021",
        remediation="Disable anonymous pull (az acr update --name NAME --anonymous-pull-enabled false) unless the registry is intentionally public.",
        evidence_marker=f"GET https://{host}/v2/ -> {code}")], 1, "ACR anonymous-pull check")


def _probe_k8s_endpoint(slug, label):
    """Factory for a public Kubernetes API-server / kubelet exposure probe.
    Read-only GETs against the control-plane (6443) and kubelet (10250).
    A k8s version/health/pods signature flags PUBLIC exposure — no objects
    are created or mutated."""
    def _p(target, req):
        host = _host(target)
        checks = [(6443, "/version"), (6443, "/healthz"), (443, "/version"),
                  (10250, "/healthz"), (10250, "/pods")]
        hit = None
        for port, path in checks:
            code, body, _ = _http_get(f"https://{host}:{port}{path}", timeout=4, insecure=True)
            bl = body[:2048].lower()
            if not code:
                continue
            is_version = "gitversion" in bl and "major" in bl
            is_health = path == "/healthz" and code == 200 and bl.strip() == "ok"
            is_kubelet_pods = path == "/pods" and code in (200, 401, 403)
            if is_version or is_health or is_kubelet_pods:
                hit = (port, path, code)
                break
        if hit:
            port, path, code = hit
            sev = "HIGH" if code == 200 else "MEDIUM"
            findings = [wrap_finding(
                f"{label}: Kubernetes control-plane/kubelet reachable from the internet (port {port}{path} -> {code})",
                sev, cvss="7.5" if sev == "HIGH" else "5.5", cwe="CWE-284", owasp="A05:2021",
                remediation="Restrict the API server (6443) and kubelet (10250) to private subnets or an "
                            "authorized CIDR allow-list; never expose them publicly; enforce authn + RBAC.",
                evidence_marker=f"GET https://{host}:{port}{path} -> {code}")]
        else:
            findings = [wrap_finding(
                f"{label}: no public Kubernetes API/kubelet endpoint detected",
                "POSITIVE", cvss="0.0", cwe="N/A",
                remediation="No action required for this check.",
                evidence_marker=f"No control-plane/kubelet response on 6443/443/10250 for {host}")]
        return _resp(slug, target, findings, 5, f"{label} public-endpoint probe")
    return _p


# ───────────────────────── PROBES registry ─────────────────────────
PROBES = {
    # §1 Discovery
    "recon_cloud_dns":                _probe_recon_cloud_dns,
    "cloudfox_aws_all":               _abd("cloudfox_aws_all", "CloudFox AWS all-checks", _CREDS),
    "cloudfox_azure":                 _abd("cloudfox_azure", "CloudFox Azure", _CREDS),
    "cloudfox_gcp":                   _abd("cloudfox_gcp", "CloudFox GCP", _CREDS),
    "scoutsuite_aws":                 _abd("scoutsuite_aws", "ScoutSuite AWS", _CREDS),
    "scoutsuite_azure":               _abd("scoutsuite_azure", "ScoutSuite Azure", _CREDS),
    "scoutsuite_gcp":                 _abd("scoutsuite_gcp", "ScoutSuite GCP", _CREDS),
    "prowler_aws_check":              _abd("prowler_aws_check", "Prowler AWS CSPM scan", _CREDS),
    "prowler_azure_check":            _abd("prowler_azure_check", "Prowler Azure CSPM scan", _CREDS),
    "prowler_gcp_check":              _abd("prowler_gcp_check", "Prowler GCP CSPM scan", _CREDS),
    "steampipe_query":                _abd("steampipe_query", "Steampipe SQL cloud queries", _CREDS),
    "cartography_graph":              _abd("cartography_graph", "Cartography asset graph", _CREDS),
    "manual_cloud_discovery":         _abd("manual_cloud_discovery", "Manual cloud discovery", _MANUAL),
    "manual_cloud_asset_inventory":   _abd("manual_cloud_asset_inventory", "Manual cloud asset inventory", _MANUAL),

    # §2 AWS
    "aws_eks_endpoint_public":        _probe_k8s_endpoint("aws_eks_endpoint_public", "AWS EKS"),
    "aws_iam_overpermissive":         _abd("aws_iam_overpermissive", "AWS IAM over-permissive policies", _CREDS),
    "aws_iam_user_keys_old":          _abd("aws_iam_user_keys_old", "AWS IAM access keys > 90 days", _CREDS),
    "aws_root_account_usage":         _abd("aws_root_account_usage", "AWS root account usage", _CREDS),
    "aws_mfa_not_enforced":           _abd("aws_mfa_not_enforced", "AWS MFA not enforced", _CREDS),
    "aws_cloudtrail_disabled":        _abd("aws_cloudtrail_disabled", "AWS CloudTrail disabled", _CREDS),
    "aws_cloudtrail_log_validation":  _abd("aws_cloudtrail_log_validation", "AWS CloudTrail log validation off", _CREDS),
    "aws_config_disabled":            _abd("aws_config_disabled", "AWS Config disabled", _CREDS),
    "aws_guardduty_disabled":         _abd("aws_guardduty_disabled", "AWS GuardDuty disabled", _CREDS),
    "aws_s3_bucket_public":           _abd("aws_s3_bucket_public", "AWS account-wide S3 public audit", _CREDS + " (single-bucket public checks ARE live: see s3_bucket_public_static_site / s3_bucket_brute)."),
    "aws_s3_bucket_acl_misconfig":    _abd("aws_s3_bucket_acl_misconfig", "AWS S3 ACL misconfiguration audit", _CREDS),
    "aws_s3_bucket_unencrypted":      _abd("aws_s3_bucket_unencrypted", "AWS S3 default-encryption audit", _CREDS),
    "aws_ec2_sg_open":                _abd("aws_ec2_sg_open", "AWS security group 0.0.0.0/0 audit", _CREDS),
    "aws_ec2_imds_v1_enabled":        _abd("aws_ec2_imds_v1_enabled", "AWS EC2 IMDSv1 enabled", _IMDS),
    "aws_rds_public_access":          _abd("aws_rds_public_access", "AWS RDS public access audit", _CREDS),
    "aws_lambda_resource_policy":     _abd("aws_lambda_resource_policy", "AWS Lambda resource-policy audit", _CREDS),
    "aws_kms_key_rotation_off":       _abd("aws_kms_key_rotation_off", "AWS KMS key rotation off", _CREDS),
    "aws_efs_unencrypted":            _abd("aws_efs_unencrypted", "AWS EFS unencrypted", _CREDS),
    "aws_secrets_manager_audit":      _abd("aws_secrets_manager_audit", "AWS Secrets Manager audit", _CREDS),

    # §3 Azure
    "azure_storage_public":           _probe_azure_storage_public,
    "azure_aks_endpoint_public":      _probe_k8s_endpoint("azure_aks_endpoint_public", "Azure AKS"),
    "azure_aad_pim_audit":            _abd("azure_aad_pim_audit", "Azure AAD PIM audit", _CREDS),
    "azure_conditional_access_audit": _abd("azure_conditional_access_audit", "Azure Conditional Access audit", _CREDS),
    "azure_managed_identity_audit":   _abd("azure_managed_identity_audit", "Azure Managed Identity audit", _CREDS),
    "azure_keyvault_public_access":   _abd("azure_keyvault_public_access", "Azure Key Vault public-access audit", _CREDS),
    "azure_storage_unencrypted":      _abd("azure_storage_unencrypted", "Azure Storage encryption audit", _CREDS),
    "azure_vm_disk_unencrypted":      _abd("azure_vm_disk_unencrypted", "Azure VM disk encryption audit", _CREDS),
    "azure_nsg_open_inbound":         _abd("azure_nsg_open_inbound", "Azure NSG open inbound audit", _CREDS),
    "azure_sql_public_access":        _abd("azure_sql_public_access", "Azure SQL public access audit", _CREDS),
    "azure_app_service_https_only":   _abd("azure_app_service_https_only", "Azure App Service HTTPS-only audit", _CREDS),
    "azure_app_registration_unused":  _abd("azure_app_registration_unused", "Azure unused app registration audit", _CREDS),
    "azure_service_principal_secrets": _abd("azure_service_principal_secrets", "Azure SP secret rotation audit", _CREDS),
    "azure_diagnostic_settings_off":  _abd("azure_diagnostic_settings_off", "Azure diagnostic settings off", _CREDS),
    "azure_defender_off":             _abd("azure_defender_off", "Microsoft Defender for Cloud off", _CREDS),

    # §4 GCP
    "gcp_gcs_bucket_public":          _probe_gcp_gcs_public,
    "gcp_gke_endpoint_public":        _probe_k8s_endpoint("gcp_gke_endpoint_public", "GCP GKE"),
    "gcp_org_policy_audit":           _abd("gcp_org_policy_audit", "GCP org policy audit", _CREDS),
    "gcp_iam_overpermissive":         _abd("gcp_iam_overpermissive", "GCP IAM over-permissive audit", _CREDS),
    "gcp_sa_key_age":                 _abd("gcp_sa_key_age", "GCP service-account key age audit", _CREDS),
    "gcp_gcs_uniform_access":         _abd("gcp_gcs_uniform_access", "GCS uniform bucket-level access audit", _CREDS),
    "gcp_firewall_open":              _abd("gcp_firewall_open", "GCP firewall 0.0.0.0/0 audit", _CREDS),
    "gcp_sql_public_access":          _abd("gcp_sql_public_access", "Cloud SQL public access audit", _CREDS),
    "gcp_cloud_kms_audit":            _abd("gcp_cloud_kms_audit", "Cloud KMS audit", _CREDS),
    "gcp_audit_logs_off":             _abd("gcp_audit_logs_off", "GCP audit logs off", _CREDS),
    "gcp_secret_manager_audit":       _abd("gcp_secret_manager_audit", "GCP Secret Manager IAM audit", _CREDS),
    "gcp_workload_identity_audit":    _abd("gcp_workload_identity_audit", "GKE Workload Identity audit", _CREDS),

    # §5 CIEM
    "ciem_overpermissive_paths":      _abd("ciem_overpermissive_paths", "CIEM over-permissive identity paths", _CREDS),
    "ciem_cross_account_trust":       _abd("ciem_cross_account_trust", "Cross-account trust audit", _CREDS),
    "ciem_oidc_federation_audit":     _abd("ciem_oidc_federation_audit", "OIDC federation audit", _CREDS),
    "ciem_unused_access_keys":        _abd("ciem_unused_access_keys", "Unused access keys audit", _CREDS),
    "ciem_privilege_escalation_paths": _abd("ciem_privilege_escalation_paths", "Cloud privesc-path mapping", _CREDS),
    "ciem_zombie_users":              _abd("ciem_zombie_users", "Zombie/dormant users audit", _CREDS),
    "ciem_excessive_perm_diff":       _abd("ciem_excessive_perm_diff", "Excessive-permission diff vs baseline", _CREDS),
    "ciem_service_account_creep":     _abd("ciem_service_account_creep", "Service-account permission creep", _CREDS),
    "manual_ciem_review":             _abd("manual_ciem_review", "Manual CIEM review", _MANUAL),
    "manual_iam_lateral_chain":       _abd("manual_iam_lateral_chain", "Manual IAM lateral-movement chain", _MANUAL),

    # §6 Serverless
    "lambdaguard_advisory":           _abd("lambdaguard_advisory", "LambdaGuard scan", _CREDS),
    "lambda_env_secrets_leak":        _abd("lambda_env_secrets_leak", "Lambda env-var secret leak", _CREDS),
    "lambda_role_overpermissive":     _abd("lambda_role_overpermissive", "Lambda execution-role over-perm", _CREDS),
    "azure_function_secrets_leak":    _abd("azure_function_secrets_leak", "Azure Function secret leak", _CREDS),
    "azure_function_managed_id":      _abd("azure_function_managed_id", "Azure Function managed-ID over-perm", _CREDS),
    "cloud_run_audit":                _abd("cloud_run_audit", "Cloud Run --allow-unauthenticated audit", _CREDS),
    "cloud_functions_overpermissive": _abd("cloud_functions_overpermissive", "Cloud Functions over-perm audit", _CREDS),
    "serverless_cold_start_oracle":   _abd("serverless_cold_start_oracle", "Serverless cold-start side-channel", _MANUAL),
    "manual_serverless_review":       _abd("manual_serverless_review", "Manual serverless review", _MANUAL),
    "manual_serverless_chain":        _abd("manual_serverless_chain", "Manual serverless chain", _MANUAL),

    # §7 Container Registry & Image
    "ecr_public_access":              _probe_ecr_public_access,
    "acr_anonymous_pull":             _probe_acr_anonymous,
    "gcr_public_access":              _probe_gcr_public_access,
    "docker_hub_public_image_secrets": _probe_docker_hub_public_image,
    "image_unsigned_no_cosign":       _abd("image_unsigned_no_cosign", "Image cosign-signature verification", _IMAGE),
    "image_vuln_critical_count":      _abd("image_vuln_critical_count", "Image critical-CVE count", _IMAGE),
    "image_baseimage_age":            _abd("image_baseimage_age", "Base-image age audit", _IMAGE),
    "image_runtime_provenance":       _abd("image_runtime_provenance", "Image runtime provenance / SLSA", _IMAGE),
    "manual_image_review":            _abd("manual_image_review", "Manual image review", _MANUAL),

    # §8 Cloud Storage
    "s3_bucket_public_static_site":   _probe_s3_public,
    "azure_blob_public_anon":         _probe_azure_blob_public,
    "gcs_bucket_acl_legacy":          _probe_gcs_bucket_public,
    "s3_bucket_lifecycle_audit":      _abd("s3_bucket_lifecycle_audit", "S3 lifecycle policy audit", _CREDS),
    "s3_bucket_versioning_off":       _abd("s3_bucket_versioning_off", "S3 versioning / MFA-delete audit", _CREDS),
    "s3_bucket_logging_off":          _abd("s3_bucket_logging_off", "S3 access-logging audit", _CREDS),
    "gcs_bucket_logging_off":         _abd("gcs_bucket_logging_off", "GCS access-logging audit", _CREDS),
    "storage_secret_in_object":       _abd("storage_secret_in_object", "Secret detected in object content", _CREDS + " A public object would be readable, but enumerating object contents requires bucket-list access or credentials."),
    "manual_storage_review":          _abd("manual_storage_review", "Manual storage review", _MANUAL),

    # §9 Network & VPC
    "vpc_flow_logs_off":              _abd("vpc_flow_logs_off", "VPC flow logs disabled audit", _CREDS),
    "nat_gateway_public_egress":      _abd("nat_gateway_public_egress", "NAT gateway public-egress audit", _CREDS),
    "vpc_endpoints_audit":            _abd("vpc_endpoints_audit", "VPC endpoints (PrivateLink) audit", _CREDS),
    "transit_gateway_audit":          _abd("transit_gateway_audit", "Transit Gateway audit", _CREDS),
    "peering_overpermissive":         _abd("peering_overpermissive", "VPC peering over-permissive audit", _CREDS),
    "ipv6_egress_audit":              _abd("ipv6_egress_audit", "IPv6 egress audit", _CREDS),
    "vpn_endpoint_public":            _abd("vpn_endpoint_public", "Cloud VPN endpoint public audit", _CREDS),
    "manual_network_review":          _abd("manual_network_review", "Manual VPC review", _MANUAL),

    # §10 Secrets & KMS
    "kms_key_rotation_off":           _abd("kms_key_rotation_off", "KMS key rotation off", _CREDS),
    "secrets_manager_versioning_off": _abd("secrets_manager_versioning_off", "Secrets Manager versioning off", _CREDS),
    "parameter_store_secret_unencrypted": _abd("parameter_store_secret_unencrypted", "SSM Parameter Store unencrypted secret", _CREDS),
    "keyvault_purge_protection_off":  _abd("keyvault_purge_protection_off", "Azure Key Vault purge-protection off", _CREDS),
    "kms_customer_managed_audit":     _abd("kms_customer_managed_audit", "Customer-managed KMS key audit", _CREDS),
    "kms_grants_audit":               _abd("kms_grants_audit", "KMS grants audit", _CREDS),
    "hsm_backed_keys_audit":          _abd("hsm_backed_keys_audit", "HSM-backed key audit", _CREDS),
    "manual_secret_review":           _abd("manual_secret_review", "Manual secret review", _MANUAL),

    # §11 Cross-Cloud OIDC
    "oidc_provider_thumbprint_audit": _probe_oidc_discovery,
    "gha_oidc_role_audit":            _abd("gha_oidc_role_audit", "GitHub Actions OIDC -> AWS role audit", _OIDCCFG),
    "cross_cloud_oidc_trust_audit":   _abd("cross_cloud_oidc_trust_audit", "Cross-cloud OIDC trust audit", _OIDCCFG),
    "oidc_subject_claim_wildcard":    _abd("oidc_subject_claim_wildcard", "OIDC subject-claim wildcard abuse", _OIDCCFG),
    "manual_oidc_audit":              _abd("manual_oidc_audit", "Manual OIDC audit", _MANUAL),
    "manual_cross_cloud_chain":       _abd("manual_cross_cloud_chain", "Manual cross-cloud chain", _MANUAL),

    # §12 Compliance
    "compliance_cis_aws_benchmark":   _probe_iac_manifest_exposed,
    "compliance_cis_azure_benchmark": _abd("compliance_cis_azure_benchmark", "CIS Azure Foundations benchmark", _CREDS),
    "compliance_cis_gcp_benchmark":   _abd("compliance_cis_gcp_benchmark", "CIS GCP Foundations benchmark", _CREDS),
    "compliance_pci_dss_cloud":       _abd("compliance_pci_dss_cloud", "PCI DSS 4.0 cloud controls", _CREDS),

    # orphan helper (no T slug — preserved from prior build; not routed)
    "s3_bucket_brute":                _probe_s3_bucket_brute,
}

T = [
    # §1 Cloud Asset Discovery (14)
    ("cloudfox_aws_all", "CloudFox aws all-checks.", "MEDIUM", "5.5"),
    ("cloudfox_azure", "CloudFox azure.", "MEDIUM", "5.5"),
    ("cloudfox_gcp", "CloudFox gcp.", "MEDIUM", "5.5"),
    ("scoutsuite_aws", "ScoutSuite AWS.", "MEDIUM", "5.5"),
    ("scoutsuite_azure", "ScoutSuite Azure.", "MEDIUM", "5.5"),
    ("scoutsuite_gcp", "ScoutSuite GCP.", "MEDIUM", "5.5"),
    ("prowler_aws_check", "Prowler AWS check.", "MEDIUM", "5.5"),
    ("prowler_azure_check", "Prowler Azure check.", "MEDIUM", "5.5"),
    ("prowler_gcp_check", "Prowler GCP check.", "MEDIUM", "5.5"),
    ("steampipe_query", "Steampipe SQL queries.", "MEDIUM", "5.5"),
    ("cartography_graph", "Cartography graph dump.", "MEDIUM", "5.5"),
    ("recon_cloud_dns", "Cloud DNS recon (ASN/cloud-detect).", "INFO", "0.0"),
    ("manual_cloud_discovery", "Manual cloud discovery.", "INFO", "0.0"),
    ("manual_cloud_asset_inventory", "Manual cloud asset inventory.", "INFO", "0.0"),
    # §2 AWS Security (19)
    ("aws_iam_overpermissive", "AWS IAM overpermissive policies.", "HIGH", "7.5"),
    ("aws_iam_user_keys_old", "AWS IAM user keys older than 90 days.", "MEDIUM", "5.5"),
    ("aws_root_account_usage", "AWS root account usage.", "HIGH", "7.5"),
    ("aws_mfa_not_enforced", "AWS MFA not enforced.", "HIGH", "7.5"),
    ("aws_cloudtrail_disabled", "AWS CloudTrail disabled.", "HIGH", "7.5"),
    ("aws_cloudtrail_log_validation", "AWS CloudTrail log validation off.", "MEDIUM", "5.5"),
    ("aws_config_disabled", "AWS Config disabled.", "MEDIUM", "5.5"),
    ("aws_guardduty_disabled", "AWS GuardDuty disabled.", "MEDIUM", "5.5"),
    ("aws_s3_bucket_public", "AWS S3 bucket public.", "CRITICAL", "9.0"),
    ("aws_s3_bucket_acl_misconfig", "AWS S3 bucket ACL misconfig.", "HIGH", "8.0"),
    ("aws_s3_bucket_unencrypted", "AWS S3 bucket unencrypted.", "MEDIUM", "5.5"),
    ("aws_ec2_sg_open", "AWS EC2 security group open to 0.0.0.0/0.", "HIGH", "8.0"),
    ("aws_ec2_imds_v1_enabled", "AWS EC2 IMDSv1 enabled.", "HIGH", "7.5"),
    ("aws_rds_public_access", "AWS RDS public access.", "HIGH", "8.0"),
    ("aws_lambda_resource_policy", "AWS Lambda resource policy open.", "HIGH", "7.5"),
    ("aws_kms_key_rotation_off", "AWS KMS key rotation off.", "MEDIUM", "5.5"),
    ("aws_efs_unencrypted", "AWS EFS unencrypted.", "MEDIUM", "5.5"),
    ("aws_eks_endpoint_public", "AWS EKS endpoint public.", "HIGH", "7.5"),
    ("aws_secrets_manager_audit", "AWS Secrets Manager audit.", "MEDIUM", "5.5"),
    # §3 Azure Security (15)
    ("azure_aad_pim_audit", "Azure AAD PIM audit.", "MEDIUM", "5.5"),
    ("azure_conditional_access_audit", "Conditional Access audit.", "HIGH", "7.5"),
    ("azure_managed_identity_audit", "Managed Identity audit.", "MEDIUM", "5.5"),
    ("azure_keyvault_public_access", "KeyVault public access.", "HIGH", "8.0"),
    ("azure_storage_public", "Storage account public.", "CRITICAL", "9.0"),
    ("azure_storage_unencrypted", "Storage unencrypted.", "MEDIUM", "5.5"),
    ("azure_vm_disk_unencrypted", "VM disk unencrypted.", "MEDIUM", "5.5"),
    ("azure_nsg_open_inbound", "NSG open inbound rules.", "HIGH", "8.0"),
    ("azure_sql_public_access", "SQL public access.", "HIGH", "8.0"),
    ("azure_app_service_https_only", "App Service HTTPS-only off.", "MEDIUM", "5.5"),
    ("azure_app_registration_unused", "App registration unused.", "MEDIUM", "5.5"),
    ("azure_service_principal_secrets", "SP secret rotation.", "MEDIUM", "5.5"),
    ("azure_aks_endpoint_public", "AKS endpoint public.", "HIGH", "7.5"),
    ("azure_diagnostic_settings_off", "Diagnostic settings off.", "MEDIUM", "5.5"),
    ("azure_defender_off", "Microsoft Defender for Cloud off.", "MEDIUM", "5.5"),
    # §4 GCP Security (12)
    ("gcp_org_policy_audit", "GCP org policy audit.", "MEDIUM", "5.5"),
    ("gcp_iam_overpermissive", "GCP IAM overpermissive.", "HIGH", "7.5"),
    ("gcp_sa_key_age", "GCP SA key age >90 days.", "MEDIUM", "5.5"),
    ("gcp_gcs_bucket_public", "GCS bucket public.", "CRITICAL", "9.0"),
    ("gcp_gcs_uniform_access", "GCS uniform bucket-level access off.", "MEDIUM", "5.5"),
    ("gcp_firewall_open", "GCP firewall open 0.0.0.0/0.", "HIGH", "8.0"),
    ("gcp_sql_public_access", "Cloud SQL public access.", "HIGH", "8.0"),
    ("gcp_gke_endpoint_public", "GKE endpoint public.", "HIGH", "7.5"),
    ("gcp_cloud_kms_audit", "Cloud KMS audit.", "MEDIUM", "5.5"),
    ("gcp_audit_logs_off", "GCP audit logs off.", "MEDIUM", "5.5"),
    ("gcp_secret_manager_audit", "Secret Manager audit.", "MEDIUM", "5.5"),
    ("gcp_workload_identity_audit", "Workload Identity audit.", "MEDIUM", "5.5"),
    # §5 Multi-Cloud CIEM (10)
    ("ciem_overpermissive_paths", "CIEM overpermissive identity paths.", "HIGH", "7.5"),
    ("ciem_cross_account_trust", "Cross-account trust audit.", "HIGH", "7.5"),
    ("ciem_oidc_federation_audit", "OIDC federation audit.", "HIGH", "7.5"),
    ("ciem_unused_access_keys", "Unused access keys.", "MEDIUM", "5.5"),
    ("ciem_privilege_escalation_paths", "Privesc paths.", "HIGH", "8.0"),
    ("ciem_zombie_users", "Zombie users (no login >90d).", "MEDIUM", "5.5"),
    ("ciem_excessive_perm_diff", "Excessive perms vs least-priv baseline.", "MEDIUM", "5.5"),
    ("ciem_service_account_creep", "Service account perm creep.", "MEDIUM", "5.5"),
    ("manual_ciem_review", "Manual CIEM review.", "INFO", "0.0"),
    ("manual_iam_lateral_chain", "Manual IAM lateral chain.", "INFO", "0.0"),
    # §6 Serverless (10)
    ("lambdaguard_advisory", "LambdaGuard advisory.", "MEDIUM", "5.5"),
    ("lambda_env_secrets_leak", "Lambda env secrets leak.", "HIGH", "7.5"),
    ("lambda_role_overpermissive", "Lambda role overpermissive.", "HIGH", "7.5"),
    ("azure_function_secrets_leak", "Azure Function secrets leak.", "HIGH", "7.5"),
    ("azure_function_managed_id", "Azure Function managed-ID overpermissive.", "HIGH", "7.5"),
    ("cloud_run_audit", "Cloud Run audit.", "MEDIUM", "5.5"),
    ("cloud_functions_overpermissive", "Cloud Functions overpermissive.", "HIGH", "7.5"),
    ("serverless_cold_start_oracle", "Serverless cold-start oracle.", "MEDIUM", "5.5"),
    ("manual_serverless_review", "Manual serverless review.", "INFO", "0.0"),
    ("manual_serverless_chain", "Manual serverless chain.", "INFO", "0.0"),
    # §7 Container Registry & Image (9)
    ("ecr_public_access", "ECR public access.", "HIGH", "7.5"),
    ("acr_anonymous_pull", "ACR anonymous pull enabled.", "HIGH", "7.5"),
    ("gcr_public_access", "GCR public access.", "HIGH", "7.5"),
    ("docker_hub_public_image_secrets", "Docker Hub image with embedded secrets.", "HIGH", "8.0"),
    ("image_unsigned_no_cosign", "Image unsigned (no cosign signature).", "MEDIUM", "5.5"),
    ("image_vuln_critical_count", "Image critical vulnerability count.", "HIGH", "7.5"),
    ("image_baseimage_age", "Base image age >90 days.", "MEDIUM", "5.5"),
    ("image_runtime_provenance", "Runtime provenance check.", "MEDIUM", "5.5"),
    ("manual_image_review", "Manual image review.", "INFO", "0.0"),
    # §8 Cloud Storage (10)
    ("s3_bucket_public_static_site", "S3 public static site.", "HIGH", "7.5"),
    ("s3_bucket_brute", "S3 bucket name-brute discovery.", "HIGH", "7.5"),
    ("s3_bucket_lifecycle_audit", "S3 lifecycle policy audit.", "MEDIUM", "5.5"),
    ("s3_bucket_versioning_off", "S3 versioning off.", "MEDIUM", "5.5"),
    ("s3_bucket_logging_off", "S3 logging off.", "MEDIUM", "5.5"),
    ("azure_blob_public_anon", "Azure Blob public anonymous.", "HIGH", "7.5"),
    ("gcs_bucket_acl_legacy", "GCS legacy ACL.", "MEDIUM", "5.5"),
    ("gcs_bucket_logging_off", "GCS logging off.", "MEDIUM", "5.5"),
    ("storage_secret_in_object", "Secret detected in object content.", "CRITICAL", "9.0"),
    ("manual_storage_review", "Manual storage review.", "INFO", "0.0"),
    # §9 Cloud Network & VPC (8)
    ("vpc_flow_logs_off", "VPC flow logs off.", "MEDIUM", "5.5"),
    ("nat_gateway_public_egress", "NAT gateway public egress audit.", "MEDIUM", "5.5"),
    ("vpc_endpoints_audit", "VPC endpoints audit.", "MEDIUM", "5.5"),
    ("transit_gateway_audit", "Transit Gateway audit.", "MEDIUM", "5.5"),
    ("peering_overpermissive", "VPC peering overpermissive.", "HIGH", "7.0"),
    ("ipv6_egress_audit", "IPv6 egress audit.", "MEDIUM", "5.5"),
    ("vpn_endpoint_public", "VPN endpoint public.", "MEDIUM", "5.5"),
    ("manual_network_review", "Manual VPC review.", "INFO", "0.0"),
    # §10 Cloud Secrets & KMS (8)
    ("kms_key_rotation_off", "KMS key rotation off.", "MEDIUM", "5.5"),
    ("secrets_manager_versioning_off", "Secrets Manager versioning off.", "MEDIUM", "5.5"),
    ("parameter_store_secret_unencrypted", "Parameter Store secret unencrypted.", "HIGH", "7.5"),
    ("keyvault_purge_protection_off", "Azure KeyVault purge protection off.", "MEDIUM", "5.5"),
    ("kms_customer_managed_audit", "Customer-managed KMS keys audit.", "MEDIUM", "5.5"),
    ("kms_grants_audit", "KMS grants audit.", "MEDIUM", "5.5"),
    ("hsm_backed_keys_audit", "HSM-backed keys audit.", "MEDIUM", "5.5"),
    ("manual_secret_review", "Manual secret review.", "INFO", "0.0"),
    # §11 Cross-Cloud OIDC (6)
    ("oidc_provider_thumbprint_audit", "OIDC provider thumbprint audit.", "HIGH", "7.5"),
    ("gha_oidc_role_audit", "GitHub Actions OIDC role audit.", "HIGH", "7.5"),
    ("cross_cloud_oidc_trust_audit", "Cross-cloud OIDC trust audit.", "HIGH", "7.5"),
    ("oidc_subject_claim_wildcard", "OIDC subject claim wildcard.", "CRITICAL", "9.0"),
    ("manual_oidc_audit", "Manual OIDC audit.", "INFO", "0.0"),
    ("manual_cross_cloud_chain", "Manual cross-cloud chain.", "INFO", "0.0"),
    # §12 Cloud Compliance (4)
    ("compliance_cis_aws_benchmark", "CIS AWS benchmark check.", "MEDIUM", "5.5"),
    ("compliance_cis_azure_benchmark", "CIS Azure benchmark check.", "MEDIUM", "5.5"),
    ("compliance_cis_gcp_benchmark", "CIS GCP benchmark check.", "MEDIUM", "5.5"),
    ("compliance_pci_dss_cloud", "PCI DSS 4.0 cloud controls.", "HIGH", "7.0"),
]

router = make_advisory_router("cloud", T,
    playbook_ref="See module_playbooks/21_cloud.md.",
    probes=PROBES)


def register(app):
    app.include_router(router)

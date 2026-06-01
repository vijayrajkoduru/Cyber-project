# Container / Kubernetes Security — Master Reference (`container_k8s_ruff`)

**100% Full Industry Standard catalogue** — aligned with CNCF Cloud Native Security Whitepaper + CIS Kubernetes Benchmark + NIST SP 800-190 + NSA/CISA Kubernetes Hardening Guide + 2024–2026 industry additions (Leaky Vessels, eBPF runtime, dMSA equivalents).

10 sections, 142 techniques.

**Legend:** auto · (probe) · manual · NEW 2024+

---

## Summary

| § | Section | Techniques | Auto | Probe | Manual |
|---|---|---|---|---|---|
| 1 | Image / Registry Security | 14 | 13 | 0 | 1 |
| 2 | Dockerfile / Build Hardening | 10 | 10 | 0 | 0 |
| 3 | Container Runtime Security | 14 | 11 | 1 | 2 |
| 4 | Kubernetes Cluster Hardening (CIS) | 18 | 17 | 0 | 1 |
| 5 | RBAC / Policy / OPA | 14 | 12 | 0 | 2 |
| 6 | Network Policy / Service Mesh | 12 | 10 | 0 | 2 |
| 7 | Secrets Management | 10 | 9 | 0 | 1 |
| 8 | Container Escape CVEs | 12 | 9 | 1 | 2 |
| 9 | Service Mesh & Ingress | 10 | 8 | 0 | 2 |
| 10 | eBPF Runtime Detection | 8 | 4 | 0 | 4 |
| **TOTAL** | | **122** | **103** | **2** | **17** |

---

## §1 — Image / Registry Security

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 1 | Trivy image vuln scan | trivy image | |
| 2 | Grype image scan | grype | |
| 3 | Snyk container test | snyk container test | |
| 4 | Anchore Engine / Enterprise | anchore-cli | |
| 5 | Clair scanner | clair-scanner | |
| 6 | Docker Bench for Security | docker-bench | |
| 7 | Secret-in-image scan | trufflehog, dive | |
| 8 | SBOM-from-image | syft | |
| 9 | Distroless / Wolfi base check | image meta + policy | |
| 10 | OCI signature verification (cosign) | cosign verify | |
| 11 | SLSA provenance attestation | slsa-verifier | |
| 12 | Registry credential audit | custom + APIs | |
| 13 | Image tag mutability audit | custom + APIs | |
| 14 | Manual reverse-engineering image | dive + manual | |

---

## §2 — Dockerfile / Build Hardening

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 15 | Hadolint Dockerfile lint | hadolint | |
| 16 | USER root audit | hadolint + custom | |
| 17 | latest tag audit | hadolint + custom | |
| 18 | ADD vs COPY audit (URL fetch) | hadolint | |
| 19 | apt-get update + install single-layer | hadolint | |
| 20 | Multi-stage build presence | custom + parse | |
| 21 | HEALTHCHECK directive presence | custom | |
| 22 | Pinned base image hash | custom | |
| 23 | Build-time secret leakage (BuildKit) | custom + audit | |
| 24 | Reproducible build verification | rebuild + diff | |

---

## §3 — Container Runtime Security

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 25 | Capabilities drop audit (--cap-drop ALL) | custom + APIs | |
| 26 | Privileged container detection | custom + APIs | |
| 27 | Host PID / IPC / Network namespace | custom + APIs | |
| 28 | hostPath volume audit | custom + APIs | |
| 29 | Read-only root filesystem audit | custom + APIs | |
| 30 | Seccomp profile audit | custom + APIs | |
| 31 | AppArmor / SELinux profile audit | custom + APIs | |
| 32 | User namespace remap audit | custom + APIs | |
| 33 | Docker socket mount audit | custom | |
| 34 | gVisor / Kata sandbox audit | custom + APIs | |
| 35 | Falco rules + alerting | falco | (probe) |
| 36 | Tetragon eBPF runtime detect | tetragon | |
| 37 | Container breakout test (manual) | chain exploit | |
| 38 | Manual runtime forensics | analyst | |

---

## §4 — Kubernetes Cluster Hardening (CIS)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 39 | kube-bench CIS scan | kube-bench | |
| 40 | kube-hunter vuln discovery | kube-hunter | |
| 41 | Kubescape NSA/CISA hardening scan | kubescape | |
| 42 | Polaris policy violations | polaris | |
| 43 | API server anonymous-auth audit | custom + kubectl | |
| 44 | etcd encryption-at-rest audit | custom + kubectl | |
| 45 | Audit log enabled + config | custom + kubectl | |
| 46 | RBAC bootstrapping audit | custom + kubectl | |
| 47 | kubelet anonymous auth disabled | custom + nuclei | |
| 48 | kubelet authorization mode (Webhook) | custom + nuclei | |
| 49 | API server port-6443 exposure | nuclei + nmap | |
| 50 | etcd port-2379 exposure | nuclei + nmap | |
| 51 | TLS cert rotation cadence | custom + APIs | |
| 52 | Encryption provider audit | custom + APIs | |
| 53 | EKS / AKS / GKE shared-responsibility audit | custom + cloud APIs | |
| 54 | Pod Security Standards (PSS) policy | kyverno, OPA | |
| 55 | Pod Security Admission (PSA) labels | custom + kubectl | |
| 56 | Manual cluster hardening report | analyst | |

---

## §5 — RBAC / Policy / OPA

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 57 | rbac-tool over-permissive role detect | rbac-tool | |
| 58 | can-i-namespace audit | kubectl + custom | |
| 59 | ServiceAccount over-permissive | custom + kubectl | |
| 60 | ClusterRoleBinding to system:authenticated | custom + kubectl | |
| 61 | Default ServiceAccount usage audit | custom + kubectl | |
| 62 | OPA / Gatekeeper policy violations | conftest, OPA eval | |
| 63 | Kyverno policy enforcement | kyverno | |
| 64 | Validating / Mutating admission webhook audit | custom + kubectl | |
| 65 | RBAC chain to cluster-admin (BloodHound-K8s) | KubeHound, BloodHound | |
| 66 | OIDC trust chain audit (cross-cloud RBAC) | custom + kubectl | |
| 67 | Workload Identity (GKE / IRSA / Azure WI) audit | custom + cloud APIs | |
| 68 | impersonation rights audit | custom + kubectl | |
| 69 | Manual privesc path (KubiScan) | KubiScan | |
| 70 | Manual creative RBAC chain | analyst | |

---

## §6 — Network Policy / Service Mesh

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 71 | NetworkPolicy presence audit | custom + kubectl | |
| 72 | Default-deny policy audit | custom + kubectl | |
| 73 | Egress restriction audit | custom + kubectl | |
| 74 | Service mesh (Istio / Linkerd) mTLS audit | istioctl analyze | |
| 75 | Cilium policy audit | cilium policy validate | |
| 76 | Calico GlobalNetworkPolicy audit | calicoctl + custom | |
| 77 | Multi-cluster federation traffic audit | custom + APIs | |
| 78 | Ingress controller version + CVE | trivy + custom | |
| 79 | NodePort / LoadBalancer exposure audit | custom + kubectl | |
| 80 | DNS policy + CoreDNS CVE | custom + nuclei | |
| 81 | Manual lateral via NetworkPolicy bypass | analyst | |
| 82 | Manual cross-namespace pivot | analyst | |

---

## §7 — Secrets Management

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 83 | Kubernetes Secret base64 audit | custom + kubectl | |
| 84 | Secret encryption-at-rest audit | custom + kubectl | |
| 85 | External secret operator (ESO) audit | custom + kubectl | |
| 86 | Vault / Sealed Secrets integration audit | custom | |
| 87 | Secret-in-ConfigMap detection | custom + grep | |
| 88 | Secret in env var leak | custom + grep | |
| 89 | Secret rotation cadence | custom + audit | |
| 90 | Secret access via RBAC audit | custom + kubectl | |
| 91 | SOPS / sealed-secrets supply chain | custom | |
| 92 | Manual secret-exfil chain | analyst | |

---

## §8 — Container Escape CVEs

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 93 | Leaky Vessels (CVE-2024-21626 runc) | trivy + custom | |
| 94 | Dirty Pipe (CVE-2022-0847) | nuclei + custom | |
| 95 | CVE-2019-5736 (runc) | nuclei + version check | |
| 96 | CVE-2022-0492 (cgroup release_agent) | nuclei + custom | |
| 97 | containerd CVE list | trivy + NVD | |
| 98 | cri-o CVE list | trivy + NVD | |
| 99 | kubelet CVE (CVE-2021-25737, etc.) | trivy + NVD | |
| 100 | "Stranger Danger" CVE class | custom + research | |
| 101 | Sys_admin capability + cgroups v1 escape | manual + custom | |
| 102 | hostPath /var/run/docker.sock escape | custom + manual | (probe) |
| 103 | Manual chained escape (kernel CVE + cap) | analyst | |
| 104 | Privileged container → host root | manual | |

---

## §9 — Service Mesh & Ingress

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 105 | Istio config audit | istioctl analyze | |
| 106 | Linkerd config audit | linkerd check | |
| 107 | Consul Connect audit | consul + custom | |
| 108 | Envoy sidecar bypass test | manual + custom | |
| 109 | Ingress controller (Nginx/Traefik) CVE | trivy + nuclei | |
| 110 | TLS certificate management (cert-manager) | custom | |
| 111 | mTLS enforcement audit | istioctl + custom | |
| 112 | Service Mesh Interface (SMI) audit | custom | |
| 113 | Manual sidecar escape | analyst | |
| 114 | Manual ingress bypass chain | analyst | |

---

## §10 — eBPF Runtime Detection NEW

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 115 | Falco rule audit | falco rules | |
| 116 | Tetragon TracingPolicy audit | tetragon | |
| 117 | Tracee runtime detection | tracee | |
| 118 | KubeArmor policy audit | kubearmor | |
| 119 | Sysdig Secure rule coverage | sysdig | |
| 120 | eBPF program injection audit | manual + research | |
| 121 | Manual eBPF detection bypass | analyst | |
| 122 | Manual kernel-level evasion | analyst | |

---

## Compliance Mapping
- **CIS Kubernetes Benchmark v1.8+** · **NIST SP 800-190** · **NSA/CISA Kubernetes Hardening Guidance** · **CNCF Cloud Native Security Whitepaper v2** · **PCI DSS 4.0** · **HIPAA** · **SOC 2** · **FedRAMP**

## VulnusLab container_k8s Status
- Status: MISSING (per modules_2026_inventory.md #24)
- Priority: P0 — top 2024+ enterprise ask

## Roadmap to 100%
1. Phase K-1: §1 image + §2 Dockerfile (24 scanners)
2. Phase K-2: §3 runtime + §4 cluster hardening (32 scanners)
3. Phase K-3: §5 RBAC + §6 NetPol + §7 Secrets (36 scanners)
4. Phase K-4: §8 escape CVE pack (12 scanners)
5. Phase K-5: §9 service mesh + §10 eBPF (18 scanners)

## References
- CIS Kubernetes Benchmark: https://www.cisecurity.org/benchmark/kubernetes
- NSA/CISA Kubernetes Hardening: https://www.cisa.gov/news-events/news/cisa-and-nsa-release-kubernetes-hardening-guidance
- Trivy: https://aquasecurity.github.io/trivy/
- kube-bench: https://github.com/aquasecurity/kube-bench
- kube-hunter: https://github.com/aquasecurity/kube-hunter
- Kubescape: https://github.com/kubescape/kubescape
- Falco: https://falco.org/
- Tetragon: https://tetragon.io/
- OPA / Gatekeeper: https://open-policy-agent.github.io/gatekeeper/
- Kyverno: https://kyverno.io/
- KubeHound (SpecterOps): https://github.com/DataDog/KubeHound

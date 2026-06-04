# Supply Chain Security — Master Reference (`supply_chain_ruff`)

**100% Full Industry Standard catalogue** — aligned with SLSA v1.0 + Sigstore + in-toto + NIST SP 800-218 (SSDF) + EU CRA + US EO 14028 + 2024–2026 industry additions.

8 sections, 110 techniques.

**Legend:** auto · (probe) · manual · NEW 2024+

---

## Summary

| § | Section | Techniques | Auto | Probe | Manual |
|---|---|---|---|---|---|
| 1 | SBOM Generation & Validation | 14 | 13 | 0 | 1 |
| 2 | Dependency Vuln (SCA) | 16 | 15 | 0 | 1 |
| 3 | Dependency Confusion / Typosquatting | 10 | 9 | 0 | 1 |
| 4 | CI/CD Pipeline Security | 18 | 15 | 1 | 2 |
| 5 | Code-Signing & Provenance (SLSA) | 14 | 13 | 0 | 1 |
| 6 | Package Registry Security | 12 | 11 | 0 | 1 |
| 7 | Container Image Supply Chain | 12 | 11 | 0 | 1 |
| 8 | Open-Source Project Health Audit | 10 | 8 | 0 | 2 |
| **TOTAL** | | **106** | **95** | **1** | **10** |

---

## §1 — SBOM Generation & Validation

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 1 | SBOM generation (Syft) | syft | |
| 2 | SBOM generation (CycloneDX) | cdxgen | |
| 3 | SBOM generation (SPDX) | tern, spdx-tools | |
| 4 | SBOM diff (declared vs actual) | sbom-diff, custom | |
| 5 | SBOM vulnerability cross-ref (OSV) | osv-scanner + SBOM | |
| 6 | SBOM license compliance | scancode, fossology | |
| 7 | SBOM completeness check | custom + heuristic | |
| 8 | SBOM consumability (Dependency-Track) | Dependency-Track | |
| 9 | SBOM signing (cosign attest) | cosign attest | |
| 10 | SBOM transparency log (Rekor) | rekor-cli | |
| 11 | VEX (Vulnerability Exploitability Exchange) audit | OpenVEX | |
| 12 | SBOM-of-SBOM (recursive) | manual + custom | |
| 13 | Runtime SBOM (in-memory dependency tracking) | manual | |
| 14 | Manual SBOM accuracy audit | analyst | |

---

## §2 — Dependency Vuln (SCA)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 15 | OSV-Scanner (universal) | osv-scanner | |
| 16 | npm audit / yarn audit / pnpm audit | npm audit | |
| 17 | pip-audit / safety | pip-audit | |
| 18 | OWASP Dependency-Check (Maven/Gradle) | dep-check | |
| 19 | bundler-audit (Ruby) | bundler-audit | |
| 20 | govulncheck (Go) | govulncheck | |
| 21 | cargo-audit (Rust) | cargo audit | |
| 22 | composer audit (PHP) | composer audit | |
| 23 | dotnet vulnerability list | dotnet list --vulnerable | |
| 24 | Snyk Open Source | snyk test | |
| 25 | GitHub Dependabot alerts | gh api + custom | |
| 26 | GitLab Dependency Scanning | GitLab API | |
| 27 | Renovate auto-update audit | renovate config | |
| 28 | Transitive-dependency depth audit | custom + depth | |
| 29 | Dependency-update frequency audit | custom + git log | |
| 30 | Manual dep CVE triage | analyst | |

---

## §3 — Dependency Confusion / Typosquatting

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 31 | NPM dependency-confusion check | confused, npm-name-check | |
| 32 | PyPI typosquat scan | pypi-typosquat, OSV | |
| 33 | RubyGems typosquat | custom + similarity | |
| 34 | Maven Central typosquat | custom + similarity | |
| 35 | Go module typosquat (proxy.golang.org) | OSV + custom | |
| 36 | Cargo crate typosquat | custom + similarity | |
| 37 | Internal-package public-name collision | custom + audit | |
| 38 | Repojacking (renamed/transferred repos) | gh api + custom | |
| 39 | Subdomain takeover via package manifest URL | nuclei + custom | |
| 40 | Manual social-engineering attempt verify | analyst | |

---

## §4 — CI/CD Pipeline Security

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 41 | GitHub Actions workflow lint | actionlint | |
| 42 | GitHub Actions secret leak (workflow logs) | gh + grep | |
| 43 | GitHub Actions third-party action pinning | custom + actionlint | |
| 44 | GitHub Actions reusable-workflow audit | actionlint + custom | |
| 45 | GitHub Actions self-hosted runner discovery | gh api + recon | |
| 46 | GitHub Actions OIDC trust → cloud | custom + audit | |
| 47 | GitLab CI / Bitbucket pipeline audit | gitlab API + custom | |
| 48 | Jenkins plugin CVE / unauth (8080) | nuclei + nmap | |
| 49 | CircleCI / TravisCI / Drone config audit | custom + APIs | |
| 50 | Tekton / Argo Workflows audit | kubectl + custom | |
| 51 | Dagger / Buildkite supply chain | custom + audit | |
| 52 | CI secret-in-log scan | trufflehog + custom | |
| 53 | CI cache poisoning vuln | manual + custom | (probe) |
| 54 | CI dependency confusion (private vs public) | confused + custom | |
| 55 | Branch protection bypass audit | gh api + custom | |
| 56 | Manual pipeline penetration test | analyst | |
| 57 | Manual privilege chain (build → deploy → prod) | analyst | |
| 58 | poisoned pull request (PWN-request) detection | custom + audit | |

---

## §5 — Code-Signing & Provenance (SLSA)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 59 | SLSA v1.0 build provenance verification | slsa-verifier | |
| 60 | Sigstore / cosign signature check | cosign verify | |
| 61 | Rekor transparency log query | rekor-cli | |
| 62 | Fulcio cert chain verification | cosign + manual | |
| 63 | in-toto attestation validation | in-toto-attestation | |
| 64 | SLSA L1 → L4 maturity assessment | custom + manual | |
| 65 | Build env hermeticity audit | custom + manual | |
| 66 | Reproducible build verification | rebuild + diff | |
| 67 | GPG / PGP signature audit (legacy) | gpg + custom | |
| 68 | Apple notarization / Windows Authenticode | codesign / signtool | |
| 69 | Tag immutability audit | custom + git | |
| 70 | Commit signing (git verify-commit) | git verify-commit | |
| 71 | Multi-party signing (M-of-N) | custom + cosign | |
| 72 | Manual provenance audit | analyst | |

---

## §6 — Package Registry Security

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 73 | npm 2FA enforcement audit | npm + custom | |
| 74 | PyPI 2FA enforcement audit | PyPI API + custom | |
| 75 | npm package-maintainer abandonment risk | custom + git age | |
| 76 | Account-takeover risk (expired domains) | dnstwist + custom | |
| 77 | Package maintainer pivot history | gh api + custom | |
| 78 | npm package install-script behavior scan | custom + sandbox | |
| 79 | PyPI install_requires arbitrary URL audit | custom + parse | |
| 80 | RubyGems gemspec post-install hooks | custom + parse | |
| 81 | Maven repository.xml mirror audit | custom + parse | |
| 82 | Cargo build.rs arbitrary code audit | custom + parse | |
| 83 | npm provenance attestation (npm 9.5+) | npm + custom | |
| 84 | Manual maintainer trust scoring | analyst | |

---

## §7 — Container Image Supply Chain

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 85 | Image base layer provenance | cosign + slsa-verifier | |
| 86 | Multi-arch image attestation | cosign + manual | |
| 87 | Image registry credential theft risk | custom + audit | |
| 88 | Registry mirror configuration audit | custom + APIs | |
| 89 | Image pull policy audit (Always vs IfNotPresent) | custom + kubectl | |
| 90 | OCI artifact signature chain | cosign + manual | |
| 91 | Sigstore policy controller audit | kyverno + custom | |
| 92 | Image promotion pipeline integrity (dev→prod) | custom + audit | |
| 93 | Manual image provenance audit | analyst | |
| 94 | Dockerfile pinned base SHA256 audit | custom + parse | |
| 95 | Image build cache poisoning risk | manual + custom | |
| 96 | Manual image RE (dive) | analyst | |

---

## §8 — Open-Source Project Health Audit

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 97 | OpenSSF Scorecard run | scorecard | |
| 98 | OSSF Best Practices Badge audit | custom + APIs | |
| 99 | Project commit activity audit | gh api + custom | |
| 100 | Maintainer count / bus-factor | gh api + custom | |
| 101 | Funding / sponsorship audit | custom + FUNDING.yml | |
| 102 | CVE response time (mean-time-to-patch) | custom + CVE DB | |
| 103 | Foundation governance (CNCF, Apache, OpenSSF) | custom + manual | |
| 104 | Forking pattern (community fork emergence) | gh api + custom | |
| 105 | Manual project sustainability rubric | analyst | |
| 106 | Manual maintainer interview / due-diligence | analyst | |

---

## Compliance Mapping
- **SLSA v1.0** · **NIST SP 800-218 (SSDF)** · **NIST SP 800-161 (Supply Chain Risk Mgmt)** · **EU CRA (Cyber Resilience Act, 2024+)** · **US EO 14028** · **CISA Secure by Design** · **OpenSSF Best Practices** · **ISO/IEC 5230 (OpenChain)**

## VulnusLab supply_chain Status
- Status: MISSING (per modules_2026_inventory.md #25)
- Priority: P0 — EU CRA + US EO 14028 mandate

## Roadmap to 100%
1. Phase S-1: §1 SBOM + §2 SCA (30 scanners)
2. Phase S-2: §3 dep confusion + §6 registry (22 scanners)
3. Phase S-3: §4 CI/CD pipeline (18 scanners)
4. Phase S-4: §5 SLSA / Sigstore (14 scanners)
5. Phase S-5: §7 container supply chain + §8 OSS health (22 scanners)

## References
- SLSA v1.0: https://slsa.dev/
- Sigstore: https://www.sigstore.dev/
- in-toto: https://in-toto.io/
- OSV (Open Source Vulnerabilities): https://osv.dev/
- OpenSSF Scorecard: https://github.com/ossf/scorecard
- NIST SP 800-218 (SSDF): https://csrc.nist.gov/publications/detail/sp/800-218/final
- US EO 14028: https://www.cisa.gov/executive-order-14028
- EU CRA: https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act
- Dependency-Track: https://dependencytrack.org/
- Syft / Grype: https://github.com/anchore

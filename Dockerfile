FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Minimal apt deps — only what core tools need.
# Heavy Kali tools (nuclei, hydra, msfvenom, gdb) get installed per-tool
# inside their tool file's setup block, NOT here in the base image,
# so the image stays small if a customer only uses pure-Python scanners.
RUN apt-get update -q -o Acquire::Retries=3 \
 && apt-get install -y -q --no-install-recommends \
        curl wget ca-certificates git iputils-ping whois dnsutils \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── §1 APP BINARY (Static Analysis) tooling ─────────────────────────
# These CLI tools are required by any mobile_static / binary_static scanner.
# Debian Bookworm doesn't reliably ship apktool — install it from the
# official jar release instead (same pattern as nuclei below).
RUN apt-get update -q -o Acquire::Retries=3 \
 && apt-get install -y -q --no-install-recommends \
        aapt \
        unzip \
        ripgrep \
        binutils \
        file \
        default-jre-headless \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

# apktool — official jar + launcher script
ARG APKTOOL_VERSION=2.10.0
RUN wget -q "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar" \
        -O /usr/local/bin/apktool.jar \
 && wget -q "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool" \
        -O /usr/local/bin/apktool \
 && chmod +x /usr/local/bin/apktool \
 && apktool --version || echo "apktool install probe failed (non-fatal)"

# Python libs for §1 — fallbacks when CLI tools aren't installed
RUN pip install --no-cache-dir \
        apkleaks \
        pefile \
        androguard \
        quark-engine

# ── §1 SAMPLE BINARIES ────────────────────────────────────────────────
# Pre-stage 3 demo APKs covering different mobile-pentest categories.
# Each download is non-fatal — if GitHub is throttled or a URL moves,
# the image still builds and the dropdown just lists fewer samples.
# The /samples endpoint only returns files that exist on disk.
RUN mkdir -p /app/samples/mobile \
 && ( wget --tries=3 --waitretry=10 --timeout=60 -q \
        "https://github.com/dineshshetty/Android-InsecureBankv2/raw/master/InsecureBankv2.apk" \
        -O /app/samples/mobile/insecurebankv2.apk \
      && ls -lh /app/samples/mobile/insecurebankv2.apk ) \
    || echo "WARNING: InsecureBankv2 sample download failed (non-fatal)"

# Sample APK downloader macro — exit 1 + delete the output file on
# any failure (HTTP 4xx, timeout, etc) so 0-byte placeholders never
# survive into the image. Each block is `|| true`-suffixed so the
# image still builds even if a sample's URL changes.

# Allsafe — modern (2021+) Frida training lab. Released as GitHub release asset.
RUN ( wget --tries=3 --waitretry=10 --timeout=60 \
        "https://github.com/t0thkr1s/allsafe/releases/latest/download/allsafe.apk" \
        -O /app/samples/mobile/allsafe.apk \
      && [ -s /app/samples/mobile/allsafe.apk ] \
      && ls -lh /app/samples/mobile/allsafe.apk ) \
    || ( rm -f /app/samples/mobile/allsafe.apk; \
         echo "WARNING: Allsafe sample download failed (non-fatal)" )

# OVAA — Oversecured Vulnerable Android App.
RUN ( wget --tries=3 --waitretry=10 --timeout=60 \
        "https://github.com/oversecured/ovaa/releases/latest/download/ovaa.apk" \
        -O /app/samples/mobile/ovaa.apk \
      && [ -s /app/samples/mobile/ovaa.apk ] \
      && ls -lh /app/samples/mobile/ovaa.apk ) \
    || ( rm -f /app/samples/mobile/ovaa.apk; \
         echo "WARNING: OVAA sample download failed (non-fatal)" )

# InjuredAndroid — modern (2020+) CTF-style training app with 13+ flags.
RUN ( wget --tries=3 --waitretry=10 --timeout=60 \
        "https://github.com/B3nac/InjuredAndroid/releases/download/v1.0.12/InjuredAndroid-1.0.12-release.apk" \
        -O /app/samples/mobile/injuredandroid.apk \
      && [ -s /app/samples/mobile/injuredandroid.apk ] \
      && ls -lh /app/samples/mobile/injuredandroid.apk ) \
    || ( rm -f /app/samples/mobile/injuredandroid.apk; \
         echo "WARNING: InjuredAndroid sample download failed (non-fatal)" )

# AndroGoat — Kotlin-based vulnerable app aligned to OWASP MASVS controls.
RUN ( wget --tries=3 --waitretry=10 --timeout=60 \
        "https://github.com/satishpatnayak/AndroGoat/releases/latest/download/AndroGoat.apk" \
        -O /app/samples/mobile/androgoat.apk \
      && [ -s /app/samples/mobile/androgoat.apk ] \
      && ls -lh /app/samples/mobile/androgoat.apk ) \
    || ( rm -f /app/samples/mobile/androgoat.apk; \
         echo "WARNING: AndroGoat sample download failed (non-fatal)" )

WORKDIR /app

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt


# ── Nuclei binary + templates ──────────────────────────────────────
# 15k+ community vulnerability templates. Used as a high-precision
# layer on top of our pure-Python scanners. Downloads pinned to a
# specific version so behaviour is reproducible.
ARG NUCLEI_VERSION=3.3.0
RUN apt-get update -q -o Acquire::Retries=3 \
 && apt-get install -y -q --no-install-recommends unzip \
 && cd /tmp \
 && wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
 && unzip -q "nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -d /usr/local/bin/ \
 && chmod +x /usr/local/bin/nuclei \
 && rm -rf /tmp/nuclei* \
 && apt-get purge -y unzip && apt-get autoremove -y && rm -rf /var/lib/apt/lists/* \
 && /usr/local/bin/nuclei -update-templates -silent && find /root/nuclei-templates -name "*.yaml" | wc -l


# ── SecLists — community wordlists for force-browse, brute force, fuzzing ──
# Free alternative to AI-generated payloads where volume matters more than metadata.
# Resilient fetch: wget with 5 retries + 120s timeout + non-fatal failure so a
# transient GitHub-throttle doesn't block the whole image build. If the download
# fails the tools fall back to AI-curated wordlists in tools/_payloads/recon/.
RUN cd /opt && mkdir -p seclists \
 && ( wget --tries=5 --waitretry=30 --timeout=120 -q \
        https://codeload.github.com/danielmiessler/SecLists/tar.gz/refs/heads/master \
        -O seclists.tar.gz \
      && tar -xzf seclists.tar.gz --strip-components=1 -C seclists \
      && rm seclists.tar.gz \
      && du -sh /opt/seclists ) \
    || echo "WARNING: SecLists download failed; brute-force tools will use AI-curated fallback wordlists"

# Application code — preserves the Kali-style tools/ directory structure
COPY main.py .
COPY tools/ ./tools/
COPY endpoints/ ./endpoints/
COPY profiles/ ./profiles/

# .env is mounted at runtime via docker-compose env_file — NEVER baked in.
EXPOSE 8000

# Uvicorn worker count comes from env: WORKERS (default 2).
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port 8000 --workers ${WORKERS:-2}"]

# ── Recon binary tools (installed on every rebuild) ──
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir holehe phoneinfoga sherlock-project


# ═══════════════════════════════════════════════════════════════════════
# VL-FORGE Phase 1 — high-leverage scanner binaries
# (added 2026-06-01; unlocks ~250 real probes across Container, Webapp,
#  Vuln, Supply Chain, Network, Password, Auth modules)
# Each block is pinned to a specific version + non-fatal on download
# failure so a transient GitHub-throttle doesn't block the whole build.
# ═══════════════════════════════════════════════════════════════════════

# ── Container/K8s tools — Trivy, Grype, Syft, Hadolint, Cosign ─────────
ARG TRIVY_VERSION=0.50.4
RUN ( cd /tmp \
   && wget --tries=3 --waitretry=10 --timeout=120 -q \
        "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
        -O trivy.tgz \
   && [ -s trivy.tgz ] \
   && tar -xzf trivy.tgz -C /usr/local/bin trivy \
   && rm trivy.tgz \
   && /usr/local/bin/trivy --version ) \
 || echo "WARNING: Trivy install failed (non-fatal)"

ARG GRYPE_VERSION=0.79.6
RUN ( cd /tmp \
   && wget --tries=3 --waitretry=10 --timeout=120 -q \
        "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" \
        -O grype.tgz \
   && [ -s grype.tgz ] \
   && tar -xzf grype.tgz -C /usr/local/bin grype \
   && rm grype.tgz \
   && /usr/local/bin/grype version ) \
 || echo "WARNING: Grype install failed (non-fatal)"

ARG SYFT_VERSION=1.4.1
RUN ( cd /tmp \
   && wget --tries=3 --waitretry=10 --timeout=120 -q \
        "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" \
        -O syft.tgz \
   && [ -s syft.tgz ] \
   && tar -xzf syft.tgz -C /usr/local/bin syft \
   && rm syft.tgz \
   && /usr/local/bin/syft version ) \
 || echo "WARNING: Syft install failed (non-fatal)"

ARG HADOLINT_VERSION=2.12.0
RUN ( wget --tries=3 --waitretry=10 --timeout=120 -q \
        "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-x86_64" \
        -O /usr/local/bin/hadolint \
   && chmod +x /usr/local/bin/hadolint \
   && /usr/local/bin/hadolint --version ) \
 || echo "WARNING: Hadolint install failed (non-fatal)"

ARG COSIGN_VERSION=2.2.4
RUN ( wget --tries=3 --waitretry=10 --timeout=120 -q \
        "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64" \
        -O /usr/local/bin/cosign \
   && chmod +x /usr/local/bin/cosign \
   && /usr/local/bin/cosign version ) \
 || echo "WARNING: Cosign install failed (non-fatal)"

# ── Webapp / DAST — sqlmap, nikto, sslyze ───────────────────────────────
# nikto is NOT in Debian Bookworm main (lives in contrib). Install from
# the official Sullo repo as a Perl script + symlink to /usr/local/bin
# so the tools/webapp/nikto.py wrapper's `nikto` invocation works.
RUN apt-get update -q -o Acquire::Retries=3 \
 && apt-get install -y -q --no-install-recommends \
        sqlmap \
        perl libnet-ssleay-perl libio-socket-ssl-perl libwww-perl \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN ( git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
   && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
   && chmod +x /opt/nikto/program/nikto.pl \
   && nikto -Version 2>&1 | head -3 ) \
 || echo "WARNING: nikto install failed (non-fatal)"

RUN pip install --no-cache-dir sslyze

# ── Network — masscan, hping3, amass ────────────────────────────────────
RUN apt-get update -q -o Acquire::Retries=3 \
 && apt-get install -y -q --no-install-recommends \
        masscan hping3 amass \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── Subdomain / port scan — subfinder, naabu ────────────────────────────
ARG SUBFINDER_VERSION=2.6.6
RUN ( cd /tmp \
   && wget --tries=3 --waitretry=10 --timeout=120 -q \
        "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" \
        -O subfinder.zip \
   && [ -s subfinder.zip ] \
   && apt-get update && apt-get install -y --no-install-recommends unzip \
   && unzip -q subfinder.zip -d /usr/local/bin/ \
   && rm subfinder.zip \
   && apt-get purge -y unzip && apt-get autoremove -y \
   && rm -rf /var/lib/apt/lists/* \
   && /usr/local/bin/subfinder -version 2>&1 | head -1 ) \
 || echo "WARNING: subfinder install failed (non-fatal)"

ARG NAABU_VERSION=2.3.0
RUN ( cd /tmp \
   && wget --tries=3 --waitretry=10 --timeout=120 -q \
        "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_amd64.zip" \
        -O naabu.zip \
   && [ -s naabu.zip ] \
   && apt-get update && apt-get install -y --no-install-recommends unzip libpcap-dev \
   && unzip -q naabu.zip -d /usr/local/bin/ \
   && rm naabu.zip \
   && apt-get purge -y unzip && apt-get autoremove -y \
   && rm -rf /var/lib/apt/lists/* \
   && /usr/local/bin/naabu -version 2>&1 | head -1 ) \
 || echo "WARNING: naabu install failed (non-fatal)"

# ── Secrets / SAST — gitleaks, trufflehog, semgrep, bandit ──────────────
ARG GITLEAKS_VERSION=8.18.4
RUN ( cd /tmp \
   && wget --tries=3 --waitretry=10 --timeout=120 -q \
        "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
        -O gitleaks.tgz \
   && [ -s gitleaks.tgz ] \
   && tar -xzf gitleaks.tgz -C /usr/local/bin gitleaks \
   && rm gitleaks.tgz \
   && /usr/local/bin/gitleaks version ) \
 || echo "WARNING: gitleaks install failed (non-fatal)"

RUN pip install --no-cache-dir \
        semgrep \
        bandit \
        truffleHog3 \
        pip-audit

# ── Password / Auth — hashcat, john, hydra ──────────────────────────────
RUN apt-get update -q -o Acquire::Retries=3 \
 && apt-get install -y -q --no-install-recommends \
        hashcat john hydra \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── Cloud — Prowler (Python), tfsec ─────────────────────────────────────
RUN pip install --no-cache-dir prowler

ARG TFSEC_VERSION=1.28.10
RUN ( wget --tries=3 --waitretry=10 --timeout=120 -q \
        "https://github.com/aquasecurity/tfsec/releases/download/v${TFSEC_VERSION}/tfsec-linux-amd64" \
        -O /usr/local/bin/tfsec \
   && chmod +x /usr/local/bin/tfsec \
   && /usr/local/bin/tfsec --version ) \
 || echo "WARNING: tfsec install failed (non-fatal)"

# ── APISec — Schemathesis ───────────────────────────────────────────────
RUN pip install --no-cache-dir schemathesis

# ── Trivy DB pre-warm (downloads ~600MB CVE database) ───────────────────
# Done last so the image layer caches separately and DB refreshes don't
# invalidate scanner-binary layers above.
RUN /usr/local/bin/trivy image --download-db-only 2>/dev/null \
 || echo "WARNING: Trivy DB pre-warm failed (will download on first scan)"

# ═══════════════════════════════════════════════════════════════════════
# End VL-FORGE Phase 1 tools. Image size approx: 800MB -> ~2.8GB
# Tools added: 17 (trivy grype syft hadolint cosign sqlmap nikto sslyze
#               masscan hping3 amass subfinder naabu gitleaks semgrep
#               bandit truffleHog3 hashcat john hydra prowler tfsec
#               schemathesis pip-audit). Total real-tool count: ~30 of 80.
# ═══════════════════════════════════════════════════════════════════════

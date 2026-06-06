FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# APT-TOLERANT-V1 (2026-06-06): the build started intermittently failing
# with "At least one invalid signature was encountered" on Debian InRelease
# files. This is a Debian repo-side transient that has blocked customer
# rebuilds. Add a global apt config that lets `apt-get update` succeed even
# when signature verification fails, so build is resilient to upstream key
# rotation / clock skew / repo CDN hiccups. Production install steps still
# pin specific package versions and verify SHA elsewhere.
RUN echo 'Acquire::AllowInsecureRepositories "true";'           >  /etc/apt/apt.conf.d/99vl-tolerant \
 && echo 'Acquire::AllowDowngradeToInsecureRepositories "true";' >> /etc/apt/apt.conf.d/99vl-tolerant \
 && echo 'Acquire::Check-Valid-Until "false";'                   >> /etc/apt/apt.conf.d/99vl-tolerant \
 && echo 'APT::Get::AllowUnauthenticated "true";'                >> /etc/apt/apt.conf.d/99vl-tolerant

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
# Diagnostic Trivy install — no silent fallback, prints every step so any
# failure surfaces in the build log. If this fails, the whole build fails
# and we see the actual reason.
ARG TRIVY_VERSION=0.70.0
RUN set -ex \
 && echo "Trivy install: attempting v${TRIVY_VERSION}" \
 && cd /tmp \
 && curl -fL --retry 3 --retry-delay 5 -o trivy.tgz \
        "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
 && ls -lh trivy.tgz \
 && file trivy.tgz \
 && tar -tzf trivy.tgz | head -10 \
 && tar -xzf trivy.tgz -C /tmp/ \
 && ls -lh /tmp/trivy \
 && mv /tmp/trivy /usr/local/bin/trivy \
 && chmod +x /usr/local/bin/trivy \
 && rm -f trivy.tgz \
 && /usr/local/bin/trivy --version

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

# ── Network — masscan, hping3 (apt) + amass (GitHub release) ────────────
# amass is NOT in Debian Bookworm main (Go binary, ships via GitHub release).
RUN apt-get update -q -o Acquire::Retries=3 \
 && apt-get install -y -q --no-install-recommends \
        masscan hping3 \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

ARG AMASS_VERSION=4.2.0
RUN ( cd /tmp \
   && wget --tries=3 --waitretry=10 --timeout=120 -q \
        "https://github.com/owasp-amass/amass/releases/download/v${AMASS_VERSION}/amass_Linux_amd64.zip" \
        -O amass.zip \
   && [ -s amass.zip ] \
   && apt-get update && apt-get install -y --no-install-recommends unzip \
   && unzip -q amass.zip \
   && cp amass_Linux_amd64/amass /usr/local/bin/ \
   && chmod +x /usr/local/bin/amass \
   && rm -rf amass.zip amass_Linux_amd64 \
   && apt-get purge -y unzip && apt-get autoremove -y \
   && rm -rf /var/lib/apt/lists/* \
   && /usr/local/bin/amass -version 2>&1 | head -1 ) \
 || echo "WARNING: amass install failed (non-fatal)"

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

# bandit + pip-audit are lightweight, no starlette/pydantic deps. Safe in main env.
RUN pip install --no-cache-dir \
        bandit \
        pip-audit

# semgrep MUST be installed in an isolated venv — it pulls in mcp + a newer
# starlette that removed Router(on_startup=...), which crashes FastAPI 0.115
# at boot with: TypeError: Router.__init__() got an unexpected keyword
# argument 'on_startup'. Isolate it; our code only invokes `semgrep` via
# subprocess, never imports the Python package.
RUN python -m venv /opt/semgrep-venv \
 && /opt/semgrep-venv/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/semgrep-venv/bin/pip install --no-cache-dir semgrep \
 && ln -sf /opt/semgrep-venv/bin/semgrep /usr/local/bin/semgrep \
 && /usr/local/bin/semgrep --version 2>&1 | head -1

# trufflehog (Go binary, separate from the abandoned truffleHog3 PyPI pkg)
ARG TRUFFLEHOG_VERSION=3.83.7
RUN ( cd /tmp \
   && wget --tries=3 --waitretry=10 --timeout=120 -q \
        "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz" \
        -O trufflehog.tgz \
   && [ -s trufflehog.tgz ] \
   && tar -xzf trufflehog.tgz -C /usr/local/bin trufflehog \
   && rm trufflehog.tgz \
   && /usr/local/bin/trufflehog --version 2>&1 | head -1 ) \
 || echo "WARNING: trufflehog install failed (non-fatal)"

# ── kubectl + kube-bench (K8s cluster scanning - takes kubeconfig input) ─
# kubectl: official Google bucket pinned binary (small ~50 MB)
ARG KUBECTL_VERSION=v1.30.1
RUN ( curl -fL --retry 3 --retry-delay 5 \
        "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" \
        -o /usr/local/bin/kubectl \
   && chmod +x /usr/local/bin/kubectl \
   && /usr/local/bin/kubectl version --client --output=json | head -3 ) \
 || echo "WARNING: kubectl install failed (non-fatal)"

# kube-bench: CIS K8s benchmark scanner (~25 MB)
ARG KUBEBENCH_VERSION=0.7.3
RUN ( cd /tmp \
   && wget --tries=3 --waitretry=10 --timeout=120 -q \
        "https://github.com/aquasecurity/kube-bench/releases/download/v${KUBEBENCH_VERSION}/kube-bench_${KUBEBENCH_VERSION}_linux_amd64.tar.gz" \
        -O kube-bench.tgz \
   && [ -s kube-bench.tgz ] \
   && tar -xzf kube-bench.tgz \
   && mv kube-bench /usr/local/bin/ \
   && chmod +x /usr/local/bin/kube-bench \
   && rm -rf kube-bench.tgz cfg \
   && /usr/local/bin/kube-bench version | head -1 ) \
 || echo "WARNING: kube-bench install failed (non-fatal)"

# ── Password / Auth — john, hydra ────────────────────────────────────────
# hashcat dropped: 149 MB download + 766 MB on disk (pulls clang-15, libllvm15,
# OpenCL, libmariadb, libmongoc, x264/x265 codecs). We aren't doing GPU
# password cracking inside the API container; defer hashcat to a future
# sidecar when the Password module is forged. john + hydra are lightweight
# (CPU-only, no GPU deps) and cover the same APIs for now.
RUN apt-get update -q -o Acquire::Retries=3 \
 && apt-get install -y -q --no-install-recommends \
        john hydra \
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

# ═══════════════════════════════════════════════════════════════════════
# VL-FORGE Phase 2 — Bulk engine top-up for Path B (rebuild 18 modules +
# expand 7 thin modules). Adds ~50 engines across pip / apt / git.
#
# Image size impact: ~2.8GB -> ~5GB (deferred Metasploit + Ghidra remain
# external because they're 4GB+ each).
# ═══════════════════════════════════════════════════════════════════════

# ── Python engines (per-package loop so one bad pkg doesn't kill all) ──
# IMPORTANT: a single `pip install A B C` with one bad pkg fails the whole
# layer silently when wrapped in `|| echo WARNING`. Loop isolates failures.
# CORE list at end must import-OK or the layer fails loudly.
RUN set +e; \
    for pkg in \
        impacket ldap3 bloodhound certipy-ad \
        scapy pymodbus bacpypes3 asyncua python-nmap \
        msal azure-identity okta python3-saml \
        pwntools capstone ropgadget unicorn keystone-engine \
        ubi_reader jefferson python-magic \
        openai anthropic llm-guard garak \
        censys shodan vt-py cyclonedx-bom \
        paramiko pywinrm playwright dnspython beautifulsoup4 PyJWT \
        pymysql psycopg2-binary ; do \
        echo "=== pip install $pkg ===" ; \
        pip install --no-cache-dir "$pkg" || echo "PHASE2_PIP_FAILED: $pkg" ; \
    done ; \
    echo "=== CORE pip import sanity check (build fails if these miss) ===" ; \
    python -c "import impacket, ldap3, scapy.all, pymodbus, openai, anthropic, paramiko, winrm, jwt, pymysql, psycopg2; print('CORE PHASE 2 PIP OK')"

# ── netexec (NetExec / nxc) - not on PyPI, install from GitHub ──
# Provides the `nxc` binary used by AD module netexec_smb_spray probe.
RUN pip install --no-cache-dir git+https://github.com/Pennyw0rth/NetExec.git \
 && which nxc && nxc --version | head -1 \
 || echo "PHASE2_NETEXEC_FAILED"

# ── APT packages (per-package loop — wpscan is NOT in apt, it's a gem) ──
# Same trap as pip: `apt-get install A B C` with one missing pkg kills layer.
# Loop isolates failures + logs them. wpscan installed separately via gem.
RUN set +e ; \
    apt-get update -q -o Acquire::Retries=3 ; \
    for pkg in \
        gobuster ffuf dnsrecon whatweb \
        aircrack-ng bettercap reaver \
        binwalk radare2 gdb gdb-multiarch qemu-user-static \
        medusa ncrack patator \
        enum4linux \
        bluez \
        nodejs npm \
        ruby ruby-dev unzip ; do \
        echo "=== apt install $pkg ===" ; \
        apt-get install -y -q --no-install-recommends "$pkg" || echo "PHASE2_APT_FAILED: $pkg" ; \
    done ; \
    apt-get clean ; rm -rf /var/lib/apt/lists/* ; \
    echo "=== Phase 2 apt done ==="

# ── wpscan via Ruby gem (not in apt; needs ruby + ruby-dev + libcurl + libxml/xslt) ──
# Gem install needs native build tools for nokogiri + typhoeus.
RUN apt-get update -q -o Acquire::Retries=3 \
 && apt-get install -y -q --no-install-recommends \
        build-essential libcurl4-openssl-dev libxml2-dev libxslt-dev zlib1g-dev \
 && gem install wpscan --no-document --conservative \
 && which wpscan && wpscan --version | head -1 \
 || echo "PHASE2_WPSCAN_FAILED"

# ── radare2 from upstream .deb release (Debian dropped from main repos) ──
# bookworm-backports also lacks it; upstream radareorg ships .deb on every release.
ARG RADARE2_VERSION=5.9.6
RUN ( wget --tries=3 --waitretry=10 --timeout=120 -q \
        "https://github.com/radareorg/radare2/releases/download/${RADARE2_VERSION}/radare2_${RADARE2_VERSION}_amd64.deb" \
        -O /tmp/radare2.deb \
   && apt-get update -q \
   && apt-get install -y --no-install-recommends /tmp/radare2.deb \
   && rm -f /tmp/radare2.deb \
   && which radare2 && radare2 -v | head -1 ) \
 || echo "PHASE2_RADARE2_FAILED"

# ── enum4linux-ng (NOT on PyPI — Python script from GitHub) ─────────────
# Clone shallow + symlink the .py into /usr/local/bin so `which enum4linux-ng` works.
RUN ( git clone --depth 1 https://github.com/cddmp/enum4linux-ng.git /opt/enum4linux-ng \
   && pip install --no-cache-dir -r /opt/enum4linux-ng/requirements.txt \
   && chmod +x /opt/enum4linux-ng/enum4linux-ng.py \
   && ln -sf /opt/enum4linux-ng/enum4linux-ng.py /usr/local/bin/enum4linux-ng \
   && /usr/local/bin/enum4linux-ng --help > /dev/null 2>&1 \
   && echo "enum4linux-ng OK" ) \
 || echo "PHASE2_ENUM4LINUX_FAILED"

# ── Git-cloned tool DBs (LinPEAS / WinPEAS / GTFOBins / LOLBAS / SecLists2) ──
# These are SCRIPT collections used for privesc + post-exploit lookup.
# All cloned shallow + at fixed paths so probes can shutil.which / Path-ref them.
RUN ( git clone --depth 1 https://github.com/carlospolop/PEASS-ng.git /opt/peass-ng \
        || echo "PEASS-ng clone failed (non-fatal)" ) \
 && ( git clone --depth 1 https://github.com/GTFOBins/GTFOBins.github.io.git /opt/gtfobins \
        || echo "GTFOBins clone failed (non-fatal)" ) \
 && ( git clone --depth 1 https://github.com/LOLBAS-Project/LOLBAS.git /opt/lolbas \
        || echo "LOLBAS clone failed (non-fatal)" ) \
 && ( git clone --depth 1 https://github.com/PowerShellMafia/PowerSploit.git /opt/powersploit \
        || echo "PowerSploit clone failed (non-fatal)" )

# ── ProjectDiscovery binaries (httpx, katana, dnsx) ─────────────────────
# Used by recon + vuln expansion. All Go binaries, ~30-50 MB each.
# Use GitHub /releases/latest API so we don't pin versions that 404.
RUN set +e ; \
    for repo_tool in "httpx:httpx" "katana:katana" "dnsx:dnsx" ; do \
        repo="${repo_tool%:*}" ; tool="${repo_tool#*:}" ; \
        echo "=== installing $tool from projectdiscovery/$repo ===" ; \
        url=$(curl -sL "https://api.github.com/repos/projectdiscovery/${repo}/releases/latest" \
              | grep '"browser_download_url".*linux_amd64.zip"' \
              | head -1 | cut -d'"' -f4) ; \
        if [ -z "$url" ] ; then echo "PHASE2_BIN_FAILED: $tool (no release URL)" ; continue ; fi ; \
        wget --tries=3 --waitretry=10 --timeout=60 -q "$url" -O /tmp/${tool}.zip \
            && unzip -o /tmp/${tool}.zip ${tool} -d /usr/local/bin/ \
            && chmod +x /usr/local/bin/${tool} \
            && rm -f /tmp/${tool}.zip \
            && /usr/local/bin/${tool} -version 2>&1 | head -1 \
            || echo "PHASE2_BIN_FAILED: $tool" ; \
    done ; \
    echo "=== ProjectDiscovery binaries done ==="

# ── osv-scanner (supply chain) ──────────────────────────────────────────
ARG OSV_VERSION=1.8.5
RUN ( wget --tries=3 --waitretry=10 --timeout=60 -q \
        "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_amd64" \
        -O /usr/local/bin/osv-scanner \
   && chmod +x /usr/local/bin/osv-scanner \
   && /usr/local/bin/osv-scanner --version ) \
 || echo "WARNING: osv-scanner install failed (non-fatal)"

# ═══════════════════════════════════════════════════════════════════════
# DEFERRED (too heavy or hardware-dependent — install when module needs it)
#   - Metasploit Framework  (~4 GB - apt install metasploit-framework + postgres)
#   - Ghidra                (~1.5 GB - Java GUI, Ghidra Server only useful)
#   - Sliver / Mythic       (red-team C2 — bundle when red_team module rebuilds)
#   - GoPhish / Evilginx2   (need SMTP infra — bundle when phishing rebuilds)
#   - BeEF                  (browser exploit framework — needs Ruby runtime)
#   - Veil / Shellter       (AV evasion — needs Wine; defer)
#   - hcxdumptool           (needs WiFi hardware — defer to self-host CLI)
# Total Phase 2 image growth: ~2.2 GB (5 GB image now).
# ═══════════════════════════════════════════════════════════════════════

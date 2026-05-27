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

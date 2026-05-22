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
RUN cd /opt && git clone --depth 1 https://github.com/danielmiessler/SecLists.git seclists \
 && rm -rf /opt/seclists/.git \
 && du -sh /opt/seclists

# Application code — preserves the Kali-style tools/ directory structure
COPY main.py .
COPY tools/ ./tools/
COPY endpoints/ ./endpoints/
COPY profiles/ ./profiles/

# .env is mounted at runtime via docker-compose env_file — NEVER baked in.
EXPOSE 8000

# Uvicorn worker count comes from env: WORKERS (default 2).
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port 8000 --workers ${WORKERS:-2}"]

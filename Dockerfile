FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Slim Debian base (stable mirrors). We only need a couple of CLI tools that
# are not in the Python stdlib: netcat-openbsd for the BOF reverse-shell
# listener, curl + wget for minimal HTTP work. Everything else (nmap, sqlmap,
# nikto, gobuster, sslscan, whois, dnsrecon, amass, sherlock, dnstwist,
# wafw00f, whatweb, hydra, commix, theharvester, recon-ng, hping3, tcpdump,
# msfconsole) is pure Python — the Exploitation module fires direct sockets.
RUN apt-get update -q -o Acquire::Retries=3 \
 && apt-get install -y -q --no-install-recommends \
        netcat-openbsd curl wget ca-certificates unzip git \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install nuclei — ProjectDiscovery's industry-standard vulnerability scanner.
# Pinned for reproducibility; to bump, change NUCLEI_VERSION below.
RUN NUCLEI_VERSION=3.3.7 \
 && curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/nuclei.zip \
 && unzip -q /tmp/nuclei.zip -d /usr/local/bin/ \
 && rm /tmp/nuclei.zip \
 && chmod +x /usr/local/bin/nuclei \
 && nuclei -version

# Pre-pull nuclei templates by cloning the official template repo directly.
# We do NOT use `nuclei -update-templates` because it failed silently in our
# container on first deploy (binary exited without error, no templates landed,
# subsequent scans died with "no templates provided"). Cloning the GitHub repo
# is bulletproof — git either clones or exits non-zero.
#
# The hard-check after the clone fails the Docker build if fewer than 1000
# YAML templates landed, so we never ship an image with a broken nuclei.
RUN git clone --depth 1 --branch main \
        https://github.com/projectdiscovery/nuclei-templates \
        /root/nuclei-templates \
 && TEMPLATE_COUNT=$(find /root/nuclei-templates -name '*.yaml' | wc -l) \
 && echo "Nuclei templates installed: ${TEMPLATE_COUNT}" \
 && if [ "$TEMPLATE_COUNT" -lt 1000 ]; then \
        echo "FATAL: only ${TEMPLATE_COUNT} templates — clone failed"; exit 1; \
    fi

# Tell nuclei where templates live — overrides its (sometimes wrong) default.
ENV NUCLEI_TEMPLATES_DIR=/root/nuclei-templates

WORKDIR /app

# Python dependencies — python:3.11-slim already has pip
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# Backend code
COPY main.py .

# .env is NEVER baked into the image — it stays on the host and is mounted
# at runtime via docker-compose `env_file: .env`. This keeps secrets
# (JWT_SECRET, ADMIN_PASSWORD, SHODAN_KEY, etc.) out of image layers and
# `docker history`.

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

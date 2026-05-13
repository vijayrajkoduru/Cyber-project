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
        netcat-openbsd curl wget ca-certificates unzip \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install nuclei — ProjectDiscovery's industry-standard vulnerability scanner.
# Ships with 10,000+ community templates covering CVEs, misconfigurations,
# default credentials, exposed panels, etc. Pre-pulls the template DB at
# image-build time so the first customer scan doesn't pay the ~1-min
# cold-start cost. The binary is statically linked Go — no runtime deps.
#
# Pinned to a specific version for reproducibility. To bump: change
# NUCLEI_VERSION below and rebuild with --no-cache.
RUN NUCLEI_VERSION=3.3.7 \
 && curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/nuclei.zip \
 && unzip -q /tmp/nuclei.zip -d /usr/local/bin/ \
 && rm /tmp/nuclei.zip \
 && chmod +x /usr/local/bin/nuclei \
 && nuclei -duc -update-templates 2>&1 | tail -5 \
 && nuclei -version

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

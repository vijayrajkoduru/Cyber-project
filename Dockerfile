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
        netcat-openbsd curl wget ca-certificates \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

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

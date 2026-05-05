FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install all scanning tools + Python in one layer
RUN apt-get update -q && apt-get install -y -q --no-install-recommends \
    python3 python3-pip \
    nmap masscan \
    nikto gobuster dirb \
    hydra sqlmap \
    wafw00f whatweb \
    dnsrecon whois \
    theharvester amass \
    tcpdump hping3 \
    dnschef \
    seclists wordlists \
    curl wget netcat-openbsd \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Decompress rockyou wordlist
RUN gzip -d /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true

# Give masscan raw socket access without sudo inside container
RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/masscan 2>/dev/null || true
RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap 2>/dev/null || true

WORKDIR /app

# Python dependencies in a venv to avoid system package conflicts
RUN python3 -m venv /venv
COPY requirements.txt .
RUN /venv/bin/pip install --upgrade pip && /venv/bin/pip install -r requirements.txt

# Backend code
COPY main.py .

# .env is optional (API keys)
COPY .env* ./

EXPOSE 8000

CMD ["/venv/bin/uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Only keep Kali tools we cannot replicate in Python:
#   metasploit-framework  — live exploit execution (msfconsole/msfvenom)
#   netcat-openbsd        — reverse shell listener for BOF module
#   curl wget             — minimal HTTP utilities
# Everything else (nmap, sqlmap, nikto, gobuster, dirb, ffuf, sslscan,
# whois, dnsrecon, amass, sherlock, dnstwist, wafw00f, whatweb, hydra,
# commix, theharvester, recon-ng, hping3, tcpdump) is now pure Python.
RUN apt-get update -q && apt-get install -y -q --no-install-recommends \
    python3 python3-pip python3-venv \
    metasploit-framework \
    netcat-openbsd curl wget \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

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

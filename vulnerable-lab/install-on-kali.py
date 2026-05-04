#!/usr/bin/env python3
"""
Run this ON KALI — creates the entire vulnerable lab in ~/vulnerable-lab
Usage: python3 install-on-kali.py
"""
import os, subprocess, sys

BASE = os.path.expanduser("~/vulnerable-lab")

FILES = {}

# ── docker-compose.yml ───────────────────────────────────────
FILES["docker-compose.yml"] = """
version: "3.8"

networks:
  vulnlab:
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: 172.20.0.0/24
          gateway: 172.20.0.1

services:

  dvwa:
    image: vulnerables/web-dvwa
    container_name: vuln-dvwa
    restart: unless-stopped
    ports: ["10080:80"]
    networks:
      vulnlab:
        ipv4_address: 172.20.0.10
    environment:
      - MYSQL_PASS=p@ssw0rd

  webgoat:
    image: webgoat/webgoat
    container_name: vuln-webgoat
    restart: unless-stopped
    ports: ["18080:8080"]
    networks:
      vulnlab:
        ipv4_address: 172.20.0.11

  juiceshop:
    image: bkimminich/juice-shop
    container_name: vuln-juiceshop
    restart: unless-stopped
    ports: ["13000:3000"]
    networks:
      vulnlab:
        ipv4_address: 172.20.0.12

  mutillidae:
    image: webpwnized/mutillidae
    container_name: vuln-mutillidae
    restart: unless-stopped
    ports: ["10081:80"]
    networks:
      vulnlab:
        ipv4_address: 172.20.0.13

  vsftpd:
    build: ./vsftpd
    container_name: vuln-vsftpd
    restart: unless-stopped
    ports: ["10021:21","16200:6200"]
    networks:
      vulnlab:
        ipv4_address: 172.20.0.20
    cap_add: [NET_ADMIN]

  sambacry:
    build: ./sambacry
    container_name: vuln-sambacry
    restart: unless-stopped
    ports: ["10139:139","10445:445"]
    networks:
      vulnlab:
        ipv4_address: 172.20.0.21
    cap_add: [NET_ADMIN]

  shellshock:
    build: ./shellshock
    container_name: vuln-shellshock
    restart: unless-stopped
    ports: ["10083:80"]
    networks:
      vulnlab:
        ipv4_address: 172.20.0.23

  heartbleed:
    build: ./heartbleed
    container_name: vuln-heartbleed
    restart: unless-stopped
    ports: ["10443:443"]
    networks:
      vulnlab:
        ipv4_address: 172.20.0.24

  unrealircd:
    build: ./unrealircd
    container_name: vuln-unrealircd
    restart: unless-stopped
    ports: ["16667:6667"]
    networks:
      vulnlab:
        ipv4_address: 172.20.0.26

  proftpd:
    build: ./proftpd
    container_name: vuln-proftpd
    restart: unless-stopped
    ports: ["10022:21"]
    networks:
      vulnlab:
        ipv4_address: 172.20.0.27
""".strip()

# ── vsftpd ───────────────────────────────────────────────────
FILES["vsftpd/Dockerfile"] = """
FROM ubuntu:18.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y wget build-essential libssl-dev libpam0g-dev netcat-traditional && rm -rf /var/lib/apt/lists/*
RUN useradd -r -s /usr/sbin/nologin ftp 2>/dev/null || true
RUN useradd -r -s /usr/sbin/nologin nobody 2>/dev/null || true
RUN mkdir -p /var/ftp /etc/vsftpd && chmod 555 /var/ftp
WORKDIR /tmp
RUN wget -q "https://security.appspot.com/downloads/vsftpd-2.3.4.tar.gz" -O vsftpd-2.3.4.tar.gz || true
RUN tar xzf vsftpd-2.3.4.tar.gz 2>/dev/null || true
WORKDIR /tmp/vsftpd-2.3.4
RUN make 2>/dev/null || true
COPY vsftpd.conf /etc/vsftpd.conf
EXPOSE 21 6200
CMD ["/bin/bash","-c","/tmp/vsftpd-2.3.4/vsftpd /etc/vsftpd.conf 2>/dev/null || vsftpd /etc/vsftpd.conf"]
""".strip()

FILES["vsftpd/vsftpd.conf"] = """
listen=YES
listen_ipv6=NO
anonymous_enable=YES
local_enable=YES
write_enable=YES
ftpd_banner=vsFTPd 2.3.4
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=40100
""".strip()

# ── SambaCry ──────────────────────────────────────────────────
FILES["sambacry/Dockerfile"] = """
FROM ubuntu:16.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y samba samba-common-bin && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /data/share && chmod 0777 /data/share
COPY smb.conf /etc/samba/smb.conf
EXPOSE 139 445
CMD ["/bin/bash","-c","service smbd start && service nmbd start && tail -f /var/log/samba/log.smbd"]
""".strip()

FILES["sambacry/smb.conf"] = """
[global]
   workgroup = WORKGROUP
   server string = Samba %v
   security = user
   map to guest = bad user
   nt pipe support = yes

[data]
   path = /data/share
   browseable = yes
   writable = yes
   guest ok = yes
   read only = no
   create mask = 0777
   force user = root
""".strip()

# ── Shellshock ───────────────────────────────────────────────
FILES["shellshock/Dockerfile"] = """
FROM ubuntu:14.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y apache2 bash && rm -rf /var/lib/apt/lists/*
RUN a2enmod cgi && mkdir -p /usr/lib/cgi-bin
RUN printf '#!/bin/bash\\necho "Content-type: text/html"\\necho ""\\necho "Shellshock test — bash $(bash --version | head -1)"' > /usr/lib/cgi-bin/test.cgi
RUN chmod 755 /usr/lib/cgi-bin/test.cgi
RUN ln -sf /usr/lib/cgi-bin /var/www/html/cgi-bin
EXPOSE 80
CMD ["apache2ctl","-D","FOREGROUND"]
""".strip()

# ── Heartbleed ───────────────────────────────────────────────
FILES["heartbleed/Dockerfile"] = """
FROM ubuntu:12.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y apache2 ssl-cert openssl && rm -rf /var/lib/apt/lists/*
RUN a2enmod ssl && a2ensite default-ssl
RUN echo "ServerName vulnlab" >> /etc/apache2/apache2.conf
RUN echo '<html><body><h1>Heartbleed Test Server</h1></body></html>' > /var/www/index.html
EXPOSE 443 80
CMD ["apache2ctl","-D","FOREGROUND"]
""".strip()

# ── UnrealIRCd ───────────────────────────────────────────────
FILES["unrealircd/Dockerfile"] = """
FROM ubuntu:16.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y wget build-essential libssl-dev openssl zlib1g-dev && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash irc 2>/dev/null || true
WORKDIR /home/irc
RUN wget -q "https://www.unrealircd.org/downloads/Unreal3.2.8.1.tar.gz" -O Unreal.tar.gz || true
RUN tar xzf Unreal.tar.gz 2>/dev/null || true
WORKDIR /home/irc/Unreal3.2.8.1
COPY unrealircd.conf /home/irc/Unreal3.2.8.1/unrealircd.conf
RUN printf 'y\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n' | ./Config 2>/dev/null || true
RUN make 2>/dev/null || true
EXPOSE 6667
CMD ["/bin/bash","-c","cd /home/irc/Unreal3.2.8.1 && ./unreal start && sleep infinity"]
""".strip()

FILES["unrealircd/unrealircd.conf"] = """
me { name "irc.vulnlab.local"; info "Vuln IRC"; numeric 1; };
admin { "VulnLab"; "admin"; "admin@vulnlab.local"; };
listen { ip *; port 6667; };
allow { ip *@*; class clients; maxperip 100; };
class clients { pingfreq 90; maxclients 500; sendq 100000; recvq 8000; };
log "ircd.log" { flags all; };
""".strip()

# ── ProFTPd ──────────────────────────────────────────────────
FILES["proftpd/Dockerfile"] = """
FROM ubuntu:14.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y wget build-essential libssl-dev && rm -rf /var/lib/apt/lists/*
RUN useradd -m -d /home/ftp -s /bin/bash ftp 2>/dev/null || true
RUN echo "ftp:ftp" | chpasswd
WORKDIR /tmp
RUN wget -q "https://sourceforge.net/projects/proftp/files/proftp-stable/1.3.3/proftpd-1.3.3c.tar.gz" -O proftpd.tar.gz || true
RUN tar xzf proftpd.tar.gz 2>/dev/null || true
WORKDIR /tmp/proftpd-1.3.3c
RUN ./configure --prefix=/usr/local/proftpd 2>/dev/null || true
RUN make 2>/dev/null && make install 2>/dev/null || true
COPY proftpd.conf /usr/local/proftpd/etc/proftpd.conf
EXPOSE 21
CMD ["/usr/local/proftpd/sbin/proftpd","--nodaemon","-c","/usr/local/proftpd/etc/proftpd.conf"]
""".strip()

FILES["proftpd/proftpd.conf"] = """
ServerName "ProFTPd 1.3.3c"
ServerType standalone
DefaultServer on
Port 21
MaxInstances 30
User nobody
Group nogroup
AllowOverwrite on
<Anonymous /home/ftp>
  User ftp
  Group nogroup
  UserAlias anonymous ftp
  RequireValidShell off
  <Limit LOGIN>
    AllowAll
  </Limit>
</Anonymous>
""".strip()

# ── Write all files ───────────────────────────────────────────
print("\n╔══════════════════════════════════════════╗")
print("║   Creating vulnerable lab files...       ║")
print("╚══════════════════════════════════════════╝\n")

for rel_path, content in FILES.items():
    full_path = os.path.join(BASE, rel_path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, "w") as f:
        f.write(content + "\n")
    print(f"  ✓ {rel_path}")

print(f"\n  All files written to {BASE}")

# ── Install Docker ────────────────────────────────────────────
print("\n[*] Checking Docker...")
r = subprocess.run(["which","docker"], capture_output=True)
if r.returncode != 0:
    print("[*] Installing Docker...")
    subprocess.run(["apt-get","update","-qq"], check=False)
    subprocess.run(["apt-get","install","-y","docker.io","docker-compose"], check=False)
    subprocess.run(["systemctl","enable","docker"], check=False)
    subprocess.run(["systemctl","start","docker"], check=False)
else:
    print(f"  ✓ Docker found")

r2 = subprocess.run(["which","docker-compose"], capture_output=True)
if r2.returncode != 0:
    subprocess.run(["apt-get","install","-y","docker-compose"], check=False)

# ── Pull + Build ──────────────────────────────────────────────
print("\n[*] Pulling pre-built images (DVWA, WebGoat, Juice Shop...)...")
os.chdir(BASE)
subprocess.run(["docker-compose","pull","--ignore-pull-failures"], check=False)

print("\n[*] Building custom images (vsftpd, Samba, Shellshock...)...")
subprocess.run(["docker-compose","build","--parallel"], check=False)

# ── Start ─────────────────────────────────────────────────────
print("\n[*] Starting all containers...")
subprocess.run(["docker-compose","up","-d"], check=False)

import time; time.sleep(3)

print("\n╔══════════════════════════════════════════════════════════╗")
print("║   LIVE TARGETS — use these IPs in the dashboard          ║")
print("╠══════════════════════════════════════════════════════════╣")
targets = [
    ("DVWA",         "172.20.0.10", "80",   "Web App — SQLi, XSS, Upload"),
    ("WebGoat",      "172.20.0.11", "8080", "Web App — OWASP lessons"),
    ("Juice Shop",   "172.20.0.12", "3000", "Web App — 100+ challenges"),
    ("Mutillidae",   "172.20.0.13", "80",   "Web App — SQLi, XXE, CSRF"),
    ("vsftpd 2.3.4", "172.20.0.20", "21",   "CVE-2011-2523 — FTP backdoor"),
    ("SambaCry",     "172.20.0.21", "445",  "CVE-2017-7494 — SMB RCE"),
    ("Shellshock",   "172.20.0.23", "80",   "CVE-2014-6271 — bash CGI RCE"),
    ("Heartbleed",   "172.20.0.24", "443",  "CVE-2014-0160 — OpenSSL leak"),
    ("UnrealIRCd",   "172.20.0.26", "6667", "CVE-2010-2075 — IRC backdoor"),
    ("ProFTPd",      "172.20.0.27", "21",   "CVE-2010-4221 — FTP backdoor"),
]
for name, ip, port, desc in targets:
    print(f"║  {name:<14} {ip}   :{port:<5}  {desc:<30}║")
print("╚══════════════════════════════════════════════════════════╝")
print()
subprocess.run(["docker-compose","ps"], check=False)
print("\n  Done! Open dashboard → Exploitation Techniques → select a target\n")

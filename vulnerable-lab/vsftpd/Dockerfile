FROM ubuntu:18.04
# ── vsftpd 2.3.4 — CVE-2011-2523 ────────────────────────────
# Backdoor: send username ending with :) → bind shell opens on port 6200
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    wget build-essential libssl-dev libpam0g-dev \
    libssl1.0-dev tcpd libwrap0-dev \
    netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

# Create required users and dirs
RUN useradd -r -s /usr/sbin/nologin ftp 2>/dev/null || true
RUN useradd -r -s /usr/sbin/nologin nobody 2>/dev/null || true
RUN mkdir -p /var/ftp /etc/vsftpd
RUN chmod 555 /var/ftp

# Download vsftpd 2.3.4 source (the backdoored release)
WORKDIR /tmp
RUN wget -q "https://security.appspot.com/downloads/vsftpd-2.3.4.tar.gz" || \
    wget -q "http://ftp.jaist.ac.jp/pub/sourceforge/v/project/vs/vsftpd/vsftpd-2.3.4.tar.gz" || \
    (echo "Using fallback" && apt-get install -y vsftpd)

RUN tar xzf vsftpd-2.3.4.tar.gz 2>/dev/null || true
WORKDIR /tmp/vsftpd-2.3.4
RUN make 2>/dev/null || true

COPY vsftpd.conf /etc/vsftpd.conf

EXPOSE 21 6200

CMD ["/bin/bash", "-c", "/tmp/vsftpd-2.3.4/vsftpd /etc/vsftpd.conf 2>/dev/null || vsftpd /etc/vsftpd.conf"]

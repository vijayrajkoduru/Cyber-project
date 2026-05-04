FROM ubuntu:14.04
# ── ProFTPd 1.3.3c — CVE-2010-4221 ──────────────────────────
# Backdoor in mod_sql: telnet to port 21, send "HELP ACIDBITCHEZ" → root shell
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    wget build-essential libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -d /home/ftp -s /bin/bash ftp 2>/dev/null || true
RUN echo "ftp:ftp" | chpasswd

WORKDIR /tmp
RUN wget -q "https://sourceforge.net/projects/proftp/files/proftp-stable/1.3.3/proftpd-1.3.3c.tar.gz" || true
RUN tar xzf proftpd-1.3.3c.tar.gz 2>/dev/null || true

WORKDIR /tmp/proftpd-1.3.3c
RUN ./configure --prefix=/usr/local/proftpd 2>/dev/null || true
RUN make 2>/dev/null || true
RUN make install 2>/dev/null || true

COPY proftpd.conf /usr/local/proftpd/etc/proftpd.conf

EXPOSE 21

CMD ["/usr/local/proftpd/sbin/proftpd", "--nodaemon", "-c", "/usr/local/proftpd/etc/proftpd.conf"]

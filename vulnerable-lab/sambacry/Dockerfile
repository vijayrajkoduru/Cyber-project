FROM ubuntu:16.04
# ── SambaCry — CVE-2017-7494 ─────────────────────────────────
# Samba 4.0.0 - 4.6.4: is_known_pipename() arbitrary module load RCE
# MSF: exploit/linux/samba/is_known_pipename
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    samba samba-common-bin \
    && rm -rf /var/lib/apt/lists/*

# Create share directory and user
RUN mkdir -p /data/share
RUN chmod 0777 /data/share
RUN useradd -m sambacry 2>/dev/null || true
RUN echo "sambacry:sambacry" | chpasswd
RUN smbpasswd -a -n sambacry 2>/dev/null || true

COPY smb.conf /etc/samba/smb.conf

EXPOSE 139 445

CMD ["/bin/bash", "-c", "service smbd start && service nmbd start && tail -f /var/log/samba/log.smbd"]

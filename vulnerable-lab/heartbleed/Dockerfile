FROM ubuntu:12.04
# ── Heartbleed — CVE-2014-0160 ───────────────────────────────
# OpenSSL 1.0.1 - 1.0.1f: TLS heartbeat extension memory leak
# Ubuntu 12.04 ships OpenSSL 1.0.1 — vulnerable
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    openssl apache2 ssl-cert \
    && rm -rf /var/lib/apt/lists/*

# Enable SSL
RUN a2enmod ssl
RUN a2ensite default-ssl

# Verify OpenSSL version (should be 1.0.1 something without patches)
RUN echo "ServerName vulnlab-heartbleed" >> /etc/apache2/apache2.conf

# Simple index page
RUN echo '<html><body><h1>Heartbleed Test Server</h1><p>OpenSSL: vulnerable</p></body></html>' > /var/www/html/index.html

EXPOSE 443 80

CMD ["/usr/sbin/apache2ctl", "-D", "FOREGROUND"]

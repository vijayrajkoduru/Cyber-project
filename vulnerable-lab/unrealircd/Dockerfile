FROM ubuntu:16.04
# ── UnrealIRCd 3.2.8.1 — CVE-2010-2075 ─────────────────────
# Backdoor: send "AB;" prefix → command executes on server
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    wget build-essential libssl-dev libcurl4-openssl-dev \
    openssl zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Create irc user
RUN useradd -m -s /bin/bash irc 2>/dev/null || true

WORKDIR /home/irc
# Download the backdoored UnrealIRCd source
RUN wget -q "https://www.unrealircd.org/downloads/Unreal3.2.8.1.tar.gz" || \
    wget -q "http://sourceforge.net/projects/unreal4/files/Unreal3.2/3.2.8.1/Unreal3.2.8.1.tar.gz" || true

RUN tar xzf Unreal3.2.8.1.tar.gz 2>/dev/null || true

WORKDIR /home/irc/Unreal3.2.8.1
COPY unrealircd.conf /home/irc/Unreal3.2.8.1/unrealircd.conf
RUN echo -e "\n\n\n\n\n\n\n\n\n\n\n\n" | ./Config 2>/dev/null || true
RUN make 2>/dev/null || true
RUN make install 2>/dev/null || true

EXPOSE 6667 6697

CMD ["/bin/bash", "-c", "cd /home/irc/Unreal3.2.8.1 && ./unreal start && tail -f /home/irc/Unreal3.2.8.1/ircd.log"]

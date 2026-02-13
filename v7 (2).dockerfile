FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Herramientas base + nikto + nmap
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    util-linux \
    bsdmainutils \
    procps \
    openssl \
    jq \
    dnsutils \
    nmap \
    perl \
    libjson-perl \
    libxml-writer-perl \
    python3 \
    python3-pip \
    openjdk-17-jre \
    unzip \
 && rm -rf /var/lib/apt/lists/*

# OWASP ZAP
RUN curl -fL https://github.com/zaproxy/zap-archive/releases/download/zap-v2.14.0/ZAP_2.14.0_Linux.tar.gz -o zap.tar.gz \
 && tar -xzf zap.tar.gz \
 && rm zap.tar.gz \
 && mv ZAP_2.14.0 /opt/zaproxy \
 && ln -s /opt/zaproxy/zap.sh /usr/local/bin/zap

# TestSSL.sh
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl \
 && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh \
 && chmod +x /usr/local/bin/testssl.sh

# Instalar Nikto manualmente
RUN git clone https://github.com/sullo/nikto.git /opt/nikto \
 && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
 && chmod +x /usr/local/bin/nikto

WORKDIR /app

COPY scanner.sh .

RUN sed -i 's/\r$//' *.sh && chmod +x scanner.sh

ENTRYPOINT ["./scanner.sh"]

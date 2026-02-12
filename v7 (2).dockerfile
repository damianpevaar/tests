FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Herramientas base
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    jq \
    nmap \
    python3 \
    python3-pip \
    openjdk-17-jre \
    unzip \
    openssl \
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

WORKDIR /app

COPY scanner.sh .

RUN chmod +x scanner.sh

ENTRYPOINT ["./scanner.sh"]

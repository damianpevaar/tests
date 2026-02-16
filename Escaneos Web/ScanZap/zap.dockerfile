FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Herramientas base + nikto + nmap
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    jq \
    openjdk-17-jre \
    unzip \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*


# OWASP ZAP
RUN curl -fL https://github.com/zaproxy/zap-archive/releases/download/zap-v2.14.0/ZAP_2.14.0_Linux.tar.gz -o zap.tar.gz \
 && tar -xzf zap.tar.gz \
 && rm zap.tar.gz \
 && mv ZAP_2.14.0 /opt/zaproxy \
 && ln -s /opt/zaproxy/zap.sh /usr/local/bin/zap


WORKDIR /app

COPY zap.sh .

RUN sed -i 's/\r$//' *.sh && chmod +x zap.sh

ENTRYPOINT ["./zap.sh"]
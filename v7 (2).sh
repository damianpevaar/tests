FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Instalación de herramientas y dependencias
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git jq nmap python3 openjdk-17-jre unzip \
    && rm -rf /var/lib/apt/lists/*

# Instalación de OWASP ZAP (Baseline)
RUN curl -s https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz -L -o zap.tar.gz \
    && tar -xzvf zap.tar.gz && rm zap.tar.gz \
    && mv ZAP_2.14.0 /opt/zaproxy \
    && ln -s /opt/zaproxy/zap.sh /usr/local/bin/zap

# Instalación de testssl.sh
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl \
    && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl

WORKDIR /app

# Definimos las variables de entorno
ENV TARGET_URL=""
ENV N8N_WEBHOOK_URL="https://mgonzalezg.app.n8n.cloud/webhook/7bebb5bd-62c6-4e89-94b3-a9dc13baec01"

COPY scanner.sh .
RUN chmod +x scanner.sh

ENTRYPOINT ["./scanner.sh"]
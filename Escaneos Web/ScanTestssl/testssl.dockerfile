FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# 1. Instalar dependencias
# Agregué 'bsdmainutils' y 'net-tools' que testssl a veces agradece tener.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    util-linux \
    bsdmainutils \
    net-tools \
    procps \
    openssl \
    jq \
    dnsutils \
 && rm -rf /var/lib/apt/lists/*

# 2. Instalar la HERRAMIENTA TestSSL.sh (Oficial)
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl \
 && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh \
 && chmod +x /usr/local/bin/testssl.sh

WORKDIR /app

# 3. Copiar TU SCRIPT WRAPPER (El que envía a n8n)
# IMPORTANTE: Lo renombramos a 'run_scan.sh' al copiarlo para diferenciarlo de la herramienta.
COPY testssl.sh ./run_scan.sh

# 4. Arreglar saltos de línea de Windows (CRLF) y dar permisos
RUN sed -i 's/\r$//' ./run_scan.sh && chmod +x ./run_scan.sh

# 5. Ejecutar el wrapper
ENTRYPOINT ["/bin/bash", "./run_scan.sh"]
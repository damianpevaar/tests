FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# 1. Dependencias del Sistema
# He añadido librerías para Nuclei Headless (navegador) y dependencias críticas de Perl/TestSSL
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git jq ca-certificates nmap openjdk-17-jre \
    python3 python3-pip python3-setuptools python3-yaml unzip dos2unix \
    xvfb xauth procps bsdmainutils dnsutils perl \
    libjson-perl libxml-writer-perl libnet-ssleay-perl libio-socket-ssl-perl \
    libwhisker2-perl \
    # Dependencias para Nuclei Headless
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
    libxkbcommon0 libxcomposite1 libxdamage1 libxrandr2 libgbm1 libasound2 \
 && rm -rf /var/lib/apt/lists/*

# 2. ZAP (Motor oficial)
COPY --from=ghcr.io/zaproxy/zaproxy:stable /zap /zap
ENV PATH=$PATH:/zap
RUN ln -s /zap/zap.sh /usr/local/bin/zap.sh

# 3. ZAP Python client
RUN pip3 install --break-system-packages zaproxy

# 4. Scripts de automatización ZAP
RUN curl -L -o /usr/local/bin/zap-baseline.py https://raw.githubusercontent.com/zaproxy/zaproxy/main/docker/zap-baseline.py \
 && curl -L -o /usr/local/bin/zap_common.py https://raw.githubusercontent.com/zaproxy/zaproxy/main/docker/zap_common.py \
 && chmod +x /usr/local/bin/zap-baseline.py /usr/local/bin/zap_common.py

# 5. NUCLEI (v3.3.0 + Pre-descarga de plantillas)
RUN curl -L -o nuclei.zip https://github.com/projectdiscovery/nuclei/releases/download/v3.3.0/nuclei_3.3.0_linux_amd64.zip \
 && unzip nuclei.zip && mv nuclei /usr/local/bin/ && rm nuclei.zip
# CRÍTICO: Descargar plantillas durante el build para ahorrar tiempo y evitar fallos de red en runtime
RUN nuclei -update-templates -silent

# 6. NIKTO (Instalación Real)
#RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
# && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# 7. TESTSSL (Instalación Real)
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl \
 && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

# 8. Preparación final
WORKDIR /app
COPY . .
# Directorio de trabajo obligatorio para reportes de ZAP
RUN mkdir -p /zap/wrk && chmod 777 /zap/wrk
RUN dos2unix *.sh && chmod +x *.sh

ENTRYPOINT ["./entrypoint.sh"]
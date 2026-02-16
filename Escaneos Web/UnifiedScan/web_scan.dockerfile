FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Instalación de todas las dependencias requeridas por los 4 scripts
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git jq ca-certificates procps net-tools bsdmainutils dnsutils util-linux \
    nmap openssl openjdk-17-jre unzip perl \
    libjson-perl libjson-pp-perl libnet-ssleay-perl libio-socket-ssl-perl \
 && rm -rf /var/lib/apt/lists/*

# Instalación de Nikto
RUN git clone https://github.com/sullo/nikto.git /opt/nikto \
 && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
 && chmod +x /usr/local/bin/nikto

# Instalación de TestSSL.sh
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl \
 && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

# Instalación de OWASP ZAP
RUN curl -fL https://github.com/zaproxy/zap-archive/releases/download/zap-v2.14.0/ZAP_2.14.0_Linux.tar.gz -o zap.tar.gz \
 && tar -xzf zap.tar.gz -C /opt && rm zap.tar.gz \
 && ln -s /opt/ZAP_2.14.0/zap.sh /usr/local/bin/zap

WORKDIR /app

# Copiamos tus scripts originales (asegúrate de renombrarlos así en tu carpeta)
COPY zap.sh .
COPY testssl.sh .
COPY nmap.sh .
COPY nikto.sh .
COPY entrypoint.sh .

# Corregimos formatos y damos permisos
RUN sed -i 's/\r$//' *.sh && chmod +x *.sh

ENTRYPOINT ["./entrypoint.sh"]
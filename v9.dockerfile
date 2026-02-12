FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Instalamos solo lo necesario para el escaneo y reporte
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    jq \
    bash \
    python3 \
    python3-pip \
    # Herramienta de escaneo de red (la base de OpenVAS)
    nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY openvas_test.sh .
RUN chmod +x openvas_test.sh

ENTRYPOINT ["./openvas_test.sh"]
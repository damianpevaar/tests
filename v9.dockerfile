# Usamos esta imagen que sí es pública y contiene todo el stack (GVM 22.4+)
FROM immauss/openvas:latest

USER root

# Instalamos curl, jq y gvm-tools para la comunicación con n8n
RUN apt-get update && apt-get install -y \
    curl \
    jq \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Instalamos gvm-tools
RUN pip3 install gvm-tools --break-system-packages

WORKDIR /app

# Copiamos tu script de orquestación
COPY openvas_test.sh .
RUN chmod +x openvas_test.sh

# Esta imagen usa un entrypoint que levanta servicios, 
# pero nosotros sobreescribimos para controlar el flujo.
ENTRYPOINT ["./openvas_test.sh"]

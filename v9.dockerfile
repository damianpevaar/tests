FROM greenbone/community-edition:latest

# Instalamos curl y jq para poder hablar con el webhook de n8n
USER root
RUN apt-get update && apt-get install -y curl jq python3-pip && rm -rf /var/lib/apt/lists/*
RUN pip3 install gvm-tools --break-system-packages

WORKDIR /app
COPY openvas_real_scan.sh .
RUN chmod +x openvas_real_scan.sh

# Esta imagen ya tiene su propio ENTRYPOINT, 
# así que usaremos el script para orquestar el escaneo tras el arranque.
ENTRYPOINT ["./openvas_test.sh"]

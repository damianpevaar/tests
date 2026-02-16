FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Herramientas base
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    jq \
    perl \
    libjson-perl \
    libxml-writer-perl \
    libnet-ssleay-perl \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*



# Instalar Nikto manualmente
RUN git clone https://github.com/sullo/nikto.git /opt/nikto \
 && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
 && chmod +x /usr/local/bin/nikto

WORKDIR /app

COPY nikton.sh .

RUN sed -i 's/\r$//' *.sh && chmod +x nikton.sh

ENTRYPOINT ["./nikton.sh"]
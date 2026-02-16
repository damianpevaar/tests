FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Herramientas base 
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    jq \
    nmap \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*


WORKDIR /app

COPY nmap.sh .

RUN sed -i 's/\r$//' *.sh && chmod +x nmap.sh

ENTRYPOINT ["./nmap.sh"]
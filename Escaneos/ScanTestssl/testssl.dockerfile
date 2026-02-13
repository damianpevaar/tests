FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    util-linux \
    bsdmainutils \
    procps \
    openssl \
    jq \
    dnsutils \
 && rm -rf /var/lib/apt/lists/*

# Instalar TestSSL.sh
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl \
 && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh \
 && chmod +x /usr/local/bin/testssl.sh

WORKDIR /app

COPY testssl.sh .

RUN sed -i 's/\r$//' *.sh && chmod +x testssl.sh

ENTRYPOINT ["/bin/bash", "./testssl.sh"]

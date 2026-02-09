FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y nmap git curl dnsutils bsdmainutils net-tools openssl && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl
RUN ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl
WORKDIR /data
CMD ["/bin/bash"]
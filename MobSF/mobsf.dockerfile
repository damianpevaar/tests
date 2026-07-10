FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV MOBSF_HOME=/home/mobsf
ENV PATH="/usr/local/bin:${PATH}"

RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-dev \
    git curl jq unzip zip wget \
    build-essential libssl-dev libffi-dev \
    libxml2-dev libxslt1-dev zlib1g-dev \
    openjdk-17-jdk \
    android-tools-adb \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install mobsf

RUN mkdir -p /app/repo /app/output
WORKDIR /app

COPY entrypoint.sh /app/entrypoint_mobsf.sh
RUN chmod +x /app/entrypoint_mobsf.sh

ENTRYPOINT ["/bin/bash", "/app/entrypoint_mobsf.sh"]
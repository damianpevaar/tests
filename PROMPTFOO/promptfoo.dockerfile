FROM node:22-slim

RUN apt-get update && apt-get install -y \
    bash \
    curl \
    jq \
    git \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g promptfoo@latest

RUN pip3 install --break-system-packages openai

WORKDIR /app
RUN mkdir -p /app/output

COPY entrypoint.sh /app/entrypoint.sh
RUN sed -i 's/\r//' /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]
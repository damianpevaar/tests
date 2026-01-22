FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# ================================
# Core OS dependencies
# ================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    jq \
    bash \
    python3 \
    python3-venv \
    python3-pip \
    nodejs \
    npm \
	unzip \
	awscli \
	openjdk-17-jdk \
    && rm -rf /var/lib/apt/lists/*

# ================================
# Install Snyk CLI
# ================================
RUN curl -s https://static.snyk.io/cli/latest/snyk-linux -o /usr/local/bin/snyk \
    && chmod +x /usr/local/bin/snyk

# ================================
# Install StackHawk CLI
# ================================
RUN curl -v https://download.stackhawk.com/hawk/cli/hawk-5.1.0.zip -o hawk-5.1.0.zip && unzip hawk-5.1.0.zip
ENV PATH="/hawk-5.1.0:$PATH"

# ================================
# App directories
# ================================
WORKDIR /app

RUN mkdir -p \
    /app/snyk-projects \
    /app/stackhawk-projects \
    /app/snyk-output \
	/app/stackhawk-output

# ================================
# Entrypoint
# ================================
COPY v7.sh .
RUN chmod +x v7.sh

ENTRYPOINT ["./v7.sh"]
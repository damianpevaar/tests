FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl git jq unzip ca-certificates openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Semgrep (SAST)
RUN pip install --no-cache-dir semgrep

# Nuclei (DAST)
RUN NUCLEI_VER=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | jq -r .tag_name) \
    && curl -sL "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VER}/nuclei_${NUCLEI_VER#v}_linux_amd64.zip" -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip nuclei -d /usr/local/bin \
    && rm /tmp/nuclei.zip \
    && chmod +x /usr/local/bin/nuclei

# Trivy (SCA/CVE) — escaneo de dependencias por CVE
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

# Pre-cachear DB de Trivy
RUN trivy --cache-dir /root/.cache/trivy image --download-db-only 2>/dev/null || true

# Pre-cachear templates de Nuclei (acelera arranque en cada job)
RUN nuclei -update-templates -silent || true

WORKDIR /app
RUN mkdir -p /app/projects /app/output

COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]

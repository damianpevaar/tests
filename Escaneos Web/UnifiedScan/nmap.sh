#!/bin/bash
set -e

echo "===== INICIANDO PROCESO DE ESCANEO ====="

# Validación básica
if [ -z "$TARGET_URL" ]; then
  echo "ERROR: TARGET_URL no definido"
  exit 1
fi

# Limpieza de URL → dominio
DOMAIN=$(echo "$TARGET_URL" | sed -e 's|^[^/]*//||' -e 's|/.*$||')

echo "→ Objetivo completo: $TARGET_URL"
echo "→ Dominio extraído: $DOMAIN"

# Nmap
echo "→ Corriendo Nmap..."
NMAP_OUT=$(nmap -sS -T3 -Pn -sV -O --script=default,vuln --open "$DOMAIN" | tr '\n' '\\n')

# Envío a n8n via tmp
echo "→ Enviando resultados a n8n..."

PAYLOAD=$(jq -n \
  --arg target "$TARGET_URL" \
  --arg domain "$DOMAIN" \
  --arg nmap "$NMAP_OUT" \
  '{
    info: {
      url: $target,
      host: $domain,
      scan_date: (now | strftime("%Y-%m-%d %H:%M:%S"))
    },
    results: {
      nmap_raw: $nmap,
    }
  }')

echo "$PAYLOAD" > /tmp/nmap_res.json
echo "===== ESCANEO FINALIZADO EXITOSAMENTE ====="

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

# TestSSL (rápido)
echo "→ Corriendo TestSSL.sh..."
testssl.sh --fast --severity HIGH --jsonfile /tmp/ssl.json "$DOMAIN" || true

if [ -f /tmp/ssl.json ]; then
  SSL_DATA=$(cat /tmp/ssl.json)
else
  SSL_DATA='{"error":"No se pudo generar reporte SSL"}'
fi

# Envío a n8n
echo "→ Enviando resultados a n8n..."

PAYLOAD=$(jq -n \
  --arg target "$TARGET_URL" \
  --arg domain "$DOMAIN" \
  --argjson ssl "$SSL_DATA" \
  '{
    info: {
      url: $target,
      host: $domain,
      scan_date: (now | strftime("%Y-%m-%d %H:%M:%S"))
    },
    results: {
      testssl_results: $ssl
    }
  }')

curl -X POST "$N8N_WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD"

echo "===== ESCANEO FINALIZADO EXITOSAMENTE ====="

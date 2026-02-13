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

#ZAP crudo
echo "→ Corriendo OWASP ZAP..."
zap -cmd -quickurl "$TARGET_URL" -quickout /tmp/zap_report.xml || true

if [ -f /tmp/zap_report.xml ]; then
  ZAP_RAW=$(cat /tmp/zap_report.xml | tr '\n' '\\n')
else
  ZAP_RAW="No se pudo generar reporte ZAP"
fi

# Envío a n8n
echo "→ Enviando resultados a n8n..."

PAYLOAD=$(jq -n \
  --arg target "$TARGET_URL" \
  --arg domain "$DOMAIN" \
  --arg zap "$ZAP_RAW" \
  '{
    info: {
      url: $target,
      host: $domain,
      scan_date: (now | strftime("%Y-%m-%d %H:%M:%S"))
    },
    results: {
      zap_raw: $zap
    }
  }')

curl -X POST "$N8N_WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD"

echo "===== ESCANEO FINALIZADO EXITOSAMENTE ====="

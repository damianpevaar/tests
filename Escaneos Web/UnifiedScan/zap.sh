#!/bin/bash
set -e
 
echo "===== INICIANDO PROCESO DE ESCANEO (JSON) ====="
 
# 1. Validación básica
if [ -z "$TARGET_URL" ]; then
  echo "ERROR: TARGET_URL no definido"
  exit 1
fi
 
# 2. Limpieza de URL -> dominio
DOMAIN=$(echo "$TARGET_URL" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
 
echo "→ Objetivo: $TARGET_URL"
echo "→ Dominio: $DOMAIN"
 
# 3. ZAP en modo JSON
# EL CAMBIO CLAVE: .json al final
echo "→ Corriendo OWASP ZAP..."
zap-cli -p 8080 status || true # Asegurar que no haya bloqueos previos
zap -cmd -quickurl "$TARGET_URL" -quickout /tmp/zap_report.json -quickprogress || true
 
# 4. Lectura segura del reporte
if [ -f /tmp/zap_report.json ]; then
  # Leemos el archivo tal cual
  ZAP_JSON_CONTENT=$(cat /tmp/zap_report.json)
else
  # Fallback en JSON válido por si falla ZAP
  ZAP_JSON_CONTENT='{"error": "No se generó reporte", "site": []}'
fi
 
# 5. Envío a n8n usando tmp 
PAYLOAD=$(jq -n \
  --arg target "$TARGET_URL" \
  --arg domain "$DOMAIN" \
  --argjson zap_results "$ZAP_JSON_CONTENT" \
  '{
    info: {
      url: $target,
      host: $domain,
      scan_date: (now | strftime("%Y-%m-%d %H:%M:%S"))
    },
    results: $zap_results
  }')
 
echo "$PAYLOAD" > /tmp/zap_res.json
echo "===== ESCANEO FINALIZADO ====="

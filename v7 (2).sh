#!/bin/bash
set -e

echo "===== INICIANDO PROCESO DE ESCANEO AVANZADO ====="

# Validación básica
if [ -z "$TARGET_URL" ] || [ -z "$N8N_WEBHOOK_URL" ]; then
  echo "ERROR: TARGET_URL o N8N_WEBHOOK_URL no definidos"
  exit 1
fi

# 1. Limpieza de URL → dominio
DOMAIN=$(echo "$TARGET_URL" | sed -e 's|^[^/]*//||' -e 's|/.*$||')

echo "→ Objetivo: $TARGET_URL"
echo "→ Dominio: $DOMAIN"

# 2. Nmap (Escaneo profundo y vulnerabilidades)
echo "→ Corriendo Nmap Intrusivo..."
# -sS: SYN Scan, -sV: Versiones, -O: OS, -Pn: No ping, --script: Vuln
nmap -sS -T3 -Pn -sV -O --script=default,vuln --open "$DOMAIN" > /tmp/nmap_res.txt
NMAP_OUT=$(cat /tmp/nmap_res.txt)

# 3. TestSSL
echo "→ Corriendo TestSSL..."
testssl.sh --jsonfile /tmp/ssl_res.json "$DOMAIN" || true
if [ -f /tmp/ssl_res.json ]; then
  SSL_DATA=$(cat /tmp/ssl_res.json)
else
  SSL_DATA='{"error":"No se pudo generar reporte SSL"}'
fi

# 4. OWASP ZAP (Reporte JSON completo)
echo "→ Corriendo OWASP ZAP (Escaneo Rápido)..."
# Generamos el reporte directamente en JSON para no perder nada de información
zap.sh -cmd -quickurl "$TARGET_URL" -quickout /tmp/zap_report.json -format json || true

if [ -f /tmp/zap_report.json ]; then
  # Leemos el JSON completo para meterlo en el payload
  ZAP_DATA=$(cat /tmp/zap_report.json)
else
  ZAP_DATA='{"error":"ZAP no generó reporte JSON"}'
fi

# 5. Enviar a n8n (Payload masivo)
echo "→ Enviando resultados completos a n8n..."

PAYLOAD=$(jq -n \
  --arg target "$TARGET_URL" \
  --arg domain "$DOMAIN" \
  --arg nmap "$NMAP_OUT" \
  --argjson ssl "$SSL_DATA" \
  --argjson zap "$ZAP_DATA" \
  '{
    info: {
      url: $target,
      host: $domain,
      scan_date: (now | strftime("%Y-%m-%d %H:%M:%S"))
    },
    results: {
      nmap_raw: $nmap,
      testssl_results: $ssl,
      zap_full_report: $zap
    }
  }')

curl -X POST "$N8N_WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD"

echo "===== ESCANEO FINALIZADO EXITOSAMENTE ====="

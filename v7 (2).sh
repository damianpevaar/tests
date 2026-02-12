#!/bin/bash
set -e

echo "===== INICIANDO PROCESO DE ESCANEO ====="

# Validación básica
if [ -z "$TARGET_URL" ]; then
  echo "ERROR: TARGET_URL no definido"
  exit 1
fi

# 1. Limpieza de URL → dominio
DOMAIN=$(echo "$TARGET_URL" | sed -e 's|^[^/]*//||' -e 's|/.*$||')

echo "→ Objetivo completo: $TARGET_URL"
echo "→ Dominio extraído: $DOMAIN"

# 2. Nmap
echo "→ Corriendo Nmap..."
NMAP_OUT=$(nmap -F "$DOMAIN" | tr '\n' '\\n')

# 3. TestSSL (robusto)
echo "→ Corriendo TestSSL..."
testssl.sh --jsonfile /tmp/ssl_res.json "$DOMAIN" || true

if [ -f /tmp/ssl_res.json ]; then
  SSL_DATA=$(cat /tmp/ssl_res.json)
else
  SSL_DATA='{"error":"No se pudo generar reporte SSL"}'
fi

# 4. OWASP ZAP
echo "→ Corriendo OWASP ZAP..."
zap -cmd -quickurl "$TARGET_URL" -quickout /tmp/zap_report.xml || true

# Parsear XML de ZAP a JSON completo
ZAP_FINDINGS=$(awk '
/<alertitem>/ {inblock=1; name=""; risk=""; desc=""; solution=""; url="";}
/<\/alertitem>/ {
  printf "{\"name\":\"%s\",\"risk\":\"%s\",\"description\":\"%s\",\"solution\":\"%s\",\"url\":\"%s\"},", name, risk, desc, solution, url;
  inblock=0;
}
inblock && /<alert>/ {gsub(/.*<alert>|<\/alert>.*/,""); name=$0}
inblock && /<riskdesc>/ {gsub(/.*<riskdesc>|<\/riskdesc>.*/,""); risk=$0}
inblock && /<desc>/ {gsub(/.*<desc>|<\/desc>.*/,""); desc=$0}
inblock && /<solution>/ {gsub(/.*<solution>|<\/solution>.*/,""); solution=$0}
inblock && /<uri>/ {gsub(/.*<uri>|<\/uri>.*/,""); url=$0}
' /tmp/zap_report.xml | sed 's/,$//')

ZAP_FINDINGS="[$ZAP_FINDINGS]"

# 5. Enviar a n8n
echo "→ Enviando resultados a n8n..."

PAYLOAD=$(jq -n \
  --arg target "$TARGET_URL" \
  --arg domain "$DOMAIN" \
  --arg nmap "$NMAP_OUT" \
  --argjson ssl "$SSL_DATA" \
  --argjson zap "$ZAP_FINDINGS" \
  '{
    info: {
      url: $target,
      host: $domain,
      scan_date: (now | strftime("%Y-%m-%d %H:%M:%S"))
    },
    results: {
      nmap_raw: $nmap,
      testssl_results: $ssl,
      zap_findings: $zap
    }
  }')

curl -X POST "$N8N_WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD"

echo "===== ESCANEO FINALIZADO EXITOSAMENTE ====="

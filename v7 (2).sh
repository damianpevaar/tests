#!/bin/bash
set -e

echo "===== INICIANDO PROCESO DE ESCANEO ====="

# 1. Limpieza de URL para herramientas que solo quieren el dominio (como nmap)
# Esto quita el http:// o https:// y las barras finales
DOMAIN=$(echo "$TARGET_URL" | sed -e 's|^[^/]*//||' -e 's|/.*$||')

echo "→ Objetivo completo: $TARGET_URL"
echo "→ Dominio extraído: $DOMAIN"

# 2. Ejecutar Nmap (Escaneo de puertos)
echo "→ Corriendo Nmap en $DOMAIN..."
NMAP_OUT=$(nmap -F "$DOMAIN")

# 3. Ejecutar TestSSL (Seguridad de certificados)
echo "→ Corriendo TestSSL en $TARGET_URL..."
testssl.sh --jsonfile /tmp/ssl_res.json "$TARGET_URL" || true
# Leer el JSON generado o crear uno vacío si falla
if [ -f /tmp/ssl_res.json ]; then
    SSL_DATA=$(cat /tmp/ssl_res.json)
else
    SSL_DATA='{"error": "No se pudo generar reporte SSL"}'
fi

# 4. Ejecutar OWASP ZAP (Vulnerabilidades Web)
echo "→ Corriendo OWASP ZAP (esto puede tomar un momento)..."
zap -cmd -quickurl "$TARGET_URL" -quickout /tmp/zap_report.xml || true
ZAP_STATUS="Escaneo Baseline completado para $TARGET_URL"

# 5. Enviar todo a n8n
echo "→ Enviando resultados al Webhook de n8n..."

PAYLOAD=$(jq -n \
    --arg target "$TARGET_URL" \
    --arg domain "$DOMAIN" \
    --arg nmap "$NMAP_OUT" \
    --argjson ssl "$SSL_DATA" \
    --arg zap "$ZAP_STATUS" \
    '{
        info: {
            url: $target,
            host: $domain,
            scan_date: (now | strftime("%Y-%m-%d %H:%M:%S"))
        },
        results: {
            nmap_raw: $nmap,
            testssl_json: $ssl,
            zap_summary: $zap
        }
    }')

curl -X POST "$N8N_WEBHOOK_URL" \
     -H "Content-Type: application/json" \
     -d "$PAYLOAD"

echo "===== ESCANEO FINALIZADO EXITOSAMENTE ====="

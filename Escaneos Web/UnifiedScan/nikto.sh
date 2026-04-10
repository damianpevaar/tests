#!/bin/bash
set -e
echo "===== INICIANDO NIKTO ====="

DOMAIN=$(echo "$TARGET_URL" | sed -e 's|^[^/]*//||' -e 's|/.*$||')

# Forzamos ejecución vía perl por seguridad de rutas
echo "→ Corriendo Nikto contra $DOMAIN..."
# Agregamos -ssl si la URL es https
if [[ "$TARGET_URL" == https* ]]; then SSL_FLAG="-ssl"; else SSL_FLAG=""; fi

nikto -h "$TARGET_URL" $SSL_FLAG -Tuning 123bde -nointeractive -Display 1234 > /tmp/nikto_raw.txt 2>&1 || true
NIKTO_OUT=$(cat /tmp/nikto_raw.txt | tr '\n' '\\n')

PAYLOAD=$(jq -n \
  --arg target "$TARGET_URL" \
  --arg domain "$DOMAIN" \
  --arg nikto "$NIKTO_OUT" \
  '{info: {url: $target, host: $domain, scan_date: (now | strftime("%Y-%m-%d %H:%M:%S"))}, results: {nikto_raw: $nikto}}')

echo "$PAYLOAD" > /tmp/nikto_res.json
echo "===== NIKTO FINALIZADO ====="
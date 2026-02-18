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


# Nikto
echo "→ Corriendo Nikto..."
NIKTO_OUT=$(nikto -h "$DOMAIN" -nointeractive -nossl 2>&1 | tr '\n' '\\n')

# Envío a n8n via tmp
echo "→ Enviando resultados a n8n..."

PAYLOAD=$(jq -n \
  --arg target "$TARGET_URL" \
  --arg domain "$DOMAIN" \
  --arg nikto "$NIKTO_OUT" \
  '{
    info: {
      url: $target,
      host: $domain,
      scan_date: (now | strftime("%Y-%m-%d %H:%M:%S"))
    },
    results: {
      nikto_raw: $nikto,
    }
  }')

echo "$PAYLOAD" > /tmp/nikto_res.json
echo "===== ESCANEO FINALIZADO EXITOSAMENTE ====="

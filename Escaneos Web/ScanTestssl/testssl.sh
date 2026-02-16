#!/bin/bash
set -e

echo "===== INICIANDO ESCANEO SSL (MODO ROBUSTO) ====="

# 1. Validación
if [ -z "$TARGET_URL" ]; then
  echo "ERROR: TARGET_URL no definido"
  exit 1
fi

DOMAIN=$(echo "$TARGET_URL" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
echo "→ Objetivo: $DOMAIN"

# 2. Ejecución de TestSSL
# Usamos --overwrite para asegurar que no se queje si el archivo ya existe
echo "→ Corriendo análisis..."
testssl.sh --quiet --overwrite --ip one --jsonfile /tmp/ssl.json "$DOMAIN" || true

# 3. Debugging del Archivo (Para ver si realmente se creó)
if [ -s /tmp/ssl.json ]; then
  FILE_SIZE=$(ls -lh /tmp/ssl.json | awk '{print $5}')
  echo "→ Archivo JSON generado correctamente. Tamaño: $FILE_SIZE"
else
  echo "ERROR CRÍTICO: El archivo /tmp/ssl.json está vacío o no existe."
  # Creamos un JSON dummy para no romper el flujo
  echo '[]' > /tmp/ssl.json
fi

# 4. Procesamiento con JQ (MÉTODO SEGURO: STREAMING)
# En lugar de cargar el archivo en una variable, se lo pasamos directo a jq con 'cat'
echo "→ Procesando datos con jq..."

PAYLOAD=$(cat /tmp/ssl.json | jq -n \
  --arg target "$TARGET_URL" \
  --arg domain "$DOMAIN" \
  --arg date "$(date '+%Y-%m-%d %H:%M:%S')" \
  '
    # "inputs" lee el stream que le pasamos por el pipe
    [inputs] as $raw | 
    # Como testssl a veces devuelve un array o varios objetos, lo aplanamos
    ($raw | flatten) as $data |
    
    {
      info: {
        url: $target,
        scan_date: $date
      },
      results: {
        grade: ($data[] | select(.id == "overall_grade") | .finding // "Unknown"),
        
        certificate: {
          expiration: ($data[] | select(.id == "cert_expiration") | .finding // "Unknown"),
          issuer: ($data[] | select(.id == "cert_issuer") | .finding // "Unknown")
        },

        # Filtramos para ver protocolos
        protocols: $data | map(select(.id | test("TLS1_2|TLS1_3|SSLv3"))) | map({
           protocol: .id,
           status: .finding
        }),

        # Filtramos vulnerabilidades críticas (Heartbleed, etc)
        security_checks: $data | map(select(.id | test("HEARTBLEED|POODLE|ROBOT"))) | map({
           test: .id,
           status: .finding
        }),

        # Cualquier advertencia real
        warnings: $data | map(select(.severity != "OK" and .severity != "INFO" and .severity != "LOW")) | map({
           id: .id,
           finding: .finding,
           severity: .severity
        })
      }
    }
  ')

# 5. Verificación final antes de enviar
if [ -z "$PAYLOAD" ]; then
  echo "ERROR: El PAYLOAD quedó vacío después de jq. Revisa la instalación de jq."
  exit 1
fi

echo "→ Enviando a n8n..."
# Debug: Descomenta esto si quieres ver el JSON antes de enviarlo
# echo "$PAYLOAD" 

curl -v -X POST "$N8N_WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD"

echo ""
echo "===== FINALIZADO ====="
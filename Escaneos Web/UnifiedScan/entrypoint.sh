#!/bin/bash
set +e

# Intentar tomar de variables de entorno, si no, tomar de argumentos $1 y $2
URL=${TARGET_URL:-$1}
TICKET=${TICKET_ID:-$2}

# Verificación: Si después de intentar ambos, siguen vacíos, dar error
if [ -z "$URL" ] || [ -z "$TICKET" ]; then
    echo "🚨 Error: Falta TARGET_URL o TICKET_ID."
    echo "Uso con variables: docker run -e TARGET_URL=... -e TICKET_ID=..."
    echo "Uso con argumentos: docker run image <URL> <TICKET_ID>"
    exit 1
fi

# Exportar para que el script maestro los vea
export TARGET_URL=$URL
export TICKET_ID=$TICKET

export FINAL_WEBHOOK="https://mgonzalezg.app.n8n.cloud/webhook/webscan"
echo "===== SECURITY SCANNER MASTER SYSTEM (CONSOLIDADO) ====="
echo "→ Target: $TARGET_URL"
echo "→ Ticket Reference: $TICKET_ID"

# 1. Definir rutas
export RES_ZAP="/tmp/zap_res.json"
export RES_NMAP="/tmp/nmap_res.json"
export RES_TESTSSL="/tmp/testssl_res.json"
export RES_NUCLEI="/tmp/nuclei_res.json"
export FINAL_PAYLOAD="/tmp/final_payload.json"

rm -f /tmp/*_res.json /tmp/final_payload.json

# 2. Ejecución de herramientas (Asegúrate que reciban el TARGET_URL)
echo "→ Ejecutando Nmap..."
./nmap.sh
echo "→ Ejecutando TestSSL..."
./testssl.sh
echo "→ Ejecutando ZAP..."
./zap.sh
echo "→ Ejecutando Nuclei..."
./nuclei.sh

# 3. Verificación de archivos individuales (Mismo código...)
echo "→ Verificando archivos de resultado..."
for f in "$RES_ZAP" "$RES_NMAP" "$RES_TESTSSL" "$RES_NUCLEI"; do
    if [ ! -f "$f" ] || [ ! -s "$f" ]; then
        echo "  [WARN] $f no existe o está vacío, generando placeholder"
        echo '{"error": "no_ejecutado", "results": []}' > "$f"
    fi
    if ! jq empty "$f" 2>/dev/null; then
        echo "  [WARN] $f contiene JSON inválido, generando placeholder"
        echo '{"error": "json_invalido", "results": []}' > "$f"
    fi
done

# 4. Construcción del Payload Maestro con VARIABLE TICKET
echo "→ Armando payload en archivo físico..."
jq -n \
  --arg target "$TARGET_URL" \
  --arg ticket "$TICKET_ID" \
  --arg date "$(date '+%Y-%m-%d %H:%M:%S')" \
  --slurpfile zap     "$RES_ZAP" \
  --slurpfile nmap    "$RES_NMAP" \
  --slurpfile ssl     "$RES_TESTSSL" \
  --slurpfile nuclei  "$RES_NUCLEI" \
  '
  {
    metadata: { 
      target: $target, 
      scan_date: $date,
      ticket: $ticket 
    },
    scans: {
      vulnerabilidades_web_zap: ($zap[0] // {"error": "no_data"}),
      puertos_red_nmap:         ($nmap[0] // {"error": "no_data"}),
      cifrado_ssl_testssl:      ($ssl[0] // {"error": "no_data"}),
      vulnerabilidades_nuclei:  ($nuclei[0] // [])
    }
  }
  ' > "$FINAL_PAYLOAD"

# 5. Verificación del archivo final
if [ ! -s "$FINAL_PAYLOAD" ]; then
    echo "[ERROR] El archivo de payload no se creó o está vacío, abortando"
    exit 1
fi

# 6. Envío Único
echo "→ Enviando resultados a n8n..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$FINAL_WEBHOOK" \
  -H "Content-Type: application/json" \
  --data-binary "@$FINAL_PAYLOAD")

echo "→ Respuesta webhook: HTTP $HTTP_CODE"
echo "===== PROCESO FINALIZADO PARA TICKET: $TICKET_ID ====="
#!/bin/bash
set +e

export FINAL_WEBHOOK="https://mgonzalezg.app.n8n.cloud/webhook/webscan"
echo "===== SECURITY SCANNER MASTER SYSTEM (CONSOLIDADO) ====="

# 1. Definir rutas
export RES_ZAP="/tmp/zap_res.json"
export RES_NIKTO="/tmp/nikto_res.json"
export RES_NMAP="/tmp/nmap_res.json"
export RES_TESTSSL="/tmp/testssl_res.json"
export RES_NUCLEI="/tmp/nuclei_res.json"
export FINAL_PAYLOAD="/tmp/final_payload.json"

rm -f /tmp/*_res.json /tmp/final_payload.json

# 2. Ejecución de herramientas
echo "→ Ejecutando Nmap..."
./nmap.sh
echo "→ Ejecutando TestSSL..."
./testssl.sh
echo "→ Ejecutando Nikto..."
./nikto.sh
echo "→ Ejecutando ZAP..."
./zap.sh
echo "→ Ejecutando Nuclei..."
./nuclei.sh

# 3. Verificación de archivos individuales
echo "→ Verificando archivos de resultado..."
for f in "$RES_ZAP" "$RES_NIKTO" "$RES_NMAP" "$RES_TESTSSL" "$RES_NUCLEI"; do
    if [ ! -f "$f" ] || [ ! -s "$f" ]; then
        echo "  [WARN] $f no existe o está vacío, generando placeholder"
        echo '{"error": "no_ejecutado", "results": []}' > "$f"
    fi
    if ! jq empty "$f" 2>/dev/null; then
        echo "  [WARN] $f contiene JSON inválido, generando placeholder"
        echo '{"error": "json_invalido", "results": []}' > "$f"
    fi
done

# 4. Construcción del Payload Maestro en archivo físico
echo "→ Armando payload en archivo físico..."
jq -n \
  --arg target "$TARGET_URL" \
  --arg date "$(date '+%Y-%m-%d %H:%M:%S')" \
  --slurpfile zap     "$RES_ZAP" \
  --slurpfile nikto   "$RES_NIKTO" \
  --slurpfile nmap    "$RES_NMAP" \
  --slurpfile ssl     "$RES_TESTSSL" \
  --slurpfile nuclei  "$RES_NUCLEI" \
  '
  {
    metadata: { target: $target, scan_date: $date },
    scans: {
      vulnerabilidades_web_zap: ($zap[0] // {"error": "no_data"}),
      servidor_web_nikto:       ($nikto[0] // {"error": "no_data"}),
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

# 6. Envío Único (Usando binary para evitar límites de tamaño)
echo "→ Enviando resultados a n8n (vía binary stream)..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$FINAL_WEBHOOK" \
  -H "Content-Type: application/json" \
  --data-binary "@$FINAL_PAYLOAD")

echo "→ Respuesta webhook: HTTP $HTTP_CODE"
echo "===== PROCESO FINALIZADO ====="
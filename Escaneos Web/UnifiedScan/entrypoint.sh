#!/bin/bash
set -e

# --- CONFIGURACIÓN ÚNICA ---
export FINAL_WEBHOOK="https://mgonzalezg.app.n8n.cloud/webhook/webscan"

echo "===== SECURITY SCANNER MASTER SYSTEM (CONSOLIDADO) ====="

# 1. Definir rutas de archivos temporales
export RES_ZAP="/tmp/zap_res.json"
export RES_NIKTO="/tmp/nikto_res.json"
export RES_NMAP="/tmp/nmap_res.json"
export RES_TESTSSL="/tmp/testssl_res.json"

# Limpiar archivos de ejecuciones previas
rm -f /tmp/*_res.json

# 2. Ejecución en cadena
# Usamos "|| true" para que si una herramienta falla, el proceso siga
echo "→ Iniciando Nmap..."
./nmap.sh || echo '{"error": "Nmap falló"}' > $RES_NMAP

echo "→ Iniciando TestSSL..."
./testssl.sh || echo '{"error": "TestSSL falló"}' > $RES_TESTSSL

echo "→ Iniciando Nikto..."
./nikto.sh || echo '{"error": "Nikto falló"}' > $RES_NIKTO

echo "→ Iniciando OWASP ZAP..."
./zap.sh || echo '{"error": "ZAP falló"}' > $RES_ZAP

# 3. Consolidación Inteligente con JQ
echo "→ Consolidando reportes en un Super-Payload..."

# Verificamos que existan los archivos, si no, creamos un placeholder
for f in $RES_ZAP $RES_NIKTO $RES_NMAP $RES_TESTSSL; do
    [ ! -f "$f" ] && echo '{"status": "no_ejecutado"}' > "$f"
done



PAYLOAD=$(jq -n \
  --arg target "$TARGET_URL" \
  --arg date "$(date '+%Y-%m-%d %H:%M:%S')" \
  --slurpfile zap $RES_ZAP \
  --slurpfile nikto $RES_NIKTO \
  --slurpfile nmap $RES_NMAP \
  --slurpfile ssl $RES_TESTSSL \
  '{
    metadata: {
      target: $target,
      scan_date: $date
    },
    scans: {
      vulnerabilidades_web_zap: $zap[0],
      servidor_web_nikto: $nikto[0],
      puertos_red_nmap: $nmap[0],
      cifrado_ssl_testssl: $ssl[0]
    }
  }')

# 4. Único Envío a n8n
echo "→ Enviando reporte final consolidado a n8n..."
curl -s -X POST "$FINAL_WEBHOOK" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD"

echo "===== PROCESO FINALIZADO EXITOSAMENTE ====="
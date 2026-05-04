#!/bin/bash
set +e

echo "===== INICIANDO ESCANEO ZAP (HEADLESS MODE) ====="
echo "→ Objetivo: $TARGET_URL"

export PATH=$PATH:/zap
REPORT_PATH="/tmp/zap_report.json"
RESULT_PATH="/tmp/zap_res.json"

cd /zap/wrk

python3 /usr/local/bin/zap-baseline.py \
    -t "$TARGET_URL" \
    -J zap_report.json \
    -m 5 \
    -z "-Xmx512m" || true

# Procesamiento del reporte
if [ -f "/zap/wrk/zap_report.json" ]; then
    mv /zap/wrk/zap_report.json "$REPORT_PATH"
elif [ -f "zap_report.json" ]; then
    mv zap_report.json "$REPORT_PATH"
else
    echo '{"alerts": [], "note": "ZAP no generó reporte"}' > "$REPORT_PATH"
fi

# Construir payload con mismo formato que nmap.sh
PAYLOAD=$(jq -n \
  --arg target "$TARGET_URL" \
  --arg date "$(date '+%Y-%m-%d %H:%M:%S')" \
  --slurpfile zap_data "$REPORT_PATH" \
  '{
    info: {
      url: $target,
      scan: "ZAP Baseline",
      scan_date: $date
    },
    results: $zap_data[0]
  }')

echo "$PAYLOAD" > "$RESULT_PATH"
echo "===== ZAP FINALIZADO ====="
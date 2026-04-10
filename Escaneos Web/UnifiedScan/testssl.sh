#!/bin/bash
set +e
echo "===== INICIANDO TESTSSL ====="

DOMAIN=$(echo "$TARGET_URL" | sed -e 's|^[^/]*//||' -e 's|/.*$||')

# Ejecución limpia
testssl.sh --quiet --overwrite --ip one --jsonfile /tmp/ssl.json "$DOMAIN" || true

if [ ! -s /tmp/ssl.json ]; then
  echo '[]' > /tmp/ssl.json
fi

# Procesamiento mejorado
PAYLOAD=$(jq -s \
  --arg target "$TARGET_URL" \
  --arg domain "$DOMAIN" \
  'flatten as $data | {
      meta: {
        target_domain: $domain,
        scanned_ip: ($data | map(select(.id == "scanTime")) | .[0].ip // "N/A"),
        scan_time: ($data | map(select(.id == "scanTime")) | .[0].finding // "N/A")
      },
      summary: {
        grade: ($data | map(select(.id == "overall_grade")) | .[0].finding // "No Grade")
      },
      full_scan_results: $data | map(select(.id != null and .id != "version"))
  }' /tmp/ssl.json)

echo "$PAYLOAD" > /tmp/testssl_res.json
echo "===== TESTSSL FINALIZADO ====="
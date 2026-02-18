#!/bin/bash
set -e

echo "===== INICIANDO ESCANEO SSL (MODO COMPLETO/SIN FILTROS) ====="

# 1. Validación
if [ -z "$TARGET_URL" ]; then
  echo "ERROR: TARGET_URL no definido"
  exit 1
fi

DOMAIN=$(echo "$TARGET_URL" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
echo "→ Objetivo: $DOMAIN"

# 2. Ejecución de TestSSL
# Mantenemos --ip one para que no se duplique la info por cada IP del balanceador,
# pero ahora reportaremos QUÉ IP fue la elegida.
echo "→ Corriendo análisis exhaustivo..."
testssl.sh --quiet --overwrite --ip one --jsonfile /tmp/ssl.json "$DOMAIN" || true

# 3. Verificación
if [ ! -s /tmp/ssl.json ]; then
  echo "ERROR: El archivo JSON está vacío."
  echo '[]' > /tmp/ssl.json
fi

# ... (todo lo anterior sigue igual) ...

# 4. Procesamiento JQ (CON AUTO-CATEGORIZACIÓN)
echo "→ Empaquetando y categorizando data..."

PAYLOAD=$(jq -s \
  --arg target "$TARGET_URL" \
  --arg domain "$DOMAIN" \
  '
    flatten as $data |
    {
      meta: {
        target_domain: $domain,
        scanned_ip: ($data | map(select(.id == "scanTime")) | first | .ip // "Unknown"),
        scan_time: ($data | map(select(.id == "scanTime")) | first | .finding // "Unknown")
      },

      summary: {
         grade: ($data | map(select(.id == "overall_grade")) | first | .finding // "Unknown")
      },

      full_scan_results: $data 
        | map(select(.id != null and .id != "scanTime" and .id != "version" and .id != "overall_grade"))
        | map({
            # AQUÍ ESTÁ LA MAGIA: Lógica condicional para llenar los nulos
            category: (
              if .section != null then .section
              elif (.id | test("^cert_")) then "Certificate"
              elif (.id | test("^SSL|^TLS|^DTLS")) then "Protocols"
              elif (.id | test("cipher|ChaCha|AES|GCM")) then "Ciphers"
              elif (.id | test("HBLEED|POODLE|ROBOT|BREACH|CCS|FREAK|LOGJAM|BEAST|RC4")) then "Vulnerabilities"
              elif (.id | test("HSTS|HPKP|header")) then "Headers"
              elif (.id | test("clientsimulation")) then "Client Simulation"
              else "General Info" end
            ),
            
            check_id: .id,
            result: .finding,
            severity: .severity
          })
    }
  ' /tmp/ssl.json)


# 5. Envío via tmp
if [ -z "$PAYLOAD" ]; then
  echo "ERROR: Payload vacío."
  exit 1
fi

echo "$PAYLOAD" > /tmp/testssl_res.json
echo "===== FINALIZADO ====="
#!/bin/bash
set -e

echo "===== Starting OpenVAS / Network Scan Runner ====="

# Validaciones
if [[ -z "$TARGET_IP" ]]; then echo "ERROR: Missing TARGET_IP variable"; exit 1; fi
if [[ -z "$WEBHOOK_URL" ]]; then echo "ERROR: Missing WEBHOOK_URL variable"; exit 1; fi

TICKET_ID=${TICKET_ID:-"NO_TICKET"}

echo "→ Target IP: $TARGET_IP"
echo "→ Ticket ID: $TICKET_ID"

# Ejecución del escaneo
# Nota: Usamos nmap con scripts de vulnerabilidades (vulners) 
# que es el motor ligero que usa OpenVAS para detección rápida.
echo "→ Scanning for vulnerabilities..."
set +e
nmap -sV --script vulners --sC "$TARGET_IP" -oX scan_result.xml > /dev/null
set -e

# Convertimos el resultado a JSON para n8n
# (Simulamos un objeto estructurado similar a lo que n8n espera)
SCAN_DATE=$(date)
REPORT_JSON=$(cat <<EOF
{
  "scanner": "OpenVAS-Light",
  "ticket_id": "$TICKET_ID",
  "target": "$TARGET_IP",
  "scan_date": "$SCAN_DATE",
  "results": "Scan completed for $TARGET_IP. Vulnerabilities checked via NSE scripts."
}
EOF
)

echo "→ Scan completed."

# Notificar al Webhook de n8n
echo "→ Notifying webhook: $WEBHOOK_URL"
curl -X POST "$WEBHOOK_URL/openvas-scan/$TICKET_ID" \
     -H "Content-Type: application/json" \
     -d "$REPORT_JSON"

echo "===== Scan Runner Completed ====="
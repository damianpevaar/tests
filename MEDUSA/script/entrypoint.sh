#!/bin/sh
set -e

# ============================================================
# Medusa Security Scanner — Entrypoint
# ============================================================
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
REPO_URL="${REPO_URL:-}"
BRANCH="${BRANCH:-master}"
TICKET_ID="${TICKET_ID:-}"
GROUP_ID="${GROUP_ID:-}"
WEBHOOK_URL="${WEBHOOK_URL:-https://mgonzalezg.app.n8n.cloud/webhook/c2a9b341-d8f9-403e-bd12-390471154875}"
USER_EMAIL="${USER_EMAIL:-}"
SCAN_DIR="/scan/repo"
RESULTS_DIR="/scan/results"
SUMMARY_FILE="/scan/summary.json"

mkdir -p "$RESULTS_DIR"

# --- Validación de inputs requeridos ---
if [ -z "$REPO_URL" ]; then
  echo "[ERROR] REPO_URL is required but not set."
  exit 1
fi

if [ -z "$WEBHOOK_URL" ]; then
  echo "[ERROR] WEBHOOK_URL is required but not set."
  exit 1
fi

echo "============================================================"
echo "  Medusa Security Scanner"
echo "  Repo:    $REPO_URL"
echo "  Branch:  $BRANCH"
echo "  Ticket:  ${TICKET_ID:-N/A}"
echo "  Group:   ${GROUP_ID:-N/A}"
echo "============================================================"

# --- Clonar el repositorio ---
echo "[1/4] Cloning repository..."
if [ -n "$GITHUB_TOKEN" ]; then
  CLONE_URL=$(echo "$REPO_URL" | sed "s|https://|https://${GITHUB_TOKEN}@|")
else
  CLONE_URL="$REPO_URL"
fi

git clone --depth=1 --branch "$BRANCH" "$CLONE_URL" "$SCAN_DIR" || {
  echo "[ERROR] Git clone failed. Check REPO_URL and BRANCH."
  curl -s -X POST "$WEBHOOK_URL" \
    -H "Content-Type: application/json" \
    -d "{
      \"status\": \"error\",
      \"error\": \"Git clone failed\",
      \"repo_url\": \"$REPO_URL\",
      \"branch\": \"$BRANCH\",
      \"ticket_id\": \"$TICKET_ID\",
      \"group_id\": \"$GROUP_ID\",
      \"scanner\": \"medusa\"
    }" || true
  exit 1
}

# --- Correr Medusa ---
echo "[2/4] Running Medusa scan..."
cd "$SCAN_DIR"

medusa init --no-interactive 2>/dev/null || true

medusa scan . \
  --output "$RESULTS_DIR" \
  --workers 4 2>&1 || true

# Tomar el JSON principal (excluir raw-payloads y scan_history)
RESULTS_FILE=$(ls -t "$RESULTS_DIR"/medusa-scan-*.json 2>/dev/null | grep -v "raw-payloads" | head -1)

# Si no se generó ningún archivo, crear uno vacío válido
if [ -z "$RESULTS_FILE" ] || [ ! -f "$RESULTS_FILE" ]; then
  echo '{"findings": [], "severity_breakdown": {}, "scan_summary": {}}' > "$RESULTS_DIR/fallback.json"
  RESULTS_FILE="$RESULTS_DIR/fallback.json"
fi

echo "[3/4] Scan complete. Parsing results..."

# Conteos desde el archivo principal
CRITICAL=$(jq '[.findings[]? | select(.severity == "CRITICAL")] | length' "$RESULTS_FILE" 2>/dev/null || echo 0)
HIGH=$(jq '[.findings[]? | select(.severity == "HIGH")] | length' "$RESULTS_FILE" 2>/dev/null || echo 0)
MEDIUM=$(jq '[.findings[]? | select(.severity == "MEDIUM")] | length' "$RESULTS_FILE" 2>/dev/null || echo 0)
LOW=$(jq '[.findings[]? | select(.severity == "LOW")] | length' "$RESULTS_FILE" 2>/dev/null || echo 0)
TOTAL=$(jq '.findings | length' "$RESULTS_FILE" 2>/dev/null || echo 0)

# Construir el payload final para n8n
jq -n \
  --arg status "completed" \
  --arg scanner "medusa" \
  --arg repo_url "$REPO_URL" \
  --arg branch "$BRANCH" \
  --arg ticket_id "$TICKET_ID" \
  --arg group_id "$GROUP_ID" \
  --arg user_email "$USER_EMAIL" \
  --argjson critical "$CRITICAL" \
  --argjson high "$HIGH" \
  --argjson medium "$MEDIUM" \
  --argjson low "$LOW" \
  --argjson total "$TOTAL" \
  --slurpfile raw_results "$RESULTS_FILE" \
  '{
    status: $status,
    scanner: $scanner,
    repo_url: $repo_url,
    branch: $branch,
    ticket_id: $ticket_id,
    group_id: $group_id,
    user_email: $user_email,
    summary: {
      total: $total,
      critical: $critical,
      high: $high,
      medium: $medium,
      low: $low
    },
    findings: ($raw_results[0].findings // [])
  }' > "$SUMMARY_FILE"

echo "[4/4] Sending results to webhook..."
echo "  Total findings: $TOTAL (CRITICAL: $CRITICAL | HIGH: $HIGH | MEDIUM: $MEDIUM | LOW: $LOW)"

# --- Enviar resultados a n8n ---
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d @"$SUMMARY_FILE")

if [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]; then
  echo "[OK] Results sent successfully (HTTP $HTTP_STATUS)"
else
  echo "[WARN] Webhook returned HTTP $HTTP_STATUS — results may not have been received"
fi

echo "============================================================"
echo "  Medusa scan finished."
echo "============================================================"
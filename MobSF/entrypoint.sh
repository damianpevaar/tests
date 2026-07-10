#!/bin/bash
set -e

echo "===== Starting MobSF Scanner ====="

if [[ -z "$GITHUB_PAT" ]]; then echo "ERROR: Missing GITHUB_PAT"; exit 1; fi
if [[ -z "$WEBHOOK_URL" ]]; then echo "ERROR: Missing WEBHOOK_URL"; exit 1; fi
if [[ -z "$REPO_URL" ]]; then echo "ERROR: Missing REPO_URL"; exit 1; fi

TICKET_ID="${TICKET_ID:-0}"
GROUP_ID="${GROUP_ID:-0}"
TIMESTAMP="${TIMESTAMP:-0}"
USER_EMAIL="${USER_EMAIL:-0}"
MOBSF_PORT=8000
MOBSF_API_KEY=""

echo "→ Config: Ticket [$TICKET_ID] | Email [$USER_EMAIL] | Repo [$REPO_URL]"

# 1. CLONAR REPO
echo "→ Cloning repository..."
git clone "https://${GITHUB_PAT}@${REPO_URL#https://}" /app/repo --quiet
cd /app/repo

# 2. DETECTAR Y PREPARAR ARCHIVO PARA ESCANEO
echo "→ Detecting app type..."
APK_FILE=$(find /app/repo -name "*.apk" | head -1)
IPA_FILE=$(find /app/repo -name "*.ipa" | head -1)

if [[ -n "$APK_FILE" ]]; then
    echo "→ APK found: $APK_FILE"
    cp "$APK_FILE" /app/target.apk
    UPLOAD_FILE="/app/target.apk"
    SCAN_TYPE="apk"
    FILE_NAME=$(basename "$APK_FILE")
elif [[ -n "$IPA_FILE" ]]; then
    echo "→ IPA found: $IPA_FILE"
    cp "$IPA_FILE" /app/target.ipa
    UPLOAD_FILE="/app/target.ipa"
    SCAN_TYPE="ipa"
    FILE_NAME=$(basename "$IPA_FILE")
else
    echo "→ No APK/IPA found, zipping source code..."
    zip -r /app/source.zip . -x "*.git*" > /dev/null
    UPLOAD_FILE="/app/source.zip"
    FILE_NAME="source.zip"
    if find /app/repo -name "*.gradle" -o -name "AndroidManifest.xml" | grep -q .; then
        SCAN_TYPE="apk"
    elif find /app/repo -name "*.xcodeproj" -o -name "*.swift" | grep -q .; then
        SCAN_TYPE="ios"
    else
        SCAN_TYPE="zip"
    fi
fi

FILE_SIZE=$(wc -c < "$UPLOAD_FILE")
echo "→ File: $FILE_NAME | Type: $SCAN_TYPE | Size: ${FILE_SIZE} bytes"

# 3. INICIAR MOBSF EN BACKGROUND Y CAPTURAR LOGS
echo "→ Starting MobSF server..."
mobsf > /tmp/mobsf.log 2>&1 &
MOBSF_PID=$!

# 4. ESPERAR QUE MOBSF ESTÉ LISTO Y CAPTURAR API KEY
echo "→ Waiting for MobSF to be ready..."
MAX_WAIT=120
WAITED=0

until curl -s "http://localhost:$MOBSF_PORT" > /dev/null 2>&1; do
    sleep 5
    WAITED=$((WAITED + 5))
    echo "→ Waiting... ${WAITED}s"

    if [[ -z "$MOBSF_API_KEY" ]]; then
        MOBSF_API_KEY=$(grep "REST API Key:" /tmp/mobsf.log 2>/dev/null | sed 's/.*REST API Key: //' | sed 's/\x1b\[[0-9;]*m//g' | tr -d '[:space:]' | tail -1 || echo "")
    fi

    if [ $WAITED -ge $MAX_WAIT ]; then
        echo "❌ ERROR: MobSF did not start in ${MAX_WAIT}s"
        curl -s -X POST "$WEBHOOK_URL/mobsf-scan/$TICKET_ID" \
             -H "Content-Type: application/json" \
             -d "{\"status\": \"error\", \"error_type\": \"MobSF Start Timeout\", \"ticket_id\": \"$TICKET_ID\", \"group_id\": \"$GROUP_ID\"}"
        exit 1
    fi
done

if [[ -z "$MOBSF_API_KEY" ]]; then
    MOBSF_API_KEY=$(grep "REST API Key:" /tmp/mobsf.log 2>/dev/null | sed 's/.*REST API Key: //' | sed 's/\x1b\[[0-9;]*m//g' | tr -d '[:space:]' | tail -1 || echo "")
fi

echo "→ MobSF is ready!"

MOBSF_API_KEY=$(echo "$MOBSF_API_KEY" | tr -d '[:space:]\r\n')
echo "→ API Key: [${MOBSF_API_KEY:0:10}]"

# 5. SUBIR ARCHIVO A MOBSF
echo "→ Uploading to MobSF..."
UPLOAD_RESPONSE=$(curl -s -X POST "http://localhost:$MOBSF_PORT/api/v1/upload" \
    -H "Authorization: $MOBSF_API_KEY" \
    -F "file=@$UPLOAD_FILE")

echo "→ Upload response: $UPLOAD_RESPONSE"
SCAN_HASH=$(echo "$UPLOAD_RESPONSE" | jq -r '.hash // empty')

if [[ -z "$SCAN_HASH" ]]; then
    echo "❌ ERROR: Failed to upload to MobSF"
    curl -s -X POST "$WEBHOOK_URL/mobsf-scan/$TICKET_ID" \
         -H "Content-Type: application/json" \
         -d "{\"status\": \"error\", \"error_type\": \"MobSF Upload Failed\", \"ticket_id\": \"$TICKET_ID\", \"group_id\": \"$GROUP_ID\"}"
    exit 1
fi
echo "→ Scan hash: $SCAN_HASH"

# 6. INICIAR ANÁLISIS
echo "→ Starting scan (type: $SCAN_TYPE)..."
SCAN_RESPONSE=$(curl -s -X POST "http://localhost:$MOBSF_PORT/api/v1/scan" \
    -H "Authorization: $MOBSF_API_KEY" \
    -d "scan_type=$SCAN_TYPE&file_name=$FILE_NAME&hash=$SCAN_HASH")
echo "→ Scan response: $SCAN_RESPONSE"

# 7. ESPERAR QUE EL SCAN TERMINE
echo "→ Waiting for scan to complete..."
MAX_SCAN_WAIT=300
SCAN_WAITED=0
until curl -s -X POST "http://localhost:$MOBSF_PORT/api/v1/report_json" \
    -H "Authorization: $MOBSF_API_KEY" \
    -d "hash=$SCAN_HASH" | jq -e '.app_name != null' > /dev/null 2>&1; do
    sleep 10
    SCAN_WAITED=$((SCAN_WAITED + 10))
    echo "→ Scan in progress... ${SCAN_WAITED}s"
    if [ $SCAN_WAITED -ge $MAX_SCAN_WAIT ]; then
        echo "❌ ERROR: Scan timeout"
        curl -s -X POST "$WEBHOOK_URL/mobsf-scan/$TICKET_ID" \
             -H "Content-Type: application/json" \
             -d "{\"status\": \"error\", \"error_type\": \"Scan Timeout\", \"ticket_id\": \"$TICKET_ID\", \"group_id\": \"$GROUP_ID\"}"
        exit 1
    fi
done
echo "→ Scan complete!"

# 8. OBTENER REPORTE JSON
echo "→ Fetching report..."
REPORT=$(curl -s -X POST "http://localhost:$MOBSF_PORT/api/v1/report_json" \
    -H "Authorization: $MOBSF_API_KEY" \
    -d "hash=$SCAN_HASH")


# 9. REDUCIR PAYLOAD Y AGREGAR METADATA
PAYLOAD=$(echo "$REPORT" | jq --arg repo "$REPO_URL" --arg ts "$TIMESTAMP" \
    --arg email "$USER_EMAIL" --arg group "$GROUP_ID" --arg ticket "$TICKET_ID" \
    '{
        ticket_id: $ticket,
        repo_url: $repo,
        scan_timestamp: $ts,
        user_email: $email,
        group_id: $group,
        status: "success",
        app_name: .app_name,
        app_type: .app_type,
        package_name: .package_name,
        version: .version_name,
        security_score: .appsec.security_score,
        trackers: .appsec.trackers,
        total_high: (.appsec.high | length),
        total_warning: (.appsec.warning | length),
        findings_high: [.appsec.high[]? | {title: .title, description: .description}],
        findings_warning: [.appsec.warning[]? | {title: .title, description: .description}],
        certificate_findings: [.certificate_analysis.certificate_findings[]? | {severity: .[0], description: .[2]}],
        manifest_findings: [.manifest_analysis.manifest_findings[]? | {title: .title, severity: .severity}]
    }')

PAYLOAD_SIZE=$(echo "$PAYLOAD" | wc -c)
echo "→ Payload size: ${PAYLOAD_SIZE} bytes"

# 10. ENVIAR AL WEBHOOK
echo "→ Sending report to webhook..."
if ! echo "$PAYLOAD" | curl -s -f -X POST "$WEBHOOK_URL/mobsf-scan/$TICKET_ID" \
     -H "Content-Type: application/json" \
     --data-binary @- > /tmp/webhook_response.log; then
    echo "❌ ERROR: Webhook delivery failed"
    curl -s -X POST "$WEBHOOK_URL/mobsf-scan/$TICKET_ID" \
         -H "Content-Type: application/json" \
         -d "{\"status\": \"error\", \"error_type\": \"Webhook Delivery Failed\", \"ticket_id\": \"$TICKET_ID\", \"group_id\": \"$GROUP_ID\"}"
else
    cat /tmp/webhook_response.log
    echo "✅ Report sent successfully"
fi

# 11. DETENER MOBSF
kill $MOBSF_PID 2>/dev/null || true

echo "===== MobSF Scanner Completed ====="
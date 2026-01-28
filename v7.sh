#!/bin/bash
set -e

###############################################
# Expected environment variables
# SNYK_PROJECTS, STACKHAWK_PROJECTS, GITHUB_PAT, 
# TICKET_ID, SNYK_CLIENT_ID, SNYK_CLIENT_SECRET, 
# STACKHAWK_API_KEY, WEBHOOK_URL
###############################################

echo "===== Starting Scan Runner ====="

# --- Validation ---
if [[ -z "$SNYK_CLIENT_ID" ]]; then echo "ERROR: Missing SNYK_CLIENT_ID variable"; exit 1; fi
if [[ -z "$SNYK_CLIENT_SECRET" ]]; then echo "ERROR: Missing SNYK_CLIENT_SECRET variable"; exit 1; fi
if [[ -z "$STACKHAWK_API_KEY" ]]; then echo "ERROR: Missing STACKHAWK_API_KEY variable"; exit 1; fi
if [[ -z "$GITHUB_PAT" ]]; then echo "ERROR: Missing GITHUB_PAT variable"; exit 1; fi
if [[ -z "$WEBHOOK_URL" ]]; then echo "ERROR: Missing WEBHOOK_URL variable"; exit 1; fi

echo "→ Authenticating Snyk CLI"
snyk auth --auth-type=oauth --client-id="$SNYK_CLIENT_ID" --client-secret="$SNYK_CLIENT_SECRET"

echo "→ Authenticating StackHawk CLI"
hawk init --api-key="$STACKHAWK_API_KEY"

TICKET_ID=${TICKET_ID:-0}

###############################################
# Process Snyk Projects
###############################################
cd /app/snyk-projects

echo "$SNYK_PROJECTS" > snyk.json

DOCKER_COUNT=1

jq -c '.[]' snyk.json | while read proj; do
  NAME=$(echo "$proj" | jq -r '.name')
  URL=$(echo "$proj" | jq -r '.url')

  echo "------------------------------------------------"
  echo "Processing Snyk project: $NAME"

  # GitHub repo
  if [[ "$URL" != "null" && "$URL" != "" ]]; then
    echo "→ Cloning repo from $URL"
    
    # -------------------------------------------------------------
    # IMPORTANTE: Asegúrate de que aquí clones la rama correcta
    # -------------------------------------------------------------
    git clone "https://$GITHUB_PAT@${URL#https://}"
    cd "$NAME"

    # --- NUEVO: Detectar la rama actual automáticamente ---
    CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
    echo "→ Detected Branch: $CURRENT_BRANCH"
    # ------------------------------------------------------

    # ==========================================================
    # LOGIC CHANGE: Check if URL contains 'iac' (case insensitive)
    # ==========================================================
    if [[ "$URL" =~ [iI][aA][cC] ]]; then
        echo "→ [IaC] Infrastructure as Code repository detected (based on URL)."
        
        echo "→ Running snyk iac test"
        set +e
        # Generamos un archivo temporal primero
        snyk iac test . --json > "/app/snyk-output/snyk-iac-temp-$NAME.json"
        code=$?
        set -e

        # --- NUEVO: Inyectamos la rama al JSON final ---
        jq --arg branch "$CURRENT_BRANCH" '. + {git_branch: $branch}' "/app/snyk-output/snyk-iac-temp-$NAME.json" > "/app/snyk-output/snyk-iac-test-$NAME.json"
        # -----------------------------------------------

        case $code in
            0) echo "Snyk IaC test completed - no issues found";;
            1) echo "Snyk IaC test completed - issues found";;
            *) echo "Snyk IaC test failed with exit code $code";;
        esac

        # Notify webhook for IaC
        if [ -s "/app/snyk-output/snyk-iac-test-$NAME.json" ]; then
            echo "→ Notifying webhook (snyk iac test)"
            curl -X POST "$WEBHOOK_URL/snyk-scan/$NAME/$TICKET_ID" \
                -H "Content-Type: application/json" \
                --data-binary @/app/snyk-output/snyk-iac-test-$NAME.json
        else
            echo "Report /app/snyk-output/snyk-iac-test-$NAME.json not found or empty"
        fi

    else
        # ==========================================================
        # STANDARD FLOW (Backend/Frontend)
        # ==========================================================
        echo "→ [Standard] Code repository detected."
        echo "→ Searching for dependencies"
        
        if [ -f "package.json" ]; then echo "Node.js project detected"; npm install; fi
        if [ -f "requirements.txt" ]; then echo "→ Creating python venv"; python3 -m venv .venv; source .venv/bin/activate; pip install -r requirements.txt; fi
        if [ -f "Cargo.toml" ]; then echo "Rust project detected"; rustup update; fi
        
        # 1. Open Source (SCA) Scan
        echo "→ Running snyk test (Open Source)"
        set +e
        snyk test --all-projects --json > "/app/snyk-output/snyk-test-temp-$NAME.json"
        code=$?
        set -e
        
        # --- NUEVO: Inyectamos rama ---
        jq --arg branch "$CURRENT_BRANCH" '. + {git_branch: $branch}' "/app/snyk-output/snyk-test-temp-$NAME.json" > "/app/snyk-output/snyk-test-$NAME.json"
        
        # 2. Code (SAST) Scan
        echo "→ Running snyk code test (SAST)"
        set +e
        snyk code test --json > "/app/snyk-output/snyk-code-temp-$NAME.json"
        code=$?
        set -e

        # --- NUEVO: Inyectamos rama ---
        jq --arg branch "$CURRENT_BRANCH" '. + {git_branch: $branch}' "/app/snyk-output/snyk-code-temp-$NAME.json" > "/app/snyk-output/snyk-code-test-$NAME.json"
        
        # Cleanup
        if command -v deactivate >/dev/null 2>&1; then echo "→ Deactivating python venv"; deactivate; fi
        
        # Notify Webhook (SCA)
        if [ -s "/app/snyk-output/snyk-test-$NAME.json" ]; then
            echo "→ Notifying webhook (snyk test)"
            curl -X POST "$WEBHOOK_URL/snyk-scan/$NAME/$TICKET_ID" \
                -H "Content-Type: application/json" \
                --data-binary @/app/snyk-output/snyk-test-$NAME.json
        fi
        
        # Notify Webhook (SAST)
        if [ -s "/app/snyk-output/snyk-code-test-$NAME.json" ]; then
            echo "→ Notifying webhook (snyk code test)"
            curl -X POST "$WEBHOOK_URL/snyk-code-scan/$NAME/$TICKET_ID" \
                -H "Content-Type: application/json" \
                --data-binary @/app/snyk-output/snyk-code-test-$NAME.json
        fi
    fi 
    # ==========================================================
    # END LOGIC CHANGE
    # ==========================================================

    cd ..
  else
    # Docker project (No changes here)
    echo "→ Docker image scan: $NAME"
    set +e
    ECR_PASSWORD=$(aws ecr get-login-password --region us-east-1)
    snyk container test "${NAME#docker.io/}" --username=AWS --password="$ECR_PASSWORD" --json > "/app/docker-scan-$DOCKER_COUNT-temp.json"
    code=$?
    set -e
    
    jq --arg image "$NAME" '. + { scannedImage: $image }' "/app/docker-scan-$DOCKER_COUNT-temp.json" > "/app/docker-scan-$DOCKER_COUNT.json"
    
    if [ -s "/app/docker-scan-$DOCKER_COUNT.json" ]; then
        echo "→ Notifying webhook (snyk container test)"
        curl -X POST "$WEBHOOK_URL/snyk-container-scan/$TICKET_ID" \
            -H "Content-Type: application/json" \
            --data-binary @/app/docker-scan-$DOCKER_COUNT.json
    fi
    DOCKER_COUNT=$((DOCKER_COUNT+1))
  fi
done

###############################################
# Process StackHawk Projects (Lógica que agregamos antes)
###############################################
cd /app/stackhawk-projects

echo "$STACKHAWK_PROJECTS" > hawk.json
jq -c '.[]' hawk.json | while read proj; do
  NAME=$(echo "$proj" | jq -r '.name')
  URL=$(echo "$proj" | jq -r '.url')

  echo "------------------------------------------------"
  echo "Processing StackHawk project: $NAME"

  if [[ "$URL" != "null" && "$URL" != "" ]]; then
    echo "→ Cloning repo from $URL"
    git clone "https://$GITHUB_PAT@${URL#https://}"
    cd "$NAME"
    
    # Detectamos rama también aquí por si acaso lo necesitas en el log de error
    CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)

    echo "→ Running hawk scan"
    set +e
    SCAN_OUTPUT=$(hawk scan --no-progress 2>&1)
    EXIT_CODE=$?
    
    SCAN_ID=$(echo "$SCAN_OUTPUT" | grep -i "scan id" | awk '{print $NF}')
    set -e
    
    if [[ -n "$SCAN_ID" ]]; then
        echo "Scan ID obtained: $SCAN_ID"
        if [[ "$TICKET_ID" != 0 ]]; then
            echo "→ Notifying webhook (hawk scan success)"
            curl -X POST "$WEBHOOK_URL/stackhawk-cloud-sec/$NAME" \
                -H "Content-Type: application/json" \
                --data "{ \"status\": \"success\", \"scan_id\": \"$SCAN_ID\", \"ticket_id\": \"$TICKET_ID\", \"branch\": \"$CURRENT_BRANCH\" }"
        else
            echo "Scan finished but TICKET_ID is 0. No webhook sent."
        fi
    else
        echo "❌ ERROR: Hawk scan failed to start or generate an ID."
        echo "Exit Code: $EXIT_CODE"
        
        echo "$SCAN_OUTPUT" > /tmp/hawk_error_log.txt
        jq -n \
          --arg status "failed" \
          --arg project "$NAME" \
          --arg ticket "$TICKET_ID" \
          --arg branch "$CURRENT_BRANCH" \
          --rawfile logs /tmp/hawk_error_log.txt \
          '{status: $status, project: $project, ticket_id: $ticket, git_branch: $branch, error_logs: $logs}' > /tmp/hawk_error_payload.json

        echo "→ Notifying webhook (hawk scan FAILURE)"
        curl -X POST "$WEBHOOK_URL/stackhawk-cloud-sec/$NAME" \
            -H "Content-Type: application/json" \
            --data-binary @/tmp/hawk_error_payload.json
            
        rm /tmp/hawk_error_log.txt /tmp/hawk_error_payload.json
    fi
    
    cd ..
  else
    echo "Project has no url"
  fi
  
done

echo "===== Scan Runner Completed ====="

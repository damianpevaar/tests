#!/bin/bash
set -e

###############################################
# Expected environment variables
# SNYK_PROJECTS, STACKHAWK_PROJECTS, GITHUB_PAT, 
# TICKET_ID, SNYK_CLIENT_ID, SNYK_CLIENT_SECRET, 
# STACKHAWK_API_KEY, WEBHOOK_URL, USER_EMAIL, TIMESTAMP
###############################################

echo "===== Starting Scan Runner ====="

# --- Validation ---
if [[ -z "$SNYK_CLIENT_ID" ]]; then echo "ERROR: Missing SNYK_CLIENT_ID variable"; exit 1; fi
if [[ -z "$SNYK_CLIENT_SECRET" ]]; then echo "ERROR: Missing SNYK_CLIENT_SECRET variable"; exit 1; fi
if [[ -z "$STACKHAWK_API_KEY" ]]; then echo "ERROR: Missing STACKHAWK_API_KEY variable"; exit 1; fi
if [[ -z "$GITHUB_PAT" ]]; then echo "ERROR: Missing GITHUB_PAT variable"; exit 1; fi
if [[ -z "$WEBHOOK_URL" ]]; then echo "ERROR: Missing WEBHOOK_URL variable"; exit 1; fi
if [[ -z "$USER_EMAIL" ]]; then echo "ERROR: Missing USER_EMAIL variable"; exit 1; fi
if [[ -z "$TIMESTAMP" ]]; then echo "ERROR: Missing TIMESTAMP variable"; exit 1; fi

echo "→ Authenticating Snyk CLI"
snyk auth --auth-type=oauth --client-id="$SNYK_CLIENT_ID" --client-secret="$SNYK_CLIENT_SECRET"

echo "→ Authenticating StackHawk CLI"
hawk init --api-key="$STACKHAWK_API_KEY" > /dev/null

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
  ROUTE=$(echo "$proj" | jq -r '.route')
  TARGET_BRANCH=$(echo "$proj" | jq -r '.branch // empty')

  echo "------------------------------------------------"
  echo "Processing Snyk project: $NAME"

  # GitHub repo
  if [[ "$URL" != "null" && "$URL" != "" ]]; then
    
    # -------------------------------------------------------------
    # Clone specific branch if provided (WITH ERROR HANDLING)
    # -------------------------------------------------------------
    set +e # Disable exit on error temporarily
    if [[ -n "$TARGET_BRANCH" && "$TARGET_BRANCH" != "null" ]]; then
        echo "→ Cloning specific branch: $TARGET_BRANCH from $URL"
        git clone -b "$TARGET_BRANCH" --single-branch "https://$GITHUB_PAT@${URL#https://}" "$NAME"
        CLONE_EXIT_CODE=$?
    else
        echo "→ Cloning default branch from $URL"
        git clone "https://$GITHUB_PAT@${URL#https://}" "$NAME"
        CLONE_EXIT_CODE=$?
    fi
    set -e # Re-enable exit on error

    # Check if git clone failed (e.g., branch does not exist)
    if [ $CLONE_EXIT_CODE -ne 0 ]; then
        echo "ERROR: Failed to clone repository $URL (Branch: $TARGET_BRANCH). Skipping Snyk scan."
        
        # Build error payload
        jq -n \
          --arg status "failed" \
          --arg error "Git clone failed. Branch '$TARGET_BRANCH' might not exist or repository is inaccessible." \
          --arg project "$NAME" \
          --arg branch "$TARGET_BRANCH" \
          --arg url "$URL" \
          --arg route "$ROUTE" \
          --arg ts "$TIMESTAMP" \
          --arg email "$USER_EMAIL" \
          '{ok: false, status: $status, error: $error, project_name: $project, git_branch: $branch, repo_url: $url, folder_route: $route, scan_timestamp: $ts, user_email: $email}' > "/app/snyk-output/snyk-error-$NAME.json"
        
        # Send error webhook
        echo "→ Notifying webhook (Snyk Git Clone Failure)"
        curl -X POST "$WEBHOOK_URL/snyk-scan/$NAME/$TICKET_ID" \
            -H "Content-Type: application/json" \
            --data-binary @"/app/snyk-output/snyk-error-$NAME.json"
        
        # Skip to the next project
        continue
    fi

    cd "$NAME"

    if [[ "$ROUTE" != "" && "$ROUTE" != "null" ]]; then
        echo "→ Changing to specified route: $ROUTE"
        cd "$ROUTE"
    fi

    CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
    echo "→ Detected Branch: $CURRENT_BRANCH"

    # ==========================================================
    # LOGIC CHANGE: Check if URL contains 'iac' (case insensitive)
    # ==========================================================
    if [[ "$URL" =~ [iI][aA][cC] ]]; then
        echo "→ [IaC] Infrastructure as Code repository detected (based on URL)."
        
        echo "→ Running snyk iac test"
        set +e
        snyk iac test . --json > "/app/snyk-output/snyk-iac-temp-$NAME.json"
        code=$?
        set -e

        # --- NEW: Inject branch, url, route, name, timestamp and email ---
		jq --arg branch "$CURRENT_BRANCH" \
           --arg url "$URL" \
           --arg route "$ROUTE" \
           --arg name "$NAME" \
           --arg ts "$TIMESTAMP" \
           --arg email "$USER_EMAIL" \
           '. + {git_branch: $branch, repo_url: $url, folder_route: $route, project_name: $name, scan_timestamp: $ts, user_email: $email}' \
           "/app/snyk-output/snyk-test-temp-$NAME.json" > "/app/snyk-output/snyk-test-$NAME.json"

        case $code in
            0) echo "Snyk IaC test completed - no issues found";;
            1) echo "Snyk IaC test completed - issues found";;
            *) echo "Snyk IaC test failed with exit code $code";;
        esac

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
        
        SNYK_EXTRA_FLAGS=""

        if [ -f "package.json" ]; then 
            echo "→ Node.js project detected"; 
            npm install --package-lock-only || npm install; 
        fi
        
        if [ -f "uv.lock" ]; then
            echo "→ [SCA] uv.lock detected. Exporting clean requirements for Snyk..."
            uv export --no-hashes --format requirements-txt > snyk-reqs-raw.txt
            
            # Limpieza extrema (nuestra lista perfecta de paquetes)
            grep -E '^[a-zA-Z0-9_.-]+==' snyk-reqs-raw.txt | cut -d ';' -f 1 | awk '{print $1}' > snyk-reqs.txt
            
            echo "→ Isolating Snyk from the host's global Python environment..."
            # Creamos el entorno virtual en /tmp/ para NO contaminar la carpeta del proyecto
            python3 -m venv /tmp/.snyk-isolated-venv
            
            # Apuntamos el comando de Snyk a la ruta temporal
            SNYK_EXTRA_FLAGS="--file=snyk-reqs.txt --package-manager=pip --command=/tmp/.snyk-isolated-venv/bin/python --skip-unresolved --project-name=${NAME}-${ROUTE}"

        elif [ -f "requirements.txt" ]; then
            echo "→ [SCA] requirements.txt detected natively."
            SNYK_EXTRA_FLAGS="--file=requirements.txt --package-manager=pip --command=python3 --skip-unresolved"
        fi
        
        if [ -f "Cargo.toml" ]; then echo "→ Rust project detected"; rustup update; fi
        
        # 1. Open Source (SCA) Scan
        echo "→ Running snyk test (Open Source)"
        set +e
        if [ -n "$SNYK_EXTRA_FLAGS" ]; then
            echo "→ Running Snyk SCA with flags: $SNYK_EXTRA_FLAGS"
            snyk test $SNYK_EXTRA_FLAGS --json > "/app/snyk-output/snyk-test-temp-$NAME.json"
        else
            echo "→ Running Snyk SCA with default behavior"
            snyk test --all-projects --json > "/app/snyk-output/snyk-test-temp-$NAME.json"
        fi
        code=$?
        set -e
        
        # --- NEW: Inject branch, url, route, name, timestamp and email ---
        jq --arg branch "$CURRENT_BRANCH" \
			--arg url "$URL" \
			--arg route "$ROUTE" \
			--arg name "$NAME" \
			--arg ts "$TIMESTAMP" \
			--arg email "$USER_EMAIL" \
			'if type == "array" then 
				map(. + {git_branch: $branch, repo_url: $url, folder_route: $route, project_name: $name, scan_timestamp: $ts, user_email: $email}) 
			 else 
				. + {git_branch: $branch, repo_url: $url, folder_route: $route, project_name: $name, scan_timestamp: $ts, user_email: $email} 
			 end' \
			"/app/snyk-output/snyk-test-temp-$NAME.json" > "/app/snyk-output/snyk-test-$NAME.json"
        
        # 2. Code (SAST) Scan
        echo "→ Running snyk code test (SAST)"
        set +e
        snyk code test --json > "/app/snyk-output/snyk-code-temp-$NAME.json"
        code=$?
        set -e

        # --- NEW: Inject branch, url, route, name, timestamp and email ---
        jq --arg branch "$CURRENT_BRANCH" \
			--arg url "$URL" \
			--arg route "$ROUTE" \
			--arg name "$NAME" \
			--arg ts "$TIMESTAMP" \
			--arg email "$USER_EMAIL" \
			'if type == "array" then 
				map(. + {git_branch: $branch, repo_url: $url, folder_route: $route, project_name: $name, scan_timestamp: $ts, user_email: $email}) 
			 else 
				. + {git_branch: $branch, repo_url: $url, folder_route: $route, project_name: $name, scan_timestamp: $ts, user_email: $email} 
			 end' \
			"/app/snyk-output/snyk-code-temp-$NAME.json" > "/app/snyk-output/snyk-code-test-$NAME.json"
        
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
    cd /app/snyk-projects
  else
    # Docker project
    echo "→ Docker image scan: $NAME"
    set +e
    ECR_PASSWORD=$(aws ecr get-login-password --region us-east-1)
    snyk container test "${NAME#docker.io/}" --username=AWS --password="$ECR_PASSWORD" --json > "/app/docker-scan-$DOCKER_COUNT-temp.json"
    code=$?
    set -e
    
    # --- NEW: Inject image name, timestamp and email ---
    jq --arg image "$NAME" \
       --arg ts "$TIMESTAMP" \
       --arg email "$USER_EMAIL" \
       '. + { scannedImage: $image, scan_timestamp: $ts, user_email: $email }' \
       "/app/docker-scan-$DOCKER_COUNT-temp.json" > "/app/docker-scan-$DOCKER_COUNT.json"
    
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
# Process StackHawk Projects 
###############################################
cd /app/stackhawk-projects

echo "$STACKHAWK_PROJECTS" > hawk.json
jq -c '.[]' hawk.json | while read proj; do
  NAME=$(echo "$proj" | jq -r '.name')
  URL=$(echo "$proj" | jq -r '.url')
  ROUTE=$(echo "$proj" | jq -r '.route')
  TARGET_BRANCH=$(echo "$proj" | jq -r '.branch // empty')

  echo "------------------------------------------------"
  # --- ENHANCED LOGS FOR STACKHAWK ---
  if [[ "$ROUTE" != "null" && "$ROUTE" != "" ]]; then
      echo "→ Analyzing StackHawk project: [$NAME] | Folder: [$ROUTE]"
  else
      echo "→ Analyzing StackHawk project: [$NAME] | Folder: [Root]"
  fi

  if [[ "$URL" != "null" && "$URL" != "" ]]; then
    
    # --- Clone specific branch if provided (WITH ERROR HANDLING) ---
    set +e # Disable exit on error temporarily
    if [[ -n "$TARGET_BRANCH" && "$TARGET_BRANCH" != "null" ]]; then
        echo "→ Cloning specific branch: [$TARGET_BRANCH] from $URL"
        git clone -b "$TARGET_BRANCH" --single-branch "https://$GITHUB_PAT@${URL#https://}" "$NAME" --quiet
        CLONE_EXIT_CODE=$?
    else
        echo "→ Cloning default branch from $URL"
        git clone "https://$GITHUB_PAT@${URL#https://}" "$NAME" --quiet
        CLONE_EXIT_CODE=$?
    fi
    set -e # Re-enable exit on error

    # Check if git clone failed
    if [ $CLONE_EXIT_CODE -ne 0 ]; then
        echo "ERROR: Failed to clone repository $URL (Branch: $TARGET_BRANCH). Skipping StackHawk scan."
        
        # Build error payload
        jq -n \
          --arg status "failed" \
          --arg error "Git clone failed. Branch '$TARGET_BRANCH' might not exist or repository is inaccessible." \
          --arg project "$NAME" \
          --arg branch "$TARGET_BRANCH" \
          --arg url "$URL" \
          --arg route "$ROUTE" \
          --arg ts "$TIMESTAMP" \
          --arg email "$USER_EMAIL" \
          '{status: $status, error: $error, project: $project, git_branch: $branch, repo_url: $url, folder_route: $route, scan_timestamp: $ts, user_email: $email}' > "/tmp/hawk_clone_error.json"
        
        # Send error webhook
        echo "→ Notifying webhook (StackHawk Git Clone Failure)"
        curl -s -S -X POST "$WEBHOOK_URL/stackhawk-cloud-sec/$NAME" \
            -H "Content-Type: application/json" \
            --data-binary @"/tmp/hawk_clone_error.json" > /dev/null
            
        rm -f "/tmp/hawk_clone_error.json"
        
        # Skip to the next project
        continue
    fi

    cd "$NAME"

    if [[ "$ROUTE" != "" && "$ROUTE" != "null" ]]; then
        echo "→ Changing to specified route: $ROUTE"
        
        # Only copy if it exists in the root AND isn't already in the target folder
        if [ -f "stackhawk.yml" ] && [ ! -f "$ROUTE/stackhawk.yml" ]; then
            echo "→ Copying stackhawk.yml from root to $ROUTE/"
            cp stackhawk.yml "$ROUTE/"
        fi

        cd "$ROUTE"
        
        if [ ! -f "stackhawk.yml" ]; then
            echo "→ WARNING: stackhawk.yml not found in $(pwd). Hawk scan might fail!"
        else
            echo "→ stackhawk.yml found in $(pwd)."
        fi
    fi
    
    # Detect branch here as well for error logs
    CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
    echo "→ Detected Branch: $CURRENT_BRANCH"
    echo "→ Running hawk scan"
    
    # --- THE MAGIC: Force StackHawk to export a local SARIF file ---
    export SARIF_ARTIFACT=true
    
    set +e
    hawk scan --no-progress 2>&1 | tee /tmp/hawk_scan_live.log
    EXIT_CODE=${PIPESTATUS[0]}
    SCAN_OUTPUT=$(cat /tmp/hawk_scan_live.log)
    set -e
    
    SCAN_ID=$(echo "$SCAN_OUTPUT" | grep -i "scan id" | awk '{print $NF}')
    
    if [[ -n "$SCAN_ID" ]]; then
        echo "→ StackHawk scan successful! Scan ID obtained: $SCAN_ID"
        
        # Verify if StackHawk generated the SARIF file
        if [ -f "stackhawk.sarif" ]; then
            echo "→ stackhawk.sarif file found. Adding metadata and sending to Webhook..."
            
            # --- NEW: Inject branch, ticket, route, timestamp and email ---
            jq --arg branch "$CURRENT_BRANCH" \
               --arg ticket "$TICKET_ID" \
               --arg folder "$ROUTE" \
               --arg ts "$TIMESTAMP" \
               --arg email "$USER_EMAIL" \
               '. + {git_branch: $branch, ticket_id: $ticket, folder_route: $folder, scan_timestamp: $ts, user_email: $email}' \
               stackhawk.sarif > payload_hawk.json
             
            echo "→ Notifying webhook (stackhawk DAST scan)"
            curl -s -S -X POST "$WEBHOOK_URL/stackhawk-cloud-sec/$NAME" \
                -H "Content-Type: application/json" \
                --data-binary @payload_hawk.json > /dev/null
                
        else
            # --- Send the FULL scan logs in the JSON if SARIF is missing ---
            echo "→ No detailed report file generated. Sending basic status payload with full execution logs..."
            
            # Save the raw output to a file to safely parse it into JSON
            echo "$SCAN_OUTPUT" > /tmp/hawk_scan_log.txt
            
            # --- NEW: Inject folder_route, timestamp and email ---
            jq -n \
              --arg status "success_no_report" \
              --arg scan "$SCAN_ID" \
              --arg ticket "$TICKET_ID" \
              --arg branch "$CURRENT_BRANCH" \
              --arg folder "$ROUTE" \
              --arg ts "$TIMESTAMP" \
              --arg email "$USER_EMAIL" \
              --rawfile logs /tmp/hawk_scan_log.txt \
              '{status: $status, scan_id: $scan, ticket_id: $ticket, branch: $branch, folder_route: $folder, scan_timestamp: $ts, user_email: $email, scan_logs: $logs}' > /tmp/hawk_basic_payload.json
            
            echo "→ Notifying webhook (stackhawk DAST scan)"
            curl -s -S -X POST "$WEBHOOK_URL/stackhawk-cloud-sec/$NAME" \
                -H "Content-Type: application/json" \
                --data-binary @/tmp/hawk_basic_payload.json > /dev/null
                
            rm /tmp/hawk_scan_log.txt /tmp/hawk_basic_payload.json
        fi
    else
        echo "ERROR: Hawk scan failed to start or generate an ID."
        echo "Exit Code: $EXIT_CODE"
        
        echo "$SCAN_OUTPUT" > /tmp/hawk_error_log.txt
        
        # --- NEW: Inject folder_route, timestamp and email ---
        jq -n \
          --arg status "failed" \
          --arg project "$NAME" \
          --arg ticket "$TICKET_ID" \
          --arg branch "$CURRENT_BRANCH" \
          --arg folder "$ROUTE" \
          --arg ts "$TIMESTAMP" \
          --arg email "$USER_EMAIL" \
          --rawfile logs /tmp/hawk_error_log.txt \
          '{status: $status, project: $project, ticket_id: $ticket, git_branch: $branch, folder_route: $folder, scan_timestamp: $ts, user_email: $email, error_logs: $logs}' > /tmp/hawk_error_payload.json

        echo "→ Notifying webhook (hawk scan FAILURE)"
        curl -s -S -X POST "$WEBHOOK_URL/stackhawk-cloud-sec/$NAME" \
            -H "Content-Type: application/json" \
            --data-binary @/tmp/hawk_error_payload.json > /dev/null
            
        rm /tmp/hawk_error_log.txt /tmp/hawk_error_payload.json
    fi
    
    cd /app/stackhawk-projects
  else
    echo "→ Project does not have a valid URL."
  fi
  
done

echo "===== Scan Runner Completed ====="
#!/bin/bash
set -e

###############################################
# Expected environment variables
#
# SNYK_PROJECTS   = JSON array of:
#   [{"name":"api","url":"https://github.com/org/api.git"}]
#
# STACKHAWK_PROJECTS = JSON array of:
#   [{"name":"payments","url":"https://github.com/org/payments-api.git"}]
#
# GITHUB_PAT      = github PAT token
# TICKET_ID       = Jira ticket id
# SNYK_CLIENT_ID  
# SNYK_CLIENT_SECRET 
# STACKHAWK_API_KEY
# WEBHOOK_URL 
#
###############################################

echo "===== Starting Scan Runner ====="

if [[ -z "$SNYK_CLIENT_ID" ]]; then
  echo "ERROR: Missing SNYK_CLIENT_ID variable"
  exit 1
fi

if [[ -z "$SNYK_CLIENT_SECRET" ]]; then
  echo "ERROR: Missing SNYK_CLIENT_SECRET variable"
  exit 1
fi

if [[ -z "$STACKHAWK_API_KEY" ]]; then
  echo "ERROR: Missing STACKHAWK_API_KEY variable"
  exit 1
fi

if [[ -z "$GITHUB_PAT" ]]; then
  echo "ERROR: Missing GITHUB_PAT variable"
  exit 1
fi

if [[ -z "$WEBHOOK_URL" ]]; then
  echo "ERROR: Missing WEBHOOK_URL variable"
  exit 1
fi

echo "→ Authenticating Snyk CLI"
snyk auth --auth-type=oauth --client-id="$SNYK_CLIENT_ID" --client-secret="$SNYK_CLIENT_SECRET"

echo "→ Authenticating StackHawk CLI"
hawk init --api-key="$STACKHAWK_API_KEY"

TICKET_ID=${TICKET_ID:-0}

#if [[ -z "$SNYK_API_TOKEN" ]]; then
#  echo "ERROR: Missing SNYK_API_TOKEN variable"
#  exit 1
#fi

###############################################
# Process Snyk Projects
###############################################
cd /app/snyk-projects

echo "$SNYK_PROJECTS" > snyk.json

DOCKER_COUNT=1

jq -c '.[]' snyk.json | while read proj; do
  NAME=$(echo "$proj" | jq -r '.name')
  URL=$(echo "$proj" | jq -r '.url')

  echo "Processing Snyk project: $NAME"

  # GitHub repo
  if [[ "$URL" != "null" && "$URL" != "" ]]; then
    echo "→ Cloning repo from $URL"
    git clone "https://$GITHUB_PAT@${URL#https://}"
    cd "$NAME"
    echo "→ Searching for dependencies"
	
	if [ -f "package.json" ]; then
		echo "Node.js project detected"
		npm install
	fi
	
	if [ -f "requirements.txt" ]; then
		echo "→ Creating python venv"
		python3 -m venv .venv
		source .venv/bin/activate
		pip install -r requirements.txt
	fi
	
	if [ -f "Cargo.toml" ]; then
		echo "Rust project detected"
		rustup update
	fi
	
	echo "→ Running snyk test"
	
	set +e
    snyk test --all-projects --json > "/app/snyk-output/snyk-test-$NAME.json"
	code=$?
	set -e
	
	case $code in
		0) echo "Snyk test completed - no vulnerabilities found";;
		1) echo "Snyk test completed - vulnerabilities found";;
		2|3) echo "Snyk test failed with exit code $code";;
	esac
	
	echo "→ Running snyk code test"
	
	set +e
	snyk code test --json > "/app/snyk-output/snyk-code-test-$NAME.json"
	code=$?
	set -e
	
	case $code in
		0) echo "Snyk code test completed - no vulnerabilities found";;
		1) echo "Snyk code test completed - vulnerabilities found";;
		2|3) echo "Snyk code test failed with exit code $code";;
	esac
	
	if command -v deactivate >/dev/null 2>&1; then
		echo "→ Deactivating python venv"
		deactivate
	fi
	
	#Notify webhook
	if [ -s "/app/snyk-output/snyk-test-$NAME.json" ]; then
		echo "→ Notifying webhook (snyk test)"
		curl -X POST "$WEBHOOK_URL/snyk-scan/$NAME/$TICKET_ID" \
			-H "Content-Type: application/json" \
			--data-binary @/app/snyk-output/snyk-test-$NAME.json
	else
		echo "Report /app/snyk-output/snyk-test-$NAME.json not found"
	fi
	
	#Notify webhook
	if [ -s "/app/snyk-output/snyk-code-test-$NAME.json" ]; then
		echo "→ Notifying webhook (snyk code test)"
		curl -X POST "$WEBHOOK_URL/snyk-code-scan/$NAME/$TICKET_ID" \
			-H "Content-Type: application/json" \
			--data-binary @/app/snyk-output/snyk-code-test-$NAME.json
	else
		echo "Report /app/snyk-output/snyk-code-test-$NAME.json not found"
	fi
	
    cd ..
  else
    # Docker project
    echo "→ Docker image scan: $NAME"
	set +e
	ECR_PASSWORD=$(aws ecr get-login-password --region us-east-1)
	echo "$ECR_PASSWORD"
    snyk container test "${NAME#docker.io/}" --username=AWS --password="$ECR_PASSWORD" --json > "/app/docker-scan-$DOCKER_COUNT-temp.json"
	code=$?
	set -e
	echo "exit code: $code"
	jq --arg image "$NAME" '. + { scannedImage: $image }' "/app/docker-scan-$DOCKER_COUNT-temp.json" > "/app/docker-scan-$DOCKER_COUNT.json"
	
	#Notify webhook
	if [ -s "/app/docker-scan-$DOCKER_COUNT.json" ]; then
		echo "→ Notifying webhook (snyk container test)"
		curl -X POST "$WEBHOOK_URL/snyk-container-scan/$TICKET_ID" \
			-H "Content-Type: application/json" \
			--data-binary @/app/docker-scan-$DOCKER_COUNT.json
	else
		echo "Report /app/docker-scan-$DOCKER_COUNT.json not found"
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

  echo "Processing StackHawk project: $NAME"

  # GitHub repo
  if [[ "$URL" != "null" && "$URL" != "" ]]; then
    echo "→ Cloning repo from $URL"
    git clone "https://$GITHUB_PAT@${URL#https://}"
    cd "$NAME"
	
	# StackHawk normally requires a hawk configuration yaml inside repo.
    # Placeholder example:
    echo "→ Running hawk scan"
	set +e
    hawk scan --no-progress
	SCAN_ID=$(hawk scan 2>&1 | grep -i "scan id" | awk '{print $NF}')
	set -e
	echo "Scan ID: $SCAN_ID"
	
	#Notify webhook
	if [[ -n "$SCAN_ID" && "$TICKET_ID" != 0 ]]; then
		echo "→ Notifying webhook (hawk scan)"
		curl -X POST "$WEBHOOK_URL/stackhawk-cloud-sec/$NAME" \
			-H "Content-Type: application/json" \
			--data "{ \"scan_id\": \"$SCAN_ID\", \"ticket_id\": \"$TICKET_ID\" }"
	else
		echo "The ScanID or TICKET_ID was empty"
	fi
	cd ..
  else
	echo "Project has no url"
  fi
  
done

echo "===== Scan Runner Completed ====="

------------- 

###############################################
# Process StackHawk Projects
###############################################
cd /app/stackhawk-projects

echo "$STACKHAWK_PROJECTS" > hawk.json
jq -c '.[]' hawk.json | while read proj; do
  NAME=$(echo "$proj" | jq -r '.name')
  URL=$(echo "$proj" | jq -r '.url')

  echo "Processing StackHawk project: $NAME"

  # GitHub repo
  if [[ "$URL" != "null" && "$URL" != "" ]]; then
    echo "→ Cloning repo from $URL"
    git clone "https://$GITHUB_PAT@${URL#https://}"
    cd "$NAME"
    
    echo "→ Running hawk scan"
    set +e
    
    # --- CORRECCIÓN: EJECUCIÓN ÚNICA ---
    # Ejecutamos 1 sola vez y guardamos todo el texto de salida en una variable
    SCAN_OUTPUT=$(hawk scan --no-progress 2>&1)
    
    # Buscamos el ID dentro del texto guardado
    SCAN_ID=$(echo "$SCAN_OUTPUT" | grep -i "scan id" | awk '{print $NF}')
    set -e
    
    echo "Scan ID: $SCAN_ID"
    
    # --- LÓGICA ORIGINAL CONSERVADA ---
    # Solo entra aquí si existe un Scan ID Y el Ticket ID NO es 0
    if [[ -n "$SCAN_ID" && "$TICKET_ID" != 0 ]]; then
        echo "→ Notifying webhook (hawk scan)"
        curl -X POST "$WEBHOOK_URL/stackhawk-cloud-sec/$NAME" \
            -H "Content-Type: application/json" \
            --data "{ \"scan_id\": \"$SCAN_ID\", \"ticket_id\": \"$TICKET_ID\" }"
    else
        echo "Skipping webhook: ScanID was empty OR TicketID was 0. (ScanID: $SCAN_ID, TicketID: $TICKET_ID)"
        # Imprimimos el output si falló para poder depurar
        if [[ -z "$SCAN_ID" ]]; then
            echo "--- Hawk Scan Output ---"
            echo "$SCAN_OUTPUT"
        fi
    fi
    cd ..
  else
    echo "Project has no url"
  fi
  
done

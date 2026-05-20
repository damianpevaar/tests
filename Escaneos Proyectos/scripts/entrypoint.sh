set -e

echo "===== Starting Scan Runner ====="

if [[ -z "$SNYK_CLIENT_ID" ]]; then echo "ERROR: Missing SNYK_CLIENT_ID"; exit 1; fi
if [[ -z "$SNYK_CLIENT_SECRET" ]]; then echo "ERROR: Missing SNYK_CLIENT_SECRET"; exit 1; fi
if [[ -z "$STACKHAWK_API_KEY" ]]; then echo "ERROR: Missing STACKHAWK_API_KEY"; exit 1; fi
if [[ -z "$GITHUB_PAT" ]]; then echo "ERROR: Missing GITHUB_PAT"; exit 1; fi
if [[ -z "$WEBHOOK_URL" ]]; then echo "ERROR: Missing WEBHOOK_URL"; exit 1; fi

echo "→ Applying Git Force-HTTPS Interceptor..."
git config --global url."https://${GITHUB_PAT}@github.com/".insteadOf "ssh://git@github.com/"
git config --global url."https://${GITHUB_PAT}@github.com/".insteadOf "git@github.com:"
git config --global url."https://${GITHUB_PAT}@github.com/".insteadOf "git+ssh://git@github.com/"

export GIT_ASKPASS=/bin/echo
export GIT_TERMINAL_PROMPT=0

mkdir -p ~/.ssh && chmod 700 ~/.ssh
touch ~/.ssh/config
echo -e "Host github.com\n\tStrictHostKeyChecking no\n\tUserKnownHostsFile=/dev/null\n" > ~/.ssh/config

TIMESTAMP="${TIMESTAMP:-0}"
USER_EMAIL="${USER_EMAIL:-0}"
TICKET_ID="${TICKET_ID:-0}"
# NUEVO: GROUP_ID (Lectura de la variable de entorno)
GROUP_ID="${GROUP_ID:-0}"

echo "→ Config: Email [$USER_EMAIL] | Timestamp [$TIMESTAMP] | Ticket [$TICKET_ID] | Group ID [$GROUP_ID]"

echo "→ Authenticating Snyk CLI..."
snyk auth --auth-type=oauth --client-id="$SNYK_CLIENT_ID" --client-secret="$SNYK_CLIENT_SECRET"

echo "→ Authenticating StackHawk CLI..."
hawk init --api-key="$STACKHAWK_API_KEY" > /dev/null

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

    if [[ "$URL" != "null" && "$URL" != "" ]]; then
        set +e
        if [[ -n "$TARGET_BRANCH" && "$TARGET_BRANCH" != "null" ]]; then
            echo "→ Cloning branch [$TARGET_BRANCH] from $URL"
            git clone -b "$TARGET_BRANCH" --single-branch "https://$GITHUB_PAT@${URL#https://}" "$NAME" --quiet
        else
            echo "→ Cloning default branch from $URL"
            git clone "https://$GITHUB_PAT@${URL#https://}" "$NAME" --quiet
        fi
        CLONE_EXIT_CODE=$?
        set -e

        if [ $CLONE_EXIT_CODE -ne 0 ]; then
            echo "❌ ERROR: Failed to clone $NAME. Skipping."
            # NUEVO: GROUP_ID en error de clonado
            curl -s -X POST "$WEBHOOK_URL/snyk-scan/$NAME/$TICKET_ID" \
                 -H "Content-Type: application/json" \
                 -d "{\"status\": \"error\", \"error_type\": \"Git Clone Failed\", \"project\": \"$NAME\", \"timestamp\": \"$TIMESTAMP\", \"group_id\": \"$GROUP_ID\"}"
            continue
        fi

        cd "/app/snyk-projects/$NAME"
        
        if [[ "$ROUTE" != "" && "$ROUTE" != "null" ]]; then
            if [ -d "$ROUTE" ]; then
                echo "→ Changing to specified route: $ROUTE"
                cd "$ROUTE"
            else
                echo "❌ ERROR: Folder '$ROUTE' not found."
                # NUEVO: GROUP_ID en error de ruta
                curl -s -X POST "$WEBHOOK_URL/snyk-scan/$NAME/$TICKET_ID" \
                     -H "Content-Type: application/json" \
                     -d "{\"status\": \"error\", \"error_type\": \"Route Not Found\", \"project\": \"$NAME\", \"folder\": \"$ROUTE\", \"timestamp\": \"$TIMESTAMP\", \"group_id\": \"$GROUP_ID\"}"
                cd /app/snyk-projects && continue
            fi
        fi

        CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)

        # ---------------------------------------------------------
        # 1. ESCANEO DE INFRAESTRUCTURA (IaC)
        # ---------------------------------------------------------
        if [[ "$URL" =~ [iI][aA][cC] ]]; then
            echo "→ Running Snyk IaC test..."
            set +e
            snyk iac test . --json > "/app/snyk-output/snyk-iac-temp-$NAME.json"
            set -e
            
            # NUEVO: GROUP_ID inyectado vía JQ
            jq --arg branch "$CURRENT_BRANCH" --arg url "$URL" --arg route "$ROUTE" --arg name "$NAME" --arg ts "$TIMESTAMP" --arg email "$USER_EMAIL" --arg group "$GROUP_ID" \
            'if type == "array" then map(. + {git_branch: $branch, repo_url: $url, folder_route: $route, project_name: $name, scan_timestamp: $ts, user_email: $email, group_id: $group}) 
             else . + {git_branch: $branch, repo_url: $url, folder_route: $route, project_name: $name, scan_timestamp: $ts, user_email: $email, group_id: $group} end' \
            "/app/snyk-output/snyk-iac-temp-$NAME.json" > "/app/snyk-output/snyk-iac-test-$NAME.json"
            
            curl -s -X POST "$WEBHOOK_URL/snyk-iac/$NAME/$TICKET_ID" -H "Content-Type: application/json" --data-binary @/app/snyk-output/snyk-iac-test-$NAME.json | jq -r '.message // "IaC Sent"'
        
        else
            # ---------------------------------------------------------
            # 2. ESCANEO DE LIBRERÍAS (SCA)
            # ---------------------------------------------------------
            echo "→ Running Snyk SCA (Dependencies)..."

            if [ -f "uv.lock" ]; then
                echo "→ [SCA] uv.lock detected. Synchronizing environment..."
                sed -i "s|ssh://git@github.com/|https://${GITHUB_PAT}@github.com/|g" uv.lock pyproject.toml 2>/dev/null || true
                
                uv pip install --system --break-system-packages -r pyproject.toml 2>/dev/null || true
                
                UV_SYSTEM_PYTHON=1 uv export --format requirements-txt --no-dev --output-file snyk-requirements.txt
                set +e; snyk test --file=snyk-requirements.txt --package-manager=pip --skip-unresolved --json > "/app/snyk-output/snyk-test-temp-$NAME.json"; set -e

            elif [ -f "requirements.txt" ]; then
                uv pip install --system --break-system-packages -r requirements.txt 2>/dev/null || true
                
                set +e; snyk test --file=requirements.txt --package-manager=pip --skip-unresolved --json > "/app/snyk-output/snyk-test-temp-$NAME.json"; set -e
            else
                echo "→ [SCA] Generic scan..."
                
                if [ -f "pyproject.toml" ] || [ -f "setup.py" ] || [ -f "setup.cfg" ]; then
                    echo "→ [SCA] Resolving transitive dependencies..."
                    uv pip install --system --break-system-packages -e . 2>/dev/null || \
                    uv pip install --system --break-system-packages . 2>/dev/null || true
                fi

                set +e
                snyk test --all-projects --skip-unresolved --json \
                    > "/app/snyk-output/snyk-test-temp-$NAME.json"
                set -e
            fi

            # NUEVO: GROUP_ID inyectado vía JQ
            jq --arg branch "$CURRENT_BRANCH" --arg url "$URL" --arg route "$ROUTE" --arg name "$NAME" --arg ts "$TIMESTAMP" --arg email "$USER_EMAIL" --arg group "$GROUP_ID" \
            'if type == "array" then map(. + {git_branch: $branch, repo_url: $url, folder_route: $route, project_name: $name, scan_timestamp: $ts, user_email: $email, group_id: $group}) 
             else . + {git_branch: $branch, repo_url: $url, folder_route: $route, project_name: $name, scan_timestamp: $ts, user_email: $email, group_id: $group} end' \
            "/app/snyk-output/snyk-test-temp-$NAME.json" > "/app/snyk-output/snyk-test-$NAME.json"

            [ -s "/app/snyk-output/snyk-test-$NAME.json" ] && curl -s -X POST "$WEBHOOK_URL/snyk-scan/$NAME/$TICKET_ID" -H "Content-Type: application/json" --data-binary @/app/snyk-output/snyk-test-$NAME.json | jq -r '.message // "SCA Sent"'

            # -----------------------------------
            # 3. ESCANEO DE CÓDIGO FUENTE (SAST)
            # -----------------------------------
            echo "→ Running Snyk Code test (SAST)..."
            set +e
            snyk code test --json > "/app/snyk-output/snyk-code-temp-$NAME.json"
            set -e

            # NUEVO: GROUP_ID inyectado vía JQ
            jq --arg branch "$CURRENT_BRANCH" --arg url "$URL" --arg route "$ROUTE" --arg name "$NAME" --arg ts "$TIMESTAMP" --arg email "$USER_EMAIL" --arg group "$GROUP_ID" \
            'if type == "array" then map(. + {git_branch: $branch, repo_url: $url, folder_route: $route, project_name: $name, scan_timestamp: $ts, user_email: $email, group_id: $group}) 
             else . + {git_branch: $branch, repo_url: $url, folder_route: $route, project_name: $name, scan_timestamp: $ts, user_email: $email, group_id: $group} end' \
            "/app/snyk-output/snyk-code-temp-$NAME.json" > "/app/snyk-output/snyk-code-test-$NAME.json"

            [ -s "/app/snyk-output/snyk-code-test-$NAME.json" ] && curl -s -X POST "$WEBHOOK_URL/snyk-code/$NAME/$TICKET_ID" -H "Content-Type: application/json" --data-binary @/app/snyk-output/snyk-code-test-$NAME.json | jq -r '.message // "SAST Sent"'
        fi
        
        cd /app/snyk-projects
    else
        # ---------------------------------------------------------
        # 4. ESCANEO DE CONTENEDORES (DOCKER)
        # ---------------------------------------------------------
        echo "→ Docker image scan: $NAME"
        
        # 1. Autenticación en ECR con captura de errores
        if ! ECR_PASSWORD=$(aws ecr get-login-password --region us-east-1 2>/tmp/aws-err-$DOCKER_COUNT.log); then
            echo "❌ ERROR [AWS ECR]: Falló la obtención de credenciales para $NAME. Log:"
            cat /tmp/aws-err-$DOCKER_COUNT.log
            # NUEVO: GROUP_ID en error
            curl -s -X POST "$WEBHOOK_URL/snyk-container-scan/$TICKET_ID" \
                 -H "Content-Type: application/json" \
                 -d "{\"status\": \"error\", \"error_type\": \"AWS ECR Auth Failed\", \"project\": \"$NAME\", \"stage\": \"Docker Scan\", \"timestamp\": \"$TIMESTAMP\", \"group_id\": \"$GROUP_ID\"}"
            continue
        fi

        # 2. Escaneo del contenedor de Snyk con evaluación del exit code
        set +e
        snyk container test "${NAME#docker.io/}" --username=AWS --password="$ECR_PASSWORD" --json > "/app/docker-scan-$DOCKER_COUNT-temp.json" 2>/tmp/snyk-err-$DOCKER_COUNT.log
        SNYK_EXIT_CODE=$?
        set -e

        if [ $SNYK_EXIT_CODE -ge 2 ]; then
            echo "❌ ERROR [Snyk]: Falló el escaneo del contenedor $NAME. Exit code: $SNYK_EXIT_CODE. Log:"
            cat /tmp/snyk-err-$DOCKER_COUNT.log
            # NUEVO: GROUP_ID en error
            curl -s -X POST "$WEBHOOK_URL/snyk-container-scan/$TICKET_ID" \
                 -H "Content-Type: application/json" \
                 -d "{\"status\": \"error\", \"error_type\": \"Snyk Container Scan Failed\", \"project\": \"$NAME\", \"exit_code\": $SNYK_EXIT_CODE, \"stage\": \"Docker Scan\", \"timestamp\": \"$TIMESTAMP\", \"group_id\": \"$GROUP_ID\"}"
            continue
        fi

        # 3. Procesamiento del JSON con JQ
        # NUEVO: GROUP_ID inyectado en el JSON final de Docker
        if ! jq --arg image "$NAME" --arg ts "$TIMESTAMP" --arg email "$USER_EMAIL" --arg group "$GROUP_ID" '. + { scannedImage: $image, scan_timestamp: $ts, user_email: $email, status: "success", group_id: $group }' "/app/docker-scan-$DOCKER_COUNT-temp.json" > "/app/docker-scan-$DOCKER_COUNT.json" 2>/tmp/jq-err-$DOCKER_COUNT.log; then
            echo "❌ ERROR [JQ]: Falló la inyección de metadata en el JSON para $NAME. Log:"
            cat /tmp/jq-err-$DOCKER_COUNT.log
            # NUEVO: GROUP_ID en error
            curl -s -X POST "$WEBHOOK_URL/snyk-container-scan/$TICKET_ID" \
                 -H "Content-Type: application/json" \
                 -d "{\"status\": \"error\", \"error_type\": \"JSON Processing Failed\", \"project\": \"$NAME\", \"stage\": \"Docker Scan\", \"timestamp\": \"$TIMESTAMP\", \"group_id\": \"$GROUP_ID\"}"
            continue
        fi

        # 4. Envío de resultados finales (Webhook de éxito)
        if ! curl -s -f -X POST "$WEBHOOK_URL/snyk-container-scan/$TICKET_ID" -H "Content-Type: application/json" --data-binary @/app/docker-scan-$DOCKER_COUNT.json > /tmp/curl-out-$DOCKER_COUNT.log; then
            echo "❌ ERROR [Webhook]: Falló el envío del reporte a la API para $NAME."
            # NUEVO: GROUP_ID en error
            curl -s -X POST "$WEBHOOK_URL/snyk-container-scan/$TICKET_ID" \
                 -H "Content-Type: application/json" \
                 -d "{\"status\": \"error\", \"error_type\": \"Final Webhook Delivery Failed\", \"project\": \"$NAME\", \"stage\": \"Docker Scan\", \"timestamp\": \"$TIMESTAMP\", \"group_id\": \"$GROUP_ID\"}"
        else
            jq -r '.message // "Docker Sent"' /tmp/curl-out-$DOCKER_COUNT.log
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
    echo "Processing StackHawk project: $NAME"

    if [[ "$URL" != "null" && "$URL" != "" ]]; then
        # 1. Clonado del repositorio
        set +e
        if [[ -n "$TARGET_BRANCH" && "$TARGET_BRANCH" != "null" ]]; then
            echo "→ Cloning branch [$TARGET_BRANCH]..."
            git clone -b "$TARGET_BRANCH" --single-branch "https://$GITHUB_PAT@${URL#https://}" "$NAME" --quiet
        else
            echo "→ Cloning default branch..."
            git clone "https://$GITHUB_PAT@${URL#https://}" "$NAME" --quiet
        fi
        CLONE_EXIT_CODE=$?
        set -e

        if [ $CLONE_EXIT_CODE -ne 0 ]; then
            echo "❌ ERROR: Failed to clone $NAME. Skipping."
            continue
        fi

        # 2. Navegar al directorio del proyecto
        cd "/app/stackhawk-projects/$NAME"
        
        # 3. Entrar en la sub-ruta (ROUTE) si está definida
        if [[ "$ROUTE" != "" && "$ROUTE" != "null" ]]; then
            if [ -d "$ROUTE" ]; then
                echo "→ Changing to specified route: $ROUTE"
                cd "$ROUTE"
            else
                echo "⚠️ WARNING: Folder '$ROUTE' not found, staying in root."
            fi
        fi

        # 4. VERIFICACIÓN DE CONFIGURACIÓN (Busca cualquier archivo .yml)
        HAWK_FILE=$(ls *hawk.yml 2>/dev/null | head -n 1)

        if [ -z "$HAWK_FILE" ]; then
            echo "❌ ERROR: No hawk.yml file found in $(pwd). Skipping scan."
            cd /app/stackhawk-projects
            continue
        fi

        echo "✅ Detected StackHawk config file: $HAWK_FILE"

        # 5. Configuración de entorno para Hawk
        CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
        export SARIF_ARTIFACT=true

        # 6. Ejecución del Escaneo
        echo "→ Running hawk scan using $HAWK_FILE..."
        set +e
        hawk scan "$HAWK_FILE" --no-progress 2>&1 | tee /tmp/hawk_scan_live.log
        SCAN_OUTPUT=$(cat /tmp/hawk_scan_live.log)
        set -e
        
        # 7. Capturar Scan ID y enviar resultados (SARIF)
        SCAN_ID=$(echo "$SCAN_OUTPUT" | grep -i "scan id" | awk '{print $NF}')
        
        if [[ -n "$SCAN_ID" ]]; then
            if [ -f "stackhawk.sarif" ]; then
                echo "→ Sending SARIF results to webhook..."
                # NUEVO: GROUP_ID inyectado en el SARIF
                jq --arg branch "$CURRENT_BRANCH" --arg ticket "$TICKET_ID" --arg folder "$ROUTE" --arg ts "$TIMESTAMP" --arg email "$USER_EMAIL" --arg group "$GROUP_ID" \
                '. + {git_branch: $branch, ticket_id: $ticket, folder_route: $folder, scan_timestamp: $ts, user_email: $email, group_id: $group}' \
                stackhawk.sarif > payload_hawk.json
                
                curl -s -X POST "$WEBHOOK_URL/stackhawk-cloud/$NAME" \
                     -H "Content-Type: application/json" \
                     --data-binary @payload_hawk.json | jq -r '.message // "Hawk Results Sent"'
            else
                echo "⚠️ WARNING: stackhawk.sarif not found. Skipping webhook."
            fi
        else
            echo "❌ ERROR: Hawk scan failed. Check logs above."
        fi
    fi
    
    cd /app/stackhawk-projects
done

echo "===== Scan Runner Completed ====="
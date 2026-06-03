#!/bin/bash
# entrypoint.sh — Scan Runner (Semgrep SAST + Nuclei DAST + Trivy SCA/IaC).
set -e
set -o pipefail

echo "===== Starting Scan Runner ====="

# -----------------------------------------------------------------------------
# 1. Validación de variables obligatorias
# -----------------------------------------------------------------------------
if [[ -z "$GITHUB_PAT"   ]]; then echo "ERROR: Missing GITHUB_PAT";   exit 1; fi
if [[ -z "$WEBHOOK_URL"  ]]; then echo "ERROR: Missing WEBHOOK_URL";  exit 1; fi
if [[ -z "$FP_FINDINGS"  ]]; then echo "ERROR: Missing FP_FINDINGS";  exit 1; fi

# Opcionales / con default
TICKET_ID="${TICKET_ID:-0}"
GROUP_ID="${GROUP_ID:-0}"
USER_EMAIL="${USER_EMAIL:-0}"
TIMESTAMP="${TIMESTAMP:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
ALLOW_PROD_TARGETS="${ALLOW_PROD_TARGETS:-false}"
# Metadata adicional (echo en cada callback para que Workflow 3 actúe)
SPREADSHEET_ID="${SPREADSHEET_ID:-}"
SHEET_GID="${SHEET_GID:-}"
FP_COMMENT_ID="${FP_COMMENT_ID:-}"
FP_AUTHOR="${FP_AUTHOR:-}"

echo "→ Config: Ticket [$TICKET_ID] | Group [$GROUP_ID] | Email [$USER_EMAIL] | TS [$TIMESTAMP]"

# -----------------------------------------------------------------------------
# 2. Git interceptors (igual al runner de Snyk/StackHawk)
# -----------------------------------------------------------------------------
echo "→ Applying Git Force-HTTPS Interceptor for GitHub..."
git config --global url."https://${GITHUB_PAT}@github.com/".insteadOf "ssh://git@github.com/"
git config --global url."https://${GITHUB_PAT}@github.com/".insteadOf "git@github.com:"
git config --global url."https://${GITHUB_PAT}@github.com/".insteadOf "git+ssh://git@github.com/"

if [[ -n "$BITBUCKET_TOKEN" && -n "$BITBUCKET_USERNAME" ]]; then
    echo "→ Applying Git Force-HTTPS Interceptor for Bitbucket..."
    git config --global url."https://${BITBUCKET_USERNAME}:${BITBUCKET_TOKEN}@bitbucket.org/".insteadOf "ssh://git@bitbucket.org/"
    git config --global url."https://${BITBUCKET_USERNAME}:${BITBUCKET_TOKEN}@bitbucket.org/".insteadOf "git@bitbucket.org:"
else
    echo "⚠️ Bitbucket interceptor skipped (no BITBUCKET_TOKEN)."
fi

export GIT_ASKPASS=/bin/echo
export GIT_TERMINAL_PROMPT=0

mkdir -p ~/.ssh && chmod 700 ~/.ssh
{ echo -e "Host github.com\n\tStrictHostKeyChecking no\n\tUserKnownHostsFile=/dev/null";
  echo -e "Host bitbucket.org\n\tStrictHostKeyChecking no\n\tUserKnownHostsFile=/dev/null"; } > ~/.ssh/config

# -----------------------------------------------------------------------------
# 3. Helpers
# -----------------------------------------------------------------------------
normalize_repo_url() {
    local RAW_URL=$1
    local COMMIT=""
    if [[ "$RAW_URL" =~ ^(https://(bitbucket\.org|github\.com)/[^/]+/[^/]+)/commits?/([0-9a-fA-F]+) ]]; then
        RAW_URL="${BASH_REMATCH[1]}"
        COMMIT="${BASH_REMATCH[3]}"
    fi
    RAW_URL="${RAW_URL%%\?*}"; RAW_URL="${RAW_URL%%#*}"; RAW_URL="${RAW_URL%/}"
    [[ "$RAW_URL" != *.git ]] && RAW_URL="${RAW_URL}.git"
    echo "$RAW_URL"
    echo "$COMMIT"
}

get_clone_url() {
    local RAW_URL=$1
    if [[ "$RAW_URL" == *"bitbucket.org"* ]]; then
        echo "https://${BITBUCKET_USERNAME}:${BITBUCKET_TOKEN}@${RAW_URL#https://}"
    else
        echo "https://${GITHUB_PAT}@${RAW_URL#https://}"
    fi
}

is_prod_target() {
    local url="$1"
    [[ "$ALLOW_PROD_TARGETS" == "true" ]] && return 1
    echo "$url" | grep -qE "(^|//|\.)(prod|production)\." && return 0
    echo "$url" | grep -qE "api\.simetrik[^-]" && return 0
    return 1
}

post_webhook() {
    local scanner_type="$1"
    local payload_file="$2"
    local url="$WEBHOOK_URL"
    # Inyectar metadata para Workflow 3 (sheet, jira comment, autor)
    local enriched="${payload_file%.json}-with-meta.json"
    jq --arg sid "$SPREADSHEET_ID" --arg gid "$SHEET_GID" \
       --arg cid "$FP_COMMENT_ID"  --arg auth "$FP_AUTHOR" \
       '. + {spreadsheet_id:$sid, sheet_gid:$gid, fp_comment_id:$cid, fp_author:$auth}' \
       "$payload_file" > "$enriched"
    echo "→ POST $url  (scanner=$scanner_type, ticket=$TICKET_ID)"
    curl -s -X POST "$url" \
         -H "Content-Type: application/json" \
         -H "X-Scanner: $scanner_type" \
         -H "X-Ticket-Id: $TICKET_ID" \
         --data-binary @"$enriched"
    echo ""
}

# Marca un finding como INCONCLUSIVE — el scanner no ejecutó/coverage gap/error.
# Esto evita que el agente downstream lo interprete como FP confirmado.
emit_inconclusive() {
    local scanner_type="$1"
    local finding_id="$2"
    local reason="$3"          # ej: "no_lockfile", "scanner_error", "target_unreachable"
    local detail="$4"          # texto humano
    local payload="/app/output/${scanner_type}-${finding_id}-inconclusive.json"
    jq -n --arg s "$scanner_type" --arg tk "$TICKET_ID" --arg fid "$finding_id" \
          --arg ts "$TIMESTAMP" --arg em "$USER_EMAIL" --arg g "$GROUP_ID" \
          --arg reason "$reason" --arg detail "$detail" \
          '{scanner:$s, ticket_id:$tk, finding_id:$fid,
            scan_timestamp:$ts, user_email:$em, group_id:$g,
            scan_status:"error",
            signal: {
              strength:"inconclusive",
              hits_total:0,
              scanner_error:true,
              error_reason:$reason,
              error_detail:$detail,
              evidence:[]
            }}' > "$payload"
    post_webhook "$scanner_type" "$payload"
}

post_error() {
    local scanner_type="$1"
    local error_type="$2"
    local finding_id="$3"
    local project="$4"
    local url="$WEBHOOK_URL"
    jq -n --arg s "$scanner_type" --arg tk "$TICKET_ID" --arg t "$error_type" \
          --arg fid "$finding_id" --arg p "$project" --arg ts "$TIMESTAMP" \
          --arg g "$GROUP_ID" --arg e "$USER_EMAIL" \
          '{status:"error", scanner:$s, ticket_id:$tk, error_type:$t,
            finding_id:$fid, project:$p, timestamp:$ts,
            group_id:$g, user_email:$e}' \
    | curl -s -X POST "$url" \
        -H "Content-Type: application/json" \
        -H "X-Scanner: $scanner_type" \
        -H "X-Ticket-Id: $TICKET_ID" \
        -d @-
    echo ""
}

# -----------------------------------------------------------------------------
# 4. Procesar findings
# -----------------------------------------------------------------------------
cd /app
# Tolerar comillas simples como en el runner de Snyk
echo "$FP_FINDINGS" | sed "s/'/\"/g" > findings.json

TOTAL=$(jq 'length' findings.json 2>/dev/null || echo 0)
echo "→ Findings recibidos: $TOTAL"

jq -c '.[]' findings.json | while read -r finding; do
    FINDING_ID=$(echo "$finding" | jq -r '.finding_id // empty')
    SCANNER=$(   echo "$finding" | jq -r '.scanner    // empty')
    RULE_ID=$(   echo "$finding" | jq -r '.rule_id    // .cve_cwe // empty')
    URL=$(       echo "$finding" | jq -r '.repo_url   // empty')
    TARGET_BRANCH=$(echo "$finding" | jq -r '.branch  // empty')
    TARGET_COMMIT=$( echo "$finding" | jq -r '.commit // empty')
    ROUTE=$(     echo "$finding" | jq -r '.route      // empty')
    TARGET_URL=$(echo "$finding" | jq -r '.target_url // empty')
    # Nuevos campos para filtrado y SCA
    AFFECTED_FILE=$(echo "$finding" | jq -r '.affected_file // empty')
    CWE=$(          echo "$finding" | jq -r '.cwe          // empty')   # ej: "CWE-79"
    PACKAGE=$(      echo "$finding" | jq -r '.package      // empty')
    FIXED_VERSION=$(echo "$finding" | jq -r '.fixed_version // empty')
    VULN_ID=$(      echo "$finding" | jq -r '.vuln_id      // empty')   # CVE-XXX o GHSA-XXX
    # Nuclei: filtros opcionales
    SEVERITY=$(echo "$finding" | jq -r '.severity // empty')           # ej: "low,medium,high,critical"
    TAGS=$(    echo "$finding" | jq -r '.tags     // empty')           # ej: "csp,misconfig"
    KEYWORD_MATCH=$(echo "$finding" | jq -r '.keyword_match // empty') # ej: "csp,wildcard"

    echo "------------------------------------------------"
    echo "Processing [$SCANNER] finding_id=$FINDING_ID rule=$RULE_ID"

    case "$SCANNER" in
    # =========================================================================
    # SEMGREP (SAST)
    # =========================================================================
    semgrep|semgrep_sast)
        if [[ -z "$URL" || "$URL" == "null" ]]; then
            echo "❌ Missing repo_url"
            post_error "semgrep" "Missing repo_url" "$FINDING_ID" ""
            continue
        fi

        NORM=$(normalize_repo_url "$URL")
        URL=$(echo "$NORM" | sed -n '1p')
        URL_COMMIT=$(echo "$NORM" | sed -n '2p')
        [[ -z "$TARGET_COMMIT" && -n "$URL_COMMIT" ]] && TARGET_COMMIT="$URL_COMMIT"

        NAME=$(basename "$URL" .git)
        CLONE_URL=$(get_clone_url "$URL")
        WORKDIR="/app/projects/${FINDING_ID}-${NAME}"
        rm -rf "$WORKDIR"

        set +e
        if [[ -n "$TARGET_BRANCH" && "$TARGET_BRANCH" != "null" ]]; then
            echo "→ Cloning branch [$TARGET_BRANCH]"
            git clone -b "$TARGET_BRANCH" --single-branch "$CLONE_URL" "$WORKDIR" --quiet
        elif [[ -n "$TARGET_COMMIT" ]]; then
            echo "→ Cloning full history (will checkout $TARGET_COMMIT)"
            git clone "$CLONE_URL" "$WORKDIR" --quiet
        else
            echo "→ Cloning default branch"
            git clone --depth 1 "$CLONE_URL" "$WORKDIR" --quiet
        fi
        CLONE_EXIT=$?
        set -e
        if [ $CLONE_EXIT -ne 0 ]; then
            echo "❌ Git clone failed for $URL"
            post_error "semgrep" "Git Clone Failed" "$FINDING_ID" "$NAME"
            continue
        fi

        cd "$WORKDIR"
        if [[ -n "$TARGET_COMMIT" ]]; then
            set +e; git checkout --quiet "$TARGET_COMMIT"; CHK=$?; set -e
            if [ $CHK -ne 0 ]; then
                post_error "semgrep" "Git Checkout Failed" "$FINDING_ID" "$NAME"
                cd /app; continue
            fi
        fi
        if [[ -n "$ROUTE" && "$ROUTE" != "null" && -d "$ROUTE" ]]; then
            cd "$ROUTE"
        fi

        CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
        [[ "$CURRENT_BRANCH" == "HEAD" && -n "$TARGET_COMMIT" ]] && CURRENT_BRANCH="$TARGET_COMMIT"

        RESULT="/app/output/semgrep-${FINDING_ID}.json"
        SEMGREP_ERR="/app/output/semgrep-${FINDING_ID}.err"
        echo "→ Running Semgrep (multi-config)..."
        SEMGREP_CONFIGS=(
            --config "p/security-audit"
            --config "p/owasp-top-ten"
            --config "p/secrets"
            --config "p/python"
            --config "p/javascript"
            --config "p/typescript"
            --config "p/default"
        )
        set +e
        semgrep "${SEMGREP_CONFIGS[@]}" \
            --timeout 60 --timeout-threshold 5 \
            --json -o "$RESULT" . 2> "$SEMGREP_ERR"
        SEMGREP_EXIT=$?
        set -e

        if [[ $SEMGREP_EXIT -ne 0 ]]; then
            echo "❌ Semgrep exit=$SEMGREP_EXIT"
            emit_inconclusive "semgrep" "$FINDING_ID" "scanner_error" \
              "Semgrep exit=$SEMGREP_EXIT. Stderr: $(head -c 300 "$SEMGREP_ERR" | tr '\n' ' ')"
            cd /app; continue
        fi
        if [[ ! -s "$RESULT" ]] || ! jq -e . "$RESULT" >/dev/null 2>&1; then
            echo "❌ Semgrep output missing/invalid"
            emit_inconclusive "semgrep" "$FINDING_ID" "scanner_error" "Semgrep produced no parseable output."
            cd /app; continue
        fi

        # Verificar que algo se escaneó realmente
        PATHS_SCANNED=$(jq '.paths.scanned | length // 0' "$RESULT" 2>/dev/null || echo 0)
        SEMGREP_ERRS=$(jq '.errors | length // 0' "$RESULT" 2>/dev/null || echo 0)
        if [[ "$PATHS_SCANNED" -eq 0 ]]; then
            echo "⚠️  Semgrep scanned 0 files"
            emit_inconclusive "semgrep" "$FINDING_ID" "no_coverage" \
              "Semgrep scanned 0 files in repo. Possibly empty clone or excluded paths."
            cd /app; continue
        fi
        echo "→ Semgrep scanned $PATHS_SCANNED files (errors in run: $SEMGREP_ERRS)"

        # ---- Cálculo de señales (filtrado por archivo + CWE) ----
        HITS_TOTAL=$(jq '.results | length // 0' "$RESULT")

        if [[ -n "$AFFECTED_FILE" ]]; then
            HITS_IN_FILE=$(jq --arg f "$AFFECTED_FILE" \
                '[.results[] | select(.path == $f or (.path | endswith($f)))] | length' "$RESULT")
        else
            HITS_IN_FILE="null"
        fi

        if [[ -n "$CWE" ]]; then
            HITS_SAME_CWE=$(jq --arg c "$CWE" \
                '[.results[] | select(.extra.metadata.cwe // [] | tostring | test($c))] | length' "$RESULT")
        else
            HITS_SAME_CWE="null"
        fi

        if [[ -n "$AFFECTED_FILE" && -n "$CWE" ]]; then
            HITS_MATCH_BOTH=$(jq --arg f "$AFFECTED_FILE" --arg c "$CWE" \
                '[.results[]
                  | select((.path == $f or (.path | endswith($f)))
                           and ((.extra.metadata.cwe // []) | tostring | test($c)))]
                 | length' "$RESULT")
        else
            HITS_MATCH_BOTH="null"
        fi

        # Top 5 hits relevantes (en archivo afectado, o top 5 generales)
        if [[ -n "$AFFECTED_FILE" ]]; then
            EVIDENCE=$(jq --arg f "$AFFECTED_FILE" \
                '[.results[] | select(.path == $f or (.path | endswith($f)))
                  | {rule_id: .check_id, path: .path, line: .start.line,
                     severity: .extra.severity, message: .extra.message,
                     cwe: .extra.metadata.cwe}] | .[0:5]' "$RESULT")
        else
            EVIDENCE=$(jq '[.results[] | {rule_id: .check_id, path: .path, line: .start.line,
                                          severity: .extra.severity, message: .extra.message,
                                          cwe: .extra.metadata.cwe}] | .[0:5]' "$RESULT")
        fi

        # ---- Lógica de signal_strength ESTRICTA ----
        # Premisa: Semgrep OSS no tiene paridad con Snyk Code.
        # Ausencia de hits != FP. Solo APPROVE con evidencia positiva (paquete absent en Trivy
        # o endpoint clean en Nuclei). Semgrep solo puede contribuir REJECT o MANUAL_REVIEW.
        SIGNAL="inconclusive"
        # Verificar que el archivo afectado fue realmente escaneado (sino coverage gap real)
        FILE_WAS_SCANNED="false"
        if [[ -n "$AFFECTED_FILE" ]]; then
            if jq -e --arg f "$AFFECTED_FILE" '.paths.scanned[] | select(. == $f or endswith($f))' "$RESULT" >/dev/null 2>&1; then
                FILE_WAS_SCANNED="true"
            fi
        fi

        if [[ -n "$AFFECTED_FILE" && -n "$CWE" ]]; then
            if [[ "$HITS_MATCH_BOTH" -gt 0 ]]; then
                SIGNAL="strong_positive"
            elif [[ "$HITS_IN_FILE" -gt 0 ]]; then
                SIGNAL="weak_positive"
            elif [[ "$FILE_WAS_SCANNED" == "false" ]]; then
                # Semgrep nunca tocó el archivo → no podemos opinar
                SIGNAL="inconclusive"
            else
                # Archivo SÍ escaneado, no encontró ese CWE — coverage gap (OSS no tiene paridad Snyk Code)
                SIGNAL="weak_negative"
            fi
        elif [[ -n "$AFFECTED_FILE" ]]; then
            if [[ "$HITS_IN_FILE" -gt 0 ]]; then
                SIGNAL="weak_positive"
            elif [[ "$FILE_WAS_SCANNED" == "false" ]]; then
                SIGNAL="inconclusive"
            else
                SIGNAL="weak_negative"
            fi
        else
            # Sin archivo afectado, no podemos filtrar — datos insuficientes
            SIGNAL="inconclusive"
        fi

        echo "→ Semgrep signal=$SIGNAL  total=$HITS_TOTAL  in_file=$HITS_IN_FILE  same_cwe=$HITS_SAME_CWE  both=$HITS_MATCH_BOTH"

        ENRICHED="/app/output/semgrep-${FINDING_ID}-final.json"
        jq -n --arg branch "$CURRENT_BRANCH" --arg url "$URL" --arg route "$ROUTE" \
              --arg name "$NAME" --arg ts "$TIMESTAMP" --arg email "$USER_EMAIL" \
              --arg group "$GROUP_ID" --arg fid "$FINDING_ID" --arg rule "$RULE_ID" \
              --arg tk "$TICKET_ID" --arg affected "$AFFECTED_FILE" --arg cwe "$CWE" \
              --arg signal "$SIGNAL" \
              --argjson hits_total "$HITS_TOTAL" \
              --argjson hits_in_file "${HITS_IN_FILE:-null}" \
              --argjson hits_same_cwe "${HITS_SAME_CWE:-null}" \
              --argjson hits_match_both "${HITS_MATCH_BOTH:-null}" \
              --argjson evidence "$EVIDENCE" \
              --arg file_scanned "$FILE_WAS_SCANNED" \
              --argjson paths_scanned "$PATHS_SCANNED" \
              '{scanner:"semgrep", ticket_id:$tk, finding_id:$fid, rule_id:$rule,
                affected_file:$affected, cwe:$cwe,
                git_branch:$branch, repo_url:$url, folder_route:$route, project_name:$name,
                scan_timestamp:$ts, user_email:$email, group_id:$group,
                scan_status:"ok",
                signal: {
                    strength: $signal,
                    paths_scanned: $paths_scanned,
                    affected_file_was_scanned: ($file_scanned == "true"),
                    hits_total: $hits_total,
                    hits_in_affected_file: $hits_in_file,
                    hits_in_same_cwe: $hits_same_cwe,
                    hits_matching_both: $hits_match_both,
                    scanner_coverage: "OSS-limited",
                    evidence: $evidence
                }}' > "$ENRICHED"

        post_webhook "semgrep" "$ENRICHED"
        cd /app
        ;;

    # =========================================================================
    # TRIVY (SCA / dependencias)
    # =========================================================================
    trivy|sca)
        if [[ -z "$URL" || "$URL" == "null" ]]; then
            echo "❌ Missing repo_url"
            post_error "trivy" "Missing repo_url" "$FINDING_ID" ""
            continue
        fi

        NORM=$(normalize_repo_url "$URL")
        URL=$(echo "$NORM" | sed -n '1p')
        URL_COMMIT=$(echo "$NORM" | sed -n '2p')
        [[ -z "$TARGET_COMMIT" && -n "$URL_COMMIT" ]] && TARGET_COMMIT="$URL_COMMIT"

        NAME=$(basename "$URL" .git)
        CLONE_URL=$(get_clone_url "$URL")
        WORKDIR="/app/projects/${FINDING_ID}-${NAME}"
        rm -rf "$WORKDIR"

        set +e
        if [[ -n "$TARGET_BRANCH" && "$TARGET_BRANCH" != "null" ]]; then
            git clone -b "$TARGET_BRANCH" --single-branch "$CLONE_URL" "$WORKDIR" --quiet
        elif [[ -n "$TARGET_COMMIT" ]]; then
            git clone "$CLONE_URL" "$WORKDIR" --quiet
        else
            git clone --depth 1 "$CLONE_URL" "$WORKDIR" --quiet
        fi
        CLONE_EXIT=$?
        set -e
        if [ $CLONE_EXIT -ne 0 ]; then
            post_error "trivy" "Git Clone Failed" "$FINDING_ID" "$NAME"
            continue
        fi

        cd "$WORKDIR"
        if [[ -n "$TARGET_COMMIT" ]]; then
            set +e; git checkout --quiet "$TARGET_COMMIT"; CHK=$?; set -e
            [ $CHK -ne 0 ] && { post_error "trivy" "Git Checkout Failed" "$FINDING_ID" "$NAME"; cd /app; continue; }
        fi
        if [[ -n "$ROUTE" && "$ROUTE" != "null" && -d "$ROUTE" ]]; then
            cd "$ROUTE"
        fi

        CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
        [[ "$CURRENT_BRANCH" == "HEAD" && -n "$TARGET_COMMIT" ]] && CURRENT_BRANCH="$TARGET_COMMIT"

        RESULT="/app/output/trivy-${FINDING_ID}.json"
        TRIVY_ERR="/app/output/trivy-${FINDING_ID}.err"
        cd "$WORKDIR"  # asegúrate de escanear desde root del repo, no desde ROUTE

        # --- Manifest detection: si no hay lockfile/manifest reconocido → inconclusive
        MANIFEST_COUNT=$(find . -maxdepth 5 \( \
            -name package-lock.json -o -name yarn.lock -o -name pnpm-lock.yaml \
            -o -name requirements.txt -o -name Pipfile.lock -o -name poetry.lock \
            -o -name uv.lock -o -name go.sum -o -name Gemfile.lock \
            -o -name pom.xml -o -name build.gradle -o -name Cargo.lock \
        \) -not -path '*/node_modules/*' 2>/dev/null | wc -l)

        if [[ "$MANIFEST_COUNT" -eq 0 ]]; then
            echo "⚠️  Trivy: no dependency manifest found in repo → inconclusive"
            emit_inconclusive "trivy" "$FINDING_ID" "no_lockfile" \
              "Repo does not contain any recognized lockfile/manifest; Trivy cannot verify SCA findings."
            cd /app; continue
        fi
        echo "→ Trivy: $MANIFEST_COUNT manifest(s) found"

        echo "→ Running Trivy fs scan (list-all-pkgs + DB up-to-date)..."
        set +e
        trivy fs --quiet --scanners vuln --list-all-pkgs --format json \
            --output "$RESULT" . 2> "$TRIVY_ERR"
        TRIVY_EXIT=$?
        set -e

        if [[ $TRIVY_EXIT -ne 0 ]]; then
            echo "❌ Trivy failed with exit=$TRIVY_EXIT"
            emit_inconclusive "trivy" "$FINDING_ID" "scanner_error" \
              "Trivy exit=$TRIVY_EXIT. Stderr: $(head -c 300 "$TRIVY_ERR" | tr '\n' ' ')"
            cd /app; continue
        fi
        if [[ ! -s "$RESULT" ]] || ! jq -e . "$RESULT" >/dev/null 2>&1; then
            echo "❌ Trivy output missing or invalid"
            emit_inconclusive "trivy" "$FINDING_ID" "scanner_error" \
              "Trivy produced no parseable output."
            cd /app; continue
        fi

        # Validar que algo se parseó (Results no vacío)
        PARSED_TARGETS=$(jq '[.Results[]?] | length' "$RESULT" 2>/dev/null || echo 0)
        if [[ "$PARSED_TARGETS" -eq 0 ]]; then
            echo "⚠️  Trivy parsed 0 targets (lockfile present but unreadable?)"
            emit_inconclusive "trivy" "$FINDING_ID" "no_coverage" \
              "Trivy parsed 0 targets despite manifests being present. Ecosystem may be unsupported."
            cd /app; continue
        fi

        # ---- Cálculo de señales (filtrado por package + vuln_id) ----
        TOTAL_VULNS=$(jq '[.Results[]?.Vulnerabilities[]?] | length' "$RESULT" 2>/dev/null || echo 0)

        # ¿Aparece el paquete vulnerable?
        if [[ -n "$PACKAGE" ]]; then
            PKG_MATCHES=$(jq --arg p "$PACKAGE" \
                '[.Results[]?.Vulnerabilities[]? | select(.PkgName | ascii_downcase == ($p | ascii_downcase))]' "$RESULT")
            PKG_FOUND=$(echo "$PKG_MATCHES" | jq 'length')
            INSTALLED_VER=$(echo "$PKG_MATCHES" | jq -r '.[0].InstalledVersion // ""')
        else
            PKG_MATCHES="[]"
            PKG_FOUND=0
            INSTALLED_VER=""
        fi

        # ¿Aparece el CVE/Vuln ID específico?
        if [[ -n "$VULN_ID" ]]; then
            VULN_MATCHES=$(jq --arg v "$VULN_ID" \
                '[.Results[]?.Vulnerabilities[]? | select(.VulnerabilityID == $v)]' "$RESULT")
            VULN_FOUND=$(echo "$VULN_MATCHES" | jq 'length')
        else
            VULN_MATCHES="[]"
            VULN_FOUND=0
        fi

        # ---- Verificación de presencia del paquete (independiente de vulns conocidas) ----
        # Con --list-all-pkgs, .Results[].Packages contiene todos los paquetes instalados.
        PKG_INSTALLED="false"
        INSTALLED_VER_ALL=""
        if [[ -n "$PACKAGE" ]]; then
            PKG_LOOKUP=$(jq --arg p "$PACKAGE" \
                '[.Results[]?.Packages[]? | select(.Name | ascii_downcase == ($p | ascii_downcase))]' "$RESULT")
            PKG_LOOKUP_COUNT=$(echo "$PKG_LOOKUP" | jq 'length')
            if [[ "$PKG_LOOKUP_COUNT" -gt 0 ]]; then
                PKG_INSTALLED="true"
                INSTALLED_VER_ALL=$(echo "$PKG_LOOKUP" | jq -r '.[0].Version // ""')
                [[ -z "$INSTALLED_VER" ]] && INSTALLED_VER="$INSTALLED_VER_ALL"
            fi
        fi

        # ---- Lógica de signal_strength ESTRICTA ----
        # APPROVE_FP solo con evidencia POSITIVA. Ausencia ≠ evidencia.
        SIGNAL="inconclusive"
        if [[ -n "$VULN_ID" && "$VULN_FOUND" -gt 0 ]]; then
            SIGNAL="strong_positive"      # CVE específico confirmado en lockfile
        elif [[ -n "$PACKAGE" && "$PKG_FOUND" -gt 0 ]]; then
            SIGNAL="weak_positive"         # paquete vulnerable presente, otro CVE
        elif [[ -n "$PACKAGE" && "$PKG_INSTALLED" == "true" && "$VULN_FOUND" -eq 0 ]]; then
            # Paquete SÍ instalado (vía --list-all-pkgs) pero ningún CVE asociado por Trivy.
            # Causas posibles: (a) version ya fijada, (b) CVE no en Trivy DB todavía.
            SIGNAL="weak_negative"         # No es strong: la DB de Trivy puede estar atrasada
        elif [[ -n "$PACKAGE" && "$PKG_INSTALLED" == "false" ]]; then
            # Paquete realmente no aparece en ningún manifest del repo → FP fuerte
            SIGNAL="strong_negative"
        elif [[ -z "$PACKAGE" && -z "$VULN_ID" ]]; then
            # Sin criterio de búsqueda + repo escaneado OK → señal débil
            [[ "$TOTAL_VULNS" -gt 0 ]] && SIGNAL="weak_positive" || SIGNAL="inconclusive"
        else
            SIGNAL="inconclusive"
        fi

        EVIDENCE=$(echo "$VULN_MATCHES" | jq '[.[] | {id: .VulnerabilityID, pkg: .PkgName, installed: .InstalledVersion, fixed: .FixedVersion, severity: .Severity, title: .Title}] | .[0:5]')
        if [[ "$VULN_FOUND" -eq 0 ]]; then
            EVIDENCE=$(echo "$PKG_MATCHES" | jq '[.[] | {id: .VulnerabilityID, pkg: .PkgName, installed: .InstalledVersion, fixed: .FixedVersion, severity: .Severity, title: .Title}] | .[0:5]')
        fi

        echo "→ Trivy signal=$SIGNAL  total=$TOTAL_VULNS  pkg_hits=$PKG_FOUND  vuln_hits=$VULN_FOUND  installed=$INSTALLED_VER"

        ENRICHED="/app/output/trivy-${FINDING_ID}-final.json"
        jq -n --arg branch "$CURRENT_BRANCH" --arg url "$URL" --arg name "$NAME" \
              --arg ts "$TIMESTAMP" --arg email "$USER_EMAIL" --arg group "$GROUP_ID" \
              --arg fid "$FINDING_ID" --arg tk "$TICKET_ID" \
              --arg pkg "$PACKAGE" --arg vuln "$VULN_ID" --arg fixed "$FIXED_VERSION" \
              --arg installed "$INSTALLED_VER" --arg signal "$SIGNAL" \
              --arg pkg_installed "$PKG_INSTALLED" \
              --argjson manifests "$MANIFEST_COUNT" \
              --argjson parsed_targets "$PARSED_TARGETS" \
              --argjson total_vulns "$TOTAL_VULNS" --argjson pkg_found "$PKG_FOUND" \
              --argjson vuln_found "$VULN_FOUND" --argjson evidence "$EVIDENCE" \
              '{scanner:"trivy", ticket_id:$tk, finding_id:$fid,
                package:$pkg, vuln_id:$vuln, fixed_version:$fixed,
                git_branch:$branch, repo_url:$url, project_name:$name,
                scan_timestamp:$ts, user_email:$email, group_id:$group,
                scan_status:"ok",
                signal: {
                    strength: $signal,
                    manifests_found: $manifests,
                    parsed_targets: $parsed_targets,
                    total_vulns_in_repo: $total_vulns,
                    package_hits: $pkg_found,
                    package_installed_in_repo: ($pkg_installed == "true"),
                    vuln_id_hits: $vuln_found,
                    installed_version: $installed,
                    evidence: $evidence
                }}' > "$ENRICHED"

        post_webhook "trivy" "$ENRICHED"
        cd /app
        ;;

    # =========================================================================
    # NUCLEI (DAST)
    # =========================================================================
    nuclei|nuclei_dast)
        if [[ -z "$TARGET_URL" || "$TARGET_URL" == "null" ]]; then
            echo "❌ Missing target_url"
            post_error "nuclei" "Missing target_url" "$FINDING_ID" ""
            continue
        fi
        if is_prod_target "$TARGET_URL"; then
            echo "❌ Blocked: production target $TARGET_URL"
            post_error "nuclei" "Production Target Blocked" "$FINDING_ID" "$TARGET_URL"
            continue
        fi

        RESULT="/app/output/nuclei-${FINDING_ID}.jsonl"
        NUCLEI_ERR="/app/output/nuclei-${FINDING_ID}.err"

        # --- Precheck: el endpoint responde ---
        echo "→ Probing $TARGET_URL ..."
        HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 "$TARGET_URL" 2>/dev/null || echo "000")
        if [[ "$HTTP_CODE" == "000" ]]; then
            echo "❌ Target unreachable (no response from $TARGET_URL)"
            emit_inconclusive "nuclei" "$FINDING_ID" "target_unreachable" \
              "Nuclei not run: target $TARGET_URL did not respond (DNS/connect failure)."
            continue
        fi
        echo "  target responded HTTP $HTTP_CODE"

        # --- Construir args ---
        # Default severity AMPLIO (incluye info,low) — issues como CSP / security headers son severidad info en Nuclei.
        echo "→ Running Nuclei against $TARGET_URL"
        NUCLEI_ARGS=(-u "$TARGET_URL" -jsonl -silent -stats-json -o "$RESULT")
        if [[ -n "$RULE_ID" ]]; then
            NUCLEI_ARGS+=(-id "$RULE_ID")
            echo "  filter: template id=$RULE_ID"
        elif [[ -n "$TAGS" ]]; then
            NUCLEI_ARGS+=(-tags "$TAGS")
            [[ -n "$SEVERITY" ]] && NUCLEI_ARGS+=(-severity "$SEVERITY")
            echo "  filter: tags=$TAGS severity=${SEVERITY:-any}"
        elif [[ -n "$SEVERITY" ]]; then
            NUCLEI_ARGS+=(-severity "$SEVERITY")
            echo "  filter: severity=$SEVERITY"
        else
            NUCLEI_ARGS+=(-severity "info,low,medium,high,critical")
            echo "  filter: severity=info,low,medium,high,critical (broad default)"
        fi
        set +e
        nuclei "${NUCLEI_ARGS[@]}" 2> "$NUCLEI_ERR"
        NUCLEI_EXIT=$?
        set -e

        if [[ $NUCLEI_EXIT -ne 0 ]]; then
            echo "❌ Nuclei exit=$NUCLEI_EXIT"
            emit_inconclusive "nuclei" "$FINDING_ID" "scanner_error" \
              "Nuclei exit=$NUCLEI_EXIT. Stderr: $(head -c 300 "$NUCLEI_ERR" | tr '\n' ' ')"
            continue
        fi

        # Convertir JSONL → array JSON
        ALL_FINDINGS="[]"
        [[ -s "$RESULT" ]] && ALL_FINDINGS=$(jq -s -c '.' "$RESULT" 2>/dev/null || echo "[]")
        HITS_TOTAL=$(echo "$ALL_FINDINGS" | jq 'length')

        # CWE normalizado (Nuclei usa minúsculas: "cwe-693")
        CWE_LOW=$(echo "$CWE" | tr 'A-Z' 'a-z')

        # Hits que matchean CWE — búsqueda robusta:
        # 1) info.classification.cwe-id (lo más típico)
        # 2) info.tags (algunos templates ponen el CWE como tag)
        # 3) Cualquier parte del objeto stringified (fallback)
        if [[ -n "$CWE_LOW" ]]; then
            HITS_CWE=$(echo "$ALL_FINDINGS" | jq --arg c "$CWE_LOW" \
                '[.[] | select(
                    ((.info.classification."cwe-id" // []) | tostring | ascii_downcase | test($c)) or
                    ((.info.tags // []) | tostring | ascii_downcase | test($c)) or
                    (. | tostring | ascii_downcase | test($c))
                )] | length')
        else
            HITS_CWE="null"
        fi

        # Hits que matchean keyword en matcher-name / template-id / info.name / info.description
        if [[ -n "$KEYWORD_MATCH" ]]; then
            # Construir regex OR a partir de keywords separadas por coma
            KW_REGEX=$(echo "$KEYWORD_MATCH" | tr ',' '|')
            HITS_KW=$(echo "$ALL_FINDINGS" | jq --arg k "$KW_REGEX" \
                '[.[] | select(
                    ((."matcher-name" // "") | ascii_downcase | test($k)) or
                    ((."template-id" // "") | ascii_downcase | test($k)) or
                    ((.info.name // "") | ascii_downcase | test($k)) or
                    ((.info.description // "") | ascii_downcase | test($k))
                )] | length')
        else
            HITS_KW="null"
            KW_REGEX=""
        fi

        # Hits que matchean AMBOS (CWE robusto + keyword)
        if [[ -n "$CWE_LOW" && -n "$KEYWORD_MATCH" ]]; then
            HITS_BOTH=$(echo "$ALL_FINDINGS" | jq --arg c "$CWE_LOW" --arg k "$KW_REGEX" \
                '[.[] | select(
                    (((.info.classification."cwe-id" // []) | tostring | ascii_downcase | test($c)) or
                     ((.info.tags // []) | tostring | ascii_downcase | test($c)) or
                     (. | tostring | ascii_downcase | test($c)))
                    and
                    (((."matcher-name" // "") | ascii_downcase | test($k)) or
                     ((."template-id" // "") | ascii_downcase | test($k)) or
                     ((.info.name // "") | ascii_downcase | test($k)) or
                     ((.info.description // "") | ascii_downcase | test($k)))
                )] | length')
        else
            HITS_BOTH="null"
        fi

        # Lógica de signal_strength
        # Principio: keyword pesa más que CWE (el CWE puede ser un paraguas amplio).
        # Si se pidió keyword_match y NINGÚN hit lo cumple → la vuln específica NO se reproduce.
        SIGNAL="inconclusive"
        if [[ -n "$CWE_LOW" && -n "$KEYWORD_MATCH" ]]; then
            if [[ "$HITS_BOTH" -gt 0 ]]; then
                SIGNAL="strong_positive"   # Nuclei reproduce la vuln exacta → NO es FP
            elif [[ "$HITS_KW" -gt 0 ]]; then
                SIGNAL="weak_positive"      # Keyword sí matchea, CWE no — sospechoso
            else
                # Keyword no matchea → la vuln específica no se reproduce.
                # CWE coincidir solo no es señal fuerte (CWEs como 693 son paraguas amplios).
                SIGNAL="weak_negative"      # Apoya FP
            fi
        elif [[ -n "$KEYWORD_MATCH" ]]; then
            [[ "$HITS_KW" -gt 0 ]] && SIGNAL="strong_positive" || SIGNAL="weak_negative"
        elif [[ -n "$CWE_LOW" ]]; then
            [[ "$HITS_CWE" -gt 0 ]] && SIGNAL="weak_positive" || SIGNAL="weak_negative"
        else
            [[ "$HITS_TOTAL" -gt 0 ]] && SIGNAL="weak_positive" || SIGNAL="strong_negative"
        fi

        # Evidencia: top 5 hits relevantes (prioriza los que matchean keyword/cwe)
        if [[ -n "$KEYWORD_MATCH" ]]; then
            EVIDENCE=$(echo "$ALL_FINDINGS" | jq --arg k "$KW_REGEX" \
                '[.[] | select(
                    ((."matcher-name" // "") | ascii_downcase | test($k)) or
                    ((."template-id" // "") | ascii_downcase | test($k)) or
                    ((.info.name // "") | ascii_downcase | test($k))
                  )
                  | {template_id: ."template-id", matcher: ."matcher-name",
                     name: .info.name, severity: .info.severity,
                     cwe: (.info.classification."cwe-id" // .info.tags // []),
                     url: ."matched-at"}] | .[0:5]')
            # Si no hubo matches por keyword, mostrar los primeros 5 generales
            if [[ "$HITS_KW" == "0" ]]; then
                EVIDENCE=$(echo "$ALL_FINDINGS" | jq \
                    '[.[] | {template_id: ."template-id", matcher: ."matcher-name",
                             name: .info.name, severity: .info.severity,
                             cwe: .info.classification."cwe-id", url: ."matched-at"}] | .[0:5]')
            fi
        else
            EVIDENCE=$(echo "$ALL_FINDINGS" | jq \
                '[.[] | {template_id: ."template-id", matcher: ."matcher-name",
                         name: .info.name, severity: .info.severity,
                         cwe: .info.classification."cwe-id", url: ."matched-at"}] | .[0:5]')
        fi

        echo "→ Nuclei signal=$SIGNAL  total=$HITS_TOTAL  cwe=$HITS_CWE  keyword=$HITS_KW  both=$HITS_BOTH"

        ENRICHED="/app/output/nuclei-${FINDING_ID}-final.json"
        jq -n --arg target "$TARGET_URL" --arg ts "$TIMESTAMP" --arg email "$USER_EMAIL" \
              --arg group "$GROUP_ID" --arg fid "$FINDING_ID" --arg rule "$RULE_ID" \
              --arg tk "$TICKET_ID" --arg cwe "$CWE" --arg kw "$KEYWORD_MATCH" \
              --arg signal "$SIGNAL" \
              --argjson total "$HITS_TOTAL" \
              --argjson hits_cwe "${HITS_CWE:-null}" \
              --argjson hits_kw "${HITS_KW:-null}" \
              --argjson hits_both "${HITS_BOTH:-null}" \
              --argjson evidence "$EVIDENCE" \
              --arg httpcode "$HTTP_CODE" \
              '{scanner:"nuclei", ticket_id:$tk, finding_id:$fid, rule_id:$rule,
                target_url:$target, cwe:$cwe, keyword_match:$kw,
                scan_timestamp:$ts, user_email:$email, group_id:$group,
                scan_status:"ok",
                signal: {
                    strength: $signal,
                    target_http_code: $httpcode,
                    hits_total: $total,
                    hits_matching_cwe: $hits_cwe,
                    hits_matching_keyword: $hits_kw,
                    hits_matching_both: $hits_both,
                    evidence: $evidence
                }}' > "$ENRICHED"

        post_webhook "nuclei" "$ENRICHED"
        ;;

    # =========================================================================
    # IaC (Terraform / Kubernetes / Dockerfile / CloudFormation)
    # Usa `trivy config` — escanea archivos de infra como código.
    # =========================================================================
    iac|trivy_iac|snyk_iac)
        if [[ -z "$URL" || "$URL" == "null" ]]; then
            echo "❌ Missing repo_url"
            post_error "iac" "Missing repo_url" "$FINDING_ID" ""
            continue
        fi

        NORM=$(normalize_repo_url "$URL")
        URL=$(echo "$NORM" | sed -n '1p')
        URL_COMMIT=$(echo "$NORM" | sed -n '2p')
        [[ -z "$TARGET_COMMIT" && -n "$URL_COMMIT" ]] && TARGET_COMMIT="$URL_COMMIT"

        NAME=$(basename "$URL" .git)
        CLONE_URL=$(get_clone_url "$URL")
        WORKDIR="/app/projects/${FINDING_ID}-${NAME}"
        rm -rf "$WORKDIR"

        set +e
        if [[ -n "$TARGET_BRANCH" && "$TARGET_BRANCH" != "null" ]]; then
            git clone -b "$TARGET_BRANCH" --single-branch "$CLONE_URL" "$WORKDIR" --quiet
        elif [[ -n "$TARGET_COMMIT" ]]; then
            git clone "$CLONE_URL" "$WORKDIR" --quiet
        else
            git clone --depth 1 "$CLONE_URL" "$WORKDIR" --quiet
        fi
        CLONE_EXIT=$?
        set -e
        [ $CLONE_EXIT -ne 0 ] && { post_error "iac" "Git Clone Failed" "$FINDING_ID" "$NAME"; continue; }

        cd "$WORKDIR"
        if [[ -n "$TARGET_COMMIT" ]]; then
            set +e; git checkout --quiet "$TARGET_COMMIT"; CHK=$?; set -e
            [ $CHK -ne 0 ] && { post_error "iac" "Git Checkout Failed" "$FINDING_ID" "$NAME"; cd /app; continue; }
        fi
        if [[ -n "$ROUTE" && "$ROUTE" != "null" && -d "$ROUTE" ]]; then
            cd "$ROUTE"
        fi

        CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
        [[ "$CURRENT_BRANCH" == "HEAD" && -n "$TARGET_COMMIT" ]] && CURRENT_BRANCH="$TARGET_COMMIT"

        RESULT="/app/output/iac-${FINDING_ID}.json"
        echo "→ Running Trivy config (IaC) scan..."
        set +e
        trivy config --quiet --format json --output "$RESULT" . 2>/dev/null
        set -e

        if [[ ! -s "$RESULT" ]]; then
            echo '{"Results":[]}' > "$RESULT"
        fi

        # Estructura de trivy config: .Results[].Misconfigurations[]
        TOTAL_MISCONFIGS=$(jq '[.Results[]?.Misconfigurations[]?] | length' "$RESULT" 2>/dev/null || echo 0)

        # Filtrado por archivo afectado
        if [[ -n "$AFFECTED_FILE" ]]; then
            FILE_MATCHES=$(jq --arg f "$AFFECTED_FILE" \
                '[.Results[]? | select(.Target == $f or (.Target | endswith($f)))
                  | .Misconfigurations[]?]' "$RESULT")
            HITS_IN_FILE=$(echo "$FILE_MATCHES" | jq 'length')
        else
            FILE_MATCHES="[]"
            HITS_IN_FILE="null"
        fi

        # Filtrado por keyword en Title/Description del misconfig
        if [[ -n "$KEYWORD_MATCH" ]]; then
            KW_REGEX=$(echo "$KEYWORD_MATCH" | tr ',' '|')
            KW_MATCHES=$(jq --arg k "$KW_REGEX" \
                '[.Results[]?.Misconfigurations[]?
                  | select(((.Title // "") | ascii_downcase | test($k))
                        or ((.Description // "") | ascii_downcase | test($k))
                        or ((.ID // "") | ascii_downcase | test($k)))]' "$RESULT")
            HITS_KW=$(echo "$KW_MATCHES" | jq 'length')
        else
            KW_MATCHES="[]"
            HITS_KW="null"
            KW_REGEX=""
        fi

        # Intersección archivo + keyword
        if [[ -n "$AFFECTED_FILE" && -n "$KEYWORD_MATCH" ]]; then
            HITS_BOTH=$(jq --arg f "$AFFECTED_FILE" --arg k "$KW_REGEX" \
                '[.Results[]? | select(.Target == $f or (.Target | endswith($f)))
                  | .Misconfigurations[]?
                  | select(((.Title // "") | ascii_downcase | test($k))
                        or ((.Description // "") | ascii_downcase | test($k))
                        or ((.ID // "") | ascii_downcase | test($k)))] | length' "$RESULT")
        else
            HITS_BOTH="null"
        fi

        # Signal strength
        SIGNAL="inconclusive"
        if [[ "$TOTAL_MISCONFIGS" -eq 0 ]]; then
            SIGNAL="inconclusive"   # repo vacío o trivy no detectó IaC → manual review
        elif [[ -n "$AFFECTED_FILE" && -n "$KEYWORD_MATCH" ]]; then
            if [[ "$HITS_BOTH" -gt 0 ]]; then
                SIGNAL="strong_positive"
            elif [[ "$HITS_KW" -gt 0 || "$HITS_IN_FILE" -gt 0 ]]; then
                SIGNAL="weak_positive"
            else
                SIGNAL="weak_negative"
            fi
        elif [[ -n "$AFFECTED_FILE" ]]; then
            [[ "$HITS_IN_FILE" -gt 0 ]] && SIGNAL="weak_positive" || SIGNAL="weak_negative"
        elif [[ -n "$KEYWORD_MATCH" ]]; then
            [[ "$HITS_KW" -gt 0 ]] && SIGNAL="weak_positive" || SIGNAL="weak_negative"
        else
            SIGNAL="weak_positive"
        fi

        # Evidencia: prioriza both → keyword → file → top 5 general
        if [[ "$HITS_BOTH" != "null" && "$HITS_BOTH" -gt 0 ]]; then
            EVIDENCE=$(jq --arg f "$AFFECTED_FILE" --arg k "$KW_REGEX" \
                '[.Results[]? | select(.Target == $f or (.Target | endswith($f)))
                  | .Target as $t | .Misconfigurations[]?
                  | select(((.Title // "") | ascii_downcase | test($k))
                        or ((.Description // "") | ascii_downcase | test($k))
                        or ((.ID // "") | ascii_downcase | test($k)))
                  | {id: .ID, title: .Title, severity: .Severity, target: $t}] | .[0:5]' "$RESULT")
        elif [[ "$HITS_KW" != "null" && "$HITS_KW" -gt 0 ]]; then
            EVIDENCE=$(echo "$KW_MATCHES" | jq '[.[] | {id: .ID, title: .Title, severity: .Severity}] | .[0:5]')
        elif [[ "$HITS_IN_FILE" != "null" && "$HITS_IN_FILE" -gt 0 ]]; then
            EVIDENCE=$(echo "$FILE_MATCHES" | jq '[.[] | {id: .ID, title: .Title, severity: .Severity}] | .[0:5]')
        else
            EVIDENCE=$(jq '[.Results[]? | .Target as $t | .Misconfigurations[]?
                            | {id: .ID, title: .Title, severity: .Severity, target: $t}] | .[0:5]' "$RESULT")
        fi

        echo "→ IaC signal=$SIGNAL  total=$TOTAL_MISCONFIGS  file=$HITS_IN_FILE  kw=$HITS_KW  both=$HITS_BOTH"

        ENRICHED="/app/output/iac-${FINDING_ID}-final.json"
        jq -n --arg branch "$CURRENT_BRANCH" --arg url "$URL" --arg name "$NAME" \
              --arg ts "$TIMESTAMP" --arg email "$USER_EMAIL" --arg group "$GROUP_ID" \
              --arg fid "$FINDING_ID" --arg tk "$TICKET_ID" \
              --arg affected "$AFFECTED_FILE" --arg kw "$KEYWORD_MATCH" \
              --arg signal "$SIGNAL" \
              --argjson total "$TOTAL_MISCONFIGS" \
              --argjson hits_file "${HITS_IN_FILE:-null}" \
              --argjson hits_kw "${HITS_KW:-null}" \
              --argjson hits_both "${HITS_BOTH:-null}" \
              --argjson evidence "$EVIDENCE" \
              '{scanner:"iac", ticket_id:$tk, finding_id:$fid,
                affected_file:$affected, keyword_match:$kw,
                git_branch:$branch, repo_url:$url, project_name:$name,
                scan_timestamp:$ts, user_email:$email, group_id:$group,
                signal: {
                    strength: $signal,
                    total_misconfigs_in_repo: $total,
                    hits_in_affected_file: $hits_file,
                    hits_matching_keyword: $hits_kw,
                    hits_matching_both: $hits_both,
                    evidence: $evidence
                }}' > "$ENRICHED"

        post_webhook "iac" "$ENRICHED"
        cd /app
        ;;

    *)
        echo "❌ Unsupported scanner: $SCANNER"
        post_error "scan" "Unsupported scanner" "$FINDING_ID" "$SCANNER"
        ;;
    esac
done

# Limpieza
rm -rf /app/projects/*
echo "===== Scan Runner Completed ====="

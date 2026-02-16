#!/bin/bash

# --- CONFIGURACIÓN DE WEBHOOKS---
export WEBHOOK_ZAP="https://mgonzalezg.app.n8n.cloud/webhook/zapscan"
export WEBHOOK_TESTSSL="https://mgonzalezg.app.n8n.cloud/webhook/testsslscan"
export WEBHOOK_NMAP="https://mgonzalezg.app.n8n.cloud/webhook/nmapscan"
export WEBHOOK_NIKTO="https://mgonzalezg.app.n8n.cloud/webhook/niktoscan"

echo "===== SECURITY SCANNER MASTER SYSTEM ====="

# Función para ejecutar con Webhook dinámico
run_zap() { 
    echo "Iniciando OWASP ZAP..."
    export N8N_WEBHOOK_URL=$WEBHOOK_ZAP
    ./zap.sh 
}

run_testssl() { 
    echo "Iniciando TestSSL..."
    export N8N_WEBHOOK_URL=$WEBHOOK_TESTSSL
    ./testssl.sh 
}

run_nmap() { 
    echo "Iniciando Nmap..."
    export N8N_WEBHOOK_URL=$WEBHOOK_NMAP
    ./nmap.sh 
}

run_nikto() { 
    echo "Iniciando Nikto..."
    export N8N_WEBHOOK_URL=$WEBHOOK_NIKTO
    ./nikto.sh 
}

# Lógica de ejecución
if [ "$TOOL_NAME" == "zap" ]; then run_zap
elif [ "$TOOL_NAME" == "testssl" ]; then run_testssl
elif [ "$TOOL_NAME" == "nmap" ]; then run_nmap
elif [ "$TOOL_NAME" == "nikto" ]; then run_nikto
else
    echo "EJECUTANDO ESCANEO COMPLETO (ALL TOOLS)"
    # Ejecutamos en cadena. Usamos || true para que si uno falla, no detenga el resto.
    run_nmap    || echo "Nmap falló, continuando..."
    run_testssl || echo "TestSSL falló, continuando..."
    run_nikto   || echo "Nikto falló, continuando..."
    run_zap     || echo "ZAP falló, continuando..."
fi

echo "===== PROCESO FINALIZADO ====="
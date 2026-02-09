#!/bin/bash

# --- VARIABLES ---
TARGET=$1
IMAGE_NAME="mi-agente-audit.dockerfile"
OUTPUT_DIR="$(pwd)/resultados_$TARGET"

# Validar dominio
if [ -z "$TARGET" ]; then
    echo "❌ Error: Faltó el dominio."
    echo "Uso: ./ejecutar_todo.sh ejemplo.com"
    exit 1
fi

# Preparar carpeta
mkdir -p "$OUTPUT_DIR"
# Permisos amplios para evitar errores de escritura con Docker en Windows
chmod 777 "$OUTPUT_DIR"

echo "---------------------------------------------------"
echo "🔨 PASO 1: CONSTRUIR LA IMAGEN (BUILD)"
echo "---------------------------------------------------"
# Aquí creamos la imagen localmente basada en tu Dockerfile
docker build -t $IMAGE_NAME .

if [ $? -ne 0 ]; then
    echo "❌ Falló la construcción de la imagen. Revisa tu Dockerfile."
    exit 1
fi
echo "✅ Imagen '$IMAGE_NAME' lista."

echo "---------------------------------------------------"
echo "🚀 PASO 2: EJECUTAR NMAP Y TESTSSL (RUN)"
echo "---------------------------------------------------"

# Explicación del comando:
# Usamos /bin/bash -c "comando1 && comando2" para correr ambos en el mismo contenedor secuencialmente
docker run --rm \
    -v "$OUTPUT_DIR":/data \
    $IMAGE_NAME \
    /bin/bash -c "
        echo 'Starting Nmap...' && \
        nmap -sS -T3 -Pn -sV -O --script=default,vuln --open $TARGET -oX /data/nmap.xml && \
        echo '✅ Nmap Finished.' && \
        echo 'Starting TestSSL...' && \
        testssl --jsonfile /data/testssl.json $TARGET && \
        echo '✅ TestSSL Finished.'
    "

echo "---------------------------------------------------"
echo "🕷️ PASO 3: EJECUTAR OWASP ZAP (Externo)"
echo "---------------------------------------------------"
# ZAP sigue siendo mejor correrlo aparte porque es muy pesado para meterlo en tu imagen
docker run --rm \
    -v "$OUTPUT_DIR":/zap/wrk/:rw \
    -t ghcr.io/zaproxy/zaproxy:stable \
    zap-baseline.py \
    -t https://$TARGET \
    -J zap_report.json > /dev/null 2>&1

echo "✅ ZAP Finalizado."
echo "---------------------------------------------------"
echo "📂 Reportes listos en: $OUTPUT_DIR"
ls -lh "$OUTPUT_DIR"
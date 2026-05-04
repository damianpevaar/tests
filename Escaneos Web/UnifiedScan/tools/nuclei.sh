#!/bin/bash
set +e

# 1. Definir rutas
RAW_FILE="/tmp/raw_nuclei.json"
FINAL_FILE="/tmp/nuclei_res.json"

echo "===== INICIANDO NUCLEI (MAX COBERTURA) ====="
echo "→ Objetivo: $TARGET_URL"

# Limpiar archivos de ejecuciones previas
rm -f "$RAW_FILE" "$FINAL_FILE"

# 2. Ejecución de Nuclei
# EXPLICACIÓN DE CAMBIOS:
# Se quitó -cl (causaba error)
# Se quitó -severity (ahora trae todo: info, low, medium, high, critical)
# Se añadió -as (Automatic Scan para detectar tecnologías)
# Se añadió -ni (Non-Interactive)
nuclei -u "$TARGET_URL" \
  -as \
  -jsonl -o "$RAW_FILE" \
  -ni -silent || true

# 3. Procesamiento de resultados
if [ -s "$RAW_FILE" ]; then
    TOTAL=$(wc -l < "$RAW_FILE")
    echo "→ Hallazgos encontrados: $TOTAL. Estructurando JSON..."
    # Convertimos JSONL (líneas) a un Array JSON real
    jq -s '.' "$RAW_FILE" > "$FINAL_FILE"
else
    echo "→ No se encontraron hallazgos. Enviando array vacío."
    echo "[]" > "$FINAL_FILE"
fi

echo "===== NUCLEI FINALIZADO ====="
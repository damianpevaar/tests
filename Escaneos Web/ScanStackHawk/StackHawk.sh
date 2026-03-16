#!/bin/sh

# 1. Validar que nos enviaron las variables necesarias
if [ -z "$TARGET_URL" ]; then
  echo "❌ ERROR: Debes proveer una TARGET_URL (ej. -e TARGET_URL=https://mipagina.com)"
  exit 1
fi

if [ -z "$HAWK_APP_ID" ]; then
  echo "❌ ERROR: Debes proveer un HAWK_APP_ID."
  exit 1
fi

echo "🚀 Iniciando Escáner On-Demand para: $TARGET_URL"

# 2. Generar el stackhawk.yml dinámicamente
cat <<EOF > /hawk/stackhawk.yml
app:
  applicationId: ${HAWK_APP_ID}
  env: Escaneo_Manual
  host: ${TARGET_URL}

hawk:
  spider:
    base: true
EOF

echo "📄 Archivo de configuración generado con éxito."

# 3. Ejecutar el escáner oficial de StackHawk
shawk /hawk/stackhawk.yml
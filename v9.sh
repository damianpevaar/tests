#!/bin/bash

echo "===== Iniciando Servicios de OpenVAS (GVM) ====="
# Aquí se inician los servicios internos de la imagen base en segundo plano
/usr/local/bin/start-gvm.sh & 

# Esperar a que el socket de Greenbone esté listo (puede tardar 2-5 min)
echo "→ Esperando a que el daemon de OpenVAS responda..."
while [ ! -S /run/gvmd/gvmd.sock ]; do
  sleep 10
done

echo "→ ¡Servicios listos! Creando tarea de escaneo para: $TARGET_IP"

# 1. Crear el Target
gvm-cli --gmp-username admin --gmp-password admin socket --xml \
"<create_target><name>Prueba_$TARGET_IP</name><hosts>$TARGET_IP</hosts></create_target>" > target_resp.xml
TARGET_ID=$(grep -oP 'id="\K[^"]+' target_resp.xml)

# 2. Crear la Tarea
gvm-cli --gmp-username admin --gmp-password admin socket --xml \
"<create_task><name>Escaneo_$TARGET_IP</name><target_id>$TARGET_ID</target_id><config_id>daba56c8-73ec-11df-a475-002264764cea</config_id></create_task>" > task_resp.xml
TASK_ID=$(grep -oP 'id="\K[^"]+' task_resp.xml)

# 3. Iniciar Escaneo
gvm-cli --gmp-username admin --gmp-password admin socket --xml \
"<start_task task_id=\"$TASK_ID\"/>"

echo "→ Escaneo en curso. Consultando estado..."

# 4. Loop de espera (Polling asincrónico interno)
STATUS="New"
while [ "$STATUS" != "Done" ]; do
  sleep 30
  STATUS=$(gvm-cli --gmp-username admin --gmp-password admin socket --xml "<get_tasks task_id=\"$TASK_ID\"/>" | grep -oP '<status>\K[^<]+')
  echo "  - Estado actual: $STATUS"
done

# 5. Obtener Reporte y enviar a n8n
REPORT_ID=$(gvm-cli --gmp-username admin --gmp-password admin socket --xml "<get_tasks task_id=\"$TASK_ID\"/>" | grep -oP '<last_report><report id="\K[^"]+')
gvm-cli --gmp-username admin --gmp-password admin socket --xml "<get_reports report_id=\"$REPORT_ID\" format_id=\"a381d221-7647-4478-aa20-ef1104155b14\"/>" > final_report.xml

# Convertimos a algo que n8n entienda y enviamos
curl -X POST "$WEBHOOK_URL" -H "Content-Type: application/xml" --data-binary @final_report.xml

echo "===== Proceso Finalizado ====="

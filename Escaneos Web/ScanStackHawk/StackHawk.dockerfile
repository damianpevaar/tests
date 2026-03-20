# Usar la imagen oficial de StackHawk como base
FROM stackhawk/hawkscan:latest

# Cambiar a usuario root temporalmente para dar permisos al script
USER root

# Copiar nuestro script inteligente al contenedor
COPY StackHawk.sh /StackHawk.sh
RUN chmod +x /StackHawk.sh

# Volver al usuario seguro de StackHawk
USER hawk

# Definir nuestro script como el punto de arranque
ENTRYPOINT ["/StackHawk.sh"]
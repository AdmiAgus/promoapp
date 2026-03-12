# Usa la misma versión que tienes en tu servidor host
FROM node:20-alpine

# Crea el directorio de trabajo
WORKDIR /app

# Copia los archivos de dependencias primero para optimizar la caché de Docker
COPY package*.json ./
RUN npm install

# Copia todo el resto del código
COPY . .

# Expon el puerto donde tu server.js escucha (3050)
EXPOSE 3050

# Inicia tu servidor activador
CMD ["node", "server.js"]

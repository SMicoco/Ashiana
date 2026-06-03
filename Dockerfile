FROM node:20-alpine

# Build deps for better-sqlite3
RUN apk add --no-cache python3 make g++ libc6-compat

WORKDIR /app

# Install deps
COPY package*.json ./
RUN npm install --omit=dev

# App
COPY . .

# Persistent storage for the SQLite file
RUN mkdir -p /data
ENV DB_PATH=/data/ashiana.db
VOLUME ["/data"]

EXPOSE 3000
CMD ["node", "server.js"]

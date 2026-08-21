# ZX — production image. Small, deterministic, prod deps only.
FROM node:20-slim

ENV NODE_ENV=production
WORKDIR /app

# Install prod dependencies first (better layer caching)
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# App source
COPY . .

# Northflank injects PORT; the app already reads process.env.PORT
EXPOSE 7817
CMD ["node", "server.js"]

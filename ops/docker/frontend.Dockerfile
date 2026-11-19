FROM node:24-trixie-slim AS build
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend ./
RUN npm run build

FROM nginx:1.30.6-trixie
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# nginx's template mechanism substitutes ${ORION_HTTPS_PORT} (and only environment variables) in *.template files
COPY ops/docker/nginx/default.conf /etc/nginx/templates/default.conf.template
COPY ops/docker/nginx/security.conf /etc/nginx/snippets/security.conf
COPY --from=build /app/dist /usr/share/nginx/html

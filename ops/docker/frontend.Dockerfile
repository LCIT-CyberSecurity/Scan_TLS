FROM node:20-alpine AS build
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend ./
RUN npm run build

FROM nginx:1.27-alpine
# nginx's template mechanism substitutes ${TLS_SCAN_HTTPS_PORT} (and only environment variables) in *.template files
COPY ops/docker/nginx/default.conf /etc/nginx/templates/default.conf.template
COPY ops/docker/nginx/security.conf /etc/nginx/snippets/security.conf
COPY --from=build /app/dist /usr/share/nginx/html

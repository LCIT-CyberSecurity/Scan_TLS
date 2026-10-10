FROM nginx:1.27-alpine
RUN apk add --no-cache openssl
COPY tests/lab/nginx.conf /etc/nginx/nginx.conf
COPY tests/lab/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]

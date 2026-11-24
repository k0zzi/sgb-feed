# Keep this on a supported stable line (nginx.org security advisories are fixed in the current stable branch only).
FROM nginx:1.30-alpine

# openssl: generates the CA, the server certificate and the password hash on first start
RUN apk add --no-cache openssl tzdata && rm -f /etc/nginx/conf.d/default.conf

COPY default.conf /etc/nginx/conf.d/default.conf
COPY 40-sgb-setup.sh /docker-entrypoint.d/40-sgb-setup.sh
RUN chmod +x /docker-entrypoint.d/40-sgb-setup.sh

EXPOSE 443

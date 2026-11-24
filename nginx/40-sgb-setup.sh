#!/bin/sh
# Runs before nginx starts (the official image's /docker-entrypoint.d mechanism).
# On error the container does not start; the reason shows in `docker compose logs nginx`.
set -eu

CERT_DIR="${CERT_DIR:-/certs}"
CONF_DIR="${CONF_DIR:-/etc/nginx}"

fail() { echo "[sgb-setup] ERROR: $*" >&2; exit 1; }
# Runs a command quietly (openssl prints progress dots); on failure shows its output and stops.
quiet() { if ! _out="$("$@" 2>&1)"; then echo "$_out" >&2; fail "command failed: $1 $2"; fi; }

# 1) Password: refuse to start if empty or left at the example value
[ -n "${UI_PASS:-}" ] || fail "UI_PASS is not set (check the .env file)."
[ "${UI_PASS}" != "change-me" ] || fail "UI_PASS is still the example value (change-me). Change it in .env."
printf '%s:%s\n' "${UI_USER:-admin}" "$(printf '%s' "$UI_PASS" | openssl passwd -apr1 -stdin)" > "$CONF_DIR/sgb_htpasswd"
# Preferably readable by the nginx group only; if there is no such group, 644 so the nginx workers can read it.
if chown root:nginx "$CONF_DIR/sgb_htpasswd" 2>/dev/null; then
    chmod 640 "$CONF_DIR/sgb_htpasswd"
else
    chmod 644 "$CONF_DIR/sgb_htpasswd"
fi

# 2) IP allow lists: "10.0.0.0/8, 192.168.1.10" -> "allow 10.0.0.0/8; allow 192.168.1.10; deny all;"
make_allow() {
    out="$1"; list="$2"; name="$3"
    [ -n "$list" ] || fail "$name is not set (check the .env file)."
    : > "$out"
    for net in $(echo "$list" | tr ',' ' '); do
        echo "$net" | grep -Eq '^[0-9a-fA-F:.]+(/[0-9]{1,3})?$' || fail "invalid value in $name: '$net'"
        echo "allow $net;" >> "$out"
    done
    echo "deny all;" >> "$out"
}
[ -n "${FEED_ALLOWED:-}" ] || fail "FEED_ALLOWED is not set (check the .env file)."
make_allow "$CONF_DIR/sgb_allow_ui.conf" "${UI_ALLOWED:-}" "UI_ALLOWED"
# Feeds can be fetched by the firewalls and (to browse them) by the UI users
make_allow "$CONF_DIR/sgb_allow_feed.conf" "${FEED_ALLOWED},${UI_ALLOWED}" "FEED_ALLOWED/UI_ALLOWED"

# 3) Certificate. A CA, and a server certificate signed by that CA
#    with a subjectAltName. Firewalls only need ca.crt. To use your own certificate, put server.crt and
#    server.key into /certs before the first start (the CA is then not created).
#    Renewal: delete server.crt and server.key and restart; the existing CA signs a new certificate,
#    so nothing has to be changed on the firewalls.
mkdir -p "$CERT_DIR"
if [ ! -s "$CERT_DIR/server.crt" ] || [ ! -s "$CERT_DIR/server.key" ]; then
    CN="${CERT_CN:-sgb-feed}"
    echo "$CN" | grep -Eq '^[A-Za-z0-9.:-]+$' || fail "invalid CERT_CN: '$CN' (letters, digits, dot, hyphen, colon only)"

    # subjectAltName: CERT_CN (as an IP entry if it is an address, otherwise a DNS entry) + every address in CERT_IP
    san=""
    if echo "$CN" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$|:'; then san="IP:$CN"; else san="DNS:$CN"; fi
    for ip in $(echo "${CERT_IP:-}" | tr ',' ' '); do
        echo "$ip" | grep -Eq '^[0-9a-fA-F:.]+$' || fail "invalid value in CERT_IP: '$ip'"
        san="$san,IP:$ip"
    done
    [ -n "${CERT_IP:-}" ] || echo "[sgb-setup] WARNING: CERT_IP is not set. A firewall that connects by IP address will not accept this certificate; set CERT_IP in .env (delete certs/server.* and restart to reissue)."

    if [ ! -s "$CERT_DIR/ca.crt" ] || [ ! -s "$CERT_DIR/ca.key" ]; then
        echo "[sgb-setup] No CA found, generating one (3650 days)."
        quiet openssl req -x509 -newkey rsa:4096 -nodes -sha256 -days 3650 \
            -subj "/CN=sgb-feed CA" \
            -addext "basicConstraints=critical,CA:TRUE" \
            -addext "keyUsage=critical,keyCertSign,cRLSign" \
            -keyout "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.crt"
        chmod 600 "$CERT_DIR/ca.key"
    fi

    echo "[sgb-setup] Generating the server certificate signed by the CA (825 days, CN=$CN, SAN=$san)."
    printf '%s\n' "basicConstraints=critical,CA:FALSE" \
        "keyUsage=critical,digitalSignature,keyEncipherment" \
        "extendedKeyUsage=serverAuth" \
        "subjectAltName=$san" > "$CERT_DIR/.server.ext"
    quiet openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$CN" \
        -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/.server.csr"
    quiet openssl x509 -req -sha256 -days 825 -in "$CERT_DIR/.server.csr" \
        -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
        -extfile "$CERT_DIR/.server.ext" -out "$CERT_DIR/server.crt"
    rm -f "$CERT_DIR/.server.csr" "$CERT_DIR/.server.ext"
    chmod 600 "$CERT_DIR/server.key"
fi

echo "[sgb-setup] Ready. UI allowed networks: ${UI_ALLOWED} | Feed allowed networks: ${FEED_ALLOWED} (+ UI networks)"

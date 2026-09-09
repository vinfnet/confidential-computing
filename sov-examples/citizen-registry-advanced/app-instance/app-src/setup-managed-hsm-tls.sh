#!/bin/bash
set -euo pipefail

if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <hsm-name> <tls-identity-client-id> <key-label> <server-ip>" >&2
    exit 2
fi

HSM_NAME=$1
TLS_IDENTITY_CLIENT_ID=$2
KEY_LABEL=$3
SERVER_IP=$4
PACKAGE_VERSION=1.1.0.03455
PACKAGE=/tmp/mhsm-pkcs11_${PACKAGE_VERSION}_amd64.deb
PACKAGE_URL="https://github.com/microsoft/managed-hsm-tls-offload/releases/download/v${PACKAGE_VERSION}/mhsm-pkcs11_${PACKAGE_VERSION}_amd64.deb"
PACKAGE_SHA256=a96e4ead390dc27fcf7061112380b897f8173a5b3a962a8c444634cfc594d8f5
CERT_DIR=/etc/citizen-registry/certs
P11_CONFIG=/etc/mhsm-pkcs11.conf
OPENSSL_CONFIG=/etc/citizen-registry/openssl-mhsm.cnf
KEY_NAME_FILE=/etc/citizen-registry/managed-hsm-tls-key-name
P11_URI="pkcs11:object=${KEY_LABEL};type=private;pin-value="

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl libengine-pkcs11-openssl opensc openssl
curl -fsSL --retry 5 --retry-connrefused --retry-delay 10 "$PACKAGE_URL" -o "$PACKAGE"
echo "$PACKAGE_SHA256  $PACKAGE" | sha256sum --check --strict
dpkg --install "$PACKAGE"

cat > "$P11_CONFIG" <<EOF
{
  "tokens": [
    {
      "slotid": 0,
      "protocol": "https://",
      "uri": "managedhsm.azure.net",
      "resourceName": "${HSM_NAME}",
      "resourceType": "mhsm"
    }
  ],
  "msi": {
    "identityMSI": true,
    "MSIClientID": "${TLS_IDENTITY_CLIENT_ID}"
  },
  "options": {
    "DisableTLSAuthentication": false
  },
  "log": {
    "directory": "/var/log/mhsm-pkcs11",
    "module": {
      "P11Interfaces": false,
      "FunctionLevelTrace": false,
      "curl": { "Level": "Off", "DisplayAsHex": false }
    },
    "flags": {
      "CloseFileAfterWrite": false,
      "SendToFile": false,
      "SendToStdOut": false,
      "SendToStdErr": false,
      "IncludeProcessId": false,
      "IncludeThreadId": false,
      "IncludePINs": false
    }
  },
  "ConnectionCache": { "Disable": false, "MaxConnections": 20 }
}
EOF
chmod 600 "$P11_CONFIG"
CONFIG_VALIDATOR="/usr/src/mhsm-pkcs11-${PACKAGE_VERSION}/samples/bin/mhsm_p11_validate_config_file"
test -x "$CONFIG_VALIDATOR"
"$CONFIG_VALIDATOR" --file "$P11_CONFIG" | grep -q 'SUCCESS: Parsing'

ENGINE_PATH=$(dpkg -L libengine-pkcs11-openssl | grep '/engines-[^/]*/pkcs11\.so$' | head -1)
test -n "$ENGINE_PATH"
cat > "$OPENSSL_CONFIG" <<EOF
openssl_conf = openssl_init
config_diagnostics = 1

[openssl_init]
providers = provider_section
engines = engine_section

[provider_section]
default = default_section
base = base_section

[default_section]
activate = 1

[base_section]
activate = 1

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = ${ENGINE_PATH}
MODULE_PATH = /usr/lib/libmhsm-pkcs11.so
init = 1
EOF
chmod 644 "$OPENSSL_CONFIG"
export OPENSSL_CONF="$OPENSSL_CONFIG"
openssl engine -t pkcs11 | grep -q '\[ available \]'

if [ ! -s "$KEY_NAME_FILE" ]; then
    KEY_OUTPUT=$(/usr/local/bin/mhsm_p11_create_key --identity --RSA 3K --label "$KEY_LABEL")
    printf '%s\n' "$KEY_OUTPUT"
    KEY_NAME=$(printf '%s\n' "$KEY_OUTPUT" | sed -n 's/^Key Name: //p' | tail -1)
    test -n "$KEY_NAME"
    printf '%s\n' "$KEY_NAME" > "$KEY_NAME_FILE"
    chmod 600 "$KEY_NAME_FILE"
fi

mkdir -p "$CERT_DIR"
rm -f "$CERT_DIR/citizen-registry.key" /tmp/citizen-registry.csr
openssl req -new -engine pkcs11 -keyform engine -key "$P11_URI" \
    -out /tmp/citizen-registry.csr \
    -subj '/C=NL/O=Norland IT Department/OU=Citizen Registry/CN=citizen-registry.internal'
printf '%s\n' \
    'basicConstraints=critical,CA:FALSE' \
    'keyUsage=critical,digitalSignature,keyEncipherment' \
    'extendedKeyUsage=serverAuth' \
    "subjectAltName=DNS:citizen-registry.internal,IP:${SERVER_IP}" \
    > /tmp/server-ext.cnf
openssl x509 -req -in /tmp/citizen-registry.csr \
    -CA "$CERT_DIR/client-ca.crt" \
    -CAkey "$CERT_DIR/client-ca.key" \
    -CAcreateserial \
    -out "$CERT_DIR/citizen-registry.crt" \
    -days 365 -sha256 -extfile /tmp/server-ext.cnf
chmod 644 "$CERT_DIR/citizen-registry.crt"

cp /opt/citizen-registry/app-src/nginx.conf /etc/nginx/nginx.conf
sed -i "s|ssl_certificate_key /etc/citizen-registry/certs/citizen-registry.key;|ssl_certificate_key engine:pkcs11:${P11_URI};|" /etc/nginx/nginx.conf
grep -Fq "ssl_certificate_key engine:pkcs11:${P11_URI};" /etc/nginx/nginx.conf
mkdir -p /etc/systemd/system/nginx.service.d
cat > /etc/systemd/system/nginx.service.d/managed-hsm.conf <<EOF
[Service]
Environment=OPENSSL_CONF=${OPENSSL_CONFIG}
EOF
systemctl daemon-reload
OPENSSL_CONF="$OPENSSL_CONFIG" nginx -t
systemctl enable nginx
systemctl restart nginx
test ! -e "$CERT_DIR/citizen-registry.key"
curl -kfsS --resolve citizen-registry.internal:443:127.0.0.1 https://citizen-registry.internal/health >/dev/null
echo "MANAGED_HSM_TLS_KEY_NAME=$(cat "$KEY_NAME_FILE")"
echo 'MANAGED_HSM_TLS_READY=1'

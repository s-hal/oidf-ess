#!/usr/bin/env bash
# bootstrap-oidf-ess.sh
# Idempotent bootstrap for oidf-ess.
# - Creates EC JWK private/public and JWKS (default P-256) via a Python keygen tool
# - Creates TLS cert/key for NGINX with SANs
# - Writes minimal metadata and .env if missing
# - Enforces sane permissions
set -euo pipefail

# Defaults (override via env or flags)
ENTITY_ID="${ENTITY_ID:-https://entity.example.org}"
CERT_HOSTS="${CERT_HOSTS:-entity.example.org,localhost,127.0.0.1}"
CURVE="${CURVE:-P-256}"                     # P-256, P-384, or P-521
OUT_DIR="${OUT_DIR:-.}"                     # repo root
FORCE="${FORCE:-false}"                     # set true or pass --force

# Paths
SECRETS_DIR="${OUT_DIR}/secrets"
CONFIG_DIR="${OUT_DIR}/config"
WWW_DIR="${OUT_DIR}/data/www/.well-known"
VENV_DIR="${OUT_DIR}/venv"
TOOLS_DIR="${OUT_DIR}/tools"
KEYGEN="${TOOLS_DIR}/ess_keygen.py"

# TLS artifacts
TLS_DIR="${OUT_DIR}/nginx/https_certs"
TLS_KEY="${TLS_DIR}/https.key"
TLS_CERT="${TLS_DIR}/https.crt"

# Args
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=true ;;
    --entity-id=*) ENTITY_ID="${arg#*=}" ;;
    --cert-hosts=*) CERT_HOSTS="${arg#*=}" ;;
    --curve=*) CURVE="${arg#*=}" ;;
    --out-dir=*)
      OUT_DIR="${arg#*=}"
      SECRETS_DIR="${OUT_DIR}/secrets"
      CONFIG_DIR="${OUT_DIR}/config"
      WWW_DIR="${OUT_DIR}/data/www/.well-known"
      VENV_DIR="${OUT_DIR}/venv"
      TOOLS_DIR="${OUT_DIR}/tools"
      KEYGEN="${TOOLS_DIR}/ess_keygen.py"
      TLS_DIR="${OUT_DIR}/nginx/https_certs"
      TLS_KEY="${TLS_DIR}/https.key"
      TLS_CERT="${TLS_DIR}/https.crt"
      ;;
    *) echo "Unknown arg: $arg" >&2; exit 2 ;;
  esac
done

# Helpers
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 127; }; }
say()  { printf '%s\n' "$*"; }

need bash
need openssl
need python3
need uuidgen

# Python venv and deps
if [[ ! -d "$VENV_DIR" ]]; then
  python3 -m venv "$VENV_DIR"
  say "Created venv: $VENV_DIR"
fi

source "$VENV_DIR/bin/activate"
pip -q install --upgrade pip >/dev/null
pip -q install -r requirements.txt >/dev/null

mkdir -p "$SECRETS_DIR" "$CONFIG_DIR" "$WWW_DIR" "$TLS_DIR"

# Filenames
KID="$(uuidgen | tr 'A-Z' 'a-z')"
PRIV_JWK="${SECRETS_DIR}/fed-es256-private.jwk"
PUB_JWK="${CONFIG_DIR}/fed-es256-public.jwk"
JWKS_JSON="${CONFIG_DIR}/fed-jwks.json"
ES_PATH="${WWW_DIR}/openid-federation"  # .well-known/openid-federation

#  Generate EC JWKs and JWKS
set +e

python "$KEYGEN" \
  --curve P-256 \
  --kid "$KID" \
  --out-private "$PRIV_JWK" \
  --out-public "$PUB_JWK" \
  --out-jwks "$JWKS_JSON" \
  $([[ "$FORCE" == "true" ]] && echo --force)
rc=$?
set -e
if [[ $rc -ne 0 && "$FORCE" != "true" ]]; then
  say "Keys already exist. Skipping generation. Use --force to overwrite."
fi

# Permissions sanity (don't fail if absent due to skip)
chmod 600 "$PRIV_JWK" 2>/dev/null || true
chmod 644 "$PUB_JWK" "$JWKS_JSON" 2>/dev/null || true

# Create self-signed TLS cert for NGINX
IFS=',' read -r -a HOSTS <<< "${CERT_HOSTS:-localhost}"
CN="${HOSTS[0]}"
# Build SAN list: DNS:... or IP:...
SAN_ENTRIES=()
for h in "${HOSTS[@]}"; do
  if [[ "$h" =~ ^[0-9.]+$ ]]; then SAN_ENTRIES+=("IP:${h}"); else SAN_ENTRIES+=("DNS:${h}"); fi
done
SAN_CSV=$(IFS=','; echo "${SAN_ENTRIES[*]}")

if [[ ! -e "$TLS_KEY" || ! -e "$TLS_CERT" || "$FORCE" == "true" ]]; then
  mkdir -p "$TLS_DIR"
  openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout "$TLS_KEY" -out "$TLS_CERT" -days 3650 -sha256 \
    -subj "/CN=${CN}" \
    -addext "subjectAltName=${SAN_CSV}" >/dev/null 2>&1
  chmod 600 "$TLS_KEY"
  chmod 644 "$TLS_CERT"
  say "Generated self-signed RSA cert for: ${CERT_HOSTS:-localhost}"
else
  say "TLS cert exists. Use --force to regenerate."
fi

# Create .env
ENV_FILE="${OUT_DIR}/.env"
if [[ ! -f "$ENV_FILE" || "$FORCE" == "true" ]]; then
  cat > "$ENV_FILE" <<EOF
UID=${UID:-$(id -u)}
GID=${GID:-$(id -g)}
ENTITY_ID=${ENTITY_ID}
EXP_SECONDS=86400
RESIGN_INTERVAL=3600
JWKS_PATH=/config/fed-jwks.json
META_PATH=/config/entity-metadata.json
OUTPUT_PATH=/out/.well-known/openid-federation
EOF
  say "Wrote: $ENV_FILE"
fi

#  Touch published file path so NGINX can serve it
touch "$ES_PATH"
chmod 644 "$ES_PATH"

# Summary
cat <<EOF

Bootstrap complete.

 Entity ID:        $ENTITY_ID
 Curve:            $CURVE
 Key KID:          $KID
 Private JWK:      $PRIV_JWK
 Public JWK:       $PUB_JWK
 JWKS:             $JWKS_JSON
 TLS key:          $TLS_KEY
 TLS cert:         $TLS_CERT
 .env:             $ENV_FILE
 Publish target:   $ES_PATH

Next:
 - Start docker compose. The signer will read keys and metadata, sign, and publish to .well-known.
 - If terminating TLS in NGINX, point it to: ${TLS_CERT} and ${TLS_KEY}

Tips:
 - Override defaults: ENTITY_ID=https://entity.example.org CERT_HOSTS='entity.example.org,api.example.org' ./bootstrap-oidf-ess.sh
 - Use --curve to pick P-384 or P-521. Default is P-256.
 - Re-run with --force to rotate keys and regenerate artifacts.
EOF

#!/usr/bin/env bash
# Generate ES256 key pair for EAR JWT signing by the verifier.
set -euo pipefail

KEYS_DIR="$(cd "$(dirname "$0")/.." && pwd)/config/keys"
mkdir -p "$KEYS_DIR"

if [[ -f "$KEYS_DIR/ear_signing.pem" ]]; then
  echo "$KEYS_DIR/ear_signing.pem already exists, skipping"
  exit 0
fi

openssl ecparam -genkey -name prime256v1 -noout -out "$KEYS_DIR/ear_signing_sec1.pem"
openssl pkcs8 -topk8 -nocrypt -in "$KEYS_DIR/ear_signing_sec1.pem" -out "$KEYS_DIR/ear_signing.pem"
rm "$KEYS_DIR/ear_signing_sec1.pem"
openssl pkey -in "$KEYS_DIR/ear_signing.pem" -pubout -out "$KEYS_DIR/ear_public.pem"
echo "Generated key pair:"
echo "  $KEYS_DIR/ear_signing.pem"
echo "  $KEYS_DIR/ear_public.pem"

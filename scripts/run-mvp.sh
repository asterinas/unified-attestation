#!/usr/bin/env bash
# End-to-end mock mode (gRPC chain + RP trigger):
#   1. Generate key pair (first run)
#   2. Build mock component
#   3. Start verifier
#   4. Start attester
#   5. RP triggers full flow and validates EAR
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

bash scripts/gen-keys.sh
bash scripts/build-appraisers.sh

cargo build

cargo run -p verifier -- --config config/verifier.toml &
VERIFIER_PID=$!
cargo run -p attester -- --config config/attester.toml &
ATTESTER_PID=$!
trap 'kill $VERIFIER_PID $ATTESTER_PID 2>/dev/null || true' EXIT

# Wait for services to start
sleep 3

cargo run -p relying-party -- \
    --attester http://127.0.0.1:9000 \
    --verifier http://127.0.0.1:8080 \
    --tee-type mock \
    --pubkey config/keys/ear_public.pem \
    --ear-out /tmp/ear.jwt

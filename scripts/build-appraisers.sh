#!/usr/bin/env bash
# Build all appraisers to wasm components with cargo-component (target/wasm32-wasip1/release/).
#
# Install cargo-component: cargo install cargo-component --locked
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v cargo-component >/dev/null 2>&1; then
  echo "cargo-component is required: cargo install cargo-component --locked"
  exit 1
fi

cargo component build --release \
  -p mock-appraiser \
  -p cca-appraiser \
  -p cca-hydra-appraiser \
  -p csv-appraiser \
  -p csv-hydra-appraiser \
  -p tdx-appraiser \
  -p tdx-hydra-appraiser \
  -p itrustee-appraiser \
  -p itrustee-hydra-appraiser \
  -p virtcca-appraiser \
  -p virtcca-hydra-appraiser
ls -lh "$ROOT/target/wasm32-wasip1/release/"*.wasm

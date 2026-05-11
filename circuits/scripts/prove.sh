#!/usr/bin/env bash
# Generate witness + Groth16 proof for the valid input.
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p generated

echo "[prove] building canonical inputs..."
node scripts/build_inputs.js

echo "[prove] generating witness from valid_input.json..."
node generated/deposit_binding_js/generate_witness.js \
    generated/deposit_binding_js/deposit_binding.wasm \
    inputs/valid_input.json \
    generated/witness_valid.wtns

echo "[prove] groth16 prove (zkey + witness)..."
snarkjs groth16 prove \
    generated/deposit_binding_final.zkey \
    generated/witness_valid.wtns \
    generated/proof_valid.json \
    generated/public_valid.json

echo "[prove] OK."
echo "  - proof:           generated/proof_valid.json"
echo "  - public_signals:  generated/public_valid.json"
cat generated/public_valid.json

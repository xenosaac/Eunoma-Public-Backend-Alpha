#!/usr/bin/env bash
# Compile the deposit-binding circuit.
# Outputs:
#   generated/deposit_binding.r1cs   — R1CS constraint system
#   generated/deposit_binding.wasm   — witness generator wasm
#   generated/deposit_binding.sym    — symbol map
#   generated/deposit_binding_js/    — js helper (witness generator)
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p generated

echo "[compile] circom version: $(circom --version)"
echo "[compile] compiling deposit_binding.circom (BN254, --r1cs --wasm --sym)..."

circom deposit_binding.circom \
    --r1cs \
    --wasm \
    --sym \
    --output generated \
    -l node_modules

# Reports
echo "[compile] info:"
snarkjs r1cs info generated/deposit_binding.r1cs

echo "[compile] OK. Artifacts at circuits/generated/"

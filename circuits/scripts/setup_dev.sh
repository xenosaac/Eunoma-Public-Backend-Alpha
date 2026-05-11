#!/usr/bin/env bash
# Development-grade trusted setup. NOT for production.
#
# Generates:
#   generated/pot15.ptau          — power-of-tau (2^15 = 32k constraint headroom)
#   generated/deposit_binding_0000.zkey
#   generated/deposit_binding_final.zkey
#   generated/deposit_binding_vk.json
#
# For production / Gate 4d testnet, replace this with a real Phase-2 ceremony.
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p generated
cd generated

if [ ! -f pot15_final.ptau ]; then
  echo "[setup] phase 1: powersoftau new (BN254, power 15 = 32k constraints)..."
  snarkjs powersoftau new bn128 15 pot15_0000.ptau -v

  echo "[setup] phase 1: contributing entropy (single contributor, dev grade)..."
  snarkjs powersoftau contribute pot15_0000.ptau pot15_0001.ptau \
      --name="aptosshield dev contributor" -v -e="aptosshield-dev-entropy-2026-05-07"

  echo "[setup] phase 1: preparing for phase 2..."
  snarkjs powersoftau prepare phase2 pot15_0001.ptau pot15_final.ptau -v

  rm -f pot15_0000.ptau pot15_0001.ptau
fi

echo "[setup] phase 2: groth16 setup..."
snarkjs groth16 setup deposit_binding.r1cs pot15_final.ptau deposit_binding_0000.zkey

echo "[setup] phase 2: contributing zkey entropy..."
snarkjs zkey contribute deposit_binding_0000.zkey deposit_binding_final.zkey \
    --name="aptosshield dev zkey contributor" -v \
    -e="aptosshield-dev-zkey-entropy-2026-05-07"

echo "[setup] exporting verification key..."
snarkjs zkey export verificationkey deposit_binding_final.zkey deposit_binding_vk.json

rm -f deposit_binding_0000.zkey

echo "[setup] OK. Artifacts:"
ls -la *.zkey *.ptau deposit_binding_vk.json

#!/usr/bin/env bash
# ASP v-next dev trusted setup. NOT for production (single dev contributor).
#
# Sets up the NEW withdraw (12 publics / hardened dual LeanIMT) + ragequit circuits from a
# power-16 powers-of-tau (43,422 / 19,329 constraints both exceed pot15's 32,768).
#
# DOES NOT touch deposit_binding (FROZEN — its zkey/VK must stay byte-identical to the CP0
# oracle; re-running its groth16 setup would change the VK).
#
# Requires generated/pot16_final.ptau (generate via: powersoftau new bn128 16 → contribute →
# prepare phase2). Outputs: withdrawal_proof_final.zkey + _vk.json, ragequit_final.zkey + _vk.json.
set -euo pipefail
cd "$(dirname "$0")/.."
cd generated

if [ ! -f pot16_final.ptau ]; then
  echo "[setup_asp] ERROR: pot16_final.ptau missing. Generate it first:" >&2
  echo "  snarkjs powersoftau new bn128 16 pot16_0000.ptau -v" >&2
  echo "  snarkjs powersoftau contribute pot16_0000.ptau pot16_0001.ptau -e=... -v" >&2
  echo "  snarkjs powersoftau prepare phase2 pot16_0001.ptau pot16_final.ptau -v" >&2
  exit 1
fi

setup_circuit() {
  local name="$1"
  echo "[setup_asp] groth16 setup ${name} (from pot16)..."
  snarkjs groth16 setup "${name}.r1cs" pot16_final.ptau "${name}_0000.zkey"
  echo "[setup_asp] contributing zkey entropy (${name})..."
  snarkjs zkey contribute "${name}_0000.zkey" "${name}_final.zkey" \
      --name="eunoma asp dev zkey ${name}" -v \
      -e="eunoma-asp-dev-zkey-${name}-entropy-2026-05-30"
  echo "[setup_asp] exporting VK (${name})..."
  snarkjs zkey export verificationkey "${name}_final.zkey" "${name}_vk.json"
  rm -f "${name}_0000.zkey"
}

setup_circuit withdrawal_proof
setup_circuit ragequit

echo "[setup_asp] OK:"
ls -la withdrawal_proof_final.zkey withdrawal_proof_vk.json ragequit_final.zkey ragequit_vk.json

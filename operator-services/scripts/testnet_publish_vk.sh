#!/usr/bin/env bash
# Phase F W3 — publish deposit-binding VK (testnet variant, 4 publics, 5 IC slots).
# Reads VK JSON and submits 9 hex args (alpha, beta, gamma, delta, ic_0..ic_4).
# BRIDGE_ADDR is overridable via env so the same script works for fresh-address
# Phase F deploys (W3 deploys to a NEW testnet address; ABI for publish_*_vk
# changed shape from 7→5 IC slots so the old 0x8268f5… address cannot consume
# this VK).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VK_FILE="$REPO_ROOT/circuits/generated/move_fixtures/vk_bytes.json"
BRIDGE_ADDR="${BRIDGE_ADDR:-0x8268f56bdd9814d1cc925b861eaa1203d41c7f5425b3d2df887f618ffeb24820}"
PROFILE="${PROFILE:-eunoma-admin}"

if [[ ! -f "$VK_FILE" ]]; then
  echo "ERROR: VK file not found: $VK_FILE" >&2
  exit 1
fi

# Extract VK fields via python (jq may not be present).
ALPHA_G1=$(python3 -c "import json; print(json.load(open('$VK_FILE'))['alpha_g1'])")
BETA_G2=$(python3 -c "import json; print(json.load(open('$VK_FILE'))['beta_g2'])")
GAMMA_G2=$(python3 -c "import json; print(json.load(open('$VK_FILE'))['gamma_g2'])")
DELTA_G2=$(python3 -c "import json; print(json.load(open('$VK_FILE'))['delta_g2'])")
IC0=$(python3 -c "import json; print(json.load(open('$VK_FILE'))['ic'][0])")
IC1=$(python3 -c "import json; print(json.load(open('$VK_FILE'))['ic'][1])")
IC2=$(python3 -c "import json; print(json.load(open('$VK_FILE'))['ic'][2])")
IC3=$(python3 -c "import json; print(json.load(open('$VK_FILE'))['ic'][3])")
IC4=$(python3 -c "import json; print(json.load(open('$VK_FILE'))['ic'][4])")

cd "$REPO_ROOT"

echo "Publishing deposit-binding VK to $BRIDGE_ADDR (Phase F W3: 5 IC slots) ..."
aptos move run \
  --profile "$PROFILE" \
  --function-id "${BRIDGE_ADDR}::eunoma_bridge::publish_deposit_binding_vk" \
  --args "hex:${ALPHA_G1}" "hex:${BETA_G2}" "hex:${GAMMA_G2}" "hex:${DELTA_G2}" \
         "hex:${IC0}" "hex:${IC1}" "hex:${IC2}" "hex:${IC3}" "hex:${IC4}" \
  --max-gas 200000 \
  --assume-yes

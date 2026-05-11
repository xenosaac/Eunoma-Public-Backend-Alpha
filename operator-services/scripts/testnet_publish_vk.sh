#!/usr/bin/env bash
# Phase 4 — publish deposit-binding VK from circuits/generated/move_fixtures/vk_bytes.json.
# Reads the VK JSON, extracts the 11 hex strings (alpha_g1, beta_g2, gamma_g2, delta_g2, ic[0..6]),
# and submits them via aptos move run as 11 hex args.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VK_FILE="$REPO_ROOT/circuits/generated/move_fixtures/vk_bytes.json"
BRIDGE_ADDR="0x8268f56bdd9814d1cc925b861eaa1203d41c7f5425b3d2df887f618ffeb24820"

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
IC5=$(python3 -c "import json; print(json.load(open('$VK_FILE'))['ic'][5])")
IC6=$(python3 -c "import json; print(json.load(open('$VK_FILE'))['ic'][6])")

cd "$REPO_ROOT"

echo "Publishing deposit-binding VK to $BRIDGE_ADDR ..."
aptos move run \
  --profile eunoma-admin \
  --function-id "${BRIDGE_ADDR}::eunoma_bridge::publish_deposit_binding_vk" \
  --args "hex:${ALPHA_G1}" "hex:${BETA_G2}" "hex:${GAMMA_G2}" "hex:${DELTA_G2}" \
         "hex:${IC0}" "hex:${IC1}" "hex:${IC2}" "hex:${IC3}" \
         "hex:${IC4}" "hex:${IC5}" "hex:${IC6}" \
  --max-gas 200000 \
  --assume-yes

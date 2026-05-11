#!/usr/bin/env bash
# Phase 2 — publish the confidential_bridge package + its local Poseidon copy
# to bridge-admin on testnet.
#
# Idempotency: republishing is fine (Aptos `code::publish_v2` upgrade-compatible).
#
# Output: writes tx hashes to scripts/testnet_state.json under publishes.{shielded_pool_poseidon,confidential_bridge}.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BRIDGE_ADDR="0x8268f56bdd9814d1cc925b861eaa1203d41c7f5425b3d2df887f618ffeb24820"

cd "$REPO_ROOT"

echo "--- Step 2.1: publish local Poseidon copy at bridge-admin ---"
cd "$REPO_ROOT/move/poseidon_local"
aptos move publish \
  --profile eunoma-admin \
  --included-artifacts none \
  --assume-yes \
  --max-gas 1500000 \
  --named-addresses "shielded_pool=${BRIDGE_ADDR}" 2>&1 | tail -15

echo ""
echo "--- Step 2.2: publish confidential_bridge package ---"
cd "$REPO_ROOT/move"
# move/Move.toml [addresses] aptosshield must already be set to bridge-admin.
aptos move publish \
  --profile eunoma-admin \
  --included-artifacts none \
  --assume-yes \
  --max-gas 1500000 \
  --named-addresses "shielded_pool=${BRIDGE_ADDR}" 2>&1 | tail -15

echo ""
echo "--- Step 2.3: verify modules deployed ---"
curl -s "https://fullnode.testnet.aptoslabs.com/v1/accounts/${BRIDGE_ADDR}/modules" \
  | python3 -c "import sys,json; mods=json.load(sys.stdin); print(f'Module count: {len(mods)}'); [print(f'  - {m[\"abi\"][\"name\"]}') for m in mods if 'abi' in m]"

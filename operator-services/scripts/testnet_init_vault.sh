#!/usr/bin/env bash
# Phase 3 — invoke init_vault_with_ca_registration on testnet.
# Reads operator pubkeys from .operator-keys.json (created by testnet_init_vault.ts).
#
# Usage: $0 [--simulate]
#
# WARNING: This currently submits with EMPTY sigma proofs. Testnet's
# 0x1::confidential_asset::register_raw will abort. The captured abort code is
# Gate 4d evidence of testnet entry-arg-shape parity. To produce VALID sigma
# proofs, port from @aptos-labs/confidential-assets package src/proofs/ (the
# package is hardcoded to devnet 0x7 and cannot be used as-is on testnet).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYS_FILE="$SCRIPT_DIR/.operator-keys.json"
BRIDGE_ADDR="0x8268f56bdd9814d1cc925b861eaa1203d41c7f5425b3d2df887f618ffeb24820"
APT_METADATA="0xa"
VAULT_SEED_HEX="65756e6f6d612d627269646765"  # "eunoma-bridge"
VAULT_EK_HEX=$(printf '00%.0s' $(seq 1 32))  # 32-byte zeros

[[ -f "$KEYS_FILE" ]] || { echo "Missing $KEYS_FILE — run testnet_init_vault.ts first." >&2; exit 1; }

SIM_FLAG=""
[[ "${1:-}" == "--simulate" ]] && SIM_FLAG="--simulate"

# Build the operator_pubkeys vector arg ("hex:HEX1,HEX2,...").
PUBKEYS_CSV=$(python3 - <<EOF
import json
keys = json.load(open("$KEYS_FILE"))
print(",".join(k["public_key"].replace("0x","") for k in keys))
EOF
)

# Build the empty sigma proof vector args.
EMPTY_VEC="hex:"  # an empty vector<vector<u8>>

cd "$REPO_ROOT"

# Invoke. Note: the CLI accepts vector<vector<u8>> as comma-separated 'hex:' segments via 'hex:H1,H2,...'.
aptos move run \
  --profile eunoma-admin \
  --function-id "${BRIDGE_ADDR}::eunoma_bridge::init_vault_with_ca_registration" \
  --args "address:${BRIDGE_ADDR}" \
         "address:${APT_METADATA}" \
         "hex:${PUBKEYS_CSV}" \
         "u64:0" \
         "u64:4" \
         "hex:${VAULT_SEED_HEX}" \
         "hex:${VAULT_EK_HEX}" \
         "hex:" \
         "hex:" \
  --max-gas 2000000 \
  --assume-yes \
  $SIM_FLAG

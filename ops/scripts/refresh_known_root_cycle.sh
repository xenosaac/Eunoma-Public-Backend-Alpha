#!/usr/bin/env bash
# R7-OPS-1+OPS-2 wrapper: normalize if needed, rollover vault pending → available
# (OPS-2), normalize again if needed, then refresh
# on-disk commitment tree from chain DepositConfirmedV2 events, then submit a new
# known_root_v2 via the recorder-delegate path (OPS-1). Both delegate paths sign
# with testnet-relayer; admin previously delegated via admin_set_recorder_delegate.
#
# Invoked by systemd unit eunoma-record-known-root.service (Type=oneshot).
# Idempotent:
#   - rollover: CA framework's rollover_pending_balance is no-op when pending empty
#   - tree builder rewrites JSON with same hash on no-change
#   - record_known_root no-ops via Move's table::contains check
#
# Order matters: rollover MUST run BEFORE record_known_root for a new root so that
# when a user withdraws against that root, the freshly-deposited funds are already
# in vault available_balance (the chunkSubtract minuend).
#
# Exits non-zero on hard failure (timer will retry next cycle).
set -euo pipefail

LOCK_FILE=${EUNOMA_REFRESH_KNOWN_ROOT_LOCK:-/tmp/eunoma-refresh-known-root-cycle.lock}
exec 9>"${LOCK_FILE}"
if ! flock -n 9; then
  echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: another cycle is already running; exiting clean"
  exit 0
fi

cd /opt/eunoma/backend-deoperator-research

BRIDGE=0xa08850b1ca22cc5aa3a3a3fb1179cf3f1f169312cea8038ff1b1e3b4ace79ec1
VAULT=0xbbb0957ec8c26ab2652280c946dc35381dde6613b8ee9041ad6f467331dcd12a
ASSET=0xa
STATE_DIR=operator-services/.agent-local/eunoma-v2/coordinator
TREE_JSON=${STATE_DIR}/commitment_tree_v2.json
MIN_ANONYMITY_SET=${EUNOMA_MIN_ANONYMITY_SET:-8}

normalize_if_needed() {
  local step_label="$1"
  echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: normalize-if-needed (${step_label})"
  node operator-services/scripts/local_v2_normalize_full.mjs \
       --bridge-package-address "${BRIDGE}" \
       --vault-address "${VAULT}" \
       --asset-type "${ASSET}" \
       --via-delegate --delegate-profile testnet-relayer \
       --aptos-node-url "${APTOS_NODE_URL:-https://fullnode.testnet.aptoslabs.com}"
}

# NORMALIZE plan (2026-05-27): re-pack chain available_balance into the 4 × 16-bit
# chunk layout the CA framework requires for the next transfer / withdraw. Idempotent: the
# script's first action is `is_normalized(vault, asset_type)` view — when already-normalized
# it exits 0 with no chain tx. CA_DKG_V2_ROSTER_JSON_PATH must be in the
# service unit's Environment= block so the orchestrator can resolve `dkgEpoch` for the
# coordinator routes.
normalize_if_needed "before tree refresh"

echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: fetching deposit tx hashes via GraphQL"
TX_HASHES=$(/bin/bash /opt/eunoma/backend-deoperator-research/ops/scripts/fetch_deposit_tx_hashes.sh)
if [ -z "$TX_HASHES" ]; then
  echo "[$(date -u +%FT%TZ)] no deposit txs found yet, exiting clean"
  exit 0
fi
echo "[$(date -u +%FT%TZ)] fetched $(echo "$TX_HASHES" | tr ',' '\n' | wc -l) tx hashes"

echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: building commitment tree from chain events"
node operator-services/scripts/local_build_commitment_tree.mjs \
  --bridge-package-address "${BRIDGE}" \
  --vault-address "${VAULT}" \
  --asset-type "${ASSET}" \
  --tx-hashes "${TX_HASHES}" \
  --refresh

LATEST_ROOT=$(node -e 'const fs=require("fs"); const p=process.argv[1]; if (!fs.existsSync(p)) process.exit(0); const j=JSON.parse(fs.readFileSync(p,"utf8")); process.stdout.write(j.latestRootHex || "");' "${TREE_JSON}")
if [ -n "${LATEST_ROOT}" ]; then
  ROOT_PREFIX=${LATEST_ROOT#0x}
  ROOT_PREFIX=${ROOT_PREFIX:0:8}
  ROOT_SIDECAR=${STATE_DIR}/known_root_v2_${ROOT_PREFIX}.json
  if [ -f "${ROOT_SIDECAR}" ]; then
    echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: root ${LATEST_ROOT} already has side-car; skipping rollover"
  else
    echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: rolling over vault pending → available (OPS-2)"
    node operator-services/scripts/local_rollover_vault_pending.mjs \
           --bridge-package-address "${BRIDGE}" \
           --via-delegate --delegate-profile testnet-relayer

    normalize_if_needed "after rollover"
  fi
else
  echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: latest root missing from ${TREE_JSON}"
  exit 2
fi

echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: recording known_root via delegate"
node operator-services/scripts/local_record_known_root_v2.mjs \
  --commitment-tree "${TREE_JSON}" \
  --bridge-package-address "${BRIDGE}" \
  --via-delegate --delegate-profile testnet-relayer \
  --min-anonymity-set "${MIN_ANONYMITY_SET}"

echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: done"

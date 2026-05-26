#!/usr/bin/env bash
# R7-OPS-1+OPS-2 wrapper: rollover vault pending → available (OPS-2), then refresh
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
# Order matters: rollover MUST run BEFORE record_known_root so that when a user
# withdraws against the newly-recorded root, the freshly-deposited funds are
# already in vault available_balance (the chunkSubtract minuend).
#
# Exits non-zero on hard failure (timer will retry next cycle).
set -euo pipefail

cd /opt/eunoma/backend-deoperator-research

BRIDGE=0xa08850b1ca22cc5aa3a3a3fb1179cf3f1f169312cea8038ff1b1e3b4ace79ec1
VAULT=0xbbb0957ec8c26ab2652280c946dc35381dde6613b8ee9041ad6f467331dcd12a
ASSET=0xa
TREE_JSON=operator-services/.agent-local/eunoma-v2/coordinator/commitment_tree_v2.json
MIN_ANONYMITY_SET=${EUNOMA_MIN_ANONYMITY_SET:-8}

echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: rolling over vault pending → available (OPS-2)"
# OPS-2: rollover does NOT block the cycle on transient failure — if CA framework
# rejects (e.g., pending already empty in some edge case the framework treats as
# error), log + continue so the known_root path still runs. Real failure modes
# (delegate misconfigured, RPC down) will fail the rollover then ALSO fail the
# later record_known_root call → systemd reports cycle failure either way.
if ! node operator-services/scripts/local_rollover_vault_pending.mjs \
       --bridge-package-address "${BRIDGE}" \
       --via-delegate --delegate-profile testnet-relayer; then
  echo "[$(date -u +%FT%TZ)] rollover failed (continuing to known_root step; will retry next cycle)"
fi

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

echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: recording known_root via delegate"
node operator-services/scripts/local_record_known_root_v2.mjs \
  --commitment-tree "${TREE_JSON}" \
  --bridge-package-address "${BRIDGE}" \
  --via-delegate --delegate-profile testnet-relayer \
  --min-anonymity-set "${MIN_ANONYMITY_SET}"

echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: done"

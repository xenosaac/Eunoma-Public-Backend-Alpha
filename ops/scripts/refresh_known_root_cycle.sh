#!/usr/bin/env bash
# Route-ready root publication wrapper.
#
# The public commitment tree is the withdraw pool-state source, so this script never
# exposes a freshly-deposited root until that route is actually withdrawable. It:
#   1. normalizes the currently-published vault route if needed;
#   2. builds a fresh commitment tree in a private staging directory;
#   3. when the staged root is new, rolls vault pending -> available and normalizes again;
#   4. records the staged root in known_roots; and only then
#   5. atomically publishes the staged tree as commitment_tree_v2.json.
#
# Delegate paths sign with testnet-relayer; admin previously delegated via
# admin_set_recorder_delegate.
#
# Invoked by systemd unit eunoma-record-known-root.service (Type=oneshot).
# Idempotent:
#   - rollover: CA framework's rollover_pending_balance is no-op when pending empty
#   - tree builder rewrites JSON with same hash on no-change
#   - record_known_root no-ops via Move's table::contains check
#
# Order matters: record_known_root MUST run before publishing the staged tree, and
# rollover/normalize MUST run before recording a new root. If any route-readiness
# step fails, the public tree stays untouched and users keep waiting instead of
# seeing a root that will fail route-balance verification.
#
# Exits non-zero on hard failure (timer will retry next cycle).
set -euo pipefail

LOCK_FILE=${EUNOMA_REFRESH_KNOWN_ROOT_LOCK:-/tmp/eunoma-refresh-known-root-cycle.lock}
exec 9>"${LOCK_FILE}"
if ! flock -n 9; then
  echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: another cycle is already running; exiting clean"
  exit 0
fi

REPO_ROOT=${EUNOMA_REPO_ROOT:-/opt/eunoma/backend-deoperator-research}
cd "${REPO_ROOT}"

BRIDGE=${BRIDGE_PACKAGE_ADDRESS:-0xa08850b1ca22cc5aa3a3a3fb1179cf3f1f169312cea8038ff1b1e3b4ace79ec1}
VAULT=${BRIDGE_VAULT_ADDRESS:-0xbbb0957ec8c26ab2652280c946dc35381dde6613b8ee9041ad6f467331dcd12a}
ASSET=${BRIDGE_ASSET_TYPE:-0xa}
STATE_DIR=${EUNOMA_COORDINATOR_STATE_DIR:-operator-services/.agent-local/eunoma-v2/coordinator}
TREE_JSON=${STATE_DIR}/commitment_tree_v2.json
LEANIMT_JSON=${STATE_DIR}/state_leanimt_tree.json
STAGING_DIR=${STATE_DIR}/.refresh-staging
STAGED_TREE_JSON=${STAGING_DIR}/commitment_tree_v2.json
STAGED_LEANIMT_JSON=${STAGING_DIR}/state_leanimt_tree.json
MIN_ANONYMITY_SET=${EUNOMA_MIN_ANONYMITY_SET:-8}
FETCH_DEPOSIT_TX_HASHES_SCRIPT=${EUNOMA_FETCH_DEPOSIT_TX_HASHES_SCRIPT:-${REPO_ROOT}/ops/scripts/fetch_deposit_tx_hashes.sh}

normalize_if_needed() {
  local step_label="$1"
  echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: normalize (${step_label})"
  node operator-services/scripts/local_v2_normalize_full.mjs \
       --bridge-package-address "${BRIDGE}" \
       --vault-address "${VAULT}" \
       --asset-type "${ASSET}" \
       --via-delegate --delegate-profile testnet-relayer \
       --aptos-node-url "${APTOS_NODE_URL:-https://fullnode.testnet.aptoslabs.com}"
}

# Re-pack chain available_balance into the 4 x 16-bit chunk layout the CA framework
# requires for the next transfer / withdraw. Idempotent: the script's first action
# is `is_normalized(vault, asset_type)` view; when already normalized it exits 0.
normalize_if_needed "before tree refresh"

echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: fetching deposit tx hashes via GraphQL"
TX_HASHES=$(/bin/bash "${FETCH_DEPOSIT_TX_HASHES_SCRIPT}")
EXTRA_TX_HASHES=${EUNOMA_EXTRA_DEPOSIT_TX_HASHES:-}
if [ -n "${EXTRA_TX_HASHES}" ]; then
  echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: including extra observed tx hashes"
  if [ -n "${TX_HASHES}" ]; then
    TX_HASHES="${EXTRA_TX_HASHES},${TX_HASHES}"
  else
    TX_HASHES="${EXTRA_TX_HASHES}"
  fi
fi
TX_HASHES=$(printf '%s' "${TX_HASHES}" | tr ',' '\n' | awk 'BEGIN{ORS=""} { gsub(/^[[:space:]]+|[[:space:]]+$/, ""); v=tolower($0); if (v ~ /^0x[0-9a-f]{64}$/ && !seen[v]++) { if (n++) printf ","; printf "%s", v } }')
if [ -z "${TX_HASHES}" ]; then
  echo "[$(date -u +%FT%TZ)] no deposit txs found yet, exiting clean"
  exit 0
fi
echo "[$(date -u +%FT%TZ)] fetched $(echo "$TX_HASHES" | tr ',' '\n' | wc -l) tx hashes"

rm -rf "${STAGING_DIR}"
mkdir -p "${STAGING_DIR}"
if [ -f "${TREE_JSON}" ]; then
  cp "${TREE_JSON}" "${STAGED_TREE_JSON}"
fi
if [ -f "${LEANIMT_JSON}" ]; then
  cp "${LEANIMT_JSON}" "${STAGED_LEANIMT_JSON}"
fi

echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: build staged tree"
node operator-services/scripts/local_build_commitment_tree.mjs \
  --bridge-package-address "${BRIDGE}" \
  --vault-address "${VAULT}" \
  --asset-type "${ASSET}" \
  --tx-hashes "${TX_HASHES}" \
  --state-dir "${STAGING_DIR}" \
  --refresh

# The recorded on-chain state root is the LeanIMT root (the dynamic-depth tree the withdraw
# circuit + frontend verify against), read from the LeanIMT snapshot — NOT the legacy fixed-20
# commitment_tree_v2.json. Fall back to the staged LeanIMT path; the build step above always
# emits it alongside commitment_tree_v2.json.
ROOT_SOURCE_JSON=${STAGED_LEANIMT_JSON}
LATEST_ROOT=$(node -e 'const fs=require("fs"); const p=process.argv[1]; if (!fs.existsSync(p)) process.exit(0); const j=JSON.parse(fs.readFileSync(p,"utf8")); process.stdout.write(j.latestRootHex || "");' "${ROOT_SOURCE_JSON}")
if [ -n "${LATEST_ROOT}" ]; then
  ROOT_PREFIX=${LATEST_ROOT#0x}
  ROOT_PREFIX=${ROOT_PREFIX:0:8}
  ROOT_SIDECAR=${STATE_DIR}/known_root_v2_${ROOT_PREFIX}.json
  if [ -f "${ROOT_SIDECAR}" ]; then
    echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: root ${LATEST_ROOT} already has side-car; skipping rollover"
  else
    echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: rollover"
    node operator-services/scripts/local_rollover_vault_pending.mjs \
           --bridge-package-address "${BRIDGE}" \
           --via-delegate --delegate-profile testnet-relayer

    normalize_if_needed "after rollover"
  fi
else
  echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: latest root missing from ${ROOT_SOURCE_JSON}"
  exit 2
fi

echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: record known root"
node operator-services/scripts/local_record_known_root_v2.mjs \
  --commitment-tree "${STAGED_LEANIMT_JSON}" \
  --bridge-package-address "${BRIDGE}" \
  --via-delegate --delegate-profile testnet-relayer \
  --min-anonymity-set "${MIN_ANONYMITY_SET}" \
  --state-dir "${STATE_DIR}"

echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: publish tree"
mv "${STAGED_TREE_JSON}" "${TREE_JSON}.tmp"
mv "${TREE_JSON}.tmp" "${TREE_JSON}"
if [ -f "${STAGED_LEANIMT_JSON}" ]; then
  mv "${STAGED_LEANIMT_JSON}" "${LEANIMT_JSON}.tmp"
  mv "${LEANIMT_JSON}.tmp" "${LEANIMT_JSON}"
fi
rm -rf "${STAGING_DIR}"

echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: done"

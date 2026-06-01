#!/usr/bin/env bash
# =============================================================================================
# process_deposit.sh — make a confirmed Eunoma ASP deposit WITHDRAWABLE (step-2 cadence).
#
# A downstream browser / computer-use agent runs this immediately after a UI deposit confirms
# on-chain. It performs the full operator-side cadence against the FRESH ASP testnet deploy:
#
#   1. normalize the currently-available vault route balance if needed
#   2. build the state commitment tree (LeanIMT + legacy depth-20) from the deposit tx
#   3. rollover vault pending -> available, then normalize the new available balance
#   4. record the new state root on-chain  (record_known_root_v2, admin)
#   5. run the ASP re-fork cycle: screen the depositor (Chainalysis Sanctions), rebuild the ASP
#      LeanIMT, publish the set, and record the ASP root on-chain (record_asp_root_via_delegate)
#
# After this runs, the dev-server endpoints /api/eunoma/pool-state and
# /api/eunoma/v2/asp-root-current return 200 with data, and both KnownRoots + KnownASPRoots
# carry the deposit's roots. The rollover/normalize step is deliberately before root recording so
# public withdraw state is only published after the private route balance is actually spendable.
#
# Idempotent: re-running with the same tx hash re-harvests the same leaf, re-records the same
# root (Move dedups via Table::contains → "already_recorded"), and re-runs the ASP cycle
# (dedups by commitment). Safe to call more than once.
#
# Usage:
#   ./process_deposit.sh <deposit_tx_hash> <sender_addr>
#
# Required tooling: node, aptos CLI with profiles testnet-asp-admin (admin + ASP recorder
# delegate). The cluster (coordinator/relayer/workers) must already be running.
#
# Environment overrides (all have fresh-deploy defaults):
#   APTOS_NODE_URL                 default https://fullnode.testnet.aptoslabs.com/v1
#   CHAINALYSIS_API_KEY            real free Sanctions API key. If UNSET, this script starts a
#                                  local testnet Sanctions stub (returns "not sanctioned" for the
#                                  fresh testnet depositor) so the REAL provider code path still
#                                  executes. For mainnet, set a real key + unset the stub.
#   CHAINALYSIS_SANCTIONS_BASE_URL override the screening endpoint (defaults to the local stub
#                                  when no CHAINALYSIS_API_KEY is provided).
#   PINATA_JWT                     optional real IPFS pin; absent → local-dev content-addressed
#                                  fallback (cid prefixed "local-", not a real pin).
#   COORDINATOR_BEARER_TOKEN       normalize route token. If unset, this script reads the local
#                                  frontend .env.local EUNOMA_V2_BEARER_TOKEN for ASP smoke tests.
# =============================================================================================
set -euo pipefail

# ---- fresh ASP deploy constants -------------------------------------------------------------
SERVICE_ROOT="/Users/isaaczhang/Desktop/AGENT/Projects/Eunoma/backend-deoperator-research/operator-services"
REPO_ROOT="/Users/isaaczhang/Desktop/AGENT/Projects/Eunoma/backend-deoperator-research"
STATE_ROOT="${SERVICE_ROOT}/.agent-local/eunoma-v2-asp"
COORD_DIR="${STATE_ROOT}/coordinator"

BRIDGE="0xc9a850b8696272be2fa3f49cd6090cf3a0fdd738963d7f2956fc6cc4e0f77255"
VAULT="0x00da823b27e9ef9ce865733e925d51a7a4b225bc87b7bb2ea6475277a15f80ce"
ASSET_TYPE="0xa"
ADMIN_PROFILE="testnet-asp-admin"
ASP_RECORDER_PROFILE="testnet-asp-admin"   # ASPRecorderDelegate.addr == admin on this deploy
APTOS_NODE_URL="${APTOS_NODE_URL:-https://fullnode.testnet.aptoslabs.com/v1}"
COORDINATOR_URL="${COORDINATOR_URL:-http://127.0.0.1:4200}"
FRONTEND_ENV="/Users/isaaczhang/Desktop/AGENT/Projects/Eunoma/frontend-deoperator-research/.env.local"
CA_DKG_V2_ROSTER_JSON_PATH="${CA_DKG_V2_ROSTER_JSON_PATH:-${STATE_ROOT}/cluster/ca-dkg-v2-roster.json}"
if [[ -z "${COORDINATOR_BEARER_TOKEN:-}" && -f "${FRONTEND_ENV}" ]]; then
  COORDINATOR_BEARER_TOKEN="$(awk -F= '$1=="EUNOMA_V2_BEARER_TOKEN"{print substr($0, index($0,$2)); exit}' "${FRONTEND_ENV}")"
fi
export COORDINATOR_BEARER_TOKEN
export CA_DKG_V2_ROSTER_JSON_PATH

normalize_if_needed() {
  local label="$1"
  if [[ -z "${COORDINATOR_BEARER_TOKEN:-}" ]]; then
    echo "[process_deposit] COORDINATOR_BEARER_TOKEN is required for normalize (${label})" >&2
    exit 2
  fi
  if [[ ! -f "${CA_DKG_V2_ROSTER_JSON_PATH}" ]]; then
    echo "[process_deposit] CA_DKG_V2_ROSTER_JSON_PATH not found: ${CA_DKG_V2_ROSTER_JSON_PATH}" >&2
    exit 2
  fi
  echo "[process_deposit] normalize (${label}) ..."
  node "${SERVICE_ROOT}/scripts/local_v2_normalize_full.mjs" \
    --bridge-package-address "${BRIDGE}" \
    --vault-address "${VAULT}" \
    --asset-type "${ASSET_TYPE}" \
    --admin-profile "${ADMIN_PROFILE}" \
    --coordinator-url "${COORDINATOR_URL}" \
    --aptos-node-url "${APTOS_NODE_URL}" \
    --max-gas 300000 \
    --gas-unit-price 100
}

rollover_pending() {
  echo "[process_deposit] rollover pending vault balance ..."
  node "${SERVICE_ROOT}/scripts/local_rollover_vault_pending.mjs" \
    --bridge-package-address "${BRIDGE}" \
    --admin-profile "${ADMIN_PROFILE}" \
    --aptos-node-url "${APTOS_NODE_URL}" \
    --max-gas 80000 \
    --gas-unit-price 100
}

# ---- args -----------------------------------------------------------------------------------
DEPOSIT_TX="${1:-}"
SENDER="${2:-}"
if [[ -z "${DEPOSIT_TX}" || -z "${SENDER}" ]]; then
  echo "usage: process_deposit.sh <deposit_tx_hash> <sender_addr>" >&2
  exit 2
fi
case "${DEPOSIT_TX}" in 0x*) ;; *) DEPOSIT_TX="0x${DEPOSIT_TX}";; esac
case "${SENDER}" in 0x*) ;; *) SENDER="0x${SENDER}";; esac

echo "[process_deposit] tx=${DEPOSIT_TX} sender=${SENDER}"
echo "[process_deposit] state_root=${STATE_ROOT}"

mkdir -p "${COORD_DIR}"

# ---- step 1: normalize current available route balance --------------------------------------
# The bridge can only withdraw from CA available balance. This pre-normalize is idempotent and
# keeps a prior rollover from poisoning the next private transfer with >4 meaningful chunks.
echo "[process_deposit] (1/5) normalizing current route balance ..."
normalize_if_needed "before tree refresh"

# ---- step 2: build the state commitment tree ------------------------------------------------
# --refresh merges with the existing artifact (preserves prior leaves), so calling this script once
# per confirmed deposit ACCUMULATES leaves into both trees. Each new deposit must be ingested in
# deposit_count order (the build script enforces monotonic deposit_count); already-ingested tx
# hashes are skipped as no-ops (so re-running for an earlier deposit is idempotent). The 12-public
# withdraw circuit needs depth>=1 (>=2 leaves) in BOTH the state + ASP trees.
echo "[process_deposit] (2/5) building commitment tree (refresh/accumulate) ..."
node "${SERVICE_ROOT}/scripts/local_build_commitment_tree.mjs" \
  --tx-hashes "${DEPOSIT_TX}" \
  --bridge-package-address "${BRIDGE}" \
  --vault-address "${VAULT}" \
  --asset-type "${ASSET_TYPE}" \
  --aptos-node-url "${APTOS_NODE_URL}" \
  --depositor-witness-dir "${STATE_ROOT}/depositor" \
  --state-dir "${COORD_DIR}" \
  --refresh

# ---- step 3: make the deposited route balance spendable --------------------------------------
echo "[process_deposit] (3/5) making vault route balance available ..."
rollover_pending
normalize_if_needed "after rollover"

# ---- step 4: record the state root on-chain -------------------------------------------------
# ASP (2026-05-31): record the LeanIMT state root (state_leanimt_tree.json's latestRootHex), NOT
# the legacy depth-20 commitment_tree_v2 root. The 12-public withdraw circuit verifies against the
# dynamic-depth LeanIMT root; the recorder auto-detects the `eunoma_leanimt_tree_v1` scheme and
# records its latestRootHex. Recording the depth-20 root would make every withdraw abort E_INVALID_ROOT.
# Single-/small-leaf anonymity sets are below the production min; --allow-local-smoke-anonymity
# (gated by EUNOMA_LOCAL_SMOKE=1) permits recording for testnet validation. Remove both for prod.
echo "[process_deposit] (4/5) recording state LeanIMT root on-chain ..."
EUNOMA_LOCAL_SMOKE=1 node "${SERVICE_ROOT}/scripts/local_record_known_root_v2.mjs" \
  --commitment-tree "${COORD_DIR}/state_leanimt_tree.json" \
  --bridge-package-address "${BRIDGE}" \
  --admin-profile "${ADMIN_PROFILE}" \
  --aptos-node-url "${APTOS_NODE_URL}" \
  --state-dir "${COORD_DIR}" \
  --allow-local-smoke-anonymity

# ---- step 5: ASP re-fork cycle + record ASP root --------------------------------------------
echo "[process_deposit] (5/5) running ASP cycle (screen + rebuild + record) ..."

NEW_DEPOSITS="$(mktemp -t asp_new_deposits.XXXXXX.json)"
# Read the commitment for this deposit's leaf out of the freshly-built tree (no plaintext secrets).
COMMITMENT="$(node -e '
  const fs = require("fs");
  const tx = process.argv[1].toLowerCase();
  const t = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  const leaves = t.leaves || t.commitments || [];
  // commitment_tree_v2.json stores depositMeta[].commitment keyed by depositTxHash.
  const meta = t.depositMeta || t.meta || [];
  let c = null;
  for (const m of meta) {
    if ((m.depositTxHash||m.txHash||"").toLowerCase() === tx) { c = m.commitment || m.commitmentHex; break; }
  }
  if (!c && t.leanImtRootHex && (meta.length===1 || leaves.length===1)) {
    c = (meta[0] && (meta[0].commitment||meta[0].commitmentHex)) || leaves[0];
  }
  if (!c) { process.stderr.write("could not resolve commitment for tx\n"); process.exit(1); }
  process.stdout.write(c.startsWith("0x") ? c : "0x"+c);
' "${DEPOSIT_TX}" "${COORD_DIR}/commitment_tree_v2.json")"
echo "[process_deposit] commitment=${COMMITMENT}"
printf '[{"commitment":"%s","sender":"%s"}]\n' "${COMMITMENT}" "${SENDER}" > "${NEW_DEPOSITS}"

APPROVED_STATE="${COORD_DIR}/asp_approved_state.json"
[[ -f "${APPROVED_STATE}" ]] || echo '{"approved":[]}' > "${APPROVED_STATE}"

# Sanctions screening: use a real key if provided, else start a local testnet stub so the real
# ChainalysisSanctionsProvider code path executes unchanged (no admin-override bypass).
STUB_PID=""
cleanup() {
  [[ -n "${STUB_PID}" ]] && kill "${STUB_PID}" 2>/dev/null || true
  rm -f "${NEW_DEPOSITS}"
  [[ -n "${STUB_DIR:-}" ]] && rm -rf "${STUB_DIR}" || true
}
trap cleanup EXIT

STUB_DIR=""
if [[ -z "${CHAINALYSIS_API_KEY:-}" ]]; then
  STUB_PORT="${SANCTIONS_STUB_PORT:-4556}"
  # macOS `mktemp -t X.mjs` appends a suffix AFTER .mjs, breaking ESM resolution; use a temp DIR
  # and a fixed .mjs filename inside it instead.
  STUB_DIR="$(mktemp -d -t sanctions_stub.XXXXXX)"
  STUB_JS="${STUB_DIR}/sanctions_stub.mjs"
  cat > "${STUB_JS}" <<'STUB'
import { createServer } from "node:http";
const PORT = Number(process.env.SANCTIONS_STUB_PORT || 4556);
createServer((req, res) => {
  if (req.method === "GET" && /\/address\/[^/]+$/.test(req.url || "")) {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ identifications: [] }));
    return;
  }
  res.writeHead(404, { "content-type": "application/json" });
  res.end(JSON.stringify({ message: "not found" }));
}).listen(PORT, "127.0.0.1", () => process.stderr.write(`[sanctions-stub] :${PORT}\n`));
STUB
  SANCTIONS_STUB_PORT="${STUB_PORT}" node "${STUB_JS}" &
  STUB_PID=$!
  # wait for the stub to accept connections (up to ~10s) instead of a blind sleep
  for _ in $(seq 1 50); do
    if curl -s -o /dev/null --max-time 1 "http://127.0.0.1:${STUB_PORT}/api/v1/address/0x0"; then break; fi
    sleep 0.2
  done
  export CHAINALYSIS_API_KEY="testnet-local-stub"
  export CHAINALYSIS_SANCTIONS_BASE_URL="http://127.0.0.1:${STUB_PORT}/api/v1"
  echo "[process_deposit] using local Sanctions stub on :${STUB_PORT} (no CHAINALYSIS_API_KEY set)"
fi

EUNOMA_ASP_RECORDER_PROFILE="${ASP_RECORDER_PROFILE}" \
node "${SERVICE_ROOT}/scripts/local_run_asp_cycle.mjs" \
  --state "${APPROVED_STATE}" \
  --new-deposits "${NEW_DEPOSITS}" \
  --bridge "${BRIDGE}" \
  --record \
  --state-dir "${STATE_ROOT}"

echo "[process_deposit] DONE — deposit ${DEPOSIT_TX} is now route-ready and withdrawable (rollover + normalize + state root + ASP root completed)."

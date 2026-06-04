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
# Signing path is configurable. Alpha defaults to the admin profile because the
# ASP bridge has not delegated recorder/rollover authority to testnet-relayer.
# Set EUNOMA_REFRESH_SIGNER_MODE=delegate after admin_set_recorder_delegate is
# configured on-chain.
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
LOCK_DIR=""
if command -v flock >/dev/null 2>&1; then
  exec 9>"${LOCK_FILE}"
  if ! flock -n 9; then
    echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: another cycle is already running; exiting clean"
    exit 0
  fi
else
  LOCK_DIR="${LOCK_FILE}.d"
  if ! mkdir "${LOCK_DIR}" 2>/dev/null; then
    echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: another cycle is already running; exiting clean"
    exit 0
  fi
fi

REPO_ROOT=${EUNOMA_REPO_ROOT:-/opt/eunoma/backend-deoperator-research}
cd "${REPO_ROOT}"

BRIDGE=${BRIDGE_PACKAGE_ADDRESS:-0xa08850b1ca22cc5aa3a3a3fb1179cf3f1f169312cea8038ff1b1e3b4ace79ec1}
VAULT=${BRIDGE_VAULT_ADDRESS:-0xbbb0957ec8c26ab2652280c946dc35381dde6613b8ee9041ad6f467331dcd12a}
ASSET=${BRIDGE_ASSET_TYPE:-0xa}
CHAIN_ID=${BRIDGE_CHAIN_ID:-${EUNOMA_CHAIN_ID:-2}}
TREE_EVENT_VERSION=${EUNOMA_TREE_EVENT_VERSION:-}
if [ -z "${TREE_EVENT_VERSION}" ] && [ "${EUNOMA_V4_MODE:-0}" = "1" ]; then
  TREE_EVENT_VERSION=v4
fi
STATE_ROOT=${EUNOMA_STATE_ROOT:-${EUNOMA_LOCAL_STATE_ROOT:-operator-services/.agent-local/eunoma-v2}}
STATE_DIR=${EUNOMA_COORDINATOR_STATE_DIR:-${STATE_ROOT%/}/coordinator}
TREE_JSON=${STATE_DIR}/commitment_tree_v2.json
LEANIMT_JSON=${STATE_DIR}/state_leanimt_tree.json
ASP_SET_JSON=${STATE_DIR}/asp_set.json
ASP_APPROVED_STATE=${STATE_DIR}/asp_approved_state.json
STAGING_DIR=${STATE_DIR}/.refresh-staging
STAGED_TREE_JSON=${STAGING_DIR}/commitment_tree_v2.json
STAGED_LEANIMT_JSON=${STAGING_DIR}/state_leanimt_tree.json
STAGED_ASP_SET_JSON=${STAGING_DIR}/asp_set.json
STAGED_ASP_APPROVED_STATE=${STAGING_DIR}/asp_approved_state.json
STAGED_ASP_NEW_DEPOSITS_JSON=${STAGING_DIR}/asp_new_deposits.json
OBSERVED_QUEUE=${EUNOMA_OBSERVED_DEPOSIT_QUEUE:-${STATE_DIR}/observed_deposit_tx_hashes.queue}
MIN_ANONYMITY_SET=${EUNOMA_MIN_ANONYMITY_SET:-8}
FETCH_DEPOSIT_TX_HASHES_SCRIPT=${EUNOMA_FETCH_DEPOSIT_TX_HASHES_SCRIPT:-${REPO_ROOT}/ops/scripts/fetch_deposit_tx_hashes.sh}
SIGNER_MODE=${EUNOMA_REFRESH_SIGNER_MODE:-admin}
ADMIN_PROFILE=${EUNOMA_REFRESH_ADMIN_PROFILE:-${ADMIN_PROFILE:-testnet-admin}}
DELEGATE_PROFILE=${EUNOMA_REFRESH_DELEGATE_PROFILE:-${DELEGATE_PROFILE:-testnet-relayer}}
ASP_RECORDER_PROFILE=${EUNOMA_REFRESH_ASP_RECORDER_PROFILE:-${ASP_RECORDER_PROFILE:-${ADMIN_PROFILE}}}
ALLOW_TESTNET_SANCTIONS_STUB=${EUNOMA_ALLOW_TESTNET_SANCTIONS_STUB:-1}
SANCTIONS_STUB_PID=""
SANCTIONS_STUB_DIR=""

cleanup_sanctions_stub() {
  if [ -n "${SANCTIONS_STUB_PID}" ]; then
    kill "${SANCTIONS_STUB_PID}" 2>/dev/null || true
  fi
  if [ -n "${SANCTIONS_STUB_DIR}" ]; then
    rm -rf "${SANCTIONS_STUB_DIR}" 2>/dev/null || true
  fi
}
cleanup_on_exit() {
  cleanup_sanctions_stub
  if [ -n "${LOCK_DIR}" ]; then
    rm -rf "${LOCK_DIR}" 2>/dev/null || true
  fi
}
trap cleanup_on_exit EXIT

case "${SIGNER_MODE}" in
  admin)
    NORMALIZE_SIGNER_ARGS=(--admin-profile "${ADMIN_PROFILE}")
    ROLLOVER_SIGNER_ARGS=(--admin-profile "${ADMIN_PROFILE}")
    RECORD_SIGNER_ARGS=(--admin-profile "${ADMIN_PROFILE}")
    ;;
  delegate)
    NORMALIZE_SIGNER_ARGS=(--via-delegate --delegate-profile "${DELEGATE_PROFILE}")
    ROLLOVER_SIGNER_ARGS=(--via-delegate --delegate-profile "${DELEGATE_PROFILE}")
    RECORD_SIGNER_ARGS=(--via-delegate --delegate-profile "${DELEGATE_PROFILE}")
    ;;
  *)
    echo "invalid EUNOMA_REFRESH_SIGNER_MODE=${SIGNER_MODE}; expected admin or delegate" >&2
    exit 2
    ;;
esac

normalize_tx_hashes() {
  awk 'BEGIN{RS="[,\n\r\t ]+"; ORS=""}
    /^0x[0-9a-fA-F]{64}$/ {
      v=tolower($0);
      if (!seen[v]++) {
        if (n++) printf ",";
        printf "%s", v;
      }
    }'
}

count_tx_hashes() {
  if [ -z "$1" ]; then
    printf '0'
  else
    printf '%s' "$1" | tr ',' '\n' | awk 'NF { n++ } END { printf "%d", n + 0 }'
  fi
}

active_asset_allowlist() {
  local raw=${EUNOMA_ACTIVE_ASSET_ADDRS:-}
  if [ -z "${raw}" ]; then
    printf '%s=%s' "${ASSET}" "${VAULT}"
    return
  fi
  awk -v vault="${VAULT}" 'BEGIN{RS="[,\n\r\t ]+"; ORS=""}
    /^0x[0-9a-fA-F]{1,64}$/ {
      v=tolower($0);
      if (!seen[v]++) {
        if (n++) printf ",";
        printf "%s=%s", v, vault;
      }
    }' <<< "${raw}"
}

persist_observed_tx_hashes() {
  local raw_hashes="$1"
  local normalized
  normalized=$(printf '%s' "${raw_hashes}" | normalize_tx_hashes)
  if [ -z "${normalized}" ]; then
    return 0
  fi
  mkdir -p "$(dirname "${OBSERVED_QUEUE}")"
  {
    if [ -f "${OBSERVED_QUEUE}" ]; then
      cat "${OBSERVED_QUEUE}"
    fi
    printf '%s' "${normalized}" | tr ',' '\n'
  } | normalize_tx_hashes | tr ',' '\n' > "${OBSERVED_QUEUE}.tmp"
  mv "${OBSERVED_QUEUE}.tmp" "${OBSERVED_QUEUE}"
  echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: queued $(count_tx_hashes "${normalized}") observed tx hashes for durable retry"
}

read_observed_queue() {
  if [ ! -f "${OBSERVED_QUEUE}" ]; then
    return 0
  fi
  normalize_tx_hashes < "${OBSERVED_QUEUE}"
}

prune_observed_queue() {
  if [ ! -f "${OBSERVED_QUEUE}" ]; then
    return 0
  fi
  node -e '
const fs = require("fs");
const queuePath = process.argv[1];
const treePath = process.argv[2];
const normalize = (s) => (typeof s === "string" && /^0x[0-9a-fA-F]{64}$/.test(s) ? s.toLowerCase() : null);
const queue = fs.existsSync(queuePath)
  ? fs.readFileSync(queuePath, "utf8").split(/\s|,/).map(normalize).filter(Boolean)
  : [];
const tree = fs.existsSync(treePath) ? JSON.parse(fs.readFileSync(treePath, "utf8")) : {};
const published = new Set((tree.depositMeta || []).map((m) => normalize(m.depositTxHash)).filter(Boolean));
const skippedNoLeaf = new Set();
for (const note of tree.eventFeedNotes || []) {
  const m = typeof note === "string" ? note.match(/^skipped_no_leaf_event:(0x[0-9a-fA-F]{64})$/) : null;
  const h = m ? normalize(m[1]) : null;
  if (h) skippedNoLeaf.add(h);
}
const seen = new Set();
const remaining = [];
for (const h of queue) {
  if (seen.has(h) || published.has(h) || skippedNoLeaf.has(h)) continue;
  seen.add(h);
  remaining.push(h);
}
fs.writeFileSync(queuePath, remaining.length ? `${remaining.join("\n")}\n` : "");
console.log(`observed tx queue pruned: before=${queue.length} after=${remaining.length} skippedNoLeaf=${skippedNoLeaf.size}`);
' "${OBSERVED_QUEUE}" "${LEANIMT_JSON}"
}

load_route_observer_config() {
  node - "${STATE_ROOT}" "${VAULT}" "${ASSET}" "${CHAIN_ID}" <<'NODE'
const fs = require("fs");
const path = require("path");
const stateRoot = process.argv[2];
const expectedVault = process.argv[3];
const expectedAsset = process.argv[4];
const expectedChainId = Number(process.argv[5]);
const sh = (value) => `'${String(value).replace(/'/g, `'\\''`)}'`;
const parseJson = (value) => {
  try { return value ? JSON.parse(value) : null; } catch { return null; }
};
const readJson = (file) => {
  try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch { return null; }
};
const firstString = (...values) => values.find((v) => typeof v === "string" && v.length > 0);
const stripHex = (value) => typeof value === "string" ? value.replace(/^0x/i, "").toLowerCase() : "";
const normalizeHex64 = (value) => stripHex(value).padStart(64, "0");

const caRoster = parseJson(process.env.CA_DKG_V2_ROSTER_JSON);
const deopRoster = parseJson(process.env.DEOPERATOR_ROSTER_JSON);
const clusterRoster = readJson(path.join(stateRoot, "cluster", "roster.json"));
const localCluster = readJson(path.join(stateRoot, "cluster", "local-cluster.json"));
const localEnv = localCluster && localCluster.coordinator && localCluster.coordinator.env
  ? localCluster.coordinator.env
  : {};
const localCaRoster = parseJson(localEnv.CA_DKG_V2_ROSTER_JSON);
const localDeopRoster = parseJson(localEnv.DEOPERATOR_ROSTER_JSON);

let currentInit = null;
try {
  const initDir = path.join(stateRoot, "coordinator", "vault_state_v2");
  const expectedVaultNorm = normalizeHex64(expectedVault);
  const expectedAssetNorm = normalizeHex64(expectedAsset);
  const candidates = fs.readdirSync(initDir)
    .filter((name) => name.endsWith(".json"))
    .map((name) => {
      const file = path.join(initDir, name);
      let mtimeMs = 0;
      try { mtimeMs = fs.statSync(file).mtimeMs; } catch {}
      return { file, mtimeMs };
    })
    .sort((a, b) => b.mtimeMs - a.mtimeMs);
  for (const candidate of candidates) {
    const json = readJson(candidate.file);
    if (json?.scheme !== "vault_state_v2") continue;
    if (normalizeHex64(json.senderAddress) !== expectedVaultNorm) continue;
    if (normalizeHex64(json.assetType) !== expectedAssetNorm) continue;
    if (Number(json.chainId) !== expectedChainId) continue;
    currentInit = json;
    break;
  }
} catch {}

let transcriptHash = firstString(
  currentInit?.caDkgTranscriptHash,
  process.env.CA_DKG_TRANSCRIPT_HASH,
  process.env.CA_DKG_V2_TRANSCRIPT_HASH,
  process.env.EUNOMA_CA_DKG_TRANSCRIPT_HASH,
  localEnv.CA_DKG_TRANSCRIPT_HASH,
  localEnv.CA_DKG_V2_TRANSCRIPT_HASH,
);
if (!transcriptHash) {
  const dkgDir = path.join(stateRoot, "cluster", "dkg");
  let candidates = [];
  try {
    candidates = fs.readdirSync(dkgDir)
      .filter((name) => name.endsWith(".json"))
      .map((name) => {
        const file = path.join(dkgDir, name);
        let mtimeMs = 0;
        try { mtimeMs = fs.statSync(file).mtimeMs; } catch {}
        return { file, mtimeMs };
      })
      .sort((a, b) => b.mtimeMs - a.mtimeMs);
  } catch {}
  for (const candidate of candidates) {
    const json = readJson(candidate.file);
    transcriptHash = firstString(json?.caDkgTranscriptHash, json?.transcriptHash);
    if (transcriptHash) break;
  }
}

const dkgEpoch = firstString(
  currentInit?.dkgEpoch,
  process.env.DKG_EPOCH,
  caRoster?.dkgEpoch,
  localCaRoster?.dkgEpoch,
  deopRoster?.dkgEpoch,
  localDeopRoster?.dkgEpoch,
  clusterRoster?.dkgEpoch,
);
const vaultEk = firstString(
  currentInit?.vaultEk,
  process.env.VAULT_EK,
  deopRoster?.vaultEk,
  localDeopRoster?.vaultEk,
  clusterRoster?.vaultEk,
);
const coordinatorHost = firstString(process.env.COORDINATOR_HOST, localEnv.COORDINATOR_HOST, "127.0.0.1");
const coordinatorPort = firstString(process.env.COORDINATOR_PORT, localEnv.COORDINATOR_PORT, "4200");
const coordinatorUrl = firstString(
  process.env.COORDINATOR_URL,
  process.env.EUNOMA_COORDINATOR_URL,
  `http://${coordinatorHost}:${coordinatorPort}`,
);
const bearerToken = firstString(process.env.COORDINATOR_BEARER_TOKEN, localEnv.COORDINATOR_BEARER_TOKEN, "");
const missing = [];
if (!dkgEpoch) missing.push("dkgEpoch");
if (!vaultEk) missing.push("vaultEk");
if (!transcriptHash) missing.push("caDkgTranscriptHash");
if (missing.length > 0) {
  console.error(`route observer config missing: ${missing.join(", ")}`);
  process.exit(18);
}
console.log(`ROUTE_OBSERVER_DKG_EPOCH=${sh(dkgEpoch)}`);
console.log(`ROUTE_OBSERVER_VAULT_EK=${sh(vaultEk)}`);
console.log(`ROUTE_OBSERVER_CA_DKG_TRANSCRIPT_HASH=${sh(transcriptHash.replace(/^0x/i, ""))}`);
console.log(`ROUTE_OBSERVER_COORDINATOR_URL=${sh(coordinatorUrl)}`);
console.log(`ROUTE_OBSERVER_BEARER_TOKEN=${sh(bearerToken)}`);
NODE
}

observe_staged_route_leaves() {
  if [ "${TREE_EVENT_VERSION}" != "v4" ]; then
    return 0
  fi
  if [ ! -f "${STAGED_LEANIMT_JSON}" ] && [ ! -f "${STAGED_TREE_JSON}" ]; then
    echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: observe route leaves skipped; no staged tree"
    return 0
  fi
  eval "$(load_route_observer_config)"
  local missing_file
  missing_file="$(mktemp -t eunoma-route-leaves.XXXXXX)"
  node - "${STAGED_LEANIMT_JSON}" "${STAGED_TREE_JSON}" "${STATE_DIR}/vault_state_v2_observed" <<'NODE' > "${missing_file}"
const fs = require("fs");
const path = require("path");
const leanPath = process.argv[2];
const treePath = process.argv[3];
const observedDir = process.argv[4];
const readJson = (p) => {
  try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return null; }
};
const tree = readJson(leanPath) ?? readJson(treePath);
if (!tree) process.exit(0);
const leafCount = Number(tree.leafCount ?? (Array.isArray(tree.leaves) ? tree.leaves.length : 0));
const meta = Array.isArray(tree.depositMeta) ? tree.depositMeta : [];
const observed = new Set();
try {
  for (const name of fs.readdirSync(observedDir)) {
    if (!name.endsWith(".json")) continue;
    const artifact = readJson(path.join(observedDir, name));
    if (artifact?.scheme !== "vault_state_v2_observe_deposit") continue;
    if (Number.isInteger(artifact.depositCount)) observed.add(artifact.depositCount);
  }
} catch {}
for (let i = 0; i < leafCount; i += 1) {
  const leafIndex = i + 1;
  if (observed.has(leafIndex)) continue;
  const entry = meta[i] ?? {};
  const txHash = typeof entry.depositTxHash === "string" && /^0x[0-9a-fA-F]{64}$/.test(entry.depositTxHash)
    ? entry.depositTxHash.toLowerCase()
    : "";
  if (!txHash) continue;
  process.stdout.write(`${leafIndex}\t${txHash}\n`);
}
NODE
  if [ ! -s "${missing_file}" ]; then
    rm -f "${missing_file}"
    echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: observe route leaves skipped; staged observed provenance complete"
    return 0
  fi
  echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: observe staged route leaves"
  local bearer_args=()
  if [ -n "${ROUTE_OBSERVER_BEARER_TOKEN:-}" ]; then
    bearer_args=(--bearer-token "${ROUTE_OBSERVER_BEARER_TOKEN}")
  fi
  while IFS=$'\t' read -r leaf_index tx_hash; do
    if [ -z "${leaf_index}" ] || [ -z "${tx_hash}" ]; then
      continue
    fi
    echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: observe route leaf ${leaf_index} tx=${tx_hash}"
    BRIDGE_VAULT_ADDRESS="${VAULT}" node operator-services/scripts/local_deposit_observer.mjs \
      --event-version v4 \
      --target-leaf-index "${leaf_index}" \
      --coordinator-url "${ROUTE_OBSERVER_COORDINATOR_URL}" \
      --aptos-node-url "${APTOS_NODE_URL:-https://fullnode.testnet.aptoslabs.com/v1}" \
      --bridge-address "${BRIDGE}" \
      --dkg-epoch "${ROUTE_OBSERVER_DKG_EPOCH}" \
      --vault-ek "${ROUTE_OBSERVER_VAULT_EK}" \
      --sender-address "${VAULT}" \
      --asset-type "${ASSET}" \
      --chain-id "${CHAIN_ID}" \
      --ca-dkg-transcript-hash "${ROUTE_OBSERVER_CA_DKG_TRANSCRIPT_HASH}" \
      --deposit-tx-hash "${tx_hash}" \
      "${bearer_args[@]}"
  done < "${missing_file}"
  rm -f "${missing_file}"
}

ensure_kyt_provider_for_asp() {
  if [ -n "${CHAINALYSIS_API_KEY:-}" ]; then
    return 0
  fi
  if [ "${ALLOW_TESTNET_SANCTIONS_STUB}" != "1" ]; then
    echo "CHAINALYSIS_API_KEY is required for ASP refresh; set EUNOMA_ALLOW_TESTNET_SANCTIONS_STUB=1 only for testnet" >&2
    exit 34
  fi
  local stub_port="${SANCTIONS_STUB_PORT:-4556}"
  SANCTIONS_STUB_DIR="$(mktemp -d -t eunoma_sanctions_stub.XXXXXX)"
  local stub_js="${SANCTIONS_STUB_DIR}/sanctions_stub.mjs"
  cat > "${stub_js}" <<'STUB'
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
  SANCTIONS_STUB_PORT="${stub_port}" node "${stub_js}" &
  SANCTIONS_STUB_PID=$!
  for _ in $(seq 1 50); do
    if curl -s -o /dev/null --max-time 1 "http://127.0.0.1:${stub_port}/api/v1/address/0x0"; then
      break
    fi
    sleep 0.2
  done
  export CHAINALYSIS_API_KEY="testnet-local-stub"
  export CHAINALYSIS_SANCTIONS_BASE_URL="http://127.0.0.1:${stub_port}/api/v1"
  echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: using local testnet sanctions stub for ASP screening"
}

stage_asp_new_deposits() {
  mkdir -p "$(dirname "${STAGED_ASP_NEW_DEPOSITS_JSON}")"
  node -e '
const fs = require("fs");
const approvedPath = process.argv[1];
const stagedTreePath = process.argv[2];
const outPath = process.argv[3];
const stagedApprovedPath = process.argv[4];
const norm = (s) => (typeof s === "string" ? (s.startsWith("0x") ? s : `0x${s}`).toLowerCase() : "");
const approved = fs.existsSync(approvedPath) ? JSON.parse(fs.readFileSync(approvedPath, "utf8")) : { approved: [] };
fs.writeFileSync(stagedApprovedPath, `${JSON.stringify(approved, null, 2)}\n`);
const staged = JSON.parse(fs.readFileSync(stagedTreePath, "utf8"));
const approvedCommitments = new Set((approved.approved || []).map((a) => norm(a.commitment)).filter(Boolean));
const out = [];
const meta = staged.depositMeta || [];
for (let i = 0; i < meta.length; i++) {
  const m = meta[i] || {};
  const commitment = norm(m.commitment || m.commitmentHex || (staged.leaves || [])[i]);
  if (!commitment || approvedCommitments.has(commitment)) continue;
  const sender = norm(m.sender);
  if (!sender) throw new Error(`missing_sender_for_asp_commitment:${commitment}`);
  out.push({ commitment, sender });
}
fs.writeFileSync(outPath, `${JSON.stringify(out, null, 2)}\n`);
process.stdout.write(String(out.length));
' "${ASP_APPROVED_STATE}" "${STAGED_TREE_JSON}" "${STAGED_ASP_NEW_DEPOSITS_JSON}" "${STAGED_ASP_APPROVED_STATE}"
}

asp_approved_state_matches_public_set() {
  node -e '
const fs = require("fs");
const approvedPath = process.argv[1];
const aspSetPath = process.argv[2];
const norm = (s) => (typeof s === "string" ? (s.startsWith("0x") ? s : `0x${s}`).toLowerCase() : "");
const approved = fs.existsSync(approvedPath) ? JSON.parse(fs.readFileSync(approvedPath, "utf8")) : { approved: [] };
const approvedCommitments = new Set((approved.approved || []).map((a) => norm(a.commitment)).filter(Boolean));
if (!fs.existsSync(aspSetPath)) process.exit(approvedCommitments.size === 0 ? 0 : 1);
const asp = JSON.parse(fs.readFileSync(aspSetPath, "utf8"));
const publicCommitments = new Set((asp.commitments || []).map(norm).filter(Boolean));
if (approvedCommitments.size !== publicCommitments.size) process.exit(1);
for (const c of approvedCommitments) if (!publicCommitments.has(c)) process.exit(1);
process.exit(0);
' "${STAGED_ASP_APPROVED_STATE}" "${ASP_SET_JSON}"
}

asp_public_root_has_record_sidecar() {
  node -e '
const fs = require("fs");
const path = require("path");
const aspSetPath = process.argv[1];
const stateDir = process.argv[2];
if (!fs.existsSync(aspSetPath)) process.exit(1);
const asp = JSON.parse(fs.readFileSync(aspSetPath, "utf8"));
const root = typeof asp.rootHex === "string" ? asp.rootHex.replace(/^0x/i, "").toLowerCase() : "";
if (!/^[0-9a-f]{64}$/.test(root)) process.exit(1);
const sidecarPath = path.join(stateDir, `asp_root_recorded_${root.slice(0, 8)}.json`);
if (!fs.existsSync(sidecarPath)) process.exit(1);
const sidecar = JSON.parse(fs.readFileSync(sidecarPath, "utf8"));
const sidecarRoot = typeof sidecar.rootHex === "string" ? sidecar.rootHex.replace(/^0x/i, "").toLowerCase() : "";
if (sidecar.scheme !== "asp_root_record_sidecar_v1") process.exit(1);
if (sidecarRoot !== root) process.exit(1);
if (sidecar.status !== "recorded") process.exit(1);
process.exit(0);
' "${ASP_SET_JSON}" "${STATE_DIR}"
}

run_asp_refresh_if_needed() {
  local new_count="$1"
  if [ "${new_count}" = "0" ]; then
    if asp_approved_state_matches_public_set; then
      if asp_public_root_has_record_sidecar; then
        echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: asp refresh skipped; no new approved-state deposits"
        return 0
      fi
      echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: asp root record side-car missing; re-recording public root"
    else
      echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: asp approved-state/public-set mismatch; rebuilding"
    fi
  fi
  ensure_kyt_provider_for_asp
  echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: asp refork + record (${new_count} new deposits)"
  EUNOMA_ASP_RECORDER_PROFILE="${ASP_RECORDER_PROFILE}" \
    node operator-services/scripts/local_run_asp_cycle.mjs \
      --state "${STAGED_ASP_APPROVED_STATE}" \
      --new-deposits "${STAGED_ASP_NEW_DEPOSITS_JSON}" \
      --bridge "${BRIDGE}" \
      --record \
      --asp-set-out "${STAGED_ASP_SET_JSON}"
}

normalize_if_needed() {
  local step_label="$1"
  echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: normalize (${step_label})"
  node operator-services/scripts/local_v2_normalize_full.mjs \
       --bridge-package-address "${BRIDGE}" \
       --vault-address "${VAULT}" \
       --asset-type "${ASSET}" \
       "${NORMALIZE_SIGNER_ARGS[@]}" \
       --aptos-node-url "${APTOS_NODE_URL:-https://fullnode.testnet.aptoslabs.com}"
}

# Re-pack chain available_balance into the 4 x 16-bit chunk layout the CA framework
# requires for the next transfer / withdraw. Idempotent: the script's first action
# is `is_normalized(vault, asset_type)` view; when already normalized it exits 0.
normalize_if_needed "before tree refresh"

EXTRA_TX_HASHES=${EUNOMA_EXTRA_DEPOSIT_TX_HASHES:-}
if [ -n "${EXTRA_TX_HASHES}" ]; then
  persist_observed_tx_hashes "${EXTRA_TX_HASHES}"
fi
QUEUED_TX_HASHES=$(read_observed_queue)
if [ -n "${QUEUED_TX_HASHES}" ]; then
  echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: including $(count_tx_hashes "${QUEUED_TX_HASHES}") persisted observed tx hashes"
fi

echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: fetching route-leaf tx hashes via GraphQL backfill"
BACKFILL_TX_HASHES=$(/bin/bash "${FETCH_DEPOSIT_TX_HASHES_SCRIPT}")
TX_HASHES=$(printf '%s,%s' "${QUEUED_TX_HASHES}" "${BACKFILL_TX_HASHES}" | normalize_tx_hashes)
if [ -z "${TX_HASHES}" ]; then
  echo "[$(date -u +%FT%TZ)] no route-leaf txs found yet, exiting clean"
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
BUILD_TREE_ARGS=(
  --bridge-package-address "${BRIDGE}"
  --vault-address "${VAULT}"
  --asset-type "${ASSET}"
  --tx-hashes "${TX_HASHES}"
  --state-dir "${STAGING_DIR}"
  --refresh
)
if [ "${TREE_EVENT_VERSION}" = "v4" ]; then
  BUILD_TREE_ARGS+=(--event-version v4 --asset-allowlist "$(active_asset_allowlist)")
fi
node operator-services/scripts/local_build_commitment_tree.mjs "${BUILD_TREE_ARGS[@]}"
ASP_NEW_DEPOSIT_COUNT=$(stage_asp_new_deposits)
echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: staged ASP new deposits count=${ASP_NEW_DEPOSIT_COUNT}"
observe_staged_route_leaves

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
  RECORD_ROOT_NEEDED=1
  if [ -f "${ROOT_SIDECAR}" ]; then
    echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: root ${LATEST_ROOT} already has side-car; skipping rollover"
    RECORD_ROOT_NEEDED=0
  else
    echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: rollover"
    node operator-services/scripts/local_rollover_vault_pending.mjs \
           --bridge-package-address "${BRIDGE}" \
           "${ROLLOVER_SIGNER_ARGS[@]}"

    normalize_if_needed "after rollover"
  fi
else
  echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: latest root missing from ${ROOT_SOURCE_JSON}"
  exit 2
fi

if [ "${RECORD_ROOT_NEEDED}" = "1" ]; then
  echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: record known root"
  RECORD_ROOT_EXTRA_ARGS=()
  if [ "${TREE_EVENT_VERSION}" = "v4" ] || [ "${EUNOMA_RECORD_KNOWN_ROOT_V4:-0}" = "1" ]; then
    RECORD_ROOT_EXTRA_ARGS+=(--v4)
  fi
  if [ "${EUNOMA_LOCAL_SMOKE:-0}" = "1" ]; then
    RECORD_ROOT_EXTRA_ARGS+=(--allow-local-smoke-anonymity)
  fi
  node operator-services/scripts/local_record_known_root_v2.mjs \
    --commitment-tree "${STAGED_LEANIMT_JSON}" \
    --bridge-package-address "${BRIDGE}" \
    "${RECORD_SIGNER_ARGS[@]}" \
    --min-anonymity-set "${MIN_ANONYMITY_SET}" \
    --state-dir "${STATE_DIR}" \
    ${RECORD_ROOT_EXTRA_ARGS[@]+"${RECORD_ROOT_EXTRA_ARGS[@]}"}
else
  echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: known root side-car present; skipping record known root"
fi

run_asp_refresh_if_needed "${ASP_NEW_DEPOSIT_COUNT}"

echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: publish tree"
mv "${STAGED_TREE_JSON}" "${TREE_JSON}.tmp"
mv "${TREE_JSON}.tmp" "${TREE_JSON}"
if [ -f "${STAGED_LEANIMT_JSON}" ]; then
  mv "${STAGED_LEANIMT_JSON}" "${LEANIMT_JSON}.tmp"
  mv "${LEANIMT_JSON}.tmp" "${LEANIMT_JSON}"
fi
if [ -f "${STAGED_ASP_SET_JSON}" ]; then
  mv "${STAGED_ASP_SET_JSON}" "${ASP_SET_JSON}.tmp"
  mv "${ASP_SET_JSON}.tmp" "${ASP_SET_JSON}"
fi
if [ -f "${STAGED_ASP_APPROVED_STATE}" ]; then
  mv "${STAGED_ASP_APPROVED_STATE}" "${ASP_APPROVED_STATE}.tmp"
  mv "${ASP_APPROVED_STATE}.tmp" "${ASP_APPROVED_STATE}"
fi
for sidecar in "${STAGING_DIR}"/asp_root_recorded_*.json; do
  if [ -f "${sidecar}" ]; then
    mv "${sidecar}" "${STATE_DIR}/$(basename "${sidecar}").tmp"
    mv "${STATE_DIR}/$(basename "${sidecar}").tmp" "${STATE_DIR}/$(basename "${sidecar}")"
  fi
done
rm -rf "${STAGING_DIR}"

prune_observed_queue
echo "[$(date -u +%FT%TZ)] refresh_known_root_cycle: done"

#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// =============================================================================================
// Milestone 3 sub-milestone 3a — MPCCA withdraw round1 fan-out driver.
//
// Drives POST /v2/withdraw/mpcca/start against a coordinator that has already run Phase 2
// (vault_ek derive), Milestone 1 (CA registration sigma), Milestone 2a (vault_state_v2 init),
// and Milestone 2b (deposit observer for the targeted depositCount). All 5 selected workers
// run their round1 public-binding work and surface the milestone 3a NotImplemented stub
// (`mpcca_withdraw_v2_round1_nonce_generation_pending_milestone4`). Round 2 / prove / finalize
// are wired but not exercised by this driver — milestone 4 will fill the crypto in.
//
// Exit codes — operator runbook contract:
//
//   0   success — printed body is whatever the coordinator returned (200 OK or a documented error).
//   1   generic request/parse failure (network, malformed JSON, coordinator 5xx other than 502
//       stub-divergence).
//   2   usage error.
//  23   stub-acceptable 501 — the milestone 3a NotImplemented stub returned as expected. Auditor
//       should review the printed transcript path + per-slot contributions before re-running.
//  24   vault_state_init_provenance_unknown — Milestone 2a prereq missing. Operator action:
//       re-run `npm run local:vault-state:init`.
//  25   crypto_stub_phase_divergence — workers returned divergent notImplementedPhase strings.
//       Operator action: investigate per-slot crypto-worker logs.
// =============================================================================================
const EXIT_SUCCESS = 0;
const EXIT_GENERIC_FAILURE = 1;
const EXIT_USAGE_ERROR = 2;
const EXIT_STUB_OK = 23;
const EXIT_INIT_PROVENANCE = 24;
const EXIT_PHASE_DIVERGENCE = 25;

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");

const args = process.argv.slice(2);
let coordinatorUrl;
let dkgEpoch;
let caDkgTranscriptHash;
let vaultEk;
let senderAddress;
let assetType;
let chainId;
let root;
let nullifierHash;
let recipient;
let recipientHash;
let amountTag;
let depositCount;
let vaultSequence;
let expirySecs;
let requestHash;
let requestId;
let bearerToken;

for (let i = 0; i < args.length; i += 1) {
  const arg = args[i];
  switch (arg) {
    case "--coordinator-url":
      coordinatorUrl = args[++i];
      break;
    case "--dkg-epoch":
      dkgEpoch = args[++i];
      break;
    case "--ca-dkg-transcript-hash":
      caDkgTranscriptHash = args[++i];
      break;
    case "--vault-ek":
      vaultEk = args[++i];
      break;
    case "--sender-address":
      senderAddress = args[++i];
      break;
    case "--asset-type":
      assetType = args[++i];
      break;
    case "--chain-id":
      chainId = args[++i];
      break;
    case "--root":
      root = args[++i];
      break;
    case "--nullifier-hash":
      nullifierHash = args[++i];
      break;
    case "--recipient":
      recipient = args[++i];
      break;
    case "--recipient-hash":
      recipientHash = args[++i];
      break;
    case "--amount-tag":
      amountTag = args[++i];
      break;
    case "--deposit-count":
      depositCount = args[++i];
      break;
    case "--vault-sequence":
      vaultSequence = args[++i];
      break;
    case "--expiry-secs":
      expirySecs = args[++i];
      break;
    case "--request-hash":
      requestHash = args[++i];
      break;
    case "--request-id":
      requestId = args[++i];
      break;
    case "--bearer-token":
      bearerToken = args[++i];
      break;
    case "--help":
    case "-h":
      console.log(
        "usage: local_mpcca_withdraw_round1 --coordinator-url URL --dkg-epoch N\n" +
          "                                   --ca-dkg-transcript-hash HEX --vault-ek HEX\n" +
          "                                   --sender-address HEX --asset-type HEX --chain-id N\n" +
          "                                   --root HEX --nullifier-hash HEX\n" +
          "                                   --recipient HEX --recipient-hash HEX --amount-tag HEX\n" +
          "                                   --deposit-count N --vault-sequence N --expiry-secs N\n" +
          "                                   --request-hash HEX\n" +
          "                                   [--request-id ID] [--bearer-token TOKEN]\n" +
          "\n" +
          "Drives POST /v2/withdraw/mpcca/start. Milestone 3a fans out round1 to 5 workers; each\n" +
          "worker does FULL public binding + persists session state + returns 501 NotImplemented.\n" +
          "round2/prove/finalize wired but deferred to milestone 4.\n" +
          "\n" +
          "Exit codes:\n" +
          `  ${EXIT_SUCCESS}   success — coordinator returned 200 (not expected under milestone 3a)\n` +
          `  ${EXIT_GENERIC_FAILURE}   generic request/parse failure\n` +
          `  ${EXIT_USAGE_ERROR}   usage error\n` +
          `  ${EXIT_STUB_OK}  milestone 3a stub returned 501 NotImplemented as expected — review transcript artifact\n` +
          `  ${EXIT_INIT_PROVENANCE}  vault_state_init_provenance_unknown — re-run local:vault-state:init\n` +
          `  ${EXIT_PHASE_DIVERGENCE}  crypto_stub_phase_divergence — workers returned divergent phases\n`,
      );
      process.exit(EXIT_SUCCESS);
    default:
      console.error(`unknown arg: ${arg}`);
      process.exit(EXIT_USAGE_ERROR);
  }
}

// Required-field validation.
function require_arg(name, value) {
  if (!value) {
    console.error(`${name} is required`);
    process.exit(EXIT_USAGE_ERROR);
  }
}
require_arg("--dkg-epoch", dkgEpoch);
if (!/^[0-9]+$/.test(dkgEpoch)) {
  console.error("--dkg-epoch must be a decimal string");
  process.exit(EXIT_USAGE_ERROR);
}
require_arg("--ca-dkg-transcript-hash", caDkgTranscriptHash);
require_arg("--vault-ek", vaultEk);
require_arg("--sender-address", senderAddress);
require_arg("--asset-type", assetType);
require_arg("--chain-id", chainId);
const chainIdNum = Number.parseInt(chainId, 10);
if (!Number.isInteger(chainIdNum) || chainIdNum < 0 || chainIdNum > 255) {
  console.error("--chain-id must be a u8 integer (0..255)");
  process.exit(EXIT_USAGE_ERROR);
}
require_arg("--root", root);
require_arg("--nullifier-hash", nullifierHash);
require_arg("--recipient", recipient);
require_arg("--recipient-hash", recipientHash);
require_arg("--amount-tag", amountTag);
require_arg("--deposit-count", depositCount);
const depositCountNum = Number.parseInt(depositCount, 10);
if (!Number.isInteger(depositCountNum) || depositCountNum < 0) {
  console.error("--deposit-count must be a non-negative integer");
  process.exit(EXIT_USAGE_ERROR);
}
require_arg("--vault-sequence", vaultSequence);
const vaultSequenceNum = Number.parseInt(vaultSequence, 10);
if (!Number.isInteger(vaultSequenceNum) || vaultSequenceNum < 0) {
  console.error("--vault-sequence must be a non-negative integer");
  process.exit(EXIT_USAGE_ERROR);
}
require_arg("--expiry-secs", expirySecs);
const expirySecsNum = Number.parseInt(expirySecs, 10);
if (!Number.isInteger(expirySecsNum) || expirySecsNum < 0) {
  console.error("--expiry-secs must be a non-negative integer");
  process.exit(EXIT_USAGE_ERROR);
}
require_arg("--request-hash", requestHash);

// Pull cluster plan defaults (when running against local:cluster:start).
const planPath = resolve(
  serviceRoot,
  process.env.EUNOMA_LOCAL_STATE_ROOT ?? ".agent-local/eunoma-v2",
  "cluster/local-cluster.json",
);
let plan;
if (existsSync(planPath)) {
  plan = JSON.parse(readFileSync(planPath, "utf8"));
  if (!coordinatorUrl) coordinatorUrl = `http://127.0.0.1:${plan.coordinator.port}`;
  if (!bearerToken) bearerToken = plan.coordinator.env.COORDINATOR_BEARER_TOKEN;
}
if (!coordinatorUrl) {
  console.error("--coordinator-url is required when no local cluster plan is found");
  process.exit(EXIT_USAGE_ERROR);
}

const payload = {
  dkgEpoch,
  caDkgTranscriptHash,
  vaultEk,
  senderAddress,
  assetType,
  chainId: chainIdNum,
  root,
  nullifierHash,
  recipient,
  recipientHash,
  amountTag,
  vaultSequence: vaultSequenceNum,
  expirySecs: expirySecsNum,
  requestHash,
  depositCount: depositCountNum,
};
if (requestId) payload.requestId = requestId;

const headers = { "content-type": "application/json" };
if (bearerToken) headers.authorization = `Bearer ${bearerToken}`;

let res;
try {
  res = await fetch(new URL("/v2/withdraw/mpcca/start", coordinatorUrl), {
    method: "POST",
    headers,
    body: JSON.stringify(payload),
  });
} catch (err) {
  console.error(`coordinator request failed: ${err?.message ?? err}`);
  process.exit(EXIT_GENERIC_FAILURE);
}
let body;
try {
  body = await res.json();
} catch {
  body = {};
}

// Surfaced error codes documented in the orchestrator's response shape.
if (res.status === 400 && body?.error === "vault_state_init_provenance_unknown") {
  console.error(
    "Milestone 2a init provenance missing — re-run `npm run local:vault-state:init` first.",
  );
  process.stdout.write(`${JSON.stringify(body, null, 2)}\n`);
  process.exit(EXIT_INIT_PROVENANCE);
}
if (res.status === 502 && body?.error === "crypto_stub_phase_divergence") {
  console.error(
    "crypto_stub_phase_divergence: workers returned divergent notImplementedPhase strings.",
  );
  process.stdout.write(`${JSON.stringify(body, null, 2)}\n`);
  process.exit(EXIT_PHASE_DIVERGENCE);
}

if (res.status === 501) {
  // Milestone 3a expected stub outcome: round1 public binding succeeded; crypto deferred.
  process.stdout.write(`${JSON.stringify(body, null, 2)}\n`);
  process.exit(EXIT_STUB_OK);
}
if (!res.ok) {
  console.error(`coordinator returned ${res.status}`);
  process.stdout.write(`${JSON.stringify(body, null, 2)}\n`);
  process.exit(EXIT_GENERIC_FAILURE);
}
// 200 OK — milestone 3a stub should not return 200; if we got here, milestone 4 has landed.
process.stdout.write(`${JSON.stringify(body, null, 2)}\n`);
process.exit(EXIT_SUCCESS);

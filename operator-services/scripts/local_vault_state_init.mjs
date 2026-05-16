#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// =============================================================================================
// Milestone 2 sub-milestone 2a — per-worker vault-state share initialization.
//
// Drives POST /v2/vault_state/init against a coordinator that has already run Phase 2
// (npm run local:vault-ek:derive) and Milestone 1 (npm run local:ca-registration:v2). Each
// of the 5 selected workers writes `state_dir/vault_state_v2.json` (mode 0o600) pinning the
// (vault_ek, registration_sigma, dkg_epoch, roster_hash) bindings + per-worker cursors
// (vault_sequence, deposit_count_observed; both start at 0). Sub-milestone 2b will plug into
// this file's deposit_count_observed cursor; subsequent MPCCA rounds will use vault_sequence.
//
// Exit codes — operator runbook contract:
//
//   0   success — prints { requestId, dkgEpoch, vaultEk, vaultEkTranscriptHash,
//                          registrationTranscriptHash, transcriptHash, transcriptPath,
//                          perSlotContributions, selectedSlots, selectionRationale } JSON.
//   1   generic request/parse failure (network, non-structured HTTP error, malformed JSON).
//   2   usage error.
//   21  vault_ek_provenance_unknown / vault_ek_provenance_mismatch — Phase 2 prereq missing
//       or mismatched. Operator action: re-run `npm run local:vault-ek:derive`.
//   22  vault_state_v2_init_in_flight — coordinator returned 409. Retry shortly.
//   23  ca_registration_provenance_unknown / ca_registration_provenance_mismatch —
//       Milestone 1 prereq missing. Operator action: re-run `npm run local:ca-registration:v2`.
// =============================================================================================
const EXIT_SUCCESS = 0;
const EXIT_GENERIC_FAILURE = 1;
const EXIT_USAGE_ERROR = 2;
const EXIT_PHASE2_PROVENANCE = 21;
const EXIT_LOCK_CONTENTION = 22;
const EXIT_MILESTONE1_PROVENANCE = 23;

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
let requestId;
let bearerToken;
let selectedSlots; // optional, comma-separated list
let vaultEkTranscriptHash;
let registrationTranscriptHash;
let aggregateCommitment;
let aggregateResponse;
let challenge;

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
    case "--request-id":
      requestId = args[++i];
      break;
    case "--bearer-token":
      bearerToken = args[++i];
      break;
    case "--selected-slots":
      selectedSlots = args[++i]
        .split(",")
        .map((s) => Number.parseInt(s.trim(), 10));
      break;
    case "--vault-ek-transcript-hash":
      vaultEkTranscriptHash = args[++i];
      break;
    case "--registration-transcript-hash":
      registrationTranscriptHash = args[++i];
      break;
    case "--aggregate-commitment":
      aggregateCommitment = args[++i];
      break;
    case "--aggregate-response":
      aggregateResponse = args[++i];
      break;
    case "--challenge":
      challenge = args[++i];
      break;
    case "--help":
    case "-h":
      console.log(
        "usage: local_vault_state_init --coordinator-url URL --dkg-epoch N\n" +
          "                              --ca-dkg-transcript-hash HEX --vault-ek HEX\n" +
          "                              --sender-address HEX --asset-type HEX --chain-id N\n" +
          "                              [--vault-ek-transcript-hash HEX]\n" +
          "                              [--registration-transcript-hash HEX]\n" +
          "                              [--aggregate-commitment HEX --aggregate-response HEX --challenge HEX]\n" +
          "                              [--request-id ID] [--bearer-token TOKEN]\n" +
          "                              [--selected-slots 0,1,2,3,4]\n" +
          "\n" +
          "When the coordinator runs with stateRoot configured (production / npm run local:cluster:start),\n" +
          "the *-transcript-hash, aggregate-*, and challenge flags are looked up from the persisted Phase\n" +
          "2 + Milestone 1 transcripts automatically. They only need to be supplied inline for dev/test\n" +
          "coordinators running without stateRoot.\n" +
          "\n" +
          "Exit codes:\n" +
          `  ${EXIT_SUCCESS}   success — prints { vaultEk, vaultEkTranscriptHash, registrationTranscriptHash, transcriptHash, transcriptPath, perSlotContributions, ... }\n` +
          `  ${EXIT_GENERIC_FAILURE}   generic request/parse failure\n` +
          `  ${EXIT_USAGE_ERROR}   usage error\n` +
          `  ${EXIT_PHASE2_PROVENANCE}  vault_ek_provenance_unknown / vault_ek_provenance_mismatch — re-run vault_ek derive\n` +
          `  ${EXIT_LOCK_CONTENTION}  vault_state_v2_init_in_flight — retry shortly\n` +
          `  ${EXIT_MILESTONE1_PROVENANCE}  ca_registration_provenance_unknown / ca_registration_provenance_mismatch — re-run ca_registration_v2\n`,
      );
      process.exit(EXIT_SUCCESS);
    default:
      console.error(`unknown arg: ${arg}`);
      process.exit(EXIT_USAGE_ERROR);
  }
}

if (!dkgEpoch || !/^[0-9]+$/.test(dkgEpoch)) {
  console.error("--dkg-epoch is required and must be a decimal string");
  process.exit(EXIT_USAGE_ERROR);
}
if (!caDkgTranscriptHash) {
  console.error("--ca-dkg-transcript-hash is required");
  process.exit(EXIT_USAGE_ERROR);
}
if (!vaultEk) {
  console.error("--vault-ek is required (Phase 2-derived public point, 32-byte hex)");
  process.exit(EXIT_USAGE_ERROR);
}
if (!senderAddress) {
  console.error("--sender-address is required (Aptos address, 32-byte hex)");
  process.exit(EXIT_USAGE_ERROR);
}
if (!assetType) {
  console.error("--asset-type is required (Aptos asset type, 32-byte hex)");
  process.exit(EXIT_USAGE_ERROR);
}
if (!chainId) {
  console.error("--chain-id is required (u8)");
  process.exit(EXIT_USAGE_ERROR);
}
const chainIdNum = Number.parseInt(chainId, 10);
if (!Number.isInteger(chainIdNum) || chainIdNum < 0 || chainIdNum > 255) {
  console.error("--chain-id must be a u8 integer (0..255)");
  process.exit(EXIT_USAGE_ERROR);
}

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
};
if (requestId) payload.requestId = requestId;
if (selectedSlots) payload.selectedSlots = selectedSlots;
if (vaultEkTranscriptHash) payload.vaultEkTranscriptHash = vaultEkTranscriptHash;
if (registrationTranscriptHash) payload.registrationTranscriptHash = registrationTranscriptHash;
if (aggregateCommitment) payload.aggregateCommitment = aggregateCommitment;
if (aggregateResponse) payload.aggregateResponse = aggregateResponse;
if (challenge) payload.challenge = challenge;

const headers = { "content-type": "application/json" };
if (bearerToken) headers.authorization = `Bearer ${bearerToken}`;

let res;
try {
  res = await fetch(new URL("/v2/vault_state/init", coordinatorUrl), {
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

if (
  res.status === 400 &&
  (body?.error === "vault_ek_provenance_unknown" || body?.error === "vault_ek_provenance_mismatch")
) {
  console.error(
    "Phase 2 provenance missing or mismatched — re-run `npm run local:vault-ek:derive` to refresh vault_ek transcripts before retrying.",
  );
  process.stdout.write(`${JSON.stringify(body, null, 2)}\n`);
  process.exit(EXIT_PHASE2_PROVENANCE);
}
if (
  res.status === 400 &&
  (body?.error === "ca_registration_provenance_unknown" ||
    body?.error === "ca_registration_provenance_mismatch")
) {
  console.error(
    "Milestone 1 provenance missing or mismatched — re-run `npm run local:ca-registration:v2` to refresh registration transcripts before retrying.",
  );
  process.stdout.write(`${JSON.stringify(body, null, 2)}\n`);
  process.exit(EXIT_MILESTONE1_PROVENANCE);
}
if (res.status === 409 && body?.error === "vault_state_v2_init_in_flight") {
  console.error("another vault_state_v2 init session is in progress; retry shortly");
  process.stdout.write(`${JSON.stringify(body, null, 2)}\n`);
  process.exit(EXIT_LOCK_CONTENTION);
}

if (!res.ok) {
  console.error(`coordinator returned ${res.status}`);
  process.stdout.write(`${JSON.stringify(body, null, 2)}\n`);
  process.exit(EXIT_GENERIC_FAILURE);
}

const out = {
  requestId: body.requestId,
  dkgEpoch: body.dkgEpoch,
  vaultEk: body.vaultEk,
  vaultEkTranscriptHash: body.vaultEkTranscriptHash,
  registrationTranscriptHash: body.registrationTranscriptHash,
  transcriptHash: body.transcriptHash,
  transcriptPath: body.transcriptPath,
  selectedSlots: body.selectedSlots,
  selectionRationale: body.selectionRationale,
  senderAddress: body.senderAddress,
  assetType: body.assetType,
  chainId: body.chainId,
  perSlotContributions: body.perSlotContributions,
};
process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);

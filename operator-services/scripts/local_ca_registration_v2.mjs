#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// =============================================================================================
// Milestone 1 — V2 threshold CA registration sigma over Phase 2-derived vault_ek.
//
// Drives `POST /v2/derive/ca_registration/start` against a coordinator that has the V2
// CA DKG roster + 5-of-7 ca_dkg_share_v2.json files persisted on each selected slot's
// worker. The vault_ek MUST come from a prior Phase 2 derivation (see
// scripts/local_vault_ek_derive.mjs).
//
// Exit codes — operator runbook contract; alerting + smoke tests parse these.
//
//   0   success — prints { vaultEk, aggregateCommitment, aggregateResponse, challenge,
//                          transcriptHash, transcriptPath, requestId, selectedSlots } JSON.
//   1   generic request/parse failure (network, non-structured HTTP error, malformed JSON).
//   2   usage error (unknown arg, missing required arg).
//   21  mpc_inverse_unavailable — Phase 2 prereq missing (a selected slot's vault_ek
//        derivation can't proceed). Operator action: `npm run mpc:bootstrap && npm run
//        mpc:check`, then re-run vault_ek derivation.
//   22  ca_registration_v2_in_flight — coordinator returned 409. Operator action: retry
//        after the previous session settles.
//   23  aggregate_proof_invalid — coordinator returned 502 because the public
//        verify equation didn't hold. Indicates a buggy worker, a tampered response,
//        or a vault_ek/share-version mismatch. Operator action: re-run the CA DKG V2 +
//        Phase 2 derivation to refresh shares, then retry.
// =============================================================================================
const EXIT_SUCCESS = 0;
const EXIT_GENERIC_FAILURE = 1;
const EXIT_USAGE_ERROR = 2;
const EXIT_MPC_UNAVAILABLE = 21;
const EXIT_LOCK_CONTENTION = 22;
const EXIT_AGGREGATE_PROOF_INVALID = 23;

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
    case "--help":
    case "-h":
      console.log(
        "usage: local_ca_registration_v2 --coordinator-url URL --dkg-epoch N\n" +
          "                                 --ca-dkg-transcript-hash HEX --vault-ek HEX\n" +
          "                                 --sender-address HEX --asset-type HEX --chain-id N\n" +
          "                                 [--request-id ID] [--bearer-token TOKEN]\n" +
          "                                 [--selected-slots 0,1,2,3,4]\n" +
          "\n" +
          "Exit codes:\n" +
          `  ${EXIT_SUCCESS}   success — prints { vaultEk, aggregateCommitment, aggregateResponse, challenge, transcriptHash, transcriptPath, requestId, selectedSlots }\n` +
          `  ${EXIT_GENERIC_FAILURE}   generic request/parse failure\n` +
          `  ${EXIT_USAGE_ERROR}   usage error\n` +
          `  ${EXIT_MPC_UNAVAILABLE}  Phase 2 prereq missing — derive vault_ek first\n` +
          `  ${EXIT_LOCK_CONTENTION}  ca_registration_v2_in_flight — retry shortly\n` +
          `  ${EXIT_AGGREGATE_PROOF_INVALID}  aggregate_proof_invalid — public verify equation failed\n`,
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

const headers = { "content-type": "application/json" };
if (bearerToken) headers.authorization = `Bearer ${bearerToken}`;

let res;
try {
  res = await fetch(new URL("/v2/derive/ca_registration/start", coordinatorUrl), {
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

if (res.status === 503 && body?.error === "mpc_inverse_unavailable") {
  console.error(
    "Phase 2 prereq missing — vault_ek derivation requires MP-SPDZ runtime. Run `npm run mpc:bootstrap && npm run mpc:check`, then re-derive vault_ek before retrying.",
  );
  process.stdout.write(`${JSON.stringify(body)}\n`);
  process.exit(EXIT_MPC_UNAVAILABLE);
}
if (res.status === 409 && body?.error === "ca_registration_v2_in_flight") {
  console.error("another ca_registration_v2 session is in progress; retry shortly");
  process.stdout.write(`${JSON.stringify(body)}\n`);
  process.exit(EXIT_LOCK_CONTENTION);
}
if (res.status === 502 && body?.error === "aggregate_proof_invalid") {
  console.error(
    "aggregate_proof_invalid — the public verify equation failed. Re-derive vault_ek + retry.",
  );
  process.stdout.write(`${JSON.stringify(body)}\n`);
  process.exit(EXIT_AGGREGATE_PROOF_INVALID);
}

if (!res.ok) {
  console.error(`coordinator returned ${res.status}`);
  process.stdout.write(`${JSON.stringify(body, null, 2)}\n`);
  process.exit(EXIT_GENERIC_FAILURE);
}

const out = {
  vaultEk: body.vaultEk,
  aggregateCommitment: body.aggregateCommitment,
  aggregateResponse: body.aggregateResponse,
  challenge: body.challenge,
  transcriptHash: body.transcriptHash,
  transcriptPath: body.transcriptPath,
  requestId: body.requestId,
  selectedSlots: body.selectedSlots,
  selectionRationale: body.selectionRationale,
  verifierSlot: body.verifierSlot,
};
process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);

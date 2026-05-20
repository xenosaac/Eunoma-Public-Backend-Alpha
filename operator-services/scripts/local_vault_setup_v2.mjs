#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// =============================================================================================
// Milestone 1 combined orchestrator: Phase 2 vault_ek derivation -> V2 threshold CA
// registration sigma. Produces the (vault_ek, aggregateCommitment, aggregateResponse)
// tuple ready for Aptos CA `init_vault_with_ca_registration_v2` (Move; chain submission
// is deferred to a later milestone).
//
// Both halves go through the coordinator's V2 surface:
//   POST /v2/derive/vault_ek/start          -> vault_ek (Phase 2 — real MP-SPDZ inversion)
//   POST /v2/derive/ca_registration/start   -> (commitment, response) sigma over that vault_ek
//
// Exit codes mirror the constituent scripts:
//   0   success — prints the assembled tuple as JSON.
//   1   generic failure.
//   2   usage error.
//   21  Phase 2 MP-SPDZ unavailable.
//   22  vault_ek or ca_registration lock contention.
//   23  aggregate_proof_invalid (public verify equation failed in registration).
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
let senderAddress;
let assetType;
let chainId;
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
    case "--help":
    case "-h":
      console.log(
        "usage: local_vault_setup_v2 --coordinator-url URL --dkg-epoch N\n" +
          "                             [--ca-dkg-transcript-hash HEX]\n" +
          "                             --sender-address HEX --asset-type HEX --chain-id N\n" +
          "                             [--request-id ID] [--bearer-token TOKEN]\n" +
          "\n" +
          "Runs Phase 2 vault_ek derivation, then V2 threshold CA registration over the\n" +
          "derived vault_ek. Prints { vaultEk, aggregateCommitment, aggregateResponse,\n" +
          "challenge, registrationTranscriptHash, vaultEkTranscriptHash }.\n",
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
if (!senderAddress) {
  console.error("--sender-address is required");
  process.exit(EXIT_USAGE_ERROR);
}
if (!assetType) {
  console.error("--asset-type is required");
  process.exit(EXIT_USAGE_ERROR);
}
if (!chainId) {
  console.error("--chain-id is required");
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

const headers = { "content-type": "application/json" };
if (bearerToken) headers.authorization = `Bearer ${bearerToken}`;

// ----- Step 1: derive vault_ek via Phase 2 -----
const vaultEkPayload = { dkgEpoch };
if (requestId) vaultEkPayload.requestId = `${requestId}__vault-ek`;
if (caDkgTranscriptHash) vaultEkPayload.caDkgTranscriptHash = caDkgTranscriptHash;

let vaultEkRes;
try {
  vaultEkRes = await fetch(new URL("/v2/derive/vault_ek/start", coordinatorUrl), {
    method: "POST",
    headers,
    body: JSON.stringify(vaultEkPayload),
  });
} catch (err) {
  console.error(`vault_ek request failed: ${err?.message ?? err}`);
  process.exit(EXIT_GENERIC_FAILURE);
}

let vaultEkBody;
try {
  vaultEkBody = await vaultEkRes.json();
} catch {
  vaultEkBody = {};
}

if (vaultEkRes.status === 503 && vaultEkBody?.error === "mpc_inverse_unavailable") {
  console.error(
    "Phase 2 MP-SPDZ unavailable. Run `npm run mpc:bootstrap && npm run mpc:check`.",
  );
  process.stdout.write(`${JSON.stringify(vaultEkBody)}\n`);
  process.exit(EXIT_MPC_UNAVAILABLE);
}
if (vaultEkRes.status === 409 && vaultEkBody?.error === "vault_ek_derivation_in_flight") {
  console.error("vault_ek_derivation_in_flight; retry shortly");
  process.stdout.write(`${JSON.stringify(vaultEkBody)}\n`);
  process.exit(EXIT_LOCK_CONTENTION);
}
if (!vaultEkRes.ok || !vaultEkBody.vaultEk) {
  console.error(`vault_ek derive returned ${vaultEkRes.status}`);
  process.stdout.write(`${JSON.stringify(vaultEkBody, null, 2)}\n`);
  process.exit(EXIT_GENERIC_FAILURE);
}

const vaultEk = vaultEkBody.vaultEk;
const vaultEkTranscriptHash = vaultEkBody.finalTranscriptHash;
const effectiveCaDkgTranscriptHash =
  caDkgTranscriptHash || vaultEkBody.caDkgTranscriptHash;
// If the user didn't supply caDkgTranscriptHash and the vault_ek response also didn't echo
// one, we have to fail — the CA registration call requires it as a binding.
if (!effectiveCaDkgTranscriptHash) {
  console.error(
    "vault_ek derive did not echo caDkgTranscriptHash and none was supplied. Pass --ca-dkg-transcript-hash explicitly.",
  );
  process.exit(EXIT_USAGE_ERROR);
}

// ----- Step 2: V2 CA registration over the Phase 2 vault_ek -----
const regPayload = {
  dkgEpoch,
  caDkgTranscriptHash: effectiveCaDkgTranscriptHash,
  vaultEk,
  senderAddress,
  assetType,
  chainId: chainIdNum,
};
if (requestId) regPayload.requestId = `${requestId}__ca-reg`;

let regRes;
try {
  regRes = await fetch(new URL("/v2/derive/ca_registration/start", coordinatorUrl), {
    method: "POST",
    headers,
    body: JSON.stringify(regPayload),
  });
} catch (err) {
  console.error(`ca_registration request failed: ${err?.message ?? err}`);
  process.exit(EXIT_GENERIC_FAILURE);
}

let regBody;
try {
  regBody = await regRes.json();
} catch {
  regBody = {};
}

if (regRes.status === 503 && regBody?.error === "mpc_inverse_unavailable") {
  console.error(
    "Phase 2 prereq missing during CA registration (shouldn't happen — we just derived vault_ek).",
  );
  process.stdout.write(`${JSON.stringify(regBody)}\n`);
  process.exit(EXIT_MPC_UNAVAILABLE);
}
if (regRes.status === 409 && regBody?.error === "ca_registration_v2_in_flight") {
  console.error("ca_registration_v2_in_flight; retry shortly");
  process.stdout.write(`${JSON.stringify(regBody)}\n`);
  process.exit(EXIT_LOCK_CONTENTION);
}
if (regRes.status === 502 && regBody?.error === "aggregate_proof_invalid") {
  console.error(
    "aggregate_proof_invalid — the public verify equation failed. Re-derive vault_ek + retry.",
  );
  process.stdout.write(`${JSON.stringify(regBody)}\n`);
  process.exit(EXIT_AGGREGATE_PROOF_INVALID);
}
if (!regRes.ok || !regBody.aggregateCommitment) {
  console.error(`ca_registration returned ${regRes.status}`);
  process.stdout.write(`${JSON.stringify(regBody, null, 2)}\n`);
  process.exit(EXIT_GENERIC_FAILURE);
}

const out = {
  vaultEk,
  vaultEkTranscriptHash,
  aggregateCommitment: regBody.aggregateCommitment,
  aggregateResponse: regBody.aggregateResponse,
  challenge: regBody.challenge,
  registrationTranscriptHash: regBody.transcriptHash,
  registrationTranscriptPath: regBody.transcriptPath,
  registrationRequestId: regBody.requestId,
  vaultEkRequestId: vaultEkBody.requestId,
  caDkgTranscriptHash: effectiveCaDkgTranscriptHash,
  senderAddress,
  assetType,
  chainId: chainIdNum,
  selectedSlots: regBody.selectedSlots,
  verifierSlot: regBody.verifierSlot,
};
process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);

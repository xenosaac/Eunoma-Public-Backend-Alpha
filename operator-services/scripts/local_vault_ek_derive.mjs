#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// =============================================================================================
// Exit codes — codex P3 #11. This contract is part of the operator runbook; consumers
// (operator-services/scripts/testnet_e2e_fail_closed.mjs, alerting, etc.) parse these.
//
//   0   success — wrote { vaultEk, finalTranscriptHash, requestId, selectedSlots,
//                          transcriptPath } JSON to stdout.
//   1   generic request/parse failure (network error, coordinator returned non-success
//        status that doesn't match the structured codes below, malformed JSON).
//   2   usage error (unknown arg, missing required arg, etc.). Operator misconfiguration.
//   21  mpc_inverse_unavailable — coordinator returned 503 because at least one selected
//        worker lacks the MP-SPDZ runtime. Operator action: `npm run mpc:bootstrap && npm
//        run mpc:check` on each affected worker.
//   22  vault_ek_derivation_in_flight — coordinator returned 409 because another vault_ek
//        derivation is in progress. Operator action: retry after the previous one settles.
//
// No other exit codes. If a new failure mode appears, add it here AND update operator runbooks.
// =============================================================================================
const EXIT_SUCCESS = 0;
const EXIT_GENERIC_FAILURE = 1;
const EXIT_USAGE_ERROR = 2;
const EXIT_MPC_UNAVAILABLE = 21;
const PHASE2_EXIT_LOCK_CONTENTION = 22;

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");

const args = process.argv.slice(2);
let coordinatorUrl;
let dkgEpoch;
let caDkgTranscriptHash;
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
    case "--request-id":
      requestId = args[++i];
      break;
    case "--bearer-token":
      bearerToken = args[++i];
      break;
    case "--help":
    case "-h":
      console.log(
        "usage: local_vault_ek_derive --coordinator-url URL --dkg-epoch N " +
          "[--ca-dkg-transcript-hash HEX] [--request-id ID] [--bearer-token TOKEN]\n" +
          "\n" +
          "Exit codes (codex P3 #11 — operator runbook contract):\n" +
          `  ${EXIT_SUCCESS}   success — prints { vaultEk, finalTranscriptHash, requestId, selectedSlots, transcriptPath }\n` +
          `  ${EXIT_GENERIC_FAILURE}   generic request/parse failure (network, non-503/409 HTTP error, malformed JSON)\n` +
          `  ${EXIT_USAGE_ERROR}   usage error (unknown arg, missing required arg)\n` +
          `  ${EXIT_MPC_UNAVAILABLE}  MP-SPDZ runtime unavailable — run \`npm run mpc:bootstrap && npm run mpc:check\`, then retry.\n` +
          `  ${PHASE2_EXIT_LOCK_CONTENTION}  another vault_ek derivation is in progress; retry shortly\n`,
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

const payload = { dkgEpoch };
if (requestId) payload.requestId = requestId;
if (caDkgTranscriptHash) payload.caDkgTranscriptHash = caDkgTranscriptHash;

const headers = { "content-type": "application/json" };
if (bearerToken) headers.authorization = `Bearer ${bearerToken}`;

let res;
try {
  res = await fetch(new URL("/v2/derive/vault_ek/start", coordinatorUrl), {
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
    "MP-SPDZ runtime unavailable — run `npm run mpc:bootstrap && npm run mpc:check`, then retry.",
  );
  process.stdout.write(`${JSON.stringify(body)}\n`);
  process.exit(EXIT_MPC_UNAVAILABLE);
}

if (res.status === 409 && body?.error === "vault_ek_derivation_in_flight") {
  console.error("another vault_ek derivation is in progress; retry shortly");
  process.stdout.write(`${JSON.stringify(body)}\n`);
  process.exit(PHASE2_EXIT_LOCK_CONTENTION);
}

if (!res.ok) {
  console.error(`coordinator returned ${res.status}`);
  process.stdout.write(`${JSON.stringify(body, null, 2)}\n`);
  process.exit(EXIT_GENERIC_FAILURE);
}

// Phase 2 success: print structured JSON that downstream scripts can parse.
const successOut = {
  vaultEk: body.vaultEk,
  finalTranscriptHash: body.finalTranscriptHash,
  requestId: body.requestId,
  selectedSlots: body.selectedSlots,
  transcriptPath: body.transcriptPath,
};
process.stdout.write(`${JSON.stringify(successOut, null, 2)}\n`);

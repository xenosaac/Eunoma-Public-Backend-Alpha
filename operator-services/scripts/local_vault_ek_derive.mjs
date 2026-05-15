#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Exit codes (distinct from default 1 for operator runbooks):
//   0   success
//   21  MP-SPDZ runtime unavailable (run `npm run mpc:bootstrap && npm run mpc:check`)
//   22  another vault_ek derivation is in flight (retry shortly)
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
          "Exit codes:\n" +
          "  0   success — prints { vaultEk, finalTranscriptHash, requestId, selectedSlots, transcriptPath }\n" +
          `  ${EXIT_MPC_UNAVAILABLE}  MP-SPDZ runtime unavailable — run \`npm run mpc:bootstrap && npm run mpc:check\`, then retry.\n` +
          `  ${PHASE2_EXIT_LOCK_CONTENTION}  another vault_ek derivation is in progress; retry shortly\n`,
      );
      process.exit(0);
    default:
      console.error(`unknown arg: ${arg}`);
      process.exit(2);
  }
}

if (!dkgEpoch || !/^[0-9]+$/.test(dkgEpoch)) {
  console.error("--dkg-epoch is required and must be a decimal string");
  process.exit(2);
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
  process.exit(2);
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
  process.exit(1);
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
  process.exit(1);
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

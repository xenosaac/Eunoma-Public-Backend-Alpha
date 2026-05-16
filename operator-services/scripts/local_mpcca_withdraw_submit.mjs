#!/usr/bin/env node
// =============================================================================================
// Milestone 5 sub-milestone 5b — MPCCA withdraw submit driver.
//
// Drives POST /v2/withdraw/mpcca/submit against a coordinator that has already produced a
// finalize transcript on disk at
//   <stateRoot>/coordinator/mpcca_withdraw/<dkgEpoch>__<requestId>__finalize.json
// In M5b the finalize transcript is still the M3a NotImplemented stub, so the EXPECTED outcome
// of this driver TODAY is exit 23 (stub-acceptable 501). When M4 lands the real finalize crypto
// + populates the on-disk artifact, this driver will start returning exit 0 unchanged.
//
// Args:
//   --coordinator-url URL     defaults to local-cluster.json plan
//   --dkg-epoch N             required, decimal string
//   --request-id ID           required, ISafeId (alphanumeric + . _ -)
//   [--bearer-token TOKEN]    optional bearer token for the coordinator
//
// Exit codes — operator runbook contract:
//
//   0   success — coordinator returned 200 OK (real chain confirmation) or 202 (simulated).
//   1   generic request/parse failure (network, malformed JSON, 5xx other than the documented
//       relayer/chain-confirmation errors below).
//   2   usage error.
//  23   stub-acceptable 501 — finalize transcript still carries `notImplementedPhase` (M3a/M4
//       stub). Driver prints the phase string. Re-run after M4 lands.
//  24   mpcca_finalize_transcript_not_found — re-run `npm run local:mpcca:withdraw:round1`
//       AND wait for M4's round2/prove/finalize to land + populate the finalize transcript.
//  25   relayer_returned_error or relayer_unreachable — investigate relayer logs.
//  26   chain_confirmation_timeout — tx submitted but did not confirm within the deadline;
//       investigate Aptos fullnode status.
// =============================================================================================
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const EXIT_SUCCESS = 0;
const EXIT_GENERIC_FAILURE = 1;
const EXIT_USAGE_ERROR = 2;
const EXIT_STUB_OK = 23;
const EXIT_FINALIZE_NOT_FOUND = 24;
const EXIT_RELAYER_ERROR = 25;
const EXIT_CHAIN_CONFIRMATION_TIMEOUT = 26;

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");

const args = process.argv.slice(2);
let coordinatorUrl;
let dkgEpoch;
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
    case "--request-id":
      requestId = args[++i];
      break;
    case "--bearer-token":
      bearerToken = args[++i];
      break;
    case "--help":
    case "-h":
      printHelp();
      process.exit(EXIT_SUCCESS);
    default:
      console.error(`unknown arg: ${arg}`);
      process.exit(EXIT_USAGE_ERROR);
  }
}

function printHelp() {
  console.log(
    "usage: local_mpcca_withdraw_submit --coordinator-url URL --dkg-epoch N --request-id ID\n" +
      "                                   [--bearer-token TOKEN]\n" +
      "\n" +
      "Drives POST /v2/withdraw/mpcca/submit. The coordinator reads the finalize transcript at\n" +
      "<stateRoot>/coordinator/mpcca_withdraw/<dkgEpoch>__<requestId>__finalize.json, assembles\n" +
      "the 27-field WithdrawV2CallArgs, calls the relayer, and polls for chain confirmation.\n" +
      "\n" +
      "M5b is plumbing-only: the finalize transcript is the M3a NotImplemented stub today, so\n" +
      "the EXPECTED outcome TODAY is exit 23 with notImplementedPhase set. When M4d/M4e land\n" +
      "the real finalize crypto, this driver returns exit 0 unchanged.\n" +
      "\n" +
      "Exit codes:\n" +
      `  ${EXIT_SUCCESS}   success — coordinator returned 200 (real chain confirmation) or 202 (simulated)\n` +
      `  ${EXIT_GENERIC_FAILURE}   generic request/parse failure\n` +
      `  ${EXIT_USAGE_ERROR}   usage error\n` +
      `  ${EXIT_STUB_OK}  stub-acceptable 501 — finalize transcript still on NotImplemented phase\n` +
      `  ${EXIT_FINALIZE_NOT_FOUND}  mpcca_finalize_transcript_not_found — re-run withdraw round1 + wait for M4\n` +
      `  ${EXIT_RELAYER_ERROR}  relayer_returned_error / relayer_unreachable\n` +
      `  ${EXIT_CHAIN_CONFIRMATION_TIMEOUT}  chain_confirmation_timeout — tx did not confirm within deadline\n`,
  );
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
require_arg("--request-id", requestId);
if (!/^[A-Za-z0-9._-]{1,128}$/.test(requestId)) {
  console.error("--request-id must be 1..=128 chars of [A-Za-z0-9._-] (ISafeId)");
  process.exit(EXIT_USAGE_ERROR);
}

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

const payload = { dkgEpoch, requestId };

const headers = { "content-type": "application/json" };
if (bearerToken) headers.authorization = `Bearer ${bearerToken}`;

let res;
try {
  res = await fetch(new URL("/v2/withdraw/mpcca/submit", coordinatorUrl), {
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
if (res.status === 400 && body?.error === "mpcca_finalize_transcript_not_found") {
  console.error(
    "finalize transcript not found — re-run `npm run local:mpcca:withdraw:round1` first " +
      "and wait for M4 to populate the finalize transcript.",
  );
  process.stdout.write(`${JSON.stringify(body, null, 2)}\n`);
  process.exit(EXIT_FINALIZE_NOT_FOUND);
}
if (
  res.status === 502 &&
  (body?.error === "relayer_returned_error" || body?.error === "relayer_unreachable")
) {
  console.error(`relayer error: ${body.error}`);
  process.stdout.write(`${JSON.stringify(body, null, 2)}\n`);
  process.exit(EXIT_RELAYER_ERROR);
}
if (res.status === 502 && body?.error === "chain_confirmation_timeout") {
  console.error("chain confirmation timed out");
  process.stdout.write(`${JSON.stringify(body, null, 2)}\n`);
  process.exit(EXIT_CHAIN_CONFIRMATION_TIMEOUT);
}

if (res.status === 501) {
  // M5b expected stub outcome: finalize transcript still on a NotImplemented phase.
  console.error(`stub-acceptable 501: notImplementedPhase=${body?.notImplementedPhase ?? "(none)"}`);
  process.stdout.write(`${JSON.stringify(body, null, 2)}\n`);
  process.exit(EXIT_STUB_OK);
}
if (!res.ok && res.status !== 202) {
  console.error(`coordinator returned ${res.status}`);
  process.stdout.write(`${JSON.stringify(body, null, 2)}\n`);
  process.exit(EXIT_GENERIC_FAILURE);
}
// 200 OK or 202 Accepted — real or simulated submission succeeded.
process.stdout.write(`${JSON.stringify(body, null, 2)}\n`);
process.exit(EXIT_SUCCESS);

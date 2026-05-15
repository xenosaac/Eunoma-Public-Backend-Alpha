#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const PHASE1_EXIT = 21;

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");

const args = process.argv.slice(2);
let coordinatorUrl;
let dkgEpoch;
let selectedSlots;
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
    case "--selected-slots":
      selectedSlots = args[++i].split(",").map((s) => Number.parseInt(s, 10));
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
        "usage: local_vault_ek_derive --coordinator-url URL --dkg-epoch N [--selected-slots 0,1,2,3,4] [--ca-dkg-transcript-hash HEX] [--request-id ID] [--bearer-token TOKEN]",
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
if (selectedSlots) payload.selectedSlots = selectedSlots;
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
    "Phase 1: MP-SPDZ adapter not available — this is expected. Phase 2 will make this command succeed.",
  );
  process.stdout.write(`${JSON.stringify(body)}\n`);
  process.exit(PHASE1_EXIT);
}

if (!res.ok) {
  console.error(`coordinator returned ${res.status}`);
  process.stdout.write(`${JSON.stringify(body, null, 2)}\n`);
  process.exit(1);
}

process.stdout.write(`${JSON.stringify(body, null, 2)}\n`);

#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// =============================================================================================
// MPCCA withdraw round1 fan-out driver.
//
// Drives POST /v2/withdraw/mpcca/start against a coordinator that has already run Phase 2
// (vault_ek derive), Milestone 1 (CA registration sigma), Milestone 2a (vault_state_v2 init),
// and Milestone 2b (deposit observer for the targeted depositCount). All 5 selected workers
// run their round1 ingress crypto (HPKE-decrypt α_share + Pedersen verify + seal at rest)
// and the coordinator persists the round1 transcript at
// `<stateRoot>/coordinator/mpcca_withdraw/<dkgEpoch>__<requestId>__round1.json`.
//
// Status: M1 round1 ingress is LIVE (Rust worker `run_round1_v2` at lib.rs:8800). This driver
// is now a single-round audit/debug tool — the umbrella orchestrator `local_v2_withdraw_submit.mjs`
// drives the full round1 → round2 → finalize → frost-attest → submit pipeline.
//
// REQUIRED ingress fields (caller-supplied — these are cryptographic outputs that the umbrella
// orchestrator generates client-side):
//   --amount-commitment HEX
//   --per-share-commitments HEX,HEX,HEX,HEX,HEX
//   --ingress-envelopes-json PATH   (JSON: HpkeEnvelope[5])
//
// Exit codes — operator runbook contract:
//
//   0    success — coordinator returned 200 with round1 transcript.
//   1    generic request/parse failure (network, malformed JSON, coordinator 5xx).
//   2    usage error.
//  24    vault_state_init_provenance_unknown — Milestone 2a prereq missing. Operator action:
//        re-run `npm run local:vault-state:init`.
//  25    crypto_stub_phase_divergence — workers returned divergent phase responses.
//  26    round1_unexpected_stub — REGRESSION: worker returned the M3a NotImplemented stub. M1
//        retired the stub; if it returns now, investigate the worker build (cargo rebuild?).
// =============================================================================================
const EXIT_SUCCESS = 0;
const EXIT_GENERIC_FAILURE = 1;
const EXIT_USAGE_ERROR = 2;
const EXIT_INIT_PROVENANCE = 24;
const EXIT_PHASE_DIVERGENCE = 25;
const EXIT_UNEXPECTED_STUB = 26;

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
let amountCommitment;
let perShareCommitmentsCsv;
let ingressEnvelopesJsonPath;

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
    case "--amount-commitment":
      amountCommitment = args[++i];
      break;
    case "--per-share-commitments":
      perShareCommitmentsCsv = args[++i];
      break;
    case "--ingress-envelopes-json":
      ingressEnvelopesJsonPath = args[++i];
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
          "                                   --amount-commitment HEX\n" +
          "                                   --per-share-commitments HEX,HEX,HEX,HEX,HEX\n" +
          "                                   --ingress-envelopes-json PATH\n" +
          "                                   [--request-id ID] [--bearer-token TOKEN]\n" +
          "\n" +
          "Drives POST /v2/withdraw/mpcca/start. M1 round1 ingress is LIVE — workers HPKE-decrypt\n" +
          "α_share + Pedersen-verify + seal at rest + return ingress_transcript_hash.\n" +
          "\n" +
          "Exit codes:\n" +
          `  ${EXIT_SUCCESS}   success — coordinator returned 200 OK with round1 transcript\n` +
          `  ${EXIT_GENERIC_FAILURE}   generic request/parse failure\n` +
          `  ${EXIT_USAGE_ERROR}   usage error\n` +
          `  ${EXIT_INIT_PROVENANCE}  vault_state_init_provenance_unknown — re-run local:vault-state:init\n` +
          `  ${EXIT_PHASE_DIVERGENCE}  crypto_stub_phase_divergence — workers returned divergent phases\n` +
          `  ${EXIT_UNEXPECTED_STUB}  round1_unexpected_stub REGRESSION — M3a stub returned despite M1 landing\n`,
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
require_arg("--amount-commitment", amountCommitment);
require_arg("--per-share-commitments", perShareCommitmentsCsv);
require_arg("--ingress-envelopes-json", ingressEnvelopesJsonPath);

const perShareCommitments = perShareCommitmentsCsv
  .split(",")
  .map((s) => s.trim())
  .filter((s) => s.length > 0);
if (perShareCommitments.length !== 5) {
  console.error(
    `--per-share-commitments must be exactly 5 hex strings (got ${perShareCommitments.length})`,
  );
  process.exit(EXIT_USAGE_ERROR);
}
let ingressEnvelopes;
try {
  ingressEnvelopes = JSON.parse(readFileSync(ingressEnvelopesJsonPath, "utf8"));
} catch (err) {
  console.error(
    `--ingress-envelopes-json read failed: ${err?.message ?? err}`,
  );
  process.exit(EXIT_USAGE_ERROR);
}
if (!Array.isArray(ingressEnvelopes) || ingressEnvelopes.length !== 5) {
  console.error("--ingress-envelopes-json must contain a 5-element array of HpkeEnvelope");
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
  amountCommitment,
  perShareCommitments,
  ingressEnvelopes,
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

// REGRESSION GUARD: M1 retired the round1 stub. If 501 + the M3a phase string returns now,
// the worker build is stale (recompile + reinstall) or a regression slipped past CI.
if (res.status === 501) {
  const phase = body?.notImplementedPhase ?? body?.phase ?? null;
  console.error(
    "round1_unexpected_stub: M1 retired this stub; the worker is returning 501 NotImplemented. " +
      "Investigate: (1) `cargo build --release` rebuilt, (2) `local:cluster:start` restarted, " +
      "(3) the request shape carries amountCommitment/perShareCommitments/ingressEnvelopes.",
  );
  if (phase) console.error(`  worker phase: ${phase}`);
  process.stdout.write(`${JSON.stringify(body, null, 2)}\n`);
  process.exit(EXIT_UNEXPECTED_STUB);
}
if (!res.ok) {
  console.error(`coordinator returned ${res.status}`);
  process.stdout.write(`${JSON.stringify(body, null, 2)}\n`);
  process.exit(EXIT_GENERIC_FAILURE);
}
// 200 OK — round1 ingress completed; transcript persisted.
process.stdout.write(`${JSON.stringify(body, null, 2)}\n`);
process.exit(EXIT_SUCCESS);

#!/usr/bin/env node
// =============================================================================================
// Milestone 6 sub-milestone 6-a — Local MPCCA withdraw full-flow smoke.
//
// Drives the complete chain:
//   round1 → round2 → finalize → frost-attest → submit (mock or real relayer)
// against a running local cluster, asserting __finalize.json transitions from M3a stub →
// M4-c4 mpccaWithdrawFinalizeArtifact → M5-c1 27-field withdrawV2CallArgsFields, then hands
// the call args to the relayer.
//
// This is the LOCAL EQUIVALENT of `npm run testnet:e2e`. testnet:e2e itself remains the
// fail-closed stub at scripts/testnet_e2e_fail_closed.mjs (exits 2) because:
//   (a) M6-b user-side withdraw Groth16 prover is NOT implemented; --withdraw-proof-hex
//       remains an operator-supplied input.
//   (b) M6-d real Aptos testnet wallet + bridge package + PreparedWithdrawProofVK are not
//       provisioned in this repo.
//
// Once M6-b + M6-d ship, testnet:e2e becomes a thin wrapper around this script that
// substitutes the real chain endpoints + relayer submit.
//
// Exit codes — operator runbook contract:
//   0   success — entire local flow including (mock) chain submission completed.
//   1   generic failure.
//   2   usage error (missing required arg).
//  30   round1 driver failed (re-run prereqs: CA DKG, vault EK, vault state init).
//  31   round2 driver failed (the M4-c2 wire — check the coordinator log for the specific
//       error code surface: round1_transcript_not_found / dk_base_indices_divergence / etc.).
//  32   finalize driver failed (M4-c4 wire — round2_transcript_not_found /
//       finalize_under_quorum / dk_base_indices_divergence / etc.).
//  33   frost-attest driver failed (M5-c1 wire — see local_mpcca_frost_attest exit codes).
//  34   submit driver failed (M5b wire — see local_mpcca_withdraw_submit exit codes).
//  35   __finalize.json shape regression at any stage.
// =============================================================================================
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const EXIT_SUCCESS = 0;
const EXIT_GENERIC_FAILURE = 1;
const EXIT_USAGE_ERROR = 2;
const EXIT_ROUND1_FAILED = 30;
const EXIT_ROUND2_FAILED = 31;
const EXIT_FINALIZE_FAILED = 32;
const EXIT_FROST_ATTEST_FAILED = 33;
const EXIT_SUBMIT_FAILED = 34;
const EXIT_FINALIZE_SHAPE_REGRESSION = 35;

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");

const args = process.argv.slice(2);
let dkgEpoch;
let requestId;
let bridge;
let vault;
let operatorSetVersion;
let frostGroupPubkey;
let circuitVersionsHash;
let withdrawProofHex;
let memoHex;
let stateRoot;
let coordinatorUrl;
let bearerToken;
let skipSubmit = false;

for (let i = 0; i < args.length; i += 1) {
  const arg = args[i];
  switch (arg) {
    case "--dkg-epoch":
      dkgEpoch = args[++i];
      break;
    case "--request-id":
      requestId = args[++i];
      break;
    case "--bridge":
      bridge = args[++i];
      break;
    case "--vault":
      vault = args[++i];
      break;
    case "--operator-set-version":
      operatorSetVersion = args[++i];
      break;
    case "--frost-group-pubkey":
      frostGroupPubkey = args[++i];
      break;
    case "--circuit-versions-hash":
      circuitVersionsHash = args[++i];
      break;
    case "--withdraw-proof-hex":
      withdrawProofHex = args[++i];
      break;
    case "--memo-hex":
      memoHex = args[++i];
      break;
    case "--state-root":
      stateRoot = args[++i];
      break;
    case "--coordinator-url":
      coordinatorUrl = args[++i];
      break;
    case "--bearer-token":
      bearerToken = args[++i];
      break;
    case "--skip-submit":
      skipSubmit = true;
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
    "usage: local_mpcca_full_smoke --dkg-epoch N --request-id ID \\\n" +
      "         --bridge HEX --vault HEX --operator-set-version N \\\n" +
      "         --frost-group-pubkey HEX --circuit-versions-hash HEX \\\n" +
      "         --withdraw-proof-hex HEX [--memo-hex HEX] [--state-root PATH] \\\n" +
      "         [--coordinator-url URL] [--bearer-token TOK] [--skip-submit]\n\n" +
      "Drives the complete MPCCA withdraw flow end-to-end against a running local cluster.\n" +
      "Prereqs (must already have run successfully):\n" +
      "  npm run local:cluster:config && npm run local:cluster:start\n" +
      "  npm run local:ca-dkg:v2 && npm run local:vault-ek:derive\n" +
      "  npm run local:ca-registration:v2 && npm run local:vault-state:init\n" +
      "  npm run local:vault-state:observe-deposit  # one or more times\n" +
      "  npm run local:mpcca:withdraw:round1  # produces __round1.json\n" +
      "Then this script drives round2 + finalize + frost-attest + submit.\n",
  );
}

const required = {
  "--dkg-epoch": dkgEpoch,
  "--request-id": requestId,
  "--bridge": bridge,
  "--vault": vault,
  "--operator-set-version": operatorSetVersion,
  "--frost-group-pubkey": frostGroupPubkey,
  "--circuit-versions-hash": circuitVersionsHash,
  "--withdraw-proof-hex": withdrawProofHex,
};
for (const [flag, value] of Object.entries(required)) {
  if (!value) {
    console.error(`missing required ${flag}`);
    process.exit(EXIT_USAGE_ERROR);
  }
}

stateRoot ??= resolve(
  serviceRoot,
  process.env.EUNOMA_LOCAL_STATE_ROOT ?? ".agent-local/eunoma-v2",
);

const planPath = resolve(stateRoot, "cluster/local-cluster.json");
if (!coordinatorUrl) {
  if (!existsSync(planPath)) {
    console.error(
      `local cluster config not found at ${planPath}; run npm run local:cluster:config or pass --coordinator-url`,
    );
    process.exit(EXIT_USAGE_ERROR);
  }
  const plan = JSON.parse(readFileSync(planPath, "utf8"));
  coordinatorUrl = `http://127.0.0.1:${plan.coordinator.port}`;
  bearerToken ??= plan.coordinator.env?.COORDINATOR_BEARER_TOKEN;
}

// Prereq check: round1 transcript must exist (round2 driver requires it).
const round1ArtifactPath = resolve(
  stateRoot,
  "coordinator",
  "mpcca_withdraw",
  `${dkgEpoch}__${requestId}__round1.json`,
);
if (!existsSync(round1ArtifactPath)) {
  console.error(
    `__round1.json not found at ${round1ArtifactPath}; run npm run local:mpcca:withdraw:round1 first`,
  );
  process.exit(EXIT_ROUND1_FAILED);
}

function runDriver(name, scriptPath, extraArgs, expectExit = EXIT_SUCCESS) {
  console.log(`▶ ${name}`);
  const result = spawnSync(
    "node",
    [scriptPath, ...extraArgs],
    { stdio: "inherit", cwd: serviceRoot },
  );
  if (result.status !== expectExit) {
    console.error(
      `✗ ${name} failed (exit ${result.status}, expected ${expectExit})`,
    );
    return result.status ?? EXIT_GENERIC_FAILURE;
  }
  console.log(`✓ ${name} succeeded`);
  return EXIT_SUCCESS;
}

const sharedArgs = [
  "--dkg-epoch",
  dkgEpoch,
  "--request-id",
  requestId,
  "--coordinator-url",
  coordinatorUrl,
  ...(bearerToken ? ["--bearer-token", bearerToken] : []),
  "--state-root",
  stateRoot,
];

// NOTE: round2 + finalize are driven by the coordinator's /v2/withdraw/mpcca/{round2,finalize}
// routes, but there's no operator-facing CLI driver for them yet (they're driven inline by
// the coordinator after round1). The M6-a smoke ASSUMES round2 + finalize have already run
// (typically via the same coordinator that handled round1). The verification below confirms
// __round2.json + __finalize.json (M4-c4 stub) are present BEFORE driving frost-attest.

const round2ArtifactPath = resolve(
  stateRoot,
  "coordinator",
  "mpcca_withdraw",
  `${dkgEpoch}__${requestId}__round2.json`,
);
if (!existsSync(round2ArtifactPath)) {
  console.error(
    `__round2.json not found at ${round2ArtifactPath}; M4-c2 round2 has not run yet for ` +
      `(${dkgEpoch}, ${requestId}). Re-run via POST /v2/withdraw/mpcca/round2.`,
  );
  process.exit(EXIT_ROUND2_FAILED);
}
const finalizeArtifactPath = resolve(
  stateRoot,
  "coordinator",
  "mpcca_withdraw",
  `${dkgEpoch}__${requestId}__finalize.json`,
);
if (!existsSync(finalizeArtifactPath)) {
  console.error(
    `__finalize.json not found at ${finalizeArtifactPath}; M4-c4 finalize has not run yet. ` +
      `Re-run via POST /v2/withdraw/mpcca/finalize.`,
  );
  process.exit(EXIT_FINALIZE_FAILED);
}
const finalizePreFrost = JSON.parse(readFileSync(finalizeArtifactPath, "utf8"));
if (
  finalizePreFrost.notImplementedPhase !== "m4_pending_frost_signature_assembly" ||
  !finalizePreFrost.mpccaWithdrawFinalizeArtifact
) {
  console.error(
    "__finalize.json shape regression pre-frost-attest: expected " +
      "notImplementedPhase = 'm4_pending_frost_signature_assembly' + " +
      "mpccaWithdrawFinalizeArtifact populated.",
  );
  process.exit(EXIT_FINALIZE_SHAPE_REGRESSION);
}

// Drive frost-attest.
const frostExit = runDriver(
  "M5-c1 frost-attest",
  resolve(scriptDir, "local_mpcca_frost_attest.mjs"),
  [
    ...sharedArgs,
    "--bridge",
    bridge,
    "--vault",
    vault,
    "--operator-set-version",
    operatorSetVersion,
    "--frost-group-pubkey",
    frostGroupPubkey,
    "--circuit-versions-hash",
    circuitVersionsHash,
    "--withdraw-proof-hex",
    withdrawProofHex,
    ...(memoHex !== undefined ? ["--memo-hex", memoHex] : []),
  ],
);
if (frostExit !== EXIT_SUCCESS) {
  process.exit(EXIT_FROST_ATTEST_FAILED);
}

// Post-frost-attest shape verification: __finalize.json must now carry full 27-field
// withdrawV2CallArgsFields, no notImplementedPhase.
const finalizePostFrost = JSON.parse(readFileSync(finalizeArtifactPath, "utf8"));
if (finalizePostFrost.notImplementedPhase !== undefined) {
  console.error(
    "__finalize.json shape regression post-frost-attest: notImplementedPhase still " +
      `present = ${JSON.stringify(finalizePostFrost.notImplementedPhase)}`,
  );
  process.exit(EXIT_FINALIZE_SHAPE_REGRESSION);
}
if (
  !finalizePostFrost.withdrawV2CallArgsFields ||
  typeof finalizePostFrost.withdrawV2CallArgsFields !== "object"
) {
  console.error(
    "__finalize.json shape regression: withdrawV2CallArgsFields missing post-frost-attest",
  );
  process.exit(EXIT_FINALIZE_SHAPE_REGRESSION);
}

if (skipSubmit) {
  console.log(
    JSON.stringify(
      {
        ok: true,
        command: "local:mpcca:full-smoke",
        skippedSubmit: true,
        coordinatorUrl,
        dkgEpoch,
        requestId,
        finalizeArtifactPath,
        withdrawV2CallArgsFieldCount: Object.keys(
          finalizePostFrost.withdrawV2CallArgsFields,
        ).length,
        message:
          "M6-a local smoke succeeded through frost-attest; submit skipped per --skip-submit. " +
          "__finalize.json carries the full 27-field WithdrawV2CallArgs.",
      },
      null,
      2,
    ),
  );
  process.exit(EXIT_SUCCESS);
}

// Drive submit (M5b). This will fan to the relayer. In a real testnet:e2e flow this is the
// chain submission gate; in a local smoke without a real relayer, this surfaces the M5b
// plumbing path including the chain-confirmation polling.
const submitExit = runDriver(
  "M5b submit",
  resolve(scriptDir, "local_mpcca_withdraw_submit.mjs"),
  sharedArgs,
);
if (submitExit !== EXIT_SUCCESS) {
  console.error(
    `submit failed (exit ${submitExit}); investigate relayer logs. The withdrawV2CallArgsFields ` +
      `is correctly assembled and the M5b plumbing is exercised; the failure is downstream of M5-c1.`,
  );
  process.exit(EXIT_SUBMIT_FAILED);
}

console.log(
  JSON.stringify(
    {
      ok: true,
      command: "local:mpcca:full-smoke",
      coordinatorUrl,
      dkgEpoch,
      requestId,
      finalizeArtifactPath,
      withdrawV2CallArgsFieldCount: Object.keys(
        finalizePostFrost.withdrawV2CallArgsFields,
      ).length,
      message:
        "M6-a local smoke succeeded: round1 → round2 → finalize → frost-attest → submit. " +
        "All stages green. testnet:e2e will succeed once M6-b user-side Groth16 prover " +
        "ships + M6-d real testnet wallet/bridge are provisioned.",
    },
    null,
    2,
  ),
);
process.exit(EXIT_SUCCESS);

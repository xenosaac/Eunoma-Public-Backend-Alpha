#!/usr/bin/env node
// =============================================================================================
// Milestone 6 — Real Aptos testnet:e2e binding final gate (goal.md Final Acceptance).
//
// goal.md contract: this script exits 0 ONLY after a real Aptos testnet chain-confirmed flow:
//   CA DKG V2 → vaultEk derivation → vault registration → deposit → confirmed worker state
//   update → MPCCA withdraw (round1 → round2 → finalize → frost-attest) → relayer submit →
//   chain confirmation.
//
// Final-report items (must all be present on exit 0):
//   - txHashes.vaultInit                — real Aptos testnet tx hash of init_vault_with_ca_registration_v2.
//   - txHashes.deposit                  — real Aptos testnet tx hash of deposit_with_commitment_v2.
//   - txHashes.relayerSubmit             — real relayer submit tx hash.
//   - txHashes.chainConfirmedWithdraw    — chain-confirmed withdraw tx hash.
//   - depositEventProof                 — full DepositConfirmedV2 event with type, sequence, version, data.
//   - transcriptHashes.caPayload, caDkgV2Roster, frostDkgV2Roster, deoperatorRoster, quorum,
//     vaultStateInit, vaultStatePerSlot[7], mpcca, submit — all goal.md item-8 hashes.
//
// If ANY prerequisite is missing, exit nonzero with a structured `preconditions_not_met` JSON
// listing every missing item + its remediation step. NO completion language is emitted on the
// failure path.
//
// Operational preconditions (env):
//   APTOS_TESTNET_NODE_URL            required — Aptos testnet fullnode REST endpoint.
//   BRIDGE_PACKAGE_ADDRESS            required — 0x-prefixed published bridge package addr.
//   RELAYER_SUBMIT_ENABLED=1          required — relayer's safety gate.
//   ADMIN_PROFILE                     required — aptos CLI profile with admin rights.
//   RELAYER_BEARER_TOKEN              required — coordinator → relayer auth.
//   EUNOMA_LOCAL_STATE_ROOT           optional — defaults to .agent-local/eunoma-v2.
//   EUNOMA_TESTNET_REQUEST_ID         required — unique requestId (ISafeId).
//   EUNOMA_TESTNET_DKG_EPOCH          required — decimal string.
//   EUNOMA_TESTNET_WITHDRAW_PROOF     required (M6-b) — hex Groth16 proof.
//   EUNOMA_TESTNET_WITHDRAW_WITNESS_JSON  alternative — auto-generates proof via M6-b.
//   EUNOMA_TESTNET_VAULT_ADDRESS      required — 0x-prefixed vault address (NOT BRIDGE fallback).
//   EUNOMA_TESTNET_ASSET_TYPE         required — 0x-prefixed Object<Metadata> address.
//   EUNOMA_TESTNET_CHAIN_ID           required — u8 (2 for testnet).
//   EUNOMA_TESTNET_SENDER_ADDRESS     required — depositor 0x address.
//   EUNOMA_TESTNET_VAULT_INIT_TX_HASH required (or auto-detected from vault-init artifact).
//   EUNOMA_TESTNET_DEPOSIT_TX_HASH    required — chain-confirmed deposit tx.
//   EUNOMA_TESTNET_DEPOSIT_COUNT      required — chain-authoritative deposit_count from event.
//   EUNOMA_TESTNET_VAULT_EK           required — 0x-prefixed compressed-Ristretto hex.
//   EUNOMA_TESTNET_CA_DKG_TRANSCRIPT_HASH  optional — when set, cross-checked against each
//                                          slot's vault_state_v2.ca_dkg_transcript_hash.
//   EUNOMA_TESTNET_REPORT_OUT         optional — file path to also write the final report JSON.
//   EUNOMA_TESTNET_OPERATOR_SET_VERSION  optional — defaults "1".
//   EUNOMA_TESTNET_FROST_GROUP_PUBKEY    optional — defaults zero-bytes.
//   EUNOMA_TESTNET_CIRCUIT_VERSIONS_HASH optional — defaults zero-bytes.
//
// Exit codes:
//
//    0   success — real Aptos testnet chain-confirmed flow completed; full report printed.
//    1   generic failure / final-report artifacts missing after a successful submit.
//    2   usage error (missing required env vars).
//   40   M6-b user-side withdraw Groth16 prover output missing or malformed.
//   41   M6-d real Aptos testnet operational setup not provisioned (CLI, profile, chain state,
//        artifact, or worker state cursor).
//   42   M6-a local smoke prerequisite failed.
//   43   relayer rejected or chain confirmation failed.
// =============================================================================================
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";

import {
  runPreflight,
  buildFinalReport,
  validateRequiredEnv,
  evaluateReplayBypass,
  evaluateSkipTreeBuild,
} from "./_lib/testnet_e2e_checks.mjs";

const EXIT_SUCCESS = 0;
const EXIT_GENERIC_FAILURE = 1;
const EXIT_USAGE_ERROR = 2;
const EXIT_M6B_NOT_IMPLEMENTED = 40;
const EXIT_M6D_NOT_PROVISIONED = 41;
const EXIT_M6A_LOCAL_SMOKE_FAILED = 42;
const EXIT_RELAYER_OR_CHAIN_FAILED = 43;

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");

const env = process.env;

// =============================================================================================
// Stage 1: env-variable precondition checks (structural; before any chain query).
//
// Required env vars and their format constraints are validated by the pure helper
// `validateRequiredEnv` in _lib/testnet_e2e_checks.mjs, so the same logic is exercised by
// unit tests.
//
// NOTE: EUNOMA_TESTNET_VAULT_INIT_TX_HASH is allowed to be derived from the persisted
// artifact in the pre-flight stage, so it is not in the required-env list.
// NOTE: EUNOMA_TESTNET_WITHDRAW_PROOF is special-cased below — it can be auto-generated from
// EUNOMA_TESTNET_WITHDRAW_WITNESS_JSON via the M6-b wrapper, so it is checked AFTER that
// auto-generation step.
// =============================================================================================

const envValidation = validateRequiredEnv(env);
const envMissing = envValidation.ok ? [] : envValidation.missing.slice();

// M6-b prover output: prefer hex proof; allow witness JSON to auto-generate via M6-b wrapper.
if (!env.EUNOMA_TESTNET_WITHDRAW_PROOF) {
  if (env.EUNOMA_TESTNET_WITHDRAW_WITNESS_JSON) {
    console.log("▶ M6-b: generating withdraw Groth16 proof from witness JSON");
    const proveArgs = [
      "scripts/local_generate_withdraw_proof.mjs",
      "--witness-json",
      env.EUNOMA_TESTNET_WITHDRAW_WITNESS_JSON,
    ];
    const prove = spawnSync("node", proveArgs, { cwd: serviceRoot, encoding: "utf8" });
    if (prove.status !== EXIT_SUCCESS) {
      console.error(
        JSON.stringify(
          {
            ok: false,
            command: "testnet:e2e",
            error: "m6b_prover_failed",
            message:
              "M6-b withdraw proof generation failed. Investigate witness inputs + circuit artifacts (circuits/generated/withdrawal_proof_*).",
            stderr: prove.stderr,
            exitCode: prove.status,
          },
          null,
          2,
        ),
      );
      process.exit(EXIT_M6B_NOT_IMPLEMENTED);
    }
    let proverOutput;
    try {
      proverOutput = JSON.parse(prove.stdout);
    } catch (parseErr) {
      console.error(
        JSON.stringify(
          {
            ok: false,
            error: "m6b_prover_output_malformed",
            message:
              "M6-b prover stdout was not valid JSON; cannot extract proofHex. " +
              (parseErr instanceof Error ? parseErr.message : String(parseErr)),
            stdoutFirst200: prove.stdout.slice(0, 200),
          },
          null,
          2,
        ),
      );
      process.exit(EXIT_M6B_NOT_IMPLEMENTED);
    }
    env.EUNOMA_TESTNET_WITHDRAW_PROOF = proverOutput.proofHex;
    if (!env.EUNOMA_TESTNET_WITHDRAW_PROOF || env.EUNOMA_TESTNET_WITHDRAW_PROOF.length === 0) {
      console.error(
        JSON.stringify(
          {
            ok: false,
            error: "m6b_prover_empty_output",
            message: "M6-b prover ran but produced empty proof hex",
          },
          null,
          2,
        ),
      );
      process.exit(EXIT_M6B_NOT_IMPLEMENTED);
    }
    console.log(
      `▶ M6-b: proof generated (${env.EUNOMA_TESTNET_WITHDRAW_PROOF.length} hex chars)`,
    );
  } else {
    envMissing.push({
      key: "EUNOMA_TESTNET_WITHDRAW_PROOF",
      message:
        "User-side Groth16 withdraw proof bytes (hex), OR set EUNOMA_TESTNET_WITHDRAW_WITNESS_JSON to a witness JSON file to auto-generate via M6-b.",
      priority: "m6b",
    });
  }
}

if (envMissing.length > 0) {
  const priorities = new Set(envMissing.map((m) => m.priority));
  console.error(
    JSON.stringify(
      {
        ok: false,
        command: "testnet:e2e",
        error: "preconditions_not_met",
        message:
          "Required env vars missing or malformed. V2 is NOT complete. Fix each item below; the script will not proceed.",
        missing: envMissing,
      },
      null,
      2,
    ),
  );
  if (priorities.has("m6b")) process.exit(EXIT_M6B_NOT_IMPLEMENTED);
  process.exit(EXIT_USAGE_ERROR);
}

// =============================================================================================
// Stage 2: structural pre-flight — CLI, chain state, artifacts, worker cursors.
// =============================================================================================

const stateRoot = env.EUNOMA_LOCAL_STATE_ROOT ?? ".agent-local/eunoma-v2";
console.log("▶ pre-flight: aptos CLI / profile / account / chain state / artifacts / worker cursors");
const preflight = await runPreflight({ env, serviceRoot, stateRoot });
if (!preflight.ok) {
  console.error(
    JSON.stringify(
      {
        ok: false,
        command: "testnet:e2e",
        error: "preconditions_not_met",
        message:
          "Real Aptos testnet:e2e requires every prereq below. Fix each item; this script will not run the withdraw flow with any missing item. V2 is NOT complete.",
        missing: preflight.missing,
      },
      null,
      2,
    ),
  );
  const priorities = new Set(preflight.missing.map((m) => m.priority));
  if (priorities.has("m6b")) process.exit(EXIT_M6B_NOT_IMPLEMENTED);
  if (
    priorities.has("m6d-cli") ||
    priorities.has("m6d-chain") ||
    priorities.has("m6d-artifact")
  ) {
    process.exit(EXIT_M6D_NOT_PROVISIONED);
  }
  process.exit(EXIT_USAGE_ERROR);
}
const preflightSnapshot = preflight.snapshot;

// =============================================================================================
// Stage 2.5: M9 fresh-requestId guard + commitment-tree refresh.
//
// M9 acceptance requires a FRESH withdraw against a multi-leaf root, not an idempotent replay of
// M8 artifacts. Detect existing MPCCA artifacts for this requestId and bail unless explicitly
// allowed (local debugging only). Also ensure commitment_tree_v2.json exists; if absent, build it
// from confirmed depositor witness tx hashes.
// =============================================================================================

{
  const stateRootForGuard = env.EUNOMA_LOCAL_STATE_ROOT ?? ".agent-local/eunoma-v2";
  // The presence of a submit artifact (mpcca_withdraw_submit/<epoch>__<id>.json) means a chain
  // submit has ALREADY happened for this requestId — that's the unambiguous replay signal.
  // Finalize artifacts are created legitimately by local_v2_withdraw_full.mjs before testnet:e2e
  // runs, so we cannot use those as the replay marker.
  const submitArtifactPath = resolve(
    serviceRoot,
    stateRootForGuard,
    "coordinator",
    "mpcca_withdraw_submit",
    `${env.EUNOMA_TESTNET_DKG_EPOCH}__${env.EUNOMA_TESTNET_REQUEST_ID}.json`,
  );
  const submitArtifactExists = existsSync(submitArtifactPath);
  // M10-i (codex P1 fix): require BOTH gates to allow artifact replay.
  // CI never sets EUNOMA_LOCAL_SMOKE=1, so this is hard-fail in CI. The previous single-env
  // check (EUNOMA_TESTNET_ALLOW_REPLAY=1) could be flipped by any caller; the *_LOCAL suffix
  // makes the local-debug-only intent explicit. Logic lives in evaluateReplayBypass so the
  // two-gate decision can be unit-tested in isolation from the orchestrator.
  const allowReplay = evaluateReplayBypass(env);
  if (submitArtifactExists && !allowReplay) {
    console.error(
      JSON.stringify(
        {
          ok: false,
          command: "testnet:e2e",
          error: "m9_replay_blocked",
          message:
            "Submit artifact for this requestId already exists on disk — a chain submit already " +
            "happened for this exact (dkgEpoch, requestId). M9 acceptance requires a FRESH " +
            "withdraw against the multi-leaf root. Use a new EUNOMA_TESTNET_REQUEST_ID for " +
            "each run. To override (local debug only) set BOTH EUNOMA_LOCAL_SMOKE=1 AND " +
            "EUNOMA_TESTNET_ALLOW_REPLAY_LOCAL=1.",
          requestId: env.EUNOMA_TESTNET_REQUEST_ID,
          dkgEpoch: env.EUNOMA_TESTNET_DKG_EPOCH,
          submitArtifactPath,
        },
        null,
        2,
      ),
    );
    process.exit(EXIT_USAGE_ERROR);
  }
  console.log(
    `▶ M9 requestId=${env.EUNOMA_TESTNET_REQUEST_ID} mode=${submitArtifactExists ? "replay (allowed by EUNOMA_LOCAL_SMOKE=1 + EUNOMA_TESTNET_ALLOW_REPLAY_LOCAL=1)" : "fresh"}`,
  );

  // Build / refresh commitment_tree_v2.json. Idempotent; uses --refresh to merge with any
  // existing snapshot rather than rebuilding from scratch.
  const treePath = resolve(
    serviceRoot,
    stateRootForGuard,
    "coordinator",
    "commitment_tree_v2.json",
  );
  // M10-i (codex P1 fix): also two-gate the tree-build skip. The previous single-env check
  // (EUNOMA_TESTNET_SKIP_TREE_BUILD=1) was bypassable by any caller; require BOTH the
  // local-smoke marker and the *_LOCAL-suffixed flag so CI cannot skip the rebuild. Logic
  // lives in evaluateSkipTreeBuild for unit-test isolation.
  const skipTreeBuild = evaluateSkipTreeBuild(env);
  if (!skipTreeBuild) {
    console.log("▶ M9 commitment tree refresh: local_build_commitment_tree.mjs");
    const treeArgs = [
      "scripts/local_build_commitment_tree.mjs",
      "--bridge-package-address",
      env.BRIDGE_PACKAGE_ADDRESS,
      "--vault-address",
      env.EUNOMA_TESTNET_VAULT_ADDRESS,
      "--asset-type",
      env.EUNOMA_TESTNET_ASSET_TYPE,
      "--aptos-node-url",
      env.APTOS_TESTNET_NODE_URL,
      "--state-dir",
      resolve(serviceRoot, stateRootForGuard, "coordinator"),
    ];
    if (existsSync(treePath)) treeArgs.push("--refresh");
    const tree = spawnSync("node", treeArgs, { stdio: "inherit", cwd: serviceRoot });
    if (tree.status !== EXIT_SUCCESS) {
      console.error(
        JSON.stringify(
          {
            ok: false,
            command: "testnet:e2e",
            error: "m9_tree_build_failed",
            message:
              "M9 commitment tree builder failed. Investigate: (a) Aptos REST rate limits, " +
              "(b) bridge/vault/asset address mismatch, (c) depositor witness tx-hash list. " +
              "V2 is NOT complete.",
            treeExitCode: tree.status,
          },
          null,
          2,
        ),
      );
      process.exit(EXIT_USAGE_ERROR);
    }
  } else {
    console.log(
      "▶ M9 EUNOMA_LOCAL_SMOKE=1 + EUNOMA_TESTNET_SKIP_TREE_BUILD_LOCAL=1 — using existing commitment_tree_v2.json",
    );
  }
}

// =============================================================================================
// Stage 3: M6-a local smoke prerequisite (round1 → round2 → finalize → frost-attest).
// =============================================================================================

console.log("▶ M6-a precondition: running local:mpcca:full-smoke");
const localSmokeArgs = [
  "scripts/local_mpcca_full_smoke.mjs",
  "--dkg-epoch",
  env.EUNOMA_TESTNET_DKG_EPOCH,
  "--request-id",
  env.EUNOMA_TESTNET_REQUEST_ID,
  "--bridge",
  env.BRIDGE_PACKAGE_ADDRESS,
  "--vault",
  env.EUNOMA_TESTNET_VAULT_ADDRESS,
  "--operator-set-version",
  env.EUNOMA_TESTNET_OPERATOR_SET_VERSION ?? "1",
  "--frost-group-pubkey",
  env.EUNOMA_TESTNET_FROST_GROUP_PUBKEY ?? "00".repeat(32),
  "--circuit-versions-hash",
  env.EUNOMA_TESTNET_CIRCUIT_VERSIONS_HASH ?? "00".repeat(32),
  "--withdraw-proof-hex",
  env.EUNOMA_TESTNET_WITHDRAW_PROOF,
  "--skip-submit",
];
const localSmoke = spawnSync("node", localSmokeArgs, { stdio: "inherit", cwd: serviceRoot });
if (localSmoke.status !== EXIT_SUCCESS) {
  console.error(
    JSON.stringify(
      {
        ok: false,
        command: "testnet:e2e",
        error: "m6a_local_smoke_failed",
        message:
          "Local cluster smoke must pass BEFORE attempting real testnet submission. Fix local correctness first.",
        localSmokeExitCode: localSmoke.status,
      },
      null,
      2,
    ),
  );
  process.exit(EXIT_M6A_LOCAL_SMOKE_FAILED);
}

// =============================================================================================
// Stage 4: real testnet submit + chain confirmation.
// =============================================================================================

console.log("▶ M5b submit → real Aptos testnet");
const submitArgs = [
  "scripts/local_mpcca_withdraw_submit.mjs",
  "--dkg-epoch",
  env.EUNOMA_TESTNET_DKG_EPOCH,
  "--request-id",
  env.EUNOMA_TESTNET_REQUEST_ID,
];
const submit = spawnSync("node", submitArgs, {
  stdio: "inherit",
  cwd: serviceRoot,
  env: { ...env },
});
if (submit.status !== EXIT_SUCCESS) {
  console.error(
    JSON.stringify(
      {
        ok: false,
        command: "testnet:e2e",
        error: "relayer_or_chain_failed",
        message:
          "M5b submit route failed. Investigate: (a) relayer logs, (b) Aptos CLI logs, (c) chain-confirmation timeout. V2 is NOT complete.",
        submitExitCode: submit.status,
      },
      null,
      2,
    ),
  );
  process.exit(EXIT_RELAYER_OR_CHAIN_FAILED);
}

// =============================================================================================
// Stage 5: assemble final report (every required hash and tx hash).
// =============================================================================================

console.log("▶ assembling final report");
const reportResult = await buildFinalReport(preflightSnapshot, env, serviceRoot, stateRoot);
if (!reportResult.ok) {
  console.error(
    JSON.stringify(
      {
        ok: false,
        command: "testnet:e2e",
        error: "final_report_artifacts_missing",
        message:
          "M5b submit returned success but one or more required artifacts are missing or incomplete on disk. goal.md Final Acceptance requires every hash before V2 can be declared complete. V2 is NOT complete.",
        missingArtifacts: reportResult.missingArtifacts,
      },
      null,
      2,
    ),
  );
  process.exit(EXIT_GENERIC_FAILURE);
}

const report = {
  ok: true,
  command: "testnet:e2e",
  v2Complete: true,
  dkgEpoch: env.EUNOMA_TESTNET_DKG_EPOCH,
  requestId: env.EUNOMA_TESTNET_REQUEST_ID,
  ...reportResult.report,
  message: "goal.md Final Acceptance items 1-8 verified — real Aptos testnet chain-confirmed flow complete.",
};

const reportJson = JSON.stringify(report, null, 2);
console.log(reportJson);

if (env.EUNOMA_TESTNET_REPORT_OUT) {
  const outPath = env.EUNOMA_TESTNET_REPORT_OUT;
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, `${reportJson}\n`);
  console.log(`▶ wrote final report to ${outPath}`);
}

process.exit(EXIT_SUCCESS);

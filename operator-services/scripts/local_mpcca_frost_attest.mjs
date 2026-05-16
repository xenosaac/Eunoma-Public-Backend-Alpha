#!/usr/bin/env node
// =============================================================================================
// Milestone 5 sub-milestone 5-c1 — MPCCA withdraw FROST attestation driver.
//
// Drives POST /v2/withdraw/mpcca/frost-attest against a coordinator that has already produced
// a finalize transcript on disk at
//   <stateRoot>/coordinator/mpcca_withdraw/<dkgEpoch>__<requestId>__finalize.json
// (from M4-c4 finalize) and a round2 transcript at
//   <stateRoot>/coordinator/mpcca_withdraw/<dkgEpoch>__<requestId>__round2.json
// (from M4-c2 round2).
//
// After this driver returns 200, the __finalize.json artifact is mutated:
//   - notImplementedPhase = "m4_pending_frost_signature_assembly" is REMOVED.
//   - withdrawV2CallArgsFields populated (27 fields) — the M5b submit route reads this.
//   - attestationConfig (5 chain-side fields) + frostAttestationTranscriptHashes (per-phase
//     audit trail) + caPayloadHashRaw + caPayloadHashFr + messageBytes added.
//
// This script is M6-a (local smoke step 1 of N) — it drives the new route + asserts the
// resulting __finalize.json shape. M6-a-prep does NOT submit to chain; that's M5b's
// local_mpcca_withdraw_submit.mjs (which now sees a populated withdrawV2CallArgsFields).
//
// Args:
//   --coordinator-url URL         optional; defaults to local-cluster.json plan
//   --dkg-epoch N                 required (decimal string)
//   --request-id ID               required (alphanumeric + . _ -)
//   --bridge HEX                  required (32-byte hex; chain bridge package address)
//   --vault HEX                   required (32-byte hex; chain vault address)
//   --operator-set-version N      required (decimal string)
//   --frost-group-pubkey HEX      required (32-byte hex)
//   --circuit-versions-hash HEX   required (32-byte hex)
//   --withdraw-proof-hex HEX      required (Groth16 proof bytes hex)
//   [--memo-hex HEX]              optional memo binding
//   [--state-root PATH]           optional override; defaults to .agent-local/eunoma-v2
//   [--bearer-token TOKEN]        optional bearer auth for the coordinator
//
// Exit codes:
//   0   success — coordinator returned 200 with populated withdrawV2CallArgsFields
//   1   generic failure
//   2   usage error
//  30   round2_transcript_not_found / finalize_transcript_not_found — re-run M4-c2/M4-c4
//  31   round2_transcript_identity_mismatch — fix request fields to match round2 artifact
//  32   frost worker rejection — investigate worker logs (frost_*_unexpected_status, etc.)
//  33   __finalize.json shape regression — withdrawV2CallArgsFields missing after 200 OK
// =============================================================================================
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const EXIT_SUCCESS = 0;
const EXIT_GENERIC_FAILURE = 1;
const EXIT_USAGE_ERROR = 2;
const EXIT_TRANSCRIPT_NOT_FOUND = 30;
const EXIT_IDENTITY_MISMATCH = 31;
const EXIT_FROST_WORKER_REJECTION = 32;
const EXIT_FINALIZE_SHAPE_REGRESSION = 33;

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");

const args = process.argv.slice(2);
let coordinatorUrl;
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
    "usage: local_mpcca_frost_attest --dkg-epoch N --request-id ID --bridge HEX --vault HEX \\\n" +
      "         --operator-set-version N --frost-group-pubkey HEX --circuit-versions-hash HEX \\\n" +
      "         --withdraw-proof-hex HEX [--memo-hex HEX] [--coordinator-url URL] [--state-root PATH] [--bearer-token TOK]",
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
let plan;
if (!coordinatorUrl) {
  if (!existsSync(planPath)) {
    console.error(
      `local cluster config not found at ${planPath}; run npm run local:cluster:config or pass --coordinator-url`,
    );
    process.exit(EXIT_USAGE_ERROR);
  }
  plan = JSON.parse(readFileSync(planPath, "utf8"));
  coordinatorUrl = `http://127.0.0.1:${plan.coordinator.port}`;
  bearerToken ??= plan.coordinator.env?.COORDINATOR_BEARER_TOKEN;
}

// Construct the orchestrate body. We don't include MpccaWithdrawBaseRequest's full set of
// fields here because the coordinator route's compareFinalizeIdentityWithRound2 helper
// validates by reading the persisted __round2.json — the body just needs to AGREE with it.
// We fetch the persisted artifact to mirror the identity fields back, then cross-check.
const round2ArtifactPath = resolve(
  stateRoot,
  "coordinator",
  "mpcca_withdraw",
  `${dkgEpoch}__${requestId}__round2.json`,
);
if (!existsSync(round2ArtifactPath)) {
  console.error(
    `__round2.json not found at ${round2ArtifactPath}; run M4-c2 round2 first`,
  );
  process.exit(EXIT_TRANSCRIPT_NOT_FOUND);
}
const round2Artifact = JSON.parse(readFileSync(round2ArtifactPath, "utf8"));

const orchestrateBody = {
  dkgEpoch,
  requestId,
  sessionId: round2Artifact.sessionId ?? requestId,
  vaultEkTranscriptHash: round2Artifact.vaultEkTranscriptHash,
  registrationTranscriptHash: round2Artifact.registrationTranscriptHash,
  vaultStateInitTranscriptHash: round2Artifact.vaultStateInitTranscriptHash,
  observedDepositTranscriptHashes: round2Artifact.observedDepositTranscriptHashes,
  rosterHash: round2Artifact.rosterHash,
  selectedSlots: round2Artifact.selectedSlots,
  selfSlot: round2Artifact.selectedSlots[0],
  playerId: 0,
  vaultEk: round2Artifact.vaultEk,
  senderAddress: round2Artifact.senderAddress,
  assetType: round2Artifact.assetType,
  chainId: round2Artifact.chainId,
  root: round2Artifact.root,
  nullifierHash: round2Artifact.nullifierHash,
  recipient: round2Artifact.recipient,
  recipientHash: round2Artifact.recipientHash,
  amountTag: round2Artifact.amountTag,
  vaultSequence: round2Artifact.vaultSequence,
  expirySecs: round2Artifact.expirySecs,
  requestHash: round2Artifact.requestHash,
  depositCount: round2Artifact.depositCount,
  attestationConfig: {
    bridge,
    vault,
    operatorSetVersion,
    frostGroupPubkey,
    circuitVersionsHash,
  },
  withdrawProofHex,
  ...(memoHex !== undefined ? { memoHex } : {}),
};

const headers = { "Content-Type": "application/json" };
if (bearerToken) headers.Authorization = `Bearer ${bearerToken}`;

let res;
try {
  res = await fetch(`${coordinatorUrl}/v2/withdraw/mpcca/frost-attest`, {
    method: "POST",
    headers,
    body: JSON.stringify(orchestrateBody),
  });
} catch (err) {
  console.error(
    `coordinator unreachable at ${coordinatorUrl}: ${err instanceof Error ? err.message : String(err)}`,
  );
  process.exit(EXIT_GENERIC_FAILURE);
}

const responseText = await res.text();
let responseBody;
try {
  responseBody = responseText ? JSON.parse(responseText) : {};
} catch {
  responseBody = { raw: responseText };
}

if (res.status !== 200) {
  console.error(
    JSON.stringify(
      { error: "frost_attest_failed", statusCode: res.status, body: responseBody },
      null,
      2,
    ),
  );
  if (
    responseBody?.error === "round2_transcript_not_found" ||
    responseBody?.error === "finalize_transcript_not_found"
  ) {
    process.exit(EXIT_TRANSCRIPT_NOT_FOUND);
  }
  if (responseBody?.error === "round2_transcript_identity_mismatch") {
    process.exit(EXIT_IDENTITY_MISMATCH);
  }
  if (
    typeof responseBody?.error === "string" &&
    responseBody.error.startsWith("frost_")
  ) {
    process.exit(EXIT_FROST_WORKER_REJECTION);
  }
  process.exit(EXIT_GENERIC_FAILURE);
}

// Verify __finalize.json transitioned from M4-c4 stub → M5-c1 fully assembled.
const finalizeArtifactPath = resolve(
  stateRoot,
  "coordinator",
  "mpcca_withdraw",
  `${dkgEpoch}__${requestId}__finalize.json`,
);
if (!existsSync(finalizeArtifactPath)) {
  console.error(
    `__finalize.json not found at ${finalizeArtifactPath} after 200 OK — coordinator did not persist`,
  );
  process.exit(EXIT_FINALIZE_SHAPE_REGRESSION);
}
const updatedFinalize = JSON.parse(readFileSync(finalizeArtifactPath, "utf8"));
if (updatedFinalize.notImplementedPhase !== undefined) {
  console.error(
    `__finalize.json still carries notImplementedPhase = ${JSON.stringify(updatedFinalize.notImplementedPhase)} after frost-attest 200 OK`,
  );
  process.exit(EXIT_FINALIZE_SHAPE_REGRESSION);
}
const callArgs = updatedFinalize.withdrawV2CallArgsFields;
if (!callArgs || typeof callArgs !== "object") {
  console.error(
    "__finalize.json withdrawV2CallArgsFields missing after frost-attest 200 OK",
  );
  process.exit(EXIT_FINALIZE_SHAPE_REGRESSION);
}
const required27Fields = [
  "root",
  "nullifierHash",
  "recipient",
  "recipientHash",
  "amountTag",
  "caPayloadHash",
  "requestHash",
  "vaultSequence",
  "withdrawProof",
  "expirySecs",
  "groupSignature",
  "fallbackBitmap",
  "fallbackSignatures",
  "newBalanceP",
  "newBalanceR",
  "newBalanceREffAud",
  "amountP",
  "amountRSender",
  "amountRRecip",
  "amountREffAud",
  "ekVolunAuds",
  "amountRVolunAuds",
  "zkrpNewBalance",
  "zkrpAmount",
  "sigmaProtoComm",
  "sigmaProtoResp",
  "memo",
];
const missing = required27Fields.filter((k) => !(k in callArgs));
if (missing.length > 0) {
  console.error(
    `__finalize.json withdrawV2CallArgsFields missing fields: ${missing.join(", ")}`,
  );
  process.exit(EXIT_FINALIZE_SHAPE_REGRESSION);
}

console.log(
  JSON.stringify(
    {
      ok: true,
      command: "local:mpcca:frost-attest",
      coordinatorUrl,
      dkgEpoch,
      requestId,
      caPayloadHashRaw: responseBody.caPayloadHashRaw,
      caPayloadHashFr: responseBody.caPayloadHashFr,
      groupSignature: responseBody.groupSignature,
      withdrawV2CallArgsFieldCount: required27Fields.length,
      finalizeArtifactPath,
      message:
        "M5-c1 frost-attest succeeded; __finalize.json now carries the full 27-field " +
        "WithdrawV2CallArgs. The M5b submit route can fan this to the relayer.",
    },
    null,
    2,
  ),
);
process.exit(EXIT_SUCCESS);

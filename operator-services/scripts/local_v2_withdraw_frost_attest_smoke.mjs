#!/usr/bin/env node
// =============================================================================================
// V2 withdraw — frost-attest smoke driver (M8 Task 5, phase 4).
//
// Reads __finalize.json + __round2.json artifacts. Computes ca_payload_hash client-side via
// the existing @eunoma/deop-protocol exported helpers (buildCaPayloadFromFinalizeArtifact +
// caPayloadHashFrV2). Computes request_hash. Builds withdraw witness via
// circuits/scripts/compute_withdraw_witness.mjs + Groth16 proof via
// scripts/local_generate_withdraw_proof.mjs. POSTs to /v2/withdraw/mpcca/frost-attest.
// =============================================================================================
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

import {
  buildCaPayloadFromFinalizeArtifact,
  caPayloadHashFrV2,
  caPayloadHashRawV2,
} from "@eunoma/deop-protocol";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");
const repoRoot = resolve(serviceRoot, "..");

function flag(name) {
  const i = process.argv.indexOf(name);
  return i < 0 ? null : process.argv[i + 1];
}
function required(v, name) {
  if (!v) {
    console.error(`required: ${name}`);
    process.exit(2);
  }
  return v;
}

const requestId = required(flag("--request-id"), "--request-id");
const dkgEpoch = required(flag("--dkg-epoch"), "--dkg-epoch");
const depositWitness = required(flag("--deposit-witness"), "--deposit-witness");
const vaultEk = required(flag("--vault-ek"), "--vault-ek");
const root = required(flag("--root"), "--root");
const withdrawBlindHex = flag("--withdraw-blind");
const COORDINATOR_URL = process.env.COORDINATOR_URL ?? "http://127.0.0.1:4200";
const COORDINATOR_BEARER_TOKEN = required(
  process.env.COORDINATOR_BEARER_TOKEN,
  "env COORDINATOR_BEARER_TOKEN",
);

const round2Path = resolve(
  serviceRoot,
  ".agent-local/eunoma-v2/coordinator/mpcca_withdraw",
  `${dkgEpoch}__${requestId}__round2.json`,
);
const finalizePath = resolve(
  serviceRoot,
  ".agent-local/eunoma-v2/coordinator/mpcca_withdraw",
  `${dkgEpoch}__${requestId}__finalize.json`,
);
if (!existsSync(round2Path) || !existsSync(finalizePath)) {
  console.error(
    `artifacts missing — need ${round2Path} + ${finalizePath}; run round1 + round2 + finalize first`,
  );
  process.exit(2);
}
const round2 = JSON.parse(readFileSync(round2Path, "utf8"));
const finalize = JSON.parse(readFileSync(finalizePath, "utf8"));
const mpccaArtifact = finalize.mpccaWithdrawFinalizeArtifact;

// 1. Compute the final CA payload via the shared helper.
const caPayload = buildCaPayloadFromFinalizeArtifact({
  recipientAddressHex: round2.recipient,
  assetTypeHex: round2.assetType,
  statementInputs: round2.statementInputs,
  mpccaArtifact: {
    aggregatedSigmaCommitmentsHex: mpccaArtifact.aggregatedSigmaCommitmentsHex,
    sigmaResponseHex: mpccaArtifact.sigmaResponseHex,
    bulletproofZkrpAmountHex: round2.userProofArtifacts.bulletproofZkrpAmountHex,
    bulletproofZkrpNewBalanceHex: round2.userProofArtifacts.bulletproofZkrpNewBalanceHex,
  },
  memoHex: "",
});

// 2. Compute caPayloadHash (raw keccak + Fr-safe).
const caPayloadHashRaw = caPayloadHashRawV2(caPayload);
const caPayloadHashFr = caPayloadHashFrV2(caPayload);
console.error(`[frost-attest] caPayloadHashRaw=${caPayloadHashRaw.slice(0, 16)}...`);
console.error(`[frost-attest] caPayloadHashFr =${caPayloadHashFr.slice(0, 16)}...`);

// 3. Generate withdraw witness JSON via compute_withdraw_witness.mjs.
const witnessOutPath = `/tmp/m8-${requestId}-witness.json`;
const witnessArgs = [
  resolve(repoRoot, "circuits/scripts/compute_withdraw_witness.mjs"),
  "--depositor-witness",
  depositWitness,
  "--recipient",
  round2.recipient.startsWith("0x") ? round2.recipient : "0x" + round2.recipient,
  "--vault-sequence",
  String(round2.vaultSequence),
  "--root",
  root.startsWith("0x") ? root : "0x" + root,
  "--ca-payload-hash",
  caPayloadHashFr.startsWith("0x") ? caPayloadHashFr : "0x" + caPayloadHashFr,
  "--output",
  witnessOutPath,
];
if (withdrawBlindHex) witnessArgs.push("--withdraw-blind-hex", withdrawBlindHex);
const witnessProc = spawnSync("node", witnessArgs, {
  encoding: "utf8",
  maxBuffer: 10 * 1024 * 1024,
});
if (witnessProc.status !== 0) {
  console.error(`compute_withdraw_witness failed: ${witnessProc.stderr || witnessProc.stdout}`);
  process.exit(1);
}
console.error(`[frost-attest] witness JSON → ${witnessOutPath}`);

// 4. Generate Groth16 proof.
const proofOutPath = `/tmp/m8-${requestId}-proof.json`;
const proofProc = spawnSync(
  "node",
  [
    resolve(serviceRoot, "scripts/local_generate_withdraw_proof.mjs"),
    "--witness-json",
    witnessOutPath,
    "--output",
    proofOutPath,
  ],
  { encoding: "utf8", maxBuffer: 10 * 1024 * 1024 },
);
if (proofProc.status !== 0) {
  console.error(`local_generate_withdraw_proof failed: ${proofProc.stderr || proofProc.stdout}`);
  process.exit(1);
}
const proof = JSON.parse(readFileSync(proofOutPath, "utf8"));
const proofHex = proof.proofHex;
console.error(`[frost-attest] Groth16 proof generated (${proofHex.length} hex chars)`);

// 5. Build frost-attest body.
// Need MpccaWithdrawFrostAttestStartRequest shape — full chained-round envelope + Statement
// inputs + withdrawProofHex + attestationConfig (operator-set version, frostGroupPubkey,
// circuitVersionsHash).
const fs2 = await import("node:fs");
const rosterText = fs2.readFileSync(
  resolve(serviceRoot, ".agent-local/eunoma-v2/cluster/ca-dkg-v2-roster.json"),
  "utf8",
);
const roster = JSON.parse(rosterText);
const frostRosterText = fs2.readFileSync(
  resolve(serviceRoot, ".agent-local/eunoma-v2/cluster/frost-dkg-v2-roster.json"),
  "utf8",
);
const frostRoster = JSON.parse(frostRosterText);

const body = {
  dkgEpoch,
  requestId,
  sessionId: round2.sessionId ?? requestId,
  rosterHash: round2.rosterHash,
  selectedSlots: round2.selectedSlots,
  selfSlot: round2.selectedSlots[0],
  playerId: 0,
  vaultEk: round2.vaultEk,
  senderAddress: round2.senderAddress,
  assetType: round2.assetType,
  chainId: round2.chainId,
  root: round2.root,
  nullifierHash: round2.nullifierHash,
  recipient: round2.recipient,
  recipientHash: round2.recipientHash,
  amountTag: round2.amountTag,
  vaultSequence: round2.vaultSequence,
  expirySecs: round2.expirySecs,
  requestHash: round2.requestHash,
  depositCount: round2.depositCount,
  caDkgTranscriptHash: round2.caDkgTranscriptHash ?? null,
  vaultEkTranscriptHash: round2.vaultEkTranscriptHash,
  registrationTranscriptHash: round2.registrationTranscriptHash,
  vaultStateInitTranscriptHash: round2.vaultStateInitTranscriptHash,
  observedDepositTranscriptHashes: round2.observedDepositTranscriptHashes,
  observedDepositCursors: Array.from(
    { length: round2.depositCount },
    (_, i) => i + 1,
  ),
  // Statement inputs (same as round2)
  recipientEk: round2.statementInputs.recipientEk,
  oldBalanceC: round2.statementInputs.oldBalanceC,
  oldBalanceD: round2.statementInputs.oldBalanceD,
  newBalanceC: round2.statementInputs.newBalanceC,
  newBalanceD: round2.statementInputs.newBalanceD,
  transferAmountC: round2.statementInputs.transferAmountC,
  transferAmountDSender: round2.statementInputs.transferAmountDSender,
  transferAmountDRecipient: round2.statementInputs.transferAmountDRecipient,
  // FROST attestation config (bridge + vault identity + frostGroupPubkey + circuit versions)
  attestationConfig: {
    bridge: process.env.BRIDGE_PACKAGE_ADDRESS,
    vault: process.env.EUNOMA_TESTNET_VAULT_ADDRESS ?? round2.senderAddress,
    operatorSetVersion: roster.operatorSetVersion,
    frostGroupPubkey: frostRoster.frostGroupPubkey ?? roster.frostGroupPubkey,
    circuitVersionsHash:
      process.env.EUNOMA_TESTNET_CIRCUIT_VERSIONS_HASH ??
      "0x0000000000000000000000000000000000000000000000000000000000000001",
  },
  withdrawProofHex: proofHex,
  memoHex: "",
};

console.error(`[frost-attest] POST /v2/withdraw/mpcca/frost-attest`);
const res = await fetch(new URL("/v2/withdraw/mpcca/frost-attest", COORDINATOR_URL), {
  method: "POST",
  headers: {
    "content-type": "application/json",
    authorization: `Bearer ${COORDINATOR_BEARER_TOKEN}`,
  },
  body: JSON.stringify(body),
});
const responseBody = await res.json().catch(() => ({}));
console.error(`[frost-attest] HTTP ${res.status}`);
process.stdout.write(
  JSON.stringify(
    {
      httpStatus: res.status,
      caPayloadHashRaw,
      caPayloadHashFr,
      proofHex,
      responseBody,
    },
    null,
    2,
  ) + "\n",
);
process.exit(res.status >= 200 && res.status < 300 ? 0 : 30);

#!/usr/bin/env node
// =============================================================================================
// V2 withdraw — finalize smoke driver (M8 Task 5, phase 3).
//
// Posts /v2/withdraw/mpcca/finalize. Reads userSigmaCommitmentsHex[29] from the persisted
// __round2.json artifact so the coordinator's cross-check matches.
// =============================================================================================
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");

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
if (!existsSync(round2Path)) {
  console.error(`round2 artifact not found at ${round2Path}`);
  process.exit(2);
}
const round2 = JSON.parse(readFileSync(round2Path, "utf8"));
const userSigmaCommitmentsHex =
  round2.userProofArtifacts?.userSigmaCommitmentsHex ?? null;
if (!Array.isArray(userSigmaCommitmentsHex) || userSigmaCommitmentsHex.length !== 29) {
  console.error(
    `round2 artifact missing userSigmaCommitmentsHex[29]; got ${userSigmaCommitmentsHex?.length ?? "none"}`,
  );
  process.exit(2);
}

const body = {
  dkgEpoch,
  requestId,
  sessionId: round2.sessionId ?? requestId,
  selectedSlots: round2.selectedSlots,
  selfSlot: round2.selectedSlots[0],
  playerId: 0,
  // Full chained-round identity envelope (same as round2)
  vaultEkTranscriptHash: round2.vaultEkTranscriptHash,
  registrationTranscriptHash: round2.registrationTranscriptHash,
  vaultStateInitTranscriptHash: round2.vaultStateInitTranscriptHash,
  observedDepositTranscriptHashes: round2.observedDepositTranscriptHashes,
  observedDepositCursors: Array.from(
    { length: round2.depositCount },
    (_, i) => i + 1,
  ),
  rosterHash: round2.rosterHash,
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
  // Same Statement inputs as round2 (the coordinator cross-checks)
  recipientEk: round2.statementInputs.recipientEk,
  oldBalanceC: round2.statementInputs.oldBalanceC,
  oldBalanceD: round2.statementInputs.oldBalanceD,
  newBalanceC: round2.statementInputs.newBalanceC,
  newBalanceD: round2.statementInputs.newBalanceD,
  transferAmountC: round2.statementInputs.transferAmountC,
  transferAmountDSender: round2.statementInputs.transferAmountDSender,
  transferAmountDRecipient: round2.statementInputs.transferAmountDRecipient,
  userSigmaCommitmentsHex,
};

console.error(`[finalize] POST /v2/withdraw/mpcca/finalize requestId=${requestId}`);
const res = await fetch(new URL("/v2/withdraw/mpcca/finalize", COORDINATOR_URL), {
  method: "POST",
  headers: {
    "content-type": "application/json",
    authorization: `Bearer ${COORDINATOR_BEARER_TOKEN}`,
  },
  body: JSON.stringify(body),
});
const responseBody = await res.json().catch(() => ({}));
console.error(`[finalize] HTTP ${res.status}`);
process.stdout.write(JSON.stringify({ httpStatus: res.status, responseBody }, null, 2) + "\n");
process.exit(res.status >= 200 && res.status < 300 ? 0 : 30);

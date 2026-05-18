#!/usr/bin/env node
// =============================================================================================
// V2 withdraw — round2 smoke driver (M8 Task 5, phase 2).
//
// Picks up from a successful round1 (reads `__round1.json` on disk) and POSTs round2 with
// Aptos CA TransferV1 Statement inputs + user-side σ artifacts. Goal is to surface the next
// concrete blocker.
//
// For this first attempt: uses deterministic-fixture σ inputs (matching coordinator-test
// patterns) — known to be cryptographically WRONG vs vault_ek. The coordinator's parser will
// accept shape but the Rust worker WILL reject at Ristretto-point validation. The exact error
// surfaced is the next concrete blocker to patch.
//
// Real σ construction requires `proveTransfer({dk: fake_dk_user})` + PRNG patching to control
// α[0] (matching the round1 commitment). That's substantial work; this driver is the iteration
// step that tells us EXACTLY which check rejects first so we know what to build next.
//
// Inputs:
//   COORDINATOR_BEARER_TOKEN           required
//   --request-id ID                    required (the round1 requestId)
//   --dkg-epoch N                      required (= "1")
//   --recipient HEX                    required
//   --vault-address HEX                required
//   --asset-type HEX                   required
//   --vault-ek HEX                     required
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
const recipient = required(flag("--recipient"), "--recipient");
const vaultAddress = required(flag("--vault-address"), "--vault-address");
const assetType = required(flag("--asset-type"), "--asset-type");
const vaultEk = required(flag("--vault-ek"), "--vault-ek");
const COORDINATOR_URL = process.env.COORDINATOR_URL ?? "http://127.0.0.1:4200";
const COORDINATOR_BEARER_TOKEN = required(
  process.env.COORDINATOR_BEARER_TOKEN,
  "env COORDINATOR_BEARER_TOKEN",
);

// Read round1 artifact for binding fields the round2 route requires.
const round1Path = resolve(
  serviceRoot,
  ".agent-local/eunoma-v2/coordinator/mpcca_withdraw",
  `${dkgEpoch}__${requestId}__round1.json`,
);
if (!existsSync(round1Path)) {
  console.error(`round1 artifact not found at ${round1Path}`);
  process.exit(2);
}
const round1 = JSON.parse(readFileSync(round1Path, "utf8"));

// Deterministic-fixture σ data (KNOWN cryptographically invalid; iterate from this baseline).
function repeat(byte, count) {
  return byte.toString(16).padStart(2, "0").repeat(count);
}
function genHex32(label, i) {
  const idx = i.toString(16).padStart(2, "0");
  return (label + idx).repeat(16);
}

const body = {
  // Base identity envelope (must match round1's binding).
  dkgEpoch,
  requestId,
  sessionId: round1.sessionId ?? requestId,
  caDkgTranscriptHash: round1.caDkgTranscriptHash ?? round1.caDkgTranscriptHashHex,
  vaultEkTranscriptHash: round1.vaultEkTranscriptHash,
  registrationTranscriptHash: round1.registrationTranscriptHash,
  vaultStateInitTranscriptHash: round1.vaultStateInitTranscriptHash,
  observedDepositTranscriptHashes: round1.observedDepositTranscriptHashes,
  // observedDepositCursors must be [1, 2, ..., depositCount] (strict monotonic from 1).
  observedDepositCursors:
    round1.observedDepositCursors ??
    Array.from({ length: round1.depositCount }, (_, i) => i + 1),
  rosterHash: round1.rosterHash,
  selectedSlots: round1.selectedSlots,
  selfSlot: round1.selectedSlots[0],
  playerId: 0,
  vaultEk: round1.vaultEk,
  senderAddress: round1.senderAddress,
  assetType: round1.assetType,
  chainId: round1.chainId,
  root: round1.root,
  nullifierHash: round1.nullifierHash,
  recipient: round1.recipient,
  recipientHash: round1.recipientHash,
  amountTag: round1.amountTag,
  vaultSequence: round1.vaultSequence,
  expirySecs: round1.expirySecs,
  requestHash: round1.requestHash,
  depositCount: round1.depositCount,

  // Statement inputs (CA TransferV1) — placeholder fixture hex.
  recipientEk: repeat(0xa1, 32),
  oldBalanceC: Array.from({ length: 8 }, (_, i) => genHex32("b0", i)),
  oldBalanceD: Array.from({ length: 8 }, (_, i) => genHex32("c0", i)),
  newBalanceC: Array.from({ length: 8 }, (_, i) => genHex32("d0", i)),
  newBalanceD: Array.from({ length: 8 }, (_, i) => genHex32("e0", i)),
  transferAmountC: Array.from({ length: 4 }, (_, i) => genHex32("f0", i)),
  transferAmountDSender: Array.from({ length: 4 }, (_, i) => genHex32("12", i)),
  transferAmountDRecipient: Array.from({ length: 4 }, (_, i) => genHex32("23", i)),

  // User σ artifacts (fixture).
  userSigmaCommitmentsHex: Array.from({ length: 29 }, (_, i) => genHex32("34", i)),
  userSigmaResponseSharesHex: Array.from({ length: 24 }, (_, i) => genHex32("45", i)),
  bulletproofZkrpAmountHex: "ab".repeat(96),
  bulletproofZkrpNewBalanceHex: "cd".repeat(160),
  perChunkCommitmentsAmountHex: Array.from({ length: 4 }, (_, i) => genHex32("56", i)),
  perChunkCommitmentsNewBalanceHex: Array.from({ length: 8 }, (_, i) => genHex32("67", i)),
};

console.error(
  `[round2] POST /v2/withdraw/mpcca/round2 requestId=${requestId} bodyKeys=${Object.keys(body).length}`,
);

const res = await fetch(new URL("/v2/withdraw/mpcca/round2", COORDINATOR_URL), {
  method: "POST",
  headers: {
    "content-type": "application/json",
    authorization: `Bearer ${COORDINATOR_BEARER_TOKEN}`,
  },
  body: JSON.stringify(body),
});
const responseBody = await res.json().catch(() => ({}));
console.error(`[round2] HTTP ${res.status}`);
process.stdout.write(JSON.stringify({ httpStatus: res.status, responseBody }, null, 2) + "\n");
process.exit(res.status >= 200 && res.status < 300 ? 0 : 30);

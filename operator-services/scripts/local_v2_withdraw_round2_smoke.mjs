#!/usr/bin/env node
// =============================================================================================
// V2 withdraw — round2 smoke driver (M8 Task 5, phase 2).
//
// Posts /v2/withdraw/mpcca/round2 with REAL Ristretto-valid CA TransferV1 Statement inputs.
// User-side σ proof artifacts are still deterministic-fixture (Ristretto-shaped points but
// NOT cryptographically bound to the witness — next iteration step).
//
// Statement inputs:
//   - recipient_ek: freshly-generated TwistedEd25519 public key
//   - oldBalanceC/D: fetched from chain via /v1/view get_available_balance
//   - newBalanceC/D: TwistedElGamal.encryptWithPK([0]*8, vaultEk, newBalanceRandomness)
//   - transferAmountC: TwistedElGamal.encryptWithPK([100,0,0,0], vaultEk, transferRandomness)
//   - transferAmountDSender: D component under sender EK (vaultEk)
//   - transferAmountDRecipient: D component under recipient_ek with SAME randomness
// =============================================================================================
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";

import {
  AVAILABLE_BALANCE_CHUNK_COUNT,
  TRANSFER_AMOUNT_CHUNK_COUNT,
  ChunkedAmount,
  TwistedEd25519PrivateKey,
  TwistedEd25519PublicKey,
  TwistedElGamal,
  RistrettoPoint,
} from "@aptos-labs/confidential-asset";
import { ed25519 } from "@noble/curves/ed25519";

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
function bytesToHex(buf) {
  return Array.from(buf).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(hex) {
  const norm = hex.replace(/^0x/i, "");
  const out = new Uint8Array(norm.length / 2);
  for (let i = 0; i < norm.length; i += 2) out[i / 2] = parseInt(norm.slice(i, i + 2), 16);
  return out;
}

const ED_N = ed25519.CURVE.n;
function randScalar() {
  while (true) {
    const buf = randomBytes(32);
    buf[31] &= 0x7f;
    let v = 0n;
    for (let i = buf.length - 1; i >= 0; i -= 1) v = (v << 8n) | BigInt(buf[i]);
    if (v < ED_N && v !== 0n) return v;
  }
}

const requestId = required(flag("--request-id"), "--request-id");
const dkgEpoch = required(flag("--dkg-epoch"), "--dkg-epoch");
const recipientAddr = required(flag("--recipient"), "--recipient");
const vaultAddress = required(flag("--vault-address"), "--vault-address");
const assetType = required(flag("--asset-type"), "--asset-type");
const vaultEk = required(flag("--vault-ek"), "--vault-ek");
const APTOS_NODE_URL = process.env.APTOS_TESTNET_NODE_URL ?? "https://fullnode.testnet.aptoslabs.com";
const COORDINATOR_URL = process.env.COORDINATOR_URL ?? "http://127.0.0.1:4200";
const COORDINATOR_BEARER_TOKEN = required(
  process.env.COORDINATOR_BEARER_TOKEN,
  "env COORDINATOR_BEARER_TOKEN",
);
// P0 Bonus fix (2026-05-23, codex micro-review iter 2): amount MUST come from depositor witness
// (matches local_v2_withdraw_full.mjs). Earlier `--amount-octas` flag is rejected if it mismatches
// witness — the smoke's prior independent knob made amount inconsistent with round1.amountTag
// (which was built from a different amount). round1 artifact does not persist amount (only
// amountTag/nullifierHash hashes), so witness is the canonical source.
const depositWitnessPath = required(flag("--depositor-witness"), "--depositor-witness");
const depositWitness = JSON.parse(readFileSync(depositWitnessPath, "utf8"));
if (depositWitness.schema !== "v2_depositor_witness_v1") {
  console.error("bad depositor witness schema");
  process.exit(2);
}
if (typeof depositWitness.amountOctas !== "string" || depositWitness.amountOctas.length === 0) {
  console.error("depositor witness missing amountOctas");
  process.exit(2);
}
const TRANSFER_AMOUNT = BigInt(depositWitness.amountOctas);
if (TRANSFER_AMOUNT <= 0n) {
  console.error(`depositor witness amountOctas must be positive (got ${TRANSFER_AMOUNT})`);
  process.exit(2);
}
const amountOverride = flag("--amount-octas");
if (amountOverride !== null && amountOverride !== depositWitness.amountOctas) {
  console.error(
    `--amount-octas (=${amountOverride}) mismatch with witness amountOctas ` +
      `(=${depositWitness.amountOctas}); amount MUST come from witness`,
  );
  process.exit(2);
}
if (
  process.env.WITHDRAW_AMOUNT_OCTAS !== undefined &&
  process.env.WITHDRAW_AMOUNT_OCTAS !== depositWitness.amountOctas
) {
  console.error(
    `WITHDRAW_AMOUNT_OCTAS env (=${process.env.WITHDRAW_AMOUNT_OCTAS}) mismatch with witness ` +
      `(=${depositWitness.amountOctas}); env is no longer honored`,
  );
  process.exit(2);
}

// Read round1 artifact for binding fields.
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

// Fetch on-chain bridge vault available balance (post-rollover, 8 chunks).
async function viewAvailableBalance() {
  const res = await fetch(`${APTOS_NODE_URL}/v1/view`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      function: "0x1::confidential_asset::get_available_balance",
      type_arguments: [],
      arguments: [vaultAddress, assetType],
    }),
  });
  if (!res.ok) throw new Error(`get_available_balance ${res.status}: ${await res.text()}`);
  const body = await res.json();
  const v1 = body[0];
  return {
    P: v1.P.map((x) => x.data.replace(/^0x/, "")),
    R: v1.R.map((x) => x.data.replace(/^0x/, "")),
  };
}

const balanceCt = await viewAvailableBalance();
console.error(`[round2] fetched chain available balance: ${balanceCt.P.length} chunks`);

// Generate recipient TwistedEd25519 keypair (fresh for this withdraw).
const recipientDkSeed = randomBytes(32);
const recipientDk = new TwistedEd25519PrivateKey(`0x${bytesToHex(recipientDkSeed)}`);
const recipientEk = recipientDk.publicKey();
const recipientEkHex = bytesToHex(recipientEk.toUint8Array());
console.error(`[round2] generated recipient_ek=${recipientEkHex.slice(0, 16)}...`);

// Compute new_balance chunks (= all-zero for full withdrawal of 100 octas).
const ell = AVAILABLE_BALANCE_CHUNK_COUNT;
const n = TRANSFER_AMOUNT_CHUNK_COUNT;
const newBalanceChunks = new Array(ell).fill(0n);
const transferAmountChunks = ChunkedAmount.createTransferAmount(TRANSFER_AMOUNT).amountChunks;
console.error(`[round2] transferAmount chunks: [${transferAmountChunks.join(", ")}]`);

// Generate fresh randomness for newBalance + transferAmount.
const newBalanceRandomness = Array.from({ length: ell }, () => randScalar());
const transferAmountRandomness = Array.from({ length: n }, () => randScalar());

const vaultEkPub = new TwistedEd25519PublicKey(`0x${vaultEk.replace(/^0x/, "")}`);
function encryptUnder(pk, chunks, rs) {
  return chunks.map((chunk, i) => TwistedElGamal.encryptWithPK(chunk, pk, rs[i]));
}

const newBalanceCt = encryptUnder(vaultEkPub, newBalanceChunks, newBalanceRandomness);
const transferSenderCt = encryptUnder(vaultEkPub, transferAmountChunks, transferAmountRandomness);
const transferRecipientCt = encryptUnder(recipientEk, transferAmountChunks, transferAmountRandomness);

const newBalanceC = newBalanceCt.map((ct) => bytesToHex(ct.C.toRawBytes()));
const newBalanceD = newBalanceCt.map((ct) => bytesToHex(ct.D.toRawBytes()));
const transferAmountC = transferSenderCt.map((ct) => bytesToHex(ct.C.toRawBytes()));
const transferAmountDSender = transferSenderCt.map((ct) => bytesToHex(ct.D.toRawBytes()));
const transferAmountDRecipient = transferRecipientCt.map((ct) => bytesToHex(ct.D.toRawBytes()));

// Generate user-side σ artifacts — these are RANDOM Ristretto points + scalars for now.
// The σ proof won't verify against the Statement (this is the next iteration step), but
// the worker may still accept the wire shape and reach round2's DK partial computation
// before the σ verification check fires.
function randomRistrettoCompressed() {
  // Hash-to-curve via a random scalar * BASE.
  return bytesToHex(RistrettoPoint.BASE.multiply(randScalar()).toRawBytes());
}
function randomScalarHex() {
  const v = randScalar();
  const buf = new Uint8Array(32);
  let r = v;
  for (let i = 0; i < 32; i += 1) {
    buf[i] = Number(r & 0xffn);
    r >>= 8n;
  }
  return bytesToHex(buf);
}

const userSigmaCommitmentsHex = Array.from({ length: 29 }, () => randomRistrettoCompressed());
const userSigmaResponseSharesHex = Array.from({ length: 24 }, () => randomScalarHex());
const perChunkCommitmentsAmountHex = Array.from({ length: n }, () => randomRistrettoCompressed());
const perChunkCommitmentsNewBalanceHex = Array.from({ length: ell }, () => randomRistrettoCompressed());

// Bulletproofs are NOT trivially generable without the Aptos SDK's batchRangeProof. Use
// fixture bytes for now — the next iteration step is to call batchRangeProof from the
// @aptos-labs/confidential-asset-bindings package.
const bulletproofZkrpAmountHex = "ab".repeat(96);
const bulletproofZkrpNewBalanceHex = "cd".repeat(160);

const body = {
  dkgEpoch,
  requestId,
  sessionId: round1.sessionId ?? requestId,
  caDkgTranscriptHash: round1.caDkgTranscriptHash ?? round1.caDkgTranscriptHashHex,
  vaultEkTranscriptHash: round1.vaultEkTranscriptHash,
  registrationTranscriptHash: round1.registrationTranscriptHash,
  vaultStateInitTranscriptHash: round1.vaultStateInitTranscriptHash,
  observedDepositTranscriptHashes: round1.observedDepositTranscriptHashes,
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
  recipientEk: recipientEkHex,
  oldBalanceC: balanceCt.P,
  oldBalanceD: balanceCt.R,
  newBalanceC,
  newBalanceD,
  transferAmountC,
  transferAmountDSender,
  transferAmountDRecipient,
  userSigmaCommitmentsHex,
  userSigmaResponseSharesHex,
  bulletproofZkrpAmountHex,
  bulletproofZkrpNewBalanceHex,
  perChunkCommitmentsAmountHex,
  perChunkCommitmentsNewBalanceHex,
};

console.error(
  `[round2] POST /v2/withdraw/mpcca/round2 bodyKeys=${Object.keys(body).length} recipientEk=${recipientEkHex.slice(0, 12)}...`,
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
process.stdout.write(
  JSON.stringify(
    {
      httpStatus: res.status,
      recipientDkHex: `0x${bytesToHex(recipientDkSeed)}`,
      recipientEkHex,
      newBalanceRandomness: newBalanceRandomness.map((r) => r.toString()),
      transferAmountRandomness: transferAmountRandomness.map((r) => r.toString()),
      responseBody,
    },
    null,
    2,
  ) + "\n",
);
process.exit(res.status >= 200 && res.status < 300 ? 0 : 30);

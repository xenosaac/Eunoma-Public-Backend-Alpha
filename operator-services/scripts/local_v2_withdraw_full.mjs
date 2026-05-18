#!/usr/bin/env node
// =============================================================================================
// V2 withdraw — unified end-to-end orchestrator with REAL σ proof + Bulletproofs.
//
// Pipeline:
//   1. Pre-compute α[0] via proveTransfer (fake dk_user) → extract from canonical response[0].
//   2. Split α[0] into 5 α_shares + per-share blinds; HPKE-seal under workers' pubkeys.
//   3. Build Bulletproof ZKRPs via batchRangeProof from @aptos-labs/confidential-asset-bindings.
//   4. POST round1 (M1 ingress).
//   5. POST round2 (Statement inputs + commitment[1..29] + response[1..24] + bulletproofs).
//   6. POST finalize.
//   7. Compute final ca_payload_hash + Groth16 withdraw proof.
//   8. POST frost-attest with proofHex.
//   9. POST submit (relayer → chain).
//
// The σ proof's response[0] gets substituted by workers via threshold reconstruction:
//   s[0]_threshold = α[0] + e · dk_REAL  (matches verifier's check against on-chain vault_ek).
// The user's proveTransfer used dk_user (fake), which the coordinator + workers then replace
// transparently during finalize aggregation. See M4-c5 byte-canonical test for the pattern.
// =============================================================================================
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";

import {
  AVAILABLE_BALANCE_CHUNK_COUNT,
  CHUNK_BITS,
  TRANSFER_AMOUNT_CHUNK_COUNT,
  APTOS_FRAMEWORK_ADDRESS,
  ChunkedAmount,
  H_RISTRETTO,
  RistrettoPoint,
  TwistedEd25519PrivateKey,
  TwistedEd25519PublicKey,
  TwistedElGamal,
  bcsSerializeTransferSession,
  proveTransfer,
  sigmaProtocolFiatShamir,
} from "@aptos-labs/confidential-asset";
import { batchRangeProof } from "@aptos-labs/confidential-asset-bindings";
import { ed25519 } from "@noble/curves/ed25519";
import { numberToBytesLE } from "@noble/curves/abstract/utils";

import {
  buildCaPayloadFromFinalizeArtifact,
  caPayloadHashFrV2,
  caPayloadHashRawV2,
  m1IngressAad,
} from "@eunoma/deop-protocol";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");
const repoRoot = resolve(serviceRoot, "..");
const HPKE_SEAL_BIN = resolve(serviceRoot, "crypto-worker-rust/target/release/hpke_seal_ingress");

function flag(name, def) {
  const i = process.argv.indexOf(name);
  if (i < 0) return def;
  return process.argv[i + 1];
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
function normalizeHex(hex) {
  return hex.replace(/^0x/i, "").toLowerCase();
}
function addr32(hex) {
  return normalizeHex(hex).padStart(64, "0");
}

const ED_N = ed25519.CURVE.n;
function modN(x) { return ((x % ED_N) + ED_N) % ED_N; }
function bytesToBigLE(bytes) {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}
function bigToLE32(v) {
  const out = new Uint8Array(32);
  let r = v;
  for (let i = 0; i < 32; i += 1) { out[i] = Number(r & 0xffn); r >>= 8n; }
  return out;
}
function randScalar() {
  while (true) {
    const buf = randomBytes(32);
    buf[31] &= 0x7f;
    const v = bytesToBigLE(buf);
    if (v < ED_N && v !== 0n) return v;
  }
}

// ---- args + env ---------------------------------------------------------------------------
const requestId = flag("--request-id", `m8-real-${Date.now()}`);
const depositWitnessPath = required(flag("--deposit-witness"), "--deposit-witness");
const vaultAddress = required(flag("--vault-address"), "--vault-address");
const vaultEk = required(flag("--vault-ek"), "--vault-ek");
const rootHex = required(flag("--root"), "--root");
const recipientArg = flag("--recipient"); // optional, defaults to fresh keypair below
const assetType = required(flag("--asset-type"), "--asset-type");
const vaultSequenceArg = required(flag("--vault-sequence"), "--vault-sequence");

const COORDINATOR_URL = process.env.COORDINATOR_URL ?? "http://127.0.0.1:4200";
const COORDINATOR_BEARER_TOKEN = required(
  process.env.COORDINATOR_BEARER_TOKEN,
  "env COORDINATOR_BEARER_TOKEN",
);
const APTOS_NODE_URL = process.env.APTOS_TESTNET_NODE_URL ?? "https://fullnode.testnet.aptoslabs.com";
const TRANSFER_AMOUNT_OCTAS = BigInt(process.env.WITHDRAW_AMOUNT_OCTAS ?? "100");
const CA_DKG_V2_ROSTER_JSON_PATH = required(
  process.env.CA_DKG_V2_ROSTER_JSON_PATH,
  "env CA_DKG_V2_ROSTER_JSON_PATH",
);
const FROST_DKG_V2_ROSTER_JSON_PATH = required(
  process.env.FROST_DKG_V2_ROSTER_JSON_PATH,
  "env FROST_DKG_V2_ROSTER_JSON_PATH",
);
const CHAIN_ID = Number(process.env.CHAIN_ID ?? "2");

// Read depositor witness.
const depositWitness = JSON.parse(readFileSync(depositWitnessPath, "utf8"));
if (depositWitness.schema !== "v2_depositor_witness_v1") {
  console.error("bad depositor witness schema");
  process.exit(2);
}

// Read rosters.
const caDkgRoster = JSON.parse(readFileSync(CA_DKG_V2_ROSTER_JSON_PATH, "utf8"));
const frostRoster = JSON.parse(readFileSync(FROST_DKG_V2_ROSTER_JSON_PATH, "utf8"));
const rosterHash = caDkgRoster.caDkgV2RosterHash;
const selectedSlots = [0, 1, 2, 3, 4];

// ---- Recipient + transfer amount ----------------------------------------------------------
const recipientDkSeed = randomBytes(32);
const recipientDk = new TwistedEd25519PrivateKey(`0x${bytesToHex(recipientDkSeed)}`);
const recipientEk = recipientDk.publicKey();
const recipientEkHex = bytesToHex(recipientEk.toUint8Array());
const recipientAddress = recipientArg ?? depositWitness.depositorAddress;
const senderAddressBytes = hexToBytes(addr32(vaultAddress));
const recipientAddressBytes = hexToBytes(addr32(recipientAddress));
const tokenAddressBytes = hexToBytes(addr32(assetType));
const vaultEkPub = new TwistedEd25519PublicKey(`0x${normalizeHex(vaultEk)}`);

const ell = AVAILABLE_BALANCE_CHUNK_COUNT;
const n = TRANSFER_AMOUNT_CHUNK_COUNT;
console.error(`[m8-real] ell=${ell} n=${n} chunkBits=${CHUNK_BITS}`);

// ---- Fetch on-chain old_balance -----------------------------------------------------------
async function fetchAvailable() {
  const res = await fetch(`${APTOS_NODE_URL}/v1/view`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      function: "0x1::confidential_asset::get_available_balance",
      type_arguments: [],
      arguments: [vaultAddress, assetType],
    }),
  });
  if (!res.ok) throw new Error(`get_available_balance: ${res.status}`);
  const b = await res.json();
  return {
    C: b[0].P.map((x) => RistrettoPoint.fromHex(hexToBytes(x.data))),
    D: b[0].R.map((x) => RistrettoPoint.fromHex(hexToBytes(x.data))),
  };
}
const oldBalanceCt = await fetchAvailable();
console.error(`[m8-real] fetched chain oldBalance: ${oldBalanceCt.C.length} chunks`);

// ---- Construct new_balance + transfer_amount chunks + randomness -------------------------
// The bridge vault holds 100 octas in chunk 0. After full withdrawal:
//   new_balance = 0 (all chunks 0)
//   transfer_amount = 100 (chunk 0 = 100, rest 0)
const newBalanceChunks = new Array(ell).fill(0n);
const transferAmountChunks = ChunkedAmount.createTransferAmount(TRANSFER_AMOUNT_OCTAS).amountChunks;

const newBalanceRandomness = Array.from({ length: ell }, () => randScalar());
const transferAmountRandomness = Array.from({ length: n }, () => randScalar());

function encrypt(pk, chunks, rs) {
  return chunks.map((c, i) => TwistedElGamal.encryptWithPK(c, pk, rs[i]));
}
const newBalanceCt = encrypt(vaultEkPub, newBalanceChunks, newBalanceRandomness);
const transferSenderCt = encrypt(vaultEkPub, transferAmountChunks, transferAmountRandomness);
const transferRecipientCt = encrypt(recipientEk, transferAmountChunks, transferAmountRandomness);

const valBase = RistrettoPoint.BASE.toRawBytes();
const randBase = H_RISTRETTO.toRawBytes();

// ---- Bulletproof ZKRPs ---------------------------------------------------------------------
console.error(`[m8-real] generating bulletproof: transferAmount (n=${n}, ${CHUNK_BITS} bits)…`);
const rangeAmount = await batchRangeProof({
  v: transferAmountChunks,
  rs: transferAmountRandomness.map((r) => numberToBytesLE(r, 32)),
  valBase,
  randBase,
  numBits: CHUNK_BITS,
});
console.error(`[m8-real] bulletproof transferAmount: ${rangeAmount.proof.length} bytes`);
const rangeNewBalance = await batchRangeProof({
  v: newBalanceChunks,
  rs: newBalanceRandomness.map((r) => numberToBytesLE(r, 32)),
  valBase,
  randBase,
  numBits: CHUNK_BITS,
});
console.error(`[m8-real] bulletproof newBalance: ${rangeNewBalance.proof.length} bytes`);

// ---- σ proof via proveTransfer with fake dk_user ------------------------------------------
const dkUserSeed = randomBytes(32);
const dkUserPriv = new TwistedEd25519PrivateKey(`0x${bytesToHex(dkUserSeed)}`);
const dkUserScalar = modN(bytesToBigLE(dkUserPriv.toUint8Array()));
console.error(`[m8-real] running proveTransfer with fake dk_user (will substitute s[0] via threshold)`);
const sigmaProof = proveTransfer({
  dk: dkUserPriv,
  senderAddress: senderAddressBytes,
  recipientAddress: recipientAddressBytes,
  tokenAddress: tokenAddressBytes,
  chainId: CHAIN_ID,
  senderEncryptionKey: vaultEkPub,
  recipientEncryptionKey: recipientEk,
  oldBalanceC: oldBalanceCt.C,
  oldBalanceD: oldBalanceCt.D,
  newBalanceC: newBalanceCt.map((x) => x.C),
  newBalanceD: newBalanceCt.map((x) => x.D),
  newAmountChunks: newBalanceChunks,
  newRandomness: newBalanceRandomness,
  transferAmountC: transferSenderCt.map((x) => x.C),
  transferAmountDSender: transferSenderCt.map((x) => x.D),
  transferAmountDRecipient: transferRecipientCt.map((x) => x.D),
  transferAmountChunks,
  transferRandomness: transferAmountRandomness,
  hasEffectiveAuditor: false,
});
console.error(`[m8-real] σ proof: commitment[${sigmaProof.commitment.length}] + response[${sigmaProof.response.length}]`);

// Recompute Fiat-Shamir e to extract α[0].
const PROTOCOL_ID_BYTES = new TextEncoder().encode("AptosConfidentialAsset/TransferV1");
const TYPE_NAME = "0x1::sigma_protocol_transfer::Transfer";
const G = RistrettoPoint.BASE;
const HRist = H_RISTRETTO;
const stmtCompressed = [G.toRawBytes(), HRist.toRawBytes(), vaultEkPub.toUint8Array(), recipientEk.toUint8Array()];
const stmtPoints = [G, HRist, RistrettoPoint.fromHex(vaultEkPub.toUint8Array()), RistrettoPoint.fromHex(recipientEk.toUint8Array())];
for (const grp of [
  oldBalanceCt.C, oldBalanceCt.D,
  newBalanceCt.map((x) => x.C), newBalanceCt.map((x) => x.D),
  transferSenderCt.map((x) => x.C),
  transferSenderCt.map((x) => x.D),
  transferRecipientCt.map((x) => x.D),
]) {
  for (const p of grp) {
    stmtPoints.push(p);
    stmtCompressed.push(p.toRawBytes());
  }
}
const stmt = { points: stmtPoints, compressedPoints: stmtCompressed, scalars: [] };
const sessionId = bcsSerializeTransferSession(
  senderAddressBytes, recipientAddressBytes, tokenAddressBytes,
  ell, n, false, 0,
);
const dst = {
  contractAddress: APTOS_FRAMEWORK_ADDRESS,
  chainId: CHAIN_ID,
  protocolId: PROTOCOL_ID_BYTES,
  sessionId,
};
const { e: feShChallenge } = sigmaProtocolFiatShamir(dst, TYPE_NAME, stmt, sigmaProof.commitment, 25);
const responseScalars = sigmaProof.response.map((r) => bytesToBigLE(r));
const alphaZero = modN(responseScalars[0] - modN(feShChallenge * dkUserScalar));
console.error(`[m8-real] extracted α[0] = ${bytesToHex(bigToLE32(alphaZero)).slice(0, 16)}... (consistent for round1 split)`);

// ---- Split α[0] for round1 + Pedersen commitments + HPKE seals ----------------------------
const alphaShares = [];
let sumSoFar = 0n;
for (let j = 0; j < 4; j += 1) {
  const s = randScalar();
  alphaShares.push(s);
  sumSoFar = modN(sumSoFar + s);
}
alphaShares.push(modN(alphaZero - sumSoFar));
if (alphaShares.reduce((a, b) => modN(a + b), 0n) !== alphaZero) {
  throw new Error("alpha_share sum check");
}
const blinds = alphaShares.map(() => randScalar());
const perShareCommitments = alphaShares.map((a, j) => {
  const p = G.multiply(modN(a)).add(HRist.multiply(modN(blinds[j])));
  return bytesToHex(p.toRawBytes());
});
const blindSum = blinds.reduce((acc, b) => modN(acc + b), 0n);
const amountCommitmentPoint = G.multiply(modN(alphaZero)).add(HRist.multiply(modN(blindSum)));
const amountCommitmentHex = bytesToHex(amountCommitmentPoint.toRawBytes());

// ---- Compute nullifier/recipient_hash/amount_tag via the witness builder ------------------
const witnessOutPath = `/tmp/m8-${requestId}-witness.json`;
const witnessTempProc = spawnSync(
  "node",
  [
    resolve(repoRoot, "circuits/scripts/compute_withdraw_witness.mjs"),
    "--depositor-witness", depositWitnessPath,
    "--recipient", recipientAddress,
    "--vault-sequence", vaultSequenceArg,
    "--root", rootHex,
    "--ca-payload-hash", `0x${"00".repeat(32)}`, // placeholder for r1
    "--output", witnessOutPath,
  ],
  { encoding: "utf8", maxBuffer: 10 * 1024 * 1024 },
);
if (witnessTempProc.status !== 0) {
  console.error(`witness build failed: ${witnessTempProc.stderr || witnessTempProc.stdout}`);
  process.exit(1);
}
const witnessSummary = JSON.parse(witnessTempProc.stdout.trim());
const witnessJson = JSON.parse(readFileSync(witnessOutPath, "utf8"));
const nullifierHashHex = `0x${bytesToHex(bigToLE32(BigInt(witnessJson.nullifier_hash)))}`;
const recipientHashHex = `0x${bytesToHex(bigToLE32(BigInt(witnessJson.recipient_hash)))}`;
const amountTagHex = `0x${bytesToHex(bigToLE32(BigInt(witnessJson.amount_tag)))}`;
const withdrawBlindHex = witnessSummary.withdraw_blind_hex;
console.error(`[m8-real] nullifierHash=${nullifierHashHex.slice(0, 16)}...`);

// ---- HPKE-seal ingress envelopes ----------------------------------------------------------
function hpkeSeal(pubHex, aad, plaintext) {
  const r = spawnSync(HPKE_SEAL_BIN, [], {
    input: JSON.stringify({
      recipientPubKeyHex: normalizeHex(pubHex),
      aadHex: bytesToHex(aad),
      plaintextHex: bytesToHex(plaintext),
    }),
    encoding: "utf8",
    maxBuffer: 4 * 1024 * 1024,
  });
  if (r.status !== 0) throw new Error(`hpke_seal: ${r.stderr || r.stdout}`);
  return JSON.parse(r.stdout.trim());
}

const ingressEnvelopes = [];
const placeholderRequestHashHex = "0x" + createHash("sha256").update("EUNOMA_PLACEHOLDER_REQUEST_HASH_V1").digest("hex");
const expirySecs = Math.floor(Date.now() / 1000) + 3600;

const nodeMap = new Map(caDkgRoster.nodes.map((n) => [Number(n.slot), n]));
for (let i = 0; i < selectedSlots.length; i += 1) {
  const slot = selectedSlots[i];
  const node = nodeMap.get(slot);
  const aadBytes = m1IngressAad({
    requestId,
    sessionId: requestId,
    dkgEpoch: String(caDkgRoster.dkgEpoch),
    selfSlot: slot,
    playerId: i,
    rosterHash,
    vaultEk: normalizeHex(vaultEk),
    root: normalizeHex(rootHex),
    nullifierHash: normalizeHex(nullifierHashHex),
    recipientHash: normalizeHex(recipientHashHex),
    amountTag: normalizeHex(amountTagHex),
    vaultSequence: Number(vaultSequenceArg),
    depositCount: Number(depositWitness.depositCount),
    amountCommitment: amountCommitmentHex,
    perShareCommitments,
  });
  const plaintext = new Uint8Array(64);
  plaintext.set(bigToLE32(alphaShares[i]), 0);
  plaintext.set(bigToLE32(blinds[i]), 32);
  ingressEnvelopes.push(hpkeSeal(node.hpkePublicKey, aadBytes, plaintext));
  console.error(`[m8-real] sealed envelope[${i}] for slot ${slot}`);
}

// ---- Helper to POST coordinator routes ----------------------------------------------------
async function post(path, body) {
  const res = await fetch(new URL(path, COORDINATOR_URL), {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${COORDINATOR_BEARER_TOKEN}` },
    body: JSON.stringify(body),
  });
  const respBody = await res.json().catch(() => ({}));
  return { status: res.status, body: respBody };
}

// ---- 1) round1 ----------------------------------------------------------------------------
const dkgEpochStr = String(caDkgRoster.dkgEpoch);
const depositCount = Number(depositWitness.depositCount);
const observedDepositCursors = Array.from({ length: depositCount }, (_, i) => i + 1);
const round1Body = {
  dkgEpoch: dkgEpochStr,
  sessionId: requestId,
  caDkgTranscriptHash: required(process.env.EUNOMA_TESTNET_CA_DKG_TRANSCRIPT_HASH, "env CA_DKG_TRANSCRIPT_HASH"),
  vaultEkTranscriptHash: required(process.env.EUNOMA_TESTNET_VAULT_EK_TRANSCRIPT_HASH, "env VAULT_EK_TRANSCRIPT_HASH"),
  registrationTranscriptHash: required(process.env.EUNOMA_TESTNET_REGISTRATION_TRANSCRIPT_HASH, "env REGISTRATION_TRANSCRIPT_HASH"),
  vaultStateInitTranscriptHash: required(process.env.EUNOMA_TESTNET_VAULT_STATE_INIT_TRANSCRIPT_HASH, "env VAULT_STATE_INIT_TRANSCRIPT_HASH"),
  observedDepositTranscriptHashes: required(process.env.EUNOMA_TESTNET_OBSERVED_DEPOSIT_TRANSCRIPT_HASHES, "env OBSERVED").split(",").map(normalizeHex),
  observedDepositCursors,
  rosterHash,
  selectedSlots,
  selfSlot: selectedSlots[0],
  playerId: 0,
  vaultEk: normalizeHex(vaultEk),
  senderAddress: addr32(vaultAddress),
  assetType: addr32(assetType),
  chainId: CHAIN_ID,
  root: normalizeHex(rootHex),
  nullifierHash: normalizeHex(nullifierHashHex),
  recipient: addr32(recipientAddress),
  recipientHash: normalizeHex(recipientHashHex),
  amountTag: normalizeHex(amountTagHex),
  vaultSequence: Number(vaultSequenceArg),
  expirySecs,
  requestHash: normalizeHex(placeholderRequestHashHex),
  depositCount,
  requestId,
  amountCommitment: amountCommitmentHex,
  perShareCommitments,
  ingressEnvelopes,
};
console.error(`[m8-real] POST /v2/withdraw/mpcca/start`);
let r = await post("/v2/withdraw/mpcca/start", round1Body);
console.error(`[m8-real] round1 → HTTP ${r.status}`);
if (r.status !== 200) {
  console.error(JSON.stringify(r.body, null, 2));
  process.exit(30);
}

// ---- 2) round2 ----------------------------------------------------------------------------
const userSigmaCommitmentsHex = sigmaProof.commitment.slice(1, 30).map((c) => bytesToHex(c));
const userSigmaResponseSharesHex = sigmaProof.response.slice(1, 25).map((r) => bytesToHex(r));
const perChunkCommitmentsAmountHex = rangeAmount.comms.map((c) => bytesToHex(c));
const perChunkCommitmentsNewBalanceHex = rangeNewBalance.comms.map((c) => bytesToHex(c));

const round2Body = {
  ...round1Body,
  amountCommitment: undefined,
  perShareCommitments: undefined,
  ingressEnvelopes: undefined,
  recipientEk: recipientEkHex,
  oldBalanceC: oldBalanceCt.C.map((p) => bytesToHex(p.toRawBytes())),
  oldBalanceD: oldBalanceCt.D.map((p) => bytesToHex(p.toRawBytes())),
  newBalanceC: newBalanceCt.map((x) => bytesToHex(x.C.toRawBytes())),
  newBalanceD: newBalanceCt.map((x) => bytesToHex(x.D.toRawBytes())),
  transferAmountC: transferSenderCt.map((x) => bytesToHex(x.C.toRawBytes())),
  transferAmountDSender: transferSenderCt.map((x) => bytesToHex(x.D.toRawBytes())),
  transferAmountDRecipient: transferRecipientCt.map((x) => bytesToHex(x.D.toRawBytes())),
  userSigmaCommitmentsHex,
  userSigmaResponseSharesHex,
  bulletproofZkrpAmountHex: bytesToHex(rangeAmount.proof),
  bulletproofZkrpNewBalanceHex: bytesToHex(rangeNewBalance.proof),
  perChunkCommitmentsAmountHex,
  perChunkCommitmentsNewBalanceHex,
};
// Strip undefined fields (would have been wire-clobbered by JSON.stringify).
for (const k of Object.keys(round2Body)) if (round2Body[k] === undefined) delete round2Body[k];

console.error(`[m8-real] POST /v2/withdraw/mpcca/round2`);
r = await post("/v2/withdraw/mpcca/round2", round2Body);
console.error(`[m8-real] round2 → HTTP ${r.status}`);
if (r.status !== 200) {
  console.error(JSON.stringify(r.body, null, 2));
  process.exit(31);
}

// ---- 3) finalize --------------------------------------------------------------------------
const finalizeBody = { ...round2Body };
delete finalizeBody.bulletproofZkrpAmountHex;
delete finalizeBody.bulletproofZkrpNewBalanceHex;
delete finalizeBody.perChunkCommitmentsAmountHex;
delete finalizeBody.perChunkCommitmentsNewBalanceHex;
delete finalizeBody.userSigmaResponseSharesHex;
console.error(`[m8-real] POST /v2/withdraw/mpcca/finalize`);
r = await post("/v2/withdraw/mpcca/finalize", finalizeBody);
console.error(`[m8-real] finalize → HTTP ${r.status}`);
if (r.status !== 200) {
  console.error(JSON.stringify(r.body, null, 2));
  process.exit(32);
}

// ---- 4) Compute real ca_payload_hash + Groth16 proof --------------------------------------
const finalizePath = resolve(serviceRoot, `.agent-local/eunoma-v2/coordinator/mpcca_withdraw/${dkgEpochStr}__${requestId}__finalize.json`);
const finalizeArtifact = JSON.parse(readFileSync(finalizePath, "utf8"));
const round2Path = resolve(serviceRoot, `.agent-local/eunoma-v2/coordinator/mpcca_withdraw/${dkgEpochStr}__${requestId}__round2.json`);
const round2Artifact = JSON.parse(readFileSync(round2Path, "utf8"));

const caPayload = buildCaPayloadFromFinalizeArtifact({
  recipientAddressHex: round2Artifact.recipient,
  assetTypeHex: round2Artifact.assetType,
  statementInputs: round2Artifact.statementInputs,
  mpccaArtifact: {
    aggregatedSigmaCommitmentsHex: finalizeArtifact.mpccaWithdrawFinalizeArtifact.aggregatedSigmaCommitmentsHex,
    sigmaResponseHex: finalizeArtifact.mpccaWithdrawFinalizeArtifact.sigmaResponseHex,
    bulletproofZkrpAmountHex: round2Artifact.userProofArtifacts.bulletproofZkrpAmountHex,
    bulletproofZkrpNewBalanceHex: round2Artifact.userProofArtifacts.bulletproofZkrpNewBalanceHex,
  },
  memoHex: "",
});
const caPayloadHashRaw = caPayloadHashRawV2(caPayload);
const caPayloadHashFr = caPayloadHashFrV2(caPayload);
console.error(`[m8-real] caPayloadHashFr = ${caPayloadHashFr.slice(0, 16)}...`);

// Regenerate witness with the REAL ca_payload_hash + withdraw_blind we already chose.
const witnessReProc = spawnSync(
  "node",
  [
    resolve(repoRoot, "circuits/scripts/compute_withdraw_witness.mjs"),
    "--depositor-witness", depositWitnessPath,
    "--recipient", recipientAddress,
    "--vault-sequence", vaultSequenceArg,
    "--root", rootHex,
    "--ca-payload-hash", caPayloadHashFr.startsWith("0x") ? caPayloadHashFr : "0x" + caPayloadHashFr,
    "--withdraw-blind-hex", withdrawBlindHex,
    "--output", witnessOutPath,
  ],
  { encoding: "utf8", maxBuffer: 10 * 1024 * 1024 },
);
if (witnessReProc.status !== 0) {
  console.error(`witness re-build failed: ${witnessReProc.stderr || witnessReProc.stdout}`);
  process.exit(33);
}
const proofOutPath = `/tmp/m8-${requestId}-proof.json`;
const proofProc = spawnSync(
  "node",
  [
    resolve(serviceRoot, "scripts/local_generate_withdraw_proof.mjs"),
    "--witness-json", witnessOutPath,
    "--output", proofOutPath,
  ],
  { encoding: "utf8", maxBuffer: 10 * 1024 * 1024 },
);
if (proofProc.status !== 0) {
  console.error(`proof gen failed: ${proofProc.stderr || proofProc.stdout}`);
  process.exit(33);
}
const proofObj = JSON.parse(readFileSync(proofOutPath, "utf8"));
const proofHex = proofObj.proofHex;
console.error(`[m8-real] Groth16 proof generated (${proofHex.length} hex chars)`);

// ---- 5) frost-attest ----------------------------------------------------------------------
const frostAttestBody = {
  ...finalizeBody,
  attestationConfig: {
    bridge: process.env.BRIDGE_PACKAGE_ADDRESS,
    vault: vaultAddress,
    operatorSetVersion: caDkgRoster.operatorSetVersion,
    frostGroupPubkey: frostRoster.frostGroupPubkey,
    circuitVersionsHash: process.env.EUNOMA_TESTNET_CIRCUIT_VERSIONS_HASH ?? "0x0000000000000000000000000000000000000000000000000000000000000001",
  },
  withdrawProofHex: proofHex,
  memoHex: "",
};
console.error(`[m8-real] POST /v2/withdraw/mpcca/frost-attest`);
r = await post("/v2/withdraw/mpcca/frost-attest", frostAttestBody);
console.error(`[m8-real] frost-attest → HTTP ${r.status}`);
if (r.status !== 200) {
  console.error(JSON.stringify(r.body, null, 2));
  process.exit(34);
}

// ---- 6) submit ----------------------------------------------------------------------------
console.error(`[m8-real] POST /v2/withdraw/mpcca/submit`);
r = await post("/v2/withdraw/mpcca/submit", { dkgEpoch: dkgEpochStr, requestId });
console.error(`[m8-real] submit → HTTP ${r.status}`);
process.stdout.write(JSON.stringify({
  ok: r.status >= 200 && r.status < 300,
  httpStatus: r.status,
  requestId,
  recipientAddress,
  amountOctas: TRANSFER_AMOUNT_OCTAS.toString(),
  caPayloadHashFr,
  proofHex,
  responseBody: r.body,
}, null, 2) + "\n");
process.exit(r.status >= 200 && r.status < 300 ? 0 : 35);

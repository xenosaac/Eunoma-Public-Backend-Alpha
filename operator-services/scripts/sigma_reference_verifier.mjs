// operator-services/scripts/sigma_reference_verifier.mjs
//
// JS port of the σ-protocol reference verifier for Aptos CA TransferV1.
// Mirrors:
//   * Rust:  operator-services/crypto-worker-rust/src/transfer_sigma_reference.rs
//            (psi_transfer @363, f_transfer @448, verify_transfer_single_party @584)
//   * SDK:   operator-services/node_modules/@aptos-labs/confidential-asset/
//            src/crypto/sigmaProtocolTransfer.ts
//            (makeTransferPsi @311, makeTransferF @405)
//   * SDK Fiat-Shamir: same package src/crypto/sigmaProtocol.ts (@171)
//
// Verifies the identity per position i ∈ [0, 30) for the Eunoma no-auditor
// config (ell=8, n=4, has_effective=false, num_volun=0):
//
//     ψ(σ)[i]  ?=  A[i]  +  e · f(stmt)[i]
//
// Returns a per-position fail mask (0 = verifies, 1 = does not verify) plus
// the aggregate `allPass` flag and the Fiat-Shamir challenge `e` for debug.
//
// This is a reference verifier: it computes the identity from first
// principles using the SDK's exported `sigmaProtocolFiatShamir` for the
// challenge derivation (so we don't reimplement the BCS Fiat-Shamir hash
// chain) and re-derives ψ and f locally in JS. No SDK helper is called for
// the per-position verification step itself, so this can be used to detect
// witness-witness mismatches that the upstream `verifyTransfer` would only
// report as a single boolean.

import {
  RistrettoPoint,
  H_RISTRETTO,
  bcsSerializeTransferSession,
  sigmaProtocolFiatShamir,
  APTOS_FRAMEWORK_ADDRESS,
} from "@aptos-labs/confidential-asset";
import { ed25519 } from "@noble/curves/ed25519";
import { mod } from "@noble/curves/abstract/modular";
import { utf8ToBytes } from "@noble/hashes/utils";

const ED_N = ed25519.CURVE.n;

// =============================================================================
// Constants (match SDK + Move source identifiers)
// =============================================================================

const PROTOCOL_ID = "AptosConfidentialAsset/TransferV1";
const TYPE_NAME = "0x1::sigma_protocol_transfer::Transfer";

// Chunk-base radix for B-power weighted sums: 2^16 (matches CHUNK_BITS).
const B_POW_BASE = 1n << 16n;

// =============================================================================
// Helpers
// =============================================================================

function modN(x) {
  return mod(x, ED_N);
}

function computeBPowers(count) {
  const out = [1n];
  for (let i = 1; i < count; i++) {
    out.push(modN(out[i - 1] * B_POW_BASE));
  }
  return out;
}

/**
 * Convert a 32-byte little-endian buffer to a scalar mod ℓ.
 * Used to parse `proof.response[]` bytes back into scalars.
 */
function bytesToScalarLE(b) {
  let x = 0n;
  for (let i = 31; i >= 0; i--) {
    x = (x << 8n) | BigInt(b[i]);
  }
  return modN(x);
}

function pointsEqual(a, b) {
  // RistrettoPoint exposes `.equals()` in noble-curves; this is the canonical
  // equality check (compares canonical encodings, not internal coords).
  return a.equals(b);
}

function ensureRistrettoPoint(p, label) {
  if (!p || typeof p.equals !== "function" || typeof p.multiply !== "function") {
    throw new TypeError(`${label}: expected RistrettoPoint instance`);
  }
  return p;
}

// =============================================================================
// Statement assembly (mirrors makeTransferPsi statement layout in
// sigmaProtocolTransfer.ts:243-271; no-auditor branch)
// =============================================================================

/**
 * Build the public statement point vector for a no-auditor transfer (Eunoma
 * config). Layout:
 *   [ G, H, ek_sid, ek_rid,
 *     old_P[ell], old_R[ell], new_P[ell], new_R[ell],
 *     P[n], R_sid[n], R_rid[n] ]
 * → 4 + 4*ell + 3*n total points (= 4 + 32 + 12 = 48 for ell=8, n=4).
 *
 * `oldBalanceCt`, `newBalanceCt` are arrays of {C, D} (length ell); transfer
 * cts are split into sender/recipient (length n each). Compressed bytes are
 * computed via `.toRawBytes()`.
 */
function buildStatement({
  ekSender, // RistrettoPoint
  ekRecipient, // RistrettoPoint
  oldBalanceCt, // [{C, D}] length ell
  newBalanceCt, // [{C, D}] length ell
  transferSenderCt, // [{C, D}] length n
  transferRecipientCt, // [{C, D}] length n  (only .D is used; see SDK pushPoint)
}) {
  const G = RistrettoPoint.BASE;
  const H = H_RISTRETTO;
  ensureRistrettoPoint(ekSender, "ekSender");
  ensureRistrettoPoint(ekRecipient, "ekRecipient");

  const points = [G, H, ekSender, ekRecipient];
  const compressed = [G.toRawBytes(), H.toRawBytes(), ekSender.toRawBytes(), ekRecipient.toRawBytes()];

  const pushP = (p, label, idx) => {
    ensureRistrettoPoint(p, `${label}[${idx}]`);
    points.push(p);
    compressed.push(p.toRawBytes());
  };

  for (let i = 0; i < oldBalanceCt.length; i++) pushP(oldBalanceCt[i].C, "oldBalanceC", i); // old_P
  for (let i = 0; i < oldBalanceCt.length; i++) pushP(oldBalanceCt[i].D, "oldBalanceD", i); // old_R
  for (let i = 0; i < newBalanceCt.length; i++) pushP(newBalanceCt[i].C, "newBalanceC", i); // new_P
  for (let i = 0; i < newBalanceCt.length; i++) pushP(newBalanceCt[i].D, "newBalanceD", i); // new_R
  for (let j = 0; j < transferSenderCt.length; j++) pushP(transferSenderCt[j].C, "transferAmountC", j); // P
  for (let j = 0; j < transferSenderCt.length; j++) pushP(transferSenderCt[j].D, "transferAmountDSender", j); // R_sid
  for (let j = 0; j < transferRecipientCt.length; j++) pushP(transferRecipientCt[j].D, "transferAmountDRecipient", j); // R_rid

  return { points, compressedPoints: compressed, scalars: [] };
}

// =============================================================================
// ψ_transfer (no-auditor branch; mirrors psi_transfer in transfer_sigma_reference.rs:363
// and makeTransferPsi in sigmaProtocolTransfer.ts:311)
//
// Witness layout: [dk, new_a[ell], new_r[ell], v[n], r[n]]   (length 1+2*ell+2*n = 25)
// Output layout (30 group elements for ell=8, n=4):
//   index 0          : ek_sid · dk
//   index 1..1+ell   : G·new_a[i] + H·new_r[i]
//   index 1+ell..1+2ell : ek_sid · new_r[i]
//   index 1+2ell     : balance equation (position 17 in ell=8 config)
//   index 2+2ell..2+2ell+n : G·v[j] + H·r[j]
//   index 2+2ell+n..2+2ell+2n : ek_sid · r[j]
//   index 2+2ell+2n..2+2ell+3n : ek_rid · r[j]
// =============================================================================

const IDX_G = 0;
const IDX_H = 1;
const IDX_EK_SID = 2;
const IDX_EK_RID = 3;
const START_IDX_OLD_P = 4;

function startIdxOldR(ell) { return START_IDX_OLD_P + ell; }
function startIdxNewP(ell) { return START_IDX_OLD_P + 2 * ell; }
function startIdxNewR(ell) { return START_IDX_OLD_P + 3 * ell; }
function startIdxP(ell)   { return START_IDX_OLD_P + 4 * ell; }
function startIdxRSid(ell, n) { return START_IDX_OLD_P + 4 * ell + n; }
function startIdxRRid(ell, n) { return START_IDX_OLD_P + 4 * ell + 2 * n; }

function psiTransfer(stmt, witness, ell, n) {
  const expectedLen = 1 + 2 * ell + 2 * n;
  if (witness.length !== expectedLen) {
    throw new Error(`psiTransfer: witness length ${witness.length} != 1+2*ell+2*n (${expectedLen})`);
  }

  const dk = witness[0];
  const newA = witness.slice(1, 1 + ell);
  const newR = witness.slice(1 + ell, 1 + 2 * ell);
  const v = witness.slice(1 + 2 * ell, 1 + 2 * ell + n);
  const r = witness.slice(1 + 2 * ell + n, 1 + 2 * ell + 2 * n);

  const G = stmt.points[IDX_G];
  const H = stmt.points[IDX_H];
  const ekSid = stmt.points[IDX_EK_SID];
  const ekRid = stmt.points[IDX_EK_RID];

  const out = [];

  // 1. dk · ek_sid
  out.push(ekSid.multiply(dk));

  // 2. G·new_a[i] + H·new_r[i]
  for (let i = 0; i < ell; i++) {
    out.push(G.multiply(newA[i]).add(H.multiply(newR[i])));
  }

  // 3. ek_sid · new_r[i]
  for (let i = 0; i < ell; i++) {
    out.push(ekSid.multiply(newR[i]));
  }

  // 4. Balance equation:
  //     dk · ⟨B, old_R⟩  +  ⟨B, new_a⟩ · G  +  ⟨B, v⟩ · G
  const bEll = computeBPowers(ell);
  const bN = computeBPowers(n);
  const startOldR = startIdxOldR(ell);
  let balance = RistrettoPoint.ZERO;
  for (let i = 0; i < ell; i++) {
    balance = balance.add(stmt.points[startOldR + i].multiply(modN(dk * bEll[i])));
  }
  for (let i = 0; i < ell; i++) {
    balance = balance.add(G.multiply(modN(newA[i] * bEll[i])));
  }
  for (let j = 0; j < n; j++) {
    balance = balance.add(G.multiply(modN(v[j] * bN[j])));
  }
  out.push(balance);

  // 5. G·v[j] + H·r[j]
  for (let j = 0; j < n; j++) {
    out.push(G.multiply(v[j]).add(H.multiply(r[j])));
  }

  // 6. ek_sid · r[j]
  for (let j = 0; j < n; j++) {
    out.push(ekSid.multiply(r[j]));
  }

  // 7. ek_rid · r[j]
  for (let j = 0; j < n; j++) {
    out.push(ekRid.multiply(r[j]));
  }

  return out;
}

// =============================================================================
// f_transfer (mirrors f_transfer in transfer_sigma_reference.rs:448 and
// makeTransferF in sigmaProtocolTransfer.ts:405; no-auditor branch)
//
// Returns the 30 target points such that ψ(σ) = A + e · f(stmt) under a
// valid proof. Reads exclusively from the public statement points; no
// witness involvement.
// =============================================================================

function fTransfer(stmt, ell, n) {
  const out = [];
  const H = stmt.points[IDX_H];

  // 1. H
  out.push(H);

  // 2. new_P[i]  (new_balance_C)
  const startNewP = startIdxNewP(ell);
  for (let i = 0; i < ell; i++) {
    out.push(stmt.points[startNewP + i]);
  }

  // 3. new_R[i]  (new_balance_D)
  const startNewR = startIdxNewR(ell);
  for (let i = 0; i < ell; i++) {
    out.push(stmt.points[startNewR + i]);
  }

  // 4. Balance equation target: ⟨B, old_P⟩  (i.e. weighted sum of oldBalanceC)
  const bEll = computeBPowers(ell);
  let target = RistrettoPoint.ZERO;
  for (let i = 0; i < ell; i++) {
    target = target.add(stmt.points[START_IDX_OLD_P + i].multiply(bEll[i]));
  }
  out.push(target);

  // 5. P[j]  (transfer_amount_C)
  const startP = startIdxP(ell);
  for (let j = 0; j < n; j++) {
    out.push(stmt.points[startP + j]);
  }

  // 6. R_sid[j]  (transfer_amount_D_sender)
  const startRSid = startIdxRSid(ell, n);
  for (let j = 0; j < n; j++) {
    out.push(stmt.points[startRSid + j]);
  }

  // 7. R_rid[j]  (transfer_amount_D_recipient)
  const startRRid = startIdxRRid(ell, n);
  for (let j = 0; j < n; j++) {
    out.push(stmt.points[startRRid + j]);
  }

  return out;
}

// =============================================================================
// Reference verifier
// =============================================================================

/**
 * Verify a TransferV1 σ-proof per position and return the failure mask.
 *
 * @param {object} args
 * @param {{ commitment: Uint8Array[], response: Uint8Array[] }} args.proof
 *   The SDK-produced proof (commitment = 30 compressed points, response = 25
 *   scalar bytes — matches the ell=8 n=4 no-auditor shape).
 * @param {{C: RistrettoPoint, D: RistrettoPoint}[]} args.oldBalanceCt
 * @param {{C: RistrettoPoint, D: RistrettoPoint}[]} args.newBalanceCt
 * @param {{C: RistrettoPoint, D: RistrettoPoint}[]} args.transferSenderCt
 * @param {{C: RistrettoPoint, D: RistrettoPoint}[]} args.transferRecipientCt
 * @param {{toUint8Array(): Uint8Array}} args.ekSender — TwistedEd25519PublicKey
 * @param {{toUint8Array(): Uint8Array}} args.ekRecipient — TwistedEd25519PublicKey
 * @param {number} args.chainId
 * @param {Uint8Array} [args.senderAddress] — 32 bytes (defaults to all-zero)
 * @param {Uint8Array} [args.recipientAddress] — 32 bytes
 * @param {Uint8Array} [args.tokenAddress] — 32 bytes
 *
 * @returns {{ failsByPosition: number[], allPass: boolean, challengeHex: string }}
 *   `failsByPosition[i]` is 0 if position i verifies, 1 otherwise.
 *   `allPass` is true iff every position verifies.
 *   `challengeHex` is the Fiat-Shamir challenge (LE 32-byte hex) for debug.
 */
export function runReferenceVerifier({
  proof,
  oldBalanceCt,
  newBalanceCt,
  transferSenderCt,
  transferRecipientCt,
  ekSender,
  ekRecipient,
  chainId,
  senderAddress = new Uint8Array(32),
  recipientAddress = new Uint8Array(32),
  tokenAddress = new Uint8Array(32),
}) {
  if (!proof || !Array.isArray(proof.commitment) || !Array.isArray(proof.response)) {
    throw new TypeError("runReferenceVerifier: proof must have commitment[] and response[]");
  }

  const ell = oldBalanceCt.length;
  const n = transferSenderCt.length;
  const expectedCommitmentLen = 2 + 2 * ell + 3 * n; // 1+ell+ell+1+n+n+n = 2+2ell+3n
  const expectedResponseLen = 1 + 2 * ell + 2 * n;
  if (proof.commitment.length !== expectedCommitmentLen) {
    throw new Error(`runReferenceVerifier: commitment length ${proof.commitment.length} != ${expectedCommitmentLen} (ell=${ell}, n=${n})`);
  }
  if (proof.response.length !== expectedResponseLen) {
    throw new Error(`runReferenceVerifier: response length ${proof.response.length} != ${expectedResponseLen} (ell=${ell}, n=${n})`);
  }
  if (newBalanceCt.length !== ell || transferRecipientCt.length !== n) {
    throw new Error("runReferenceVerifier: new-balance / transfer-recipient ciphertext shape mismatch");
  }

  // Convert ekSender/ekRecipient (TwistedEd25519PublicKey-shaped) to RistrettoPoints.
  const ekSenderBytes = ekSender.toUint8Array();
  const ekRecipientBytes = ekRecipient.toUint8Array();
  const ekSenderPoint = RistrettoPoint.fromHex(ekSenderBytes);
  const ekRecipientPoint = RistrettoPoint.fromHex(ekRecipientBytes);

  // Build statement (same layout as proveTransfer).
  const stmt = buildStatement({
    ekSender: ekSenderPoint,
    ekRecipient: ekRecipientPoint,
    oldBalanceCt,
    newBalanceCt,
    transferSenderCt,
    transferRecipientCt,
  });

  // Recompute Fiat-Shamir challenge `e` from the same BCS-encoded inputs the
  // prover used. We pass k = response.length (the witness length) to match
  // sigmaProtocolFiatShamir's signature.
  const sessionId = bcsSerializeTransferSession(
    senderAddress,
    recipientAddress,
    tokenAddress,
    ell,
    n,
    /* hasEffectiveAuditor */ false,
    /* numVolunAuditors */ 0,
  );
  const dst = {
    contractAddress: APTOS_FRAMEWORK_ADDRESS,
    chainId,
    protocolId: utf8ToBytes(PROTOCOL_ID),
    sessionId,
  };
  const k = proof.response.length;
  const { e } = sigmaProtocolFiatShamir(dst, TYPE_NAME, stmt, proof.commitment, k);

  // Parse responses (25 scalars) and compute ψ(σ).
  const sigma = proof.response.map((bytes) => bytesToScalarLE(bytes));
  const psiSigma = psiTransfer(stmt, sigma, ell, n);

  // Decompress commitment points A[i].
  const commitmentPoints = proof.commitment.map((bytes) => RistrettoPoint.fromHex(bytes));

  // Compute f(stmt).
  const fStmt = fTransfer(stmt, ell, n);

  if (psiSigma.length !== expectedCommitmentLen || fStmt.length !== expectedCommitmentLen) {
    throw new Error("runReferenceVerifier: internal ψ/f length mismatch — translation bug");
  }

  // Verify per-position: ψ(σ)[i]  ?=  A[i]  +  e · f(stmt)[i]
  const failsByPosition = new Array(expectedCommitmentLen).fill(0);
  for (let i = 0; i < expectedCommitmentLen; i++) {
    const expected = commitmentPoints[i].add(fStmt[i].multiply(e));
    failsByPosition[i] = pointsEqual(psiSigma[i], expected) ? 0 : 1;
  }

  const allPass = failsByPosition.every((x) => x === 0);

  // 32-byte LE hex for diagnostic display.
  let eBytes = e;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(eBytes & 0xffn);
    eBytes >>= 8n;
  }
  const challengeHex = Buffer.from(out).toString("hex");

  return { failsByPosition, allPass, challengeHex };
}

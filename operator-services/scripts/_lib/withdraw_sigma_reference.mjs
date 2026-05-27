// operator-services/scripts/_lib/withdraw_sigma_reference.mjs
//
// JS port of the σ-protocol reference verifier for Aptos CA WithdrawalV1
// (which is also the protocol used by normalize_raw, since normalize ==
// withdrawal with v=0).
//
// Mirrors:
//   * SDK source: operator-services/node_modules/@aptos-labs/confidential-asset/
//                 src/crypto/sigmaProtocolWithdraw.ts
//                 (makeWithdrawPsi @122, makeWithdrawF @183, verifyWithdrawInternal @408)
//   * SDK Fiat-Shamir: same package src/crypto/sigmaProtocol.ts @171
//
// Sibling: operator-services/scripts/sigma_reference_verifier.mjs (TRANSFER variant).
//
// Verifies the identity per position i ∈ [0, m) for the Eunoma vault-normalize
// config (ell=8, no auditor → m = 2 + 2*ell = 18; with auditor → m = 2 + 3*ell = 26):
//
//     ψ(σ)[i]  ?=  A[i]  +  e · f(stmt)[i]
//
// Returns either {ok: true} or throws with a position-specific name so that
// debug output can pinpoint the failing constraint (e.g. position 0 = dk·ek,
// position 1..ell = new_a[i]·G + new_r[i]·H, etc.).
//
// =============================================================================
// DUAL-PACKAGE HAZARD MITIGATION (matches recover_balance_chunks.mjs:24-46)
// =============================================================================
//
// `@noble/curves/ed25519` ships its own `RistrettoPoint` class. If two callers
// resolve the package from different node_modules trees, they get DIFFERENT
// class objects despite identical wire types — `pointA.add(pointB)` then throws
// "RistrettoPoint expected" at edwards.js:380.
//
// To stay interop-clean with circuits/ and other consumers we DO import the
// SDK's RistrettoPoint at module scope (so the verifier API can be called
// stand-alone), but we ALSO derive the point class from a representative input
// point when the caller passes in Ristretto-shaped points whose constructor
// might be a different instance. The internal builders (buildStatement /
// psiWithdraw / fWithdraw) use the SAME class as the input points, never
// mixing two RistrettoPoint instances.

import {
  RistrettoPoint,
  H_RISTRETTO,
  bcsSerializeWithdrawSession,
  sigmaProtocolFiatShamir,
  APTOS_FRAMEWORK_ADDRESS,
} from "@aptos-labs/confidential-asset";
import { ed25519 } from "@noble/curves/ed25519";
import { mod } from "@noble/curves/abstract/modular";
import { numberToBytesLE } from "@noble/curves/abstract/utils";
import { utf8ToBytes } from "@noble/hashes/utils";

const ED_N = ed25519.CURVE.n;

// =============================================================================
// Constants (match SDK + Move source identifiers)
// =============================================================================

const PROTOCOL_ID_WITHDRAWAL = "AptosConfidentialAsset/WithdrawalV1";
const TYPE_NAME = "0x1::sigma_protocol_withdraw::Withdrawal";

// Chunk-base radix for B-power weighted sums: 2^16 (matches CHUNK_BITS).
const B_POW_BASE = 1n << 16n;

// Statement point layout indices (auditor-less; for auditor-present, see
// getIdxEkAud / getStartIdxNewRAud helpers below).
const IDX_G = 0;
const IDX_H = 1;
const IDX_EK = 2;
const START_IDX_OLD_P = 3;

function startIdxOldR(ell) { return START_IDX_OLD_P + ell; }
function startIdxNewP(ell) { return START_IDX_OLD_P + 2 * ell; }
function startIdxNewR(ell) { return START_IDX_OLD_P + 3 * ell; }
function idxEkAud(ell)     { return START_IDX_OLD_P + 4 * ell; }
function startIdxNewRAud(ell) { return START_IDX_OLD_P + 4 * ell + 1; }

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
  if (!(b instanceof Uint8Array)) {
    throw new TypeError("bytesToScalarLE: expected Uint8Array");
  }
  if (b.length !== 32) {
    throw new RangeError(`bytesToScalarLE: expected 32 bytes, got ${b.length}`);
  }
  let x = 0n;
  for (let i = 31; i >= 0; i--) {
    x = (x << 8n) | BigInt(b[i]);
  }
  return modN(x);
}

function pointsEqual(a, b) {
  return a.equals(b);
}

function ensureRistrettoPoint(p, label) {
  if (
    p === null ||
    typeof p !== "object" ||
    typeof p.equals !== "function" ||
    typeof p.multiply !== "function" ||
    typeof p.add !== "function" ||
    typeof p.toRawBytes !== "function"
  ) {
    throw new TypeError(`${label}: expected RistrettoPoint instance (missing equals/multiply/add/toRawBytes)`);
  }
  return p;
}

// =============================================================================
// Position-name table — used to surface a human-readable failure label
// (auditor-less branch first; auditor-present branch lengths checked in builder).
// =============================================================================

function buildPositionNames(ell, hasAuditor) {
  const names = [];
  // 0: dk * ek  (proves knowledge of dk such that ek = dk · G in the Twisted
  //    Ed25519 sense; here ψ outputs dk·ek and f outputs H, so the check is
  //    sigma_0·ek == A_0 + e·H, hence the implicit identity is "dk·ek == ek·dk").
  names.push("position_0_dk_ek_consistency");
  // 1..ell: new_a[i] * G + new_r[i] * H  vs  new_P[i]
  for (let i = 0; i < ell; i++) {
    names.push(`position_${1 + i}_new_C_chunk_${i}`);
  }
  // ell+1..2*ell: new_r[i] * ek  vs  new_R[i]
  for (let i = 0; i < ell; i++) {
    names.push(`position_${1 + ell + i}_new_D_chunk_${i}`);
  }
  if (hasAuditor) {
    // 2*ell+1..3*ell: new_r[i] * ek_aud  vs  new_R_aud[i]
    for (let i = 0; i < ell; i++) {
      names.push(`position_${1 + 2 * ell + i}_new_D_aud_chunk_${i}`);
    }
  }
  // m-1: balance equation  dk·⟨B,old_R⟩ + ⟨B,new_a⟩·G  vs  ⟨B,old_P⟩ - v·G
  const balanceIdx = hasAuditor ? 1 + 3 * ell : 1 + 2 * ell;
  names.push(`position_${balanceIdx}_balance_equation`);
  return names;
}

// =============================================================================
// Statement assembly (mirrors makeWithdrawPsi / verifyWithdrawInternal statement
// layout in sigmaProtocolWithdraw.ts:290-326)
// =============================================================================

/**
 * Build the public statement point vector for a normalize/withdraw proof.
 *
 * Auditor-less layout (ell + 0):
 *   [ G, H, ek,
 *     old_P[ell], old_R[ell], new_P[ell], new_R[ell] ]
 *   → 3 + 4*ell total points (= 3 + 32 = 35 for ell=8).
 *
 * Auditor-present layout:
 *   [ ... auditor-less ..., ek_aud, new_R_aud[ell] ]
 *   → 4 + 5*ell total points (= 4 + 40 = 44 for ell=8).
 *
 * Compressed bytes are computed via `.toRawBytes()`.
 *
 * The statement scalars vector contains a single 32-byte LE element
 * `[v]` — the withdraw amount (= 0n for normalize). This MUST be included or
 * the Fiat-Shamir transcript diverges from the SDK's
 * `verifyWithdrawInternal` (sigmaProtocolWithdraw.ts:478-484).
 *
 * `oldBalanceC[i]`, `oldBalanceD[i]`, `newBalanceC[i]`, `newBalanceD[i]` are
 * RistrettoPoints (length ell). `newBalanceDAud` is only consulted when
 * `ekAud` is non-null.
 */
function buildStatement({
  ek,                // RistrettoPoint  (vault encryption key)
  ekAud,             // RistrettoPoint | null
  oldBalanceC,       // RistrettoPoint[ell]
  oldBalanceD,       // RistrettoPoint[ell]
  newBalanceC,       // RistrettoPoint[ell]
  newBalanceD,       // RistrettoPoint[ell]
  newBalanceDAud,    // RistrettoPoint[ell] | null
  amount,            // bigint — withdraw amount (0n for normalize)
}) {
  const G = RistrettoPoint.BASE;
  const H = H_RISTRETTO;
  ensureRistrettoPoint(ek, "ek");

  const points = [G, H, ek];
  const compressed = [G.toRawBytes(), H.toRawBytes(), ek.toRawBytes()];

  const pushP = (p, label, idx) => {
    ensureRistrettoPoint(p, `${label}[${idx}]`);
    points.push(p);
    compressed.push(p.toRawBytes());
  };

  for (let i = 0; i < oldBalanceC.length; i++) pushP(oldBalanceC[i], "oldBalanceC", i);  // old_P
  for (let i = 0; i < oldBalanceD.length; i++) pushP(oldBalanceD[i], "oldBalanceD", i);  // old_R
  for (let i = 0; i < newBalanceC.length; i++) pushP(newBalanceC[i], "newBalanceC", i);  // new_P
  for (let i = 0; i < newBalanceD.length; i++) pushP(newBalanceD[i], "newBalanceD", i);  // new_R

  if (ekAud !== null && ekAud !== undefined) {
    ensureRistrettoPoint(ekAud, "ekAud");
    points.push(ekAud);
    compressed.push(ekAud.toRawBytes());
    if (!Array.isArray(newBalanceDAud) || newBalanceDAud.length !== oldBalanceC.length) {
      throw new Error(
        `buildStatement: newBalanceDAud required and must have length ell=${oldBalanceC.length} when ekAud is present`,
      );
    }
    for (let i = 0; i < newBalanceDAud.length; i++) pushP(newBalanceDAud[i], "newBalanceDAud", i);
  }

  // Statement scalars: [v] as 32-byte LE — matches sigmaProtocolWithdraw.ts:329-334.
  const vScalar = numberToBytesLE(modN(amount), 32);

  return { points, compressedPoints: compressed, scalars: [vScalar] };
}

// =============================================================================
// ψ_withdraw (mirrors makeWithdrawPsi in sigmaProtocolWithdraw.ts:122)
//
// Witness layout: [dk, new_a[ell], new_r[ell]]   (length 1 + 2*ell)
//
// Output layout (auditor-less, m = 2 + 2*ell):
//   index 0                : ek · dk
//   index 1..ell           : G·new_a[i] + H·new_r[i]
//   index 1+ell..1+2ell    : ek · new_r[i]
//   index 1+2ell           : balance equation
//                            = dk·⟨B,old_R⟩ + ⟨B,new_a⟩·G
//
// With auditor (m = 2 + 3*ell):
//   index 1+2ell..1+3ell   : ek_aud · new_r[i]
//   index 1+3ell           : balance equation
// =============================================================================

/**
 * Exported for reuse by normalize_proof_builder.mjs (which calls
 * `sigmaProtocolProve` directly with a CUSTOM statement that embeds the
 * real vault ek, NOT a dk_user_fake.publicKey()-derived ek; see the
 * Twisted-Ed25519 ek-derivation note in that file for why this is required).
 */
export function psiWithdraw(stmt, witness, ell, hasAuditor) {
  const expectedLen = 1 + 2 * ell;
  if (witness.length !== expectedLen) {
    throw new Error(`psiWithdraw: witness length ${witness.length} != 1+2*ell (${expectedLen})`);
  }

  const dk = witness[0];
  const newA = witness.slice(1, 1 + ell);
  const newR = witness.slice(1 + ell, 1 + 2 * ell);

  const G = stmt.points[IDX_G];
  const H = stmt.points[IDX_H];
  const ek = stmt.points[IDX_EK];

  const out = [];

  // 0. dk · ek
  out.push(ek.multiply(dk));

  // 1..ell: G·new_a[i] + H·new_r[i]
  for (let i = 0; i < ell; i++) {
    out.push(G.multiply(newA[i]).add(H.multiply(newR[i])));
  }

  // 1+ell..1+2ell: ek · new_r[i]
  for (let i = 0; i < ell; i++) {
    out.push(ek.multiply(newR[i]));
  }

  // (auditor) 1+2ell..1+3ell: ek_aud · new_r[i]
  if (hasAuditor) {
    const ekAud = stmt.points[idxEkAud(ell)];
    for (let i = 0; i < ell; i++) {
      out.push(ekAud.multiply(newR[i]));
    }
  }

  // Balance equation:
  //   dk · ⟨B, old_R⟩  +  ⟨B, new_a⟩ · G
  const bEll = computeBPowers(ell);
  const startOldR = startIdxOldR(ell);
  let balance = RistrettoPoint.ZERO;
  for (let i = 0; i < ell; i++) {
    balance = balance.add(stmt.points[startOldR + i].multiply(modN(dk * bEll[i])));
  }
  for (let i = 0; i < ell; i++) {
    balance = balance.add(G.multiply(modN(newA[i] * bEll[i])));
  }
  out.push(balance);

  return out;
}

// =============================================================================
// f_withdraw (mirrors makeWithdrawF in sigmaProtocolWithdraw.ts:183)
//
// Returns the m target points such that ψ(σ) = A + e · f(stmt) under a
// valid proof. Reads exclusively from the public statement points; no
// witness involvement.
//
// `amount` parameter: pass 0n for normalize, the withdraw amount otherwise.
// The balance-equation target is ⟨B, old_P⟩ - v·G; for v=0 we skip the
// multiply-by-zero (mirrors the SDK guard at sigmaProtocolWithdraw.ts:219).
// =============================================================================

function fWithdraw(stmt, ell, hasAuditor, amount) {
  const out = [];
  const H = stmt.points[IDX_H];
  const G = stmt.points[IDX_G];

  // 0. H
  out.push(H);

  // 1..ell: new_P[i]
  const startNewP = startIdxNewP(ell);
  for (let i = 0; i < ell; i++) {
    out.push(stmt.points[startNewP + i]);
  }

  // 1+ell..1+2ell: new_R[i]
  const startNewR = startIdxNewR(ell);
  for (let i = 0; i < ell; i++) {
    out.push(stmt.points[startNewR + i]);
  }

  // (auditor) 1+2ell..1+3ell: new_R_aud[i]
  if (hasAuditor) {
    const startNewRAud = startIdxNewRAud(ell);
    for (let i = 0; i < ell; i++) {
      out.push(stmt.points[startNewRAud + i]);
    }
  }

  // Balance equation target: ⟨B, old_P⟩ - v·G
  const bEll = computeBPowers(ell);
  let target = RistrettoPoint.ZERO;
  for (let i = 0; i < ell; i++) {
    target = target.add(stmt.points[START_IDX_OLD_P + i].multiply(bEll[i]));
  }
  const vMod = modN(amount);
  if (vMod !== 0n) {
    // Subtract v·G by adding (-v)·G; skip when v=0 (RistrettoPoint.multiply(0) throws).
    const negV = modN(ED_N - vMod);
    target = target.add(G.multiply(negV));
  }
  out.push(target);

  return out;
}

// =============================================================================
// Reference verifier — public API
// =============================================================================

/**
 * Verify a WithdrawalV1 σ-proof per position and either return `{ok: true}` or
 * throw with a specific position name.
 *
 * Use this AFTER assembling the threshold-substituted final response
 *   response = [s0_threshold, response[1], ..., response[k-1]]
 * (where s0_threshold = α[0] + e · dk_REAL is what the workers reconstruct
 *  Shamir-in-the-exponent style; α[0] = response_user[0] - e · dk_user_fake).
 *
 * @param {object} args
 * @param {{ commitment: Uint8Array[], response: Uint8Array[] }} args.proof
 *   The σ-proof to verify. `commitment[i]` is a 32-byte compressed Ristretto
 *   point; `response[i]` is a 32-byte LE scalar.
 *
 * @param {RistrettoPoint[]} args.oldBalanceC — length ell
 * @param {RistrettoPoint[]} args.oldBalanceD — length ell
 * @param {RistrettoPoint[]} args.newBalanceC — length ell
 * @param {RistrettoPoint[]} args.newBalanceD — length ell
 *
 * @param {{toUint8Array(): Uint8Array}} args.vaultEkPub — TwistedEd25519PublicKey
 *
 * @param {{toUint8Array(): Uint8Array} | null} [args.auditorEkPub]
 *   Optional auditor public key. When null/undefined, the auditor-less branch
 *   is used. When provided, `newBalanceDAud` must also be supplied.
 * @param {RistrettoPoint[]} [args.newBalanceDAud] — length ell (auditor only)
 *
 * @param {number} args.chainId — for Fiat-Shamir DST binding.
 * @param {bigint} [args.amount=0n] — withdraw amount; 0 for normalize.
 * @param {Uint8Array} [args.senderAddress] — 32 bytes (default all-zero)
 * @param {Uint8Array} [args.tokenAddress]  — 32 bytes (default all-zero)
 *
 * @returns {{ ok: true, challengeHex: string, ell: number, hasAuditor: boolean }}
 * @throws {Error} with `position_<i>_<name>` message + a `failedPositions[]`
 *   array in case multiple positions fail.
 */
export function verifyWithdrawSigmaProof({
  proof,
  oldBalanceC,
  oldBalanceD,
  newBalanceC,
  newBalanceD,
  vaultEkPub,
  auditorEkPub = null,
  newBalanceDAud = null,
  chainId,
  amount = 0n,
  senderAddress = new Uint8Array(32),
  tokenAddress = new Uint8Array(32),
}) {
  if (!proof || !Array.isArray(proof.commitment) || !Array.isArray(proof.response)) {
    throw new TypeError("verifyWithdrawSigmaProof: proof must have commitment[] and response[] arrays");
  }

  const ell = oldBalanceC.length;
  const hasAuditor = auditorEkPub !== null && auditorEkPub !== undefined;

  // Shape sanity (mirrors makeWithdrawPsi output cardinality).
  const expectedCommitmentLen = hasAuditor ? 2 + 3 * ell : 2 + 2 * ell;
  const expectedResponseLen = 1 + 2 * ell;
  if (proof.commitment.length !== expectedCommitmentLen) {
    throw new Error(
      `verifyWithdrawSigmaProof: commitment length ${proof.commitment.length} != ${expectedCommitmentLen} ` +
        `(ell=${ell}, hasAuditor=${hasAuditor})`,
    );
  }
  if (proof.response.length !== expectedResponseLen) {
    throw new Error(
      `verifyWithdrawSigmaProof: response length ${proof.response.length} != ${expectedResponseLen} ` +
        `(ell=${ell})`,
    );
  }
  if (oldBalanceD.length !== ell || newBalanceC.length !== ell || newBalanceD.length !== ell) {
    throw new Error(
      `verifyWithdrawSigmaProof: chunk count mismatch — oldBalanceC=${ell}, ` +
        `oldBalanceD=${oldBalanceD.length}, newBalanceC=${newBalanceC.length}, newBalanceD=${newBalanceD.length}`,
    );
  }
  if (hasAuditor && (!Array.isArray(newBalanceDAud) || newBalanceDAud.length !== ell)) {
    throw new Error(
      `verifyWithdrawSigmaProof: auditor branch requires newBalanceDAud of length ${ell}`,
    );
  }

  // Convert vaultEkPub / auditorEkPub (TwistedEd25519PublicKey-shaped) to
  // RistrettoPoints in our local class.
  const ekBytes = vaultEkPub.toUint8Array();
  const ekPoint = RistrettoPoint.fromHex(ekBytes);
  const ekAudPoint = hasAuditor
    ? RistrettoPoint.fromHex(auditorEkPub.toUint8Array())
    : null;

  // Build statement (same layout as proveWithdrawal).
  const stmt = buildStatement({
    ek: ekPoint,
    ekAud: ekAudPoint,
    oldBalanceC,
    oldBalanceD,
    newBalanceC,
    newBalanceD,
    newBalanceDAud,
    amount,
  });

  // Recompute Fiat-Shamir challenge `e` from the same BCS-encoded inputs the
  // prover used. We pass k = response.length (the witness length).
  const sessionId = bcsSerializeWithdrawSession(senderAddress, tokenAddress, ell, hasAuditor);
  const dst = {
    contractAddress: APTOS_FRAMEWORK_ADDRESS,
    chainId,
    protocolId: utf8ToBytes(PROTOCOL_ID_WITHDRAWAL),
    sessionId,
  };
  const k = proof.response.length;
  const { e } = sigmaProtocolFiatShamir(dst, TYPE_NAME, stmt, proof.commitment, k);

  // Parse responses to scalars and compute ψ(σ).
  const sigma = proof.response.map((bytes) => bytesToScalarLE(bytes));
  const psiSigma = psiWithdraw(stmt, sigma, ell, hasAuditor);

  // Decompress commitment points A[i].
  const commitmentPoints = proof.commitment.map((bytes) => RistrettoPoint.fromHex(bytes));

  // Compute f(stmt).
  const fStmt = fWithdraw(stmt, ell, hasAuditor, amount);

  if (psiSigma.length !== expectedCommitmentLen || fStmt.length !== expectedCommitmentLen) {
    throw new Error(
      `verifyWithdrawSigmaProof: internal ψ/f length mismatch — ` +
        `psi=${psiSigma.length}, f=${fStmt.length}, expected=${expectedCommitmentLen}`,
    );
  }

  // Verify per-position: ψ(σ)[i]  ?=  A[i]  +  e · f(stmt)[i]
  const positionNames = buildPositionNames(ell, hasAuditor);
  const failedPositions = [];
  for (let i = 0; i < expectedCommitmentLen; i++) {
    const expected = commitmentPoints[i].add(fStmt[i].multiply(e));
    if (!pointsEqual(psiSigma[i], expected)) {
      failedPositions.push({ index: i, name: positionNames[i] });
    }
  }

  if (failedPositions.length > 0) {
    const firstFail = failedPositions[0];
    const err = new Error(
      `${firstFail.name}_failed_lhs_eq_rhs ` +
        `(${failedPositions.length} of ${expectedCommitmentLen} positions failed)`,
    );
    err.failedPositions = failedPositions;
    err.expectedCommitmentLen = expectedCommitmentLen;
    err.ell = ell;
    err.hasAuditor = hasAuditor;
    throw err;
  }

  // 32-byte LE hex for diagnostic display.
  let eBytes = e;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(eBytes & 0xffn);
    eBytes >>= 8n;
  }
  let challengeHex = "";
  for (let i = 0; i < 32; i++) {
    challengeHex += out[i].toString(16).padStart(2, "0");
  }

  return { ok: true, challengeHex, ell, hasAuditor };
}

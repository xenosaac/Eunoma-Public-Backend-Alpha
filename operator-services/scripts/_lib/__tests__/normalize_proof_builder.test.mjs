// operator-services/scripts/_lib/__tests__/normalize_proof_builder.test.mjs
//
// Test the WithdrawalV1 σ-proof port (used by `normalize_raw`) with the
// fake-dk + threshold-s[0]-substitute trick.
//
// Run with Node's built-in test runner (NOT vitest):
//
//   cd backend-deoperator-research && \
//     node --test operator-services/scripts/_lib/__tests__/normalize_proof_builder.test.mjs
//
// What this proves:
//   1. The builder produces 6 well-formed Move payload pieces + the α[0] /
//      Fiat-Shamir-challenge tuple for the coordinator.
//   2. When we simulate the threshold substitution single-party
//      (s0_threshold = α[0] + e · dk_REAL_scalar), the reassembled proof
//      verifies under the JS reference verifier in
//      operator-services/scripts/_lib/withdraw_sigma_reference.mjs.
//
// This is the regression-guard. If Test 2 passes, the σ port is byte-identical
// to what a vanilla `proveNormalization({dk: dk_REAL, ...})` would produce
// (after substituting s[0]) — and therefore what the Move `normalize_raw`
// verifier expects.

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import {
  RistrettoPoint,
  TwistedEd25519PrivateKey,
  TwistedElGamal,
  AVAILABLE_BALANCE_CHUNK_COUNT as ELL,
  verifyWithdrawal,
} from "@aptos-labs/confidential-asset";
import { ed25519 } from "@noble/curves/ed25519";
import { mod } from "@noble/curves/abstract/modular";

import { buildNormalizeProofBundle } from "../normalize_proof_builder.mjs";
import { verifyWithdrawSigmaProof } from "../withdraw_sigma_reference.mjs";

const ED_N = ed25519.CURVE.n;
const CHAIN_ID = 2; // Aptos testnet chain id (matches sigma_position_17_parity tests)

// =============================================================================
// Helpers
// =============================================================================

function modN(x) {
  return mod(x, ED_N);
}

function randScalar() {
  while (true) {
    const buf = randomBytes(32);
    buf[31] &= 0x7f;
    let v = 0n;
    for (let i = 31; i >= 0; i--) v = (v << 8n) | BigInt(buf[i]);
    if (v < ED_N && v !== 0n) return v;
  }
}

function bytesToScalarLE(bytes) {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) v = (v << 8n) | BigInt(bytes[i]);
  return modN(v);
}

function scalarToBytesLE32(s) {
  const v = modN(s);
  const out = new Uint8Array(32);
  let x = v;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function rawBigintToBytesLE32(v) {
  if (v < 0n || v >= (1n << 256n)) {
    throw new RangeError("rawBigintToBytesLE32: value out of 32-byte range");
  }
  const out = new Uint8Array(32);
  let x = v;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

/**
 * Synthesize a fake chain "available_balance" ciphertext by encrypting a
 * known plaintext chunk vector under a known dk_REAL. Returns the input chunks
 * plus the per-chunk {C, D} pair as decompressed RistrettoPoints.
 *
 * The chunks here are intentionally chosen so that they ARE already in normal
 * form (each < 2^16) — the test isn't exercising un-normalization, just the
 * σ-proof port. Re-chunking is the orchestrator's responsibility.
 */
function synthesizeChainBalance(dkReal, chunks) {
  const ekReal = dkReal.publicKey();
  const randomness = Array.from({ length: chunks.length }, () => randScalar());
  const cts = chunks.map((m, i) => TwistedElGamal.encryptWithPK(m, ekReal, randomness[i]));
  // TwistedElGamalCiphertext.C / .D are decompressed RistrettoPoint instances
  // (twistedElGamal.ts:194-197 constructor).
  return {
    oldBalanceC: cts.map((ct) => ct.C),
    oldBalanceD: cts.map((ct) => ct.D),
    ekReal,
    randomness,
  };
}

function assembleThresholdProof({ dkReal, bundle }) {
  const dkRealScalar = modN(bytesToScalarLE(dkReal.toUint8Array()));
  const alphaZero = bytesToScalarLE(bundle.sigmaRespS0NeedsThreshold.alphaZero);
  const e = bytesToScalarLE(bundle.sigmaRespS0NeedsThreshold.fiatShamirChallenge);
  const s0Threshold = modN(alphaZero + modN(e * dkRealScalar));
  const response = [
    scalarToBytesLE32(s0Threshold),
    ...bundle.sigmaRespS0NeedsThreshold.responseTail,
  ];
  assert.equal(response.length, 1 + 2 * ELL, "final response length sanity");
  return {
    commitment: bundle.sigmaCommHex,
    response,
  };
}

function bundlePoints(bundle) {
  return {
    newBalanceC: bundle.newBalanceP.map((bytes) => RistrettoPoint.fromHex(bytes)),
    newBalanceD: bundle.newBalanceR.map((bytes) => RistrettoPoint.fromHex(bytes)),
    newBalanceDAud:
      bundle.newBalanceRAud.length > 0
        ? bundle.newBalanceRAud.map((bytes) => RistrettoPoint.fromHex(bytes))
        : null,
  };
}

function verifyReferenceAndSdk({
  proof,
  oldBalanceC,
  oldBalanceD,
  newBalanceC,
  newBalanceD,
  newBalanceDAud = null,
  vaultEkPub,
  auditorEkPub = null,
  senderAddress = new Uint8Array(32),
  tokenAddress = new Uint8Array(32),
}) {
  const refResult = verifyWithdrawSigmaProof({
    proof,
    oldBalanceC,
    oldBalanceD,
    newBalanceC,
    newBalanceD,
    vaultEkPub,
    auditorEkPub,
    newBalanceDAud,
    chainId: CHAIN_ID,
    amount: 0n,
    senderAddress,
    tokenAddress,
  });
  assert.deepEqual(refResult.ok, true, "reference verifier must return {ok: true}");

  const sdkArgs = {
    senderAddress,
    tokenAddress,
    chainId: CHAIN_ID,
    amount: 0n,
    ekBytes: vaultEkPub.toUint8Array(),
    oldBalanceC,
    oldBalanceD,
    newBalanceC,
    newBalanceD,
    proof,
  };
  if (auditorEkPub !== null) {
    sdkArgs.auditorEkBytes = auditorEkPub.toUint8Array();
    sdkArgs.newBalanceDAud = newBalanceDAud;
  }
  assert.equal(verifyWithdrawal(sdkArgs), true, "SDK verifyWithdrawal must accept");

  return refResult;
}

// =============================================================================
// Test 1: builder produces well-formed output (auditor-less)
// =============================================================================

test("buildNormalizeProofBundle: produces well-formed 6-vector output (no auditor)", async () => {
  // A modest balance: chunk0 = 5888, chunk1 = 10681 (matches the test plan's
  // re-chunked example), trailing six chunks zero. Total amount fits in
  // 2 × 16-bit chunks, the other six pad with zero.
  const knownChunks = new Array(ELL).fill(0n);
  knownChunks[0] = 5888n;
  knownChunks[1] = 10681n;

  // dk_REAL belongs only to the test harness; in production it is sharded.
  const dkReal = TwistedEd25519PrivateKey.generate();
  const { oldBalanceC, oldBalanceD } = synthesizeChainBalance(dkReal, knownChunks);

  // newBalanceChunks: in a real normalize they are the SAME plaintext just
  // potentially re-chunked into 16-bit pieces. For this test the chain
  // ciphertext is already 16-bit-clean so the new chunks equal the old chunks.
  const newBalanceChunks = knownChunks.slice();

  const bundle = await buildNormalizeProofBundle({
    oldBalanceC,
    oldBalanceD,
    newBalanceChunks,
    vaultEkPub: dkReal.publicKey(),
    auditorEkPub: null,
    senderAddress: new Uint8Array(32),
    tokenAddress: new Uint8Array(32),
    chainId: CHAIN_ID,
  });

  // Shape checks.
  assert.equal(bundle.newBalanceP.length, ELL, "newBalanceP must have ell chunks");
  assert.equal(bundle.newBalanceR.length, ELL, "newBalanceR must have ell chunks");
  for (let i = 0; i < ELL; i++) {
    assert.ok(bundle.newBalanceP[i] instanceof Uint8Array, `newBalanceP[${i}] is Uint8Array`);
    assert.equal(bundle.newBalanceP[i].length, 32, `newBalanceP[${i}] is 32 bytes`);
    assert.ok(bundle.newBalanceR[i] instanceof Uint8Array, `newBalanceR[${i}] is Uint8Array`);
    assert.equal(bundle.newBalanceR[i].length, 32, `newBalanceR[${i}] is 32 bytes`);
  }

  // No auditor → newBalanceRAud must be length 0 (per task spec).
  assert.equal(bundle.newBalanceRAud.length, 0, "no-auditor branch leaves newBalanceRAud empty");

  // Bulletproof blob is non-empty.
  assert.ok(bundle.zkrpNewBalance instanceof Uint8Array, "zkrpNewBalance is Uint8Array");
  assert.ok(bundle.zkrpNewBalance.length > 0, "zkrpNewBalance is non-empty");

  // σ-proof shapes: commitment = 2+2*ell = 18, response (tail) = 2*ell = 16
  // (since the full response has length 1+2*ell = 17 and we strip [0]).
  assert.equal(bundle.sigmaCommHex.length, 2 + 2 * ELL, `sigmaCommHex length = ${2 + 2 * ELL}`);
  for (let i = 0; i < bundle.sigmaCommHex.length; i++) {
    assert.equal(bundle.sigmaCommHex[i].length, 32, `sigmaCommHex[${i}] is 32 bytes`);
  }
  assert.equal(
    bundle.sigmaRespS0NeedsThreshold.responseTail.length,
    2 * ELL,
    `responseTail length = ${2 * ELL}`,
  );
  for (let i = 0; i < 2 * ELL; i++) {
    assert.equal(
      bundle.sigmaRespS0NeedsThreshold.responseTail[i].length,
      32,
      `responseTail[${i}] is 32 bytes`,
    );
  }

  // α[0] and e are 32-byte LE scalars.
  assert.ok(
    bundle.sigmaRespS0NeedsThreshold.alphaZero instanceof Uint8Array,
    "alphaZero is Uint8Array",
  );
  assert.equal(bundle.sigmaRespS0NeedsThreshold.alphaZero.length, 32, "alphaZero is 32 bytes");
  assert.ok(
    bundle.sigmaRespS0NeedsThreshold.fiatShamirChallenge instanceof Uint8Array,
    "fiatShamirChallenge is Uint8Array",
  );
  assert.equal(
    bundle.sigmaRespS0NeedsThreshold.fiatShamirChallenge.length,
    32,
    "fiatShamirChallenge is 32 bytes",
  );

  // sessionBcs is a non-empty buffer (BCS-encoded WithdrawSession).
  assert.ok(
    bundle.sigmaRespS0NeedsThreshold.sessionBcs instanceof Uint8Array,
    "sessionBcs is Uint8Array",
  );
  assert.ok(bundle.sigmaRespS0NeedsThreshold.sessionBcs.length > 0, "sessionBcs is non-empty");
});

// =============================================================================
// Test 2: round-trip with simulated single-party threshold substitution
// =============================================================================

test("verifyWithdrawSigmaProof: round-trip after simulated s0 substitution (no auditor)", async () => {
  // Same setup as Test 1, but here we ALSO compute s0_threshold ourselves and
  // run the reference verifier on the reassembled proof. This proves that the
  // fake-dk extraction + Shamir-in-the-exponent substitution math is correct:
  // the σ-verifier accepts a proof where response[0] came from a *different*
  // dk than the one the prover passed to proveWithdrawal, as long as we
  // re-derive the substitution scalar against the SAME e and dk_REAL.
  const knownChunks = new Array(ELL).fill(0n);
  knownChunks[0] = 5888n;
  knownChunks[1] = 10681n;
  knownChunks[2] = 7n; // a non-trivial third chunk to catch off-by-one indexing

  const dkReal = TwistedEd25519PrivateKey.generate();
  const { oldBalanceC, oldBalanceD, ekReal } = synthesizeChainBalance(dkReal, knownChunks);

  // newBalanceChunks: same plaintext re-encrypted with fresh randomness.
  const newBalanceChunks = knownChunks.slice();

  const bundle = await buildNormalizeProofBundle({
    oldBalanceC,
    oldBalanceD,
    newBalanceChunks,
    vaultEkPub: ekReal,
    auditorEkPub: null,
    senderAddress: new Uint8Array(32),
    tokenAddress: new Uint8Array(32),
    chainId: CHAIN_ID,
  });

  const proof = assembleThresholdProof({ dkReal, bundle });

  // Re-derive newBalanceC/D points from the encoded bytes (the verifier needs
  // RistrettoPoints in its own class — see the dual-package-hazard note in
  // withdraw_sigma_reference.mjs).
  const { newBalanceC, newBalanceD } = bundlePoints(bundle);

  const result = verifyReferenceAndSdk({
    proof,
    oldBalanceC,
    oldBalanceD,
    newBalanceC,
    newBalanceD,
    vaultEkPub: ekReal,
  });

  assert.equal(result.ell, ELL, "verifier reports ell");
  assert.equal(result.hasAuditor, false, "verifier reports no auditor");
  assert.equal(result.challengeHex.length, 64, "challengeHex is 32 LE bytes hex-encoded");
});

test("verifyWithdrawal: round-trip after simulated s0 substitution (auditor present)", async () => {
  const knownChunks = new Array(ELL).fill(0n);
  knownChunks[0] = 1n;
  knownChunks[1] = 2n;
  knownChunks[2] = 3n;
  knownChunks[3] = 4n;

  const dkReal = TwistedEd25519PrivateKey.generate();
  const { oldBalanceC, oldBalanceD, ekReal } = synthesizeChainBalance(dkReal, knownChunks);
  const auditorEk = TwistedEd25519PrivateKey.generate().publicKey();

  const bundle = await buildNormalizeProofBundle({
    oldBalanceC,
    oldBalanceD,
    newBalanceChunks: knownChunks.slice(),
    vaultEkPub: ekReal,
    auditorEkPub: auditorEk,
    senderAddress: new Uint8Array(32),
    tokenAddress: new Uint8Array(32),
    chainId: CHAIN_ID,
  });

  assert.equal(bundle.newBalanceRAud.length, ELL, "auditor branch emits ell auditor D points");
  assert.equal(bundle.sigmaCommHex.length, 2 + 3 * ELL, "auditor commitment length");

  const proof = assembleThresholdProof({ dkReal, bundle });
  const { newBalanceC, newBalanceD, newBalanceDAud } = bundlePoints(bundle);
  const result = verifyReferenceAndSdk({
    proof,
    oldBalanceC,
    oldBalanceD,
    newBalanceC,
    newBalanceD,
    newBalanceDAud,
    vaultEkPub: ekReal,
    auditorEkPub: auditorEk,
  });

  assert.equal(result.ell, ELL, "verifier reports ell");
  assert.equal(result.hasAuditor, true, "verifier reports auditor present");
});

test("buildNormalizeProofBundle: fake dk seed scalar-order boundary sanity", async () => {
  const knownChunks = new Array(ELL).fill(0n);
  knownChunks[0] = 42n;
  knownChunks[1] = 9n;

  const dkReal = TwistedEd25519PrivateKey.generate();
  const { oldBalanceC, oldBalanceD, ekReal } = synthesizeChainBalance(dkReal, knownChunks);
  const boundarySeeds = [
    ED_N - 100n,
    ED_N - 1n,
    ED_N,
    ED_N + 1n,
    ED_N + 100n,
  ];

  for (const seedScalar of boundarySeeds) {
    const bundle = await buildNormalizeProofBundle({
      oldBalanceC,
      oldBalanceD,
      newBalanceChunks: knownChunks.slice(),
      vaultEkPub: ekReal,
      auditorEkPub: null,
      senderAddress: new Uint8Array(32),
      tokenAddress: new Uint8Array(32),
      chainId: CHAIN_ID,
      dkUserFakeSeed: rawBigintToBytesLE32(seedScalar),
    });
    const proof = assembleThresholdProof({ dkReal, bundle });
    const { newBalanceC, newBalanceD } = bundlePoints(bundle);
    const result = verifyReferenceAndSdk({
      proof,
      oldBalanceC,
      oldBalanceD,
      newBalanceC,
      newBalanceD,
      vaultEkPub: ekReal,
    });
    assert.equal(result.hasAuditor, false, `boundary seed ${seedScalar} remains auditor-less`);
  }
});

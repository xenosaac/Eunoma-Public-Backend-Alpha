// circuits/scripts/__tests__/recover_balance_chunks.test.mjs
//
// M10-d Step d.2 — unit tests for `recoverBalanceChunks`. Run via:
//
//     cd circuits && node --test scripts/__tests__/recover_balance_chunks.test.mjs
//
// The five tests cover:
//   1. Degenerate 1-slot quorum (lambda=[1], partial=dk*D) at 100 octas.
//   2. 5-of-7 quorum at 828 octas (matches plan M10-d "happy path" scale,
//      equal to 8 cumulative testnet deposits of 100..107).
//   3. Forged partial -> BSGS decode returns null -> function throws.
//   4. chunkBits=16 with a mixed-chunk balance vector.
//   5. Max chunk value 2^chunkBits - 1 (boundary of the BSGS search range).
//
// Cross-references:
//   * M10-a sigma_reference_verifier.mjs (curve pattern mirror)
//   * M10-c balance_decrypt route (Shamir + Lagrange convention)
//   * SDK Twisted ElGamal:
//     operator-services/node_modules/@aptos-labs/confidential-asset/src/crypto/twistedElGamal.ts

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import { RistrettoPoint, ed25519 } from "@noble/curves/ed25519";

import { recoverBalanceChunks, bsgsDecodeChunk } from "../recover_balance_chunks.mjs";

const G = RistrettoPoint.BASE;
const Q = ed25519.CURVE.n;

function modQ(x) {
  let v = x % Q;
  if (v < 0n) v += Q;
  return v;
}

function randScalar() {
  while (true) {
    const buf = randomBytes(32);
    buf[31] &= 0x7f;
    let v = 0n;
    for (let i = 31; i >= 0; i--) v = (v << 8n) | BigInt(buf[i]);
    if (v < Q && v !== 0n) return v;
  }
}

/**
 * Safe scalar-multiply that handles m=0 (which `noble` rejects with
 * "invalid scalar: expected 1 <= sc < curve.n"). Matches the SDK pattern
 * (`m === 0n ? RistrettoPoint.ZERO : base.multiply(m)` at twistedElGamal.ts:74).
 */
function safeMul(point, scalar) {
  if (scalar === 0n) return RistrettoPoint.ZERO;
  return point.multiply(scalar);
}

/**
 * Multiplicative-inverse mod Q via the extended Euclidean algorithm.
 * Q is prime, so any non-zero x has an inverse.
 */
function modInverse(x, m) {
  let [a, b, u, v] = [modQ(x), m, 1n, 0n];
  while (a !== 0n) {
    const t = b / a;
    [a, b] = [b - t * a, a];
    [u, v] = [v - t * u, u];
  }
  if (b !== 1n) throw new Error(`no inverse for ${x}`);
  return modQ(v);
}

/**
 * Lagrange coefficients at x=0 for the set { x_j = slots[j] + 1 } over the
 * Ed25519 scalar field. Mirrors `lagrangeCoefficientsAtZero` in
 * operator-services/deop-protocol/src/vault_ek_derivation.ts:413; we
 * re-derive it here so the circuits-side test stays decoupled from the
 * operator-services workspace build.
 */
function lagrangeAtZero(slots) {
  const xs = slots.map((s) => BigInt(s + 1));
  const out = [];
  for (let i = 0; i < xs.length; i++) {
    let num = 1n;
    let den = 1n;
    for (let j = 0; j < xs.length; j++) {
      if (j === i) continue;
      num = modQ(num * modQ(-xs[j]));
      den = modQ(den * modQ(xs[i] - xs[j]));
    }
    out.push(modQ(num * modInverse(den, Q)));
  }
  return out;
}

/**
 * Encrypt a length-ell chunk vector. We maintain the invariant required by
 * `recoverBalanceChunks`:
 *     oldBalanceC[k] - dk * oldBalanceD[k]  ==  m_k * G
 *
 * Concretely we set
 *     C[k] = m_k * G  +  r_k * (dk * G)         (= m_k*G + r_k*ek_proxy)
 *     D[k] = r_k * G                            (proxy form — see note)
 *
 * The SDK's actual Twisted ElGamal layout (twistedElGamal.ts:64-80) is
 *     pk = sk^-1 * H_RISTRETTO,
 *     C  = m * G  +  r * H_RISTRETTO,
 *     D  = r * pk = r * sk^-1 * H_RISTRETTO,
 * which decrypts via sk * D = r * H_RISTRETTO, yielding C - sk*D = m * G.
 *
 * The proxy form used here is algebraically simpler and exercises the
 * SAME invariant `recoverBalanceChunks` consumes. The orchestrator never
 * sees raw H_RISTRETTO — it only sees C and D as opaque chain points.
 */
function encryptChunks(chunks, dk, randomness) {
  const ek = G.multiply(dk); // proxy "ek" = sk*G
  return chunks.map((m, k) => {
    const r = randomness[k];
    const C = safeMul(G, m).add(ek.multiply(r)); // m*G + r*(sk*G) = (m + r*sk)*G
    const D = G.multiply(r); // r*G — so sk*D = r*sk*G = r*ek, satisfies the invariant
    return { C, D };
  });
}

// =============================================================================
// Test 1 - degenerate 1-slot quorum
// =============================================================================
test("recovers 100-octa balance with 1-slot quorum (degenerate)", () => {
  const dk = randScalar();
  const balanceChunks = [100n, 0n, 0n, 0n, 0n, 0n, 0n, 0n];
  const randomness = Array.from({ length: 8 }, () => randScalar());
  const ct = encryptChunks(balanceChunks, dk, randomness);
  const oldBalanceC = ct.map((x) => x.C);
  const oldBalanceD = ct.map((x) => x.D);

  // Degenerate 1-slot quorum: partial = dk * D, lagrange = [1].
  const partials = oldBalanceD.map((D) => D.multiply(dk));
  const partialsFromSlots = [{ slot: 0, partials }];
  const lagrangeCoeffs = [1n];

  const { chunks } = recoverBalanceChunks({
    oldBalanceC,
    oldBalanceD,
    partialsFromSlots,
    lagrangeCoeffs,
    chunkBits: 16,
  });
  assert.deepEqual(chunks, balanceChunks);
});

// =============================================================================
// Test 2 - 5-of-7 quorum (production scale)
// =============================================================================
test("recovers 828-octa balance with 5-of-7 quorum", () => {
  // Total = 100+101+...+107 = 828 (M10-d plan smoke-test scale).
  const total = 100n + 101n + 102n + 103n + 104n + 105n + 106n + 107n;
  assert.equal(total, 828n);
  const balanceChunks = [total, 0n, 0n, 0n, 0n, 0n, 0n, 0n];

  // Synthesize a Shamir polynomial f(x) of degree 4 (threshold-5) with secret
  // dk = f(0). Evaluate at x_i = slot_i + 1 for slots 0..6.
  const dk = randScalar();
  const coeffs = [dk, randScalar(), randScalar(), randScalar(), randScalar()];
  function evalPoly(x) {
    let acc = 0n;
    for (let i = coeffs.length - 1; i >= 0; i--) {
      acc = modQ(acc * x + coeffs[i]);
    }
    return acc;
  }
  const allSlots = [0, 1, 2, 3, 4, 5, 6];
  const allShares = allSlots.map((slot) => ({ slot, dkShare: evalPoly(BigInt(slot + 1)) }));
  // Pick the lowest 5 slots (matches M10-c lowestEligibleSlots(_, 5) selector).
  const selected = allShares.slice(0, 5);
  const selectedSlots = selected.map((s) => s.slot);
  const lagrangeCoeffs = lagrangeAtZero(selectedSlots);

  // Sanity: sum_i lambda_i * dkShare_i == dk (mod Q).
  const reconstructed = selected.reduce(
    (acc, s, i) => modQ(acc + s.dkShare * lagrangeCoeffs[i]),
    0n,
  );
  assert.equal(reconstructed, dk, "Lagrange-Shamir self-check failed");

  // Encrypt under the same dk.
  const randomness = Array.from({ length: 8 }, () => randScalar());
  const ct = encryptChunks(balanceChunks, dk, randomness);
  const oldBalanceC = ct.map((x) => x.C);
  const oldBalanceD = ct.map((x) => x.D);

  // Each worker contributes dk_share_i * D[k].
  const partialsFromSlots = selected.map((s) => ({
    slot: s.slot,
    partials: oldBalanceD.map((D) => D.multiply(s.dkShare)),
  }));

  const { chunks } = recoverBalanceChunks({
    oldBalanceC,
    oldBalanceD,
    partialsFromSlots,
    lagrangeCoeffs,
    chunkBits: 16,
  });
  assert.deepEqual(chunks, balanceChunks);
});

// =============================================================================
// Test 3 - forged partial fails BSGS
// =============================================================================
test("rejects negative result (forged partial)", () => {
  const dk = randScalar();
  const balanceChunks = [100n, 0n, 0n, 0n, 0n, 0n, 0n, 0n];
  const randomness = Array.from({ length: 8 }, () => randScalar());
  const ct = encryptChunks(balanceChunks, dk, randomness);
  const oldBalanceC = ct.map((x) => x.C);
  const oldBalanceD = ct.map((x) => x.D);

  // Wrong dk -> partial = wrong_dk * D != real_dk * D. The aggregated point
  // subtracted from C[k] will leave a random group element that, with
  // overwhelming probability, is NOT in {0*G, 1*G, ..., (2^16-1)*G}.
  const wrongDk = modQ(dk + 1n);
  const partials = oldBalanceD.map((D) => D.multiply(wrongDk));
  const partialsFromSlots = [{ slot: 0, partials }];
  const lagrangeCoeffs = [1n];

  assert.throws(
    () =>
      recoverBalanceChunks({
        oldBalanceC,
        oldBalanceD,
        partialsFromSlots,
        lagrangeCoeffs,
        chunkBits: 16,
      }),
    /bsgs_decode_failed_at_chunk_\d+/,
  );
});

// =============================================================================
// Test 4 - chunkBits=16 explicit (mixed-chunk balance)
// =============================================================================
test("handles chunkBits=16", () => {
  // Non-trivial chunk vector exercising every chunk position; each chunk
  // fits in [0, 2^16).
  const balanceChunks = [12345n, 65535n, 0n, 1n, 32768n, 4n, 9999n, 256n];
  const dk = randScalar();
  const randomness = Array.from({ length: 8 }, () => randScalar());
  const ct = encryptChunks(balanceChunks, dk, randomness);
  const oldBalanceC = ct.map((x) => x.C);
  const oldBalanceD = ct.map((x) => x.D);

  const partials = oldBalanceD.map((D) => D.multiply(dk));
  const partialsFromSlots = [{ slot: 0, partials }];
  const lagrangeCoeffs = [1n];

  const { chunks } = recoverBalanceChunks({
    oldBalanceC,
    oldBalanceD,
    partialsFromSlots,
    lagrangeCoeffs,
    chunkBits: 16,
  });
  assert.deepEqual(chunks, balanceChunks);
});

// =============================================================================
// Test 5 - BSGS decode for max chunk value
// =============================================================================
test("BSGS decodes max chunk value 2^chunkBits - 1", () => {
  // Direct BSGS exercise: validate the boundary case at the high end of
  // [0, 2^chunkBits) for several chunk widths.
  for (const chunkBits of [8, 12, 16]) {
    const maxVal = (1n << BigInt(chunkBits)) - 1n;
    const target = G.multiply(maxVal);
    const recovered = bsgsDecodeChunk(target, chunkBits);
    assert.equal(
      recovered,
      maxVal,
      `chunkBits=${chunkBits}: expected ${maxVal}, got ${recovered}`,
    );
  }
  // Out-of-range: BSGS for chunkBits=8 on m=2^8 should return null.
  const overshoot = G.multiply(256n);
  const r = bsgsDecodeChunk(overshoot, 8);
  assert.equal(r, null, `chunkBits=8 on m=256 should be out-of-range, got ${r}`);
});

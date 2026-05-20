// circuits/scripts/recover_balance_chunks.mjs
//
// M10-d: pure-JS reconstruction of the chain-encrypted available-balance from
// Lagrange-aggregated worker partial decryption shares, plus BSGS decoding of
// each chunk's plaintext integer.
//
// Pipeline this enables (in operator-services/scripts/local_v2_withdraw_full.mjs):
//
//     for each chunk k:
//         aggregated[k] = sum_i  lambda_i * partials_i[k]              (group ops)
//                       ==  real_dk * oldBalanceD[k]                   (Shamir)
//         balancePoint[k] = oldBalanceC[k] - aggregated[k]
//                       ==  m_k * G                                    (Twisted ElGamal)
//         m_k             = BSGS_decode(balancePoint[k], chunkBits)
//
// where `lambda_i` are the Lagrange coefficients at x=0 over the selected 5-of-7
// quorum (computed coordinator-side in M10-c via `lagrangeCoefficientsAtZero`
// in `@eunoma/deop-protocol`). The resulting `m_k` chunks are then fed to the
// orchestrator's `chunkSubtract(balance_chunks, transfer_chunks)` to derive
// the TRUTHFUL `newAmountChunks` witness for the sigma-protocol — which makes
// position 17 verify (the M9-blocker root cause; see plan M10-a/M10-d).
//
// =============================================================================
// DUAL-PACKAGE HAZARD MITIGATION
// =============================================================================
//
// `@noble/curves/ed25519` ships its own `RistrettoPoint` *class*. When two
// callers (orchestrator + this file) resolve `@noble/curves` from different
// node_modules trees (operator-services/node_modules vs circuits/node_modules),
// they get *different* class objects despite identical wire types. Calling
// `pointA.add(pointB)` cross-class throws "RistrettoPoint expected" at
// edwards.js:380 (assertSame).
//
// This file therefore NEVER imports `RistrettoPoint` at module scope. Instead
// it derives the point class from the inputs' constructors, looking up
// `.ZERO`, `.BASE`, and (via `point.constructor === otherPoint.constructor`)
// using the input points' own class for all group ops. This makes the
// orchestrator + circuits-test paths interop-clean.
//
// Cross-references (all M10-d cousins):
//   * M10-a JS reference verifier:       operator-services/scripts/sigma_reference_verifier.mjs
//   * M10-a chunk subtract / pad:        operator-services/scripts/_lib/chunk_arithmetic.mjs
//   * M10-b worker partial decrypt:      operator-services/crypto-worker-rust/src/balance_decrypt.rs
//   * M10-c coordinator quorum + lambda: operator-services/coordinator/src/routes/balance_decrypt.ts
//   * SDK Twisted ElGamal:               operator-services/node_modules/@aptos-labs/
//                                          confidential-asset/src/crypto/twistedElGamal.ts

// Ed25519 scalar field order ell = 2^252 + 27742317777372353535851937790883648493.
// Same constant as `ed25519.CURVE.n` used in M10-a's sigma_reference_verifier.mjs.
const ED25519_SCALAR_Q =
  7237005577332262213973186563042994240857116359379907606001950938285454250989n;

function modN(x) {
  let v = x % ED25519_SCALAR_Q;
  if (v < 0n) v += ED25519_SCALAR_Q;
  return v;
}

/**
 * Mirror the M10-a sigma_reference_verifier.mjs convention: a compressed
 * Ristretto encoding rendered as a 64-char lowercase-hex string. Used as the
 * key in the BSGS baby-step lookup table.
 */
function compressedHex(point) {
  const bytes = point.toRawBytes();
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    s += bytes[i].toString(16).padStart(2, "0");
  }
  return s;
}

/**
 * Validate that a value looks like a `RistrettoPoint` (any version). We
 * deliberately don't `instanceof` against an imported class — see the dual-
 * package hazard note above — so we duck-type the few methods we use.
 */
function assertPointShape(p, label) {
  if (
    p === null ||
    typeof p !== "object" ||
    typeof p.add !== "function" ||
    typeof p.subtract !== "function" ||
    typeof p.multiply !== "function" ||
    typeof p.toRawBytes !== "function"
  ) {
    throw new TypeError(`${label}: not a RistrettoPoint (missing add/subtract/multiply/toRawBytes)`);
  }
  return p;
}

/**
 * Recover plaintext balance chunks from chain-encrypted balance using
 * Lagrange-aggregated worker partial decryption shares.
 *
 * @param {object} args
 * @param {RistrettoPoint[]} args.oldBalanceC
 *   Length-ell vector of chain `available_balance.C` (Twisted ElGamal C = m_k*G + r_k*H).
 * @param {RistrettoPoint[]} args.oldBalanceD
 *   Length-ell vector of chain `available_balance.D` (Twisted ElGamal D = r_k * pk_inv).
 * @param {{slot: number, partials: RistrettoPoint[]}[]} args.partialsFromSlots
 *   One entry per quorum member. `partials[k]` = dk_share_i * oldBalanceD[k].
 *   Same order as `lagrangeCoeffs`.
 * @param {bigint[]} args.lagrangeCoeffs
 *   Lagrange coefficients lambda_i(0), in the SAME order as `partialsFromSlots`.
 *   Caller is responsible for parsing the coordinator's LE-hex encoding into
 *   bigints — see M10-c's `scalarHexFromBigint`.
 * @param {number} args.chunkBits — chunk width in bits (16 in @aptos-labs/confidential-asset).
 *
 * @returns {{ chunks: bigint[] }} — Length-ell vector of plaintext chunks, each in [0, 2^chunkBits).
 *
 * Throws:
 *   - "quorum/lagrange mismatch"          : partials.length !== lagrangeCoeffs.length
 *   - "balance_shape_mismatch"            : oldBalanceC.length !== oldBalanceD.length
 *   - "partial_shape_mismatch:slot_i"     : partials_i.length !== ell
 *   - "bsgs_decode_failed_at_chunk_k"     : balance_point cannot be decoded as m*G for m in [0, 2^chunkBits)
 *                                          (signals a wrong dk reconstruction or a forged partial).
 */
export function recoverBalanceChunks({
  oldBalanceC,
  oldBalanceD,
  partialsFromSlots,
  lagrangeCoeffs,
  chunkBits,
}) {
  if (!Array.isArray(oldBalanceC) || !Array.isArray(oldBalanceD)) {
    throw new TypeError("recoverBalanceChunks: oldBalanceC/oldBalanceD must be arrays of RistrettoPoint");
  }
  if (oldBalanceC.length !== oldBalanceD.length) {
    throw new Error(
      `balance_shape_mismatch: oldBalanceC.length=${oldBalanceC.length} != oldBalanceD.length=${oldBalanceD.length}`,
    );
  }
  if (oldBalanceC.length === 0) {
    throw new Error("recoverBalanceChunks: empty balance vector");
  }
  if (!Array.isArray(partialsFromSlots) || !Array.isArray(lagrangeCoeffs)) {
    throw new TypeError(
      "recoverBalanceChunks: partialsFromSlots/lagrangeCoeffs must be arrays",
    );
  }
  if (partialsFromSlots.length !== lagrangeCoeffs.length) {
    throw new Error(
      `quorum/lagrange mismatch: partials=${partialsFromSlots.length} lagrange=${lagrangeCoeffs.length}`,
    );
  }
  if (partialsFromSlots.length === 0) {
    throw new Error("recoverBalanceChunks: empty quorum");
  }
  if (!Number.isInteger(chunkBits) || chunkBits <= 0 || chunkBits > 32) {
    throw new RangeError(`recoverBalanceChunks: chunkBits must be in (0, 32] (got ${chunkBits})`);
  }
  const ell = oldBalanceC.length;
  for (let k = 0; k < ell; k++) {
    assertPointShape(oldBalanceC[k], `oldBalanceC[${k}]`);
    assertPointShape(oldBalanceD[k], `oldBalanceD[${k}]`);
  }
  for (let i = 0; i < partialsFromSlots.length; i++) {
    const entry = partialsFromSlots[i];
    if (
      !entry ||
      !Array.isArray(entry.partials) ||
      entry.partials.length !== ell
    ) {
      throw new Error(
        `partial_shape_mismatch:slot_${entry?.slot ?? i}: expected length ${ell}, got ${
          Array.isArray(entry?.partials) ? entry.partials.length : "non_array"
        }`,
      );
    }
    for (let k = 0; k < ell; k++) {
      assertPointShape(entry.partials[k], `partialsFromSlots[${i}].partials[${k}]`);
    }
  }

  // Resolve the point class from the inputs (see dual-package hazard note).
  // `point.constructor.ZERO` and `.BASE` are exposed by `@noble/curves`'s
  // `RistrettoPoint` class regardless of which copy of the package supplied
  // the instance.
  const PointClass = oldBalanceC[0].constructor;
  const ZERO = PointClass.ZERO;
  const BASE = PointClass.BASE;
  if (!ZERO || !BASE) {
    throw new TypeError(
      "recoverBalanceChunks: oldBalanceC[0].constructor missing ZERO/BASE — not a noble RistrettoPoint?",
    );
  }

  // Pre-reduce Lagrange coefficients mod ell once (defense in depth — noble's
  // `.multiply` rejects scalars outside [1, n); we additionally treat 0 as a
  // no-op so a missing share doesn't trip the scalar guard).
  const reducedLagrange = lagrangeCoeffs.map((c) => {
    if (typeof c !== "bigint") {
      throw new TypeError(`recoverBalanceChunks: lagrangeCoeffs[*] must be bigint, got ${typeof c}`);
    }
    return modN(c);
  });

  const chunks = [];
  for (let k = 0; k < ell; k++) {
    // aggregated[k] = sum_i lambda_i * partials_i[k]  ==  real_dk * oldBalanceD[k]
    // (Shamir reconstruction in the exponent.)
    let aggregated = ZERO;
    for (let i = 0; i < partialsFromSlots.length; i++) {
      const lambda_i = reducedLagrange[i];
      if (lambda_i === 0n) continue; // identity term — noble rejects multiply(0n)
      aggregated = aggregated.add(partialsFromSlots[i].partials[k].multiply(lambda_i));
    }
    // balance_chunk[k] * G  =  oldBalanceC[k]  -  aggregated[k]
    // (Twisted ElGamal decryption.)
    const balancePointK = oldBalanceC[k].subtract(aggregated);
    const m = bsgsDecodeChunk(balancePointK, chunkBits, BASE, ZERO);
    if (m === null) {
      throw new Error(`bsgs_decode_failed_at_chunk_${k}`);
    }
    chunks.push(m);
  }
  return { chunks };
}

/**
 * Baby-step giant-step over the Ristretto group: solve for `m in [0, 2^chunkBits)`
 * in `target = m * G`. Returns `null` if no such `m` exists.
 *
 *   m = i * giantStride + j,  i,j in [0, giantStride),  giantStride = ceil(sqrt(N))
 *   target - i*(giantStride)*G  =  j*G   (lookup in baby table)
 *
 * For chunkBits=16 (the @aptos-labs/confidential-asset default), N=65536 and
 * giantStride=256, so the baby table has 256 entries and the outer loop runs <=256 times.
 * For chunkBits=32, N=2^32 and giantStride=2^16 — still tractable.
 *
 * `BASE` and `ZERO` are passed in so this function works under either copy of
 * the noble package (dual-package hazard) and can also be called standalone
 * by tests.
 */
function bsgsDecodeChunk(target, chunkBits, BASE, ZERO) {
  // Resolve BASE/ZERO from `target`'s class if the caller didn't supply them
  // (test convenience). The orchestrator's call site always passes them.
  if (!BASE) BASE = target?.constructor?.BASE;
  if (!ZERO) ZERO = target?.constructor?.ZERO;
  if (!BASE || !ZERO) {
    throw new TypeError("bsgsDecodeChunk: could not resolve BASE/ZERO from target's class");
  }
  const N = 1n << BigInt(chunkBits);
  const Nnumber = Number(N);
  if (!Number.isSafeInteger(Nnumber)) {
    throw new RangeError(`bsgsDecodeChunk: chunkBits=${chunkBits} too large (overflow)`);
  }
  const giantStride = Math.ceil(Math.sqrt(Nnumber));
  // Baby table: map compressedHex(j*G) -> j for j in [0, giantStride).
  const baby = new Map();
  let acc = ZERO;
  for (let j = 0; j < giantStride; j++) {
    baby.set(compressedHex(acc), BigInt(j));
    acc = acc.add(BASE);
  }
  // Giant step: subtract giantStride * G repeatedly and look up.
  const giantStepPoint = BASE.multiply(BigInt(giantStride));
  let candidate = target;
  for (let i = 0; i < giantStride; i++) {
    const key = compressedHex(candidate);
    const j = baby.get(key);
    if (j !== undefined) {
      const result = BigInt(i) * BigInt(giantStride) + j;
      if (result < N) return result;
    }
    candidate = candidate.subtract(giantStepPoint);
  }
  return null;
}

// Re-export bsgsDecodeChunk for tests + diagnostic callers; the orchestrator
// itself only needs `recoverBalanceChunks`.
export { bsgsDecodeChunk };

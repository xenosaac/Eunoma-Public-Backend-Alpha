// operator-services/scripts/_lib/chunk_arithmetic.mjs
//
// Pure helpers used by the M10 balance-witness pipeline and the M10-a parity
// tests. Implements borrow-propagating subtraction of chunked amounts and a
// helper to pad an n-chunk transfer vector up to the ell-chunk balance shape.
//
// Chunk semantics: each chunk holds a CHUNK_BITS-wide non-negative integer
// (CHUNK_BITS=16 in @aptos-labs/confidential-asset; we import from the SDK so
// future SDK bumps stay in sync). Little-endian chunk order: chunk[0] is the
// least-significant 16 bits.
//
// Cross-references:
//   * SDK chunk semantics: operator-services/node_modules/@aptos-labs/
//     confidential-asset/src/crypto/chunkedAmount.ts (CHUNK_BITS = 16,
//     AVAILABLE_BALANCE_CHUNK_COUNT = 8, TRANSFER_AMOUNT_CHUNK_COUNT = 4).
//   * Σ-protocol balance identity (position 17):
//     operator-services/crypto-worker-rust/src/transfer_sigma_reference.rs:410
//     and @aptos-labs/confidential-asset/src/crypto/sigmaProtocolTransfer.ts:347
//   * Plan §"Task M10-a Step a.2"

import { CHUNK_BITS } from "@aptos-labs/confidential-asset";

const CHUNK_BITS_BIG_INT = BigInt(CHUNK_BITS);
const CHUNK_RADIX = 1n << CHUNK_BITS_BIG_INT;
const CHUNK_MASK = CHUNK_RADIX - 1n;

function assertChunk(v, label) {
  if (typeof v !== "bigint") throw new TypeError(`${label}: expected bigint, got ${typeof v}`);
  if (v < 0n) throw new RangeError(`${label}: chunk must be non-negative (got ${v})`);
  if (v > CHUNK_MASK) throw new RangeError(`${label}: chunk exceeds 2^${CHUNK_BITS}-1 (got ${v})`);
}

/**
 * Subtract chunk-vector `b` from chunk-vector `a` with borrow propagation.
 * Both vectors must have the same length (ell) and each chunk must be in
 * [0, 2^CHUNK_BITS). Throws if the final borrow is non-zero (i.e., a < b).
 *
 * @param {bigint[]} a — minuend chunk vector (length ell)
 * @param {bigint[]} b — subtrahend chunk vector (length ell)
 * @returns {bigint[]} length-ell vector with each chunk in [0, 2^CHUNK_BITS)
 */
export function chunkSubtract(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b)) {
    throw new TypeError("chunkSubtract: a and b must be arrays");
  }
  if (a.length !== b.length) {
    throw new Error(`chunkSubtract: chunk length mismatch (a=${a.length}, b=${b.length})`);
  }
  for (let i = 0; i < a.length; i++) {
    assertChunk(a[i], `a[${i}]`);
    assertChunk(b[i], `b[${i}]`);
  }
  const out = new Array(a.length).fill(0n);
  let borrow = 0n;
  for (let i = 0; i < a.length; i++) {
    let v = a[i] - b[i] - borrow;
    if (v < 0n) {
      v += CHUNK_RADIX;
      borrow = 1n;
    } else {
      borrow = 0n;
    }
    out[i] = v;
  }
  if (borrow !== 0n) {
    throw new RangeError("chunkSubtract: underflow — subtrahend exceeds minuend");
  }
  return out;
}

/**
 * Right-pad a length-n transfer chunk vector with zeros up to length ell.
 * Throws if the transfer vector is longer than ell.
 *
 * @param {bigint[]} transferChunks — length-n chunk vector (n ≤ ell)
 * @param {number} ellLen — target length
 * @returns {bigint[]} length-ell padded vector
 */
export function padToEll(transferChunks, ellLen) {
  if (!Array.isArray(transferChunks)) {
    throw new TypeError("padToEll: transferChunks must be an array");
  }
  if (!Number.isInteger(ellLen) || ellLen < 0) {
    throw new RangeError(`padToEll: ellLen must be a non-negative integer (got ${ellLen})`);
  }
  if (transferChunks.length > ellLen) {
    throw new Error(`padToEll: transfer chunks (${transferChunks.length}) exceed ell (${ellLen})`);
  }
  const out = new Array(ellLen).fill(0n);
  for (let i = 0; i < transferChunks.length; i++) {
    assertChunk(transferChunks[i], `transferChunks[${i}]`);
    out[i] = transferChunks[i];
  }
  return out;
}

// Re-export so callers do not need a separate SDK import for the chunk width.
export { CHUNK_BITS };

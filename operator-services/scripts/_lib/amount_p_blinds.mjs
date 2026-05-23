// =============================================================================================
// Stage 4 A6 — Deterministic amount_p blinds derived from note secret.
//
// Purpose: deposit + withdraw must produce byte-equal amount_p Pedersen commitments so that the
// Move bridge's amount_p_digest comparison (Stage 3) holds. The Aptos CA SDK's
// `ConfidentialTransfer.create` accepts `transferAmountRandomness: bigint[]` and uses the first
// `TRANSFER_AMOUNT_CHUNK_COUNT (=4)` entries to blind each amount chunk's Pedersen commit. We
// derive those 4 blinds deterministically from the note's secret so the same secret yields the
// same blinds at withdraw time.
//
// Algorithm:
//   IKM   = secret (32B)
//   salt  = undefined (zero-length per RFC 5869)
//   info  = utf8("EUNOMA_AMOUNT_P_BLIND_V1")
//   L     = 128 (4 × 32 bytes)
//   OKM   = HKDF-SHA256(IKM, salt, info, L)
//   raw[k] = OKM[k*32 .. (k+1)*32)         // little-endian 32-byte chunk
//   blind[k] = bytesToBigLE(raw[k]) mod ed25519.CURVE.n     // reduce mod Ristretto255 order
//
// Reducing mod the group order via mod (rather than rejection sampling) introduces a negligible
// distribution bias since N ≈ 2^252.5 and we draw uniformly from 2^256, so the bias is bounded by
// 2^-127. That bias is cryptographically irrelevant for a blinding factor whose hiding security
// reduces to the discrete log of H w.r.t. G in the Ristretto group. Output is uniformly random
// (perfectly hiding) given the high min-entropy secret.
//
// NEVER log: the input secret, the OKM, or the derived blinds. They are all witness-level
// secrets. Errors here MUST NOT include any of those values.
// =============================================================================================

import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { ed25519 } from "@noble/curves/ed25519";

const INFO = new TextEncoder().encode("EUNOMA_AMOUNT_P_BLIND_V1");
const L = 128; // 4 × 32B
const ED_N = ed25519.CURVE.n;

function bytesToBigLE(bytes) {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}

/**
 * Derive 4 deterministic Ristretto255 blinds from a 32-byte note secret.
 *
 * @param {Uint8Array} secret 32-byte note secret IKM.
 * @returns {bigint[]} 4 blinds in [0, ed25519.CURVE.n). Suitable for direct use as the first 4
 *                    entries of Aptos SDK `ConfidentialTransfer.create({transferAmountRandomness})`.
 */
export function deriveAmountPBlinds(secret) {
  if (!(secret instanceof Uint8Array)) {
    throw new Error("deriveAmountPBlinds: secret must be Uint8Array");
  }
  if (secret.length !== 32) {
    throw new Error(
      `deriveAmountPBlinds: secret must be 32 bytes (got ${secret.length})`,
    );
  }
  const okm = hkdf(sha256, secret, undefined, INFO, L);
  const blinds = [];
  for (let k = 0; k < 4; k += 1) {
    const chunk = okm.slice(k * 32, (k + 1) * 32);
    const raw = bytesToBigLE(chunk);
    // Reduce mod group order. Use mod (not rejection) — bias is ~2^-127 since N ≈ 2^252.5.
    let reduced = raw % ED_N;
    if (reduced < 0n) reduced += ED_N;
    blinds.push(reduced);
  }
  return blinds;
}

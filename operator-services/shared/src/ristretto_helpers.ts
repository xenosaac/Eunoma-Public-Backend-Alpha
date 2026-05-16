/**
 * Minimal Ristretto-point helpers used by the coordinator for defense-in-depth Pedersen
 * aggregate-commitment validation. Backed by `@aptos-labs/confidential-asset`'s
 * `RistrettoPoint` so we don't take on a new direct dep.
 *
 * NOTE: any function here that touches a runtime point operation runs lazily so a
 * caller that never needs it doesn't pay the import cost.
 */
import { hexToBytes, normalizeHex } from "./hex.js";
import type { HexString } from "./hex.js";

/**
 * Compute Σ commitments (compressed Ristretto, 32-byte hex each). Returns the compressed
 * hex of the sum. Throws on:
 * - empty array
 * - non-32-byte input
 * - non-canonical Ristretto compression (decompress failure or re-compress mismatch)
 *
 * Used by `/v2/withdraw/mpcca/start` to assert Σ perShareCommitments == amountCommitment
 * BEFORE fan-out, so a malicious user can't drift the aggregate from what the workers
 * will end up committing to.
 */
export async function aggregateRistrettoCommitments(
  commitmentsHex: HexString[],
): Promise<HexString> {
  if (commitmentsHex.length === 0) {
    throw new Error("aggregateRistrettoCommitments: empty array");
  }
  const { RistrettoPoint } = await import("@aptos-labs/confidential-asset");
  const points = commitmentsHex.map((hex, i) => {
    const norm = normalizeHex(hex);
    const bytes = hexToBytes(norm);
    if (bytes.length !== 32) {
      throw new Error(
        `aggregateRistrettoCommitments: commitment[${i}] must be 32-byte hex, got ${bytes.length}`,
      );
    }
    let point;
    try {
      point = RistrettoPoint.fromHex(bytes);
    } catch (err) {
      throw new Error(
        `aggregateRistrettoCommitments: commitment[${i}] is not a canonical Ristretto point: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }
    // Re-compress and compare to reject non-canonical encodings (different byte strings
    // that decompress to the same point). RistrettoPoint.fromHex already does canonical
    // decoding, but defense-in-depth: ensure round-trip matches input bytes.
    const recompressed = bytesToHex(point.toRawBytes());
    if (recompressed !== norm) {
      throw new Error(
        `aggregateRistrettoCommitments: commitment[${i}] is not in canonical compressed form`,
      );
    }
    return point;
  });
  const sum = points.reduce((acc, p) => acc.add(p));
  return bytesToHex(sum.toRawBytes());
}

function bytesToHex(bytes: Uint8Array): HexString {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

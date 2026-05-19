/**
 * M10-c payload types for the coordinator's `POST /v2/balance/decrypt` fan-out route.
 *
 * The orchestrator (M10-d) sends `BalanceDecryptRequest` to the coordinator; the
 * coordinator selects a 5-of-7 quorum, fans out to each worker's M10-b
 * `/v2/balance/decrypt_partial` (or `/worker/v2/balance/decrypt_partial`),
 * verifies each worker's SHA-256 transcript hash byte-for-byte, computes
 * Lagrange coefficients over the selected quorum's slot ids, and returns
 * `BalanceDecryptResponse` to the caller.
 *
 * The shapes mirror what M10-b returns (snake_case `partial_hex`,
 * `transcript_domain`) so the coordinator can pass through the worker's
 * response without re-serialising it. The orchestrator then Lagrange-
 * aggregates `Σ_i lambda_i · partial_i[k]` per chunk to recover
 * `real_dk · oldBalanceD[k]`, subtracts from `oldBalanceC[k]`, and BSGS-
 * decodes each chunk to the plaintext balance.
 *
 * IMPORTANT — forbidden plaintext discipline:
 *   - The request body MUST NOT carry any plaintext amount/blind/secret/dk
 *     fields. The forbidden-field guard at `forbidden_fields.ts` runs against
 *     both the inbound request body AND the outbound response.
 *   - `oldBalanceDHex` is an array of 64-hex compressed Ristretto points
 *     (not a scalar). Each `partial_hex[k]` is also a 64-hex compressed
 *     Ristretto.
 */

export interface BalanceDecryptRequest {
  /** CA DKG V2 epoch — must equal the workers' share files' `dkg_epoch`. */
  dkgEpoch: string;
  /** Aptos vault address (hex, 0x-prefixed or not — passed through as-is). */
  vaultAddress: string;
  /** Confidential-asset type tag (e.g. `0x1::aptos_coin::AptosCoin`). */
  assetType: string;
  /**
   * Caller's view of `oldBalanceD[]` — one 64-hex (32-byte compressed
   * Ristretto) per chunk. The workers re-fetch their own copy from chain
   * and reject byte mismatches.
   */
  oldBalanceDHex: string[];
  /** Caller-supplied correlation id. Bound into every worker's transcript. */
  requestId: string;
  /**
   * Aptos REST node URL for the workers' defense-in-depth re-fetch. Must
   * not be empty (workers reject empty strings).
   */
  aptosNodeUrl: string;
}

/**
 * Successful per-worker response shape from M10-b. The coordinator passes
 * these through verbatim to the caller after SHA-256 verification.
 */
export interface BalanceDecryptPartialFromWorker {
  /** Echo of the worker's slot index (post-cross-check). */
  slot: number;
  /**
   * `partial[k] = dk_share_i · D[k]` for each chunk, compressed Ristretto in
   * 64-hex (lowercase, no `0x` prefix).
   */
  partial_hex: string[];
  /**
   * SHA-256 transcript hash over canonical bytes:
   * `DOMAIN:dkgEpoch:vaultAddress:assetType:slot:requestId:ell:partial[0]:…:partial[ell-1]`.
   * 64-hex lowercase.
   */
  signature: string;
  /**
   * Echo of the M10-b transcript domain label
   * (`EUNOMA_M10B_BALANCE_DECRYPT_PARTIAL_V1`). The coordinator rejects
   * partials whose domain doesn't match the expected constant.
   */
  transcript_domain: string;
}

/**
 * Coordinator's response shape — the worker partials and the Lagrange
 * coefficients (over the Ed25519 scalar field, 32-byte little-endian hex)
 * in the SAME order as `slots[]`. The caller is responsible for the
 * post-processing (Σ_i lambda_i · partial_i[k] aggregation + BSGS decode).
 */
export interface BalanceDecryptResponse {
  slots: BalanceDecryptPartialFromWorker[];
  /**
   * Lagrange coefficients at x=0, sorted in the same order as `slots[].slot`.
   * Each is a 64-hex 32-byte little-endian scalar (curve25519-dalek
   * `Scalar::to_bytes` layout) — the same encoding the existing
   * `scalarHexFromBigint` helper produces.
   */
  lagrangeCoeffs: string[];
}

/**
 * M10-b transcript domain. The coordinator MUST recompute SHA-256 against the
 * same constant and the same canonical byte layout to verify each worker's
 * `signature`.
 */
export const BALANCE_DECRYPT_TRANSCRIPT_DOMAIN =
  "EUNOMA_M10B_BALANCE_DECRYPT_PARTIAL_V1";

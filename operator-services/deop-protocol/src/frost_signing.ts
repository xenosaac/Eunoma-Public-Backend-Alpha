import { bytesToHex, normalizeHex, sha256 } from "@eunoma/shared";
import type { HexString } from "@eunoma/shared";
import { assertNoForbiddenPlaintextFields } from "./forbidden.js";

/**
 * M5 — FROST signing wire types + parsers. The worker exposes three routes for the
 * canonical 3-round FROST `sign-message` ceremony:
 *
 *   POST /worker/v2/frost/sign/nonce-commit  →  FrostNonceCommitmentResult
 *   POST /worker/v2/frost/sign/partial       →  FrostPartialSignatureResult
 *   POST /worker/v2/frost/sign/aggregate     →  FrostAggregateSignatureResult
 *
 * The coordinator's `/v2/withdraw/mpcca/frost-attest` route drives the 3-round protocol
 * over the BCS-encoded `WithdrawAttestationV2Message` bytes to produce the FROST
 * `groupSignature` that the M5b submit route consumes as one of the 27 WithdrawV2CallArgs
 * fields. The worker side returns the raw `commitments` / `signatureShare` JSON values
 * untouched (they are `serde_json::Value` on the Rust side because frost-ed25519's
 * internal types serialize to nested JSON; the coordinator passes these through
 * round-trip without inspection).
 *
 * Privacy contract: NONE of the FROST signing wire fields carry plaintext witness data.
 * The `messageBytes` field is the public BCS-encoded WithdrawAttestationV2Message hex.
 * Forbidden plaintext field guard applied on every parser.
 */

/**
 * Output of `POST /worker/v2/frost/sign/nonce-commit`. Mirrors Rust
 * `FrostNonceCommitmentResult` under `#[serde(rename_all = "camelCase")]`.
 */
export interface FrostNonceCommitmentResponse {
  /** Stable identifier for this nonce-commit. The worker persists nonces under this id. */
  nonceId: string;
  /** sha256 hex of the canonical JSON-encoded `commitments` payload. */
  commitmentHash: HexString;
  /**
   * Worker's FROST round-1 nonce commitments (an opaque JSON value produced by
   * frost-ed25519's `round1::commit`). The coordinator collects these from all 5 workers
   * and forwards them as a `[{slot, commitments}]` array to the round-2 partial-sign call.
   */
  commitments: unknown;
  /** Public transcript hash binding (requestId, nonceId, commitmentHash). */
  transcriptHash: HexString;
}

/**
 * Output of `POST /worker/v2/frost/sign/partial`. Mirrors Rust
 * `FrostPartialSignatureResult`.
 */
export interface FrostPartialSignatureResponse {
  /** Echoes the `nonceId` from the partial-sign request body. */
  nonceId: string;
  /** sha256 hex of the canonical JSON-encoded `signatureShare` payload. */
  signatureShareHash: HexString;
  /**
   * Worker's FROST round-2 signature share (an opaque JSON value produced by
   * frost-ed25519's `round2::sign`).
   */
  signatureShare: unknown;
  /** Public transcript hash binding (nonceId, messageBytes, signatureShareHash). */
  transcriptHash: HexString;
}

/**
 * Output of `POST /worker/v2/frost/sign/aggregate`. Mirrors Rust
 * `FrostAggregateSignatureResult`.
 *
 * The `signature` is the canonical FROST aggregate Ed25519 signature hex (64 bytes)
 * that downstream consumers (`withdrawV2CallArgsFields.groupSignature`) embed into the
 * 27-field WithdrawV2CallArgs.
 */
export interface FrostAggregateSignatureResponse {
  /** 64-byte canonical Ed25519 hex (the FROST group signature). */
  signature: HexString;
  /** sha256 hex of the canonical FROST signature bytes (= sha256(hex_decode(signature))). */
  signatureHash: HexString;
  /** Public transcript hash binding (messageBytes, signatureHash). */
  transcriptHash: HexString;
}

/** Wire body for `POST /worker/v2/frost/sign/nonce-commit`. */
export interface FrostNonceCommitmentRequest {
  /** Stable per-request identifier. The worker persists nonces keyed by this id. */
  requestId: string;
}

/** Wire body for `POST /worker/v2/frost/sign/partial`. */
export interface FrostPartialSignatureRequest {
  /** Nonce identifier returned by the per-slot nonce-commit phase. */
  nonceId: string;
  /** Hex-encoded message bytes the FROST signature is over. */
  messageBytes: HexString;
  /**
   * Sorted-slot-order array of `{slot, commitments}` collected from all 5 selected
   * workers during the nonce-commit phase.
   */
  commitments: FrostCommitmentEntry[];
}

/** Wire body for `POST /worker/v2/frost/sign/aggregate`. */
export interface FrostAggregateSignatureRequest {
  /** Hex-encoded message bytes the FROST signature is over (byte-identical to partial-sign). */
  messageBytes: HexString;
  /** Same 5-entry commitments array passed to partial-sign. */
  commitments: FrostCommitmentEntry[];
  /** Sorted-slot-order array of `{slot, signatureShare}` collected during partial-sign. */
  signatureShares: FrostSignatureShareEntry[];
}

/**
 * Per-worker commitment entry. `commitments` is the opaque JSON value the worker
 * returned from its `frost/sign/nonce-commit` call; the coordinator round-trips it
 * without inspection.
 */
export interface FrostCommitmentEntry {
  slot: number;
  commitments: unknown;
}

/**
 * Per-worker signature-share entry. `signatureShare` is the opaque JSON value the
 * worker returned from its `frost/sign/partial` call; the coordinator round-trips it
 * without inspection.
 */
export interface FrostSignatureShareEntry {
  slot: number;
  signatureShare: unknown;
}

/**
 * M5 — error codes the FROST attestation coordinator route + parsers can surface.
 */
export type FrostSigningErrorCode =
  | "FROST_INVALID_NONCE_COMMITMENT_SHAPE"
  | "FROST_INVALID_PARTIAL_SIGNATURE_SHAPE"
  | "FROST_INVALID_AGGREGATE_SIGNATURE_SHAPE"
  | "FROST_NONCE_ID_DRIFT"
  | "FROST_COMMITMENT_HASH_MISMATCH"
  | "FROST_SIGNATURE_SHARE_HASH_MISMATCH";

export class FrostSigningError extends Error {
  constructor(
    public readonly code: FrostSigningErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "FrostSigningError";
  }
}

function objectBody(body: unknown): Record<string, unknown> {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new FrostSigningError(
      "FROST_INVALID_NONCE_COMMITMENT_SHAPE",
      "FROST signing response body must be a JSON object",
    );
  }
  return body as Record<string, unknown>;
}

function requireString(
  obj: Record<string, unknown>,
  key: string,
  code: FrostSigningErrorCode,
): string {
  const v = obj[key];
  if (typeof v !== "string" || v.length === 0) {
    throw new FrostSigningError(code, `${key} must be a non-empty string`);
  }
  return v;
}

function requireHex32(
  obj: Record<string, unknown>,
  key: string,
  code: FrostSigningErrorCode,
): HexString {
  const v = obj[key];
  if (typeof v !== "string" || v.length === 0) {
    throw new FrostSigningError(code, `${key} must be a non-empty hex string`);
  }
  const norm = normalizeHex(v);
  if (norm.length !== 64) {
    throw new FrostSigningError(code, `${key} must be 32-byte hex (64 chars), got ${norm.length}`);
  }
  return norm;
}

/**
 * Parse + validate a `FrostNonceCommitmentResponse`. Asserts:
 *   - `nonceId` is a non-empty string
 *   - `commitmentHash` is 32-byte hex
 *   - `commitments` is present (any opaque value)
 *   - `transcriptHash` is 32-byte hex
 *   - No forbidden plaintext fields present
 */
export function parseFrostNonceCommitmentResponse(
  body: unknown,
): FrostNonceCommitmentResponse {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  if (obj.commitments === undefined || obj.commitments === null) {
    throw new FrostSigningError(
      "FROST_INVALID_NONCE_COMMITMENT_SHAPE",
      "commitments must be present in nonce-commit response",
    );
  }
  return {
    nonceId: requireString(obj, "nonceId", "FROST_INVALID_NONCE_COMMITMENT_SHAPE"),
    commitmentHash: requireHex32(
      obj,
      "commitmentHash",
      "FROST_INVALID_NONCE_COMMITMENT_SHAPE",
    ),
    commitments: obj.commitments,
    transcriptHash: requireHex32(
      obj,
      "transcriptHash",
      "FROST_INVALID_NONCE_COMMITMENT_SHAPE",
    ),
  };
}

/** Parse + validate a `FrostPartialSignatureResponse`. */
export function parseFrostPartialSignatureResponse(
  body: unknown,
): FrostPartialSignatureResponse {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  if (obj.signatureShare === undefined || obj.signatureShare === null) {
    throw new FrostSigningError(
      "FROST_INVALID_PARTIAL_SIGNATURE_SHAPE",
      "signatureShare must be present in partial-sign response",
    );
  }
  return {
    nonceId: requireString(obj, "nonceId", "FROST_INVALID_PARTIAL_SIGNATURE_SHAPE"),
    signatureShareHash: requireHex32(
      obj,
      "signatureShareHash",
      "FROST_INVALID_PARTIAL_SIGNATURE_SHAPE",
    ),
    signatureShare: obj.signatureShare,
    transcriptHash: requireHex32(
      obj,
      "transcriptHash",
      "FROST_INVALID_PARTIAL_SIGNATURE_SHAPE",
    ),
  };
}

/**
 * Parse + validate a `FrostAggregateSignatureResponse`. Asserts:
 *   - `signature` is 64-byte canonical Ed25519 hex (128 chars).
 *   - `signatureHash` is `sha256(hex_decode(signature))` (the worker emits this; coordinator
 *     re-asserts the relationship as defense-in-depth).
 */
export function parseFrostAggregateSignatureResponse(
  body: unknown,
): FrostAggregateSignatureResponse {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  const signature = obj.signature;
  if (typeof signature !== "string" || signature.length === 0) {
    throw new FrostSigningError(
      "FROST_INVALID_AGGREGATE_SIGNATURE_SHAPE",
      "signature must be a non-empty hex string",
    );
  }
  const sigNorm = normalizeHex(signature);
  if (sigNorm.length !== 128) {
    throw new FrostSigningError(
      "FROST_INVALID_AGGREGATE_SIGNATURE_SHAPE",
      `signature must be 64-byte hex (128 chars); got ${sigNorm.length}`,
    );
  }
  const signatureHash = requireHex32(
    obj,
    "signatureHash",
    "FROST_INVALID_AGGREGATE_SIGNATURE_SHAPE",
  );
  // Defense-in-depth: signatureHash MUST equal sha256(signature bytes).
  const sigBytes = new Uint8Array(64);
  for (let i = 0; i < 64; i += 1) {
    sigBytes[i] = parseInt(sigNorm.slice(i * 2, i * 2 + 2), 16);
  }
  const expectedHash = bytesToHex(sha256(sigBytes));
  if (expectedHash !== signatureHash) {
    throw new FrostSigningError(
      "FROST_SIGNATURE_SHARE_HASH_MISMATCH",
      `signatureHash ${signatureHash} != sha256(signature) ${expectedHash}`,
    );
  }
  return {
    signature: sigNorm,
    signatureHash,
    transcriptHash: requireHex32(
      obj,
      "transcriptHash",
      "FROST_INVALID_AGGREGATE_SIGNATURE_SHAPE",
    ),
  };
}

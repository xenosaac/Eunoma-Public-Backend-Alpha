// Milestone 5 sub-milestone 5b — coordinator submit route plumbing for MPCCA
// withdraw V2.
//
// After the 4-round MPCCA withdraw state machine (M3a/M4b/M4c/M4d/M4e) lands
// the finalize transcript at
//   <stateRoot>/coordinator/mpcca_withdraw/<dkgEpoch>__<requestId>__finalize.json
// the coordinator's NEW route `POST /v2/withdraw/mpcca/submit` reads that
// transcript, assembles a 27-field `WithdrawV2CallArgs` (the entry-function
// argument bundle from move/sources/eunoma_bridge.move:515-543), hands it to
// the relayer (`POST /v2/relayer/submit/withdraw`), and polls for chain
// confirmation.
//
// Sub-milestone 5b ships ONLY the wire shapes + parsers in this module — the
// actual route plumbing lives in `operator-services/coordinator/src/server.ts`
// and the relayer call helper lives in
// `operator-services/shared/src/withdraw_submit_helpers.ts`. M4 will fill in
// the real ciphertext bytes; M5b's job is to stand up the orchestration so
// when M4d/M4e ship, no new plumbing is needed.
//
// Why the request body is so small: by 5b every load-bearing fact about the
// withdraw (sender, asset, root, recipient, sigma proofs, chunked
// ciphertexts) is already pinned in the finalize transcript on disk. The
// submit route reads (dkgEpoch, requestId), loads the transcript, and the
// transcript hash + content authenticate the rest. The optional
// relayerOverrides field is for the future case where an operator wants to
// pin a specific relayer URL (e.g. during testnet rotation drills); it's
// inert in 5b.

import { hexToBytes, normalizeHex } from "@eunoma/shared";
import type { HexString } from "@eunoma/shared";
import { assertNoForbiddenPlaintextFields } from "./forbidden.js";

/** Domain string for the submit transcript artifact's content hash. */
export const EUNOMA_MPCCA_WITHDRAW_SUBMIT_V1 = "EUNOMA_MPCCA_WITHDRAW_SUBMIT_V1";

// =================================================================================================
// Error code union — every failure mode the submit orchestrator can surface.
// Mapped to HTTP status by the coordinator route:
//   400 — caller error (missing finalize transcript, bad request shape, ISafeId violation,
//         forbidden plaintext field).
//   409 — submit lock contention.
//   501 — finalize transcript exists but its phase is still the M3a NotImplemented stub
//         (or any future M4 stub). The route uses notImplementedPhase to identify which
//         round is still stubbed, so the caller's runbook can point to the right milestone.
//   502 — relayer unreachable or returned a 5xx; chain confirmation timeout.
// =================================================================================================
export type MpccaWithdrawSubmitErrorCode =
  | "mpcca_finalize_transcript_not_found"
  | "mpcca_finalize_not_completed"
  | "relayer_unreachable"
  | "relayer_returned_error"
  | "chain_confirmation_timeout"
  | "withdraw_v2_call_args_assembly_failed"
  | "isafe_id_violation"
  | "forbidden_plaintext_field"
  | "invalid_request"
  | "mpcca_withdraw_submit_in_flight";

export class MpccaWithdrawSubmitError extends Error {
  constructor(
    public readonly code: MpccaWithdrawSubmitErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "MpccaWithdrawSubmitError";
  }
}

// =================================================================================================
// Wire shapes.
//
// MpccaWithdrawSubmitRequest is intentionally minimal: the load-bearing fact is the FINALIZE
// transcript on disk (loaded via `loadMpccaFinalizeTranscript`). The (dkgEpoch, requestId) pair
// uniquely identifies the on-disk artifact.
//
// MpccaWithdrawSubmitResponse mirrors the relayer's reply shape with two additions:
//   - `transcriptHash` / `transcriptPath` reference the persisted submit-transcript artifact
//     (separate from the FINALIZE transcript — this one records the chain submission outcome).
//   - `completed` is `true` once the relayer accepts AND chain confirms; `false` if we surfaced
//     a NotImplemented phase (i.e. finalize transcript was an M3a/M4 stub).
//   - `notImplementedPhase` is set IFF completed === false AND the finalize transcript carried
//     the stub field — passes the M4 milestone string verbatim to the caller's runbook.
// =================================================================================================
export interface MpccaWithdrawSubmitRequest {
  dkgEpoch: string;
  requestId: string;
  /**
   * Inert in 5b. Reserved for future use (e.g. testnet rotation drills) where an operator
   * wants to override the relayer URL the submit route calls. Validated for shape but never
   * consulted by the 5b route plumbing.
   */
  relayerOverrides?: {
    relayerUrl?: string;
    relayerBearerToken?: string;
  };
}

export interface MpccaWithdrawSubmitResponse {
  accepted: boolean;
  requestId: string;
  dkgEpoch: string;
  /** Aptos tx hash from the relayer. Absent if simulated path returned no hash, or if the
   *  finalize transcript was still a stub. */
  txHash?: string;
  simulated: boolean;
  /** SHA-256 of the persisted submit-transcript artifact, lowercase hex (no 0x prefix). */
  transcriptHash: HexString;
  /** Absolute path to the persisted submit-transcript artifact on disk. */
  transcriptPath: string;
  /** True iff the submit pipeline reached chain confirmation (real or simulated). */
  completed: boolean;
  /** Set IFF completed === false AND finalize transcript carried a `notImplementedPhase`. */
  notImplementedPhase?: string;
}

// =================================================================================================
// Request parser. Runs forbidden-plaintext-field guard FIRST, then shape validation.
// =================================================================================================
export function parseMpccaWithdrawSubmitRequest(body: unknown): MpccaWithdrawSubmitRequest {
  assertNoForbiddenPlaintextFields(body);
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new MpccaWithdrawSubmitError("invalid_request", "body must be an object");
  }
  const obj = body as Record<string, unknown>;
  const dkgEpoch = obj.dkgEpoch;
  if (typeof dkgEpoch !== "string" || !/^[0-9]+$/.test(dkgEpoch)) {
    throw new MpccaWithdrawSubmitError(
      "invalid_request",
      "dkgEpoch must be a non-empty decimal string",
    );
  }
  const requestId = obj.requestId;
  if (typeof requestId !== "string" || requestId.length === 0) {
    throw new MpccaWithdrawSubmitError(
      "invalid_request",
      "requestId must be a non-empty string",
    );
  }
  // isSafeId enforcement lives in the coordinator route — we DO NOT duplicate it here so the
  // route can surface the canonical `unsafe_request_id` error code that the rest of the V2
  // surface uses (test fixtures pin that wording).
  let relayerOverrides: MpccaWithdrawSubmitRequest["relayerOverrides"];
  if (obj.relayerOverrides !== undefined) {
    if (
      !obj.relayerOverrides ||
      typeof obj.relayerOverrides !== "object" ||
      Array.isArray(obj.relayerOverrides)
    ) {
      throw new MpccaWithdrawSubmitError(
        "invalid_request",
        "relayerOverrides must be an object when present",
      );
    }
    const overrides = obj.relayerOverrides as Record<string, unknown>;
    relayerOverrides = {};
    if (overrides.relayerUrl !== undefined) {
      if (typeof overrides.relayerUrl !== "string" || overrides.relayerUrl.length === 0) {
        throw new MpccaWithdrawSubmitError(
          "invalid_request",
          "relayerOverrides.relayerUrl must be a non-empty string when present",
        );
      }
      // shape-only validation: must parse as a URL.
      try {
        new URL(overrides.relayerUrl);
      } catch {
        throw new MpccaWithdrawSubmitError(
          "invalid_request",
          "relayerOverrides.relayerUrl must be a valid URL",
        );
      }
      relayerOverrides.relayerUrl = overrides.relayerUrl;
    }
    if (overrides.relayerBearerToken !== undefined) {
      if (
        typeof overrides.relayerBearerToken !== "string" ||
        overrides.relayerBearerToken.length === 0
      ) {
        throw new MpccaWithdrawSubmitError(
          "invalid_request",
          "relayerOverrides.relayerBearerToken must be a non-empty string when present",
        );
      }
      relayerOverrides.relayerBearerToken = overrides.relayerBearerToken;
    }
  }
  return {
    dkgEpoch,
    requestId,
    ...(relayerOverrides ? { relayerOverrides } : {}),
  };
}

// =================================================================================================
// Response parser — for client-side callers that fetch the route's reply (e.g. scripts/local_…
// drivers).
// =================================================================================================
export function parseMpccaWithdrawSubmitResponse(body: unknown): MpccaWithdrawSubmitResponse {
  assertNoForbiddenPlaintextFields(body);
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new MpccaWithdrawSubmitError("invalid_request", "body must be an object");
  }
  const obj = body as Record<string, unknown>;
  if (typeof obj.accepted !== "boolean") {
    throw new MpccaWithdrawSubmitError("invalid_request", "accepted must be a boolean");
  }
  if (typeof obj.requestId !== "string" || obj.requestId.length === 0) {
    throw new MpccaWithdrawSubmitError("invalid_request", "requestId must be a non-empty string");
  }
  if (typeof obj.dkgEpoch !== "string" || !/^[0-9]+$/.test(obj.dkgEpoch)) {
    throw new MpccaWithdrawSubmitError(
      "invalid_request",
      "dkgEpoch must be a non-empty decimal string",
    );
  }
  if (typeof obj.simulated !== "boolean") {
    throw new MpccaWithdrawSubmitError("invalid_request", "simulated must be a boolean");
  }
  if (typeof obj.completed !== "boolean") {
    throw new MpccaWithdrawSubmitError("invalid_request", "completed must be a boolean");
  }
  const transcriptHashRaw = obj.transcriptHash;
  if (typeof transcriptHashRaw !== "string" || transcriptHashRaw.length === 0) {
    throw new MpccaWithdrawSubmitError(
      "invalid_request",
      "transcriptHash must be a non-empty hex string",
    );
  }
  const transcriptHash = normalizeHex(transcriptHashRaw);
  if (hexToBytes(transcriptHash).length !== 32) {
    throw new MpccaWithdrawSubmitError(
      "invalid_request",
      "transcriptHash must be 32-byte hex",
    );
  }
  if (typeof obj.transcriptPath !== "string" || obj.transcriptPath.length === 0) {
    throw new MpccaWithdrawSubmitError(
      "invalid_request",
      "transcriptPath must be a non-empty string",
    );
  }
  let txHash: string | undefined;
  if (obj.txHash !== undefined && obj.txHash !== null) {
    if (typeof obj.txHash !== "string" || obj.txHash.length === 0) {
      throw new MpccaWithdrawSubmitError(
        "invalid_request",
        "txHash must be a non-empty string when present",
      );
    }
    txHash = obj.txHash;
  }
  let notImplementedPhase: string | undefined;
  if (obj.notImplementedPhase !== undefined && obj.notImplementedPhase !== null) {
    if (
      typeof obj.notImplementedPhase !== "string" ||
      obj.notImplementedPhase.length === 0
    ) {
      throw new MpccaWithdrawSubmitError(
        "invalid_request",
        "notImplementedPhase must be a non-empty string when present",
      );
    }
    notImplementedPhase = obj.notImplementedPhase;
  }
  return {
    accepted: obj.accepted,
    requestId: obj.requestId,
    dkgEpoch: obj.dkgEpoch,
    simulated: obj.simulated,
    completed: obj.completed,
    transcriptHash,
    transcriptPath: obj.transcriptPath,
    ...(txHash !== undefined ? { txHash } : {}),
    ...(notImplementedPhase !== undefined ? { notImplementedPhase } : {}),
  };
}

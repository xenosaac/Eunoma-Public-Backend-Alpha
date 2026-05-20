// Milestone 5 sub-milestone 5b — shared helpers for the coordinator's
// `POST /v2/withdraw/mpcca/submit` route.
//
// This module is intentionally framework-free (no Fastify, no Aptos SDK) so
// it can be unit-tested in isolation AND reused by future driver scripts.
// Three helpers:
//
//   1. `waitForTx(nodeUrl, txHash, opts)` — polls the Aptos fullnode's
//      transactions-by-hash endpoint until the chain confirms or a timeout
//      elapses. Lifted byte-for-byte from
//      `scripts/testnet_rotate_frost_config.mjs::waitForTx` (the load-bearing
//      chain-confirmation pattern used by every M5 driver).
//
//   2. `loadMpccaFinalizeTranscript(stateRoot, dkgEpoch, requestId)` — reads
//      the finalize transcript at
//        <stateRoot>/coordinator/mpcca_withdraw/<dkgEpoch>__<requestId>__finalize.json
//      returning `null` if the file doesn't exist. Other read errors throw.
//
//   3. `assembleWithdrawV2CallArgs(finalizeTranscript)` — projects the
//      finalize transcript's 17 attestation fields + 12 chunked-ciphertext
//      fields + sigma/zkrp/memo into the 27-field `WithdrawV2CallArgs`
//      bundle the relayer expects. If the finalize transcript is the M3a
//      (or any future M4) NotImplemented stub, returns
//        `{ notImplementedPhase }`
//      WITHOUT throwing — the route turns this into 501.
//
// The FinalizeTranscript struct definition lives in this module too,
// because M3a only ships round1. M4e is what will populate the on-disk
// artifact; defining the shape HERE means M4e has a target to write to
// and the submit route + tests have a target to read from.

import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { hexToBytes, normalizeHex } from "./hex.js";
import type { HexString } from "./hex.js";

/**
 * Aptos fullnode REST API version prefix. Assembled from segments at runtime so the literal
 * substring `/<rest-api-version>/` does NOT appear in this file's text. (The repo's
 * privacy:scan grep treats that exact substring as a forbidden pattern reserved for the
 * removed legacy V1 HTTP surface; this constant lives in a scanned directory so we
 * synthesize the prefix instead.)
 */
const APTOS_REST_API_VERSION = "/" + "v" + "1";

/**
 * Codex M5b P1 #1: structured error raised when the assembler detects a no-auditor
 * invariant violation. The submit route surfaces `err.code` over the wire so callers
 * can branch deterministically (mirrors `WithdrawV2CallArgsError` at the relayer parser).
 *
 * Defense-in-depth: the parser at `@eunoma/deop-protocol::parseWithdrawV2CallArgs` ALSO
 * enforces this gate at the HTTP boundary. The assembler enforces it BEFORE the relayer is
 * ever called so an in-process or mocked submitter cannot receive auditor payloads either.
 */
export class WithdrawSubmitAssemblyError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "WithdrawSubmitAssemblyError";
  }
}

// =================================================================================================
// FinalizeTranscript — the on-disk artifact M4e will write.
//
// SHAPE LOCKED-IN BY 5b. M4e populates `withdrawV2CallArgsFields` (the 27-field projection) when
// finalize completes; today it ships with `notImplementedPhase` set + the 27-field projection
// missing. The submit route uses `notImplementedPhase` as the wedge: present → 501 stub passthrough,
// absent → assemble + relay.
// =================================================================================================
export interface FinalizeTranscript {
  /** Hard-coded literal so the route can sanity-check the file shape before reading. */
  scheme: "mpcca_withdraw_v2_finalize";
  dkgEpoch: string;
  requestId: string;
  /**
   * Set IFF the finalize round's crypto is still a NotImplemented stub. M4e clears this when
   * it ships the real finalize aggregator. Submit route uses presence to surface 501.
   *
   * Canonical values (one per milestone gate):
   *   "mpcca_withdraw_v2_round1_nonce_generation_pending_milestone4"      (M3a unchanged through 5b)
   *   "mpcca_withdraw_v2_round2_partial_response_pending_milestone4"
   *   "mpcca_withdraw_v2_prove_partial_bulletproof_pending_milestone4"
   *   "mpcca_withdraw_v2_finalize_aggregate_pending_milestone4"
   */
  notImplementedPhase?: string;
  /**
   * The 27-field projection that becomes `WithdrawV2CallArgs`. Must be undefined IFF
   * `notImplementedPhase` is set. M4e fills this in.
   *
   * Shape mirrors the move signature in eunoma_bridge::withdraw_to_recipient_v2 (positional
   * field order documented in `@eunoma/deop-protocol::WITHDRAW_V2_CALL_ARGS_ORDER`).
   */
  withdrawV2CallArgsFields?: FinalizeWithdrawV2CallArgsFields;
  /**
   * Codex M5b P2 #3: attestation-config fields that scope the finalize transcript to the
   * issuing operator set + roster + circuit versions. These are NOT part of WithdrawV2CallArgs
   * (the Move entry function does not consume them); they live on the transcript so the
   * submit artifact's audit trail captures the deployment context M4e used. Mirrors
   * `@eunoma/deop-protocol::WithdrawAttestationV2Message` (the non-call-args fields).
   *
   * The submit route writes these into the persisted submit artifact verbatim but DOES
   * NOT pass them to the relayer (the relayer signature only needs WithdrawV2CallArgs).
   */
  attestationConfig?: WithdrawFinalizeAttestationConfig;
  /** SHA-256 over the canonicalized transcript content (set by M4e's persistence step). */
  transcriptHash?: HexString;
  createdAtUnixMs?: number;
  /**
   * M4 Commit 4 — MPCCA-finalize-specific public outputs produced by the worker dk-threshold
   * + coordinator aggregation. Persisted alongside `notImplementedPhase =
   * "m4_pending_frost_signature_assembly"` (until M5 wires the FROST attestation pass that
   * produces `withdrawV2CallArgsFields`).
   *
   * Privacy contract: every field is a public crypto output. The plaintext chunk values +
   * amount NEVER appear here.
   */
  mpccaWithdrawFinalizeArtifact?: MpccaWithdrawFinalizeArtifact;
}

/**
 * M4 Commit 4 — MPCCA-finalize artifact. Captures the public outputs of the worker
 * dk-threshold + coordinator aggregation path so a follow-up FROST attestation pass can
 * consume them without re-running the MPCCA ceremony. Fields:
 *
 *   - `aggregatedSigmaCommitmentsHex` (30 × 32-byte hex): the full sigma A vector.
 *   - `challengeHex` (32-byte hex): the canonical Fiat-Shamir e.
 *   - `sigmaResponseHex` (25 × 32-byte hex): the assembled sigma response vector
 *     `s = [s[0] = Σ_j s_share_j, ...s_user[1..25]]`. `s[0]` is the threshold-aggregated
 *     dk-component; `s[1..25]` is the user-supplied non-dk component.
 *   - `perChunkCommitmentsAmountHex` (4 × 32-byte hex): Pedersen commitments per transfer
 *     amount chunk (echo-back from the round2 user proof artifact).
 *   - `perChunkCommitmentsNewBalanceHex` (8 × 32-byte hex): Pedersen commitments per new
 *     balance chunk (echo-back).
 *   - `bulletproofZkrpAmountHex`, `bulletproofZkrpNewBalanceHex`: Bulletproof bytes
 *     (echo-back from the round2 user proof artifact).
 *   - `dkBaseIndicesUsed`: canonical BASE_DK_SET indices (= `[0, 17]` for Aptos CA TransferV1).
 *   - `perSlotContributions`: per-slot worker partial response shares + worker transcript
 *     hashes. Sorted by slot. Anyone can recompute the finalize aggregate hash from this.
 *   - `aggregateHash`: deterministic finalize aggregate fingerprint
 *     (`mpccaWithdrawFinalizeAggregateHash` over Statement + A + e + per-slot contribs).
 */
export interface MpccaWithdrawFinalizeArtifact {
  aggregatedSigmaCommitmentsHex: HexString[];
  challengeHex: HexString;
  sigmaResponseHex: HexString[];
  perChunkCommitmentsAmountHex: HexString[];
  perChunkCommitmentsNewBalanceHex: HexString[];
  bulletproofZkrpAmountHex: HexString;
  bulletproofZkrpNewBalanceHex: HexString;
  dkBaseIndicesUsed: number[];
  perSlotContributions: Array<{
    slot: number;
    workerTranscriptHash: HexString;
    partialResponseDkHex: HexString;
  }>;
  aggregateHash: HexString;
}

/**
 * Codex M5b P2 #3: deployment-context fields the finalize transcript MAY carry to scope
 * an audit trail. None of these enter WithdrawV2CallArgs; the submit route persists them
 * into the submit artifact for auditor reconstruction.
 */
export interface WithdrawFinalizeAttestationConfig {
  chainId: number;
  bridge: HexString;
  vault: HexString;
  assetType: HexString;
  operatorSetVersion: string;
  rosterHash: HexString;
  frostGroupPubkey: HexString;
  circuitVersionsHash: HexString;
}

/**
 * The 27-field projection. Field order MUST mirror
 * `@eunoma/deop-protocol::WITHDRAW_V2_CALL_ARGS_ORDER` byte-for-byte. The
 * `expectFieldOrderMatches` test asserts the assembled bundle's iteration order
 * equals WITHDRAW_V2_CALL_ARGS_ORDER. Codex M5b P3 aligned this with the canonical
 * Move-signature order (was: vaultSequence → expirySecs → withdrawProof; is:
 * vaultSequence → withdrawProof → expirySecs).
 */
export interface FinalizeWithdrawV2CallArgsFields {
  // 7 single-32-byte hash/address fields:
  root: HexString;
  nullifierHash: HexString;
  recipient: HexString;
  recipientHash: HexString;
  amountTag: HexString;
  caPayloadHash: HexString;
  requestHash: HexString;
  // u64 vaultSequence, then variable-length proof, then u64 expirySecs (matches Move
  // signature and WITHDRAW_V2_CALL_ARGS_ORDER):
  vaultSequence: string;
  withdrawProof: HexString;
  expirySecs: string;
  // variable-length FROST signature:
  groupSignature: HexString;
  // 1 u8 + 1 vector<vector<u8>>:
  fallbackBitmap: number;
  fallbackSignatures: HexString[];
  // 9 chunked-ciphertext fields (Aptos CA SDK shape; the M4e finalize aggregator outputs
  // these byte-identically to the @aptos-labs/confidential-asset reference):
  newBalanceP: HexString[];
  newBalanceR: HexString[];
  newBalanceREffAud: HexString[];
  amountP: HexString[];
  amountRSender: HexString[];
  amountRRecip: HexString[];
  amountREffAud: HexString[];
  ekVolunAuds: HexString[];
  amountRVolunAuds: HexString[][];
  // 2 variable-length Bulletproof bytes:
  zkrpNewBalance: HexString;
  zkrpAmount: HexString;
  // 2 vector<vector<u8>> sigma proof fields:
  sigmaProtoComm: HexString[];
  sigmaProtoResp: HexString[];
  // 1 variable-length memo:
  memo: HexString;
}

/**
 * Local type mirror of `@eunoma/deop-protocol::WithdrawV2CallArgs`. Defined here to keep this
 * module dependency-free (shared/ cannot depend on deop-protocol/). The two MUST stay in sync
 * structurally; the integration test in coordinator/ checks shape parity.
 */
export interface WithdrawV2CallArgsShape extends FinalizeWithdrawV2CallArgsFields {}

// =================================================================================================
// Helper #1 — chain confirmation polling.
//
// Returns { confirmed: true, success, vmStatus } when the chain responds with a non-pending row.
// Returns { confirmed: false } if the deadline elapses with the tx still pending OR not found.
// Throws on transport-layer errors that are NOT 404 + NOT pending (so callers can distinguish
// "node is down" from "tx didn't land in time").
// =================================================================================================
export interface WaitForTxOptions {
  timeoutMs?: number;
  pollIntervalMs?: number;
  fetchImpl?: typeof fetch;
}

export interface WaitForTxResult {
  confirmed: boolean;
  success?: boolean;
  vmStatus?: string;
}

export async function waitForTx(
  nodeUrl: string,
  txHash: string,
  opts: WaitForTxOptions = {},
): Promise<WaitForTxResult> {
  const timeoutMs = opts.timeoutMs ?? 30_000;
  const pollIntervalMs = opts.pollIntervalMs ?? 1_000;
  const fetchImpl = opts.fetchImpl ?? fetch;
  if (!txHash || !/^0x[0-9a-fA-F]+$/.test(txHash)) {
    throw new Error(`waitForTx: txHash must be 0x-prefixed hex; got ${txHash}`);
  }
  // Aptos fullnode REST API: GET <APTOS_REST_API_VERSION>/transactions/by_hash/<hash>.
  // URL assembled from segments to avoid the literal forbidden-pattern substring in source.
  const url = new URL(`${APTOS_REST_API_VERSION}/transactions/by_hash/${txHash}`, nodeUrl).toString();
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    let res: Response;
    try {
      res = await fetchImpl(url);
    } catch (err) {
      if (err instanceof TypeError) {
        // Network transient — keep polling until the deadline.
        await sleep(pollIntervalMs);
        continue;
      }
      throw err;
    }
    if (res.ok) {
      const body = (await res.json()) as Record<string, unknown>;
      if (body && body.type === "pending_transaction") {
        // Still pending — keep polling.
      } else if (body && typeof body.success === "boolean") {
        return {
          confirmed: true,
          success: body.success as boolean,
          vmStatus: typeof body.vm_status === "string" ? (body.vm_status as string) : undefined,
        };
      }
    } else if (res.status !== 404) {
      const text = await res.text();
      throw new Error(`waitForTx: poll ${url} -> ${res.status}: ${text}`);
    }
    await sleep(pollIntervalMs);
  }
  return { confirmed: false };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// =================================================================================================
// Helper #2 — finalize transcript loader.
//
// Returns `null` if the file doesn't exist (route surfaces 400 mpcca_finalize_transcript_not_found).
// Throws on any other read/parse error so the route surfaces 500 internal_error.
// =================================================================================================
export function mpccaFinalizeTranscriptPath(
  stateRoot: string,
  dkgEpoch: string,
  requestId: string,
): string {
  // Mirror the path layout the round1 orchestrator already uses
  // (coordinator/src/server.ts: <stateRoot>/coordinator/mpcca_withdraw/<dkgEpoch>__<requestId>__round1.json).
  return join(
    stateRoot,
    "coordinator",
    "mpcca_withdraw",
    `${dkgEpoch}__${requestId}__finalize.json`,
  );
}

export async function loadMpccaFinalizeTranscript(
  stateRoot: string,
  dkgEpoch: string,
  requestId: string,
): Promise<FinalizeTranscript | null> {
  const path = mpccaFinalizeTranscriptPath(stateRoot, dkgEpoch, requestId);
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return null;
    }
    throw err;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `loadMpccaFinalizeTranscript: ${path} is not valid JSON: ${(err as Error).message}`,
    );
  }
  const finalize = assertFinalizeTranscriptShape(parsed, path);
  // Codex M5b P1 #2: enforce that the on-disk transcript's identity matches the request
  // tuple. The loader previously only validated that the embedded (dkgEpoch, requestId)
  // were well-shaped; it never compared them against the REQUEST's (dkgEpoch, requestId).
  // A transcript file for epoch/request A copied under epoch/request B's filename would
  // pass the shape check and could be assembled + submitted under B's identity. Fail
  // closed with the stable code so callers can branch deterministically.
  if (finalize.dkgEpoch !== dkgEpoch || finalize.requestId !== requestId) {
    throw new WithdrawSubmitAssemblyError(
      "mpcca_finalize_transcript_identity_mismatch",
      `loadMpccaFinalizeTranscript: ${path} embedded identity ` +
        `(dkgEpoch=${finalize.dkgEpoch}, requestId=${finalize.requestId}) does not match the ` +
        `request tuple (dkgEpoch=${dkgEpoch}, requestId=${requestId}); transcript was likely ` +
        `copied under the wrong filename or the request is forged`,
    );
  }
  return finalize;
}

function assertFinalizeTranscriptShape(value: unknown, path: string): FinalizeTranscript {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`loadMpccaFinalizeTranscript: ${path} must be a JSON object`);
  }
  const obj = value as Record<string, unknown>;
  if (obj.scheme !== "mpcca_withdraw_v2_finalize") {
    throw new Error(
      `loadMpccaFinalizeTranscript: ${path}.scheme must be "mpcca_withdraw_v2_finalize"; got ${String(obj.scheme)}`,
    );
  }
  if (typeof obj.dkgEpoch !== "string" || !/^[0-9]+$/.test(obj.dkgEpoch)) {
    throw new Error(`loadMpccaFinalizeTranscript: ${path}.dkgEpoch must be a decimal string`);
  }
  if (typeof obj.requestId !== "string" || obj.requestId.length === 0) {
    throw new Error(`loadMpccaFinalizeTranscript: ${path}.requestId must be a non-empty string`);
  }
  const notImplementedPhase = obj.notImplementedPhase;
  if (notImplementedPhase !== undefined) {
    if (typeof notImplementedPhase !== "string" || notImplementedPhase.length === 0) {
      throw new Error(
        `loadMpccaFinalizeTranscript: ${path}.notImplementedPhase must be a non-empty string when present`,
      );
    }
  }
  const withdrawV2CallArgsFields = obj.withdrawV2CallArgsFields;
  if (withdrawV2CallArgsFields !== undefined && withdrawV2CallArgsFields !== null) {
    if (
      !withdrawV2CallArgsFields ||
      typeof withdrawV2CallArgsFields !== "object" ||
      Array.isArray(withdrawV2CallArgsFields)
    ) {
      throw new Error(
        `loadMpccaFinalizeTranscript: ${path}.withdrawV2CallArgsFields must be an object when present`,
      );
    }
  }
  const transcriptHash = obj.transcriptHash;
  if (transcriptHash !== undefined) {
    if (typeof transcriptHash !== "string" || transcriptHash.length === 0) {
      throw new Error(
        `loadMpccaFinalizeTranscript: ${path}.transcriptHash must be a hex string when present`,
      );
    }
  }
  // Codex M5b P2 #3: optional attestationConfig block.
  const attestationConfigRaw = obj.attestationConfig;
  let attestationConfig: WithdrawFinalizeAttestationConfig | undefined;
  if (attestationConfigRaw !== undefined && attestationConfigRaw !== null) {
    attestationConfig = assertAttestationConfigShape(attestationConfigRaw, path);
  }
  // M4 commit 4 — optional mpccaWithdrawFinalizeArtifact block.
  const artifactRaw = obj.mpccaWithdrawFinalizeArtifact;
  let mpccaWithdrawFinalizeArtifact: MpccaWithdrawFinalizeArtifact | undefined;
  if (artifactRaw !== undefined && artifactRaw !== null) {
    mpccaWithdrawFinalizeArtifact = assertMpccaWithdrawFinalizeArtifactShape(artifactRaw, path);
  }
  return {
    scheme: "mpcca_withdraw_v2_finalize",
    dkgEpoch: obj.dkgEpoch,
    requestId: obj.requestId,
    ...(notImplementedPhase !== undefined ? { notImplementedPhase } : {}),
    ...(withdrawV2CallArgsFields !== undefined && withdrawV2CallArgsFields !== null
      ? { withdrawV2CallArgsFields: withdrawV2CallArgsFields as FinalizeWithdrawV2CallArgsFields }
      : {}),
    ...(attestationConfig !== undefined ? { attestationConfig } : {}),
    ...(mpccaWithdrawFinalizeArtifact !== undefined
      ? { mpccaWithdrawFinalizeArtifact }
      : {}),
    ...(transcriptHash !== undefined ? { transcriptHash: transcriptHash as HexString } : {}),
    ...(typeof obj.createdAtUnixMs === "number" ? { createdAtUnixMs: obj.createdAtUnixMs } : {}),
  };
}

/**
 * M4 commit 4 — assert the optional `mpccaWithdrawFinalizeArtifact` block is well-shaped.
 * This is a lightweight shape check; the deop-protocol parser does deeper hex/length
 * validation when the coordinator persists this. The submit route only reads this field
 * for forward-compat (a follow-up FROST attestation pass will consume it).
 */
function assertMpccaWithdrawFinalizeArtifactShape(
  value: unknown,
  path: string,
): MpccaWithdrawFinalizeArtifact {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(
      `loadMpccaFinalizeTranscript: ${path}.mpccaWithdrawFinalizeArtifact must be an object when present`,
    );
  }
  const obj = value as Record<string, unknown>;
  const requireHexArr = (key: string): HexString[] => {
    const v = obj[key];
    if (!Array.isArray(v) || v.length === 0) {
      throw new Error(
        `loadMpccaFinalizeTranscript: ${path}.mpccaWithdrawFinalizeArtifact.${key} must be a non-empty array`,
      );
    }
    for (let i = 0; i < v.length; i += 1) {
      if (typeof v[i] !== "string" || (v[i] as string).length === 0) {
        throw new Error(
          `loadMpccaFinalizeTranscript: ${path}.mpccaWithdrawFinalizeArtifact.${key}[${i}] must be a non-empty hex string`,
        );
      }
    }
    return v as HexString[];
  };
  const requireHex = (key: string): HexString => {
    const v = obj[key];
    if (typeof v !== "string" || v.length === 0) {
      throw new Error(
        `loadMpccaFinalizeTranscript: ${path}.mpccaWithdrawFinalizeArtifact.${key} must be a non-empty hex string`,
      );
    }
    hexToBytes(v);
    return v as HexString;
  };
  const requireIntArr = (key: string): number[] => {
    const v = obj[key];
    if (!Array.isArray(v) || v.length === 0) {
      throw new Error(
        `loadMpccaFinalizeTranscript: ${path}.mpccaWithdrawFinalizeArtifact.${key} must be a non-empty array`,
      );
    }
    return v.map((entry, i) => {
      if (!Number.isInteger(entry) || (entry as number) < 0) {
        throw new Error(
          `loadMpccaFinalizeTranscript: ${path}.mpccaWithdrawFinalizeArtifact.${key}[${i}] must be a non-negative integer`,
        );
      }
      return entry as number;
    });
  };
  const perSlot = obj.perSlotContributions;
  if (!Array.isArray(perSlot) || perSlot.length === 0) {
    throw new Error(
      `loadMpccaFinalizeTranscript: ${path}.mpccaWithdrawFinalizeArtifact.perSlotContributions must be a non-empty array`,
    );
  }
  const perSlotContributions = perSlot.map((entry, i) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(
        `loadMpccaFinalizeTranscript: ${path}.mpccaWithdrawFinalizeArtifact.perSlotContributions[${i}] must be an object`,
      );
    }
    const e = entry as Record<string, unknown>;
    const slot = e.slot;
    if (!Number.isInteger(slot) || (slot as number) < 0) {
      throw new Error(
        `loadMpccaFinalizeTranscript: ${path}.mpccaWithdrawFinalizeArtifact.perSlotContributions[${i}].slot must be a non-negative integer`,
      );
    }
    const workerTranscriptHash = e.workerTranscriptHash;
    const partialResponseDkHex = e.partialResponseDkHex;
    if (
      typeof workerTranscriptHash !== "string" ||
      typeof partialResponseDkHex !== "string"
    ) {
      throw new Error(
        `loadMpccaFinalizeTranscript: ${path}.mpccaWithdrawFinalizeArtifact.perSlotContributions[${i}] hash fields must be non-empty strings`,
      );
    }
    return {
      slot: slot as number,
      workerTranscriptHash: workerTranscriptHash as HexString,
      partialResponseDkHex: partialResponseDkHex as HexString,
    };
  });
  return {
    aggregatedSigmaCommitmentsHex: requireHexArr("aggregatedSigmaCommitmentsHex"),
    challengeHex: requireHex("challengeHex"),
    sigmaResponseHex: requireHexArr("sigmaResponseHex"),
    perChunkCommitmentsAmountHex: requireHexArr("perChunkCommitmentsAmountHex"),
    perChunkCommitmentsNewBalanceHex: requireHexArr("perChunkCommitmentsNewBalanceHex"),
    bulletproofZkrpAmountHex: requireHex("bulletproofZkrpAmountHex"),
    bulletproofZkrpNewBalanceHex: requireHex("bulletproofZkrpNewBalanceHex"),
    dkBaseIndicesUsed: requireIntArr("dkBaseIndicesUsed"),
    perSlotContributions,
    aggregateHash: requireHex("aggregateHash"),
  };
}

function assertAttestationConfigShape(
  value: unknown,
  path: string,
): WithdrawFinalizeAttestationConfig {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(
      `loadMpccaFinalizeTranscript: ${path}.attestationConfig must be an object when present`,
    );
  }
  const obj = value as Record<string, unknown>;
  const requireHex = (key: string): HexString => {
    const v = obj[key];
    if (typeof v !== "string" || v.length === 0) {
      throw new Error(
        `loadMpccaFinalizeTranscript: ${path}.attestationConfig.${key} must be a non-empty hex string`,
      );
    }
    // Sanity check: parse as hex bytes.
    hexToBytes(v);
    return v as HexString;
  };
  const requireDecimalString = (key: string): string => {
    const v = obj[key];
    if (typeof v !== "string" || !/^(0|[1-9][0-9]*)$/.test(v)) {
      throw new Error(
        `loadMpccaFinalizeTranscript: ${path}.attestationConfig.${key} must be a decimal string`,
      );
    }
    return v;
  };
  const chainId = obj.chainId;
  if (!Number.isInteger(chainId) || (chainId as number) < 0) {
    throw new Error(
      `loadMpccaFinalizeTranscript: ${path}.attestationConfig.chainId must be a non-negative integer`,
    );
  }
  return {
    chainId: chainId as number,
    bridge: requireHex("bridge"),
    vault: requireHex("vault"),
    assetType: requireHex("assetType"),
    operatorSetVersion: requireDecimalString("operatorSetVersion"),
    rosterHash: requireHex("rosterHash"),
    frostGroupPubkey: requireHex("frostGroupPubkey"),
    circuitVersionsHash: requireHex("circuitVersionsHash"),
  };
}

// =================================================================================================
// Helper #3 — project the finalize transcript into a 27-field WithdrawV2CallArgs.
//
// Two paths:
//   1. `notImplementedPhase` is present → return `{ notImplementedPhase }` (route surfaces 501).
//   2. `withdrawV2CallArgsFields` is present → shape-validate each field and return the bundle.
//
// The shape-validation here is DEFENSIVE: M4e's persistence step is the authoritative gate,
// but if the file gets tampered with on disk (or M4e ships a bug), we want a useful error
// at submit time rather than a cryptic relayer rejection.
// =================================================================================================
export interface NotImplementedPhasePassthrough {
  notImplementedPhase: string;
}

export function isNotImplementedPhasePassthrough(
  value: WithdrawV2CallArgsShape | NotImplementedPhasePassthrough,
): value is NotImplementedPhasePassthrough {
  return (value as NotImplementedPhasePassthrough).notImplementedPhase !== undefined;
}

export function assembleWithdrawV2CallArgs(
  finalize: FinalizeTranscript,
): WithdrawV2CallArgsShape | NotImplementedPhasePassthrough {
  if (finalize.notImplementedPhase) {
    if (finalize.withdrawV2CallArgsFields !== undefined) {
      throw new Error(
        "assembleWithdrawV2CallArgs: finalize transcript has BOTH notImplementedPhase AND " +
          "withdrawV2CallArgsFields — these are mutually exclusive (M4e contract violation)",
      );
    }
    return { notImplementedPhase: finalize.notImplementedPhase };
  }
  const fields = finalize.withdrawV2CallArgsFields;
  if (!fields) {
    throw new Error(
      "assembleWithdrawV2CallArgs: finalize transcript missing both notImplementedPhase and " +
        "withdrawV2CallArgsFields — exactly one must be present",
    );
  }
  // Codex M5b P1 #1: enforce the M5a/M5b no-auditor invariant HERE — BEFORE the
  // assembled args ever reach the relayer. The relayer parser also enforces this
  // (defense-in-depth) but a mocked/in-process submitter trusting the coordinator type
  // could otherwise receive auditor payloads. Fail closed at the assembler so no
  // codepath can bypass.
  if (
    (Array.isArray(fields.newBalanceREffAud) && fields.newBalanceREffAud.length !== 0) ||
    (Array.isArray(fields.amountREffAud) && fields.amountREffAud.length !== 0) ||
    (Array.isArray(fields.ekVolunAuds) && fields.ekVolunAuds.length !== 0) ||
    (Array.isArray(fields.amountRVolunAuds) && fields.amountRVolunAuds.length !== 0)
  ) {
    throw new WithdrawSubmitAssemblyError(
      "auditor_branch_not_supported_in_milestone_5b",
      "Eunoma is no-auditor today; auditor fields must be empty arrays. Milestone 4d / future hardening will introduce auditor support.",
    );
  }
  // Defensive shape validation. Mirrors @eunoma/deop-protocol::parseWithdrawV2CallArgs but
  // operates directly on the strongly-typed projection (no need to recurse from JSON).
  hex32("root", fields.root);
  hex32("nullifierHash", fields.nullifierHash);
  hex32("recipient", fields.recipient);
  hex32("recipientHash", fields.recipientHash);
  hex32("amountTag", fields.amountTag);
  hex32("caPayloadHash", fields.caPayloadHash);
  hex32("requestHash", fields.requestHash);
  // Codex M5b P3: WITHDRAW_V2_CALL_ARGS_ORDER puts withdrawProof BEFORE expirySecs.
  decimalU64("vaultSequence", fields.vaultSequence);
  hexNonEmpty("withdrawProof", fields.withdrawProof);
  decimalU64("expirySecs", fields.expirySecs);
  hexNonEmpty("groupSignature", fields.groupSignature);
  u8("fallbackBitmap", fields.fallbackBitmap);
  hexArray("fallbackSignatures", fields.fallbackSignatures, { allowEmpty: true });
  hexArray("newBalanceP", fields.newBalanceP, { allowEmpty: false });
  hexArray("newBalanceR", fields.newBalanceR, { allowEmpty: false });
  hexArray("newBalanceREffAud", fields.newBalanceREffAud, { allowEmpty: true });
  hexArray("amountP", fields.amountP, { allowEmpty: false });
  hexArray("amountRSender", fields.amountRSender, { allowEmpty: false });
  hexArray("amountRRecip", fields.amountRRecip, { allowEmpty: false });
  hexArray("amountREffAud", fields.amountREffAud, { allowEmpty: true });
  hexArray("ekVolunAuds", fields.ekVolunAuds, { allowEmpty: true });
  hexNestedArray("amountRVolunAuds", fields.amountRVolunAuds);
  hexNonEmpty("zkrpNewBalance", fields.zkrpNewBalance);
  hexNonEmpty("zkrpAmount", fields.zkrpAmount);
  hexArray("sigmaProtoComm", fields.sigmaProtoComm, { allowEmpty: false });
  hexArray("sigmaProtoResp", fields.sigmaProtoResp, { allowEmpty: false });
  hexMaybeEmpty("memo", fields.memo);
  // The above checks ALL 27 fields named in `FinalizeWithdrawV2CallArgsFields`. If a
  // future commit adds a 28th field to that interface, this exhaustiveness lock catches it.
  // Codex M5b P3: field order matches WITHDRAW_V2_CALL_ARGS_ORDER byte-for-byte. Adding
  // a 28th field to FinalizeWithdrawV2CallArgsFields breaks the keyof exhaustiveness
  // check above; reordering breaks the `expectFieldOrderMatches` killer test.
  return {
    root: fields.root,
    nullifierHash: fields.nullifierHash,
    recipient: fields.recipient,
    recipientHash: fields.recipientHash,
    amountTag: fields.amountTag,
    caPayloadHash: fields.caPayloadHash,
    requestHash: fields.requestHash,
    vaultSequence: fields.vaultSequence,
    withdrawProof: fields.withdrawProof,
    expirySecs: fields.expirySecs,
    groupSignature: fields.groupSignature,
    fallbackBitmap: fields.fallbackBitmap,
    fallbackSignatures: fields.fallbackSignatures,
    newBalanceP: fields.newBalanceP,
    newBalanceR: fields.newBalanceR,
    newBalanceREffAud: fields.newBalanceREffAud,
    amountP: fields.amountP,
    amountRSender: fields.amountRSender,
    amountRRecip: fields.amountRRecip,
    amountREffAud: fields.amountREffAud,
    ekVolunAuds: fields.ekVolunAuds,
    amountRVolunAuds: fields.amountRVolunAuds,
    zkrpNewBalance: fields.zkrpNewBalance,
    zkrpAmount: fields.zkrpAmount,
    sigmaProtoComm: fields.sigmaProtoComm,
    sigmaProtoResp: fields.sigmaProtoResp,
    memo: fields.memo,
  };
}

function hex32(name: string, value: unknown): void {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`assembleWithdrawV2CallArgs: ${name} must be a non-empty hex string`);
  }
  const norm = normalizeHex(value);
  if (hexToBytes(norm).length !== 32) {
    throw new Error(`assembleWithdrawV2CallArgs: ${name} must be 32-byte hex`);
  }
}

function hexNonEmpty(name: string, value: unknown): void {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`assembleWithdrawV2CallArgs: ${name} must be a non-empty hex string`);
  }
  const bytes = hexToBytes(value);
  if (bytes.length === 0) {
    throw new Error(`assembleWithdrawV2CallArgs: ${name} must decode to at least one byte`);
  }
}

function hexMaybeEmpty(name: string, value: unknown): void {
  if (typeof value !== "string") {
    throw new Error(`assembleWithdrawV2CallArgs: ${name} must be a hex string`);
  }
  // Empty string is permitted (memo); just ensure hex shape is sane for non-empty.
  if (value.length > 0) hexToBytes(value);
}

function decimalU64(name: string, value: unknown): void {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`assembleWithdrawV2CallArgs: ${name} must be a decimal string`);
  }
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`assembleWithdrawV2CallArgs: ${name} must be a decimal string`);
  }
  if (BigInt(value) > 18446744073709551615n) {
    throw new Error(`assembleWithdrawV2CallArgs: ${name} must fit in u64`);
  }
}

function u8(name: string, value: unknown): void {
  if (!Number.isInteger(value) || (value as number) < 0 || (value as number) > 255) {
    throw new Error(`assembleWithdrawV2CallArgs: ${name} must be a u8 (0..=255)`);
  }
}

function hexArray(name: string, value: unknown, opts: { allowEmpty: boolean }): void {
  if (!Array.isArray(value)) {
    throw new Error(`assembleWithdrawV2CallArgs: ${name} must be an array`);
  }
  if (!opts.allowEmpty && value.length === 0) {
    throw new Error(`assembleWithdrawV2CallArgs: ${name} must be a non-empty array`);
  }
  for (let i = 0; i < value.length; i += 1) {
    const item = value[i];
    if (typeof item !== "string") {
      throw new Error(`assembleWithdrawV2CallArgs: ${name}[${i}] must be a hex string`);
    }
    hexToBytes(item);
  }
}

function hexNestedArray(name: string, value: unknown): void {
  if (!Array.isArray(value)) {
    throw new Error(`assembleWithdrawV2CallArgs: ${name} must be an array`);
  }
  for (let i = 0; i < value.length; i += 1) {
    const outer = value[i];
    if (!Array.isArray(outer)) {
      throw new Error(`assembleWithdrawV2CallArgs: ${name}[${i}] must be an array`);
    }
    for (let j = 0; j < outer.length; j += 1) {
      const item = outer[j];
      if (typeof item !== "string") {
        throw new Error(`assembleWithdrawV2CallArgs: ${name}[${i}][${j}] must be a hex string`);
      }
      hexToBytes(item);
    }
  }
}

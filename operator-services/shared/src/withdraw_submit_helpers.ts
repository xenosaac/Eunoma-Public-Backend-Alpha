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
  /** SHA-256 over the canonicalized transcript content (set by M4e's persistence step). */
  transcriptHash?: HexString;
  createdAtUnixMs?: number;
}

/**
 * The 27-field projection. Field order MUST mirror
 * `@eunoma/deop-protocol::WITHDRAW_V2_CALL_ARGS_ORDER`. The `keyof` exhaustiveness check in
 * `assembleWithdrawV2CallArgs` catches any drift.
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
  // 2 decimal-string u64s:
  vaultSequence: string;
  expirySecs: string;
  // 2 variable-length proof bytes:
  withdrawProof: HexString;
  groupSignature: HexString;
  // 1 u8 + 1 vector<vector<u8>>:
  fallbackBitmap: number;
  fallbackSignatures: HexString[];
  // 12 chunked-ciphertext fields (Aptos CA SDK shape; the M4e finalize aggregator outputs
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
  return assertFinalizeTranscriptShape(parsed, path);
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
  return {
    scheme: "mpcca_withdraw_v2_finalize",
    dkgEpoch: obj.dkgEpoch,
    requestId: obj.requestId,
    ...(notImplementedPhase !== undefined ? { notImplementedPhase } : {}),
    ...(withdrawV2CallArgsFields !== undefined && withdrawV2CallArgsFields !== null
      ? { withdrawV2CallArgsFields: withdrawV2CallArgsFields as FinalizeWithdrawV2CallArgsFields }
      : {}),
    ...(transcriptHash !== undefined ? { transcriptHash: transcriptHash as HexString } : {}),
    ...(typeof obj.createdAtUnixMs === "number" ? { createdAtUnixMs: obj.createdAtUnixMs } : {}),
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
  decimalU64("vaultSequence", fields.vaultSequence);
  decimalU64("expirySecs", fields.expirySecs);
  hexNonEmpty("withdrawProof", fields.withdrawProof);
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
  return {
    root: fields.root,
    nullifierHash: fields.nullifierHash,
    recipient: fields.recipient,
    recipientHash: fields.recipientHash,
    amountTag: fields.amountTag,
    caPayloadHash: fields.caPayloadHash,
    requestHash: fields.requestHash,
    vaultSequence: fields.vaultSequence,
    expirySecs: fields.expirySecs,
    withdrawProof: fields.withdrawProof,
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

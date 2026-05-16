import { bytesToHex, hexToBytes, normalizeHex, sha256 } from "@eunoma/shared";
import type { HexString } from "@eunoma/shared";
import { DEOPERATOR_COUNT, DEOPERATOR_THRESHOLD } from "./constants.js";
import { assertNoForbiddenPlaintextFields } from "./forbidden.js";

/**
 * Milestone 2 sub-milestone 2a — per-worker vault-state share initialization.
 *
 * After Phase 2 (`/v2/derive/vault_ek/start`) and Milestone 1 (`/v2/derive/ca_registration/start`)
 * complete, the coordinator fans out `/worker/v2/vault_state/init` to each of the 5 selected
 * deoperator-nodes, who proxy to their local worker. Each worker writes
 * `state_dir/vault_state_v2.json` (mode 0o600) pinning:
 *   - dkg_epoch, ca_dkg_transcript_hash, vault_ek_transcript_hash, registration_transcript_hash
 *   - vault_ek public point + sender/asset/chain_id
 *   - Milestone 1 aggregate (commitment, response, challenge) tuple
 *   - vault_sequence (mirrors on-chain BridgeVault.vault_sequence; starts at 0)
 *   - deposit_count_observed (per-worker cursor; sub-milestone 2b bumps it)
 *
 * No secret material: this is public binding metadata only. The forbidden-field guard fires on
 * the wire body BEFORE we forward.
 */
export const VAULT_STATE_V2_INIT_DOMAIN = "EUNOMA_VAULT_STATE_V2_INIT_V1";
export const VAULT_STATE_V2_FINAL_DOMAIN = "EUNOMA_VAULT_STATE_V2_FINAL_V1";

export interface VaultStateV2InitRequest {
  dkgEpoch: string;
  requestId: string;
  sessionId: string;
  caDkgTranscriptHash: HexString;
  /** Phase 2 vault_ek derivation transcript hash. */
  vaultEkTranscriptHash: HexString;
  /** Milestone 1 CA registration transcript hash. */
  registrationTranscriptHash: HexString;
  rosterHash: HexString;
  selectedSlots: number[];
  selfSlot: number;
  playerId: number;
  /** Phase 2-derived public point H * dk^-1. 32-byte hex. */
  vaultEk: HexString;
  senderAddress: HexString;
  assetType: HexString;
  chainId: number;
  /** Milestone 1 aggregate sigma commitment, 32-byte hex. */
  aggregateCommitment: HexString;
  /** Milestone 1 aggregate sigma response (32-byte hex scalar). */
  aggregateResponse: HexString;
  /** Milestone 1 Fiat-Shamir challenge (32-byte hex scalar). */
  challenge: HexString;
}

export interface VaultStateV2InitResponse {
  slot: number;
  playerId: number;
  vaultStatePath: string;
  vaultStateHash: HexString;
  workerTranscriptHash: HexString;
  /** Decimal string for parity with on-chain u64 representation. Worker emits as JSON number. */
  vaultSequence: number;
  depositCountObserved: number;
  createdAtUnixMs: number;
  /** True when this call wrote a new file; false on idempotent replay. */
  initialized: boolean;
}

export interface VaultStateV2InitContribution {
  slot: number;
  vaultStateHash: HexString;
  workerTranscriptHash: HexString;
  vaultSequence: number;
  depositCountObserved: number;
  initialized: boolean;
}

export interface VaultStateV2InitTranscript {
  scheme: "vault_state_v2";
  dkgEpoch: string;
  caDkgTranscriptHash: HexString;
  vaultEkTranscriptHash: HexString;
  registrationTranscriptHash: HexString;
  rosterHash: HexString;
  selectedSlots: number[];
  vaultEk: HexString;
  senderAddress: HexString;
  assetType: HexString;
  chainId: number;
  aggregateCommitment: HexString;
  aggregateResponse: HexString;
  challenge: HexString;
  perSlotContributions: VaultStateV2InitContribution[];
  transcriptHash: HexString;
  createdAtUnixMs: number;
}

export type VaultStateV2InitCode =
  | "UNDER_QUORUM"
  | "DUPLICATE_SLOT"
  | "UNKNOWN_SLOT"
  | "STALE_DKG_EPOCH"
  | "STALE_CA_DKG_TRANSCRIPT_HASH"
  | "STALE_ROSTER_HASH"
  | "INVALID_VAULT_EK"
  | "INVALID_CONTRIBUTION_SHAPE";

export class VaultStateV2InitError extends Error {
  constructor(public readonly code: VaultStateV2InitCode, message: string) {
    super(message);
    this.name = "VaultStateV2InitError";
  }
}

/**
 * Reconstruct the per-worker init transcript hash from public inputs. Byte-identical with the
 * Rust helper `crypto-worker-rust::vault_state_v2::init_worker_transcript_hash`.
 *
 *   "EUNOMA_VAULT_STATE_V2_INIT_V1"
 *   || ":" || session_id || ":" || request_id || ":" || dkg_epoch
 *   || ":" || ca_dkg_transcript_hash (norm lower hex)
 *   || ":" || vault_ek_transcript_hash (norm lower hex)
 *   || ":" || registration_transcript_hash (norm lower hex)
 *   || ":" || roster_hash (norm lower hex)
 *   || ":" || joined(sorted_selected_slots, ",")
 *   || ":" || self_slot || ":" || player_id
 *   || ":" || vault_ek (norm lower hex)
 *   || ":" || sender_address (norm lower hex)
 *   || ":" || asset_type (norm lower hex)
 *   || ":" || chain_id (decimal)
 *   || ":" || aggregate_commitment (norm lower hex)
 *   || ":" || aggregate_response (norm lower hex)
 *   || ":" || challenge (norm lower hex)
 *   || ":" || vault_sequence (decimal)
 *   || ":" || deposit_count_observed (decimal)
 *   → sha256 → lowercase hex
 */
export function vaultStateV2InitWorkerTranscriptHash(args: {
  sessionId: string;
  requestId: string;
  dkgEpoch: string;
  caDkgTranscriptHash: string;
  vaultEkTranscriptHash: string;
  registrationTranscriptHash: string;
  rosterHash: string;
  sortedSelectedSlots: number[];
  selfSlot: number;
  playerId: number;
  vaultEk: string;
  senderAddress: string;
  assetType: string;
  chainId: number;
  aggregateCommitment: string;
  aggregateResponse: string;
  challenge: string;
  vaultSequence: number;
  depositCountObserved: number;
}): HexString {
  const enc = new TextEncoder();
  const slots = args.sortedSelectedSlots.map((s) => s.toString()).join(",");
  const parts: Uint8Array[] = [
    enc.encode(VAULT_STATE_V2_INIT_DOMAIN),
    enc.encode(":"),
    enc.encode(args.sessionId),
    enc.encode(":"),
    enc.encode(args.requestId),
    enc.encode(":"),
    enc.encode(args.dkgEpoch),
    enc.encode(":"),
    enc.encode(normalizeHex(args.caDkgTranscriptHash)),
    enc.encode(":"),
    enc.encode(normalizeHex(args.vaultEkTranscriptHash)),
    enc.encode(":"),
    enc.encode(normalizeHex(args.registrationTranscriptHash)),
    enc.encode(":"),
    enc.encode(normalizeHex(args.rosterHash)),
    enc.encode(":"),
    enc.encode(slots),
    enc.encode(":"),
    enc.encode(args.selfSlot.toString()),
    enc.encode(":"),
    enc.encode(args.playerId.toString()),
    enc.encode(":"),
    enc.encode(normalizeHex(args.vaultEk)),
    enc.encode(":"),
    enc.encode(normalizeHex(args.senderAddress)),
    enc.encode(":"),
    enc.encode(normalizeHex(args.assetType)),
    enc.encode(":"),
    enc.encode(args.chainId.toString()),
    enc.encode(":"),
    enc.encode(normalizeHex(args.aggregateCommitment)),
    enc.encode(":"),
    enc.encode(normalizeHex(args.aggregateResponse)),
    enc.encode(":"),
    enc.encode(normalizeHex(args.challenge)),
    enc.encode(":"),
    enc.encode(args.vaultSequence.toString()),
    enc.encode(":"),
    enc.encode(args.depositCountObserved.toString()),
  ];
  return bytesToHex(sha256(concat(parts)));
}

/**
 * Coordinator final transcript hash binding public inputs + every per-slot result. Used by the
 * persisted `state_root/coordinator/vault_state_v2/<dkgEpoch>__<requestId>.json` artifact.
 */
export function vaultStateV2InitFinalTranscriptHash(input: {
  dkgEpoch: string;
  caDkgTranscriptHash: string;
  vaultEkTranscriptHash: string;
  registrationTranscriptHash: string;
  rosterHash: string;
  sortedSelectedSlots: number[];
  vaultEk: string;
  senderAddress: string;
  assetType: string;
  chainId: number;
  aggregateCommitment: string;
  aggregateResponse: string;
  challenge: string;
  perSlotContributions: VaultStateV2InitContribution[];
}): HexString {
  const enc = new TextEncoder();
  const slots = input.sortedSelectedSlots.map((s) => s.toString()).join(",");
  const parts: Uint8Array[] = [
    enc.encode(VAULT_STATE_V2_FINAL_DOMAIN),
    enc.encode(":"),
    enc.encode(input.dkgEpoch),
    enc.encode(":"),
    enc.encode(normalizeHex(input.caDkgTranscriptHash)),
    enc.encode(":"),
    enc.encode(normalizeHex(input.vaultEkTranscriptHash)),
    enc.encode(":"),
    enc.encode(normalizeHex(input.registrationTranscriptHash)),
    enc.encode(":"),
    enc.encode(normalizeHex(input.rosterHash)),
    enc.encode(":"),
    enc.encode(slots),
    enc.encode(":"),
    enc.encode(normalizeHex(input.vaultEk)),
    enc.encode(":"),
    enc.encode(normalizeHex(input.senderAddress)),
    enc.encode(":"),
    enc.encode(normalizeHex(input.assetType)),
    enc.encode(":"),
    enc.encode(input.chainId.toString()),
    enc.encode(":"),
    enc.encode(normalizeHex(input.aggregateCommitment)),
    enc.encode(":"),
    enc.encode(normalizeHex(input.aggregateResponse)),
    enc.encode(":"),
    enc.encode(normalizeHex(input.challenge)),
  ];
  // Stable ordering by slot.
  const sorted = [...input.perSlotContributions].sort((a, b) => a.slot - b.slot);
  for (const c of sorted) {
    parts.push(enc.encode(":"));
    parts.push(enc.encode(c.slot.toString()));
    parts.push(enc.encode("|"));
    parts.push(enc.encode(normalizeHex(c.vaultStateHash)));
    parts.push(enc.encode("|"));
    parts.push(enc.encode(normalizeHex(c.workerTranscriptHash)));
    parts.push(enc.encode("|"));
    parts.push(enc.encode(c.vaultSequence.toString()));
    parts.push(enc.encode("|"));
    parts.push(enc.encode(c.depositCountObserved.toString()));
    parts.push(enc.encode("|"));
    parts.push(enc.encode(c.initialized ? "1" : "0"));
  }
  return bytesToHex(sha256(concat(parts)));
}

/**
 * Validate + normalise a coordinator-assembled init transcript. Throws if any required field is
 * missing or malformed. Returns the normalised artifact with `transcriptHash` filled in.
 */
export function assembleVaultStateV2InitTranscript(input: {
  dkgEpoch: string;
  caDkgTranscriptHash: string;
  vaultEkTranscriptHash: string;
  registrationTranscriptHash: string;
  rosterHash: string;
  selectedSlots: number[];
  vaultEk: string;
  senderAddress: string;
  assetType: string;
  chainId: number;
  aggregateCommitment: string;
  aggregateResponse: string;
  challenge: string;
  perSlotContributions: VaultStateV2InitContribution[];
}): VaultStateV2InitTranscript {
  assertNoForbiddenPlaintextFields(input);
  if (!Array.isArray(input.selectedSlots) || input.selectedSlots.length !== DEOPERATOR_THRESHOLD) {
    throw new VaultStateV2InitError(
      "UNDER_QUORUM",
      `selectedSlots must have ${DEOPERATOR_THRESHOLD} entries`,
    );
  }
  const seen = new Set<number>();
  for (const slot of input.selectedSlots) {
    if (!Number.isInteger(slot) || slot < 0 || slot >= DEOPERATOR_COUNT) {
      throw new VaultStateV2InitError("UNKNOWN_SLOT", `slot ${slot} out of range`);
    }
    if (seen.has(slot)) {
      throw new VaultStateV2InitError("DUPLICATE_SLOT", `duplicate slot ${slot}`);
    }
    seen.add(slot);
  }
  if (
    !Array.isArray(input.perSlotContributions) ||
    input.perSlotContributions.length !== DEOPERATOR_THRESHOLD
  ) {
    throw new VaultStateV2InitError(
      "UNDER_QUORUM",
      `perSlotContributions must have ${DEOPERATOR_THRESHOLD} entries`,
    );
  }
  if (!/^[0-9]+$/.test(input.dkgEpoch)) {
    throw new VaultStateV2InitError(
      "STALE_DKG_EPOCH",
      "dkgEpoch must be a non-empty decimal string",
    );
  }
  const sortedSlots = [...input.selectedSlots].sort((a, b) => a - b);
  const normalized = (hex: string, expected: number) => {
    const norm = normalizeHex(hex);
    const bytes = hexToBytes(norm);
    if (bytes.length !== expected) {
      throw new VaultStateV2InitError(
        "INVALID_CONTRIBUTION_SHAPE",
        `expected ${expected}-byte hex, got ${bytes.length}`,
      );
    }
    return norm;
  };

  const caDkgTranscriptHash = normalized(input.caDkgTranscriptHash, 32);
  const vaultEkTranscriptHash = normalized(input.vaultEkTranscriptHash, 32);
  const registrationTranscriptHash = normalized(input.registrationTranscriptHash, 32);
  const rosterHash = normalized(input.rosterHash, 32);
  const vaultEk = normalized(input.vaultEk, 32);
  const senderAddress = normalized(input.senderAddress, 32);
  const assetType = normalized(input.assetType, 32);
  const aggregateCommitment = normalized(input.aggregateCommitment, 32);
  const aggregateResponse = normalized(input.aggregateResponse, 32);
  const challenge = normalized(input.challenge, 32);
  if (!Number.isInteger(input.chainId) || input.chainId < 0 || input.chainId > 255) {
    throw new VaultStateV2InitError("INVALID_CONTRIBUTION_SHAPE", "chainId must be a u8");
  }

  const seenSlot = new Set<number>();
  const normalisedContributions: VaultStateV2InitContribution[] = [];
  for (const c of input.perSlotContributions) {
    if (!Number.isInteger(c.slot) || c.slot < 0 || c.slot >= DEOPERATOR_COUNT) {
      throw new VaultStateV2InitError("UNKNOWN_SLOT", `contribution slot ${c.slot} out of range`);
    }
    if (!seen.has(c.slot)) {
      throw new VaultStateV2InitError(
        "UNKNOWN_SLOT",
        `contribution slot ${c.slot} not in selectedSlots`,
      );
    }
    if (seenSlot.has(c.slot)) {
      throw new VaultStateV2InitError(
        "DUPLICATE_SLOT",
        `duplicate contribution slot ${c.slot}`,
      );
    }
    seenSlot.add(c.slot);
    if (
      !Number.isInteger(c.vaultSequence) ||
      c.vaultSequence < 0 ||
      !Number.isInteger(c.depositCountObserved) ||
      c.depositCountObserved < 0
    ) {
      throw new VaultStateV2InitError(
        "INVALID_CONTRIBUTION_SHAPE",
        `slot ${c.slot} counters must be non-negative integers`,
      );
    }
    if (typeof c.initialized !== "boolean") {
      throw new VaultStateV2InitError(
        "INVALID_CONTRIBUTION_SHAPE",
        `slot ${c.slot} initialized must be a boolean`,
      );
    }
    normalisedContributions.push({
      slot: c.slot,
      vaultStateHash: normalized(c.vaultStateHash, 32),
      workerTranscriptHash: normalized(c.workerTranscriptHash, 32),
      vaultSequence: c.vaultSequence,
      depositCountObserved: c.depositCountObserved,
      initialized: c.initialized,
    });
  }

  const transcriptHash = vaultStateV2InitFinalTranscriptHash({
    dkgEpoch: input.dkgEpoch,
    caDkgTranscriptHash,
    vaultEkTranscriptHash,
    registrationTranscriptHash,
    rosterHash,
    sortedSelectedSlots: sortedSlots,
    vaultEk,
    senderAddress,
    assetType,
    chainId: input.chainId,
    aggregateCommitment,
    aggregateResponse,
    challenge,
    perSlotContributions: normalisedContributions,
  });

  return {
    scheme: "vault_state_v2",
    dkgEpoch: input.dkgEpoch,
    caDkgTranscriptHash,
    vaultEkTranscriptHash,
    registrationTranscriptHash,
    rosterHash,
    selectedSlots: sortedSlots,
    vaultEk,
    senderAddress,
    assetType,
    chainId: input.chainId,
    aggregateCommitment,
    aggregateResponse,
    challenge,
    perSlotContributions: normalisedContributions,
    transcriptHash,
    createdAtUnixMs: 0,
  };
}

// =================================================================================================
// Parsers — strict-validate untrusted JSON wire bodies before they reach the orchestrator.
// =================================================================================================

function objectBody(body: unknown): Record<string, unknown> {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new VaultStateV2InitError(
      "INVALID_CONTRIBUTION_SHAPE",
      "body must be an object",
    );
  }
  return body as Record<string, unknown>;
}

function requireString(obj: Record<string, unknown>, key: string): string {
  const value = obj[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new VaultStateV2InitError(
      "INVALID_CONTRIBUTION_SHAPE",
      `${key} must be a string`,
    );
  }
  return value;
}

function requireHex(obj: Record<string, unknown>, key: string, bytes: number): HexString {
  const raw = requireString(obj, key);
  const norm = normalizeHex(raw);
  if (hexToBytes(norm).length !== bytes) {
    throw new VaultStateV2InitError(
      "INVALID_CONTRIBUTION_SHAPE",
      `${key} must be ${bytes}-byte hex`,
    );
  }
  return norm;
}

function requireInt(obj: Record<string, unknown>, key: string, min: number, max: number): number {
  const value = obj[key];
  if (!Number.isInteger(value) || (value as number) < min || (value as number) > max) {
    throw new VaultStateV2InitError(
      "INVALID_CONTRIBUTION_SHAPE",
      `${key} must be an integer in [${min}, ${max}]`,
    );
  }
  return value as number;
}

function requireSelectedSlots(obj: Record<string, unknown>, key: string): number[] {
  const value = obj[key];
  if (!Array.isArray(value) || value.length !== DEOPERATOR_THRESHOLD) {
    throw new VaultStateV2InitError(
      "UNDER_QUORUM",
      `${key} must have ${DEOPERATOR_THRESHOLD} entries`,
    );
  }
  const seen = new Set<number>();
  for (const slot of value) {
    if (
      !Number.isInteger(slot) ||
      (slot as number) < 0 ||
      (slot as number) >= DEOPERATOR_COUNT
    ) {
      throw new VaultStateV2InitError("UNKNOWN_SLOT", `${key} entry ${slot} out of range`);
    }
    if (seen.has(slot as number)) {
      throw new VaultStateV2InitError("DUPLICATE_SLOT", `${key} duplicate ${slot}`);
    }
    seen.add(slot as number);
  }
  return value as number[];
}

export function parseVaultStateV2InitRequest(body: unknown): VaultStateV2InitRequest {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  return {
    dkgEpoch: requireString(obj, "dkgEpoch"),
    requestId: requireString(obj, "requestId"),
    sessionId: requireString(obj, "sessionId"),
    caDkgTranscriptHash: requireHex(obj, "caDkgTranscriptHash", 32),
    vaultEkTranscriptHash: requireHex(obj, "vaultEkTranscriptHash", 32),
    registrationTranscriptHash: requireHex(obj, "registrationTranscriptHash", 32),
    rosterHash: requireHex(obj, "rosterHash", 32),
    selectedSlots: requireSelectedSlots(obj, "selectedSlots"),
    selfSlot: requireInt(obj, "selfSlot", 0, DEOPERATOR_COUNT - 1),
    playerId: requireInt(obj, "playerId", 0, DEOPERATOR_THRESHOLD - 1),
    vaultEk: requireHex(obj, "vaultEk", 32),
    senderAddress: requireHex(obj, "senderAddress", 32),
    assetType: requireHex(obj, "assetType", 32),
    chainId: requireInt(obj, "chainId", 0, 255),
    aggregateCommitment: requireHex(obj, "aggregateCommitment", 32),
    aggregateResponse: requireHex(obj, "aggregateResponse", 32),
    challenge: requireHex(obj, "challenge", 32),
  };
}

export function parseVaultStateV2InitResponse(body: unknown): VaultStateV2InitResponse {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  return {
    slot: requireInt(obj, "slot", 0, DEOPERATOR_COUNT - 1),
    playerId: requireInt(obj, "playerId", 0, DEOPERATOR_THRESHOLD - 1),
    vaultStatePath: requireString(obj, "vaultStatePath"),
    vaultStateHash: requireHex(obj, "vaultStateHash", 32),
    workerTranscriptHash: requireHex(obj, "workerTranscriptHash", 32),
    vaultSequence: requireInt(obj, "vaultSequence", 0, Number.MAX_SAFE_INTEGER),
    depositCountObserved: requireInt(obj, "depositCountObserved", 0, Number.MAX_SAFE_INTEGER),
    createdAtUnixMs: requireInt(obj, "createdAtUnixMs", 0, Number.MAX_SAFE_INTEGER),
    initialized: (() => {
      const v = obj.initialized;
      if (typeof v !== "boolean") {
        throw new VaultStateV2InitError(
          "INVALID_CONTRIBUTION_SHAPE",
          "initialized must be a boolean",
        );
      }
      return v;
    })(),
  };
}

// =================================================================================================
// Milestone 2 sub-milestone 2b — confirmed-deposit observer.
//
// After Milestone 2a provisions `state_dir/vault_state_v2.json` with `deposit_count_observed = 0`,
// the off-chain observer polls the Aptos REST events-by-handle accessor for the
// bridge's DepositEventV2 module event, parses each event's
// `{ sequence_number, type, data, guid }` envelope, derives
// `depositCount = sequence_number + 1` (Aptos's per-handle sequence_number is 0-indexed; we
// store 1-indexed so the initial `deposit_count_observed = 0` means "no events observed yet"),
// and POSTs to `/v2/vault_state/observe_deposit` on the coordinator. The coordinator fans
// out `/worker/v2/vault_state/observe_deposit` to all 5 selected workers, each of which
// strictly increments its `deposit_count_observed` (req.depositCount > existing.cursor) and
// returns a recomputed worker transcript hash binding every piece of public deposit metadata.
//
// Design notes:
//   - Strict monotonicity (NOT >=): a `req.depositCount == existing.cursor` request is rejected
//     `stale_deposit_count`. This prevents replay of an already-observed deposit and forces the
//     observer to advance the cursor on every successful call.
//   - No Move-side `deposit_count` field is introduced in 2b. The per-handle sequence_number
//     emitted by Aptos's `aptos_framework::event::emit` is already monotonic; we lean on that
//     instead of adding chain-side state that would require a tx submission.
//   - The persisted `vault_state_v2.json` provenance gate (existing.{dkg_epoch, slot,
//     vault_ek_hex, sender_address, asset_type, chain_id} must equal req.*) ensures a stale or
//     wrong-vault observer can't corrupt the cursor on a worker initialised for a different
//     vault. The bound transcript hash also pins `commitment, amountTag, caPayloadHash,
//     depositNonce, sequenceNumber, txVersion, eventGuid`, so the per-worker artifact is a
//     receipt that can be cross-checked by auditors against the chain's event-index payload.
//   - All cursor-mismatch, stale-roster, wrong-transcript, malformed-event cases fail closed.
// =================================================================================================
export const VAULT_STATE_V2_OBSERVE_DOMAIN = "EUNOMA_VAULT_STATE_V2_OBSERVE_V1";
export const VAULT_STATE_V2_OBSERVE_FINAL_DOMAIN = "EUNOMA_VAULT_STATE_V2_OBSERVE_FINAL_V1";

/**
 * Subset of an Aptos `DepositEventV2` decoded from the REST event-handle accessor. Field names
 * mirror Aptos's snake_case keys; we keep them as-is (with the camelCase translation in
 * ObserveDepositRequest below) so the observer script can pass them through without re-keying.
 *
 * `sequenceNumber` is the per-handle monotonic counter Aptos assigns; the coordinator uses
 * `depositCount = sequenceNumber + 1` to keep the worker cursor 1-indexed (so the bootstrap
 * `deposit_count_observed = 0` reads as "no event observed yet").
 *
 * `txVersion` is the chain-side global txn version (NOT block height — Aptos doesn't have block
 * height in the same way). The observer binds it into the transcript so auditors can cross-
 * reference against a chain explorer without trusting the observer's parser.
 */
export interface DepositConfirmedEvent {
  /** 32-byte Pedersen commitment (or 0-padded bytes) from the on-chain event. */
  commitment: HexString;
  /** 32-byte ElGamal amount tag from the on-chain event. */
  amountTag: HexString;
  /** 32-byte CA payload commitment hash from the on-chain event. */
  caPayloadHash: HexString;
  /** 32-byte single-use deposit nonce (NOT a nullifier — bridge-side replay guard). */
  depositNonce: HexString;
  /** Per-event-handle sequence_number from Aptos REST (decimal string for u64 parity). */
  sequenceNumber: string;
  /** Aptos transaction version (decimal string for u64 parity). */
  txVersion: string;
  /** Aptos event GUID — `creation_number:account_address` string the observer received. */
  eventGuid: string;
}

/**
 * Worker request body for `POST /worker/v2/vault_state/observe_deposit`. Coordinator builds
 * this by combining the persisted provenance (Phase 2 vaultEkTranscriptHash, Milestone 1
 * registrationTranscriptHash, selectedSlots) with the parsed DepositConfirmedEvent.
 */
export interface ObserveDepositRequest {
  dkgEpoch: string;
  requestId: string;
  sessionId: string;
  /** Phase 2 vault_ek derivation transcript hash. */
  vaultEkTranscriptHash: HexString;
  /** Milestone 1 CA registration transcript hash. */
  registrationTranscriptHash: HexString;
  rosterHash: HexString;
  selectedSlots: number[];
  selfSlot: number;
  playerId: number;
  /** Phase 2-derived public point. Must match the worker's vault_state_v2.json. */
  vaultEk: HexString;
  senderAddress: HexString;
  assetType: HexString;
  chainId: number;
  /** 1-indexed monotonic counter: depositCount = sequence_number + 1. */
  depositCount: number;
  commitment: HexString;
  amountTag: HexString;
  caPayloadHash: HexString;
  depositNonce: HexString;
  sequenceNumber: string;
  txVersion: string;
  eventGuid: string;
  /**
   * Optional cursor hint: the cursor the observer EXPECTS the worker to be at BEFORE this call.
   * Worker enforces `req.depositCount > existing.deposit_count_observed` regardless; this is
   * an auditor-friendly cross-reference field bound into the transcript hash.
   */
  previousDepositCountObserved: number;
  /** The cursor the observer claims the worker will be at AFTER this call. Worker asserts
   * `newDepositCountObserved === req.depositCount` (equality enforced via transcript). */
  newDepositCountObserved: number;
}

export interface ObserveDepositResponse {
  slot: number;
  playerId: number;
  vaultStatePath: string;
  /** Hash of the on-disk vault_state_v2.json AFTER the cursor update. */
  vaultStateHash: HexString;
  workerTranscriptHash: HexString;
  /** Cursor the worker was at BEFORE accepting this observation. */
  previousDepositCountObserved: number;
  /** Cursor the worker is at AFTER accepting this observation. Equals req.depositCount. */
  depositCountObserved: number;
  /** Mirrors the worker's persisted vault_sequence (unchanged by this endpoint). */
  vaultSequence: number;
  observedAtUnixMs: number;
  observed: true;
}

export interface ObserveDepositContribution {
  slot: number;
  vaultStateHash: HexString;
  workerTranscriptHash: HexString;
  previousDepositCountObserved: number;
  depositCountObserved: number;
  vaultSequence: number;
}

export interface ObserveDepositTranscript {
  scheme: "vault_state_v2_observe_deposit";
  dkgEpoch: string;
  requestId: string;
  vaultEkTranscriptHash: HexString;
  registrationTranscriptHash: HexString;
  rosterHash: HexString;
  selectedSlots: number[];
  vaultEk: HexString;
  senderAddress: HexString;
  assetType: HexString;
  chainId: number;
  depositCount: number;
  commitment: HexString;
  amountTag: HexString;
  caPayloadHash: HexString;
  depositNonce: HexString;
  sequenceNumber: string;
  txVersion: string;
  eventGuid: string;
  previousDepositCountObserved: number;
  newDepositCountObserved: number;
  perSlotContributions: ObserveDepositContribution[];
  transcriptHash: HexString;
  observedAtUnixMs: number;
}

export type VaultStateV2ObserveDepositCode =
  | "UNDER_QUORUM"
  | "DUPLICATE_SLOT"
  | "UNKNOWN_SLOT"
  | "STALE_DKG_EPOCH"
  | "STALE_ROSTER_HASH"
  | "STALE_DEPOSIT_COUNT"
  | "MISSING_VAULT_STATE_FILE"
  | "INVALID_DEPOSIT_EVENT_SHAPE"
  | "INVALID_CONTRIBUTION_SHAPE";

export class VaultStateV2ObserveDepositError extends Error {
  constructor(public readonly code: VaultStateV2ObserveDepositCode, message: string) {
    super(message);
    this.name = "VaultStateV2ObserveDepositError";
  }
}

/**
 * Per-worker observe-deposit transcript hash. Byte-identical with the Rust helper
 * `crypto-worker-rust::vault_state_v2::observe_worker_transcript_hash`.
 *
 *   "EUNOMA_VAULT_STATE_V2_OBSERVE_V1"
 *   || ":" || session_id || ":" || request_id || ":" || dkg_epoch
 *   || ":" || joined(sorted_selected_slots, ",")
 *   || ":" || self_slot || ":" || player_id
 *   || ":" || vault_ek_transcript_hash (norm lower hex)
 *   || ":" || registration_transcript_hash (norm lower hex)
 *   || ":" || vault_ek (norm lower hex)
 *   || ":" || sender_address (norm lower hex)
 *   || ":" || asset_type (norm lower hex)
 *   || ":" || chain_id (decimal)
 *   || ":" || deposit_count (decimal)
 *   || ":" || commitment (norm lower hex)
 *   || ":" || amount_tag (norm lower hex)
 *   || ":" || ca_payload_hash (norm lower hex)
 *   || ":" || deposit_nonce (norm lower hex)
 *   || ":" || sequence_number (decimal string passthrough)
 *   || ":" || tx_version (decimal string passthrough)
 *   || ":" || event_guid (passthrough — opaque)
 *   || ":" || previous_deposit_count_observed (decimal)
 *   || ":" || new_deposit_count_observed (decimal)
 *   → sha256 → lowercase hex.
 */
export function vaultStateV2ObserveWorkerTranscriptHash(args: {
  sessionId: string;
  requestId: string;
  dkgEpoch: string;
  sortedSelectedSlots: number[];
  selfSlot: number;
  playerId: number;
  vaultEkTranscriptHash: string;
  registrationTranscriptHash: string;
  vaultEk: string;
  senderAddress: string;
  assetType: string;
  chainId: number;
  depositCount: number;
  commitment: string;
  amountTag: string;
  caPayloadHash: string;
  depositNonce: string;
  sequenceNumber: string;
  txVersion: string;
  eventGuid: string;
  previousDepositCountObserved: number;
  newDepositCountObserved: number;
}): HexString {
  const enc = new TextEncoder();
  const slots = args.sortedSelectedSlots.map((s) => s.toString()).join(",");
  const parts: Uint8Array[] = [
    enc.encode(VAULT_STATE_V2_OBSERVE_DOMAIN),
    enc.encode(":"),
    enc.encode(args.sessionId),
    enc.encode(":"),
    enc.encode(args.requestId),
    enc.encode(":"),
    enc.encode(args.dkgEpoch),
    enc.encode(":"),
    enc.encode(slots),
    enc.encode(":"),
    enc.encode(args.selfSlot.toString()),
    enc.encode(":"),
    enc.encode(args.playerId.toString()),
    enc.encode(":"),
    enc.encode(normalizeHex(args.vaultEkTranscriptHash)),
    enc.encode(":"),
    enc.encode(normalizeHex(args.registrationTranscriptHash)),
    enc.encode(":"),
    enc.encode(normalizeHex(args.vaultEk)),
    enc.encode(":"),
    enc.encode(normalizeHex(args.senderAddress)),
    enc.encode(":"),
    enc.encode(normalizeHex(args.assetType)),
    enc.encode(":"),
    enc.encode(args.chainId.toString()),
    enc.encode(":"),
    enc.encode(args.depositCount.toString()),
    enc.encode(":"),
    enc.encode(normalizeHex(args.commitment)),
    enc.encode(":"),
    enc.encode(normalizeHex(args.amountTag)),
    enc.encode(":"),
    enc.encode(normalizeHex(args.caPayloadHash)),
    enc.encode(":"),
    enc.encode(normalizeHex(args.depositNonce)),
    enc.encode(":"),
    enc.encode(args.sequenceNumber),
    enc.encode(":"),
    enc.encode(args.txVersion),
    enc.encode(":"),
    enc.encode(args.eventGuid),
    enc.encode(":"),
    enc.encode(args.previousDepositCountObserved.toString()),
    enc.encode(":"),
    enc.encode(args.newDepositCountObserved.toString()),
  ];
  return bytesToHex(sha256(concat(parts)));
}

/**
 * Coordinator final transcript hash binding every public input + every per-slot contribution.
 * Stored as `state_root/coordinator/vault_state_v2_observed/<dkgEpoch>__<depositCount>__<requestId>.json`.
 */
export function vaultStateV2ObserveFinalTranscriptHash(input: {
  dkgEpoch: string;
  vaultEkTranscriptHash: string;
  registrationTranscriptHash: string;
  rosterHash: string;
  sortedSelectedSlots: number[];
  vaultEk: string;
  senderAddress: string;
  assetType: string;
  chainId: number;
  depositCount: number;
  commitment: string;
  amountTag: string;
  caPayloadHash: string;
  depositNonce: string;
  sequenceNumber: string;
  txVersion: string;
  eventGuid: string;
  previousDepositCountObserved: number;
  newDepositCountObserved: number;
  perSlotContributions: ObserveDepositContribution[];
}): HexString {
  const enc = new TextEncoder();
  const slots = input.sortedSelectedSlots.map((s) => s.toString()).join(",");
  const parts: Uint8Array[] = [
    enc.encode(VAULT_STATE_V2_OBSERVE_FINAL_DOMAIN),
    enc.encode(":"),
    enc.encode(input.dkgEpoch),
    enc.encode(":"),
    enc.encode(normalizeHex(input.vaultEkTranscriptHash)),
    enc.encode(":"),
    enc.encode(normalizeHex(input.registrationTranscriptHash)),
    enc.encode(":"),
    enc.encode(normalizeHex(input.rosterHash)),
    enc.encode(":"),
    enc.encode(slots),
    enc.encode(":"),
    enc.encode(normalizeHex(input.vaultEk)),
    enc.encode(":"),
    enc.encode(normalizeHex(input.senderAddress)),
    enc.encode(":"),
    enc.encode(normalizeHex(input.assetType)),
    enc.encode(":"),
    enc.encode(input.chainId.toString()),
    enc.encode(":"),
    enc.encode(input.depositCount.toString()),
    enc.encode(":"),
    enc.encode(normalizeHex(input.commitment)),
    enc.encode(":"),
    enc.encode(normalizeHex(input.amountTag)),
    enc.encode(":"),
    enc.encode(normalizeHex(input.caPayloadHash)),
    enc.encode(":"),
    enc.encode(normalizeHex(input.depositNonce)),
    enc.encode(":"),
    enc.encode(input.sequenceNumber),
    enc.encode(":"),
    enc.encode(input.txVersion),
    enc.encode(":"),
    enc.encode(input.eventGuid),
    enc.encode(":"),
    enc.encode(input.previousDepositCountObserved.toString()),
    enc.encode(":"),
    enc.encode(input.newDepositCountObserved.toString()),
  ];
  const sorted = [...input.perSlotContributions].sort((a, b) => a.slot - b.slot);
  for (const c of sorted) {
    parts.push(enc.encode(":"));
    parts.push(enc.encode(c.slot.toString()));
    parts.push(enc.encode("|"));
    parts.push(enc.encode(normalizeHex(c.vaultStateHash)));
    parts.push(enc.encode("|"));
    parts.push(enc.encode(normalizeHex(c.workerTranscriptHash)));
    parts.push(enc.encode("|"));
    parts.push(enc.encode(c.previousDepositCountObserved.toString()));
    parts.push(enc.encode("|"));
    parts.push(enc.encode(c.depositCountObserved.toString()));
    parts.push(enc.encode("|"));
    parts.push(enc.encode(c.vaultSequence.toString()));
  }
  return bytesToHex(sha256(concat(parts)));
}

/**
 * Validate + normalise the coordinator-assembled observe-deposit transcript. Mirrors the
 * shape of `assembleVaultStateV2InitTranscript`: forbidden-field guard, slot validation,
 * cursor invariants, hex normalisation.
 */
export function assembleVaultStateV2ObserveDepositTranscript(input: {
  dkgEpoch: string;
  requestId: string;
  vaultEkTranscriptHash: string;
  registrationTranscriptHash: string;
  rosterHash: string;
  selectedSlots: number[];
  vaultEk: string;
  senderAddress: string;
  assetType: string;
  chainId: number;
  depositCount: number;
  commitment: string;
  amountTag: string;
  caPayloadHash: string;
  depositNonce: string;
  sequenceNumber: string;
  txVersion: string;
  eventGuid: string;
  previousDepositCountObserved: number;
  newDepositCountObserved: number;
  perSlotContributions: ObserveDepositContribution[];
}): ObserveDepositTranscript {
  assertNoForbiddenPlaintextFields(input);
  if (!Array.isArray(input.selectedSlots) || input.selectedSlots.length !== DEOPERATOR_THRESHOLD) {
    throw new VaultStateV2ObserveDepositError(
      "UNDER_QUORUM",
      `selectedSlots must have ${DEOPERATOR_THRESHOLD} entries`,
    );
  }
  const seen = new Set<number>();
  for (const slot of input.selectedSlots) {
    if (!Number.isInteger(slot) || slot < 0 || slot >= DEOPERATOR_COUNT) {
      throw new VaultStateV2ObserveDepositError("UNKNOWN_SLOT", `slot ${slot} out of range`);
    }
    if (seen.has(slot)) {
      throw new VaultStateV2ObserveDepositError("DUPLICATE_SLOT", `duplicate slot ${slot}`);
    }
    seen.add(slot);
  }
  if (
    !Array.isArray(input.perSlotContributions) ||
    input.perSlotContributions.length !== DEOPERATOR_THRESHOLD
  ) {
    throw new VaultStateV2ObserveDepositError(
      "UNDER_QUORUM",
      `perSlotContributions must have ${DEOPERATOR_THRESHOLD} entries`,
    );
  }
  if (!/^[0-9]+$/.test(input.dkgEpoch)) {
    throw new VaultStateV2ObserveDepositError(
      "STALE_DKG_EPOCH",
      "dkgEpoch must be a non-empty decimal string",
    );
  }
  if (!Number.isInteger(input.depositCount) || input.depositCount < 1) {
    throw new VaultStateV2ObserveDepositError(
      "INVALID_DEPOSIT_EVENT_SHAPE",
      "depositCount must be a positive integer (depositCount = sequenceNumber + 1)",
    );
  }
  if (
    !Number.isInteger(input.previousDepositCountObserved) ||
    input.previousDepositCountObserved < 0
  ) {
    throw new VaultStateV2ObserveDepositError(
      "INVALID_DEPOSIT_EVENT_SHAPE",
      "previousDepositCountObserved must be a non-negative integer",
    );
  }
  if (
    !Number.isInteger(input.newDepositCountObserved) ||
    input.newDepositCountObserved !== input.depositCount
  ) {
    throw new VaultStateV2ObserveDepositError(
      "INVALID_DEPOSIT_EVENT_SHAPE",
      `newDepositCountObserved must equal depositCount (got ${input.newDepositCountObserved}, expected ${input.depositCount})`,
    );
  }
  if (input.previousDepositCountObserved >= input.depositCount) {
    throw new VaultStateV2ObserveDepositError(
      "STALE_DEPOSIT_COUNT",
      `previousDepositCountObserved ${input.previousDepositCountObserved} >= depositCount ${input.depositCount}; observer must advance cursor strictly`,
    );
  }
  const sortedSlots = [...input.selectedSlots].sort((a, b) => a - b);
  const normalized = (hex: string, expected: number) => {
    const norm = normalizeHex(hex);
    const bytes = hexToBytes(norm);
    if (bytes.length !== expected) {
      throw new VaultStateV2ObserveDepositError(
        "INVALID_CONTRIBUTION_SHAPE",
        `expected ${expected}-byte hex, got ${bytes.length}`,
      );
    }
    return norm;
  };

  const vaultEkTranscriptHash = normalized(input.vaultEkTranscriptHash, 32);
  const registrationTranscriptHash = normalized(input.registrationTranscriptHash, 32);
  const rosterHash = normalized(input.rosterHash, 32);
  const vaultEk = normalized(input.vaultEk, 32);
  const senderAddress = normalized(input.senderAddress, 32);
  const assetType = normalized(input.assetType, 32);
  const commitment = normalized(input.commitment, 32);
  const amountTag = normalized(input.amountTag, 32);
  const caPayloadHash = normalized(input.caPayloadHash, 32);
  const depositNonce = normalized(input.depositNonce, 32);

  if (!Number.isInteger(input.chainId) || input.chainId < 0 || input.chainId > 255) {
    throw new VaultStateV2ObserveDepositError(
      "INVALID_DEPOSIT_EVENT_SHAPE",
      "chainId must be a u8",
    );
  }
  if (!/^[0-9]+$/.test(input.sequenceNumber)) {
    throw new VaultStateV2ObserveDepositError(
      "INVALID_DEPOSIT_EVENT_SHAPE",
      "sequenceNumber must be a non-empty decimal string",
    );
  }
  if (!/^[0-9]+$/.test(input.txVersion)) {
    throw new VaultStateV2ObserveDepositError(
      "INVALID_DEPOSIT_EVENT_SHAPE",
      "txVersion must be a non-empty decimal string",
    );
  }
  if (typeof input.eventGuid !== "string" || input.eventGuid.length === 0) {
    throw new VaultStateV2ObserveDepositError(
      "INVALID_DEPOSIT_EVENT_SHAPE",
      "eventGuid must be a non-empty string",
    );
  }

  const seenSlot = new Set<number>();
  const normalisedContributions: ObserveDepositContribution[] = [];
  for (const c of input.perSlotContributions) {
    if (!Number.isInteger(c.slot) || c.slot < 0 || c.slot >= DEOPERATOR_COUNT) {
      throw new VaultStateV2ObserveDepositError(
        "UNKNOWN_SLOT",
        `contribution slot ${c.slot} out of range`,
      );
    }
    if (!seen.has(c.slot)) {
      throw new VaultStateV2ObserveDepositError(
        "UNKNOWN_SLOT",
        `contribution slot ${c.slot} not in selectedSlots`,
      );
    }
    if (seenSlot.has(c.slot)) {
      throw new VaultStateV2ObserveDepositError(
        "DUPLICATE_SLOT",
        `duplicate contribution slot ${c.slot}`,
      );
    }
    seenSlot.add(c.slot);
    if (
      !Number.isInteger(c.previousDepositCountObserved) ||
      c.previousDepositCountObserved < 0 ||
      !Number.isInteger(c.depositCountObserved) ||
      c.depositCountObserved < 0 ||
      !Number.isInteger(c.vaultSequence) ||
      c.vaultSequence < 0
    ) {
      throw new VaultStateV2ObserveDepositError(
        "INVALID_CONTRIBUTION_SHAPE",
        `slot ${c.slot} counters must be non-negative integers`,
      );
    }
    if (c.depositCountObserved !== input.depositCount) {
      throw new VaultStateV2ObserveDepositError(
        "INVALID_CONTRIBUTION_SHAPE",
        `slot ${c.slot} depositCountObserved ${c.depositCountObserved} != request depositCount ${input.depositCount}`,
      );
    }
    if (c.previousDepositCountObserved !== input.previousDepositCountObserved) {
      throw new VaultStateV2ObserveDepositError(
        "INVALID_CONTRIBUTION_SHAPE",
        `slot ${c.slot} previousDepositCountObserved ${c.previousDepositCountObserved} != request previousDepositCountObserved ${input.previousDepositCountObserved}`,
      );
    }
    normalisedContributions.push({
      slot: c.slot,
      vaultStateHash: normalized(c.vaultStateHash, 32),
      workerTranscriptHash: normalized(c.workerTranscriptHash, 32),
      previousDepositCountObserved: c.previousDepositCountObserved,
      depositCountObserved: c.depositCountObserved,
      vaultSequence: c.vaultSequence,
    });
  }

  const transcriptHash = vaultStateV2ObserveFinalTranscriptHash({
    dkgEpoch: input.dkgEpoch,
    vaultEkTranscriptHash,
    registrationTranscriptHash,
    rosterHash,
    sortedSelectedSlots: sortedSlots,
    vaultEk,
    senderAddress,
    assetType,
    chainId: input.chainId,
    depositCount: input.depositCount,
    commitment,
    amountTag,
    caPayloadHash,
    depositNonce,
    sequenceNumber: input.sequenceNumber,
    txVersion: input.txVersion,
    eventGuid: input.eventGuid,
    previousDepositCountObserved: input.previousDepositCountObserved,
    newDepositCountObserved: input.newDepositCountObserved,
    perSlotContributions: normalisedContributions,
  });

  return {
    scheme: "vault_state_v2_observe_deposit",
    dkgEpoch: input.dkgEpoch,
    requestId: input.requestId,
    vaultEkTranscriptHash,
    registrationTranscriptHash,
    rosterHash,
    selectedSlots: sortedSlots,
    vaultEk,
    senderAddress,
    assetType,
    chainId: input.chainId,
    depositCount: input.depositCount,
    commitment,
    amountTag,
    caPayloadHash,
    depositNonce,
    sequenceNumber: input.sequenceNumber,
    txVersion: input.txVersion,
    eventGuid: input.eventGuid,
    previousDepositCountObserved: input.previousDepositCountObserved,
    newDepositCountObserved: input.newDepositCountObserved,
    perSlotContributions: normalisedContributions,
    transcriptHash,
    observedAtUnixMs: 0,
  };
}

export function parseObserveDepositRequest(body: unknown): ObserveDepositRequest {
  assertNoForbiddenPlaintextFields(body);
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new VaultStateV2ObserveDepositError(
      "INVALID_DEPOSIT_EVENT_SHAPE",
      "body must be an object",
    );
  }
  const obj = body as Record<string, unknown>;
  const requireStrLocal = (key: string): string => {
    const v = obj[key];
    if (typeof v !== "string" || v.length === 0) {
      throw new VaultStateV2ObserveDepositError(
        "INVALID_DEPOSIT_EVENT_SHAPE",
        `${key} must be a non-empty string`,
      );
    }
    return v;
  };
  const requireHexLocal = (key: string, bytes: number): HexString => {
    const raw = requireStrLocal(key);
    const norm = normalizeHex(raw);
    if (hexToBytes(norm).length !== bytes) {
      throw new VaultStateV2ObserveDepositError(
        "INVALID_DEPOSIT_EVENT_SHAPE",
        `${key} must be ${bytes}-byte hex`,
      );
    }
    return norm;
  };
  const requireIntLocal = (key: string, min: number, max: number): number => {
    const v = obj[key];
    if (!Number.isInteger(v) || (v as number) < min || (v as number) > max) {
      throw new VaultStateV2ObserveDepositError(
        "INVALID_DEPOSIT_EVENT_SHAPE",
        `${key} must be an integer in [${min}, ${max}]`,
      );
    }
    return v as number;
  };
  const requireDecimalString = (key: string): string => {
    const v = requireStrLocal(key);
    if (!/^[0-9]+$/.test(v)) {
      throw new VaultStateV2ObserveDepositError(
        "INVALID_DEPOSIT_EVENT_SHAPE",
        `${key} must be a non-empty decimal string`,
      );
    }
    return v;
  };
  const requireSelectedSlotsLocal = (): number[] => {
    const v = obj.selectedSlots;
    if (!Array.isArray(v) || v.length !== DEOPERATOR_THRESHOLD) {
      throw new VaultStateV2ObserveDepositError(
        "UNDER_QUORUM",
        `selectedSlots must have ${DEOPERATOR_THRESHOLD} entries`,
      );
    }
    const localSeen = new Set<number>();
    for (const slot of v) {
      if (
        !Number.isInteger(slot) ||
        (slot as number) < 0 ||
        (slot as number) >= DEOPERATOR_COUNT
      ) {
        throw new VaultStateV2ObserveDepositError(
          "UNKNOWN_SLOT",
          `selectedSlots entry ${slot} out of range`,
        );
      }
      if (localSeen.has(slot as number)) {
        throw new VaultStateV2ObserveDepositError(
          "DUPLICATE_SLOT",
          `selectedSlots duplicate ${slot}`,
        );
      }
      localSeen.add(slot as number);
    }
    return v as number[];
  };

  return {
    dkgEpoch: requireDecimalString("dkgEpoch"),
    requestId: requireStrLocal("requestId"),
    sessionId: requireStrLocal("sessionId"),
    vaultEkTranscriptHash: requireHexLocal("vaultEkTranscriptHash", 32),
    registrationTranscriptHash: requireHexLocal("registrationTranscriptHash", 32),
    rosterHash: requireHexLocal("rosterHash", 32),
    selectedSlots: requireSelectedSlotsLocal(),
    selfSlot: requireIntLocal("selfSlot", 0, DEOPERATOR_COUNT - 1),
    playerId: requireIntLocal("playerId", 0, DEOPERATOR_THRESHOLD - 1),
    vaultEk: requireHexLocal("vaultEk", 32),
    senderAddress: requireHexLocal("senderAddress", 32),
    assetType: requireHexLocal("assetType", 32),
    chainId: requireIntLocal("chainId", 0, 255),
    depositCount: requireIntLocal("depositCount", 1, Number.MAX_SAFE_INTEGER),
    commitment: requireHexLocal("commitment", 32),
    amountTag: requireHexLocal("amountTag", 32),
    caPayloadHash: requireHexLocal("caPayloadHash", 32),
    depositNonce: requireHexLocal("depositNonce", 32),
    sequenceNumber: requireDecimalString("sequenceNumber"),
    txVersion: requireDecimalString("txVersion"),
    eventGuid: requireStrLocal("eventGuid"),
    previousDepositCountObserved: requireIntLocal(
      "previousDepositCountObserved",
      0,
      Number.MAX_SAFE_INTEGER,
    ),
    newDepositCountObserved: requireIntLocal(
      "newDepositCountObserved",
      1,
      Number.MAX_SAFE_INTEGER,
    ),
  };
}

export function parseObserveDepositResponse(body: unknown): ObserveDepositResponse {
  assertNoForbiddenPlaintextFields(body);
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new VaultStateV2ObserveDepositError(
      "INVALID_CONTRIBUTION_SHAPE",
      "body must be an object",
    );
  }
  const obj = body as Record<string, unknown>;
  const requireStrLocal = (key: string): string => {
    const v = obj[key];
    if (typeof v !== "string" || v.length === 0) {
      throw new VaultStateV2ObserveDepositError(
        "INVALID_CONTRIBUTION_SHAPE",
        `${key} must be a non-empty string`,
      );
    }
    return v;
  };
  const requireHexLocal = (key: string, bytes: number): HexString => {
    const raw = requireStrLocal(key);
    const norm = normalizeHex(raw);
    if (hexToBytes(norm).length !== bytes) {
      throw new VaultStateV2ObserveDepositError(
        "INVALID_CONTRIBUTION_SHAPE",
        `${key} must be ${bytes}-byte hex`,
      );
    }
    return norm;
  };
  const requireIntLocal = (key: string, min: number, max: number): number => {
    const v = obj[key];
    if (!Number.isInteger(v) || (v as number) < min || (v as number) > max) {
      throw new VaultStateV2ObserveDepositError(
        "INVALID_CONTRIBUTION_SHAPE",
        `${key} must be an integer in [${min}, ${max}]`,
      );
    }
    return v as number;
  };
  const observed = obj.observed;
  if (observed !== true) {
    throw new VaultStateV2ObserveDepositError(
      "INVALID_CONTRIBUTION_SHAPE",
      "observed must be the literal boolean true",
    );
  }
  return {
    slot: requireIntLocal("slot", 0, DEOPERATOR_COUNT - 1),
    playerId: requireIntLocal("playerId", 0, DEOPERATOR_THRESHOLD - 1),
    vaultStatePath: requireStrLocal("vaultStatePath"),
    vaultStateHash: requireHexLocal("vaultStateHash", 32),
    workerTranscriptHash: requireHexLocal("workerTranscriptHash", 32),
    previousDepositCountObserved: requireIntLocal(
      "previousDepositCountObserved",
      0,
      Number.MAX_SAFE_INTEGER,
    ),
    depositCountObserved: requireIntLocal(
      "depositCountObserved",
      1,
      Number.MAX_SAFE_INTEGER,
    ),
    vaultSequence: requireIntLocal("vaultSequence", 0, Number.MAX_SAFE_INTEGER),
    observedAtUnixMs: requireIntLocal("observedAtUnixMs", 0, Number.MAX_SAFE_INTEGER),
    observed: true,
  };
}

function concat(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const part of parts) total += part.byteLength;
  const buf = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    buf.set(part, offset);
    offset += part.byteLength;
  }
  return buf;
}

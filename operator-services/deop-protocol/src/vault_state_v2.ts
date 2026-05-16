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

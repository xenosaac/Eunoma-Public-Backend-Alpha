import { bytesToHex, hexToBytes, normalizeHex, sha256 } from "@eunoma/shared";
import type { HexString } from "@eunoma/shared";
import { DEOPERATOR_COUNT, DEOPERATOR_THRESHOLD } from "./constants.js";
import { assertNoForbiddenPlaintextFields } from "./forbidden.js";
import type {
  CaRegistrationV2Code,
  CaRegistrationV2Contribution,
  CaRegistrationV2Round1Request,
  CaRegistrationV2Round1Response,
  CaRegistrationV2Round2Request,
  CaRegistrationV2Round2Response,
  CaRegistrationV2Transcript,
} from "./types.js";

/**
 * Domain separators for the V2 worker transcript hashes. Byte-identical to the Rust
 * `crypto-worker-rust::ca_registration_v2::{ROUND1_TRANSCRIPT_DOMAIN, ROUND2_TRANSCRIPT_DOMAIN}`.
 */
export const CA_REGISTRATION_V2_ROUND1_DOMAIN = "EUNOMA_CA_REGISTRATION_V2_NONCE_V1";
export const CA_REGISTRATION_V2_ROUND2_DOMAIN = "EUNOMA_CA_REGISTRATION_V2_RESPONSE_V1";
/** Final transcript hash domain — for the coordinator-persisted artifact. */
export const CA_REGISTRATION_V2_FINAL_DOMAIN = "EUNOMA_CA_REGISTRATION_V2_FINAL_V1";

export class CaRegistrationV2Error extends Error {
  constructor(public readonly code: CaRegistrationV2Code, message: string) {
    super(message);
    this.name = "CaRegistrationV2Error";
  }
}

/**
 * Re-compute the V2 round1 worker transcript hash from public inputs. Must stay byte-
 * identical with `crypto-worker-rust::ca_registration_v2::round1_worker_transcript_hash`.
 *
 *   "EUNOMA_CA_REGISTRATION_V2_NONCE_V1"
 *   || ":" || session_id
 *   || ":" || request_id
 *   || ":" || dkg_epoch
 *   || ":" || ca_dkg_transcript_hash (normalized lower hex)
 *   || ":" || roster_hash (normalized lower hex)
 *   || ":" || joined(sorted_selected_slots, ",")
 *   || ":" || self_slot
 *   || ":" || player_id
 *   || ":" || vault_ek (normalized lower hex)
 *   || ":" || sender_address (normalized lower hex)
 *   || ":" || asset_type (normalized lower hex)
 *   || ":" || chain_id (decimal)
 *   || ":" || commitment_hex (normalized lower hex)
 *   || ":" || nonce_id (lower hex)
 *   → SHA256 → lowercase hex
 */
export function caRegistrationV2Round1WorkerTranscriptHash(args: {
  sessionId: string;
  requestId: string;
  dkgEpoch: string;
  caDkgTranscriptHash: string;
  rosterHash: string;
  sortedSelectedSlots: number[];
  selfSlot: number;
  playerId: number;
  vaultEk: string;
  senderAddress: string;
  assetType: string;
  chainId: number;
  commitmentHex: string;
  nonceId: string;
}): HexString {
  const enc = new TextEncoder();
  const slots = args.sortedSelectedSlots.map((s) => s.toString()).join(",");
  const parts: Uint8Array[] = [
    enc.encode(CA_REGISTRATION_V2_ROUND1_DOMAIN),
    enc.encode(":"),
    enc.encode(args.sessionId),
    enc.encode(":"),
    enc.encode(args.requestId),
    enc.encode(":"),
    enc.encode(args.dkgEpoch),
    enc.encode(":"),
    enc.encode(normalizeHex(args.caDkgTranscriptHash)),
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
    enc.encode(normalizeHex(args.commitmentHex)),
    enc.encode(":"),
    enc.encode(normalizeHex(args.nonceId)),
  ];
  return bytesToHex(sha256(concat(parts)));
}

/**
 * Re-compute the V2 round2 worker transcript hash. Byte-identical with
 * `crypto-worker-rust::ca_registration_v2::round2_worker_transcript_hash`.
 */
export function caRegistrationV2Round2WorkerTranscriptHash(args: {
  sessionId: string;
  requestId: string;
  dkgEpoch: string;
  caDkgTranscriptHash: string;
  sortedSelectedSlots: number[];
  selfSlot: number;
  playerId: number;
  nonceId: string;
  challenge: string;
  responseHash: string;
}): HexString {
  const enc = new TextEncoder();
  const slots = args.sortedSelectedSlots.map((s) => s.toString()).join(",");
  const parts: Uint8Array[] = [
    enc.encode(CA_REGISTRATION_V2_ROUND2_DOMAIN),
    enc.encode(":"),
    enc.encode(args.sessionId),
    enc.encode(":"),
    enc.encode(args.requestId),
    enc.encode(":"),
    enc.encode(args.dkgEpoch),
    enc.encode(":"),
    enc.encode(normalizeHex(args.caDkgTranscriptHash)),
    enc.encode(":"),
    enc.encode(slots),
    enc.encode(":"),
    enc.encode(args.selfSlot.toString()),
    enc.encode(":"),
    enc.encode(args.playerId.toString()),
    enc.encode(":"),
    enc.encode(normalizeHex(args.nonceId)),
    enc.encode(":"),
    enc.encode(normalizeHex(args.challenge)),
    enc.encode(":"),
    enc.encode(normalizeHex(args.responseHash)),
  ];
  return bytesToHex(sha256(concat(parts)));
}

/**
 * Coordinator-side final transcript hash binding every public input + every per-slot
 * artifact. Stable for replay verification + audit.
 */
export function caRegistrationV2FinalTranscriptHash(input: {
  dkgEpoch: string;
  caDkgTranscriptHash: string;
  rosterHash: string;
  sortedSelectedSlots: number[];
  vaultEk: string;
  senderAddress: string;
  assetType: string;
  chainId: number;
  aggregateCommitment: string;
  aggregateResponse: string;
  challenge: string;
  perSlotContributions: CaRegistrationV2Contribution[];
}): HexString {
  const enc = new TextEncoder();
  const slots = input.sortedSelectedSlots.map((s) => s.toString()).join(",");
  const parts: Uint8Array[] = [
    enc.encode(CA_REGISTRATION_V2_FINAL_DOMAIN),
    enc.encode(":"),
    enc.encode(input.dkgEpoch),
    enc.encode(":"),
    enc.encode(normalizeHex(input.caDkgTranscriptHash)),
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
  // Stable ordering by slot for the per-slot section.
  const sorted = [...input.perSlotContributions].sort((a, b) => a.slot - b.slot);
  for (const c of sorted) {
    parts.push(enc.encode(":"));
    parts.push(enc.encode(c.slot.toString()));
    parts.push(enc.encode("|"));
    parts.push(enc.encode(normalizeHex(c.commitmentHex)));
    parts.push(enc.encode("|"));
    parts.push(enc.encode(normalizeHex(c.responseHex)));
    parts.push(enc.encode("|"));
    parts.push(enc.encode(normalizeHex(c.workerRound1TranscriptHash)));
    parts.push(enc.encode("|"));
    parts.push(enc.encode(normalizeHex(c.workerRound2TranscriptHash)));
  }
  return bytesToHex(sha256(concat(parts)));
}

/**
 * Validate a coordinator-assembled V2 transcript artifact. Returns the normalized
 * artifact (lowercased hex everywhere, sorted selectedSlots). Throws if any required
 * field is missing or malformed.
 *
 * CP5 RC3 (multi-asset) invariant — PER-ASSET TRANSCRIPT, ONE SHARED vault_ek:
 *   - `assetType` is a REAL per-asset arg: it is bound into the round1 / round2 / final
 *     transcript hashes (so a sigma registration for cUSDC can never be replayed for APT, and
 *     vice versa). Each ACTIVE asset gets its own CA-registration transcript keyed on its
 *     assetType — there is no singleton asset assumption here.
 *   - `vaultEk` is the ONE shared threshold CA encryption key (T1: one resource-account vault,
 *     one vault_ek across all assets — see eunoma_bridge.move::activate_asset_ca_v4 asserting
 *     `st.vault_ek == DeoperatorConfigV2.vault_ek`). This module NEVER derives a second vault_ek;
 *     the caller passes the SAME provenance-verified vault_ek for every asset. Re-running
 *     CA registration for a new assetType reuses that shared vault_ek — it does not, and must
 *     not, trigger a fresh vault_ek DKG.
 */
export function assembleCaRegistrationV2Transcript(input: {
  dkgEpoch: string;
  caDkgTranscriptHash: string;
  rosterHash: string;
  selectedSlots: number[];
  verifierSlot: number;
  vaultEk: string;
  senderAddress: string;
  assetType: string;
  chainId: number;
  aggregateCommitment: string;
  aggregateResponse: string;
  challenge: string;
  perSlotContributions: CaRegistrationV2Contribution[];
}): CaRegistrationV2Transcript {
  assertNoForbiddenPlaintextFields(input);
  if (!Array.isArray(input.selectedSlots) || input.selectedSlots.length !== DEOPERATOR_THRESHOLD) {
    throw new CaRegistrationV2Error(
      "UNDER_QUORUM",
      `selectedSlots must have ${DEOPERATOR_THRESHOLD} entries`,
    );
  }
  const seen = new Set<number>();
  for (const slot of input.selectedSlots) {
    if (!Number.isInteger(slot) || slot < 0 || slot >= DEOPERATOR_COUNT) {
      throw new CaRegistrationV2Error("UNKNOWN_SLOT", `slot ${slot} out of range`);
    }
    if (seen.has(slot)) {
      throw new CaRegistrationV2Error("DUPLICATE_SLOT", `duplicate slot ${slot}`);
    }
    seen.add(slot);
  }
  if (!Number.isInteger(input.verifierSlot) || !seen.has(input.verifierSlot)) {
    throw new CaRegistrationV2Error("UNKNOWN_SLOT", "verifierSlot must be in selectedSlots");
  }
  if (
    !Array.isArray(input.perSlotContributions) ||
    input.perSlotContributions.length !== DEOPERATOR_THRESHOLD
  ) {
    throw new CaRegistrationV2Error(
      "UNDER_QUORUM",
      `perSlotContributions must have ${DEOPERATOR_THRESHOLD} entries`,
    );
  }
  if (!/^[0-9]+$/.test(input.dkgEpoch)) {
    throw new CaRegistrationV2Error(
      "STALE_DKG_EPOCH",
      "dkgEpoch must be a non-empty decimal string",
    );
  }
  const sortedSlots = [...input.selectedSlots].sort((a, b) => a - b);
  const normalized = (hex: string, expected: number) => {
    const norm = normalizeHex(hex);
    const bytes = hexToBytes(norm);
    if (bytes.length !== expected) {
      throw new CaRegistrationV2Error(
        "INVALID_CONTRIBUTION_SHAPE",
        `expected ${expected}-byte hex, got ${bytes.length}`,
      );
    }
    return norm;
  };

  const caDkgTranscriptHash = normalized(input.caDkgTranscriptHash, 32);
  const rosterHash = normalized(input.rosterHash, 32);
  const vaultEk = normalized(input.vaultEk, 32);
  const senderAddress = normalized(input.senderAddress, 32);
  const assetType = normalized(input.assetType, 32);
  const aggregateCommitment = normalized(input.aggregateCommitment, 32);
  const aggregateResponse = normalized(input.aggregateResponse, 32);
  const challenge = normalized(input.challenge, 32);
  if (!Number.isInteger(input.chainId) || input.chainId < 0 || input.chainId > 255) {
    throw new CaRegistrationV2Error("INVALID_CONTRIBUTION_SHAPE", "chainId must be a u8");
  }

  const seenContribution = new Set<number>();
  const normalizedContributions: CaRegistrationV2Contribution[] = [];
  for (const c of input.perSlotContributions) {
    if (!Number.isInteger(c.slot) || c.slot < 0 || c.slot >= DEOPERATOR_COUNT) {
      throw new CaRegistrationV2Error("UNKNOWN_SLOT", `contribution slot ${c.slot} out of range`);
    }
    if (!seen.has(c.slot)) {
      throw new CaRegistrationV2Error(
        "UNKNOWN_SLOT",
        `contribution slot ${c.slot} not in selectedSlots`,
      );
    }
    if (seenContribution.has(c.slot)) {
      throw new CaRegistrationV2Error("DUPLICATE_SLOT", `duplicate contribution slot ${c.slot}`);
    }
    seenContribution.add(c.slot);
    normalizedContributions.push({
      slot: c.slot,
      commitmentHex: normalized(c.commitmentHex, 32),
      responseHex: normalized(c.responseHex, 32),
      workerRound1TranscriptHash: normalized(c.workerRound1TranscriptHash, 32),
      workerRound2TranscriptHash: normalized(c.workerRound2TranscriptHash, 32),
    });
  }

  const transcriptHash = caRegistrationV2FinalTranscriptHash({
    dkgEpoch: input.dkgEpoch,
    caDkgTranscriptHash,
    rosterHash,
    sortedSelectedSlots: sortedSlots,
    vaultEk,
    senderAddress,
    assetType,
    chainId: input.chainId,
    aggregateCommitment,
    aggregateResponse,
    challenge,
    perSlotContributions: normalizedContributions,
  });

  return {
    scheme: "ca_registration_v2",
    dkgEpoch: input.dkgEpoch,
    caDkgTranscriptHash,
    rosterHash,
    selectedSlots: sortedSlots,
    verifierSlot: input.verifierSlot,
    vaultEk,
    senderAddress,
    assetType,
    chainId: input.chainId,
    aggregateCommitment,
    aggregateResponse,
    challenge,
    perSlotContributions: normalizedContributions,
    transcriptHash,
    createdAtUnixMs: 0,
  };
}

// =============================================================================================
// Parsers — strict-validate untrusted JSON wire bodies before they reach the orchestrator.
// =============================================================================================

function objectBody(body: unknown): Record<string, unknown> {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new CaRegistrationV2Error("INVALID_CONTRIBUTION_SHAPE", "body must be an object");
  }
  return body as Record<string, unknown>;
}

function requireString(obj: Record<string, unknown>, key: string): string {
  const value = obj[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new CaRegistrationV2Error("INVALID_CONTRIBUTION_SHAPE", `${key} must be a string`);
  }
  return value;
}

function requireHex(obj: Record<string, unknown>, key: string, bytes: number): HexString {
  const raw = requireString(obj, key);
  const normalized = normalizeHex(raw);
  if (hexToBytes(normalized).length !== bytes) {
    throw new CaRegistrationV2Error(
      "INVALID_CONTRIBUTION_SHAPE",
      `${key} must be ${bytes}-byte hex`,
    );
  }
  return normalized;
}

function requireInt(obj: Record<string, unknown>, key: string, min: number, max: number): number {
  const value = obj[key];
  if (!Number.isInteger(value) || (value as number) < min || (value as number) > max) {
    throw new CaRegistrationV2Error(
      "INVALID_CONTRIBUTION_SHAPE",
      `${key} must be an integer in [${min}, ${max}]`,
    );
  }
  return value as number;
}

function requireSelectedSlots(obj: Record<string, unknown>, key: string): number[] {
  const value = obj[key];
  if (!Array.isArray(value) || value.length !== DEOPERATOR_THRESHOLD) {
    throw new CaRegistrationV2Error(
      "UNDER_QUORUM",
      `${key} must have ${DEOPERATOR_THRESHOLD} entries`,
    );
  }
  const seen = new Set<number>();
  for (const slot of value) {
    if (!Number.isInteger(slot) || (slot as number) < 0 || (slot as number) >= DEOPERATOR_COUNT) {
      throw new CaRegistrationV2Error("UNKNOWN_SLOT", `${key} entry ${slot} out of range`);
    }
    if (seen.has(slot as number)) {
      throw new CaRegistrationV2Error("DUPLICATE_SLOT", `${key} duplicate ${slot}`);
    }
    seen.add(slot as number);
  }
  return value as number[];
}

export function parseCaRegistrationV2Round1Request(
  body: unknown,
): CaRegistrationV2Round1Request {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  return {
    dkgEpoch: requireString(obj, "dkgEpoch"),
    requestId: requireString(obj, "requestId"),
    sessionId: requireString(obj, "sessionId"),
    caDkgTranscriptHash: requireHex(obj, "caDkgTranscriptHash", 32),
    rosterHash: requireHex(obj, "rosterHash", 32),
    selectedSlots: requireSelectedSlots(obj, "selectedSlots"),
    selfSlot: requireInt(obj, "selfSlot", 0, DEOPERATOR_COUNT - 1),
    playerId: requireInt(obj, "playerId", 0, DEOPERATOR_THRESHOLD - 1),
    vaultEk: requireHex(obj, "vaultEk", 32),
    senderAddress: requireHex(obj, "senderAddress", 32),
    assetType: requireHex(obj, "assetType", 32),
    chainId: requireInt(obj, "chainId", 0, 255),
  };
}

export function parseCaRegistrationV2Round1Response(
  body: unknown,
): CaRegistrationV2Round1Response {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  return {
    slot: requireInt(obj, "slot", 0, DEOPERATOR_COUNT - 1),
    commitmentHex: requireHex(obj, "commitmentHex", 32),
    commitmentHash: requireHex(obj, "commitmentHash", 32),
    nonceId: requireHex(obj, "nonceId", 32),
    workerTranscriptHash: requireHex(obj, "workerTranscriptHash", 32),
  };
}

export function parseCaRegistrationV2Round2Request(
  body: unknown,
): CaRegistrationV2Round2Request {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  return {
    dkgEpoch: requireString(obj, "dkgEpoch"),
    requestId: requireString(obj, "requestId"),
    sessionId: requireString(obj, "sessionId"),
    caDkgTranscriptHash: requireHex(obj, "caDkgTranscriptHash", 32),
    rosterHash: requireHex(obj, "rosterHash", 32),
    selectedSlots: requireSelectedSlots(obj, "selectedSlots"),
    selfSlot: requireInt(obj, "selfSlot", 0, DEOPERATOR_COUNT - 1),
    playerId: requireInt(obj, "playerId", 0, DEOPERATOR_THRESHOLD - 1),
    nonceId: requireHex(obj, "nonceId", 32),
    challenge: requireHex(obj, "challenge", 32),
  };
}

export function parseCaRegistrationV2Round2Response(
  body: unknown,
): CaRegistrationV2Round2Response {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  return {
    slot: requireInt(obj, "slot", 0, DEOPERATOR_COUNT - 1),
    responseHex: requireHex(obj, "responseHex", 32),
    responseHash: requireHex(obj, "responseHash", 32),
    workerTranscriptHash: requireHex(obj, "workerTranscriptHash", 32),
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

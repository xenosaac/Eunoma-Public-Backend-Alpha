import { bytesToHex, hexToBytes, normalizeHex, sha256 } from "@eunoma/shared";
import { DEOPERATOR_COUNT, DEOPERATOR_THRESHOLD } from "./constants.js";
import { assertNoForbiddenPlaintextFields } from "./forbidden.js";
import { caDkgV2RosterHash } from "./roster.js";
import type {
  CaDkgV2Roster,
  VaultEkContribution,
  VaultEkDerivationCode,
  VaultEkDerivationInput,
  VaultEkDerivationTranscript,
} from "./types.js";

/**
 * Canonical byte layout for the per-worker transcript hash. MUST stay byte-identical with
 * crypto-worker-rust::vault_ek_derivation_v2::worker_transcript_hash so a worker's hash can be
 * recomputed and cross-checked off-cluster.
 *
 *   "EUNOMA_VAULT_EK_DERIVATION_V1"
 *   || dkg_epoch_string_bytes
 *   || ":"
 *   || ca_dkg_transcript_hash_normalized_lowercase_hex_bytes
 *   || ":"
 *   || roster_hash_normalized_lowercase_hex_bytes
 *   || ":"
 *   || joined("," sorted_selected_slots, decimal)
 *   || ":"
 *   || slot_decimal_bytes
 *   || ":"
 *   || h_contribution_normalized_lowercase_hex_bytes
 *   -> SHA256 -> lowercase hex
 */
export const VAULT_EK_DERIVATION_WORKER_DOMAIN = "EUNOMA_VAULT_EK_DERIVATION_V1";

export class VaultEkDerivationError extends Error {
  constructor(public readonly code: VaultEkDerivationCode, message: string) {
    super(message);
    this.name = "VaultEkDerivationError";
  }
}

export function assembleVaultEkTranscript(
  input: VaultEkDerivationInput,
): VaultEkDerivationTranscript {
  assertNoForbiddenPlaintextFields(input);

  if (!Array.isArray(input.contributions) || input.contributions.length !== DEOPERATOR_THRESHOLD) {
    throw new VaultEkDerivationError(
      "UNDER_QUORUM",
      `contributions must have ${DEOPERATOR_THRESHOLD} entries, got ${
        Array.isArray(input.contributions) ? input.contributions.length : "non-array"
      }`,
    );
  }
  if (!Array.isArray(input.selectedSlots) || input.selectedSlots.length !== DEOPERATOR_THRESHOLD) {
    throw new VaultEkDerivationError(
      "UNDER_QUORUM",
      `selectedSlots must have ${DEOPERATOR_THRESHOLD} entries, got ${
        Array.isArray(input.selectedSlots) ? input.selectedSlots.length : "non-array"
      }`,
    );
  }

  const seenSelected = new Set<number>();
  for (const slot of input.selectedSlots) {
    if (!Number.isInteger(slot) || slot < 0 || slot >= DEOPERATOR_COUNT) {
      throw new VaultEkDerivationError(
        "UNKNOWN_SLOT",
        `selectedSlots entry ${slot} is not a valid deoperator slot`,
      );
    }
    if (seenSelected.has(slot)) {
      throw new VaultEkDerivationError("DUPLICATE_SLOT", `duplicate selectedSlots entry ${slot}`);
    }
    seenSelected.add(slot);
  }

  const rosterSlots = new Set(input.roster.nodes.map((node) => node.slot));
  for (const slot of input.selectedSlots) {
    if (!rosterSlots.has(slot)) {
      throw new VaultEkDerivationError(
        "UNKNOWN_SLOT",
        `selectedSlots entry ${slot} is not in CaDkgV2Roster`,
      );
    }
  }

  const computedRosterHash = caDkgV2RosterHash(input.roster);
  let rosterHashNorm: string;
  try {
    rosterHashNorm = normalizeHexBytes(input.rosterHash, 32);
  } catch {
    throw new VaultEkDerivationError(
      "STALE_ROSTER_HASH",
      `rosterHash is not a 32-byte hex string`,
    );
  }
  if (rosterHashNorm !== normalizeHex(computedRosterHash)) {
    throw new VaultEkDerivationError(
      "STALE_ROSTER_HASH",
      `rosterHash ${rosterHashNorm} does not match caDkgV2RosterHash(roster) ${normalizeHex(computedRosterHash)}`,
    );
  }
  if (String(input.roster.dkgEpoch) !== String(input.dkgEpoch)) {
    throw new VaultEkDerivationError(
      "STALE_DKG_EPOCH",
      `roster.dkgEpoch ${input.roster.dkgEpoch} does not match input.dkgEpoch ${input.dkgEpoch}`,
    );
  }
  if (!/^[0-9]+$/.test(String(input.dkgEpoch))) {
    throw new VaultEkDerivationError(
      "STALE_DKG_EPOCH",
      `dkgEpoch must be a non-empty decimal string, got ${input.dkgEpoch}`,
    );
  }

  let caDkgTranscriptHashNorm: string;
  try {
    caDkgTranscriptHashNorm = normalizeHexBytes(input.caDkgTranscriptHash, 32);
  } catch {
    throw new VaultEkDerivationError(
      "STALE_CA_DKG_TRANSCRIPT_HASH",
      `caDkgTranscriptHash is not a 32-byte hex string`,
    );
  }

  const sortedSlots = [...input.selectedSlots].sort((a, b) => a - b);
  const selectedSet = new Set(sortedSlots);
  const seenContribution = new Set<number>();

  for (const contribution of input.contributions) {
    if (!Number.isInteger(contribution.slot) || contribution.slot < 0 || contribution.slot >= DEOPERATOR_COUNT) {
      throw new VaultEkDerivationError(
        "INVALID_CONTRIBUTION_SHAPE",
        `contribution slot ${contribution.slot} is not a valid deoperator slot`,
      );
    }
    if (!selectedSet.has(contribution.slot)) {
      throw new VaultEkDerivationError(
        "DUPLICATE_SLOT",
        `contribution slot ${contribution.slot} is not in selectedSlots`,
      );
    }
    if (seenContribution.has(contribution.slot)) {
      throw new VaultEkDerivationError(
        "DUPLICATE_SLOT",
        `duplicate contribution for slot ${contribution.slot}`,
      );
    }
    seenContribution.add(contribution.slot);

    let hContributionNorm: string;
    let workerHashNorm: string;
    try {
      hContributionNorm = normalizeHexBytes(contribution.hContribution, 32);
      normalizeHexBytes(contribution.schnorrProof?.R, 32);
      normalizeHexBytes(contribution.schnorrProof?.s, 32);
      workerHashNorm = normalizeHexBytes(contribution.workerTranscriptHash, 32);
    } catch (err) {
      throw new VaultEkDerivationError(
        "INVALID_CONTRIBUTION_SHAPE",
        `contribution slot ${contribution.slot} has invalid hex: ${
          err instanceof Error ? err.message : "unknown"
        }`,
      );
    }

    const expectedHash = workerTranscriptHashCanonical({
      dkgEpoch: String(input.dkgEpoch),
      caDkgTranscriptHash: caDkgTranscriptHashNorm,
      rosterHash: rosterHashNorm,
      sortedSelectedSlots: sortedSlots,
      slot: contribution.slot,
      hContribution: hContributionNorm,
    });
    if (workerHashNorm !== expectedHash) {
      throw new VaultEkDerivationError(
        "INVALID_CONTRIBUTION_SHAPE",
        `worker_transcript_hash mismatch for slot ${contribution.slot}: expected ${expectedHash}, got ${workerHashNorm}`,
      );
    }
  }

  const normalizedContributions: VaultEkContribution[] = input.contributions.map((contribution) => ({
    slot: contribution.slot,
    hContribution: normalizeHexBytes(contribution.hContribution, 32),
    schnorrProof: {
      R: normalizeHexBytes(contribution.schnorrProof.R, 32),
      s: normalizeHexBytes(contribution.schnorrProof.s, 32),
    },
    workerTranscriptHash: normalizeHexBytes(contribution.workerTranscriptHash, 32),
  }));

  return {
    scheme: "vault_ek_derivation_v1",
    dkgEpoch: String(input.dkgEpoch),
    caDkgTranscriptHash: caDkgTranscriptHashNorm,
    selectedSlots: sortedSlots,
    rosterHash: rosterHashNorm,
    contributions: normalizedContributions,
  };
}

export function workerTranscriptHashCanonical(args: {
  dkgEpoch: string;
  caDkgTranscriptHash: string;
  rosterHash: string;
  sortedSelectedSlots: number[];
  slot: number;
  hContribution: string;
}): string {
  const ca = normalizeHex(args.caDkgTranscriptHash);
  const roster = normalizeHex(args.rosterHash);
  const h = normalizeHex(args.hContribution);
  const slotsJoined = args.sortedSelectedSlots.map((slot) => slot.toString()).join(",");

  const parts: Uint8Array[] = [
    new TextEncoder().encode(VAULT_EK_DERIVATION_WORKER_DOMAIN),
    new TextEncoder().encode(String(args.dkgEpoch)),
    new TextEncoder().encode(":"),
    new TextEncoder().encode(ca),
    new TextEncoder().encode(":"),
    new TextEncoder().encode(roster),
    new TextEncoder().encode(":"),
    new TextEncoder().encode(slotsJoined),
    new TextEncoder().encode(":"),
    new TextEncoder().encode(args.slot.toString()),
    new TextEncoder().encode(":"),
    new TextEncoder().encode(h),
  ];
  let total = 0;
  for (const part of parts) total += part.byteLength;
  const buf = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    buf.set(part, offset);
    offset += part.byteLength;
  }
  return bytesToHex(sha256(buf));
}

function normalizeHexBytes(input: unknown, expected: number): string {
  if (typeof input !== "string") {
    throw new Error("expected string");
  }
  const normalized = normalizeHex(input);
  const bytes = hexToBytes(normalized);
  if (bytes.length !== expected) {
    throw new Error(`expected ${expected} bytes, got ${bytes.length}`);
  }
  return normalized;
}

export function parseVaultEkContribution(value: unknown): VaultEkContribution {
  assertNoForbiddenPlaintextFields(value);
  if (!value || typeof value !== "object") {
    throw new VaultEkDerivationError("INVALID_CONTRIBUTION_SHAPE", "contribution must be an object");
  }
  const obj = value as Record<string, unknown>;
  const slot = obj.slot;
  if (!Number.isInteger(slot) || (slot as number) < 0 || (slot as number) >= DEOPERATOR_COUNT) {
    throw new VaultEkDerivationError(
      "INVALID_CONTRIBUTION_SHAPE",
      `contribution.slot must be a deoperator slot, got ${slot}`,
    );
  }
  const proofObj =
    obj.schnorrProof && typeof obj.schnorrProof === "object"
      ? (obj.schnorrProof as Record<string, unknown>)
      : undefined;
  let hContribution: string;
  let proofR: string;
  let proofS: string;
  let workerTranscriptHash: string;
  try {
    hContribution = normalizeHexBytes(obj.hContribution, 32);
    proofR = normalizeHexBytes(proofObj?.R, 32);
    proofS = normalizeHexBytes(proofObj?.s, 32);
    workerTranscriptHash = normalizeHexBytes(obj.workerTranscriptHash, 32);
  } catch (err) {
    throw new VaultEkDerivationError(
      "INVALID_CONTRIBUTION_SHAPE",
      err instanceof Error ? err.message : "invalid hex",
    );
  }
  return {
    slot: slot as number,
    hContribution,
    schnorrProof: { R: proofR, s: proofS },
    workerTranscriptHash,
  };
}

export function parseVaultEkContributions(value: unknown): VaultEkContribution[] {
  if (!Array.isArray(value)) {
    throw new VaultEkDerivationError("INVALID_CONTRIBUTION_SHAPE", "contributions must be an array");
  }
  return value.map((item) => parseVaultEkContribution(item));
}


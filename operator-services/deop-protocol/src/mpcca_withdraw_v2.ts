import { bytesToHex, hexToBytes, normalizeHex, sha256 } from "@eunoma/shared";
import type { HexString } from "@eunoma/shared";
import { DEOPERATOR_COUNT, DEOPERATOR_THRESHOLD } from "./constants.js";
import { assertNoForbiddenPlaintextFields } from "./forbidden.js";

/**
 * Milestone 3 sub-milestone 3a — MPCCA withdraw state machine scaffolding.
 *
 * After Phase 2 (vault_ek), Milestone 1 (CA registration sigma), Milestone 2a (per-worker
 * vault_state_v2.json), and Milestone 2b (deposit observer cursor advancement) all land, the
 * coordinator can begin driving a withdraw against a vault. The MPCCA withdraw state machine
 * runs in four rounds:
 *
 *   round1   — per-slot nonce generation + commitment broadcast (TS layer in 3a, crypto stub).
 *   round2   — per-slot partial sigma response over the Round-1 aggregate (3b).
 *   prove    — collaborative range/correctness proof (Bulletproof shares) over the partial
 *              outputs (3c).
 *   finalize — aggregate the partial outputs + range proof into the withdraw transcript that
 *              gets posted on-chain (3d).
 *
 * Sub-milestone 3a ships ONLY round1 — and even round1's crypto core is a NotImplemented stub:
 * the per-worker handler does the FULL public-binding work (id safety, hex normalisation,
 * provenance gate against `vault_state_v2.json`, Milestone 1 sigma re-verify) BEFORE returning
 * `NotImplemented("mpcca_withdraw_v2_round1_nonce_generation_pending_milestone4")`. The
 * load-bearing public binding is in place so milestone 4 can fill the crypto in without
 * rewriting the request validation / replay / provenance plumbing.
 *
 * Why this matters: a tampered request (wrong vault_ek, wrong sigma, stale provenance) must
 * surface a SPECIFIC validation error TODAY — not a generic NotImplemented after milestone 4
 * fills in the crypto. The hard test (`mpcca_withdraw_v2_round1_surfaces_not_implemented_after_provenance_verifies`)
 * asserts the wedge: happy-path → NotImplemented; tampered vault_ek → Crypto (sigma rejects
 * earlier); stale provenance → InvalidDkgState.
 */

// =================================================================================================
// Domain constants — one per round + a final-transcript domain. Each per-round worker hash binds
// the round name into its domain so cross-round transcript replay is impossible by construction.
// =================================================================================================
export const EUNOMA_MPCCA_WITHDRAW_V2_ROUND1_V1 = "EUNOMA_MPCCA_WITHDRAW_V2_ROUND1_V1";
export const EUNOMA_MPCCA_WITHDRAW_V2_ROUND2_V1 = "EUNOMA_MPCCA_WITHDRAW_V2_ROUND2_V1";
export const EUNOMA_MPCCA_WITHDRAW_V2_PROVE_V1 = "EUNOMA_MPCCA_WITHDRAW_V2_PROVE_V1";
export const EUNOMA_MPCCA_WITHDRAW_V2_FINALIZE_V1 = "EUNOMA_MPCCA_WITHDRAW_V2_FINALIZE_V1";
export const EUNOMA_MPCCA_WITHDRAW_V2_FINAL_V1 = "EUNOMA_MPCCA_WITHDRAW_V2_FINAL_V1";

// =================================================================================================
// Error codes — every failure mode the orchestrator + worker can surface. Mapped to HTTP status
// codes by the orchestrator (400 = caller error, 502 = worker reply tampered, 501 = stub).
// =================================================================================================
export type MpccaWithdrawV2ErrorCode =
  | "UNDER_QUORUM"
  | "DUPLICATE_SLOT"
  | "UNKNOWN_SLOT"
  | "STALE_DKG_EPOCH"
  | "STALE_ROSTER_HASH"
  | "STALE_VAULT_SEQUENCE"
  | "MISSING_VAULT_STATE_FILE"
  | "OBSERVED_DEPOSIT_NOT_FOUND"
  | "CRYPTO_STUB_PHASE_DIVERGENCE"
  | "INVALID_WITHDRAW_FIELD_SHAPE"
  | "INVALID_CONTRIBUTION_SHAPE";

export class MpccaWithdrawV2Error extends Error {
  constructor(
    public readonly code: MpccaWithdrawV2ErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "MpccaWithdrawV2Error";
  }
}

// =================================================================================================
// Per-round Request shapes. All four rounds share the same provenance + identity envelope:
//   - dkgEpoch, requestId, sessionId — caller identifiers, FS-safe.
//   - rosterHash, selectedSlots, selfSlot, playerId — 5-of-7 plumbing.
//   - vaultEkTranscriptHash, registrationTranscriptHash, vaultStateInitTranscriptHash — cross-
//     reference into Phase 2 / Milestone 1 / Milestone 2a transcripts; the coordinator's
//     provenance gate has already verified these match a persisted artifact.
//   - observedDepositTranscriptHashes[] — every Milestone 2b observe-deposit transcript that
//     the withdraw is consuming (one per observed deposit since the last withdraw, in cursor
//     order). Binds the per-vault deposit ordering into the withdraw transcript so an auditor
//     can confirm the withdraw consumes exactly the observed deposits.
//   - vaultEk + senderAddress + assetType + chainId — public chain-side identity. Same shape
//     as Milestone 1 + Milestone 2a + Milestone 2b.
//   - Per-withdraw envelope: root, nullifierHash, recipient, recipientHash, amountTag,
//     vaultSequence, expirySecs, requestHash, depositCount.
//   - Optional cross-round chaining: previousRoundTranscriptHash + previousRoundCommitments,
//     filled by the coordinator for rounds 2/prove/finalize.
//
// All round bodies pass through the forbidden-plaintext-field guard FIRST (see parseMpccaWithdraw…
// functions). The HARD invariant is: amount/blind/secret/dk*/share/nullifier-class field names
// MUST NEVER appear in any of these bodies.
// =================================================================================================
interface MpccaWithdrawBaseRequest {
  dkgEpoch: string;
  requestId: string;
  sessionId: string;
  vaultEkTranscriptHash: HexString;
  registrationTranscriptHash: HexString;
  vaultStateInitTranscriptHash: HexString;
  observedDepositTranscriptHashes: HexString[];
  rosterHash: HexString;
  selectedSlots: number[];
  selfSlot: number;
  playerId: number;
  vaultEk: HexString;
  senderAddress: HexString;
  assetType: HexString;
  chainId: number;
  root: HexString;
  nullifierHash: HexString;
  recipient: HexString;
  recipientHash: HexString;
  amountTag: HexString;
  vaultSequence: number;
  expirySecs: number;
  requestHash: HexString;
  depositCount: number;
}

interface MpccaWithdrawChainedRequest extends MpccaWithdrawBaseRequest {
  /** Hash of the immediately-previous round's coordinator transcript artifact. */
  previousRoundTranscriptHash: HexString;
  /** Aggregate of per-slot commitments from the previous round, in selectedSlots order. */
  previousRoundCommitments: HexString[];
}

export type MpccaWithdrawRound1Request = MpccaWithdrawBaseRequest;
export type MpccaWithdrawRound2Request = MpccaWithdrawChainedRequest;
export type MpccaWithdrawProveRequest = MpccaWithdrawChainedRequest;
export type MpccaWithdrawFinalizeRequest = MpccaWithdrawChainedRequest;

// =================================================================================================
// Per-round Response shapes. Each round returns a per-slot "contribution" (commitment, partial
// response, partial bulletproof share, partial CA payload field bytes — whichever applies). On
// the NotImplemented stub path (milestone 3a), the response still carries the public binding
// outputs (session_state_path, session_state_hash, worker_transcript_hash) so the coordinator
// can persist the partial round transcript even though the crypto is pending milestone 4.
// =================================================================================================
interface MpccaWithdrawBaseResponse {
  slot: number;
  playerId: number;
  sessionStatePath: string;
  sessionStateHash: HexString;
  workerTranscriptHash: HexString;
  observedAtUnixMs: number;
  completed: false;
  notImplementedPhase: string;
}

export interface MpccaWithdrawRound1Response extends MpccaWithdrawBaseResponse {
  /** Per-slot Round 1 commitment (32-byte hex). undefined under the milestone 3a stub. */
  roundCommitment?: HexString;
}

export interface MpccaWithdrawRound2Response extends MpccaWithdrawBaseResponse {
  /** Per-slot Round 2 partial sigma response (32-byte hex scalar). */
  partialResponse?: HexString;
}

export interface MpccaWithdrawProveResponse extends MpccaWithdrawBaseResponse {
  /** Per-slot Bulletproof partial share (bytes hex). */
  partialBulletproofShare?: HexString;
}

export interface MpccaWithdrawFinalizeResponse extends MpccaWithdrawBaseResponse {
  /** Per-slot CA payload partial bytes that the finalize aggregator collects. */
  partialCaPayloadFields?: HexString;
}

// =================================================================================================
// Per-round Contribution — the slim shape the coordinator persists in the round transcript.
// Mirrors the (slot, contribution-hash, worker-transcript-hash) triple pattern from
// vault_state_v2 + ca_registration_v2.
// =================================================================================================
interface MpccaWithdrawBaseContribution {
  slot: number;
  sessionStateHash: HexString;
  workerTranscriptHash: HexString;
  completed: false;
  notImplementedPhase: string;
}

export interface MpccaWithdrawRound1Contribution extends MpccaWithdrawBaseContribution {
  roundCommitment?: HexString;
}

export interface MpccaWithdrawRound2Contribution extends MpccaWithdrawBaseContribution {
  partialResponse?: HexString;
}

export interface MpccaWithdrawProveContribution extends MpccaWithdrawBaseContribution {
  partialBulletproofShare?: HexString;
}

export interface MpccaWithdrawFinalizeContribution extends MpccaWithdrawBaseContribution {
  partialCaPayloadFields?: HexString;
}

// =================================================================================================
// Final assembled coordinator transcript — built when finalize completes. In milestone 3a only
// round1's partial transcript is persisted; this type lives in this module so coordinator code
// can use it consistently once the milestone 4 crypto fills in.
// =================================================================================================
export interface MpccaWithdrawTranscript {
  scheme: "mpcca_withdraw_v2";
  dkgEpoch: string;
  requestId: string;
  vaultEkTranscriptHash: HexString;
  registrationTranscriptHash: HexString;
  vaultStateInitTranscriptHash: HexString;
  observedDepositTranscriptHashes: HexString[];
  rosterHash: HexString;
  selectedSlots: number[];
  vaultEk: HexString;
  senderAddress: HexString;
  assetType: HexString;
  chainId: number;
  root: HexString;
  nullifierHash: HexString;
  recipient: HexString;
  recipientHash: HexString;
  amountTag: HexString;
  vaultSequence: number;
  expirySecs: number;
  requestHash: HexString;
  depositCount: number;
  round1Contributions: MpccaWithdrawRound1Contribution[];
  round2Contributions: MpccaWithdrawRound2Contribution[];
  proveContributions: MpccaWithdrawProveContribution[];
  finalizeContributions: MpccaWithdrawFinalizeContribution[];
  transcriptHash: HexString;
  createdAtUnixMs: number;
}

// =================================================================================================
// Worker transcript hash reconstructors. Byte-identical with the Rust helpers in
// `crypto-worker-rust::mpcca_withdraw_v2::round{1,2,prove,finalize}_worker_transcript_hash`.
//
// Shape (round1):
//   "EUNOMA_MPCCA_WITHDRAW_V2_ROUND1_V1"
//   || ":" || session_id || ":" || request_id || ":" || dkg_epoch
//   || ":" || vault_ek_transcript_hash || ":" || registration_transcript_hash
//   || ":" || vault_state_init_transcript_hash
//   || ":" || joined(observed_deposit_transcript_hashes, ",")
//   || ":" || roster_hash || ":" || joined(sorted_selected_slots, ",")
//   || ":" || self_slot || ":" || player_id
//   || ":" || vault_ek || ":" || sender_address || ":" || asset_type
//   || ":" || chain_id (decimal)
//   || ":" || root || ":" || nullifier_hash || ":" || recipient || ":" || recipient_hash
//   || ":" || amount_tag || ":" || vault_sequence (decimal) || ":" || expiry_secs (decimal)
//   || ":" || request_hash || ":" || deposit_count (decimal)
//   → sha256 → lowercase hex.
//
// Rounds 2/prove/finalize extend the above by appending:
//   || ":" || previous_round_transcript_hash
//   || ":" || joined(previous_round_commitments, "|")
// =================================================================================================
function baseHashParts(args: {
  domain: string;
  sessionId: string;
  requestId: string;
  dkgEpoch: string;
  vaultEkTranscriptHash: string;
  registrationTranscriptHash: string;
  vaultStateInitTranscriptHash: string;
  observedDepositTranscriptHashes: string[];
  rosterHash: string;
  sortedSelectedSlots: number[];
  selfSlot: number;
  playerId: number;
  vaultEk: string;
  senderAddress: string;
  assetType: string;
  chainId: number;
  root: string;
  nullifierHash: string;
  recipient: string;
  recipientHash: string;
  amountTag: string;
  vaultSequence: number;
  expirySecs: number;
  requestHash: string;
  depositCount: number;
}): Uint8Array[] {
  const enc = new TextEncoder();
  const slots = args.sortedSelectedSlots.map((s) => s.toString()).join(",");
  const observedJoined = args.observedDepositTranscriptHashes
    .map(normalizeHex)
    .join(",");
  return [
    enc.encode(args.domain),
    enc.encode(":"),
    enc.encode(args.sessionId),
    enc.encode(":"),
    enc.encode(args.requestId),
    enc.encode(":"),
    enc.encode(args.dkgEpoch),
    enc.encode(":"),
    enc.encode(normalizeHex(args.vaultEkTranscriptHash)),
    enc.encode(":"),
    enc.encode(normalizeHex(args.registrationTranscriptHash)),
    enc.encode(":"),
    enc.encode(normalizeHex(args.vaultStateInitTranscriptHash)),
    enc.encode(":"),
    enc.encode(observedJoined),
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
    enc.encode(normalizeHex(args.root)),
    enc.encode(":"),
    enc.encode(normalizeHex(args.nullifierHash)),
    enc.encode(":"),
    enc.encode(normalizeHex(args.recipient)),
    enc.encode(":"),
    enc.encode(normalizeHex(args.recipientHash)),
    enc.encode(":"),
    enc.encode(normalizeHex(args.amountTag)),
    enc.encode(":"),
    enc.encode(args.vaultSequence.toString()),
    enc.encode(":"),
    enc.encode(args.expirySecs.toString()),
    enc.encode(":"),
    enc.encode(normalizeHex(args.requestHash)),
    enc.encode(":"),
    enc.encode(args.depositCount.toString()),
  ];
}

export function mpccaWithdrawRound1WorkerTranscriptHash(args: {
  sessionId: string;
  requestId: string;
  dkgEpoch: string;
  vaultEkTranscriptHash: string;
  registrationTranscriptHash: string;
  vaultStateInitTranscriptHash: string;
  observedDepositTranscriptHashes: string[];
  rosterHash: string;
  sortedSelectedSlots: number[];
  selfSlot: number;
  playerId: number;
  vaultEk: string;
  senderAddress: string;
  assetType: string;
  chainId: number;
  root: string;
  nullifierHash: string;
  recipient: string;
  recipientHash: string;
  amountTag: string;
  vaultSequence: number;
  expirySecs: number;
  requestHash: string;
  depositCount: number;
}): HexString {
  const parts = baseHashParts({
    domain: EUNOMA_MPCCA_WITHDRAW_V2_ROUND1_V1,
    ...args,
  });
  return bytesToHex(sha256(concat(parts)));
}

function chainedRoundHash(
  domain: string,
  args: {
    sessionId: string;
    requestId: string;
    dkgEpoch: string;
    vaultEkTranscriptHash: string;
    registrationTranscriptHash: string;
    vaultStateInitTranscriptHash: string;
    observedDepositTranscriptHashes: string[];
    rosterHash: string;
    sortedSelectedSlots: number[];
    selfSlot: number;
    playerId: number;
    vaultEk: string;
    senderAddress: string;
    assetType: string;
    chainId: number;
    root: string;
    nullifierHash: string;
    recipient: string;
    recipientHash: string;
    amountTag: string;
    vaultSequence: number;
    expirySecs: number;
    requestHash: string;
    depositCount: number;
    previousRoundTranscriptHash: string;
    previousRoundCommitments: string[];
  },
): HexString {
  const parts = baseHashParts({ domain, ...args });
  const enc = new TextEncoder();
  parts.push(enc.encode(":"));
  parts.push(enc.encode(normalizeHex(args.previousRoundTranscriptHash)));
  parts.push(enc.encode(":"));
  parts.push(
    enc.encode(args.previousRoundCommitments.map(normalizeHex).join("|")),
  );
  return bytesToHex(sha256(concat(parts)));
}

export function mpccaWithdrawRound2WorkerTranscriptHash(args: {
  sessionId: string;
  requestId: string;
  dkgEpoch: string;
  vaultEkTranscriptHash: string;
  registrationTranscriptHash: string;
  vaultStateInitTranscriptHash: string;
  observedDepositTranscriptHashes: string[];
  rosterHash: string;
  sortedSelectedSlots: number[];
  selfSlot: number;
  playerId: number;
  vaultEk: string;
  senderAddress: string;
  assetType: string;
  chainId: number;
  root: string;
  nullifierHash: string;
  recipient: string;
  recipientHash: string;
  amountTag: string;
  vaultSequence: number;
  expirySecs: number;
  requestHash: string;
  depositCount: number;
  previousRoundTranscriptHash: string;
  previousRoundCommitments: string[];
}): HexString {
  return chainedRoundHash(EUNOMA_MPCCA_WITHDRAW_V2_ROUND2_V1, args);
}

export function mpccaWithdrawProveWorkerTranscriptHash(args: {
  sessionId: string;
  requestId: string;
  dkgEpoch: string;
  vaultEkTranscriptHash: string;
  registrationTranscriptHash: string;
  vaultStateInitTranscriptHash: string;
  observedDepositTranscriptHashes: string[];
  rosterHash: string;
  sortedSelectedSlots: number[];
  selfSlot: number;
  playerId: number;
  vaultEk: string;
  senderAddress: string;
  assetType: string;
  chainId: number;
  root: string;
  nullifierHash: string;
  recipient: string;
  recipientHash: string;
  amountTag: string;
  vaultSequence: number;
  expirySecs: number;
  requestHash: string;
  depositCount: number;
  previousRoundTranscriptHash: string;
  previousRoundCommitments: string[];
}): HexString {
  return chainedRoundHash(EUNOMA_MPCCA_WITHDRAW_V2_PROVE_V1, args);
}

export function mpccaWithdrawFinalizeWorkerTranscriptHash(args: {
  sessionId: string;
  requestId: string;
  dkgEpoch: string;
  vaultEkTranscriptHash: string;
  registrationTranscriptHash: string;
  vaultStateInitTranscriptHash: string;
  observedDepositTranscriptHashes: string[];
  rosterHash: string;
  sortedSelectedSlots: number[];
  selfSlot: number;
  playerId: number;
  vaultEk: string;
  senderAddress: string;
  assetType: string;
  chainId: number;
  root: string;
  nullifierHash: string;
  recipient: string;
  recipientHash: string;
  amountTag: string;
  vaultSequence: number;
  expirySecs: number;
  requestHash: string;
  depositCount: number;
  previousRoundTranscriptHash: string;
  previousRoundCommitments: string[];
}): HexString {
  return chainedRoundHash(EUNOMA_MPCCA_WITHDRAW_V2_FINALIZE_V1, args);
}

// =================================================================================================
// Final transcript hash — binds the entire 4-round contribution set into one hash that lives in
// the coordinator's persisted artifact. Defensively scoped so milestone 4 can keep using it
// without revisiting the domain string.
// =================================================================================================
export function mpccaWithdrawFinalTranscriptHash(input: {
  dkgEpoch: string;
  vaultEkTranscriptHash: string;
  registrationTranscriptHash: string;
  vaultStateInitTranscriptHash: string;
  observedDepositTranscriptHashes: string[];
  rosterHash: string;
  sortedSelectedSlots: number[];
  vaultEk: string;
  senderAddress: string;
  assetType: string;
  chainId: number;
  root: string;
  nullifierHash: string;
  recipient: string;
  recipientHash: string;
  amountTag: string;
  vaultSequence: number;
  expirySecs: number;
  requestHash: string;
  depositCount: number;
  round1Contributions: MpccaWithdrawRound1Contribution[];
  round2Contributions: MpccaWithdrawRound2Contribution[];
  proveContributions: MpccaWithdrawProveContribution[];
  finalizeContributions: MpccaWithdrawFinalizeContribution[];
}): HexString {
  const enc = new TextEncoder();
  const slots = input.sortedSelectedSlots.map((s) => s.toString()).join(",");
  const observedJoined = input.observedDepositTranscriptHashes
    .map(normalizeHex)
    .join(",");
  const parts: Uint8Array[] = [
    enc.encode(EUNOMA_MPCCA_WITHDRAW_V2_FINAL_V1),
    enc.encode(":"),
    enc.encode(input.dkgEpoch),
    enc.encode(":"),
    enc.encode(normalizeHex(input.vaultEkTranscriptHash)),
    enc.encode(":"),
    enc.encode(normalizeHex(input.registrationTranscriptHash)),
    enc.encode(":"),
    enc.encode(normalizeHex(input.vaultStateInitTranscriptHash)),
    enc.encode(":"),
    enc.encode(observedJoined),
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
    enc.encode(normalizeHex(input.root)),
    enc.encode(":"),
    enc.encode(normalizeHex(input.nullifierHash)),
    enc.encode(":"),
    enc.encode(normalizeHex(input.recipient)),
    enc.encode(":"),
    enc.encode(normalizeHex(input.recipientHash)),
    enc.encode(":"),
    enc.encode(normalizeHex(input.amountTag)),
    enc.encode(":"),
    enc.encode(input.vaultSequence.toString()),
    enc.encode(":"),
    enc.encode(input.expirySecs.toString()),
    enc.encode(":"),
    enc.encode(normalizeHex(input.requestHash)),
    enc.encode(":"),
    enc.encode(input.depositCount.toString()),
  ];
  const writeContribution = (
    label: string,
    contribs: MpccaWithdrawBaseContribution[],
    perSlotPayload: (idx: number) => string,
  ) => {
    parts.push(enc.encode(":"));
    parts.push(enc.encode(label));
    const sorted = [...contribs].sort((a, b) => a.slot - b.slot);
    for (let idx = 0; idx < sorted.length; idx += 1) {
      const c = sorted[idx];
      parts.push(enc.encode(":"));
      parts.push(enc.encode(c.slot.toString()));
      parts.push(enc.encode("|"));
      parts.push(enc.encode(normalizeHex(c.sessionStateHash)));
      parts.push(enc.encode("|"));
      parts.push(enc.encode(normalizeHex(c.workerTranscriptHash)));
      parts.push(enc.encode("|"));
      parts.push(enc.encode(c.notImplementedPhase));
      parts.push(enc.encode("|"));
      parts.push(enc.encode(perSlotPayload(idx)));
    }
  };
  const sortedR1 = [...input.round1Contributions].sort((a, b) => a.slot - b.slot);
  writeContribution("r1", sortedR1, (i) =>
    sortedR1[i].roundCommitment ? normalizeHex(sortedR1[i].roundCommitment!) : "",
  );
  const sortedR2 = [...input.round2Contributions].sort((a, b) => a.slot - b.slot);
  writeContribution("r2", sortedR2, (i) =>
    sortedR2[i].partialResponse ? normalizeHex(sortedR2[i].partialResponse!) : "",
  );
  const sortedPr = [...input.proveContributions].sort((a, b) => a.slot - b.slot);
  writeContribution("pr", sortedPr, (i) =>
    sortedPr[i].partialBulletproofShare
      ? normalizeHex(sortedPr[i].partialBulletproofShare!)
      : "",
  );
  const sortedFin = [...input.finalizeContributions].sort((a, b) => a.slot - b.slot);
  writeContribution("fin", sortedFin, (i) =>
    sortedFin[i].partialCaPayloadFields
      ? normalizeHex(sortedFin[i].partialCaPayloadFields!)
      : "",
  );
  return bytesToHex(sha256(concat(parts)));
}

/**
 * Assemble + validate a final MPCCA withdraw transcript. Mirrors the shape of the vault_state_v2
 * assemble helpers. Used by the coordinator when the finalize round lands (milestone 4); in
 * milestone 3a the round1-only partial transcript is persisted via the per-round helpers.
 */
export function assembleMpccaWithdrawTranscript(input: {
  dkgEpoch: string;
  requestId: string;
  vaultEkTranscriptHash: string;
  registrationTranscriptHash: string;
  vaultStateInitTranscriptHash: string;
  observedDepositTranscriptHashes: string[];
  rosterHash: string;
  selectedSlots: number[];
  vaultEk: string;
  senderAddress: string;
  assetType: string;
  chainId: number;
  root: string;
  nullifierHash: string;
  recipient: string;
  recipientHash: string;
  amountTag: string;
  vaultSequence: number;
  expirySecs: number;
  requestHash: string;
  depositCount: number;
  round1Contributions: MpccaWithdrawRound1Contribution[];
  round2Contributions: MpccaWithdrawRound2Contribution[];
  proveContributions: MpccaWithdrawProveContribution[];
  finalizeContributions: MpccaWithdrawFinalizeContribution[];
}): MpccaWithdrawTranscript {
  assertNoForbiddenPlaintextFields(input);
  if (
    !Array.isArray(input.selectedSlots) ||
    input.selectedSlots.length !== DEOPERATOR_THRESHOLD
  ) {
    throw new MpccaWithdrawV2Error(
      "UNDER_QUORUM",
      `selectedSlots must have ${DEOPERATOR_THRESHOLD} entries`,
    );
  }
  const seen = new Set<number>();
  for (const slot of input.selectedSlots) {
    if (!Number.isInteger(slot) || slot < 0 || slot >= DEOPERATOR_COUNT) {
      throw new MpccaWithdrawV2Error(
        "UNKNOWN_SLOT",
        `slot ${slot} out of range`,
      );
    }
    if (seen.has(slot)) {
      throw new MpccaWithdrawV2Error("DUPLICATE_SLOT", `duplicate slot ${slot}`);
    }
    seen.add(slot);
  }
  if (!/^[0-9]+$/.test(input.dkgEpoch)) {
    throw new MpccaWithdrawV2Error(
      "STALE_DKG_EPOCH",
      "dkgEpoch must be a non-empty decimal string",
    );
  }
  const sortedSlots = [...input.selectedSlots].sort((a, b) => a - b);
  const normalized = (hex: string, expected: number): string => {
    const norm = normalizeHex(hex);
    const bytes = hexToBytes(norm);
    if (bytes.length !== expected) {
      throw new MpccaWithdrawV2Error(
        "INVALID_WITHDRAW_FIELD_SHAPE",
        `expected ${expected}-byte hex, got ${bytes.length}`,
      );
    }
    return norm;
  };
  const vaultEkTranscriptHash = normalized(input.vaultEkTranscriptHash, 32);
  const registrationTranscriptHash = normalized(input.registrationTranscriptHash, 32);
  const vaultStateInitTranscriptHash = normalized(input.vaultStateInitTranscriptHash, 32);
  const rosterHash = normalized(input.rosterHash, 32);
  const vaultEk = normalized(input.vaultEk, 32);
  const senderAddress = normalized(input.senderAddress, 32);
  const assetType = normalized(input.assetType, 32);
  const root = normalized(input.root, 32);
  const nullifierHash = normalized(input.nullifierHash, 32);
  const recipient = normalized(input.recipient, 32);
  const recipientHash = normalized(input.recipientHash, 32);
  const amountTag = normalized(input.amountTag, 32);
  const requestHash = normalized(input.requestHash, 32);
  if (!Array.isArray(input.observedDepositTranscriptHashes)) {
    throw new MpccaWithdrawV2Error(
      "OBSERVED_DEPOSIT_NOT_FOUND",
      "observedDepositTranscriptHashes must be an array",
    );
  }
  const observedDepositTranscriptHashes = input.observedDepositTranscriptHashes.map((h) =>
    normalized(h, 32),
  );
  if (!Number.isInteger(input.chainId) || input.chainId < 0 || input.chainId > 255) {
    throw new MpccaWithdrawV2Error(
      "INVALID_WITHDRAW_FIELD_SHAPE",
      "chainId must be a u8",
    );
  }
  if (!Number.isInteger(input.vaultSequence) || input.vaultSequence < 0) {
    throw new MpccaWithdrawV2Error(
      "STALE_VAULT_SEQUENCE",
      "vaultSequence must be a non-negative integer",
    );
  }
  if (!Number.isInteger(input.expirySecs) || input.expirySecs < 0) {
    throw new MpccaWithdrawV2Error(
      "INVALID_WITHDRAW_FIELD_SHAPE",
      "expirySecs must be a non-negative integer",
    );
  }
  if (!Number.isInteger(input.depositCount) || input.depositCount < 0) {
    throw new MpccaWithdrawV2Error(
      "INVALID_WITHDRAW_FIELD_SHAPE",
      "depositCount must be a non-negative integer",
    );
  }
  const transcriptHash = mpccaWithdrawFinalTranscriptHash({
    dkgEpoch: input.dkgEpoch,
    vaultEkTranscriptHash,
    registrationTranscriptHash,
    vaultStateInitTranscriptHash,
    observedDepositTranscriptHashes,
    rosterHash,
    sortedSelectedSlots: sortedSlots,
    vaultEk,
    senderAddress,
    assetType,
    chainId: input.chainId,
    root,
    nullifierHash,
    recipient,
    recipientHash,
    amountTag,
    vaultSequence: input.vaultSequence,
    expirySecs: input.expirySecs,
    requestHash,
    depositCount: input.depositCount,
    round1Contributions: input.round1Contributions,
    round2Contributions: input.round2Contributions,
    proveContributions: input.proveContributions,
    finalizeContributions: input.finalizeContributions,
  });
  return {
    scheme: "mpcca_withdraw_v2",
    dkgEpoch: input.dkgEpoch,
    requestId: input.requestId,
    vaultEkTranscriptHash,
    registrationTranscriptHash,
    vaultStateInitTranscriptHash,
    observedDepositTranscriptHashes,
    rosterHash,
    selectedSlots: sortedSlots,
    vaultEk,
    senderAddress,
    assetType,
    chainId: input.chainId,
    root,
    nullifierHash,
    recipient,
    recipientHash,
    amountTag,
    vaultSequence: input.vaultSequence,
    expirySecs: input.expirySecs,
    requestHash,
    depositCount: input.depositCount,
    round1Contributions: input.round1Contributions,
    round2Contributions: input.round2Contributions,
    proveContributions: input.proveContributions,
    finalizeContributions: input.finalizeContributions,
    transcriptHash,
    createdAtUnixMs: 0,
  };
}

// =================================================================================================
// Parsers — strict-validate untrusted JSON wire bodies BEFORE the orchestrator/handler reads
// individual fields. All parsers run `assertNoForbiddenPlaintextFields(body)` FIRST so an extra
// `amount`/`blind`/`secret`/`dkShare`/`nullifier` field is rejected at the boundary.
// =================================================================================================
function objectBody(body: unknown): Record<string, unknown> {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new MpccaWithdrawV2Error(
      "INVALID_WITHDRAW_FIELD_SHAPE",
      "body must be an object",
    );
  }
  return body as Record<string, unknown>;
}

function requireString(obj: Record<string, unknown>, key: string): string {
  const v = obj[key];
  if (typeof v !== "string" || v.length === 0) {
    throw new MpccaWithdrawV2Error(
      "INVALID_WITHDRAW_FIELD_SHAPE",
      `${key} must be a non-empty string`,
    );
  }
  return v;
}

function requireDecimalString(obj: Record<string, unknown>, key: string): string {
  const v = requireString(obj, key);
  if (!/^[0-9]+$/.test(v)) {
    throw new MpccaWithdrawV2Error(
      "INVALID_WITHDRAW_FIELD_SHAPE",
      `${key} must be a non-empty decimal string`,
    );
  }
  return v;
}

function requireHex(obj: Record<string, unknown>, key: string, bytes: number): HexString {
  const raw = requireString(obj, key);
  const norm = normalizeHex(raw);
  if (hexToBytes(norm).length !== bytes) {
    throw new MpccaWithdrawV2Error(
      "INVALID_WITHDRAW_FIELD_SHAPE",
      `${key} must be ${bytes}-byte hex`,
    );
  }
  return norm;
}

function requireInt(
  obj: Record<string, unknown>,
  key: string,
  min: number,
  max: number,
): number {
  const v = obj[key];
  if (!Number.isInteger(v) || (v as number) < min || (v as number) > max) {
    throw new MpccaWithdrawV2Error(
      "INVALID_WITHDRAW_FIELD_SHAPE",
      `${key} must be an integer in [${min}, ${max}]`,
    );
  }
  return v as number;
}

function requireSelectedSlots(obj: Record<string, unknown>, key: string): number[] {
  const v = obj[key];
  if (!Array.isArray(v) || v.length !== DEOPERATOR_THRESHOLD) {
    throw new MpccaWithdrawV2Error(
      "UNDER_QUORUM",
      `${key} must have ${DEOPERATOR_THRESHOLD} entries`,
    );
  }
  const seen = new Set<number>();
  for (const slot of v) {
    if (
      !Number.isInteger(slot) ||
      (slot as number) < 0 ||
      (slot as number) >= DEOPERATOR_COUNT
    ) {
      throw new MpccaWithdrawV2Error(
        "UNKNOWN_SLOT",
        `${key} entry ${slot} out of range`,
      );
    }
    if (seen.has(slot as number)) {
      throw new MpccaWithdrawV2Error("DUPLICATE_SLOT", `${key} duplicate ${slot}`);
    }
    seen.add(slot as number);
  }
  return v as number[];
}

function requireObservedDepositTranscriptHashes(
  obj: Record<string, unknown>,
): HexString[] {
  const v = obj.observedDepositTranscriptHashes;
  if (!Array.isArray(v)) {
    throw new MpccaWithdrawV2Error(
      "OBSERVED_DEPOSIT_NOT_FOUND",
      "observedDepositTranscriptHashes must be an array",
    );
  }
  const out: HexString[] = [];
  for (let i = 0; i < v.length; i += 1) {
    const entry = v[i];
    if (typeof entry !== "string" || entry.length === 0) {
      throw new MpccaWithdrawV2Error(
        "OBSERVED_DEPOSIT_NOT_FOUND",
        `observedDepositTranscriptHashes[${i}] must be a non-empty string`,
      );
    }
    const norm = normalizeHex(entry);
    if (hexToBytes(norm).length !== 32) {
      throw new MpccaWithdrawV2Error(
        "OBSERVED_DEPOSIT_NOT_FOUND",
        `observedDepositTranscriptHashes[${i}] must be 32-byte hex`,
      );
    }
    out.push(norm);
  }
  return out;
}

function requirePreviousRoundCommitments(obj: Record<string, unknown>): HexString[] {
  const v = obj.previousRoundCommitments;
  if (!Array.isArray(v) || v.length !== DEOPERATOR_THRESHOLD) {
    throw new MpccaWithdrawV2Error(
      "INVALID_CONTRIBUTION_SHAPE",
      `previousRoundCommitments must have ${DEOPERATOR_THRESHOLD} entries`,
    );
  }
  const out: HexString[] = [];
  for (let i = 0; i < v.length; i += 1) {
    const entry = v[i];
    if (typeof entry !== "string" || entry.length === 0) {
      throw new MpccaWithdrawV2Error(
        "INVALID_CONTRIBUTION_SHAPE",
        `previousRoundCommitments[${i}] must be a non-empty string`,
      );
    }
    const norm = normalizeHex(entry);
    if (hexToBytes(norm).length !== 32) {
      throw new MpccaWithdrawV2Error(
        "INVALID_CONTRIBUTION_SHAPE",
        `previousRoundCommitments[${i}] must be 32-byte hex`,
      );
    }
    out.push(norm);
  }
  return out;
}

function parseBaseRequest(body: unknown): MpccaWithdrawBaseRequest {
  // Forbidden-field guard FIRST.
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  return {
    dkgEpoch: requireDecimalString(obj, "dkgEpoch"),
    requestId: requireString(obj, "requestId"),
    sessionId: requireString(obj, "sessionId"),
    vaultEkTranscriptHash: requireHex(obj, "vaultEkTranscriptHash", 32),
    registrationTranscriptHash: requireHex(obj, "registrationTranscriptHash", 32),
    vaultStateInitTranscriptHash: requireHex(obj, "vaultStateInitTranscriptHash", 32),
    observedDepositTranscriptHashes: requireObservedDepositTranscriptHashes(obj),
    rosterHash: requireHex(obj, "rosterHash", 32),
    selectedSlots: requireSelectedSlots(obj, "selectedSlots"),
    selfSlot: requireInt(obj, "selfSlot", 0, DEOPERATOR_COUNT - 1),
    playerId: requireInt(obj, "playerId", 0, DEOPERATOR_THRESHOLD - 1),
    vaultEk: requireHex(obj, "vaultEk", 32),
    senderAddress: requireHex(obj, "senderAddress", 32),
    assetType: requireHex(obj, "assetType", 32),
    chainId: requireInt(obj, "chainId", 0, 255),
    root: requireHex(obj, "root", 32),
    nullifierHash: requireHex(obj, "nullifierHash", 32),
    recipient: requireHex(obj, "recipient", 32),
    recipientHash: requireHex(obj, "recipientHash", 32),
    amountTag: requireHex(obj, "amountTag", 32),
    vaultSequence: requireInt(obj, "vaultSequence", 0, Number.MAX_SAFE_INTEGER),
    expirySecs: requireInt(obj, "expirySecs", 0, Number.MAX_SAFE_INTEGER),
    requestHash: requireHex(obj, "requestHash", 32),
    depositCount: requireInt(obj, "depositCount", 0, Number.MAX_SAFE_INTEGER),
  };
}

function parseChainedRequest(body: unknown): MpccaWithdrawChainedRequest {
  // parseBaseRequest already runs the forbidden-field guard.
  const base = parseBaseRequest(body);
  const obj = objectBody(body);
  return {
    ...base,
    previousRoundTranscriptHash: requireHex(obj, "previousRoundTranscriptHash", 32),
    previousRoundCommitments: requirePreviousRoundCommitments(obj),
  };
}

export function parseMpccaWithdrawRound1Request(
  body: unknown,
): MpccaWithdrawRound1Request {
  return parseBaseRequest(body);
}

export function parseMpccaWithdrawRound2Request(
  body: unknown,
): MpccaWithdrawRound2Request {
  return parseChainedRequest(body);
}

export function parseMpccaWithdrawProveRequest(
  body: unknown,
): MpccaWithdrawProveRequest {
  return parseChainedRequest(body);
}

export function parseMpccaWithdrawFinalizeRequest(
  body: unknown,
): MpccaWithdrawFinalizeRequest {
  return parseChainedRequest(body);
}

function parseBaseResponse(body: unknown): MpccaWithdrawBaseResponse {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  const completed = obj.completed;
  if (completed !== false) {
    // Sub-milestone 3a returns `completed: false` from the stub. Milestone 4 will return
    // `completed: true` from the finalize handler; that's a separate Response type.
    throw new MpccaWithdrawV2Error(
      "INVALID_CONTRIBUTION_SHAPE",
      "completed must be the literal boolean false (milestone 3a is stub-only)",
    );
  }
  return {
    slot: requireInt(obj, "slot", 0, DEOPERATOR_COUNT - 1),
    playerId: requireInt(obj, "playerId", 0, DEOPERATOR_THRESHOLD - 1),
    sessionStatePath: requireString(obj, "sessionStatePath"),
    sessionStateHash: requireHex(obj, "sessionStateHash", 32),
    workerTranscriptHash: requireHex(obj, "workerTranscriptHash", 32),
    observedAtUnixMs: requireInt(obj, "observedAtUnixMs", 0, Number.MAX_SAFE_INTEGER),
    completed: false,
    notImplementedPhase: requireString(obj, "notImplementedPhase"),
  };
}

function maybeHex(obj: Record<string, unknown>, key: string): HexString | undefined {
  const v = obj[key];
  if (v === undefined || v === null) return undefined;
  if (typeof v !== "string" || v.length === 0) {
    throw new MpccaWithdrawV2Error(
      "INVALID_CONTRIBUTION_SHAPE",
      `${key} must be a non-empty hex string when present`,
    );
  }
  const norm = normalizeHex(v);
  if (hexToBytes(norm).length === 0) {
    throw new MpccaWithdrawV2Error(
      "INVALID_CONTRIBUTION_SHAPE",
      `${key} must decode to at least one byte`,
    );
  }
  return norm;
}

export function parseMpccaWithdrawRound1Response(
  body: unknown,
): MpccaWithdrawRound1Response {
  const base = parseBaseResponse(body);
  const obj = objectBody(body);
  return { ...base, roundCommitment: maybeHex(obj, "roundCommitment") };
}

export function parseMpccaWithdrawRound2Response(
  body: unknown,
): MpccaWithdrawRound2Response {
  const base = parseBaseResponse(body);
  const obj = objectBody(body);
  return { ...base, partialResponse: maybeHex(obj, "partialResponse") };
}

export function parseMpccaWithdrawProveResponse(
  body: unknown,
): MpccaWithdrawProveResponse {
  const base = parseBaseResponse(body);
  const obj = objectBody(body);
  return {
    ...base,
    partialBulletproofShare: maybeHex(obj, "partialBulletproofShare"),
  };
}

export function parseMpccaWithdrawFinalizeResponse(
  body: unknown,
): MpccaWithdrawFinalizeResponse {
  const base = parseBaseResponse(body);
  const obj = objectBody(body);
  return {
    ...base,
    partialCaPayloadFields: maybeHex(obj, "partialCaPayloadFields"),
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

import { bytesToHex, hexToBytes, normalizeHex, sha256 } from "@eunoma/shared";
import type { HexString } from "@eunoma/shared";
import { DEOPERATOR_COUNT, DEOPERATOR_THRESHOLD } from "./constants.js";
import { assertNoForbiddenPlaintextFields } from "./forbidden.js";
import type { HpkeEnvelope } from "./types.js";

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
/**
 * Round1 domain bumped to V2 in Milestone 1 (Threshold ElGamal Amount Ingress).
 * V1 was the M3a stub-mode domain that bound only the public withdraw envelope; V2 extends
 * the bound bytes with `amount_commitment`, `per_share_commitments`, and `ingress_envelopes_hash`,
 * so any tampered ingress field flips the per-worker transcript hash and is rejected by the
 * coordinator's worker-transcript-agreement check. V1 stays exported as a historical marker —
 * the active hash function uses V2.
 */
export const EUNOMA_MPCCA_WITHDRAW_V2_ROUND1_V1 = "EUNOMA_MPCCA_WITHDRAW_V2_ROUND1_V1";
export const EUNOMA_MPCCA_WITHDRAW_V2_ROUND1_V2 = "EUNOMA_MPCCA_WITHDRAW_V2_ROUND1_V2";
/**
 * M4 Commit 1: round2 transcript-hash domain bumped V1→V2. The chained-round body now
 * binds Aptos CA TransferV1 Statement input fields via the round2 worker_transcript_hash;
 * any pre-M4 V1 artifact deserialised against the V2 binding fails closed at the
 * coordinator's worker-hash cross-check.
 */
export const EUNOMA_MPCCA_WITHDRAW_V2_ROUND2_V2 = "EUNOMA_MPCCA_WITHDRAW_V2_ROUND2_V2";
export const EUNOMA_MPCCA_WITHDRAW_V2_PROVE_V1 = "EUNOMA_MPCCA_WITHDRAW_V2_PROVE_V1";
export const EUNOMA_MPCCA_WITHDRAW_V2_FINALIZE_V1 = "EUNOMA_MPCCA_WITHDRAW_V2_FINALIZE_V1";
export const EUNOMA_MPCCA_WITHDRAW_V2_FINAL_V1 = "EUNOMA_MPCCA_WITHDRAW_V2_FINAL_V1";

/**
 * M4 Commit 2: deterministic domain for the coordinator-side round2 aggregate hash that
 * binds (Statement input fields ‖ sorted worker dk-base partial commitments ‖ sorted worker
 * transcript hashes). Persisted into `__round2.json` and consumed by prove/finalize as the
 * `previousRoundTranscriptHash` chain seed.
 */
export const EUNOMA_MPCCA_WITHDRAW_V2_ROUND2_AGGREGATE_V1 =
  "EUNOMA_MPCCA_WITHDRAW_V2_ROUND2_AGGREGATE_V1";

/**
 * Canonical Aptos CA TransferV1 Statement vector lengths. `ROUND2_ELL` (= 8) is the
 * new-balance chunk count, `ROUND2_N` (= 4) is the transfer-amount chunk count. Mirrors
 * the Rust constants of the same names in `crypto-worker-rust::mpcca_withdraw_v2`.
 */
export const ROUND2_ELL = 8;
export const ROUND2_N = 4;

/**
 * M4 Commit 2 — coordinator-inbound user-supplied proof artifact lengths. Documented here
 * because the wire shape REQUIRES exactly these counts; under-quorum or over-quorum fail
 * closed at the boundary.
 *
 * - `USER_SIGMA_COMMITMENTS_LEN = 29`: 30-point CA TransferV1 commitment vector minus the
 *   single pure-dk position (index 0 in the canonical psi_transfer output). The position-17
 *   slot is shared — the user contributes its non-dk component here and the workers add
 *   the dk-component at aggregation time.
 * - `USER_SIGMA_RESPONSE_SHARES_LEN = 24`: 25-element response vector minus the dk slot
 *   (index 0). User-supplied response shares for witness[1..25].
 * - `DK_BASE_INDICES_CANONICAL = [0, 17]`: programmatic BASE_DK_SET output for Aptos CA
 *   TransferV1 (ell=8, n=4, no auditor). Validated by `derive_dk_base_points` in the
 *   Rust worker at every round2 call; the coordinator cross-checks the returned indices.
 */
export const USER_SIGMA_COMMITMENTS_LEN = 29;
export const USER_SIGMA_RESPONSE_SHARES_LEN = 24;
export const DK_BASE_INDICES_CANONICAL: readonly number[] = Object.freeze([0, 17]);

/**
 * HPKE AAD domain for the M1 amount-ingress envelope. Locked. Any change must bump the V1
 * suffix and is a wire-protocol break.
 *
 * AAD layout (canonical JSON, byte-identical TS↔Rust):
 *   {
 *     "amountCommitmentHex": <32-byte hex>,
 *     "amountTag": <32-byte hex>,
 *     "depositCount": <decimal>,
 *     "dkgEpoch": <decimal>,
 *     "domain": "EUNOMA_M1_AMOUNT_INGRESS_V1",
 *     "nullifierHash": <32-byte hex>,
 *     "perShareCommitmentsHashHex": <sha256-hex>,
 *     "playerId": <0..4>,
 *     "recipientHash": <32-byte hex>,
 *     "requestId": <string>,
 *     "root": <32-byte hex>,
 *     "rosterHash": <32-byte hex>,
 *     "selfSlot": <0..6>,
 *     "sessionId": <string>,
 *     "vaultEk": <32-byte hex>,
 *     "vaultSequence": <decimal>
 *   }
 *
 * Keys are alphabetically sorted (TS uses `canonicalJsonStringify`; Rust uses a `BTreeMap` →
 * `serde_json::to_vec`). Tampering with any field invalidates the HPKE seal.
 */
export const EUNOMA_M1_AMOUNT_INGRESS_V1 = "EUNOMA_M1_AMOUNT_INGRESS_V1";

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
  | "INVALID_CONTRIBUTION_SHAPE"
  // Milestone 1: Threshold ElGamal Amount Ingress validation.
  | "INGRESS_COMMITMENT_COUNT_MISMATCH"
  | "INGRESS_ENVELOPE_COUNT_MISMATCH"
  | "INGRESS_AGGREGATE_COMMITMENT_MISMATCH"
  | "INGRESS_INVALID_COMMITMENT_SHAPE"
  | "INGRESS_INVALID_ENVELOPE_SHAPE"
  // M4 commit 2: round2 orchestration + Statement / user-proof shape validation.
  | "INVALID_STATEMENT_INPUT_SHAPE"
  | "INVALID_USER_SIGMA_SHAPE"
  | "INVALID_BULLETPROOF_BYTES"
  | "INVALID_PER_CHUNK_COMMITMENT_SHAPE"
  | "DK_BASE_INDICES_DIVERGENCE"
  | "DUPLICATE_DK_INDEX"
  | "INVALID_ROUND2_PARTIAL_SHAPE";

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
  /**
   * Optional parallel cursor list paired with `observedDepositTranscriptHashes`. When supplied,
   * the coordinator passes it through to workers' strict-monotonic ordering check; when absent,
   * the coordinator synthesizes `[1, 2, …, depositCount]`. M9: typed here so server.ts builds
   * cleanly under tsc (M8 holdover from the M2b ordering bind).
   */
  observedDepositCursors?: number[];
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

/**
 * Milestone 1 — Threshold ElGamal Amount Ingress fields carried by the round1 request.
 *
 * The user's client constructs `amount` and `blind` as scalars over the Ed25519 scalar
 * field, computes the public Pedersen commitment `amountCommitment = G·amount + H·blind`,
 * additively shares each into 5 pieces over the same field, computes per-share Pedersen
 * commitments `perShareCommitments[i] = G·a_i + H·b_i`, and seals each `(a_i, b_i)` to the
 * i-th selectedSlot's HPKE public key with the M1 AAD (see EUNOMA_M1_AMOUNT_INGRESS_V1 above).
 *
 * Coordinator validates `Σ perShareCommitments[i] = amountCommitment` over compressed
 * Ristretto bytes; each worker validates its own decrypted `(a_i, b_i)` against the claimed
 * per-share commitment and rejects zero shares. Plaintext shares never leave the worker's
 * own process — they are persisted HPKE-encrypted-at-rest under the same slot's HPKE pubkey
 * for later consumption by M4b/c/d.
 */
export interface MpccaWithdrawRound1IngressFields {
  /** Public Pedersen commitment to the full amount + blind. 32-byte compressed Ristretto. */
  amountCommitment: HexString;
  /**
   * Per-slot public Pedersen commitments. `perShareCommitments[i]` MUST equal
   * `G·a_i + H·b_i` where `(a_i, b_i)` is the share addressed to selectedSlots[i]
   * (sorted-selectedSlots order). Length === DEOPERATOR_THRESHOLD (5).
   */
  perShareCommitments: HexString[];
  /**
   * HPKE envelopes, one per sorted-selectedSlot. `ingressEnvelopes[i]` is sealed under the
   * i-th sorted-selectedSlot worker's HPKE public key with the M1 AAD (binding requestId,
   * sessionId, dkgEpoch, selfSlot, playerId, rosterHash, vaultEk, root, nullifierHash,
   * recipientHash, amountTag, vaultSequence, depositCount, amountCommitmentHex,
   * perShareCommitmentsHashHex). Plaintext is 64 bytes: `concat(a_i.to_bytes_le(32),
   * b_i.to_bytes_le(32))`. Length === DEOPERATOR_THRESHOLD (5).
   */
  ingressEnvelopes: HpkeEnvelope[];
}

export type MpccaWithdrawRound1Request = MpccaWithdrawBaseRequest &
  MpccaWithdrawRound1IngressFields;

/**
 * M4 Commit 1 — public Aptos CA TransferV1 Statement input fields. Carried by every Round 2
 * worker request so the worker can (a) reconstruct the public `Statement` and (b) derive
 * `BASE_DK_SET` via `psi_transfer` inspection. Vector lengths are pinned at compile time
 * (`ROUND2_ELL` = 8, `ROUND2_N` = 4) per the canonical no-auditor TransferV1 shape.
 *
 * Privacy contract: every field is a public chain ciphertext / public encryption key. The
 * plaintext chunk values + scalar blinds NEVER appear here.
 */
export interface MpccaWithdrawRound2StatementInputFields {
  /** Recipient encryption key (`ek_rid`). 32-byte compressed Ristretto hex. */
  recipientEk: HexString;
  /** Old balance Pedersen commitments `C[i] = G·old_a[i] + H·old_r[i]`. 8 entries. */
  oldBalanceC: HexString[];
  /** Old balance ElGamal D-component `D[i] = ek_sid · old_r[i]`. 8 entries. */
  oldBalanceD: HexString[];
  /** New balance Pedersen commitments. 8 entries. */
  newBalanceC: HexString[];
  /** New balance ElGamal D-component. 8 entries. */
  newBalanceD: HexString[];
  /** Transfer-amount Pedersen commitments. 4 entries. */
  transferAmountC: HexString[];
  /** Transfer-amount ElGamal D-component (sender). 4 entries. */
  transferAmountDSender: HexString[];
  /** Transfer-amount ElGamal D-component (recipient). 4 entries. */
  transferAmountDRecipient: HexString[];
}

/**
 * M4 Commit 1 — Round 2 worker request. Extends the chained-round envelope with the public
 * CA TransferV1 Statement input fields. Byte-shape mirrors the Rust `Round2Request` struct
 * (which uses `#[serde(flatten)]` to splice `ChainedRoundRequest` into the JSON top level).
 */
export type MpccaWithdrawRound2Request = MpccaWithdrawChainedRequest &
  MpccaWithdrawRound2StatementInputFields;

export type MpccaWithdrawProveRequest = MpccaWithdrawChainedRequest;

/**
 * M4 Commit 3 — public Fiat-Shamir / aggregate fields carried alongside the chained-round
 * envelope at the finalize boundary. The coordinator builds these from the persisted
 * `__round2.json` artifact (worker dk-base partials aggregated across the 5 selected workers,
 * combined with the user-supplied 29-entry `A_user` to form the full 30-point `A`); `e` is
 * computed by the coordinator via `sigma_fiat_shamir_seed(BCS(domain, type_name, k=25, stmt.x,
 * stmt.scalars, A))`. Each worker re-derives `e` locally and asserts byte-equality so a
 * malicious coordinator cannot lie about `e`.
 *
 * Privacy contract: every field is a public crypto output (commitment / scalar). No plaintext
 * witness component appears here.
 */
export interface MpccaWithdrawFinalizeFiatShamirFields {
  /**
   * Coordinator-aggregated 30-point sigma commitment vector `A_full`. Built by inlining the
   * worker dk-base partials at canonical BASE_DK_SET positions into the user-supplied
   * `A_user[29]` and the 1 shared position. 30 × 32-byte hex compressed Ristretto.
   */
  aggregatedSigmaCommitmentsHex: HexString[];
  /**
   * Coordinator-computed Fiat-Shamir challenge `e`. 32-byte canonical Ed25519 scalar hex.
   * Each worker re-derives `e` and rejects on byte mismatch.
   */
  challengeHex: HexString;
}

/**
 * M4 Commit 3 — Finalize worker request. Extends the chained-round envelope with the same
 * Aptos CA TransferV1 Statement input fields as round2 (the worker re-derives BASE_DK_SET and
 * the Fiat-Shamir input from these) PLUS the coordinator-aggregated `A` + `e`. Byte-shape
 * mirrors the Rust `FinalizeRequest` struct (which uses `#[serde(flatten)]` to splice
 * `ChainedRoundRequest` into the JSON top level).
 *
 * The worker is the ONLY party that can decrypt `α_share_j[0]` from the round2 at-rest
 * envelope; the coordinator supplies (A, e) and the worker returns `s_share_j = α_share_j[0]
 * + e · (λ_j · dk_share_j)`. The at-rest finalize pin (see Rust `FinalizePinFile`) makes
 * any second call with different (A, e) fail closed BEFORE α is decrypted, blocking the
 * α-share replay key-recovery attack.
 */
export type MpccaWithdrawFinalizeRequest = MpccaWithdrawChainedRequest &
  MpccaWithdrawRound2StatementInputFields &
  MpccaWithdrawFinalizeFiatShamirFields;

/**
 * M4 Commit 3 — Finalize worker response shape. The worker contributes ONLY the dk-component
 * of the sigma response vector `s`: a single 32-byte canonical Ed25519 scalar
 * `s_share_j = α_share_j[0] + e · (λ_j · dk_share_j)`. The coordinator aggregates the 5
 * selected workers' shares via `s[0] = Σ_j s_share_j` and combines with user-supplied
 * `s_user[1..25]` to assemble the full 25-vector sigma response.
 *
 * `dkBaseIndicesUsed` mirrors round2's contract — re-derived from `psi_transfer` at finalize
 * as defense-in-depth.
 */
export interface MpccaWithdrawFinalizeDkResult extends MpccaWithdrawBasePublicOutputs {
  completed: true;
  /** Single 32-byte canonical Ed25519 scalar hex. */
  partialResponseDkHex: HexString;
  /** Canonical BASE_DK_SET indices re-derived at finalize via psi_transfer inspection. */
  dkBaseIndicesUsed: number[];
}

/**
 * M4 Commit 4 — coordinator-inbound `/v2/withdraw/mpcca/finalize` request body. Only the base
 * identity envelope is carried; the coordinator reconstructs the Statement inputs + user
 * sigma response + Bulletproof + per-chunk commitments + worker dk-base partials by reading
 * the persisted `__round2.json` artifact for `(dkgEpoch, requestId)`. The coordinator then:
 *   1. Builds the aggregated 30-point `A_full` (worker dk-base partials at canonical BASE_DK_SET
 *      positions, user-supplied `A_user[29]` at the remaining positions).
 *   2. Computes the canonical Fiat-Shamir challenge `e` via Aptos CA TransferV1 BCS-encoded
 *      sigma_fiat_shamir_seed.
 *   3. Fans out the per-worker `MpccaWithdrawFinalizeRequest` (with aggregated A + e) to all
 *      5 selected slots concurrently with bounded AbortController timeouts.
 *   4. Aggregates `s[0] = Σ_j partialResponseDkHex_j` and combines with the user-supplied
 *      `s_user[1..25]` to form the full 25-scalar sigma response.
 *   5. Persists `__finalize.json` with the canonical mpcca-finalize artifact (transcript hash,
 *      aggregated A, e, s[0..25], per-slot worker partial responses, perChunk commitments,
 *      bulletproof bytes echo-back).
 *
 * Forbidden plaintext fields are guarded by `parseBaseRequest`.
 */
export interface MpccaWithdrawFinalizeOrchestrateRequest extends MpccaWithdrawBaseRequest {}

/**
 * M4 Commit 2 — user-supplied proof artifacts carried by the coordinator-inbound round2
 * orchestrate request body. These artifacts are forwarded ONLY to the coordinator (NOT to
 * any worker) and are persisted echoed-back in the `__round2.json` artifact for prove /
 * finalize to consume. Workers never see Bulletproof bytes or user sigma commitments — the
 * coordinator is the sole party that aggregates the user's contribution with the worker
 * dk-base partials.
 *
 * Privacy contract: every entry is public crypto output (commitment / response scalar /
 * Bulletproof byte string). The plaintext chunk values + amount NEVER appear here.
 */
export interface MpccaWithdrawRound2OrchestrateProofFields {
  /**
   * User's pre-computed sigma commitment vector (the 30-point Aptos CA TransferV1
   * commitment vector minus the single pure-dk position). 29 × 32-byte hex.
   *
   * At aggregation time the coordinator inlines the worker dk-base partials into the
   * positions named by `dkBaseIndicesUsed` to assemble the full 30-point vector A.
   */
  userSigmaCommitmentsHex: HexString[];
  /**
   * User's pre-computed sigma response scalars for witness slots `[1..25)` (the 25-element
   * response vector minus the dk slot at index 0). 24 × 32-byte hex.
   */
  userSigmaResponseSharesHex: HexString[];
  /** User-generated Bulletproof bytes proving the transfer amount is in range. Hex. */
  bulletproofZkrpAmountHex: HexString;
  /** User-generated Bulletproof bytes proving the new balance is in range. Hex. */
  bulletproofZkrpNewBalanceHex: HexString;
  /** Per-chunk Pedersen commitments to transfer-amount chunks. 4 × 32-byte hex. */
  perChunkCommitmentsAmountHex: HexString[];
  /** Per-chunk Pedersen commitments to new-balance chunks. 8 × 32-byte hex. */
  perChunkCommitmentsNewBalanceHex: HexString[];
}

/**
 * M4 Commit 2 — coordinator-inbound /v2/withdraw/mpcca/round2 request body. Combines the
 * Milestone 3a base identity envelope, the Round2 Statement inputs, and the user-supplied
 * proof artifacts. The coordinator reconstructs `previousRoundTranscriptHash` +
 * `previousRoundCommitments` from the persisted `__round1.json` artifact — callers do NOT
 * supply them here (the round1 transcript IS the source of truth).
 */
export interface MpccaWithdrawRound2OrchestrateRequest
  extends MpccaWithdrawBaseRequest,
    MpccaWithdrawRound2StatementInputFields,
    MpccaWithdrawRound2OrchestrateProofFields {}

/**
 * M4 Commit 1 — single worker dk-base partial commitment. `commitmentHex` = `α_share_j[0]·base`
 * where `base` is the public point at canonical BASE_DK_SET position `index`.
 */
export interface MpccaWithdrawRound2DkPartial {
  index: number;
  commitmentHex: HexString;
}

/**
 * M4 Commit 1 — Round 2 worker response shape. The worker contributes ONLY the dk-component
 * of the sigma commitment vector A. Returned points cover exactly the BASE_DK_SET indices
 * (= `[0, 17]` for Aptos CA TransferV1 ell=8/n=4/no-auditor).
 *
 * Replaces the M3a stub-mode `MpccaWithdrawRound2Response` (which lives on as
 * `MpccaWithdrawRound2StubResponse` for backwards-compat with any in-flight chained-round
 * stub callers).
 */
export interface MpccaWithdrawRound2DkResult extends MpccaWithdrawBasePublicOutputs {
  completed: true;
  partialDkCommitments: MpccaWithdrawRound2DkPartial[];
  dkBaseIndicesUsed: number[];
}

// =================================================================================================
// Per-round Response shapes. Each round returns a per-slot "contribution" (commitment, partial
// response, partial bulletproof share, partial CA payload field bytes — whichever applies).
//
// Round1 ships with completed:true in Milestone 1 (ingress is real). Rounds 2/prove/finalize
// remain stub-mode with completed:false + notImplementedPhase until M4 lands.
// =================================================================================================
interface MpccaWithdrawBasePublicOutputs {
  slot: number;
  playerId: number;
  sessionStatePath: string;
  sessionStateHash: HexString;
  workerTranscriptHash: HexString;
  observedAtUnixMs: number;
}

interface MpccaWithdrawBaseStubResponse extends MpccaWithdrawBasePublicOutputs {
  completed: false;
  notImplementedPhase: string;
}

/**
 * Round1 ingress response. Successful M1 ingress flips `completed` to true and drops
 * `notImplementedPhase`. The new `ingressTranscriptHash` re-publishes the per-worker hash
 * over the M1-extended round1 transcript bytes so the coordinator's worker-agreement check
 * binds every worker to the same `(amountCommitment, perShareCommitments[], ingressEnvelopesHash)`.
 */
export interface MpccaWithdrawRound1Response extends MpccaWithdrawBasePublicOutputs {
  completed: true;
  /** Equals workerTranscriptHash. Named explicitly to make the M1 binding contract searchable. */
  ingressTranscriptHash: HexString;
}

export interface MpccaWithdrawRound2Response extends MpccaWithdrawBaseStubResponse {
  /** Per-slot Round 2 partial sigma response (32-byte hex scalar). */
  partialResponse?: HexString;
}

export interface MpccaWithdrawProveResponse extends MpccaWithdrawBaseStubResponse {
  /** Per-slot Bulletproof partial share (bytes hex). */
  partialBulletproofShare?: HexString;
}

export interface MpccaWithdrawFinalizeResponse extends MpccaWithdrawBaseStubResponse {
  /** Per-slot CA payload partial bytes that the finalize aggregator collects. */
  partialCaPayloadFields?: HexString;
}

// =================================================================================================
// Per-round Contribution — the slim shape the coordinator persists in the round transcript.
// Mirrors the (slot, contribution-hash, worker-transcript-hash) triple pattern from
// vault_state_v2 + ca_registration_v2.
//
// Round1 contribution carries completed:true under M1; chained rounds remain stub.
// =================================================================================================
interface MpccaWithdrawBaseContributionFields {
  slot: number;
  sessionStateHash: HexString;
  workerTranscriptHash: HexString;
}

interface MpccaWithdrawBaseStubContribution extends MpccaWithdrawBaseContributionFields {
  completed: false;
  notImplementedPhase: string;
}

export interface MpccaWithdrawRound1Contribution extends MpccaWithdrawBaseContributionFields {
  completed: true;
  /** Equals workerTranscriptHash. Public re-publication for the M1 binding contract. */
  ingressTranscriptHash: HexString;
}

export interface MpccaWithdrawRound2Contribution extends MpccaWithdrawBaseStubContribution {
  partialResponse?: HexString;
}

export interface MpccaWithdrawProveContribution extends MpccaWithdrawBaseStubContribution {
  partialBulletproofShare?: HexString;
}

export interface MpccaWithdrawFinalizeContribution extends MpccaWithdrawBaseStubContribution {
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

/**
 * Hash over the M1-extended round1 worker transcript. Domain bumped to V2; binds the three
 * ingress fields in addition to the base public envelope. Byte-identical to the Rust
 * `mpcca_withdraw_v2::round1_worker_transcript_hash` helper.
 *
 * Layout (round1 V2):
 *   base_parts (V2 domain) || ":"
 *   || amount_commitment_hex
 *   || ":" || joined(per_share_commitments_hex, "|")
 *   || ":" || ingress_envelopes_hash_hex
 *   → sha256 → lowercase hex.
 *
 * `ingressEnvelopesHash` is the lowercase hex of `sha256(concat(canonicalJsonStringify(env)
 * bytes))` over the 5 envelopes in sorted-selectedSlots order. The 5-of-7 worker-agreement
 * check at the coordinator binds every worker to the same envelope set.
 */
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
  amountCommitment: string;
  perShareCommitments: string[];
  ingressEnvelopesHash: string;
}): HexString {
  const parts = baseHashParts({
    domain: EUNOMA_MPCCA_WITHDRAW_V2_ROUND1_V2,
    ...args,
  });
  const enc = new TextEncoder();
  parts.push(enc.encode(":"));
  parts.push(enc.encode(normalizeHex(args.amountCommitment)));
  parts.push(enc.encode(":"));
  parts.push(enc.encode(args.perShareCommitments.map(normalizeHex).join("|")));
  parts.push(enc.encode(":"));
  parts.push(enc.encode(normalizeHex(args.ingressEnvelopesHash)));
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

/**
 * M4 Commit 1 — canonical sha256-hex of the normalised round2 Statement input fields. Byte
 * identical to Rust `statement_inputs_hash_hex` so the coordinator's worker_transcript_hash
 * cross-check holds across the language boundary.
 *
 * Layout (utf8 bytes, then sha256):
 *   recipient_ek_hex
 *   || ":" || old_balance_c[0]|...|old_balance_c[7]
 *   || ":" || old_balance_d[0]|...|old_balance_d[7]
 *   || ":" || new_balance_c[0]|...|new_balance_c[7]
 *   || ":" || new_balance_d[0]|...|new_balance_d[7]
 *   || ":" || transfer_amount_c[0]|...|transfer_amount_c[3]
 *   || ":" || transfer_amount_d_sender[0]|...|transfer_amount_d_sender[3]
 *   || ":" || transfer_amount_d_recipient[0]|...|transfer_amount_d_recipient[3]
 *
 * Every hex MUST already be normalised (32-byte lowercase, no `0x`). Caller validates lengths.
 */
export function mpccaWithdrawRound2StatementInputsHash(
  inputs: MpccaWithdrawRound2StatementInputFields,
): HexString {
  const enc = new TextEncoder();
  const parts: Uint8Array[] = [enc.encode(normalizeHex(inputs.recipientEk))];
  const groups: HexString[][] = [
    inputs.oldBalanceC,
    inputs.oldBalanceD,
    inputs.newBalanceC,
    inputs.newBalanceD,
    inputs.transferAmountC,
    inputs.transferAmountDSender,
    inputs.transferAmountDRecipient,
  ];
  for (const group of groups) {
    parts.push(enc.encode(":"));
    parts.push(enc.encode(group.map(normalizeHex).join("|")));
  }
  return bytesToHex(sha256(concat(parts)));
}

/**
 * M4 Commit 1 — round2 worker_transcript_hash. Byte-identical with Rust
 * `round2_v2_worker_transcript_hash(chained_hash_hex, statement_inputs_hash_hex)`.
 *
 *   chained_hash = sha256(round2 base + previous-round chain)  [domain V2]
 *   statement_inputs_hash = sha256(7 Statement input groups)
 *   worker_transcript_hash = sha256(chained_hash || ":" || statement_inputs_hash)
 *
 * A tampered Statement input flips the per-slot hash → the coordinator's
 * worker-transcript-agreement check rejects.
 */
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
  statementInputs: MpccaWithdrawRound2StatementInputFields;
}): HexString {
  const { statementInputs, ...chainedArgs } = args;
  const chainedHash = chainedRoundHash(EUNOMA_MPCCA_WITHDRAW_V2_ROUND2_V2, chainedArgs);
  const statementInputsHash = mpccaWithdrawRound2StatementInputsHash(statementInputs);
  const enc = new TextEncoder();
  const combined = concat([
    enc.encode(chainedHash),
    enc.encode(":"),
    enc.encode(statementInputsHash),
  ]);
  return bytesToHex(sha256(combined));
}

/**
 * M4 Commit 2 — deterministic coordinator-side round2 aggregate hash. Persisted into
 * `__round2.json` and consumed by prove/finalize as the `previousRoundTranscriptHash`
 * chain seed. Binds:
 *
 *   - The full Statement input set (via `mpccaWithdrawRound2StatementInputsHash`).
 *   - Per-slot worker dk-base partials in (slot ASC, dkIndex ASC) order.
 *   - Per-slot worker_transcript_hash values in slot ASC order.
 *   - The agreed dkBaseIndicesUsed canonical set.
 *
 * Anyone can recompute this hash from the persisted artifact; it is the public deterministic
 * fingerprint of the round2 step. NOT to be confused with the Fiat-Shamir sigma challenge
 * `e` (which is computed in M4 commit 4 once the full A vector is assembled).
 */
export function mpccaWithdrawRound2AggregateHash(input: {
  statementInputs: MpccaWithdrawRound2StatementInputFields;
  dkBaseIndicesUsed: number[];
  perSlotContributions: Array<{
    slot: number;
    workerTranscriptHash: HexString;
    partialDkCommitments: MpccaWithdrawRound2DkPartial[];
  }>;
}): HexString {
  const enc = new TextEncoder();
  const parts: Uint8Array[] = [
    enc.encode(EUNOMA_MPCCA_WITHDRAW_V2_ROUND2_AGGREGATE_V1),
    enc.encode(":"),
    enc.encode(mpccaWithdrawRound2StatementInputsHash(input.statementInputs)),
    enc.encode(":"),
    enc.encode([...input.dkBaseIndicesUsed].sort((a, b) => a - b).join(",")),
  ];
  const sortedContribs = [...input.perSlotContributions].sort((a, b) => a.slot - b.slot);
  for (const c of sortedContribs) {
    parts.push(enc.encode(":"));
    parts.push(enc.encode(c.slot.toString()));
    parts.push(enc.encode("|"));
    parts.push(enc.encode(normalizeHex(c.workerTranscriptHash)));
    parts.push(enc.encode("|"));
    const sortedPartials = [...c.partialDkCommitments].sort((a, b) => a.index - b.index);
    parts.push(
      enc.encode(
        sortedPartials.map((p) => `${p.index}=${normalizeHex(p.commitmentHex)}`).join(","),
      ),
    );
  }
  return bytesToHex(sha256(concat(parts)));
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

/**
 * M4 Commit 4 — canonical sha256 hex over the 30-entry aggregated sigma commitment vector.
 * Each entry is the normalised 32-byte hex; entries joined by `|`. Byte-identical with the
 * Rust `aggregated_sigma_commitments_hash_hex` helper.
 */
export function mpccaWithdrawFinalizeAggregatedCommitmentsHash(
  aggregatedSigmaCommitmentsHex: HexString[],
): HexString {
  const enc = new TextEncoder();
  const joined = aggregatedSigmaCommitmentsHex.map(normalizeHex).join("|");
  return bytesToHex(sha256(enc.encode(joined)));
}

/**
 * M4 Commit 3 — finalize worker_transcript_hash. Byte-identical with Rust
 * `finalize_v2_worker_transcript_hash(chained_hash, statement_inputs_hash,
 * aggregated_commitments_hash, challenge_hex)`.
 *
 *   chained_hash             = chainedRoundHash(FINALIZE domain)
 *   statement_inputs_hash    = mpccaWithdrawRound2StatementInputsHash(7 groups)
 *   aggregated_commits_hash  = sha256("hex0|hex1|...|hex29")
 *   worker_transcript_hash   = sha256(chained_hash || ":" || statement_inputs_hash
 *                                    || ":" || aggregated_commits_hash
 *                                    || ":" || challenge_hex)
 *
 * Binds the full coordinator-supplied (Statement, A, e) tuple into the per-slot hash so a
 * coordinator that tampers with ANY of the three for a single worker is rejected at the
 * coordinator-side cross-check.
 */
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
  statementInputs: MpccaWithdrawRound2StatementInputFields;
  aggregatedSigmaCommitmentsHex: HexString[];
  challengeHex: HexString;
}): HexString {
  const {
    statementInputs,
    aggregatedSigmaCommitmentsHex,
    challengeHex,
    ...chainedArgs
  } = args;
  const chainedHash = chainedRoundHash(EUNOMA_MPCCA_WITHDRAW_V2_FINALIZE_V1, chainedArgs);
  const statementInputsHash = mpccaWithdrawRound2StatementInputsHash(statementInputs);
  const aggregatedCommitmentsHash = mpccaWithdrawFinalizeAggregatedCommitmentsHash(
    aggregatedSigmaCommitmentsHex,
  );
  const challengeHexNorm = normalizeHex(challengeHex);
  const enc = new TextEncoder();
  const combined = concat([
    enc.encode(chainedHash),
    enc.encode(":"),
    enc.encode(statementInputsHash),
    enc.encode(":"),
    enc.encode(aggregatedCommitmentsHash),
    enc.encode(":"),
    enc.encode(challengeHexNorm),
  ]);
  return bytesToHex(sha256(combined));
}

/**
 * M4 Commit 4 — deterministic coordinator-side finalize aggregate hash. Persisted into
 * `__finalize.json` as the audit fingerprint binding:
 *
 *   - Statement input set (via `mpccaWithdrawRound2StatementInputsHash`).
 *   - Aggregated 30-point sigma commitment vector hash.
 *   - Fiat-Shamir challenge `e`.
 *   - Per-slot worker partial response shares + worker transcript hashes (sorted by slot).
 *
 * Domain: `EUNOMA_MPCCA_WITHDRAW_V2_FINALIZE_AGGREGATE_V1`. Distinct from the round2 aggregate
 * hash domain so cross-round transcript replay is impossible by construction.
 */
export const EUNOMA_MPCCA_WITHDRAW_V2_FINALIZE_AGGREGATE_V1 =
  "EUNOMA_MPCCA_WITHDRAW_V2_FINALIZE_AGGREGATE_V1";

/**
 * M4 Commit 4 — coordinator-side Fiat-Shamir challenge `e` derivation for the Aptos CA
 * TransferV1 sigma protocol. Calls into the Aptos SDK's `sigmaProtocolFiatShamir`, which
 * is the byte-canonical Move-compatible implementation, so the coordinator's e matches
 * what each worker computes locally (and what the chain verifier would compute).
 *
 * Inputs:
 *   - `statementInputs`: the 7 Aptos CA TransferV1 Statement input fields (recipient_ek +
 *     6 ciphertext vectors). Used together with the `vaultEkHex` (= sender_ek) to build
 *     the public Statement points.
 *   - `senderAddressHex`, `recipientAddressHex`, `assetTypeHex`, `chainId`: the chain-side
 *     identity that goes into the DomainSeparator's BCS-serialized TransferSession.
 *   - `aggregatedSigmaCommitmentsHex`: the 30-point aggregated commitment vector (each
 *     entry 32-byte compressed Ristretto hex).
 *
 * Returns the canonical 32-byte hex of `e` (LE bytes of the scalar mod ed25519 order).
 *
 * Defense in depth: each worker also recomputes `e` locally; the coordinator-supplied
 * `challengeHex` is byte-equality-checked by the worker before s_share is computed.
 */
export async function mpccaWithdrawFinalizeDeriveChallenge(input: {
  vaultEkHex: HexString;
  statementInputs: MpccaWithdrawRound2StatementInputFields;
  senderAddressHex: HexString;
  recipientAddressHex: HexString;
  assetTypeHex: HexString;
  chainId: number;
  aggregatedSigmaCommitmentsHex: HexString[];
}): Promise<HexString> {
  const {
    APTOS_FRAMEWORK_ADDRESS,
    H_RISTRETTO,
    RistrettoPoint,
    bcsSerializeTransferSession,
    sigmaProtocolFiatShamir,
  } = await import("@aptos-labs/confidential-asset");
  const PROTOCOL_ID = "AptosConfidentialAsset/TransferV1";
  const TYPE_NAME = "0x1::sigma_protocol_transfer::Transfer";

  function hexBytes32(hex: HexString, label: string): Uint8Array {
    const norm = normalizeHex(hex);
    const bytes = hexToBytes(norm);
    if (bytes.length !== 32) {
      throw new Error(
        `${label} must be 32-byte hex; got ${bytes.length} bytes`,
      );
    }
    return bytes;
  }

  const ekSidBytes = hexBytes32(input.vaultEkHex, "vaultEk");
  const ekRidBytes = hexBytes32(input.statementInputs.recipientEk, "recipientEk");
  const ekSid = RistrettoPoint.fromHex(ekSidBytes);
  const ekRid = RistrettoPoint.fromHex(ekRidBytes);
  const G = RistrettoPoint.BASE;
  const H = H_RISTRETTO;

  const points: ReturnType<typeof RistrettoPoint.fromHex>[] = [G, H, ekSid, ekRid];
  const compressedPoints: Uint8Array[] = [
    G.toRawBytes(),
    H.toRawBytes(),
    ekSidBytes,
    ekRidBytes,
  ];
  const pushAll = (group: HexString[], label: string) => {
    for (let i = 0; i < group.length; i += 1) {
      const bytes = hexBytes32(group[i], `${label}[${i}]`);
      points.push(RistrettoPoint.fromHex(bytes));
      compressedPoints.push(bytes);
    }
  };
  pushAll(input.statementInputs.oldBalanceC, "oldBalanceC");
  pushAll(input.statementInputs.oldBalanceD, "oldBalanceD");
  pushAll(input.statementInputs.newBalanceC, "newBalanceC");
  pushAll(input.statementInputs.newBalanceD, "newBalanceD");
  pushAll(input.statementInputs.transferAmountC, "transferAmountC");
  pushAll(input.statementInputs.transferAmountDSender, "transferAmountDSender");
  pushAll(input.statementInputs.transferAmountDRecipient, "transferAmountDRecipient");

  const senderAddr = hexBytes32(input.senderAddressHex, "senderAddress");
  const recipientAddr = hexBytes32(input.recipientAddressHex, "recipientAddress");
  const assetAddr = hexBytes32(input.assetTypeHex, "assetType");
  const sessionId = bcsSerializeTransferSession(
    senderAddr,
    recipientAddr,
    assetAddr,
    ROUND2_ELL,
    ROUND2_N,
    false,
    0,
  );
  const dst = {
    contractAddress: APTOS_FRAMEWORK_ADDRESS,
    chainId: input.chainId,
    protocolId: new TextEncoder().encode(PROTOCOL_ID),
    sessionId,
  };

  if (input.aggregatedSigmaCommitmentsHex.length !== 30) {
    throw new Error(
      `aggregatedSigmaCommitmentsHex must have 30 entries; got ${input.aggregatedSigmaCommitmentsHex.length}`,
    );
  }
  const compressedA: Uint8Array[] = input.aggregatedSigmaCommitmentsHex.map(
    (hex, i) => hexBytes32(hex, `aggregatedSigmaCommitmentsHex[${i}]`),
  );

  const stmt = { points, compressedPoints, scalars: [] };
  const { e } = sigmaProtocolFiatShamir(dst, TYPE_NAME, stmt, compressedA, 25);

  // Convert e (bigint scalar mod n) to 32-byte LE hex matching Rust's `Scalar::to_bytes()`.
  const eBytes = new Uint8Array(32);
  let value = e;
  for (let i = 0; i < 32; i += 1) {
    eBytes[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytesToHex(eBytes);
}

/**
 * M5 prep — build the Aptos CA TransferV1 `ConfidentialTransferRawPayloadV2` from M4's
 * MPCCA-finalize artifact + Statement inputs + base identity. This payload becomes the
 * BCS-encoded input to `keccak256` for `caPayloadHash`, which is the canonical hash the
 * Move-side verifier asserts via `hash_confidential_transfer_payload_v2`.
 *
 * Mapping (CA TransferV1, ell=8, n=4, no auditor):
 *   assetType            ← request.assetType (chain-side coin/token address)
 *   to                   ← request.recipient (chain-side recipient address)
 *   newBalanceP          ← statementInputs.newBalanceC (8 entries; Pedersen commitments)
 *   newBalanceR          ← statementInputs.newBalanceD (8 entries; ElGamal D-component)
 *   newBalanceREffAud    ← []                          (no effective auditor in alpha)
 *   amountP              ← statementInputs.transferAmountC (4 entries)
 *   amountRSender        ← statementInputs.transferAmountDSender (4 entries)
 *   amountRRecip         ← statementInputs.transferAmountDRecipient (4 entries)
 *   amountREffAud        ← []
 *   ekVolunAuds          ← []
 *   amountRVolunAuds     ← []
 *   zkrpNewBalance       ← mpccaWithdrawFinalizeArtifact.bulletproofZkrpNewBalanceHex
 *   zkrpAmount           ← mpccaWithdrawFinalizeArtifact.bulletproofZkrpAmountHex
 *   sigmaProtoComm       ← mpccaWithdrawFinalizeArtifact.aggregatedSigmaCommitmentsHex (30)
 *   sigmaProtoResp       ← mpccaWithdrawFinalizeArtifact.sigmaResponseHex (25)
 *   memo                 ← "" (empty in alpha; M5+ may bind out-of-band memo bytes)
 *
 * Byte-parity contract: pass the returned payload to `caPayloadHashRawV2` from `./bcs.js`
 * to compute the canonical keccak256 over the BCS encoding. The result MUST byte-equal
 * what the Move verifier produces from the same inputs (asserted by the
 * `caPayloadHashRawV2_matches_move_bcs_byte_layout` test).
 *
 * Inputs:
 *   - `mpccaArtifact`: the `mpccaWithdrawFinalizeArtifact` block persisted in
 *     `__finalize.json` by M4-c4 (M5 reads this from disk via `loadMpccaFinalizeTranscript`).
 *   - `statementInputs`: the round2 Statement input fields (recipient_ek + 6 ciphertext
 *     vectors). These travel with the round2 artifact; M5 will also persist them in
 *     `__finalize.json` (or M5 callers will read them from `__round2.json`).
 *   - `recipientAddressHex`, `assetTypeHex`: chain-side identity from the base request.
 */
export function buildCaPayloadFromFinalizeArtifact(input: {
  recipientAddressHex: HexString;
  assetTypeHex: HexString;
  statementInputs: MpccaWithdrawRound2StatementInputFields;
  mpccaArtifact: {
    aggregatedSigmaCommitmentsHex: HexString[];
    sigmaResponseHex: HexString[];
    bulletproofZkrpAmountHex: HexString;
    bulletproofZkrpNewBalanceHex: HexString;
  };
  memoHex?: HexString;
}): {
  assetType: HexString;
  to: HexString;
  newBalanceP: HexString[];
  newBalanceR: HexString[];
  newBalanceREffAud: HexString[];
  amountP: HexString[];
  amountRSender: HexString[];
  amountRRecip: HexString[];
  amountREffAud: HexString[];
  ekVolunAuds: HexString[];
  amountRVolunAuds: HexString[][];
  zkrpNewBalance: HexString;
  zkrpAmount: HexString;
  sigmaProtoComm: HexString[];
  sigmaProtoResp: HexString[];
  memo: HexString;
} {
  if (input.statementInputs.newBalanceC.length !== ROUND2_ELL) {
    throw new Error(
      `buildCaPayloadFromFinalizeArtifact: newBalanceC must have ${ROUND2_ELL} entries; got ${input.statementInputs.newBalanceC.length}`,
    );
  }
  if (input.statementInputs.newBalanceD.length !== ROUND2_ELL) {
    throw new Error(
      `buildCaPayloadFromFinalizeArtifact: newBalanceD must have ${ROUND2_ELL} entries; got ${input.statementInputs.newBalanceD.length}`,
    );
  }
  if (input.statementInputs.transferAmountC.length !== ROUND2_N) {
    throw new Error(
      `buildCaPayloadFromFinalizeArtifact: transferAmountC must have ${ROUND2_N} entries; got ${input.statementInputs.transferAmountC.length}`,
    );
  }
  if (input.statementInputs.transferAmountDSender.length !== ROUND2_N) {
    throw new Error(
      `buildCaPayloadFromFinalizeArtifact: transferAmountDSender must have ${ROUND2_N} entries; got ${input.statementInputs.transferAmountDSender.length}`,
    );
  }
  if (input.statementInputs.transferAmountDRecipient.length !== ROUND2_N) {
    throw new Error(
      `buildCaPayloadFromFinalizeArtifact: transferAmountDRecipient must have ${ROUND2_N} entries; got ${input.statementInputs.transferAmountDRecipient.length}`,
    );
  }
  if (input.mpccaArtifact.aggregatedSigmaCommitmentsHex.length !== 30) {
    throw new Error(
      `buildCaPayloadFromFinalizeArtifact: aggregatedSigmaCommitmentsHex must have 30 entries; got ${input.mpccaArtifact.aggregatedSigmaCommitmentsHex.length}`,
    );
  }
  if (input.mpccaArtifact.sigmaResponseHex.length !== 25) {
    throw new Error(
      `buildCaPayloadFromFinalizeArtifact: sigmaResponseHex must have 25 entries; got ${input.mpccaArtifact.sigmaResponseHex.length}`,
    );
  }
  return {
    assetType: normalizeHex(input.assetTypeHex),
    to: normalizeHex(input.recipientAddressHex),
    newBalanceP: input.statementInputs.newBalanceC.map((h) => normalizeHex(h)),
    newBalanceR: input.statementInputs.newBalanceD.map((h) => normalizeHex(h)),
    newBalanceREffAud: [],
    amountP: input.statementInputs.transferAmountC.map((h) => normalizeHex(h)),
    amountRSender: input.statementInputs.transferAmountDSender.map((h) => normalizeHex(h)),
    amountRRecip: input.statementInputs.transferAmountDRecipient.map((h) => normalizeHex(h)),
    amountREffAud: [],
    ekVolunAuds: [],
    amountRVolunAuds: [],
    zkrpNewBalance: normalizeHex(input.mpccaArtifact.bulletproofZkrpNewBalanceHex),
    zkrpAmount: normalizeHex(input.mpccaArtifact.bulletproofZkrpAmountHex),
    sigmaProtoComm: input.mpccaArtifact.aggregatedSigmaCommitmentsHex.map((h) => normalizeHex(h)),
    sigmaProtoResp: input.mpccaArtifact.sigmaResponseHex.map((h) => normalizeHex(h)),
    memo: input.memoHex ? normalizeHex(input.memoHex) : "",
  };
}

export function mpccaWithdrawFinalizeAggregateHash(input: {
  statementInputs: MpccaWithdrawRound2StatementInputFields;
  aggregatedSigmaCommitmentsHex: HexString[];
  challengeHex: HexString;
  dkBaseIndicesUsed: number[];
  perSlotContributions: Array<{
    slot: number;
    workerTranscriptHash: HexString;
    partialResponseDkHex: HexString;
  }>;
}): HexString {
  const enc = new TextEncoder();
  const parts: Uint8Array[] = [
    enc.encode(EUNOMA_MPCCA_WITHDRAW_V2_FINALIZE_AGGREGATE_V1),
    enc.encode(":"),
    enc.encode(mpccaWithdrawRound2StatementInputsHash(input.statementInputs)),
    enc.encode(":"),
    enc.encode(mpccaWithdrawFinalizeAggregatedCommitmentsHash(input.aggregatedSigmaCommitmentsHex)),
    enc.encode(":"),
    enc.encode(normalizeHex(input.challengeHex)),
    enc.encode(":"),
    enc.encode([...input.dkBaseIndicesUsed].sort((a, b) => a - b).join(",")),
  ];
  const sortedContribs = [...input.perSlotContributions].sort((a, b) => a.slot - b.slot);
  for (const c of sortedContribs) {
    parts.push(enc.encode(":"));
    parts.push(enc.encode(c.slot.toString()));
    parts.push(enc.encode("|"));
    parts.push(enc.encode(normalizeHex(c.workerTranscriptHash)));
    parts.push(enc.encode("|"));
    parts.push(enc.encode(normalizeHex(c.partialResponseDkHex)));
  }
  return bytesToHex(sha256(concat(parts)));
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
  const writeStubContribution = (
    label: string,
    contribs: MpccaWithdrawBaseStubContribution[],
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
  // Round1 has its own completed:true layout under M1: label "r1v2" + per-slot
  // ingressTranscriptHash. The "r1v2" label intentionally differs from the M3a "r1" stub
  // label so any stale stub-mode transcript cannot collide with a completed-M1 transcript.
  const sortedR1 = [...input.round1Contributions].sort((a, b) => a.slot - b.slot);
  parts.push(enc.encode(":"));
  parts.push(enc.encode("r1v2"));
  for (const c of sortedR1) {
    parts.push(enc.encode(":"));
    parts.push(enc.encode(c.slot.toString()));
    parts.push(enc.encode("|"));
    parts.push(enc.encode(normalizeHex(c.sessionStateHash)));
    parts.push(enc.encode("|"));
    parts.push(enc.encode(normalizeHex(c.workerTranscriptHash)));
    parts.push(enc.encode("|"));
    parts.push(enc.encode("completed"));
    parts.push(enc.encode("|"));
    parts.push(enc.encode(normalizeHex(c.ingressTranscriptHash)));
  }
  const sortedR2 = [...input.round2Contributions].sort((a, b) => a.slot - b.slot);
  writeStubContribution("r2", sortedR2, (i) =>
    sortedR2[i].partialResponse ? normalizeHex(sortedR2[i].partialResponse!) : "",
  );
  const sortedPr = [...input.proveContributions].sort((a, b) => a.slot - b.slot);
  writeStubContribution("pr", sortedPr, (i) =>
    sortedPr[i].partialBulletproofShare
      ? normalizeHex(sortedPr[i].partialBulletproofShare!)
      : "",
  );
  const sortedFin = [...input.finalizeContributions].sort((a, b) => a.slot - b.slot);
  writeStubContribution("fin", sortedFin, (i) =>
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

// =================================================================================================
// Milestone 1 — ingress envelope validation helpers. All shape validation; no crypto evaluation.
// The aggregate-commitment invariant (`Σ perShareCommitments = amountCommitment`) is checked
// by `aggregatePerShareCommitments` outside of the parser to keep parsing pure.
// =================================================================================================
function requireHpkeEnvelopeShape(value: unknown, where: string): HpkeEnvelope {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new MpccaWithdrawV2Error(
      "INGRESS_INVALID_ENVELOPE_SHAPE",
      `${where} must be an HpkeEnvelope object`,
    );
  }
  const obj = value as Record<string, unknown>;
  if (obj.kem !== "DHKEM_X25519_HKDF_SHA256") {
    throw new MpccaWithdrawV2Error(
      "INGRESS_INVALID_ENVELOPE_SHAPE",
      `${where}.kem must be DHKEM_X25519_HKDF_SHA256`,
    );
  }
  if (obj.kdf !== "HKDF_SHA256") {
    throw new MpccaWithdrawV2Error(
      "INGRESS_INVALID_ENVELOPE_SHAPE",
      `${where}.kdf must be HKDF_SHA256`,
    );
  }
  if (obj.aead !== "AES_256_GCM") {
    throw new MpccaWithdrawV2Error(
      "INGRESS_INVALID_ENVELOPE_SHAPE",
      `${where}.aead must be AES_256_GCM`,
    );
  }
  const enc = obj.enc;
  const ciphertext = obj.ciphertext;
  const aadHash = obj.aadHash;
  if (typeof enc !== "string" || enc.length === 0) {
    throw new MpccaWithdrawV2Error(
      "INGRESS_INVALID_ENVELOPE_SHAPE",
      `${where}.enc must be a non-empty hex string`,
    );
  }
  if (typeof ciphertext !== "string" || ciphertext.length === 0) {
    throw new MpccaWithdrawV2Error(
      "INGRESS_INVALID_ENVELOPE_SHAPE",
      `${where}.ciphertext must be a non-empty hex string`,
    );
  }
  if (typeof aadHash !== "string" || aadHash.length === 0) {
    throw new MpccaWithdrawV2Error(
      "INGRESS_INVALID_ENVELOPE_SHAPE",
      `${where}.aadHash must be a non-empty hex string`,
    );
  }
  const encNorm = normalizeHex(enc);
  if (hexToBytes(encNorm).length !== 32) {
    throw new MpccaWithdrawV2Error(
      "INGRESS_INVALID_ENVELOPE_SHAPE",
      `${where}.enc must be 32-byte hex (X25519 KEM ephemeral)`,
    );
  }
  const aadHashNorm = normalizeHex(aadHash);
  if (hexToBytes(aadHashNorm).length !== 32) {
    throw new MpccaWithdrawV2Error(
      "INGRESS_INVALID_ENVELOPE_SHAPE",
      `${where}.aadHash must be 32-byte hex`,
    );
  }
  const ciphertextNorm = normalizeHex(ciphertext);
  const ctBytes = hexToBytes(ciphertextNorm);
  // 64-byte plaintext (a_i || b_i) + 16-byte AES-GCM tag.
  if (ctBytes.length !== 80) {
    throw new MpccaWithdrawV2Error(
      "INGRESS_INVALID_ENVELOPE_SHAPE",
      `${where}.ciphertext must be 80-byte hex (64-byte plaintext + 16-byte GCM tag)`,
    );
  }
  return {
    kem: "DHKEM_X25519_HKDF_SHA256",
    kdf: "HKDF_SHA256",
    aead: "AES_256_GCM",
    enc: encNorm,
    ciphertext: ciphertextNorm,
    aadHash: aadHashNorm,
  };
}

function requireIngressEnvelopes(obj: Record<string, unknown>): HpkeEnvelope[] {
  const v = obj.ingressEnvelopes;
  if (!Array.isArray(v)) {
    throw new MpccaWithdrawV2Error(
      "INGRESS_ENVELOPE_COUNT_MISMATCH",
      "ingressEnvelopes must be an array",
    );
  }
  if (v.length !== DEOPERATOR_THRESHOLD) {
    throw new MpccaWithdrawV2Error(
      "INGRESS_ENVELOPE_COUNT_MISMATCH",
      `ingressEnvelopes must have exactly ${DEOPERATOR_THRESHOLD} entries, got ${v.length}`,
    );
  }
  return v.map((entry, i) =>
    requireHpkeEnvelopeShape(entry, `ingressEnvelopes[${i}]`),
  );
}

function requirePerShareCommitments(obj: Record<string, unknown>): HexString[] {
  const v = obj.perShareCommitments;
  if (!Array.isArray(v)) {
    throw new MpccaWithdrawV2Error(
      "INGRESS_COMMITMENT_COUNT_MISMATCH",
      "perShareCommitments must be an array",
    );
  }
  if (v.length !== DEOPERATOR_THRESHOLD) {
    throw new MpccaWithdrawV2Error(
      "INGRESS_COMMITMENT_COUNT_MISMATCH",
      `perShareCommitments must have exactly ${DEOPERATOR_THRESHOLD} entries, got ${v.length}`,
    );
  }
  const out: HexString[] = [];
  for (let i = 0; i < v.length; i += 1) {
    const entry = v[i];
    if (typeof entry !== "string" || entry.length === 0) {
      throw new MpccaWithdrawV2Error(
        "INGRESS_INVALID_COMMITMENT_SHAPE",
        `perShareCommitments[${i}] must be a non-empty hex string`,
      );
    }
    const norm = normalizeHex(entry);
    if (hexToBytes(norm).length !== 32) {
      throw new MpccaWithdrawV2Error(
        "INGRESS_INVALID_COMMITMENT_SHAPE",
        `perShareCommitments[${i}] must be 32-byte hex (compressed Ristretto)`,
      );
    }
    out.push(norm);
  }
  return out;
}

/**
 * Canonical JSON-stringify with sorted keys. Used for AAD and `ingressEnvelopesHash`
 * computation so byte-parity holds across TS↔Rust.
 */
export function canonicalJsonStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map((v) => canonicalJsonStringify(v)).join(",") + "]";
  }
  const entries = Object.entries(value as Record<string, unknown>).sort(
    ([a], [b]) => (a < b ? -1 : a > b ? 1 : 0),
  );
  return (
    "{" +
    entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJsonStringify(v)}`).join(",") +
    "}"
  );
}

/**
 * sha256-hex over `concat(canonicalJsonStringify(env) as utf8 bytes)` across the 5 envelopes
 * in sorted-selectedSlots order. Used as the public binding for the M1 round1 transcript hash.
 * Byte-identical to Rust `mpcca_withdraw_v2::ingress_envelopes_hash`.
 */
export function ingressEnvelopesHash(envelopes: HpkeEnvelope[]): HexString {
  const enc = new TextEncoder();
  const parts: Uint8Array[] = [];
  for (const e of envelopes) {
    parts.push(enc.encode(canonicalJsonStringify(e)));
  }
  return bytesToHex(sha256(concat(parts)));
}

/**
 * sha256-hex over `concat(perShareCommitmentsHexBytes...)`. The result is folded into the
 * M1 AAD so a tampered commitment list invalidates every envelope.
 */
export function perShareCommitmentsHash(perShareCommitments: HexString[]): HexString {
  const enc = new TextEncoder();
  const parts: Uint8Array[] = [];
  for (const c of perShareCommitments) {
    parts.push(enc.encode(normalizeHex(c)));
  }
  return bytesToHex(sha256(concat(parts)));
}

/**
 * AAD used by the user's client and re-derived by each worker on decrypt. Byte-identical
 * to Rust `mpcca_withdraw_v2::m1_ingress_aad`. Any field mismatch invalidates the seal.
 */
export function m1IngressAad(args: {
  requestId: string;
  sessionId: string;
  dkgEpoch: string;
  selfSlot: number;
  playerId: number;
  rosterHash: HexString;
  vaultEk: HexString;
  root: HexString;
  nullifierHash: HexString;
  recipientHash: HexString;
  amountTag: HexString;
  vaultSequence: number;
  depositCount: number;
  amountCommitment: HexString;
  perShareCommitments: HexString[];
}): Uint8Array {
  const aad = {
    amountCommitmentHex: normalizeHex(args.amountCommitment),
    amountTag: normalizeHex(args.amountTag),
    depositCount: args.depositCount.toString(),
    dkgEpoch: args.dkgEpoch,
    domain: EUNOMA_M1_AMOUNT_INGRESS_V1,
    nullifierHash: normalizeHex(args.nullifierHash),
    perShareCommitmentsHashHex: perShareCommitmentsHash(args.perShareCommitments),
    playerId: args.playerId.toString(),
    recipientHash: normalizeHex(args.recipientHash),
    requestId: args.requestId,
    root: normalizeHex(args.root),
    rosterHash: normalizeHex(args.rosterHash),
    selfSlot: args.selfSlot.toString(),
    sessionId: args.sessionId,
    vaultEk: normalizeHex(args.vaultEk),
    vaultSequence: args.vaultSequence.toString(),
  };
  return new TextEncoder().encode(canonicalJsonStringify(aad));
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
  const base = parseBaseRequest(body);
  const obj = objectBody(body);
  const amountCommitment = requireHex(obj, "amountCommitment", 32);
  const perShareCommitments = requirePerShareCommitments(obj);
  const ingressEnvelopes = requireIngressEnvelopes(obj);
  return {
    ...base,
    amountCommitment,
    perShareCommitments,
    ingressEnvelopes,
  };
}

/**
 * M4 Commit 1 — validate the 7 Statement input fields with their canonical
 * `ROUND2_ELL=8` / `ROUND2_N=4` lengths and 32-byte hex per entry.
 */
function requireRound2StatementInputs(
  obj: Record<string, unknown>,
): MpccaWithdrawRound2StatementInputFields {
  const requireHexVec = (key: string, expected: number): HexString[] => {
    const v = obj[key];
    if (!Array.isArray(v) || v.length !== expected) {
      throw new MpccaWithdrawV2Error(
        "INVALID_STATEMENT_INPUT_SHAPE",
        `${key} must be an array of exactly ${expected} entries (got ${
          Array.isArray(v) ? v.length : typeof v
        })`,
      );
    }
    const out: HexString[] = [];
    for (let i = 0; i < v.length; i += 1) {
      const entry = v[i];
      if (typeof entry !== "string" || entry.length === 0) {
        throw new MpccaWithdrawV2Error(
          "INVALID_STATEMENT_INPUT_SHAPE",
          `${key}[${i}] must be a non-empty hex string`,
        );
      }
      const norm = normalizeHex(entry);
      if (hexToBytes(norm).length !== 32) {
        throw new MpccaWithdrawV2Error(
          "INVALID_STATEMENT_INPUT_SHAPE",
          `${key}[${i}] must be 32-byte hex (compressed Ristretto)`,
        );
      }
      out.push(norm);
    }
    return out;
  };
  return {
    recipientEk: requireHex(obj, "recipientEk", 32),
    oldBalanceC: requireHexVec("oldBalanceC", ROUND2_ELL),
    oldBalanceD: requireHexVec("oldBalanceD", ROUND2_ELL),
    newBalanceC: requireHexVec("newBalanceC", ROUND2_ELL),
    newBalanceD: requireHexVec("newBalanceD", ROUND2_ELL),
    transferAmountC: requireHexVec("transferAmountC", ROUND2_N),
    transferAmountDSender: requireHexVec("transferAmountDSender", ROUND2_N),
    transferAmountDRecipient: requireHexVec("transferAmountDRecipient", ROUND2_N),
  };
}

/**
 * M4 Commit 1 — round2 worker request. Chained-round envelope + 7 Statement input fields.
 * Used by the worker-side handler at `POST /worker/v2/mpcca/withdraw/round2`. Forbidden
 * plaintext fields are guarded by `parseBaseRequest`.
 */
export function parseMpccaWithdrawRound2Request(
  body: unknown,
): MpccaWithdrawRound2Request {
  const chained = parseChainedRequest(body);
  const obj = objectBody(body);
  return { ...chained, ...requireRound2StatementInputs(obj) };
}

/**
 * M4 Commit 2 — coordinator-inbound orchestrate request for `POST /v2/withdraw/mpcca/round2`.
 *
 * Wire shape: base identity (the Milestone 3a base envelope minus the previous-round chain
 * fields, which the coordinator lifts from the persisted `__round1.json` artifact), the 7
 * Statement input fields, and the user-supplied proof artifacts. Forbidden plaintext fields
 * are guarded by `parseBaseRequest`.
 *
 * Coordinator builds the per-worker `Round2Request` (chained binding + Statement) by joining
 * this body with the round1 transcript's `transcriptHash` and per-slot ingressTranscriptHash.
 */
export function parseMpccaWithdrawRound2OrchestrateRequest(
  body: unknown,
): MpccaWithdrawRound2OrchestrateRequest {
  const base = parseBaseRequest(body);
  const obj = objectBody(body);
  const stmt = requireRound2StatementInputs(obj);
  const userSigmaCommitmentsHex = requireFixedLengthHexVec(
    obj,
    "userSigmaCommitmentsHex",
    USER_SIGMA_COMMITMENTS_LEN,
    32,
    "INVALID_USER_SIGMA_SHAPE",
  );
  const userSigmaResponseSharesHex = requireFixedLengthHexVec(
    obj,
    "userSigmaResponseSharesHex",
    USER_SIGMA_RESPONSE_SHARES_LEN,
    32,
    "INVALID_USER_SIGMA_SHAPE",
  );
  const bulletproofZkrpAmountHex = requireNonEmptyHex(
    obj,
    "bulletproofZkrpAmountHex",
    "INVALID_BULLETPROOF_BYTES",
  );
  const bulletproofZkrpNewBalanceHex = requireNonEmptyHex(
    obj,
    "bulletproofZkrpNewBalanceHex",
    "INVALID_BULLETPROOF_BYTES",
  );
  const perChunkCommitmentsAmountHex = requireFixedLengthHexVec(
    obj,
    "perChunkCommitmentsAmountHex",
    ROUND2_N,
    32,
    "INVALID_PER_CHUNK_COMMITMENT_SHAPE",
  );
  const perChunkCommitmentsNewBalanceHex = requireFixedLengthHexVec(
    obj,
    "perChunkCommitmentsNewBalanceHex",
    ROUND2_ELL,
    32,
    "INVALID_PER_CHUNK_COMMITMENT_SHAPE",
  );
  return {
    ...base,
    ...stmt,
    userSigmaCommitmentsHex,
    userSigmaResponseSharesHex,
    bulletproofZkrpAmountHex,
    bulletproofZkrpNewBalanceHex,
    perChunkCommitmentsAmountHex,
    perChunkCommitmentsNewBalanceHex,
  };
}

function requireFixedLengthHexVec(
  obj: Record<string, unknown>,
  key: string,
  expected: number,
  bytesPerEntry: number,
  errorCode: MpccaWithdrawV2ErrorCode,
): HexString[] {
  const v = obj[key];
  if (!Array.isArray(v) || v.length !== expected) {
    throw new MpccaWithdrawV2Error(
      errorCode,
      `${key} must be an array of exactly ${expected} entries (got ${
        Array.isArray(v) ? v.length : typeof v
      })`,
    );
  }
  const out: HexString[] = [];
  for (let i = 0; i < v.length; i += 1) {
    const entry = v[i];
    if (typeof entry !== "string" || entry.length === 0) {
      throw new MpccaWithdrawV2Error(
        errorCode,
        `${key}[${i}] must be a non-empty hex string`,
      );
    }
    const norm = normalizeHex(entry);
    if (hexToBytes(norm).length !== bytesPerEntry) {
      throw new MpccaWithdrawV2Error(
        errorCode,
        `${key}[${i}] must be ${bytesPerEntry}-byte hex`,
      );
    }
    out.push(norm);
  }
  return out;
}

function requireNonEmptyHex(
  obj: Record<string, unknown>,
  key: string,
  errorCode: MpccaWithdrawV2ErrorCode,
): HexString {
  const v = obj[key];
  if (typeof v !== "string" || v.length === 0) {
    throw new MpccaWithdrawV2Error(errorCode, `${key} must be a non-empty hex string`);
  }
  const norm = normalizeHex(v);
  if (hexToBytes(norm).length === 0) {
    throw new MpccaWithdrawV2Error(
      errorCode,
      `${key} must decode to at least one byte`,
    );
  }
  return norm;
}

export function parseMpccaWithdrawProveRequest(
  body: unknown,
): MpccaWithdrawProveRequest {
  return parseChainedRequest(body);
}

/**
 * M4 Commit 3 — finalize worker request. Chained-round envelope + 7 Statement input fields
 * (byte-identical to round2's) + the coordinator-aggregated 30-point sigma commitment vector
 * + Fiat-Shamir challenge `e`. Used by the worker-side handler at
 * `POST /worker/v2/mpcca/withdraw/finalize`. Forbidden plaintext fields are guarded by
 * `parseBaseRequest`.
 *
 * Wire shape: every base ChainedRoundRequest field at top level, then the 7 Statement input
 * fields, then `aggregatedSigmaCommitmentsHex` (30 × 32-byte hex compressed Ristretto), then
 * `challengeHex` (32-byte canonical Ed25519 scalar hex). Mirrors the Rust `FinalizeRequest`
 * struct.
 */
export function parseMpccaWithdrawFinalizeRequest(
  body: unknown,
): MpccaWithdrawFinalizeRequest {
  const chained = parseChainedRequest(body);
  const obj = objectBody(body);
  const stmt = requireRound2StatementInputs(obj);
  const aggregatedSigmaCommitmentsHex = requireFixedLengthHexVec(
    obj,
    "aggregatedSigmaCommitmentsHex",
    30,
    32,
    "INVALID_USER_SIGMA_SHAPE",
  );
  const challengeHex = requireFixedLengthHex(
    obj,
    "challengeHex",
    32,
    "INVALID_USER_SIGMA_SHAPE",
  );
  return {
    ...chained,
    ...stmt,
    aggregatedSigmaCommitmentsHex,
    challengeHex,
  };
}

/**
 * M4 Commit 3 — parse the worker's `FinalizeDkResult` HTTP reply. The Rust worker emits this
 * shape under `#[serde(rename_all = "camelCase")]`. Validates:
 *   - `completed === true` (M4 commit 3 path; stub-mode finalize is retired).
 *   - `partialResponseDkHex` is canonical 32-byte hex (an Ed25519 scalar).
 *   - `dkBaseIndicesUsed` is a sorted-equal-to-canonical subset of `DK_BASE_INDICES_CANONICAL`
 *     (= `[0, 17]`).
 *
 * Caller-side: the coordinator additionally cross-checks
 * `dkBaseIndicesUsed === DK_BASE_INDICES_CANONICAL` across ALL 5 workers (any divergence
 * surfaces `DK_BASE_INDICES_DIVERGENCE`).
 */
export function parseMpccaWithdrawFinalizeDkResult(
  body: unknown,
): MpccaWithdrawFinalizeDkResult {
  const pub = parsePublicOutputs(body);
  const obj = objectBody(body);
  const completed = obj.completed;
  if (completed !== true) {
    throw new MpccaWithdrawV2Error(
      "INVALID_ROUND2_PARTIAL_SHAPE",
      "M4 commit 3 finalize response must have completed: true",
    );
  }
  const partialResponseDkHex = requireFixedLengthHex(
    obj,
    "partialResponseDkHex",
    32,
    "INVALID_ROUND2_PARTIAL_SHAPE",
  );
  const rawIndices = obj.dkBaseIndicesUsed;
  if (!Array.isArray(rawIndices)) {
    throw new MpccaWithdrawV2Error(
      "INVALID_ROUND2_PARTIAL_SHAPE",
      "dkBaseIndicesUsed must be an array",
    );
  }
  const dkBaseIndicesUsed: number[] = [];
  for (let i = 0; i < rawIndices.length; i += 1) {
    const idx = rawIndices[i];
    if (!Number.isInteger(idx) || (idx as number) < 0 || (idx as number) > 1024) {
      throw new MpccaWithdrawV2Error(
        "INVALID_ROUND2_PARTIAL_SHAPE",
        `dkBaseIndicesUsed[${i}] must be a small non-negative integer`,
      );
    }
    dkBaseIndicesUsed.push(idx as number);
  }
  // Defense-in-depth: every index must be in the canonical {0, 17} set.
  for (const idx of dkBaseIndicesUsed) {
    if (!DK_BASE_INDICES_CANONICAL.includes(idx)) {
      throw new MpccaWithdrawV2Error(
        "INVALID_ROUND2_PARTIAL_SHAPE",
        `dkBaseIndicesUsed entry ${idx} not in canonical BASE_DK_SET ${DK_BASE_INDICES_CANONICAL.join(",")}`,
      );
    }
  }
  return {
    ...pub,
    completed: true,
    partialResponseDkHex,
    dkBaseIndicesUsed,
  };
}

/**
 * M5 Commit 1 — `WithdrawFinalizeAttestationConfig` shape used to seal a withdraw
 * attestation message. Mirrors the persisted `attestationConfig` field on the finalize
 * transcript: chain-side identity (bridge, vault, asset) + operator-set version + roster
 * hash + FROST group pubkey + circuit-versions hash. The FROST attestation route uses
 * these fields when building the `WithdrawAttestationV2Message` that workers sign.
 */
export interface MpccaWithdrawFrostAttestConfig {
  bridge: HexString;
  vault: HexString;
  operatorSetVersion: string;
  frostGroupPubkey: HexString;
  circuitVersionsHash: HexString;
}

/**
 * M5 Commit 1 — coordinator-inbound `POST /v2/withdraw/mpcca/frost-attest` request body.
 *
 * Wire shape: base identity envelope + chain-side `attestationConfig` + user-supplied
 * `withdrawProofHex` (the Groth16 zk-SNARK over (root, nullifierHash, asset_id,
 * recipientHash, amountTag, caPayloadHash, requestHash, vaultSequence)).
 *
 * The coordinator reconstructs:
 *   - the MPCCA-finalize artifact (aggregated A + e + sigma response + zkrp + perChunk)
 *     by reading `__finalize.json`
 *   - the Statement input fields by reading `__round2.json`
 * Then it builds the CA payload + caPayloadHash, drives the 3-round FROST signing
 * ceremony over the BCS-encoded `WithdrawAttestationV2Message`, and assembles the
 * 27-field `withdrawV2CallArgsFields` written back into `__finalize.json` (removing
 * the `notImplementedPhase = "m4_pending_frost_signature_assembly"` sentinel).
 */
export interface MpccaWithdrawFrostAttestStartRequest extends MpccaWithdrawBaseRequest {
  /** Chain-side attestation context (bridge, vault, operator set, FROST group pubkey). */
  attestationConfig: MpccaWithdrawFrostAttestConfig;
  /**
   * User-supplied withdraw Groth16 proof bytes, or "0x" after the user has already
   * verified and cached the proof with `prepare_withdraw_proof_v2`.
   */
  withdrawProofHex: HexString;
  /** Optional memo bytes bound into the CA payload. Defaults to empty. */
  memoHex?: HexString;
  /** ASP: asp_root (32B Fr) + the 2 LeanIMT depths — public inputs of the withdraw proof. */
  aspRoot: HexString;
  stateTreeDepth: number;
  aspTreeDepth: number;
  /** V4 B-prime: change commitment plus spent-note/remainder conservation publics. */
  changeCommitment: HexString;
  amountPDigest: HexString;
  amountPOld: HexString[];
  amountPRem: HexString[];
}

/**
 * M4 Commit 4 — coordinator-inbound orchestrate request for `POST /v2/withdraw/mpcca/finalize`.
 *
 * Wire shape: ONLY the base identity envelope. The coordinator reconstructs Statement inputs +
 * user proof artifacts from the persisted `__round2.json` artifact and aggregates worker
 * partials into `A_full[30]` + computes Fiat-Shamir `e`. Forbidden plaintext fields are
 * guarded by `parseBaseRequest`.
 */
export function parseMpccaWithdrawFinalizeOrchestrateRequest(
  body: unknown,
): MpccaWithdrawFinalizeOrchestrateRequest {
  return parseBaseRequest(body);
}

/**
 * M5 Commit 1 — coordinator-inbound parser for `POST /v2/withdraw/mpcca/frost-attest`.
 *
 * Validates the base identity envelope + the chain-side attestation config (bridge,
 * vault, operatorSetVersion, frostGroupPubkey, circuitVersionsHash) + the user-supplied
 * withdrawProofHex bytes. "0x" is allowed only for the Stage 4 A6 prepared-withdraw path:
 * Move will consume an exact pending proof tuple or abort. Forbidden plaintext fields rejected
 * via parseBaseRequest.
 */
export function parseMpccaWithdrawFrostAttestStartRequest(
  body: unknown,
): MpccaWithdrawFrostAttestStartRequest {
  const base = parseBaseRequest(body);
  const obj = objectBody(body);
  const attestationConfigRaw = obj.attestationConfig;
  if (
    !attestationConfigRaw ||
    typeof attestationConfigRaw !== "object" ||
    Array.isArray(attestationConfigRaw)
  ) {
    throw new MpccaWithdrawV2Error(
      "INVALID_WITHDRAW_FIELD_SHAPE",
      "attestationConfig must be an object",
    );
  }
  const config = attestationConfigRaw as Record<string, unknown>;
  const bridge = requireHex(config, "bridge", 32);
  const vault = requireHex(config, "vault", 32);
  const frostGroupPubkey = requireHex(config, "frostGroupPubkey", 32);
  const circuitVersionsHash = requireHex(config, "circuitVersionsHash", 32);
  const operatorSetVersionRaw = config.operatorSetVersion;
  if (
    typeof operatorSetVersionRaw !== "string" ||
    !/^(0|[1-9][0-9]*)$/.test(operatorSetVersionRaw)
  ) {
    throw new MpccaWithdrawV2Error(
      "INVALID_WITHDRAW_FIELD_SHAPE",
      "attestationConfig.operatorSetVersion must be a decimal string",
    );
  }
  const withdrawProofHex = obj.withdrawProofHex;
  if (typeof withdrawProofHex !== "string" || withdrawProofHex.length === 0) {
    throw new MpccaWithdrawV2Error(
      "INVALID_BULLETPROOF_BYTES",
      "withdrawProofHex must be a hex string (Groth16 proof bytes, or 0x after prepare_withdraw_proof_v2)",
    );
  }
  const withdrawProofNorm = normalizeHex(withdrawProofHex);
  hexToBytes(withdrawProofNorm);
  let memoHex: HexString | undefined;
  const memoRaw = obj.memoHex;
  if (memoRaw !== undefined && memoRaw !== null) {
    if (typeof memoRaw !== "string") {
      throw new MpccaWithdrawV2Error(
        "INVALID_WITHDRAW_FIELD_SHAPE",
        "memoHex must be a hex string when present",
      );
    }
    memoHex = normalizeHex(memoRaw);
    // Sanity: decode to validate it's hex.
    hexToBytes(memoHex);
  }
  // ASP: asp_root (32B Fr) + the 2 LeanIMT depths (1..32). Public inputs of the withdraw proof.
  const aspRoot = requireHex(obj, "aspRoot", 32);
  const changeCommitment = requireHex(obj, "changeCommitment", 32);
  const amountPDigest = requireHex(obj, "amountPDigest", 32);
  const amountPOld = requireFixedLengthHexVec(
    obj,
    "amountPOld",
    4,
    32,
    "INVALID_WITHDRAW_FIELD_SHAPE",
  );
  const amountPRem = requireFixedLengthHexVec(
    obj,
    "amountPRem",
    4,
    32,
    "INVALID_WITHDRAW_FIELD_SHAPE",
  );
  const stateTreeDepthRaw = obj.stateTreeDepth;
  const aspTreeDepthRaw = obj.aspTreeDepth;
  if (
    typeof stateTreeDepthRaw !== "number" || !Number.isInteger(stateTreeDepthRaw) ||
    stateTreeDepthRaw < 1 || stateTreeDepthRaw > 32 ||
    typeof aspTreeDepthRaw !== "number" || !Number.isInteger(aspTreeDepthRaw) ||
    aspTreeDepthRaw < 1 || aspTreeDepthRaw > 32
  ) {
    throw new MpccaWithdrawV2Error(
      "INVALID_WITHDRAW_FIELD_SHAPE",
      "stateTreeDepth and aspTreeDepth must be integers in [1,32]",
    );
  }
  return {
    ...base,
    aspRoot,
    stateTreeDepth: stateTreeDepthRaw,
    aspTreeDepth: aspTreeDepthRaw,
    changeCommitment,
    amountPDigest,
    amountPOld,
    amountPRem,
    attestationConfig: {
      bridge,
      vault,
      operatorSetVersion: operatorSetVersionRaw,
      frostGroupPubkey,
      circuitVersionsHash,
    },
    withdrawProofHex: withdrawProofNorm,
    ...(memoHex !== undefined ? { memoHex } : {}),
  };
}

function requireFixedLengthHex(
  obj: Record<string, unknown>,
  key: string,
  bytes: number,
  errorCode: MpccaWithdrawV2ErrorCode,
): HexString {
  const v = obj[key];
  if (typeof v !== "string" || v.length === 0) {
    throw new MpccaWithdrawV2Error(errorCode, `${key} must be a non-empty hex string`);
  }
  const norm = normalizeHex(v);
  if (hexToBytes(norm).length !== bytes) {
    throw new MpccaWithdrawV2Error(errorCode, `${key} must be ${bytes}-byte hex`);
  }
  return norm;
}

function parsePublicOutputs(body: unknown): MpccaWithdrawBasePublicOutputs {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  return {
    slot: requireInt(obj, "slot", 0, DEOPERATOR_COUNT - 1),
    playerId: requireInt(obj, "playerId", 0, DEOPERATOR_THRESHOLD - 1),
    sessionStatePath: requireString(obj, "sessionStatePath"),
    sessionStateHash: requireHex(obj, "sessionStateHash", 32),
    workerTranscriptHash: requireHex(obj, "workerTranscriptHash", 32),
    observedAtUnixMs: requireInt(obj, "observedAtUnixMs", 0, Number.MAX_SAFE_INTEGER),
  };
}

function parseBaseStubResponse(body: unknown): MpccaWithdrawBaseStubResponse {
  const pub = parsePublicOutputs(body);
  const obj = objectBody(body);
  const completed = obj.completed;
  if (completed !== false) {
    throw new MpccaWithdrawV2Error(
      "INVALID_CONTRIBUTION_SHAPE",
      "completed must be the literal boolean false for stub-mode rounds (round2/prove/finalize)",
    );
  }
  return {
    ...pub,
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
  const pub = parsePublicOutputs(body);
  const obj = objectBody(body);
  const completed = obj.completed;
  if (completed !== true) {
    throw new MpccaWithdrawV2Error(
      "INVALID_CONTRIBUTION_SHAPE",
      "round1 response must have completed: true (Milestone 1 ingress is real, not stub)",
    );
  }
  const ingressTranscriptHash = requireHex(obj, "ingressTranscriptHash", 32);
  if (normalizeHex(ingressTranscriptHash) !== normalizeHex(pub.workerTranscriptHash)) {
    throw new MpccaWithdrawV2Error(
      "INVALID_CONTRIBUTION_SHAPE",
      "ingressTranscriptHash must equal workerTranscriptHash",
    );
  }
  return { ...pub, completed: true, ingressTranscriptHash };
}

export function parseMpccaWithdrawRound2Response(
  body: unknown,
): MpccaWithdrawRound2Response {
  const base = parseBaseStubResponse(body);
  const obj = objectBody(body);
  return { ...base, partialResponse: maybeHex(obj, "partialResponse") };
}

/**
 * M4 Commit 1 — parse the worker's `Round2DkResult` HTTP reply. The Rust worker emits this
 * shape under `#[serde(rename_all = "camelCase")]`. Validates:
 *   - `completed === true` (M4 commit 1 path; stub-mode rounds are gone for round2).
 *   - `partialDkCommitments` is a non-empty array of `{ index, commitmentHex }`, no duplicate
 *     indices, each `commitmentHex` is canonical 32-byte hex.
 *   - `dkBaseIndicesUsed` equals `partialDkCommitments.map(p => p.index)` after sort, and is
 *     a subset of `DK_BASE_INDICES_CANONICAL` (= `[0, 17]`).
 *
 * Caller-side: the coordinator additionally cross-checks
 * `dkBaseIndicesUsed === DK_BASE_INDICES_CANONICAL` across ALL 5 workers (any divergence
 * surfaces `DK_BASE_INDICES_DIVERGENCE`).
 */
export function parseMpccaWithdrawRound2DkResult(
  body: unknown,
): MpccaWithdrawRound2DkResult {
  const pub = parsePublicOutputs(body);
  const obj = objectBody(body);
  const completed = obj.completed;
  if (completed !== true) {
    throw new MpccaWithdrawV2Error(
      "INVALID_ROUND2_PARTIAL_SHAPE",
      "M4 commit 1 round2 response must have completed: true",
    );
  }
  const rawPartials = obj.partialDkCommitments;
  if (!Array.isArray(rawPartials) || rawPartials.length === 0) {
    throw new MpccaWithdrawV2Error(
      "INVALID_ROUND2_PARTIAL_SHAPE",
      "partialDkCommitments must be a non-empty array",
    );
  }
  const partialDkCommitments: MpccaWithdrawRound2DkPartial[] = [];
  const seenIndices = new Set<number>();
  for (let i = 0; i < rawPartials.length; i += 1) {
    const entry = rawPartials[i];
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new MpccaWithdrawV2Error(
        "INVALID_ROUND2_PARTIAL_SHAPE",
        `partialDkCommitments[${i}] must be an object`,
      );
    }
    const e = entry as Record<string, unknown>;
    const index = e.index;
    if (
      !Number.isInteger(index) ||
      (index as number) < 0 ||
      (index as number) > 1024
    ) {
      throw new MpccaWithdrawV2Error(
        "INVALID_ROUND2_PARTIAL_SHAPE",
        `partialDkCommitments[${i}].index must be a small non-negative integer`,
      );
    }
    if (seenIndices.has(index as number)) {
      throw new MpccaWithdrawV2Error(
        "DUPLICATE_DK_INDEX",
        `partialDkCommitments duplicate index ${index}`,
      );
    }
    seenIndices.add(index as number);
    const commitmentHex = e.commitmentHex;
    if (typeof commitmentHex !== "string" || commitmentHex.length === 0) {
      throw new MpccaWithdrawV2Error(
        "INVALID_ROUND2_PARTIAL_SHAPE",
        `partialDkCommitments[${i}].commitmentHex must be a non-empty hex string`,
      );
    }
    const norm = normalizeHex(commitmentHex);
    if (hexToBytes(norm).length !== 32) {
      throw new MpccaWithdrawV2Error(
        "INVALID_ROUND2_PARTIAL_SHAPE",
        `partialDkCommitments[${i}].commitmentHex must be 32-byte hex`,
      );
    }
    partialDkCommitments.push({ index: index as number, commitmentHex: norm });
  }
  const rawIndices = obj.dkBaseIndicesUsed;
  if (!Array.isArray(rawIndices)) {
    throw new MpccaWithdrawV2Error(
      "INVALID_ROUND2_PARTIAL_SHAPE",
      "dkBaseIndicesUsed must be an array",
    );
  }
  const dkBaseIndicesUsed: number[] = [];
  for (let i = 0; i < rawIndices.length; i += 1) {
    const idx = rawIndices[i];
    if (!Number.isInteger(idx) || (idx as number) < 0 || (idx as number) > 1024) {
      throw new MpccaWithdrawV2Error(
        "INVALID_ROUND2_PARTIAL_SHAPE",
        `dkBaseIndicesUsed[${i}] must be a small non-negative integer`,
      );
    }
    dkBaseIndicesUsed.push(idx as number);
  }
  // dkBaseIndicesUsed must mirror partialDkCommitments[*].index (any order).
  const partialIndicesSorted = partialDkCommitments
    .map((p) => p.index)
    .sort((a, b) => a - b);
  const dkIndicesSorted = [...dkBaseIndicesUsed].sort((a, b) => a - b);
  if (partialIndicesSorted.length !== dkIndicesSorted.length) {
    throw new MpccaWithdrawV2Error(
      "INVALID_ROUND2_PARTIAL_SHAPE",
      "dkBaseIndicesUsed length must equal partialDkCommitments length",
    );
  }
  for (let i = 0; i < partialIndicesSorted.length; i += 1) {
    if (partialIndicesSorted[i] !== dkIndicesSorted[i]) {
      throw new MpccaWithdrawV2Error(
        "INVALID_ROUND2_PARTIAL_SHAPE",
        "dkBaseIndicesUsed entries must match partialDkCommitments indices",
      );
    }
  }
  // Defense in depth: the canonical BASE_DK_SET for Aptos CA TransferV1 is `[0, 17]`. Reject
  // any out-of-set indices at the boundary. The coordinator additionally enforces all 5
  // workers return the SAME set via DK_BASE_INDICES_DIVERGENCE.
  for (const idx of dkBaseIndicesUsed) {
    if (!DK_BASE_INDICES_CANONICAL.includes(idx)) {
      throw new MpccaWithdrawV2Error(
        "INVALID_ROUND2_PARTIAL_SHAPE",
        `dkBaseIndicesUsed entry ${idx} not in canonical BASE_DK_SET ${DK_BASE_INDICES_CANONICAL.join(",")}`,
      );
    }
  }
  return {
    ...pub,
    completed: true,
    partialDkCommitments,
    dkBaseIndicesUsed,
  };
}

export function parseMpccaWithdrawProveResponse(
  body: unknown,
): MpccaWithdrawProveResponse {
  const base = parseBaseStubResponse(body);
  const obj = objectBody(body);
  return {
    ...base,
    partialBulletproofShare: maybeHex(obj, "partialBulletproofShare"),
  };
}

export function parseMpccaWithdrawFinalizeResponse(
  body: unknown,
): MpccaWithdrawFinalizeResponse {
  const base = parseBaseStubResponse(body);
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

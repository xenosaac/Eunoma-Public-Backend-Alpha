import type { HexString } from "@eunoma/shared";

export type RequestPhase =
  | "dkg-ca"
  | "dkg-frost"
  | "deposit-bind"
  | "withdraw-ca-payload"
  | "mpcca-withdraw"
  | "attestation"
  | "abort";

export type DkgProtocol = "ca" | "frost";

export type DkgRound =
  | "round1"
  | "round2"
  | "round2_send"
  | "round2_receive"
  | "complaint"
  | "finalize";

export type MpccaProtocol = "withdraw";

export type MpccaRound = "round1" | "round2" | "prove" | "finalize";

export type QuorumSlots5 = [number, number, number, number, number];

export type PartialArtifactKind =
  | "dkg-ca-round"
  | "dkg-frost-round"
  | "ca-registration"
  | "mpcca-withdraw-round"
  | "deposit-bind"
  | "withdraw-ca-payload"
  | "attestation";

export interface CircuitVersions {
  depositBinding: string;
  withdraw: string;
  caPayload: string;
}

export type CaDkgScheme = "ca_dkg_v2" | "ca_local";

export interface RosterNode {
  slot: number;
  nodeId: string;
  endpoint: string;
  hpkePublicKey: HexString;
  transcriptPublicKey: HexString;
  frostVerifyingShare: HexString;
}

export interface DeoperatorRoster {
  operatorSetVersion: string;
  dkgEpoch: string;
  caDkgScheme: CaDkgScheme;
  threshold: number;
  nodes: RosterNode[];
  frostGroupPubkey: HexString;
  vaultEk: HexString;
  circuitVersions: CircuitVersions;
}

export interface CaDkgV2RosterNode {
  slot: number;
  nodeId: string;
  endpoint: string;
  hpkePublicKey: HexString;
  transcriptPublicKey: HexString;
}

export interface CaDkgV2Roster {
  operatorSetVersion: string;
  dkgEpoch: string;
  caDkgScheme: "ca_dkg_v2";
  threshold: number;
  nodes: CaDkgV2RosterNode[];
}

export interface FrostDkgV2RosterNode {
  slot: number;
  nodeId: string;
  endpoint: string;
  hpkePublicKey: HexString;
  transcriptPublicKey: HexString;
}

export interface FrostDkgV2Roster {
  operatorSetVersion: string;
  dkgEpoch: string;
  caDkgScheme: "frost_dkg_v2";
  threshold: number;
  nodes: FrostDkgV2RosterNode[];
}

export interface FrostRound1Broadcast {
  slot: number;
  packageHex: HexString;
  packageHash: HexString;
  transcriptHash: HexString;
}

export interface FrostRound2Envelope {
  dealerSlot: number;
  toSlot: number;
  packageCommitment: HexString;
  hpke: HpkeEnvelope;
}

export interface FrostDkgV2Complaint {
  accusedSlot: number;
  evidenceKind: string;
  evidenceHash: HexString;
}

export interface HpkeEnvelope {
  kem: "DHKEM_X25519_HKDF_SHA256";
  kdf: "HKDF_SHA256";
  aead: "AES_256_GCM";
  enc: HexString;
  ciphertext: HexString;
  aadHash: HexString;
}

export interface SessionShareEnvelope {
  requestId: string;
  sessionId: string;
  phase: RequestPhase;
  rosterHash: HexString;
  senderHpkePublicKey: HexString;
  shareCommitments: HexString[];
  envelopes: Array<{
    slot: number;
    shareCommitment: HexString;
    hpke: HpkeEnvelope;
  }>;
  transcriptHash?: HexString;
}

export interface DepositBindRequest {
  requestId: string;
  sessionId: string;
  rosterHash: HexString;
  commitment: HexString;
  amountTag: HexString;
  caPayloadHash: HexString;
  depositNonce: HexString;
  shareCommitments: HexString[];
  transcriptHash: HexString;
}

export interface DepositBindResult {
  requestId: string;
  sessionId: string;
  slot: number;
  accepted: true;
  transcriptHash: HexString;
  bindingProofShare: HexString;
}

export interface WithdrawCAPayloadRequest {
  requestId: string;
  sessionId: string;
  rosterHash: HexString;
  root: HexString;
  nullifierHash: HexString;
  recipient: HexString;
  recipientHash: HexString;
  amountTag: HexString;
  vaultSequence: string;
  shareCommitments: HexString[];
  transcriptHash: HexString;
}

export interface WithdrawCAPayloadResult {
  requestId: string;
  sessionId: string;
  slot: number;
  accepted: true;
  transcriptHash: HexString;
  caPayloadShare: HexString;
  caPayloadHashShare: HexString;
}

export interface DkgRoundRequest {
  requestId: string;
  sessionId: string;
  protocol: DkgProtocol;
  round: DkgRound;
  operatorSetVersion: string;
  dkgEpoch: string;
  rosterHash: HexString;
  threshold: number;
  participantSlots: number[];
  slot: number;
  transcriptHash?: HexString;
  commitments: HexString[];
  encryptedShares: Array<{
    dealerSlot?: number;
    toSlot: number;
    shareCommitment?: HexString;
    hpke: HpkeEnvelope;
  }>;
  caDkgScheme?: CaDkgScheme;
  caDkgV2Roster?: CaDkgV2Roster;
  dealerBroadcasts?: CaDkgV2DealerBroadcast[];
  frostDkgV2Roster?: FrostDkgV2Roster;
  frostDkgV2RosterHash?: HexString;
  frostRound1Broadcasts?: FrostRound1Broadcast[];
  frostRound2Envelopes?: FrostRound2Envelope[];
  complaint?: {
    accusedSlot: number;
    evidenceHash: HexString;
  };
}

export interface CaDkgV2DealerBroadcast {
  slot: number;
  commitments: HexString[];
  transcriptHash: HexString;
}

export interface CaDkgV2Complaint {
  accusedSlot: number;
  evidenceHash: HexString;
  reason?: string;
}

export interface DkgRoundResult {
  requestId: string;
  sessionId: string;
  protocol: DkgProtocol;
  round: DkgRound;
  operatorSetVersion: string;
  dkgEpoch: string;
  slot: number;
  accepted: true;
  transcriptHash: HexString;
  artifactHash: HexString;
  publicShare?: HexString;
  groupPublicKey?: HexString;
  abortEvidenceHash?: HexString;
  dealerBroadcast?: CaDkgV2DealerBroadcast;
  encryptedShares?: Array<{
    dealerSlot?: number;
    toSlot: number;
    shareCommitment?: HexString;
    hpke: HpkeEnvelope;
  }>;
  acceptedDealers?: number[];
  aggregateCommitments?: HexString[];
  caDkgShareHash?: HexString;
  complaints?: CaDkgV2Complaint[];
  finalized?: boolean;
  caDkgTranscriptHash?: HexString;
  frostRound1Broadcast?: FrostRound1Broadcast;
  frostRound2Envelopes?: FrostRound2Envelope[];
  frostVerifyingShare?: HexString;
  frostKeyPackageHash?: HexString;
  frostPublicPackageHash?: HexString;
}

export interface FrostDkgV2WorkerArtifact {
  slot: number;
  artifactHash: HexString;
  frostKeyPackageHash: HexString;
  frostPublicPackageHash: HexString;
  frostVerifyingShare: HexString;
}

export interface CaRegistrationCommitmentInput {
  slot: number;
  commitment: HexString;
}

export interface CaRegistrationResponseInput {
  slot: number;
  response: HexString;
}

export interface CaRegistrationNonceCommitRequest {
  requestId: string;
}

export interface CaRegistrationNonceCommitResult {
  nonce_id: string;
  commitment: HexString;
  commitment_hash: HexString;
  transcript_hash: HexString;
}

export interface CaRegistrationChallengeRequest {
  vaultEk: HexString;
  senderAddress: HexString;
  assetType: HexString;
  chainId: number;
  quorumSlots: QuorumSlots5;
  commitments: CaRegistrationCommitmentInput[];
}

export interface CaRegistrationChallengeResult {
  aggregateCommitment: HexString;
  challenge: HexString;
}

export interface CaRegistrationPartialRequest {
  nonceId: string;
  challenge: HexString;
}

export interface CaRegistrationPartialResult {
  nonce_id: string;
  response: HexString;
  response_hash: HexString;
  transcript_hash: HexString;
}

export interface CaRegistrationAggregateRequest {
  vaultEk: HexString;
  senderAddress: HexString;
  assetType: HexString;
  chainId: number;
  quorumSlots: QuorumSlots5;
  commitments: CaRegistrationCommitmentInput[];
  responses: CaRegistrationResponseInput[];
}

export interface CaRegistrationAggregateResult {
  sigma_proto_comm: HexString[];
  sigma_proto_resp: HexString[];
  challenge: HexString;
  proof_hash: HexString;
  transcript_hash: HexString;
}

export interface MpccaRoundRequest {
  requestId: string;
  sessionId: string;
  protocol: MpccaProtocol;
  round: MpccaRound;
  rosterHash: HexString;
  slot: number;
  quorumSlots?: QuorumSlots5;
  root: HexString;
  nullifierHash: HexString;
  recipient: HexString;
  recipientHash: HexString;
  amountTag: HexString;
  vaultSequence: string;
  shareCommitments: HexString[];
  transcriptHash: HexString;
  publicInputsHash: HexString;
  roundCommitments: HexString[];
}

export interface MpccaRoundResult {
  requestId: string;
  sessionId: string;
  protocol: MpccaProtocol;
  round: MpccaRound;
  slot: number;
  accepted: true;
  transcriptHash: HexString;
  artifactHash: HexString;
  caPayloadHashShare?: HexString;
  caPayload?: ConfidentialTransferRawPayloadV2;
  caPayloadHashRaw?: HexString;
  caPayloadHashFrSafe?: HexString;
  quorumTranscriptHash?: HexString;
  workerArtifactHashes?: HexString[];
}

export interface AttestationPartialRequest {
  requestId: string;
  sessionId: string;
  rosterHash: HexString;
  quorumSlots: QuorumSlots5;
  messageBytes: HexString;
  caPayloadHash: HexString;
  groth16ProofHash: HexString;
  transcriptHash: HexString;
}

export interface AttestationPartialResult {
  requestId: string;
  sessionId: string;
  slot: number;
  accepted: true;
  transcriptHash: HexString;
  frostSignatureShare: HexString;
}

export interface AbortEvidenceRequest {
  requestId: string;
  sessionId: string;
  rosterHash: HexString;
  accusedSlot: number;
  evidenceKind: "bad-share" | "timeout" | "invalid-proof-share" | "equivocation";
  transcriptHash: HexString;
  evidenceHash: HexString;
}

export interface RequestStatus {
  requestId: string;
  status: "unknown" | "pending" | "complete" | "aborted";
  rosterHash?: HexString;
  transcriptHashes: HexString[];
  updatedAt: string;
}

export interface WithdrawAttestationV2Message {
  chainId: number;
  bridge: HexString;
  vault: HexString;
  assetType: HexString;
  operatorSetVersion: string;
  dkgEpoch: string;
  rosterHash: HexString;
  frostGroupPubkey: HexString;
  root: HexString;
  nullifierHash: HexString;
  recipient: HexString;
  recipientHash: HexString;
  amountTag: HexString;
  caPayloadHash: HexString;
  requestHash: HexString;
  vaultSequence: string;
  expirySecs: string;
  circuitVersionsHash: HexString;
}

export interface DepositAttestationV2Message {
  chainId: number;
  bridge: HexString;
  vault: HexString;
  assetType: HexString;
  operatorSetVersion: string;
  dkgEpoch: string;
  rosterHash: HexString;
  frostGroupPubkey: HexString;
  commitment: HexString;
  amountTag: HexString;
  caPayloadHash: HexString;
  depositNonce: HexString;
  expirySecs: string;
  circuitVersionsHash: HexString;
}

export interface ConfidentialTransferRawPayloadV2 {
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
}

export interface CAPayloadHashesV2 {
  raw: HexString;
  fr: HexString;
}

export interface AptosTestnetChainConfigV2 {
  network: "testnet";
  chainId: 2;
  nodeUrl: string;
}

export interface VaultEkContribution {
  slot: number;
  hContribution: HexString;
  schnorrProof: { R: HexString; s: HexString };
  workerTranscriptHash: HexString;
}

export interface VaultEkDerivationInput {
  dkgEpoch: string;
  caDkgTranscriptHash: HexString;
  selectedSlots: number[];
  rosterHash: HexString;
  contributions: VaultEkContribution[];
  roster: CaDkgV2Roster;
}

/**
 * Phase 2 wire shape for `/worker/v2/derive/vault_ek/round1`. Adds the fields each MASCOT
 * party needs to spawn its own subprocess + recompute the Lagrange coefficient locally.
 * `selectedSlots` is already in the Phase 1 shape; it is duplicated here for clarity since
 * `playerId` is the ordinal within sorted(`selectedSlots`).
 */
export interface VaultEkRound1Request {
  dkgEpoch: string;
  caDkgTranscriptHash: HexString;
  rosterHash: HexString;
  selectedSlots: number[];
  selfSlot: number;
  /** Phase 2: identifier for this derivation request (echoed in the artifact). */
  requestId: string;
  /** Phase 2: outer coordination session — equal to requestId in Phase 2. */
  sessionId: string;
  /** Phase 2: this party's ordinal within sorted(selectedSlots), 0..N-1. */
  playerId: number;
  /** Phase 2: ordered `host:port` for the 5 MASCOT peers, in player-ordinal order. */
  peerAddresses: string[];
  /** Phase 2: hex-encoded Lagrange coefficients at x=0 for sorted(selectedSlots). */
  lagrangeCoefficients: HexString[];
}

export interface VaultEkDerivationTranscript {
  scheme: "vault_ek_derivation_v1";
  dkgEpoch: string;
  caDkgTranscriptHash: HexString;
  selectedSlots: number[];
  rosterHash: HexString;
  contributions: VaultEkContribution[];
}

export type VaultEkDerivationCode =
  | "UNDER_QUORUM"
  | "DUPLICATE_SLOT"
  | "UNKNOWN_SLOT"
  | "STALE_DKG_EPOCH"
  | "STALE_CA_DKG_TRANSCRIPT_HASH"
  | "STALE_ROSTER_HASH"
  | "INVALID_CONTRIBUTION_SHAPE";

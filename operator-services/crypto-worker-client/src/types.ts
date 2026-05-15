import type {
  AttestationPartialRequest,
  AttestationPartialResult,
  CaRegistrationAggregateRequest,
  CaRegistrationAggregateResult,
  CaRegistrationChallengeRequest,
  CaRegistrationChallengeResult,
  CaRegistrationNonceCommitRequest,
  CaRegistrationNonceCommitResult,
  CaRegistrationPartialRequest,
  CaRegistrationPartialResult,
  DepositBindRequest,
  DepositBindResult,
  DkgRoundRequest,
  DkgRoundResult,
  MpccaRoundRequest,
  MpccaRoundResult,
  SessionShareEnvelope,
  WithdrawCAPayloadRequest,
  WithdrawCAPayloadResult,
} from "@eunoma/deop-protocol";

export type {
  CaRegistrationAggregateRequest,
  CaRegistrationAggregateResult,
  CaRegistrationChallengeRequest,
  CaRegistrationChallengeResult,
  CaRegistrationNonceCommitRequest,
  CaRegistrationNonceCommitResult,
  CaRegistrationPartialRequest,
  CaRegistrationPartialResult,
} from "@eunoma/deop-protocol";

export interface DkgCaStartRequest {
  operatorSetVersion: string;
  dkgEpoch: string;
  rosterHash: string;
}

export interface DkgCaStartResult {
  dkgEpoch: string;
  vaultEkShare: string;
  transcriptHash: string;
}

export interface DkgFrostStartRequest {
  operatorSetVersion: string;
  dkgEpoch: string;
  rosterHash: string;
}

export interface DkgFrostStartResult {
  dkgEpoch: string;
  frostVerifyingShare: string;
  transcriptHash: string;
}

export interface WorkerLocalState {
  slot: number;
  state_dir: string;
  has_frost_key_package: boolean;
  has_frost_public_package: boolean;
  frost_key_package_hash?: string;
  frost_public_package_hash?: string;
  pending_frost_nonces: number;
  has_ca_dkg_share?: boolean;
  ca_dkg_share_hash?: string;
  ca_dkg_transcript_hash?: string;
  vault_ek?: string;
  pending_registration_nonces?: number;
}

export interface FrostCommitmentInput {
  slot: number;
  commitments: unknown;
}

export interface FrostSignatureShareInput {
  slot: number;
  signatureShare: unknown;
}

export interface FrostNonceCommitRequest {
  requestId: string;
}

export interface FrostNonceCommitResult {
  nonce_id: string;
  commitment_hash: string;
  commitments: unknown;
  transcript_hash: string;
}

export interface FrostPartialSignRequest {
  nonceId: string;
  messageBytes: string;
  commitments: FrostCommitmentInput[];
}

export interface FrostPartialSignResult {
  nonce_id: string;
  signature_share_hash: string;
  signature_share: unknown;
  transcript_hash: string;
}

export interface FrostAggregateRequest {
  messageBytes: string;
  commitments: FrostCommitmentInput[];
  signatureShares: FrostSignatureShareInput[];
}

export interface FrostAggregateResult {
  signature: string;
  signature_hash: string;
  transcript_hash: string;
}

export interface CryptoWorker {
  getLocalState(): Promise<WorkerLocalState>;
  acceptSessionShare(input: SessionShareEnvelope): Promise<{ accepted: true; transcriptHash: string }>;
  runDkgRound(input: DkgRoundRequest): Promise<DkgRoundResult>;
  runMpccaRound(input: MpccaRoundRequest): Promise<MpccaRoundResult>;
  startDkgCa(input: DkgCaStartRequest): Promise<DkgCaStartResult>;
  startDkgFrost(input: DkgFrostStartRequest): Promise<DkgFrostStartResult>;
  bindDeposit(input: DepositBindRequest): Promise<DepositBindResult>;
  buildWithdrawCAPayload(input: WithdrawCAPayloadRequest): Promise<WithdrawCAPayloadResult>;
  partialAttestation(input: AttestationPartialRequest): Promise<AttestationPartialResult>;
  frostNonceCommit(input: FrostNonceCommitRequest): Promise<FrostNonceCommitResult>;
  frostPartialSign(input: FrostPartialSignRequest): Promise<FrostPartialSignResult>;
  frostAggregate(input: FrostAggregateRequest): Promise<FrostAggregateResult>;
  caRegistrationNonceCommit(input: CaRegistrationNonceCommitRequest): Promise<CaRegistrationNonceCommitResult>;
  caRegistrationChallenge(input: CaRegistrationChallengeRequest): Promise<CaRegistrationChallengeResult>;
  caRegistrationPartial(input: CaRegistrationPartialRequest): Promise<CaRegistrationPartialResult>;
  caRegistrationAggregate(input: CaRegistrationAggregateRequest): Promise<CaRegistrationAggregateResult>;
}

export class CryptoWorkerUnavailableError extends Error {
  constructor(message = "crypto worker unavailable") {
    super(message);
    this.name = "CryptoWorkerUnavailableError";
  }
}

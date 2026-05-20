import { hexToBytes } from "@eunoma/shared";
import { caPayloadHashFrV2, caPayloadHashRawV2 } from "./bcs.js";
import {
  CA_DKG_SCHEME_LOCAL,
  CA_DKG_SCHEME_V2,
  DEOPERATOR_COUNT,
  DEOPERATOR_THRESHOLD,
  ED25519_PUBLIC_KEY_BYTES,
  FR_BYTES,
} from "./constants.js";
import { assertNoForbiddenPlaintextFields } from "./forbidden.js";
import type {
  AbortEvidenceRequest,
  AttestationPartialRequest,
  CaDkgV2Roster,
  CaRegistrationAggregateRequest,
  CaRegistrationAggregateResult,
  CaRegistrationChallengeRequest,
  CaRegistrationChallengeResult,
  CaRegistrationCommitmentInput,
  CaRegistrationNonceCommitRequest,
  CaRegistrationNonceCommitResult,
  CaRegistrationPartialRequest,
  CaRegistrationPartialResult,
  CaRegistrationResponseInput,
  ConfidentialTransferRawPayloadV2,
  DepositBindRequest,
  DkgProtocol,
  DkgRound,
  DkgRoundRequest,
  DkgRoundResult,
  FrostDkgV2Roster,
  FrostRound1Broadcast,
  FrostRound2Envelope,
  MpccaProtocol,
  MpccaRound,
  MpccaRoundRequest,
  MpccaRoundResult,
  PartialArtifactKind,
  QuorumSlots5,
  SessionShareEnvelope,
  WithdrawCAPayloadRequest,
} from "./types.js";

export class UnderQuorumError extends Error {
  readonly code = "under_quorum";

  constructor(message = "under-quorum rejected") {
    super(message);
    this.name = "UnderQuorumError";
  }
}

export function parseSessionShareEnvelope(body: unknown): SessionShareEnvelope {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  const out = {
    requestId: stringField(obj, "requestId"),
    sessionId: stringField(obj, "sessionId"),
    phase: phaseField(stringField(obj, "phase")),
    rosterHash: hexField(obj, "rosterHash", 32),
    senderHpkePublicKey: hexField(obj, "senderHpkePublicKey", 32),
    shareCommitments: hexArrayField(obj, "shareCommitments", FR_BYTES),
    envelopes: envelopeArrayField(obj, "envelopes"),
    transcriptHash: optionalHexField(obj, "transcriptHash", 32),
  };
  return out;
}

export function parseDepositBindRequest(body: unknown): DepositBindRequest {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  return {
    requestId: stringField(obj, "requestId"),
    sessionId: stringField(obj, "sessionId"),
    rosterHash: hexField(obj, "rosterHash", 32),
    commitment: hexField(obj, "commitment", FR_BYTES),
    amountTag: hexField(obj, "amountTag", FR_BYTES),
    caPayloadHash: hexField(obj, "caPayloadHash", 32),
    depositNonce: hexField(obj, "depositNonce"),
    shareCommitments: hexArrayField(obj, "shareCommitments", FR_BYTES),
    transcriptHash: hexField(obj, "transcriptHash", 32),
  };
}

export function parseWithdrawCAPayloadRequest(body: unknown): WithdrawCAPayloadRequest {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  return {
    requestId: stringField(obj, "requestId"),
    sessionId: stringField(obj, "sessionId"),
    rosterHash: hexField(obj, "rosterHash", 32),
    root: hexField(obj, "root", FR_BYTES),
    nullifierHash: hexField(obj, "nullifierHash", FR_BYTES),
    recipient: hexField(obj, "recipient", 32),
    recipientHash: hexField(obj, "recipientHash", FR_BYTES),
    amountTag: hexField(obj, "amountTag", FR_BYTES),
    vaultSequence: decimalStringField(obj, "vaultSequence"),
    shareCommitments: hexArrayField(obj, "shareCommitments", FR_BYTES),
    transcriptHash: hexField(obj, "transcriptHash", 32),
  };
}

export function parseAttestationPartialRequest(body: unknown): AttestationPartialRequest {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  return {
    requestId: stringField(obj, "requestId"),
    sessionId: stringField(obj, "sessionId"),
    rosterHash: hexField(obj, "rosterHash", 32),
    quorumSlots: parseQuorumSlots5(obj.quorumSlots),
    messageBytes: hexField(obj, "messageBytes"),
    caPayloadHash: hexField(obj, "caPayloadHash", 32),
    groth16ProofHash: hexField(obj, "groth16ProofHash", 32),
    transcriptHash: hexField(obj, "transcriptHash", 32),
  };
}

export function parseAbortEvidenceRequest(body: unknown): AbortEvidenceRequest {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  const evidenceKind = stringField(obj, "evidenceKind");
  if (
    evidenceKind !== "bad-share" &&
    evidenceKind !== "timeout" &&
    evidenceKind !== "invalid-proof-share" &&
    evidenceKind !== "equivocation"
  ) {
    throw new Error("invalid evidenceKind");
  }
  return {
    requestId: stringField(obj, "requestId"),
    sessionId: stringField(obj, "sessionId"),
    rosterHash: hexField(obj, "rosterHash", 32),
    accusedSlot: slotField(obj, "accusedSlot"),
    evidenceKind,
    transcriptHash: hexField(obj, "transcriptHash", 32),
    evidenceHash: hexField(obj, "evidenceHash", 32),
  };
}

export function parseDkgRoundRequest(body: unknown): DkgRoundRequest {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  const protocol = dkgProtocolField(stringField(obj, "protocol"));
  const round = dkgRoundFieldForProtocol(protocol, stringField(obj, "round"));
  const rosterHash =
    protocol === "frost"
      ? optionalHexField(obj, "rosterHash", 32) ?? "00".repeat(32)
      : hexField(obj, "rosterHash", 32);
  const commitments = hexArrayField(obj, "commitments", undefined, true);
  const encryptedShares = encryptedSharesField(obj, "encryptedShares");
  const result: DkgRoundRequest = {
    requestId: stringField(obj, "requestId"),
    sessionId: stringField(obj, "sessionId"),
    protocol,
    round,
    operatorSetVersion: stringField(obj, "operatorSetVersion"),
    dkgEpoch: decimalStringField(obj, "dkgEpoch"),
    rosterHash,
    threshold: thresholdField(obj, "threshold"),
    participantSlots: participantSlotsField(obj, "participantSlots"),
    slot: slotField(obj, "slot"),
    transcriptHash: optionalHexField(obj, "transcriptHash", 32),
    commitments,
    encryptedShares,
    caDkgScheme: optionalCaDkgSchemeField(obj, "caDkgScheme"),
    caDkgV2Roster: optionalCaDkgV2RosterField(obj, "caDkgV2Roster"),
    dealerBroadcasts: optionalDealerBroadcastsField(obj, "dealerBroadcasts"),
    frostDkgV2Roster: optionalFrostDkgV2RosterField(obj, "frostDkgV2Roster"),
    frostDkgV2RosterHash: optionalHexField(obj, "frostDkgV2RosterHash", 32),
    frostRound1Broadcasts: optionalFrostRound1BroadcastsField(obj, "frostRound1Broadcasts"),
    frostRound2Envelopes: optionalFrostRound2EnvelopesField(obj, "frostRound2Envelopes"),
    complaint: optionalComplaintField(obj, "complaint"),
  };
  if (protocol === "frost") {
    if (round === "round1" && !result.frostDkgV2Roster) {
      throw new Error("frostDkgV2Roster is required for FROST DKG V2 round1");
    }
    if (round === "round2_send" || round === "round2_receive") {
      if ((result.frostRound1Broadcasts ?? []).length !== DEOPERATOR_COUNT) {
        throw new Error(
          `${round} requires ${DEOPERATOR_COUNT} frostRound1Broadcasts`,
        );
      }
    }
    if (round === "round2_receive") {
      const envelopes = result.frostRound2Envelopes ?? [];
      if (envelopes.length !== DEOPERATOR_COUNT - 1) {
        throw new Error(
          `round2_receive requires ${DEOPERATOR_COUNT - 1} frostRound2Envelopes`,
        );
      }
      for (const env of envelopes) {
        if (env.toSlot !== result.slot) {
          throw new Error("round2_receive envelope toSlot must equal slot");
        }
        if (env.dealerSlot === result.slot) {
          throw new Error("round2_receive envelope dealerSlot must differ from slot");
        }
      }
    }
    if (round === "finalize" && !result.transcriptHash) {
      throw new Error("FROST DKG V2 finalize requires transcriptHash");
    }
  }
  return result;
}

export function parseDkgRoundResult(body: unknown): DkgRoundResult {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  if (obj.accepted !== true) throw new Error("accepted must be true");
  return {
    requestId: stringField(obj, "requestId"),
    sessionId: stringField(obj, "sessionId"),
    protocol: dkgProtocolField(stringField(obj, "protocol")),
    round: dkgRoundField(stringField(obj, "round")),
    operatorSetVersion: stringField(obj, "operatorSetVersion"),
    dkgEpoch: decimalStringField(obj, "dkgEpoch"),
    slot: slotField(obj, "slot"),
    accepted: true,
    transcriptHash: hexField(obj, "transcriptHash", 32),
    artifactHash: hexField(obj, "artifactHash", 32),
    publicShare: optionalHexField(obj, "publicShare", 32),
    groupPublicKey: optionalHexField(obj, "groupPublicKey", 32),
    abortEvidenceHash: optionalHexField(obj, "abortEvidenceHash", 32),
    dealerBroadcast: optionalDealerBroadcastField(obj, "dealerBroadcast"),
    encryptedShares: optionalEncryptedSharesField(obj, "encryptedShares"),
    acceptedDealers: optionalSlotArrayField(obj, "acceptedDealers"),
    aggregateCommitments: optionalHexArrayField(obj, "aggregateCommitments", 32),
    caDkgShareHash: optionalHexField(obj, "caDkgShareHash", 32),
    complaints: optionalComplaintsField(obj, "complaints"),
    finalized: optionalBooleanField(obj, "finalized"),
    caDkgTranscriptHash: optionalHexField(obj, "caDkgTranscriptHash", 32),
    frostRound1Broadcast: optionalFrostRound1BroadcastField(obj, "frostRound1Broadcast"),
    frostRound2Envelopes: optionalFrostRound2EnvelopesField(obj, "frostRound2Envelopes"),
    frostVerifyingShare: optionalHexField(obj, "frostVerifyingShare", 32),
    frostKeyPackageHash: optionalHexField(obj, "frostKeyPackageHash", 32),
    frostPublicPackageHash: optionalHexField(obj, "frostPublicPackageHash", 32),
  };
}

export function parseCaDkgV2Roster(body: unknown): CaDkgV2Roster {
  assertNoForbiddenPlaintextFields(body);
  return caDkgV2RosterBody(body);
}

export function parseFrostDkgV2Roster(body: unknown): FrostDkgV2Roster {
  assertNoForbiddenPlaintextFields(body);
  return frostDkgV2RosterBody(body);
}

export function parseCaRegistrationNonceCommitRequest(
  body: unknown,
): CaRegistrationNonceCommitRequest {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  return {
    requestId: stringField(obj, "requestId"),
  };
}

export function parseCaRegistrationNonceCommitResult(
  body: unknown,
): CaRegistrationNonceCommitResult {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  return {
    nonce_id: hexField(obj, "nonce_id", 32),
    commitment: hexField(obj, "commitment", 32),
    commitment_hash: hexField(obj, "commitment_hash", 32),
    transcript_hash: hexField(obj, "transcript_hash", 32),
  };
}

export function parseCaRegistrationChallengeRequest(
  body: unknown,
): CaRegistrationChallengeRequest {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  const quorumSlots = quorumSlotsFromRegistrationRows(obj, "commitments");
  return {
    vaultEk: hexField(obj, "vaultEk", 32),
    senderAddress: hexField(obj, "senderAddress", 32),
    assetType: hexField(obj, "assetType", 32),
    chainId: chainIdField(obj, "chainId"),
    quorumSlots,
    commitments: registrationCommitmentsField(obj, "commitments", quorumSlots),
  };
}

export function parseCaRegistrationChallengeResult(
  body: unknown,
): CaRegistrationChallengeResult {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  return {
    aggregateCommitment: hexField(obj, "aggregateCommitment", 32),
    challenge: hexField(obj, "challenge", 32),
  };
}

export function parseCaRegistrationPartialRequest(
  body: unknown,
): CaRegistrationPartialRequest {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  return {
    nonceId: hexField(obj, "nonceId", 32),
    challenge: hexField(obj, "challenge", 32),
  };
}

export function parseCaRegistrationPartialResult(
  body: unknown,
): CaRegistrationPartialResult {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  return {
    nonce_id: hexField(obj, "nonce_id", 32),
    response: hexField(obj, "response", 32),
    response_hash: hexField(obj, "response_hash", 32),
    transcript_hash: hexField(obj, "transcript_hash", 32),
  };
}

export function parseCaRegistrationAggregateRequest(
  body: unknown,
): CaRegistrationAggregateRequest {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  const quorumSlots = quorumSlotsFromRegistrationRows(obj, "commitments");
  return {
    vaultEk: hexField(obj, "vaultEk", 32),
    senderAddress: hexField(obj, "senderAddress", 32),
    assetType: hexField(obj, "assetType", 32),
    chainId: chainIdField(obj, "chainId"),
    quorumSlots,
    commitments: registrationCommitmentsField(obj, "commitments", quorumSlots),
    responses: registrationResponsesField(obj, "responses", quorumSlots),
  };
}

export function parseCaRegistrationAggregateResult(
  body: unknown,
): CaRegistrationAggregateResult {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  return {
    sigma_proto_comm: hexArrayField(obj, "sigma_proto_comm", 32),
    sigma_proto_resp: hexArrayField(obj, "sigma_proto_resp", 32),
    challenge: hexField(obj, "challenge", 32),
    proof_hash: hexField(obj, "proof_hash", 32),
    transcript_hash: hexField(obj, "transcript_hash", 32),
  };
}

export function parseMpccaRoundRequest(body: unknown): MpccaRoundRequest {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  const round = mpccaRoundField(stringField(obj, "round"));
  const quorumSlots =
    round === "prove" || round === "finalize" ? parseQuorumSlots5(obj.quorumSlots) : undefined;
  return {
    requestId: stringField(obj, "requestId"),
    sessionId: stringField(obj, "sessionId"),
    protocol: mpccaProtocolField(stringField(obj, "protocol")),
    round,
    rosterHash: hexField(obj, "rosterHash", 32),
    slot: slotField(obj, "slot"),
    quorumSlots,
    root: hexField(obj, "root", FR_BYTES),
    nullifierHash: hexField(obj, "nullifierHash", FR_BYTES),
    recipient: hexField(obj, "recipient", 32),
    recipientHash: hexField(obj, "recipientHash", FR_BYTES),
    amountTag: hexField(obj, "amountTag", FR_BYTES),
    vaultSequence: decimalStringField(obj, "vaultSequence"),
    shareCommitments: hexArrayField(obj, "shareCommitments", FR_BYTES),
    transcriptHash: hexField(obj, "transcriptHash", 32),
    publicInputsHash: hexField(obj, "publicInputsHash", 32),
    roundCommitments: hexArrayField(obj, "roundCommitments"),
  };
}

export function parseMpccaRoundResult(body: unknown): MpccaRoundResult {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  if (obj.accepted !== true) throw new Error("accepted must be true");
  const round = mpccaRoundField(stringField(obj, "round"));
  const caPayload =
    obj.caPayload === undefined ? undefined : parseConfidentialTransferRawPayloadV2(obj.caPayload);
  const caPayloadHashRaw =
    obj.caPayloadHashRaw === undefined ? undefined : hexField(obj, "caPayloadHashRaw", 32);
  const caPayloadHashFrSafe =
    obj.caPayloadHashFrSafe === undefined ? undefined : hexField(obj, "caPayloadHashFrSafe", 32);
  if (caPayload) {
    const expectedRaw = caPayloadHashRawV2(caPayload);
    const expectedFr = caPayloadHashFrV2(caPayload);
    if (caPayloadHashRaw?.replace(/^0x/i, "").toLowerCase() !== expectedRaw) {
      throw new Error("caPayloadHashRaw mismatch");
    }
    if (caPayloadHashFrSafe?.replace(/^0x/i, "").toLowerCase() !== expectedFr) {
      throw new Error("caPayloadHashFrSafe mismatch");
    }
  }
  if (round === "finalize" && !caPayload) {
    throw new Error("MPCCA finalize result must include caPayload");
  }
  return {
    requestId: stringField(obj, "requestId"),
    sessionId: stringField(obj, "sessionId"),
    protocol: mpccaProtocolField(stringField(obj, "protocol")),
    round,
    slot: slotField(obj, "slot"),
    accepted: true,
    transcriptHash: hexField(obj, "transcriptHash", 32),
    artifactHash: hexField(obj, "artifactHash", 32),
    caPayloadHashShare: optionalHexField(obj, "caPayloadHashShare", 32),
    caPayload,
    caPayloadHashRaw,
    caPayloadHashFrSafe,
    quorumTranscriptHash: optionalHexField(obj, "quorumTranscriptHash", 32),
    workerArtifactHashes: optionalHexArrayField(obj, "workerArtifactHashes", 32),
  };
}

export function artifactKindForDkg(protocol: DkgProtocol): PartialArtifactKind {
  return protocol === "ca" ? "dkg-ca-round" : "dkg-frost-round";
}

export function parseConfidentialTransferRawPayloadV2(
  body: unknown,
): ConfidentialTransferRawPayloadV2 {
  assertNoForbiddenPlaintextFields(body);
  const obj = objectBody(body);
  return {
    assetType: hexField(obj, "assetType", 32),
    to: hexField(obj, "to", 32),
    newBalanceP: hexArrayField(obj, "newBalanceP"),
    newBalanceR: hexArrayField(obj, "newBalanceR"),
    newBalanceREffAud: hexArrayField(obj, "newBalanceREffAud", undefined, true),
    amountP: hexArrayField(obj, "amountP"),
    amountRSender: hexArrayField(obj, "amountRSender"),
    amountRRecip: hexArrayField(obj, "amountRRecip"),
    amountREffAud: hexArrayField(obj, "amountREffAud", undefined, true),
    ekVolunAuds: hexArrayField(obj, "ekVolunAuds", undefined, true),
    amountRVolunAuds: hexArrayArrayField(obj, "amountRVolunAuds"),
    zkrpNewBalance: hexField(obj, "zkrpNewBalance"),
    zkrpAmount: hexField(obj, "zkrpAmount"),
    sigmaProtoComm: hexArrayField(obj, "sigmaProtoComm"),
    sigmaProtoResp: hexArrayField(obj, "sigmaProtoResp"),
    memo: hexField(obj, "memo"),
  };
}

function objectBody(body: unknown): Record<string, unknown> {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new Error("body must be an object");
  }
  return body as Record<string, unknown>;
}

function stringField(obj: Record<string, unknown>, key: string): string {
  const value = obj[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${key} must be a non-empty string`);
  }
  return value;
}

function decimalStringField(obj: Record<string, unknown>, key: string): string {
  const value = stringField(obj, key);
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${key} must be a decimal string`);
  }
  return value;
}

function phaseField(value: string): SessionShareEnvelope["phase"] {
  if (
    value !== "dkg-ca" &&
    value !== "dkg-frost" &&
    value !== "deposit-bind" &&
    value !== "withdraw-ca-payload" &&
    value !== "mpcca-withdraw" &&
    value !== "attestation" &&
    value !== "abort"
  ) {
    throw new Error("invalid phase");
  }
  return value;
}

function dkgProtocolField(value: string): DkgProtocol {
  if (value !== "ca" && value !== "frost") {
    throw new Error("invalid DKG protocol");
  }
  return value;
}

function dkgRoundField(value: string): DkgRound {
  if (
    value !== "round1" &&
    value !== "round2" &&
    value !== "round2_send" &&
    value !== "round2_receive" &&
    value !== "complaint" &&
    value !== "finalize"
  ) {
    throw new Error("invalid DKG round");
  }
  return value;
}

function dkgRoundFieldForProtocol(protocol: DkgProtocol, value: string): DkgRound {
  if (protocol === "ca") {
    if (value !== "round1" && value !== "round2" && value !== "complaint" && value !== "finalize") {
      throw new Error("invalid CA DKG round");
    }
    return value;
  }
  if (
    value !== "round1" &&
    value !== "round2_send" &&
    value !== "round2_receive" &&
    value !== "complaint" &&
    value !== "finalize"
  ) {
    throw new Error("invalid FROST DKG round");
  }
  return value;
}

function mpccaProtocolField(value: string): MpccaProtocol {
  if (value !== "withdraw") {
    throw new Error("invalid MPCCA protocol");
  }
  return value;
}

function mpccaRoundField(value: string): MpccaRound {
  if (value !== "round1" && value !== "round2" && value !== "prove" && value !== "finalize") {
    throw new Error("invalid MPCCA round");
  }
  return value;
}

function thresholdField(obj: Record<string, unknown>, key: string): number {
  const value = obj[key];
  if (value !== DEOPERATOR_THRESHOLD) {
    throw new Error(`${key} must be ${DEOPERATOR_THRESHOLD}`);
  }
  return value;
}

function participantSlotsField(obj: Record<string, unknown>, key: string): number[] {
  const value = obj[key];
  if (!Array.isArray(value) || value.length !== DEOPERATOR_COUNT) {
    throw new Error(`${key} must contain ${DEOPERATOR_COUNT} slots`);
  }
  const seen = new Set<number>();
  return value.map((_, index) => {
    const slot = slotField({ [key]: value[index] }, key);
    if (seen.has(slot)) throw new Error(`${key} contains duplicate slot`);
    seen.add(slot);
    return slot;
  });
}

export function parseQuorumSlots5(value: unknown): QuorumSlots5 {
  if (!Array.isArray(value)) {
    throw new Error("quorumSlots must be an array");
  }
  if (value.length < DEOPERATOR_THRESHOLD) {
    throw new UnderQuorumError();
  }
  if (value.length !== DEOPERATOR_THRESHOLD) {
    throw new Error("quorumSlots must contain exactly 5 slots");
  }

  const seen = new Set<number>();
  const slots = value.map((slot, index) => {
    if (!Number.isInteger(slot) || (slot as number) < 0 || (slot as number) >= DEOPERATOR_COUNT) {
      throw new Error(`quorumSlots[${index}] must be a deoperator slot`);
    }
    if (seen.has(slot as number)) {
      throw new Error("duplicate quorum slot");
    }
    seen.add(slot as number);
    return slot as number;
  });
  return slots as QuorumSlots5;
}

function quorumSlotsFromRegistrationRows(
  obj: Record<string, unknown>,
  key: string,
): QuorumSlots5 {
  const value = obj[key];
  if (!Array.isArray(value)) {
    throw new Error(`${key} must be an array`);
  }
  return parseQuorumSlots5(
    value.map((item) => {
      const row = objectBody(item);
      return row.slot;
    }),
  );
}

function slotField(obj: Record<string, unknown>, key: string): number {
  const value = obj[key];
  if (!Number.isInteger(value) || (value as number) < 0 || (value as number) >= DEOPERATOR_COUNT) {
    throw new Error(`${key} must be a deoperator slot`);
  }
  return value as number;
}

function chainIdField(obj: Record<string, unknown>, key: string): number {
  const value = obj[key];
  if (!Number.isInteger(value) || (value as number) < 0 || (value as number) > 255) {
    throw new Error(`${key} must be a u8`);
  }
  return value as number;
}

function hexField(obj: Record<string, unknown>, key: string, bytes?: number): string {
  const value = stringField(obj, key);
  const parsed = hexToBytes(value);
  if (bytes !== undefined && parsed.length !== bytes) {
    throw new Error(`${key} must be ${bytes} bytes`);
  }
  return value;
}

function registrationCommitmentsField(
  obj: Record<string, unknown>,
  key: string,
  quorumSlots: QuorumSlots5,
): CaRegistrationCommitmentInput[] {
  const value = obj[key];
  if (!Array.isArray(value)) {
    throw new Error(`${key} must be an array`);
  }
  if (value.length !== quorumSlots.length) {
    throw new Error(`${key} must contain exactly 5 commitments`);
  }
  return value.map((item, index) => {
    const row = objectBody(item);
    const slot = slotField(row, "slot");
    if (slot !== quorumSlots[index]) {
      throw new Error(`${key}[${index}] slot must match quorumSlots`);
    }
    return {
      slot,
      commitment: hexField(row, "commitment", 32),
    };
  });
}

function registrationResponsesField(
  obj: Record<string, unknown>,
  key: string,
  quorumSlots: QuorumSlots5,
): CaRegistrationResponseInput[] {
  const value = obj[key];
  if (!Array.isArray(value)) {
    throw new Error(`${key} must be an array`);
  }
  if (value.length < DEOPERATOR_THRESHOLD) {
    throw new UnderQuorumError();
  }
  if (value.length !== quorumSlots.length) {
    throw new Error(`${key} must contain exactly 5 responses`);
  }
  return value.map((item, index) => {
    const row = objectBody(item);
    const slot = slotField(row, "slot");
    if (slot !== quorumSlots[index]) {
      throw new Error(`${key}[${index}] slot must match quorumSlots`);
    }
    return {
      slot,
      response: hexField(row, "response", 32),
    };
  });
}

function optionalHexField(
  obj: Record<string, unknown>,
  key: string,
  bytes: number,
): string | undefined {
  if (obj[key] === undefined) return undefined;
  return hexField(obj, key, bytes);
}

function optionalBooleanField(obj: Record<string, unknown>, key: string): boolean | undefined {
  if (obj[key] === undefined) return undefined;
  if (typeof obj[key] !== "boolean") throw new Error(`${key} must be a boolean`);
  return obj[key] as boolean;
}

function hexArrayField(
  obj: Record<string, unknown>,
  key: string,
  bytes?: number,
  allowEmpty = false,
): string[] {
  const value = obj[key];
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0)) {
    throw new Error(`${key} must be ${allowEmpty ? "an" : "a non-empty"} array`);
  }
  return value.map((item, index) => {
    if (typeof item !== "string") throw new Error(`${key}[${index}] must be a string`);
    const parsed = hexToBytes(item);
    if (bytes !== undefined && parsed.length !== bytes) {
      throw new Error(`${key}[${index}] must be ${bytes} bytes`);
    }
    return item;
  });
}

function optionalHexArrayField(
  obj: Record<string, unknown>,
  key: string,
  bytes?: number,
): string[] | undefined {
  if (obj[key] === undefined) return undefined;
  return hexArrayField(obj, key, bytes, true);
}

function optionalSlotArrayField(obj: Record<string, unknown>, key: string): number[] | undefined {
  if (obj[key] === undefined) return undefined;
  const value = obj[key];
  if (!Array.isArray(value)) throw new Error(`${key} must be an array`);
  return value.map((_, index) => slotField({ [key]: value[index] }, key));
}

function hexArrayArrayField(obj: Record<string, unknown>, key: string): string[][] {
  const value = obj[key];
  if (!Array.isArray(value)) {
    throw new Error(`${key} must be an array`);
  }
  return value.map((item, index) => {
    if (!Array.isArray(item)) {
      throw new Error(`${key}[${index}] must be an array`);
    }
    return item.map((hex, innerIndex) => {
      if (typeof hex !== "string") {
        throw new Error(`${key}[${index}][${innerIndex}] must be a string`);
      }
      hexToBytes(hex);
      return hex;
    });
  });
}

function envelopeArrayField(
  obj: Record<string, unknown>,
  key: string,
): SessionShareEnvelope["envelopes"] {
  const value = obj[key];
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${key} must be a non-empty array`);
  }
  return value.map((item, index) => {
    const envelope = objectBody(item);
    const hpke = objectBody(envelope.hpke);
    return {
      slot: slotField(envelope, "slot"),
      shareCommitment: hexField(envelope, "shareCommitment", FR_BYTES),
      hpke: {
        kem: literal(hpke, "kem", "DHKEM_X25519_HKDF_SHA256"),
        kdf: literal(hpke, "kdf", "HKDF_SHA256"),
        aead: literal(hpke, "aead", "AES_256_GCM"),
        enc: hexField(hpke, "enc", 32),
        ciphertext: hexField(hpke, "ciphertext"),
        aadHash: hexField(hpke, "aadHash", 32),
      },
    };
  });
}

function encryptedSharesField(
  obj: Record<string, unknown>,
  key: string,
): DkgRoundRequest["encryptedShares"] {
  const value = obj[key];
  if (!Array.isArray(value)) {
    throw new Error(`${key} must be an array`);
  }
  return value.map((item) => {
    const share = objectBody(item);
    const hpke = objectBody(share.hpke);
    const out: DkgRoundRequest["encryptedShares"][number] = {
      toSlot: slotField(share, "toSlot"),
      hpke: {
        kem: literal(hpke, "kem", "DHKEM_X25519_HKDF_SHA256"),
        kdf: literal(hpke, "kdf", "HKDF_SHA256"),
        aead: literal(hpke, "aead", "AES_256_GCM"),
        enc: hexField(hpke, "enc", 32),
        ciphertext: hexField(hpke, "ciphertext"),
        aadHash: hexField(hpke, "aadHash", 32),
      },
    };
    if (share.dealerSlot !== undefined) out.dealerSlot = slotField(share, "dealerSlot");
    if (share.shareCommitment !== undefined) {
      out.shareCommitment = hexField(share, "shareCommitment", 32);
    }
    return out;
  });
}

function optionalEncryptedSharesField(
  obj: Record<string, unknown>,
  key: string,
): DkgRoundResult["encryptedShares"] | undefined {
  if (obj[key] === undefined) return undefined;
  return encryptedSharesField(obj, key);
}

function optionalCaDkgSchemeField(
  obj: Record<string, unknown>,
  key: string,
): DkgRoundRequest["caDkgScheme"] {
  if (obj[key] === undefined) return undefined;
  const value = stringField(obj, key);
  if (value !== CA_DKG_SCHEME_V2 && value !== CA_DKG_SCHEME_LOCAL) {
    throw new Error(`${key} must be ca_dkg_v2 or ca_local`);
  }
  return value;
}

function optionalCaDkgV2RosterField(
  obj: Record<string, unknown>,
  key: string,
): CaDkgV2Roster | undefined {
  if (obj[key] === undefined) return undefined;
  return caDkgV2RosterBody(obj[key]);
}

function caDkgV2RosterBody(body: unknown): CaDkgV2Roster {
  const obj = objectBody(body);
  const caDkgScheme = literal(obj, "caDkgScheme", CA_DKG_SCHEME_V2);
  const nodes = obj.nodes;
  if (!Array.isArray(nodes) || nodes.length !== DEOPERATOR_COUNT) {
    throw new Error(`CA DKG V2 roster nodes must contain ${DEOPERATOR_COUNT} nodes`);
  }
  const seen = new Set<number>();
  return {
    operatorSetVersion: stringField(obj, "operatorSetVersion"),
    dkgEpoch: decimalStringField(obj, "dkgEpoch"),
    caDkgScheme,
    threshold: thresholdField(obj, "threshold"),
    nodes: nodes.map((item) => {
      const node = objectBody(item);
      const slot = slotField(node, "slot");
      if (seen.has(slot)) throw new Error("CA DKG V2 roster contains duplicate slot");
      seen.add(slot);
      return {
        slot,
        nodeId: stringField(node, "nodeId"),
        endpoint: stringField(node, "endpoint"),
        hpkePublicKey: hexField(node, "hpkePublicKey", 32),
        transcriptPublicKey: hexField(node, "transcriptPublicKey", ED25519_PUBLIC_KEY_BYTES),
      };
    }),
  };
}

function optionalDealerBroadcastsField(
  obj: Record<string, unknown>,
  key: string,
): DkgRoundRequest["dealerBroadcasts"] {
  if (obj[key] === undefined) return undefined;
  const value = obj[key];
  if (!Array.isArray(value)) throw new Error(`${key} must be an array`);
  return value.map((item) => dealerBroadcastBody(item));
}

function optionalFrostDkgV2RosterField(
  obj: Record<string, unknown>,
  key: string,
): FrostDkgV2Roster | undefined {
  if (obj[key] === undefined) return undefined;
  return frostDkgV2RosterBody(obj[key]);
}

function frostDkgV2RosterBody(body: unknown): FrostDkgV2Roster {
  const obj = objectBody(body);
  const caDkgScheme = literal(obj, "caDkgScheme", "frost_dkg_v2");
  const nodes = obj.nodes;
  if (!Array.isArray(nodes) || nodes.length !== DEOPERATOR_COUNT) {
    throw new Error(`FROST DKG V2 roster nodes must contain ${DEOPERATOR_COUNT} nodes`);
  }
  const seen = new Set<number>();
  return {
    operatorSetVersion: decimalStringField(obj, "operatorSetVersion"),
    dkgEpoch: decimalStringField(obj, "dkgEpoch"),
    caDkgScheme,
    threshold: thresholdField(obj, "threshold"),
    nodes: nodes.map((item) => {
      const node = objectBody(item);
      const slot = slotField(node, "slot");
      if (seen.has(slot)) throw new Error("FROST DKG V2 roster contains duplicate slot");
      seen.add(slot);
      return {
        slot,
        nodeId: stringField(node, "nodeId"),
        endpoint: stringField(node, "endpoint"),
        hpkePublicKey: hexField(node, "hpkePublicKey", 32),
        transcriptPublicKey: hexField(node, "transcriptPublicKey", ED25519_PUBLIC_KEY_BYTES),
      };
    }),
  };
}

function optionalFrostRound1BroadcastField(
  obj: Record<string, unknown>,
  key: string,
): FrostRound1Broadcast | undefined {
  if (obj[key] === undefined) return undefined;
  const row = objectBody(obj[key]);
  return {
    slot: slotField(row, "slot"),
    packageHex: hexField(row, "packageHex"),
    packageHash: hexField(row, "packageHash", 32),
    transcriptHash: hexField(row, "transcriptHash", 32),
  };
}

function optionalFrostRound1BroadcastsField(
  obj: Record<string, unknown>,
  key: string,
): FrostRound1Broadcast[] | undefined {
  if (obj[key] === undefined) return undefined;
  const value = obj[key];
  if (!Array.isArray(value)) throw new Error(`${key} must be an array`);
  return value.map((item) => {
    const row = objectBody(item);
    return {
      slot: slotField(row, "slot"),
      packageHex: hexField(row, "packageHex"),
      packageHash: hexField(row, "packageHash", 32),
      transcriptHash: hexField(row, "transcriptHash", 32),
    };
  });
}

function optionalFrostRound2EnvelopesField(
  obj: Record<string, unknown>,
  key: string,
): FrostRound2Envelope[] | undefined {
  if (obj[key] === undefined) return undefined;
  const value = obj[key];
  if (!Array.isArray(value)) throw new Error(`${key} must be an array`);
  return value.map((item) => {
    const row = objectBody(item);
    const hpke = objectBody(row.hpke);
    return {
      dealerSlot: slotField(row, "dealerSlot"),
      toSlot: slotField(row, "toSlot"),
      packageCommitment: hexField(row, "packageCommitment", 32),
      hpke: {
        kem: literal(hpke, "kem", "DHKEM_X25519_HKDF_SHA256"),
        kdf: literal(hpke, "kdf", "HKDF_SHA256"),
        aead: literal(hpke, "aead", "AES_256_GCM"),
        enc: hexField(hpke, "enc", 32),
        ciphertext: hexField(hpke, "ciphertext"),
        aadHash: hexField(hpke, "aadHash", 32),
      },
    };
  });
}

function optionalDealerBroadcastField(
  obj: Record<string, unknown>,
  key: string,
): DkgRoundResult["dealerBroadcast"] {
  if (obj[key] === undefined) return undefined;
  return dealerBroadcastBody(obj[key]);
}

function dealerBroadcastBody(body: unknown): NonNullable<DkgRoundResult["dealerBroadcast"]> {
  const obj = objectBody(body);
  const commitments = hexArrayField(obj, "commitments", 32);
  if (commitments.length !== DEOPERATOR_THRESHOLD) {
    throw new Error(`dealer broadcast commitments must contain ${DEOPERATOR_THRESHOLD} points`);
  }
  return {
    slot: slotField(obj, "slot"),
    commitments,
    transcriptHash: hexField(obj, "transcriptHash", 32),
  };
}

function optionalComplaintsField(
  obj: Record<string, unknown>,
  key: string,
): DkgRoundResult["complaints"] {
  if (obj[key] === undefined) return undefined;
  const value = obj[key];
  if (!Array.isArray(value)) throw new Error(`${key} must be an array`);
  return value.map((item) => {
    const complaint = objectBody(item);
    const out: NonNullable<DkgRoundResult["complaints"]>[number] = {
      accusedSlot: slotField(complaint, "accusedSlot"),
      evidenceHash: hexField(complaint, "evidenceHash", 32),
    };
    if (complaint.reason !== undefined) out.reason = stringField(complaint, "reason");
    return out;
  });
}

function optionalComplaintField(
  obj: Record<string, unknown>,
  key: string,
): DkgRoundRequest["complaint"] {
  if (obj[key] === undefined) return undefined;
  const complaint = objectBody(obj[key]);
  return {
    accusedSlot: slotField(complaint, "accusedSlot"),
    evidenceHash: hexField(complaint, "evidenceHash", 32),
  };
}

function literal<T extends string>(
  obj: Record<string, unknown>,
  key: string,
  expected: T,
): T {
  if (obj[key] !== expected) {
    throw new Error(`${key} must be ${expected}`);
  }
  return expected;
}

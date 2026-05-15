import type {
  AbortEvidenceRequest,
  AttestationPartialResult,
  DepositBindResult,
  DkgRoundResult,
  MpccaRoundResult,
  SessionShareEnvelope,
  WithdrawCAPayloadResult,
} from "@eunoma/deop-protocol";
import { hexToBytes } from "@eunoma/shared";

export interface DeoperatorNodeStore {
  putSessionShare(input: SessionShareEnvelope): Promise<void>;
  putDkgRoundArtifact(input: DkgRoundResult): Promise<void>;
  putMpccaRoundArtifact(input: MpccaRoundResult): Promise<void>;
  putDepositBindShare(input: DepositBindResult): Promise<void>;
  putWithdrawPayloadShare(input: WithdrawCAPayloadResult): Promise<void>;
  putAttestationShare(input: AttestationPartialResult): Promise<void>;
  putAbortEvidence(input: AbortEvidenceRequest): Promise<void>;
  status(requestId: string): Promise<{
    requestId: string;
    dkgRoundArtifacts: number;
    mpccaRoundArtifacts: number;
    sessionShares: number;
    depositBindShares: number;
    withdrawPayloadShares: number;
    attestationShares: number;
    abortEvidence: number;
  }>;
}

export class InMemoryDeoperatorNodeStore implements DeoperatorNodeStore {
  private readonly sessionShares: SessionShareEnvelope[] = [];
  private readonly dkgRoundArtifacts: DkgRoundResult[] = [];
  private readonly mpccaRoundArtifacts: MpccaRoundResult[] = [];
  private readonly depositBindShares: DepositBindResult[] = [];
  private readonly withdrawPayloadShares: WithdrawCAPayloadResult[] = [];
  private readonly attestationShares: AttestationPartialResult[] = [];
  private readonly abortEvidenceRows: AbortEvidenceRequest[] = [];

  async putSessionShare(input: SessionShareEnvelope): Promise<void> {
    this.sessionShares.push(input);
  }

  async putDkgRoundArtifact(input: DkgRoundResult): Promise<void> {
    this.dkgRoundArtifacts.push(input);
  }

  async putMpccaRoundArtifact(input: MpccaRoundResult): Promise<void> {
    this.mpccaRoundArtifacts.push(input);
  }

  async putDepositBindShare(input: DepositBindResult): Promise<void> {
    this.depositBindShares.push(input);
  }

  async putWithdrawPayloadShare(input: WithdrawCAPayloadResult): Promise<void> {
    this.withdrawPayloadShares.push(input);
  }

  async putAttestationShare(input: AttestationPartialResult): Promise<void> {
    this.attestationShares.push(input);
  }

  async putAbortEvidence(input: AbortEvidenceRequest): Promise<void> {
    this.abortEvidenceRows.push(input);
  }

  async status(requestId: string): Promise<{
    requestId: string;
    dkgRoundArtifacts: number;
    mpccaRoundArtifacts: number;
    sessionShares: number;
    depositBindShares: number;
    withdrawPayloadShares: number;
    attestationShares: number;
    abortEvidence: number;
  }> {
    return {
      requestId,
      dkgRoundArtifacts: this.dkgRoundArtifacts.filter((row) => row.requestId === requestId).length,
      mpccaRoundArtifacts: this.mpccaRoundArtifacts.filter((row) => row.requestId === requestId).length,
      sessionShares: this.sessionShares.filter((row) => row.requestId === requestId).length,
      depositBindShares: this.depositBindShares.filter((row) => row.requestId === requestId).length,
      withdrawPayloadShares: this.withdrawPayloadShares.filter((row) => row.requestId === requestId).length,
      attestationShares: this.attestationShares.filter((row) => row.requestId === requestId).length,
      abortEvidence: this.abortEvidenceRows.filter((row) => row.requestId === requestId).length,
    };
  }
}

export interface PgQueryExecutor {
  query<T = Record<string, unknown>>(
    sql: string,
    params?: unknown[],
  ): Promise<{ rows: T[]; rowCount: number | null }>;
}

export class PostgresDeoperatorNodeStore implements DeoperatorNodeStore {
  constructor(private readonly db: PgQueryExecutor) {}

  async putSessionShare(input: SessionShareEnvelope): Promise<void> {
    for (const envelope of input.envelopes) {
      await this.db.query(
        `
          INSERT INTO deop_v2_node_session_envelopes (
            id, request_id, session_id, phase, roster_hash, slot,
            sender_hpke_public_key, share_commitment, hpke_aad_hash,
            hpke_enc, hpke_ciphertext, transcript_hash
          )
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
          ON CONFLICT (id) DO UPDATE
          SET transcript_hash = EXCLUDED.transcript_hash
        `,
        [
          `${input.requestId}:${input.sessionId}:${envelope.slot}:${envelope.shareCommitment}`,
          input.requestId,
          input.sessionId,
          input.phase,
          bytes(input.rosterHash),
          envelope.slot,
          bytes(input.senderHpkePublicKey),
          bytes(envelope.shareCommitment),
          bytes(envelope.hpke.aadHash),
          bytes(envelope.hpke.enc),
          bytes(envelope.hpke.ciphertext),
          input.transcriptHash ? bytes(input.transcriptHash) : null,
        ],
      );
    }
  }

  async putDkgRoundArtifact(input: DkgRoundResult): Promise<void> {
    await this.putPartial(
      input.requestId,
      input.sessionId,
      input.slot,
      input.protocol === "ca" ? "dkg-ca-round" : "dkg-frost-round",
      input.artifactHash,
      input.transcriptHash,
    );
  }

  async putMpccaRoundArtifact(input: MpccaRoundResult): Promise<void> {
    await this.putPartial(
      input.requestId,
      input.sessionId,
      input.slot,
      "mpcca-withdraw-round",
      input.artifactHash,
      input.transcriptHash,
    );
  }

  async putDepositBindShare(input: DepositBindResult): Promise<void> {
    await this.putPartial(input.requestId, input.sessionId, input.slot, "deposit-bind", input.bindingProofShare, input.transcriptHash);
  }

  async putWithdrawPayloadShare(input: WithdrawCAPayloadResult): Promise<void> {
    await this.putPartial(input.requestId, input.sessionId, input.slot, "withdraw-ca-payload", input.caPayloadHashShare, input.transcriptHash);
  }

  async putAttestationShare(input: AttestationPartialResult): Promise<void> {
    await this.putPartial(input.requestId, input.sessionId, input.slot, "attestation", input.frostSignatureShare, input.transcriptHash);
  }

  async putAbortEvidence(input: AbortEvidenceRequest): Promise<void> {
    await this.db.query(
      `
        INSERT INTO deop_v2_node_abort_evidence (
          id, request_id, session_id, roster_hash, accused_slot,
          evidence_kind, evidence_hash, transcript_hash
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (id) DO NOTHING
      `,
      [
        `${input.requestId}:${input.sessionId}:${input.accusedSlot}:${input.evidenceHash}`,
        input.requestId,
        input.sessionId,
        bytes(input.rosterHash),
        input.accusedSlot,
        input.evidenceKind,
        bytes(input.evidenceHash),
        bytes(input.transcriptHash),
      ],
    );
  }

  async status(requestId: string): Promise<{
    requestId: string;
    dkgRoundArtifacts: number;
    mpccaRoundArtifacts: number;
    sessionShares: number;
    depositBindShares: number;
    withdrawPayloadShares: number;
    attestationShares: number;
    abortEvidence: number;
  }> {
    const counts = await this.db.query<{ kind: string; count: string }>(
      `
        SELECT 'session' AS kind, COUNT(*)::text AS count
          FROM deop_v2_node_session_envelopes WHERE request_id = $1
        UNION ALL
        SELECT artifact_kind AS kind, COUNT(*)::text AS count
          FROM deop_v2_node_partial_artifacts WHERE request_id = $1 GROUP BY artifact_kind
        UNION ALL
        SELECT 'abort' AS kind, COUNT(*)::text AS count
          FROM deop_v2_node_abort_evidence WHERE request_id = $1
      `,
      [requestId],
    );
    const byKind = new Map(counts.rows.map((row) => [row.kind, Number.parseInt(row.count, 10)]));
    return {
      requestId,
      dkgRoundArtifacts: (byKind.get("dkg-ca-round") ?? 0) + (byKind.get("dkg-frost-round") ?? 0),
      mpccaRoundArtifacts: byKind.get("mpcca-withdraw-round") ?? 0,
      sessionShares: byKind.get("session") ?? 0,
      depositBindShares: byKind.get("deposit-bind") ?? 0,
      withdrawPayloadShares: byKind.get("withdraw-ca-payload") ?? 0,
      attestationShares: byKind.get("attestation") ?? 0,
      abortEvidence: byKind.get("abort") ?? 0,
    };
  }

  private async putPartial(
    requestId: string,
    sessionId: string,
    slot: number,
    artifactKind: string,
    artifactHash: string,
    transcriptHash: string,
  ): Promise<void> {
    await this.db.query(
      `
        INSERT INTO deop_v2_node_partial_artifacts (
          id, request_id, session_id, slot, artifact_kind, artifact_hash, transcript_hash
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (id) DO NOTHING
      `,
      [
        `${requestId}:${sessionId}:${slot}:${artifactKind}:${artifactHash}`,
        requestId,
        sessionId,
        slot,
        artifactKind,
        bytes(artifactHash),
        bytes(transcriptHash),
      ],
    );
  }
}

function bytes(hex: string): Buffer {
  return Buffer.from(hexToBytes(hex));
}

import type { RequestStatus, SessionShareEnvelope } from "@eunoma/deop-protocol";
import { bytesToHex, hexToBytes } from "@eunoma/shared";

export interface PartialArtifactRecord {
  requestId: string;
  sessionId: string;
  rosterHash?: string;
  slot: number;
  artifactKind: string;
  artifactHash: string;
  transcriptHash: string;
}

export interface CoordinatorStore {
  recordSessionShare(input: SessionShareEnvelope): Promise<void>;
  recordPartialArtifact(input: PartialArtifactRecord): Promise<void>;
  getStatus(requestId: string): Promise<RequestStatus>;
  markComplete(requestId: string): Promise<void>;
  markAborted(requestId: string): Promise<void>;
}

interface MutableStatus {
  requestId: string;
  status: RequestStatus["status"];
  rosterHash?: string;
  transcriptHashes: Set<string>;
  updatedAt: string;
}

export class InMemoryCoordinatorStore implements CoordinatorStore {
  private readonly statuses = new Map<string, MutableStatus>();

  async recordSessionShare(input: SessionShareEnvelope): Promise<void> {
    const row: MutableStatus = this.statuses.get(input.requestId) ?? {
      requestId: input.requestId,
      status: "pending" as const,
      transcriptHashes: new Set<string>(),
      updatedAt: new Date().toISOString(),
    };
    row.status = row.status === "unknown" ? "pending" : row.status;
    row.rosterHash = input.rosterHash;
    if (input.transcriptHash) row.transcriptHashes.add(input.transcriptHash);
    row.updatedAt = new Date().toISOString();
    this.statuses.set(input.requestId, row);
  }

  async recordPartialArtifact(input: PartialArtifactRecord): Promise<void> {
    const row: MutableStatus = this.statuses.get(input.requestId) ?? {
      requestId: input.requestId,
      status: "pending" as const,
      transcriptHashes: new Set<string>(),
      updatedAt: new Date().toISOString(),
    };
    row.status = row.status === "unknown" ? "pending" : row.status;
    if (input.rosterHash) row.rosterHash = input.rosterHash;
    row.transcriptHashes.add(input.transcriptHash);
    row.updatedAt = new Date().toISOString();
    this.statuses.set(input.requestId, row);
  }

  async getStatus(requestId: string): Promise<RequestStatus> {
    const row = this.statuses.get(requestId);
    if (!row) {
      return {
        requestId,
        status: "unknown",
        transcriptHashes: [],
        updatedAt: new Date(0).toISOString(),
      };
    }
    return {
      requestId,
      status: row.status,
      rosterHash: row.rosterHash,
      transcriptHashes: [...row.transcriptHashes],
      updatedAt: row.updatedAt,
    };
  }

  async markComplete(requestId: string): Promise<void> {
    this.setStatus(requestId, "complete");
  }

  async markAborted(requestId: string): Promise<void> {
    this.setStatus(requestId, "aborted");
  }

  private setStatus(requestId: string, status: RequestStatus["status"]): void {
    const row = this.statuses.get(requestId) ?? {
      requestId,
      status,
      transcriptHashes: new Set<string>(),
      updatedAt: new Date().toISOString(),
    };
    row.status = status;
    row.updatedAt = new Date().toISOString();
    this.statuses.set(requestId, row);
  }
}

export interface PgQueryExecutor {
  query<T = Record<string, unknown>>(
    sql: string,
    params?: unknown[],
  ): Promise<{ rows: T[]; rowCount: number | null }>;
}

export class PostgresCoordinatorStore implements CoordinatorStore {
  constructor(private readonly db: PgQueryExecutor) {}

  async recordSessionShare(input: SessionShareEnvelope): Promise<void> {
    await this.db.query(
      `
        INSERT INTO deop_v2_requests (request_id, status, roster_hash)
        VALUES ($1, 'pending', $2)
        ON CONFLICT (request_id) DO UPDATE
        SET status = CASE
              WHEN deop_v2_requests.status = 'unknown' THEN 'pending'
              ELSE deop_v2_requests.status
            END,
            roster_hash = EXCLUDED.roster_hash,
            updated_at = NOW()
      `,
      [input.requestId, bytes(input.rosterHash)],
    );

    for (const envelope of input.envelopes) {
      await this.db.query(
        `
          INSERT INTO deop_v2_session_envelopes (
            id, request_id, session_id, phase, slot, sender_hpke_public_key,
            share_commitment, hpke_aad_hash, hpke_enc, hpke_ciphertext,
            transcript_hash
          )
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
          ON CONFLICT (id) DO UPDATE
          SET transcript_hash = EXCLUDED.transcript_hash
        `,
        [
          `${input.requestId}:${input.sessionId}:${envelope.slot}:${envelope.shareCommitment}`,
          input.requestId,
          input.sessionId,
          input.phase,
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

  async recordPartialArtifact(input: PartialArtifactRecord): Promise<void> {
    await this.db.query(
      `
        INSERT INTO deop_v2_requests (request_id, status, roster_hash)
        VALUES ($1, 'pending', $2)
        ON CONFLICT (request_id) DO UPDATE
        SET status = CASE
              WHEN deop_v2_requests.status = 'unknown' THEN 'pending'
              ELSE deop_v2_requests.status
            END,
            updated_at = NOW()
      `,
      [input.requestId, input.rosterHash ? bytes(input.rosterHash) : Buffer.alloc(0)],
    );
    await this.db.query(
      `
        INSERT INTO deop_v2_partial_artifacts (
          id, request_id, session_id, slot, artifact_kind, artifact_hash, transcript_hash
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (id) DO NOTHING
      `,
      [
        `${input.requestId}:${input.sessionId}:${input.slot}:${input.artifactKind}:${input.artifactHash}`,
        input.requestId,
        input.sessionId,
        input.slot,
        input.artifactKind,
        bytes(input.artifactHash),
        bytes(input.transcriptHash),
      ],
    );
  }

  async getStatus(requestId: string): Promise<RequestStatus> {
    const request = await this.db.query<{
      status: string;
      roster_hash: Uint8Array;
      updated_at: Date | string;
    }>(
      "SELECT status, roster_hash, updated_at FROM deop_v2_requests WHERE request_id = $1",
      [requestId],
    );
    if (request.rows.length === 0) {
      return {
        requestId,
        status: "unknown",
        transcriptHashes: [],
        updatedAt: new Date(0).toISOString(),
      };
    }
    const transcripts = await this.db.query<{ transcript_hash: Uint8Array }>(
      `
        SELECT DISTINCT transcript_hash FROM (
          SELECT transcript_hash
          FROM deop_v2_session_envelopes
          WHERE request_id = $1 AND transcript_hash IS NOT NULL
          UNION ALL
          SELECT transcript_hash
          FROM deop_v2_partial_artifacts
          WHERE request_id = $1
        ) AS transcript_rows
        ORDER BY transcript_hash
      `,
      [requestId],
    );
    const row = request.rows[0];
    return {
      requestId,
      status: row.status as RequestStatus["status"],
      rosterHash: bytesToHex(new Uint8Array(row.roster_hash)),
      transcriptHashes: transcripts.rows.map((item) => bytesToHex(new Uint8Array(item.transcript_hash))),
      updatedAt: new Date(row.updated_at).toISOString(),
    };
  }

  async markComplete(requestId: string): Promise<void> {
    await this.setStatus(requestId, "complete");
  }

  async markAborted(requestId: string): Promise<void> {
    await this.setStatus(requestId, "aborted");
  }

  private async setStatus(requestId: string, status: RequestStatus["status"]): Promise<void> {
    await this.db.query(
      `
        INSERT INTO deop_v2_requests (request_id, status, roster_hash)
        VALUES ($1, $2, '\\x'::bytea)
        ON CONFLICT (request_id) DO UPDATE
        SET status = EXCLUDED.status, updated_at = NOW()
      `,
      [requestId, status],
    );
  }
}

function bytes(hex: string): Buffer {
  return Buffer.from(hexToBytes(hex));
}

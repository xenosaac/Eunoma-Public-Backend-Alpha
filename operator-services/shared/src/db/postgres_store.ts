// Postgres-backed Store implementation (Phase 4 W2).
//
// Persistent counterpart to InMemoryStore. Same Store interface;
// main-operator chooses which implementation at boot via DATABASE_URL env.
//
// Schema is owned by shared/db/migrations/0001_init.sql, auto-loaded by
// docker-compose into /docker-entrypoint-initdb.d on first postgres start.

import pg from "pg";
import type { CAPayloadJson } from "../types.js";
import type {
  AttestationSignatureRow,
  AuditLogRow,
  DepositRequestRow,
  Store,
} from "./store.js";

const { Pool, types } = pg;

// Postgres returns BIGINT (OID 20) as a string by default to preserve precision.
// Our Store interface uses bigint — parse client-side once for all consumers.
types.setTypeParser(20, (val: string) => BigInt(val));

export class PostgresStore implements Store {
  constructor(private readonly pool: pg.Pool) {}

  static async create(databaseUrl: string): Promise<PostgresStore> {
    const pool = new Pool({ connectionString: databaseUrl });
    await pool.query("SELECT 1");
    return new PostgresStore(pool);
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  async insertDepositRequest(row: DepositRequestRow): Promise<void> {
    await this.pool.query(
      `INSERT INTO deposit_requests (
        request_id, user_addr, vault_addr, asset_type, amount,
        deposit_blind, amount_tag, commitment, deposit_binding_proof,
        ca_payload_hash, ca_payload_jsonb, deposit_nonce, expiry, status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
      [
        row.request_id,
        row.user_addr,
        row.vault_addr,
        row.asset_type,
        row.amount.toString(),
        Buffer.from(row.deposit_blind),
        Buffer.from(row.amount_tag),
        Buffer.from(row.commitment),
        Buffer.from(row.deposit_binding_proof),
        Buffer.from(row.ca_payload_hash),
        row.ca_payload_jsonb,
        Buffer.from(row.deposit_nonce),
        row.expiry.toString(),
        row.status,
        row.created_at,
      ],
    );
  }

  async getDepositRequest(request_id: string): Promise<DepositRequestRow | null> {
    const res = await this.pool.query(
      `SELECT * FROM deposit_requests WHERE request_id = $1`,
      [request_id],
    );
    if (res.rows.length === 0) return null;
    return rowToDepositRequest(res.rows[0]);
  }

  async updateDepositRequestStatus(
    request_id: string,
    status: DepositRequestRow["status"],
  ): Promise<void> {
    const res = await this.pool.query(
      `UPDATE deposit_requests SET status = $1 WHERE request_id = $2`,
      [status, request_id],
    );
    if (res.rowCount === 0) {
      throw new Error(`No such request_id: ${request_id}`);
    }
  }

  async insertAttestationSignature(row: AttestationSignatureRow): Promise<void> {
    await this.pool.query(
      `INSERT INTO attestation_signatures (
        id, request_id, operator_slot, signature_bytes,
        message_bytes_hash, verification_status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        row.id,
        row.request_id,
        row.operator_slot,
        Buffer.from(row.signature_bytes),
        Buffer.from(row.message_bytes_hash),
        row.verification_status,
        row.created_at,
      ],
    );
  }

  async getSignaturesForRequest(
    request_id: string,
  ): Promise<AttestationSignatureRow[]> {
    const res = await this.pool.query(
      `SELECT * FROM attestation_signatures WHERE request_id = $1 ORDER BY operator_slot`,
      [request_id],
    );
    return res.rows.map(rowToAttestationSignature);
  }

  async insertAuditLog(row: AuditLogRow): Promise<void> {
    await this.pool.query(
      `INSERT INTO audit_logs (id, request_id, event_type, payload_jsonb, timestamp)
       VALUES ($1, $2, $3, $4, $5)`,
      [row.id, row.request_id, row.event_type, row.payload_jsonb, row.timestamp],
    );
  }

  async hasNonce(deposit_nonce: Uint8Array): Promise<boolean> {
    const res = await this.pool.query(
      `SELECT 1 FROM deposit_requests WHERE deposit_nonce = $1 LIMIT 1`,
      [Buffer.from(deposit_nonce)],
    );
    return res.rows.length > 0;
  }
}

function rowToDepositRequest(r: any): DepositRequestRow {
  return {
    request_id: r.request_id,
    user_addr: r.user_addr,
    vault_addr: r.vault_addr,
    asset_type: r.asset_type,
    amount: typeof r.amount === "bigint" ? r.amount : BigInt(r.amount),
    deposit_blind: new Uint8Array(r.deposit_blind),
    amount_tag: new Uint8Array(r.amount_tag),
    commitment: new Uint8Array(r.commitment),
    deposit_binding_proof: new Uint8Array(r.deposit_binding_proof),
    ca_payload_hash: new Uint8Array(r.ca_payload_hash),
    ca_payload_jsonb: r.ca_payload_jsonb as CAPayloadJson,
    deposit_nonce: new Uint8Array(r.deposit_nonce),
    expiry: typeof r.expiry === "bigint" ? r.expiry : BigInt(r.expiry),
    status: r.status,
    created_at: new Date(r.created_at),
  };
}

function rowToAttestationSignature(r: any): AttestationSignatureRow {
  return {
    id: r.id,
    request_id: r.request_id,
    operator_slot: r.operator_slot,
    signature_bytes: new Uint8Array(r.signature_bytes),
    message_bytes_hash: new Uint8Array(r.message_bytes_hash),
    verification_status: r.verification_status,
    created_at: new Date(r.created_at),
  };
}

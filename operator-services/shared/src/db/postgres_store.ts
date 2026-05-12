// Postgres-backed Store implementation (Phase 4 W2).
//
// Persistent counterpart to InMemoryStore. Same Store interface;
// main-operator chooses which implementation at boot via DATABASE_URL env.
//
// Schema is owned by shared/db/migrations/0001_init.sql, auto-loaded by
// docker-compose into /docker-entrypoint-initdb.d on first postgres start.

import pg from "pg";
import type { CAPayloadJson } from "../types.js";
import {
  PrepareInflightError,
  type AttestationSignatureRow,
  type AuditLogRow,
  type DepositRequestRow,
  type Store,
  type WithdrawRequestRow,
  type WithdrawRequestStatus,
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

  async insertWithdrawRequestActiveOnly(
    row: WithdrawRequestRow,
    nowSecs: bigint,
  ): Promise<void> {
    // Single Postgres transaction:
    //   1. Take a transaction-scoped advisory lock keyed on
    //      (vault_addr, vault_sequence). Concurrent inserts on the same key
    //      block here until the holder's COMMIT. WHERE NOT EXISTS alone is
    //      NOT enough at READ COMMITTED — neither concurrent tx would see
    //      the other's uncommitted INSERT and both could succeed.
    //   2. Expire any stale PREPARED rows for the same key.
    //   3. INSERT ... WHERE NOT EXISTS to atomically guard against an
    //      *already-committed* active row (e.g. a slow second prepare arriving
    //      after the first one's COMMIT released the lock).
    //   4. NO partial unique index exists; this method is the only writer.
    //
    // The advisory key is the 64-bit `hashtextextended` of
    // `hex(vault_addr) || ':' || vault_sequence` — collisions are tolerable
    // (they just serialize unrelated keys; correctness unaffected) and the
    // hash is stable across sessions.
    const client = await this.pool.connect();
    const nowStr = nowSecs.toString();
    const vaultAddrBuf = Buffer.from(row.vault_addr);
    const vaultSeqStr = row.vault_sequence.toString();
    const vaultAddrHex = vaultAddrBuf.toString("hex");
    try {
      await client.query("BEGIN");

      await client.query(
        `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
        [`withdraw:${vaultAddrHex}:${vaultSeqStr}`],
      );

      await client.query(
        `UPDATE withdraw_requests
           SET status = 'EXPIRED'
         WHERE vault_addr = $1
           AND vault_sequence = $2
           AND status = 'PREPARED'
           AND expiry <= $3`,
        [vaultAddrBuf, vaultSeqStr, nowStr],
      );

      // Parameter map (15 placeholders):
      //   $1 vault_addr      $9  asset_type
      //   $2 vault_sequence  $10 asset_id_le32
      //   $3 now_secs        $11 chain_id
      //   $4 request_id      $12 ca_payload_hash
      //   $5 disclosed_amt   $13 ca_payload_jsonb
      //   $6 withdraw_blind  $14 expiry
      //   $7 recipient       $15 created_at
      //   $8 recipient_hash
      const insertRes = await client.query(
        `INSERT INTO withdraw_requests (
            request_id, status, disclosed_amount, withdraw_blind,
            recipient, recipient_hash, vault_addr, asset_type, asset_id_le32,
            chain_id, vault_sequence, ca_payload_hash, ca_payload_jsonb,
            expiry, created_at, finalized_at
         )
         SELECT $4, 'PREPARED', $5, $6, $7, $8, $1, $9, $10,
                $11, $2, $12, $13, $14, $15, NULL
         WHERE NOT EXISTS (
             SELECT 1 FROM withdraw_requests
              WHERE vault_addr = $1
                AND vault_sequence = $2
                AND status = 'PREPARED'
                AND expiry > $3
         )
         RETURNING request_id`,
        [
          vaultAddrBuf,                        // $1
          vaultSeqStr,                         // $2
          nowStr,                              // $3
          row.request_id,                      // $4
          row.disclosed_amount.toString(),     // $5
          Buffer.from(row.withdraw_blind),     // $6
          Buffer.from(row.recipient),          // $7
          Buffer.from(row.recipient_hash),     // $8
          Buffer.from(row.asset_type),         // $9
          Buffer.from(row.asset_id_le32),      // $10
          row.chain_id,                        // $11
          Buffer.from(row.ca_payload_hash),    // $12
          row.ca_payload_jsonb,                // $13
          row.expiry.toString(),               // $14
          row.created_at,                      // $15
        ],
      );

      if (insertRes.rowCount === 0) {
        await client.query("ROLLBACK");
        throw new PrepareInflightError(
          "0x" + vaultAddrBuf.toString("hex"),
          row.vault_sequence,
        );
      }

      await client.query("COMMIT");
    } catch (err) {
      try { await client.query("ROLLBACK"); } catch { /* already rolled back */ }
      throw err;
    } finally {
      client.release();
    }
  }

  async getWithdrawRequest(request_id: string): Promise<WithdrawRequestRow | null> {
    const res = await this.pool.query(
      `SELECT * FROM withdraw_requests WHERE request_id = $1`,
      [request_id],
    );
    if (res.rows.length === 0) return null;
    return rowToWithdrawRequest(res.rows[0]);
  }

  async updateWithdrawRequestStatus(
    request_id: string,
    status: WithdrawRequestStatus,
    finalizedAt?: Date,
  ): Promise<void> {
    const res = await this.pool.query(
      `UPDATE withdraw_requests
         SET status = $1,
             finalized_at = COALESCE($2, finalized_at)
       WHERE request_id = $3`,
      [status, finalizedAt ?? null, request_id],
    );
    if (res.rowCount === 0) {
      throw new Error(`No such withdraw request_id: ${request_id}`);
    }
  }

  async expireStaleWithdrawRequests(nowSecs: bigint): Promise<number> {
    const res = await this.pool.query(
      `UPDATE withdraw_requests
         SET status = 'EXPIRED'
       WHERE status = 'PREPARED'
         AND expiry <= $1`,
      [nowSecs.toString()],
    );
    return res.rowCount ?? 0;
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

function rowToWithdrawRequest(r: any): WithdrawRequestRow {
  return {
    request_id: r.request_id,
    status: r.status as WithdrawRequestStatus,
    disclosed_amount: typeof r.disclosed_amount === "bigint" ? r.disclosed_amount : BigInt(r.disclosed_amount),
    withdraw_blind: new Uint8Array(r.withdraw_blind),
    recipient: new Uint8Array(r.recipient),
    recipient_hash: new Uint8Array(r.recipient_hash),
    vault_addr: new Uint8Array(r.vault_addr),
    asset_type: new Uint8Array(r.asset_type),
    asset_id_le32: new Uint8Array(r.asset_id_le32),
    chain_id: r.chain_id,
    vault_sequence: typeof r.vault_sequence === "bigint" ? r.vault_sequence : BigInt(r.vault_sequence),
    ca_payload_hash: new Uint8Array(r.ca_payload_hash),
    ca_payload_jsonb: r.ca_payload_jsonb,
    expiry: typeof r.expiry === "bigint" ? r.expiry : BigInt(r.expiry),
    created_at: new Date(r.created_at),
    finalized_at: r.finalized_at ? new Date(r.finalized_at) : null,
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

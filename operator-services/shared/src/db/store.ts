// In-memory persistence implementation for Gate 4c.
//
// Production swap-in: replace this module with a Prisma-backed implementation
// using `shared/src/db/schema.prisma`. The Store interface is the integration
// boundary — both implementations must honor it.
//
// We deliberately do NOT pull in Prisma at Gate 4c because:
//   * SQLite + Prisma adds Rust-native bindings that complicate CI for tests
//   * The schema is the canonical artifact (see `shared/db/migrations/0001_init.sql`
//     for the equivalent SQL DDL — production deployments run Prisma migrate
//     against this schema)
//   * Gate 4c's pass criteria #8 + #9 only require persistence READ/WRITE
//     correctness, not specific RDBMS. The Store interface gives us that.

import { CAPayloadJson } from "../types.js";

export interface DepositRequestRow {
  request_id: string;
  user_addr: string;
  vault_addr: string;
  asset_type: string;
  amount: bigint;
  deposit_blind: Uint8Array;
  amount_tag: Uint8Array;
  commitment: Uint8Array;
  deposit_binding_proof: Uint8Array;
  ca_payload_hash: Uint8Array;
  ca_payload_jsonb: CAPayloadJson;
  deposit_nonce: Uint8Array;
  expiry: bigint;
  status: "received" | "verified" | "complete" | "rejected";
  created_at: Date;
}

export interface AttestationSignatureRow {
  id: string;
  request_id: string;
  operator_slot: number;
  signature_bytes: Uint8Array;
  message_bytes_hash: Uint8Array;
  verification_status: "valid" | "invalid";
  created_at: Date;
}

export interface AuditLogRow {
  id: string;
  request_id: string | null;
  event_type: string;
  payload_jsonb: any;
  timestamp: Date;
}

export interface Store {
  insertDepositRequest(row: DepositRequestRow): Promise<void>;
  getDepositRequest(request_id: string): Promise<DepositRequestRow | null>;
  updateDepositRequestStatus(
    request_id: string,
    status: DepositRequestRow["status"],
  ): Promise<void>;
  insertAttestationSignature(row: AttestationSignatureRow): Promise<void>;
  getSignaturesForRequest(request_id: string): Promise<AttestationSignatureRow[]>;
  insertAuditLog(row: AuditLogRow): Promise<void>;
  hasNonce(deposit_nonce: Uint8Array): Promise<boolean>;
}

export class InMemoryStore implements Store {
  private deposits = new Map<string, DepositRequestRow>();
  private nonces = new Set<string>();
  private signatures: AttestationSignatureRow[] = [];
  private auditLogs: AuditLogRow[] = [];

  private nonceKey(b: Uint8Array): string {
    return Buffer.from(b).toString("hex");
  }

  async insertDepositRequest(row: DepositRequestRow): Promise<void> {
    if (this.deposits.has(row.request_id)) {
      throw new Error(`Duplicate request_id: ${row.request_id}`);
    }
    const nonceKey = this.nonceKey(row.deposit_nonce);
    if (this.nonces.has(nonceKey)) {
      throw new Error(`Duplicate deposit_nonce`);
    }
    this.nonces.add(nonceKey);
    this.deposits.set(row.request_id, row);
  }

  async getDepositRequest(request_id: string): Promise<DepositRequestRow | null> {
    return this.deposits.get(request_id) ?? null;
  }

  async updateDepositRequestStatus(
    request_id: string,
    status: DepositRequestRow["status"],
  ): Promise<void> {
    const row = this.deposits.get(request_id);
    if (!row) throw new Error(`No such request_id: ${request_id}`);
    row.status = status;
  }

  async insertAttestationSignature(row: AttestationSignatureRow): Promise<void> {
    this.signatures.push(row);
  }

  async getSignaturesForRequest(
    request_id: string,
  ): Promise<AttestationSignatureRow[]> {
    return this.signatures.filter((s) => s.request_id === request_id);
  }

  async insertAuditLog(row: AuditLogRow): Promise<void> {
    this.auditLogs.push(row);
  }

  async hasNonce(deposit_nonce: Uint8Array): Promise<boolean> {
    return this.nonces.has(this.nonceKey(deposit_nonce));
  }

  // Test helpers
  _allDeposits(): DepositRequestRow[] {
    return [...this.deposits.values()];
  }
  _allSignatures(): AttestationSignatureRow[] {
    return [...this.signatures];
  }
  _allAuditLogs(): AuditLogRow[] {
    return [...this.auditLogs];
  }
}

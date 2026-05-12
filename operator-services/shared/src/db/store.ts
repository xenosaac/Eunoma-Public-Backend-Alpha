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

/// Thrown by `insertWithdrawRequestActiveOnly` when an active PREPARED row
/// already exists for the same `(vault_addr, vault_sequence)`. Route layer
/// catches this and returns HTTP 409 `prepare_inflight`.
export class PrepareInflightError extends Error {
  readonly vault_addr: string;
  readonly vault_sequence: bigint;
  constructor(vault_addr: string, vault_sequence: bigint) {
    super(
      `prepare_inflight: active PREPARED withdraw exists for vault_addr=${vault_addr} vault_sequence=${vault_sequence}`,
    );
    this.name = "PrepareInflightError";
    this.vault_addr = vault_addr;
    this.vault_sequence = vault_sequence;
  }
}

/// Status states for a withdraw request row, mirroring the prepare→finalize
/// lifecycle. PREPARED is the only "active" state; transitions are
///   PREPARED ─(finalize success)─→ FINALIZED
///   PREPARED ─(hash/proof/public-input fail)─→ FAILED       (terminal, retry forbidden)
///   PREPARED ─(expiry elapsed)─→ EXPIRED                    (next prepare allowed)
/// FINALIZED/FAILED/EXPIRED rows DO NOT block a fresh prepare on the same
/// vault_sequence (see `insertWithdrawRequestActiveOnly`).
export type WithdrawRequestStatus = "PREPARED" | "FINALIZED" | "FAILED" | "EXPIRED";

export interface WithdrawRequestRow {
  request_id: string;
  status: WithdrawRequestStatus;
  disclosed_amount: bigint;       // u64 octas — server-only, never leaves backend
  withdraw_blind: Uint8Array;     // 32B LE Fr — committed at prepare, replayed at finalize
  recipient: Uint8Array;          // 32B Aptos address (where to send)
  recipient_hash: Uint8Array;     // 32B LE Fr — pre-computed at prepare via deriveRecipientHash
  vault_addr: Uint8Array;         // 32B Aptos address
  asset_type: Uint8Array;         // 32B Aptos address (e.g. 0xa) — for CA payload + attestation msg
  asset_id_le32: Uint8Array;      // 32B LE Fr — for circuit / amount_tag / request_hash
  chain_id: number;               // u8
  vault_sequence: bigint;         // u64 — read from chain at prepare, re-checked at finalize
  ca_payload_hash: Uint8Array;    // 32B Fr-safe — server canonical, MUST match client-rehash at finalize
  ca_payload_jsonb: any;          // full CA payload object (saved for finalize rehash + audit)
  expiry: bigint;                 // u64 unix seconds — prepare row becomes ineligible past this
  created_at: Date;
  finalized_at: Date | null;
}

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

  /// Atomically: (1) flip any expired PREPARED row for the same
  /// (vault_addr, vault_sequence) to EXPIRED, (2) reject if an unexpired
  /// PREPARED row still exists (throw `PrepareInflightError`), (3) INSERT
  /// the new row with `status='PREPARED'`. In PostgresStore this MUST be
  /// a single DB transaction — partial unique index is intentionally absent,
  /// so correctness depends on this method being atomic. In InMemoryStore
  /// the implementation serializes calls via a Promise-chain mutex.
  insertWithdrawRequestActiveOnly(
    row: WithdrawRequestRow,
    nowSecs: bigint,
  ): Promise<void>;
  getWithdrawRequest(request_id: string): Promise<WithdrawRequestRow | null>;
  updateWithdrawRequestStatus(
    request_id: string,
    status: WithdrawRequestStatus,
    finalizedAt?: Date,
  ): Promise<void>;
  /// Background-job-friendly: flip every PREPARED row whose expiry has
  /// elapsed into EXPIRED. Returns the number of rows affected. Not called
  /// from the prepare/finalize hot paths.
  expireStaleWithdrawRequests(nowSecs: bigint): Promise<number>;
}

export class InMemoryStore implements Store {
  private deposits = new Map<string, DepositRequestRow>();
  private nonces = new Set<string>();
  private signatures: AttestationSignatureRow[] = [];
  private auditLogs: AuditLogRow[] = [];

  private withdraws = new Map<string, WithdrawRequestRow>();
  // Mutex: a promise-chain that serializes all `insertWithdrawRequestActiveOnly`
  // calls. Postgres uses transaction isolation; in-memory uses this to make the
  // concurrent-insert race test deterministic and to match the contract.
  private withdrawInsertLock: Promise<void> = Promise.resolve();

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

  async insertWithdrawRequestActiveOnly(
    row: WithdrawRequestRow,
    nowSecs: bigint,
  ): Promise<void> {
    // Promise-chain mutex: each call waits for the previous body to release
    // before entering the critical section. Mirrors Postgres single-tx
    // contract under concurrent same-sequence inserts.
    const previous = this.withdrawInsertLock;
    let release!: () => void;
    const next = new Promise<void>((r) => { release = r; });
    this.withdrawInsertLock = previous.then(() => next).catch(() => next);
    await previous;
    try {
      if (this.withdraws.has(row.request_id)) {
        throw new Error(`Duplicate request_id: ${row.request_id}`);
      }
      const vaultAddrKey = bytesKey(row.vault_addr);
      for (const existing of this.withdraws.values()) {
        if (existing.status !== "PREPARED") continue;
        if (bytesKey(existing.vault_addr) !== vaultAddrKey) continue;
        if (existing.vault_sequence !== row.vault_sequence) continue;
        if (existing.expiry <= nowSecs) {
          existing.status = "EXPIRED";
          continue;
        }
        throw new PrepareInflightError(vaultAddrKey, row.vault_sequence);
      }
      this.withdraws.set(row.request_id, { ...row, status: "PREPARED" });
    } finally {
      release();
    }
  }

  async getWithdrawRequest(request_id: string): Promise<WithdrawRequestRow | null> {
    const r = this.withdraws.get(request_id);
    return r ? { ...r } : null;
  }

  async updateWithdrawRequestStatus(
    request_id: string,
    status: WithdrawRequestStatus,
    finalizedAt?: Date,
  ): Promise<void> {
    const r = this.withdraws.get(request_id);
    if (!r) throw new Error(`No such withdraw request_id: ${request_id}`);
    r.status = status;
    if (finalizedAt !== undefined) r.finalized_at = finalizedAt;
  }

  async expireStaleWithdrawRequests(nowSecs: bigint): Promise<number> {
    let n = 0;
    for (const r of this.withdraws.values()) {
      if (r.status === "PREPARED" && r.expiry <= nowSecs) {
        r.status = "EXPIRED";
        n++;
      }
    }
    return n;
  }

  // Test helpers
  _allDeposits(): DepositRequestRow[] {
    return [...this.deposits.values()];
  }
  _allWithdraws(): WithdrawRequestRow[] {
    return [...this.withdraws.values()].map((r) => ({ ...r }));
  }
  _allSignatures(): AttestationSignatureRow[] {
    return [...this.signatures];
  }
  _allAuditLogs(): AuditLogRow[] {
    return [...this.auditLogs];
  }
}

function bytesKey(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

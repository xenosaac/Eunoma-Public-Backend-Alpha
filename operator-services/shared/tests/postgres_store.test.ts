// Postgres-backed Store roundtrip + restart-resilience test (Phase 4 W2).
//
// Requires a running Postgres with the schema in shared/db/migrations/0001_init.sql
// applied. Set TEST_DATABASE_URL to enable; otherwise skips so CI without docker
// stays green.
//
// Local dev:
//   docker compose -f operator-services/docker-compose.yml up -d postgres
//   TEST_DATABASE_URL=postgres://operator:operator@localhost:5432/eunoma \
//     npm test -w @eunoma/shared

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import pg from "pg";
import { PostgresStore } from "../src/db/postgres_store.js";
import type {
  AttestationSignatureRow,
  AuditLogRow,
  DepositRequestRow,
} from "../src/db/store.js";
import { randomUUID } from "node:crypto";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;

// vitest's describe.skipIf is the standard idiom for conditional suite skip.
const describeIfDb = TEST_DATABASE_URL ? describe : describe.skip;

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = Math.floor(Math.random() * 256);
  return out;
}

function makeDepositRow(): DepositRequestRow {
  return {
    request_id: randomUUID(),
    user_addr: "0x" + "a".repeat(64),
    vault_addr: "0x" + "b".repeat(64),
    asset_type: "0x" + "c".repeat(64),
    amount: 12345678n,
    deposit_blind: randomBytes(32),
    amount_tag: randomBytes(32),
    commitment: randomBytes(32),
    deposit_binding_proof: randomBytes(256),
    ca_payload_hash: randomBytes(32),
    ca_payload_jsonb: { test: "payload", nested: { x: 1 } } as any,
    deposit_nonce: randomBytes(16),
    expiry: BigInt(Math.floor(Date.now() / 1000) + 3600),
    status: "received",
    created_at: new Date(),
  };
}

describeIfDb("PostgresStore", () => {
  let store: PostgresStore;

  beforeAll(async () => {
    store = await PostgresStore.create(TEST_DATABASE_URL!);
    // Clean slate — order matters: FKs reference deposit_requests
    const cleanup = new pg.Pool({ connectionString: TEST_DATABASE_URL! });
    await cleanup.query("TRUNCATE audit_logs, attestation_signatures, ca_payloads, deposit_requests RESTART IDENTITY CASCADE");
    await cleanup.end();
  });

  afterAll(async () => {
    await store.close();
  });

  it("roundtrip: insertDepositRequest + getDepositRequest preserves all fields", async () => {
    const row = makeDepositRow();
    await store.insertDepositRequest(row);
    const got = await store.getDepositRequest(row.request_id);
    expect(got).not.toBeNull();
    expect(got!.request_id).toBe(row.request_id);
    expect(got!.user_addr).toBe(row.user_addr);
    expect(got!.amount).toBe(row.amount);
    expect(Array.from(got!.deposit_blind)).toEqual(Array.from(row.deposit_blind));
    expect(Array.from(got!.commitment)).toEqual(Array.from(row.commitment));
    expect(Array.from(got!.deposit_nonce)).toEqual(Array.from(row.deposit_nonce));
    expect(got!.expiry).toBe(row.expiry);
    expect(got!.status).toBe("received");
    expect(got!.ca_payload_jsonb).toEqual(row.ca_payload_jsonb);
  });

  it("getDepositRequest returns null for missing id", async () => {
    const got = await store.getDepositRequest("nonexistent-id-xyz");
    expect(got).toBeNull();
  });

  it("updateDepositRequestStatus mutates persisted row", async () => {
    const row = makeDepositRow();
    await store.insertDepositRequest(row);
    await store.updateDepositRequestStatus(row.request_id, "complete");
    const got = await store.getDepositRequest(row.request_id);
    expect(got!.status).toBe("complete");
  });

  it("updateDepositRequestStatus throws on missing id", async () => {
    await expect(
      store.updateDepositRequestStatus("nonexistent-id-xyz", "complete"),
    ).rejects.toThrow(/No such request_id/);
  });

  it("insertDepositRequest rejects duplicate request_id", async () => {
    const row = makeDepositRow();
    await store.insertDepositRequest(row);
    await expect(store.insertDepositRequest(row)).rejects.toThrow();
  });

  it("insertDepositRequest rejects duplicate deposit_nonce", async () => {
    const row1 = makeDepositRow();
    const row2 = { ...makeDepositRow(), deposit_nonce: row1.deposit_nonce };
    await store.insertDepositRequest(row1);
    await expect(store.insertDepositRequest(row2)).rejects.toThrow();
  });

  it("hasNonce reflects insertion state", async () => {
    const row = makeDepositRow();
    expect(await store.hasNonce(row.deposit_nonce)).toBe(false);
    await store.insertDepositRequest(row);
    expect(await store.hasNonce(row.deposit_nonce)).toBe(true);
  });

  it("insertAttestationSignature + getSignaturesForRequest returns all", async () => {
    const dep = makeDepositRow();
    await store.insertDepositRequest(dep);

    const sigs: AttestationSignatureRow[] = [0, 1, 2, 3].map((slot) => ({
      id: randomUUID(),
      request_id: dep.request_id,
      operator_slot: slot,
      signature_bytes: randomBytes(64),
      message_bytes_hash: randomBytes(32),
      verification_status: "valid",
      created_at: new Date(),
    }));

    for (const s of sigs) await store.insertAttestationSignature(s);

    const got = await store.getSignaturesForRequest(dep.request_id);
    expect(got).toHaveLength(4);
    expect(got.map((s) => s.operator_slot)).toEqual([0, 1, 2, 3]);
    expect(Array.from(got[0].signature_bytes)).toEqual(Array.from(sigs[0].signature_bytes));
  });

  it("insertAuditLog persists without throwing", async () => {
    const dep = makeDepositRow();
    await store.insertDepositRequest(dep);
    const log: AuditLogRow = {
      id: randomUUID(),
      request_id: dep.request_id,
      event_type: "deposit_received",
      payload_jsonb: { reason: "test", count: 42 },
      timestamp: new Date(),
    };
    await store.insertAuditLog(log);
    // (No getAuditLogsForRequest in interface yet — just verify no throw.)
  });

  it("restart resilience: close + reopen preserves persisted state", async () => {
    const row = makeDepositRow();
    await store.insertDepositRequest(row);

    // Simulate restart: close pool, open fresh PostgresStore from same URL.
    await store.close();
    store = await PostgresStore.create(TEST_DATABASE_URL!);

    const got = await store.getDepositRequest(row.request_id);
    expect(got).not.toBeNull();
    expect(got!.request_id).toBe(row.request_id);
    expect(got!.amount).toBe(row.amount);
  });
});

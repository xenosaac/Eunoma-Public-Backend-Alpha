// CP2 — withdraw_store tests. Exercises the Store contract for the new
// WithdrawRequest model on both InMemoryStore (always runs) and PostgresStore
// (skipped without TEST_DATABASE_URL).
//
// Required CP2 race cases (enumerated in the plan):
//   a) expired PREPARED same sequence → insert succeeds, old row → EXPIRED
//   b) active PREPARED same sequence → reject with PrepareInflightError
//   c) concurrent same-sequence inserts → exactly one wins, other throws
//
// Plus basic CRUD: get / updateStatus / expireStaleWithdrawRequests / and
// FINALIZED|FAILED|EXPIRED states not blocking re-prepare.

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import pg from "pg";
import { randomUUID } from "node:crypto";
import { InMemoryStore, PrepareInflightError } from "../src/db/store.js";
import type { Store, WithdrawRequestRow } from "../src/db/store.js";
import { PostgresStore } from "../src/db/postgres_store.js";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;
const describeIfDb = TEST_DATABASE_URL ? describe : describe.skip;

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = Math.floor(Math.random() * 256);
  return out;
}

interface RowOverrides {
  request_id?: string;
  status?: WithdrawRequestRow["status"];
  vault_addr?: Uint8Array;
  vault_sequence?: bigint;
  expiry?: bigint;
  created_at?: Date;
  finalized_at?: Date | null;
}

function makeRow(o: RowOverrides = {}): WithdrawRequestRow {
  return {
    request_id: o.request_id ?? randomUUID(),
    status: o.status ?? "PREPARED",
    disclosed_amount: 1_000_000n,
    withdraw_blind: randomBytes(32),
    recipient: randomBytes(32),
    recipient_hash: randomBytes(32),
    vault_addr: o.vault_addr ?? randomBytes(32),
    asset_type: randomBytes(32),
    asset_id_le32: randomBytes(32),
    chain_id: 2,
    vault_sequence: o.vault_sequence ?? 1n,
    ca_payload_hash: randomBytes(32),
    ca_payload_jsonb: { test: "withdraw_payload" },
    expiry: o.expiry ?? BigInt(Math.floor(Date.now() / 1000) + 600),
    created_at: o.created_at ?? new Date(),
    finalized_at: o.finalized_at ?? null,
  };
}

function nowSecsBig(): bigint {
  return BigInt(Math.floor(Date.now() / 1000));
}

// Shared suite — receives a fresh `Store` and a `truncate` fn for each test.
function defineStoreSuite(label: string, ctx: () => {
  store: Store;
  truncate: () => Promise<void>;
}): void {
  describe(`${label}: WithdrawRequest Store contract`, () => {
    let store: Store;
    let truncate: () => Promise<void>;

    beforeEach(async () => {
      ({ store, truncate } = ctx());
      await truncate();
    });

    it("insert + get round-trip preserves all fields", async () => {
      const row = makeRow();
      await store.insertWithdrawRequestActiveOnly(row, nowSecsBig());
      const got = await store.getWithdrawRequest(row.request_id);
      expect(got).not.toBeNull();
      expect(got!.request_id).toBe(row.request_id);
      expect(got!.status).toBe("PREPARED");
      expect(got!.disclosed_amount).toBe(row.disclosed_amount);
      expect(Array.from(got!.withdraw_blind)).toEqual(Array.from(row.withdraw_blind));
      expect(Array.from(got!.recipient_hash)).toEqual(Array.from(row.recipient_hash));
      expect(Array.from(got!.asset_type)).toEqual(Array.from(row.asset_type));
      expect(Array.from(got!.asset_id_le32)).toEqual(Array.from(row.asset_id_le32));
      expect(got!.chain_id).toBe(row.chain_id);
      expect(got!.vault_sequence).toBe(row.vault_sequence);
      expect(got!.expiry).toBe(row.expiry);
      expect(got!.finalized_at).toBeNull();
    });

    it("getWithdrawRequest returns null for unknown id", async () => {
      const got = await store.getWithdrawRequest("nonexistent");
      expect(got).toBeNull();
    });

    it("updateWithdrawRequestStatus → FINALIZED sets finalized_at", async () => {
      const row = makeRow();
      await store.insertWithdrawRequestActiveOnly(row, nowSecsBig());
      const fin = new Date();
      await store.updateWithdrawRequestStatus(row.request_id, "FINALIZED", fin);
      const got = await store.getWithdrawRequest(row.request_id);
      expect(got!.status).toBe("FINALIZED");
      expect(got!.finalized_at).not.toBeNull();
    });

    it("updateWithdrawRequestStatus throws on missing id", async () => {
      await expect(
        store.updateWithdrawRequestStatus("nonexistent", "FAILED"),
      ).rejects.toThrow(/No such withdraw request_id/);
    });

    // ---------- CP2 race case (a) ----------
    it("CP2 race-a: expired PREPARED same sequence — fresh insert succeeds, stale → EXPIRED", async () => {
      const vault_addr = randomBytes(32);
      const vault_sequence = 7n;
      const stale = makeRow({
        vault_addr,
        vault_sequence,
        expiry: 1n, // far in the past
      });
      // Insert with `nowSecs=0` so the stale row passes (expiry=1 > 0).
      await store.insertWithdrawRequestActiveOnly(stale, 0n);

      const fresh = makeRow({ vault_addr, vault_sequence });
      // Now nowSecs is `today`, stale.expiry=1 is in the past → must be flipped.
      await store.insertWithdrawRequestActiveOnly(fresh, nowSecsBig());

      const staleGot = await store.getWithdrawRequest(stale.request_id);
      const freshGot = await store.getWithdrawRequest(fresh.request_id);
      expect(staleGot!.status).toBe("EXPIRED");
      expect(freshGot!.status).toBe("PREPARED");
    });

    // ---------- CP2 race case (b) ----------
    it("CP2 race-b: active PREPARED same sequence — second insert throws PrepareInflightError", async () => {
      const vault_addr = randomBytes(32);
      const vault_sequence = 11n;
      const first = makeRow({ vault_addr, vault_sequence });
      await store.insertWithdrawRequestActiveOnly(first, nowSecsBig());

      const second = makeRow({ vault_addr, vault_sequence });
      await expect(
        store.insertWithdrawRequestActiveOnly(second, nowSecsBig()),
      ).rejects.toBeInstanceOf(PrepareInflightError);

      // first row must remain PREPARED; second must not be persisted.
      expect((await store.getWithdrawRequest(first.request_id))!.status).toBe("PREPARED");
      expect(await store.getWithdrawRequest(second.request_id)).toBeNull();
    });

    // ---------- CP2 race case (c) ----------
    it("CP2 race-c: concurrent same-sequence inserts — exactly one resolves, other rejects", async () => {
      const vault_addr = randomBytes(32);
      const vault_sequence = 13n;
      const a = makeRow({ vault_addr, vault_sequence });
      const b = makeRow({ vault_addr, vault_sequence });
      const now = nowSecsBig();

      const results = await Promise.allSettled([
        store.insertWithdrawRequestActiveOnly(a, now),
        store.insertWithdrawRequestActiveOnly(b, now),
      ]);
      const fulfilled = results.filter((r) => r.status === "fulfilled").length;
      const rejected = results.filter((r) => r.status === "rejected");
      expect(fulfilled).toBe(1);
      expect(rejected.length).toBe(1);
      const reason = (rejected[0] as PromiseRejectedResult).reason;
      expect(reason).toBeInstanceOf(PrepareInflightError);
    });

    // ---------- non-PREPARED states must not block re-prepare ----------
    it("FAILED status does not block re-prepare on same (vault_addr, vault_sequence)", async () => {
      const vault_addr = randomBytes(32);
      const vault_sequence = 17n;
      const first = makeRow({ vault_addr, vault_sequence });
      await store.insertWithdrawRequestActiveOnly(first, nowSecsBig());
      await store.updateWithdrawRequestStatus(first.request_id, "FAILED");

      const second = makeRow({ vault_addr, vault_sequence });
      await store.insertWithdrawRequestActiveOnly(second, nowSecsBig());
      expect((await store.getWithdrawRequest(second.request_id))!.status).toBe("PREPARED");
    });

    it("EXPIRED status does not block re-prepare", async () => {
      const vault_addr = randomBytes(32);
      const vault_sequence = 19n;
      const first = makeRow({ vault_addr, vault_sequence });
      await store.insertWithdrawRequestActiveOnly(first, nowSecsBig());
      await store.updateWithdrawRequestStatus(first.request_id, "EXPIRED");

      const second = makeRow({ vault_addr, vault_sequence });
      await store.insertWithdrawRequestActiveOnly(second, nowSecsBig());
      expect((await store.getWithdrawRequest(second.request_id))!.status).toBe("PREPARED");
    });

    it("expireStaleWithdrawRequests flips only stale PREPARED rows", async () => {
      const past = 1n;
      const future = BigInt(Math.floor(Date.now() / 1000) + 600);
      const stale = makeRow({ vault_sequence: 1n, expiry: past });
      const fresh = makeRow({ vault_sequence: 2n, expiry: future });
      await store.insertWithdrawRequestActiveOnly(stale, 0n);
      await store.insertWithdrawRequestActiveOnly(fresh, 0n);

      const n = await store.expireStaleWithdrawRequests(nowSecsBig());
      expect(n).toBe(1);
      expect((await store.getWithdrawRequest(stale.request_id))!.status).toBe("EXPIRED");
      expect((await store.getWithdrawRequest(fresh.request_id))!.status).toBe("PREPARED");
    });
  });
}

// ---- InMemoryStore (always runs) ----
defineStoreSuite("InMemoryStore", () => {
  const store = new InMemoryStore();
  return {
    store,
    truncate: async () => {
      // InMemoryStore doesn't expose a clear API; recreate via test-helper bypass.
      // Simplest: replace internal maps via cast — keeps test self-contained.
      (store as any).withdraws = new Map();
      (store as any).withdrawInsertLock = Promise.resolve();
    },
  };
});

// ---- PostgresStore (TEST_DATABASE_URL gated) ----
describeIfDb("PostgresStore: WithdrawRequest contract", () => {
  let store: PostgresStore;
  let cleanupPool: pg.Pool;

  beforeAll(async () => {
    store = await PostgresStore.create(TEST_DATABASE_URL!);
    cleanupPool = new pg.Pool({ connectionString: TEST_DATABASE_URL! });
  });

  afterAll(async () => {
    await store.close();
    await cleanupPool.end();
  });

  beforeEach(async () => {
    await cleanupPool.query("TRUNCATE withdraw_requests RESTART IDENTITY");
  });

  async function insertAndAssertPrepared(row: WithdrawRequestRow): Promise<void> {
    await store.insertWithdrawRequestActiveOnly(row, nowSecsBig());
    const got = await store.getWithdrawRequest(row.request_id);
    expect(got!.status).toBe("PREPARED");
  }

  it("Postgres race-a: expired PREPARED same sequence → fresh OK, stale=EXPIRED", async () => {
    const vault_addr = randomBytes(32);
    const stale = makeRow({ vault_addr, vault_sequence: 23n, expiry: 1n });
    await store.insertWithdrawRequestActiveOnly(stale, 0n);
    const fresh = makeRow({ vault_addr, vault_sequence: 23n });
    await insertAndAssertPrepared(fresh);
    expect((await store.getWithdrawRequest(stale.request_id))!.status).toBe("EXPIRED");
  });

  it("Postgres race-b: active PREPARED same sequence → PrepareInflightError", async () => {
    const vault_addr = randomBytes(32);
    const first = makeRow({ vault_addr, vault_sequence: 29n });
    await store.insertWithdrawRequestActiveOnly(first, nowSecsBig());
    const second = makeRow({ vault_addr, vault_sequence: 29n });
    await expect(
      store.insertWithdrawRequestActiveOnly(second, nowSecsBig()),
    ).rejects.toBeInstanceOf(PrepareInflightError);
    expect(await store.getWithdrawRequest(second.request_id)).toBeNull();
  });

  it("Postgres race-c: concurrent same-sequence inserts — exactly one wins", async () => {
    const vault_addr = randomBytes(32);
    const a = makeRow({ vault_addr, vault_sequence: 31n });
    const b = makeRow({ vault_addr, vault_sequence: 31n });
    const now = nowSecsBig();
    const results = await Promise.allSettled([
      store.insertWithdrawRequestActiveOnly(a, now),
      store.insertWithdrawRequestActiveOnly(b, now),
    ]);
    const fulfilled = results.filter((r) => r.status === "fulfilled").length;
    expect(fulfilled).toBe(1);
    const rejected = results.find((r) => r.status === "rejected") as PromiseRejectedResult;
    expect(rejected.reason).toBeInstanceOf(PrepareInflightError);
  });

  it("Postgres: FAILED/EXPIRED rows do not block re-prepare on same sequence", async () => {
    const vault_addr = randomBytes(32);
    const seq = 37n;
    const r1 = makeRow({ vault_addr, vault_sequence: seq });
    await store.insertWithdrawRequestActiveOnly(r1, nowSecsBig());
    await store.updateWithdrawRequestStatus(r1.request_id, "FAILED");
    const r2 = makeRow({ vault_addr, vault_sequence: seq });
    await store.insertWithdrawRequestActiveOnly(r2, nowSecsBig());
    await store.updateWithdrawRequestStatus(r2.request_id, "EXPIRED");
    const r3 = makeRow({ vault_addr, vault_sequence: seq });
    await store.insertWithdrawRequestActiveOnly(r3, nowSecsBig());
    expect((await store.getWithdrawRequest(r3.request_id))!.status).toBe("PREPARED");
  });

  it("Postgres: expireStaleWithdrawRequests batch update", async () => {
    const past = 1n;
    const future = BigInt(Math.floor(Date.now() / 1000) + 600);
    const stale = makeRow({ vault_sequence: 41n, expiry: past });
    const fresh = makeRow({ vault_sequence: 43n, expiry: future });
    await store.insertWithdrawRequestActiveOnly(stale, 0n);
    await store.insertWithdrawRequestActiveOnly(fresh, 0n);
    const n = await store.expireStaleWithdrawRequests(nowSecsBig());
    expect(n).toBe(1);
    expect((await store.getWithdrawRequest(stale.request_id))!.status).toBe("EXPIRED");
    expect((await store.getWithdrawRequest(fresh.request_id))!.status).toBe("PREPARED");
  });
});

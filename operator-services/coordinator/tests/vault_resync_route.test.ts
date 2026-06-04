/**
 * M11 — tests for POST /v2/vault/resync_{after_withdraw,before_round1}.
 *
 * The route fans the resync out to EVERY roster node's `/v2/vault/resync`
 * worker endpoint and succeeds when >= threshold (5) workers return 200. Tests
 * inject a `singleNodeForwarder` mock that simulates per-slot worker responses.
 * Bearer auth is the server's global onRequest concern (tested in server.test.ts),
 * so it is not re-tested per-route here (mirrors balance_decrypt_route.test.ts).
 */

import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { CaDkgV2Roster } from "@eunoma/deop-protocol";
import { buildCoordinatorServer } from "../src/index.js";

const h32 = (byte: string) => byte.repeat(64);

const TEST_BRIDGE_VAULT_ADDRESS = "0x" + "a".repeat(64);
const TEST_BRIDGE_ASSET_TYPE = "0x1::aptos_coin::AptosCoin";
const TEST_PKG = "0x" + "b".repeat(64);
const TEST_TX = "0x" + "7e".repeat(32);

function dkgRoster(): CaDkgV2Roster {
  return {
    operatorSetVersion: "1",
    dkgEpoch: "1",
    caDkgScheme: "ca_dkg_v2",
    threshold: 5,
    nodes: Array.from({ length: 7 }, (_, slot) => ({
      slot,
      nodeId: `node-${slot}`,
      endpoint: `http://node-${slot}.invalid`,
      hpkePublicKey: h32(String(slot + 1)),
      transcriptPublicKey: h32("d"),
    })),
  };
}

interface ResyncBody {
  dkgEpoch: string;
  requestId: string;
  txHash: string;
  bridgePackage: string;
  vault: string;
  assetType: string;
  root: string;
  nullifierHash: string;
  recipientHash: string;
  requestHash: string;
  eventVaultSequence: number;
  expectedNextSequence: number;
}

const baseBody = (overrides: Partial<ResyncBody> = {}): ResyncBody => ({
  dkgEpoch: "1",
  requestId: "m11-test",
  txHash: TEST_TX,
  bridgePackage: TEST_PKG,
  vault: TEST_BRIDGE_VAULT_ADDRESS,
  assetType: TEST_BRIDGE_ASSET_TYPE,
  root: h32("1"),
  nullifierHash: h32("2"),
  recipientHash: h32("3"),
  requestHash: h32("4"),
  eventVaultSequence: 1,
  expectedNextSequence: 2,
  ...overrides,
});

type ForwarderResult = {
  slot: number;
  ok: boolean;
  statusCode?: number;
  body?: unknown;
  error?: string;
};

/**
 * Mock forwarder. By default every slot returns a 200 fresh-advance. `failSlots`
 * makes the listed slots return 404 (uninitialized-slot simulation). `recordCalls`
 * captures the forwarded (path, slot, body) for assertions.
 */
function makeForwarder(opts: {
  failSlots?: number[];
  recordCalls?: Array<{ path: string; slot: number; body: unknown }>;
} = {}) {
  const fail = new Set(opts.failSlots ?? []);
  return async (
    path: string,
    body: unknown,
    _roster: unknown,
    slot: number,
  ): Promise<ForwarderResult> => {
    opts.recordCalls?.push({ path, slot, body });
    if (fail.has(slot)) {
      return {
        slot,
        ok: false,
        statusCode: 404,
        body: { error: "vault_resync_error", code: "vault_state_not_found" },
      };
    }
    const b = body as Record<string, unknown>;
    const vaultSequence =
      typeof b.expectedNextSequence === "number" ? b.expectedNextSequence : 2;
    return {
      slot,
      ok: true,
      statusCode: 200,
      body: {
        vaultSequence,
        chainVaultSequence: vaultSequence,
        previousVaultSequence: Math.max(0, vaultSequence - 1),
        updatedAtMs: 1,
        idempotent: false,
        legacyBackfill: false,
      },
    };
  };
}

describe("M11 — POST /v2/vault/resync_*", () => {
  it("happy: 7-of-7 fan-out → 200 with all okSlots", async () => {
    const calls: Array<{ path: string; slot: number; body: unknown }> = [];
    const { server } = buildCoordinatorServer({
      caDkgV2Roster: dkgRoster(),
      bridgeVaultAddress: TEST_BRIDGE_VAULT_ADDRESS,
      bridgeAssetType: TEST_BRIDGE_ASSET_TYPE,
      singleNodeForwarder: makeForwarder({ recordCalls: calls }),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/vault/resync_after_withdraw",
      payload: baseBody(),
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.ok).toBe(true);
    expect(body.trigger).toBe("after_withdraw");
    expect(body.summary.okSlots).toEqual([0, 1, 2, 3, 4, 5, 6]);
    expect(body.summary.failedSlots).toEqual([]);
    expect(body.summary.thresholdMet).toBe(true);
    // Fan-out hit every slot on the worker resync path.
    expect(calls.map((c) => c.slot).sort((a, b) => a - b)).toEqual([0, 1, 2, 3, 4, 5, 6]);
    expect(new Set(calls.map((c) => c.path))).toEqual(new Set(["/v2/vault/resync"]));
    // The worker body is camelCase and carries NO `trigger`.
    for (const c of calls) {
      const cb = c.body as Record<string, unknown>;
      expect(cb).toMatchObject({ dkgEpoch: "1", requestId: "m11-test", eventVaultSequence: 1, expectedNextSequence: 2 });
      expect(cb).not.toHaveProperty("trigger");
    }
  });

  it("threshold: 5 ok + 2 uninitialized (404) → 200, okSlots = [0..4]", async () => {
    const { server } = buildCoordinatorServer({
      caDkgV2Roster: dkgRoster(),
      bridgeVaultAddress: TEST_BRIDGE_VAULT_ADDRESS,
      bridgeAssetType: TEST_BRIDGE_ASSET_TYPE,
      singleNodeForwarder: makeForwarder({ failSlots: [5, 6] }),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/vault/resync_before_round1",
      payload: baseBody(),
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.ok).toBe(true);
    expect(body.trigger).toBe("before_round1");
    expect(body.summary.okSlots).toEqual([0, 1, 2, 3, 4]);
    expect(body.summary.failedSlots).toEqual([5, 6]);
  });

  it("sub-threshold: 4 ok + 3 fail → 502", async () => {
    const { server } = buildCoordinatorServer({
      caDkgV2Roster: dkgRoster(),
      bridgeVaultAddress: TEST_BRIDGE_VAULT_ADDRESS,
      bridgeAssetType: TEST_BRIDGE_ASSET_TYPE,
      singleNodeForwarder: makeForwarder({ failSlots: [4, 5, 6] }),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/vault/resync_after_withdraw",
      payload: baseBody(),
    });
    expect(res.statusCode).toBe(502);
    const body = res.json();
    expect(body.ok).toBe(false);
    expect(body.summary.okSlots).toEqual([0, 1, 2, 3]);
    expect(body.summary.thresholdMet).toBe(false);
  });

  it("rejects sequence-binding invalid (expectedNextSequence != eventVaultSequence + 1)", async () => {
    const { server } = buildCoordinatorServer({
      caDkgV2Roster: dkgRoster(),
      bridgeVaultAddress: TEST_BRIDGE_VAULT_ADDRESS,
      bridgeAssetType: TEST_BRIDGE_ASSET_TYPE,
      singleNodeForwarder: async () => ({ slot: -1, ok: false, statusCode: 500, error: "should_not_be_called" }),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/vault/resync_after_withdraw",
      payload: baseBody({ eventVaultSequence: 1, expectedNextSequence: 3 }),
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().message).toContain("expectedNextSequence_must_be_eventVaultSequence_plus_one");
  });

  it("rejects vault mismatch against configured bridge vault", async () => {
    const { server } = buildCoordinatorServer({
      caDkgV2Roster: dkgRoster(),
      bridgeVaultAddress: TEST_BRIDGE_VAULT_ADDRESS,
      bridgeAssetType: TEST_BRIDGE_ASSET_TYPE,
      singleNodeForwarder: async () => ({ slot: -1, ok: false, statusCode: 500, error: "should_not_be_called" }),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/vault/resync_after_withdraw",
      payload: baseBody({ vault: "0x" + "c".repeat(64) }),
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().message).toContain("does not match the configured bridge vault");
  });

  it("forbidden-field guard rejects a bare `nullifier` key", async () => {
    const { server } = buildCoordinatorServer({
      caDkgV2Roster: dkgRoster(),
      bridgeVaultAddress: TEST_BRIDGE_VAULT_ADDRESS,
      bridgeAssetType: TEST_BRIDGE_ASSET_TYPE,
      singleNodeForwarder: async () => ({ slot: -1, ok: false, statusCode: 500, error: "should_not_be_called" }),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/vault/resync_after_withdraw",
      // `nullifier` (bare) is forbidden; note our legitimate `nullifierHash` is NOT.
      payload: { ...baseBody(), nullifier: h32("9") },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("forbidden_field");
    expect(res.json().field).toContain("nullifier");
  });

  it("legitimate nullifierHash / recipientHash / requestHash pass the forbidden guard", async () => {
    const { server } = buildCoordinatorServer({
      caDkgV2Roster: dkgRoster(),
      bridgeVaultAddress: TEST_BRIDGE_VAULT_ADDRESS,
      bridgeAssetType: TEST_BRIDGE_ASSET_TYPE,
      singleNodeForwarder: makeForwarder(),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/vault/resync_after_withdraw",
      payload: baseBody(),
    });
    // 200 proves the body (which contains nullifierHash etc.) passed the guard.
    expect(res.statusCode).toBe(200);
  });

  it("sync_sequence: 7-of-7 fan-out uses generic sequence-sync worker path", async () => {
    const calls: Array<{ path: string; slot: number; body: unknown }> = [];
    const { server } = buildCoordinatorServer({
      caDkgV2Roster: dkgRoster(),
      bridgeVaultAddress: TEST_BRIDGE_VAULT_ADDRESS,
      bridgeAssetType: TEST_BRIDGE_ASSET_TYPE,
      singleNodeForwarder: makeForwarder({ recordCalls: calls }),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/vault/sync_sequence",
      payload: {
        dkgEpoch: "1",
        requestId: "m11-seq-test",
        bridgePackage: TEST_PKG,
        vault: TEST_BRIDGE_VAULT_ADDRESS,
        assetType: TEST_BRIDGE_ASSET_TYPE,
      },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.ok).toBe(true);
    expect(body.trigger).toBe("sync_sequence");
    expect(body.summary.okSlots).toEqual([0, 1, 2, 3, 4, 5, 6]);
    expect(new Set(calls.map((c) => c.path))).toEqual(new Set(["/v2/vault/sync_sequence"]));
    for (const c of calls) {
      expect(c.body).toMatchObject({
        dkgEpoch: "1",
        requestId: "m11-seq-test",
        bridgePackage: TEST_PKG,
        vault: TEST_BRIDGE_VAULT_ADDRESS,
        assetType: TEST_BRIDGE_ASSET_TYPE,
      });
      expect(c.body).not.toHaveProperty("txHash");
      expect(c.body).not.toHaveProperty("trigger");
    }
  });

  it("sync_sequence: sub-threshold worker sync returns 502", async () => {
    const { server } = buildCoordinatorServer({
      caDkgV2Roster: dkgRoster(),
      bridgeVaultAddress: TEST_BRIDGE_VAULT_ADDRESS,
      bridgeAssetType: TEST_BRIDGE_ASSET_TYPE,
      singleNodeForwarder: makeForwarder({ failSlots: [4, 5, 6] }),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/vault/sync_sequence",
      payload: {
        dkgEpoch: "1",
        requestId: "m11-seq-subthreshold",
        bridgePackage: TEST_PKG,
        vault: TEST_BRIDGE_VAULT_ADDRESS,
        assetType: TEST_BRIDGE_ASSET_TYPE,
      },
    });
    expect(res.statusCode).toBe(502);
    expect(res.json().summary.okSlots).toEqual([0, 1, 2, 3]);
  });

  it("rejects body with caDkgV2Roster (SSRF defense)", async () => {
    const { server } = buildCoordinatorServer({
      caDkgV2Roster: dkgRoster(),
      bridgeVaultAddress: TEST_BRIDGE_VAULT_ADDRESS,
      bridgeAssetType: TEST_BRIDGE_ASSET_TYPE,
      singleNodeForwarder: async () => ({ slot: -1, ok: false, statusCode: 500, error: "should_not_be_called" }),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/vault/resync_after_withdraw",
      payload: { ...baseBody(), caDkgV2Roster: dkgRoster() },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().message).toContain("caDkgV2Roster_not_allowed_in_body");
  });

  it("persists an audit transcript under stateRoot/coordinator/vault_resync", async () => {
    const stateRoot = mkdtempSync(join(tmpdir(), "eunoma-resync-"));
    const { server } = buildCoordinatorServer({
      caDkgV2Roster: dkgRoster(),
      bridgeVaultAddress: TEST_BRIDGE_VAULT_ADDRESS,
      bridgeAssetType: TEST_BRIDGE_ASSET_TYPE,
      stateRoot,
      singleNodeForwarder: makeForwarder(),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/vault/resync_after_withdraw",
      payload: baseBody(),
    });
    expect(res.statusCode).toBe(200);
    const path = join(stateRoot, "coordinator", "vault_resync", "1__m11-test__after_withdraw.json");
    expect(existsSync(path)).toBe(true);
    const t = JSON.parse(readFileSync(path, "utf8"));
    expect(t.trigger).toBe("after_withdraw");
    expect(t.summary.okSlots).toEqual([0, 1, 2, 3, 4, 5, 6]);
    // Transcript must carry public hashes only — no forbidden plaintext keys.
    const flat = JSON.stringify(t);
    for (const tok of ['"amount"', '"secret"', '"nullifier"', '"dk"', '"blind', "leafIndex"]) {
      expect(flat.includes(tok)).toBe(false);
    }
  });

  it("sync_sequence persists an audit transcript under stateRoot/coordinator/vault_sequence_sync", async () => {
    const stateRoot = mkdtempSync(join(tmpdir(), "eunoma-seq-sync-"));
    const { server } = buildCoordinatorServer({
      caDkgV2Roster: dkgRoster(),
      bridgeVaultAddress: TEST_BRIDGE_VAULT_ADDRESS,
      bridgeAssetType: TEST_BRIDGE_ASSET_TYPE,
      stateRoot,
      singleNodeForwarder: makeForwarder(),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/vault/sync_sequence",
      payload: {
        dkgEpoch: "1",
        requestId: "m11-seq-persist",
        bridgePackage: TEST_PKG,
        vault: TEST_BRIDGE_VAULT_ADDRESS,
        assetType: TEST_BRIDGE_ASSET_TYPE,
      },
    });
    expect(res.statusCode).toBe(200);
    const path = join(stateRoot, "coordinator", "vault_sequence_sync", "1__m11-seq-persist.json");
    expect(existsSync(path)).toBe(true);
    const t = JSON.parse(readFileSync(path, "utf8"));
    expect(t.trigger).toBe("sync_sequence");
    expect(t.summary.okSlots).toEqual([0, 1, 2, 3, 4, 5, 6]);
    const flat = JSON.stringify(t);
    for (const tok of ['"amount"', '"secret"', '"nullifier"', '"dk"', '"blind', "leafIndex"]) {
      expect(flat.includes(tok)).toBe(false);
    }
  });

  // codex P2: a path-traversal requestId must be rejected before it reaches the
  // transcript filename join.
  it("rejects a path-traversal requestId before constructing the transcript path", async () => {
    const stateRoot = mkdtempSync(join(tmpdir(), "eunoma-resync-pt-"));
    const { server } = buildCoordinatorServer({
      caDkgV2Roster: dkgRoster(),
      bridgeVaultAddress: TEST_BRIDGE_VAULT_ADDRESS,
      bridgeAssetType: TEST_BRIDGE_ASSET_TYPE,
      stateRoot,
      singleNodeForwarder: async () => ({ slot: -1, ok: false, statusCode: 500, error: "should_not_be_called" }),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/vault/resync_after_withdraw",
      payload: baseBody({ requestId: "x/../../outside" }),
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().message).toContain("requestId_must_be_safe_id");
    // Nothing must have been written outside the vault_resync dir.
    expect(existsSync(join(stateRoot, "outside.json"))).toBe(false);
  });

  // codex P2: a worker that echoes a forbidden plaintext key must 500 via the outbound
  // guard BEFORE the transcript is persisted — no forbidden data lands on disk.
  it("rejects + does NOT persist when a worker body carries a forbidden key", async () => {
    const stateRoot = mkdtempSync(join(tmpdir(), "eunoma-resync-fk-"));
    const { server } = buildCoordinatorServer({
      caDkgV2Roster: dkgRoster(),
      bridgeVaultAddress: TEST_BRIDGE_VAULT_ADDRESS,
      bridgeAssetType: TEST_BRIDGE_ASSET_TYPE,
      stateRoot,
      // One worker echoes a forbidden `amount` key in its 200 body.
      singleNodeForwarder: async (_path, _body, _roster, slot) => ({
        slot,
        ok: true,
        statusCode: 200,
        body: slot === 3 ? { vaultSequence: 2, amount: 999 } : { vaultSequence: 2, idempotent: false },
      }),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/vault/resync_after_withdraw",
      payload: baseBody(),
    });
    expect(res.statusCode).toBe(500);
    expect(res.json().error).toBe("outbound_forbidden_field");
    // The transcript file must NOT exist (guard ran before persist).
    expect(existsSync(join(stateRoot, "coordinator", "vault_resync", "1__m11-test__after_withdraw.json"))).toBe(false);
  });
});

import { describe, expect, it } from "vitest";
import type { CryptoWorker } from "@eunoma/crypto-worker-client";
import type { CaDkgV2Roster } from "@eunoma/deop-protocol";
import { buildDeoperatorNodeServer } from "../src/index.js";

// M10-e-fix tests for the deop-node `/v2/balance/decrypt_partial` passthrough.
// The route mirrors the FROST signing passthrough posture: forbidden-field
// guard + slot binding + stateless forward to the local crypto-worker. The
// coordinator's `/v2/balance/decrypt` (M10-c) selects slots from its
// configured CA DKG V2 roster and POSTs each selected slot's deop-node
// endpoint at this path; the deop-node forwards to the local worker
// `/v2/balance/decrypt_partial`.

const h32 = (byte: string) => byte.repeat(64);

function testDkgRoster(): CaDkgV2Roster {
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

/** Stub crypto-worker — `/v2/balance/decrypt_partial` is a pure HTTP passthrough,
 * so none of the typed `CryptoWorker` methods are exercised. */
function worker(slot: number): CryptoWorker {
  return {
    async getLocalState() {
      return {
        slot,
        state_dir: `.agent-local/eunoma-v2/slot-${slot}`,
        has_frost_key_package: true,
        has_frost_public_package: true,
        pending_frost_nonces: 0,
      };
    },
    async acceptSessionShare() {
      throw new Error("not used");
    },
    async runDkgRound() {
      throw new Error("not used");
    },
    async runMpccaRound() {
      throw new Error("not used");
    },
    async startDkgCa() {
      throw new Error("not used");
    },
    async startDkgFrost() {
      throw new Error("not used");
    },
    async bindDeposit() {
      throw new Error("not used");
    },
    async buildWithdrawCAPayload() {
      throw new Error("not used");
    },
    async partialAttestation() {
      throw new Error("not used");
    },
    async frostNonceCommit() {
      throw new Error("not used");
    },
    async frostPartialSign() {
      throw new Error("not used");
    },
    async frostAggregate() {
      throw new Error("not used");
    },
    async caRegistrationNonceCommit() {
      throw new Error("not used");
    },
    async caRegistrationChallenge() {
      throw new Error("not used");
    },
    async caRegistrationPartial() {
      throw new Error("not used");
    },
    async caRegistrationAggregate() {
      throw new Error("not used");
    },
    async runMpccaWithdrawRound1() {
      throw new Error("not used");
    },
    async runMpccaWithdrawRound2() {
      throw new Error("not used");
    },
    async runMpccaWithdrawProve() {
      throw new Error("not used");
    },
    async runMpccaWithdrawFinalize() {
      throw new Error("not used");
    },
  };
}

/** Canonical wire body the coordinator's `/v2/balance/decrypt` route emits per
 * selected slot — mirrors `balance_decrypt.ts` `workerBody`. */
function decryptPartialBody(slot: number, overrides: Record<string, unknown> = {}) {
  return {
    dkgEpoch: "1",
    vaultAddress: "0x".concat(h32("a").slice(0, 64)),
    assetType: "0x1::aptos_coin::AptosCoin",
    oldBalanceDHex: [h32("1"), h32("2"), h32("3"), h32("4")],
    requestId: "m10-e-fix-test",
    slot,
    aptosNodeUrl: "https://fullnode.testnet.aptoslabs.com",
    ...overrides,
  };
}

describe("M10-e-fix — deop-node /v2/balance/decrypt_partial passthrough", () => {
  it("happy: forwards a valid request to the local worker and returns 200", async () => {
    const caDkgV2Roster = testDkgRoster();
    let forwardedPath: string | undefined;
    let forwardedBody: Record<string, unknown> | undefined;
    let forwardedHeaders: Record<string, string> | undefined;
    const oldFetch = globalThis.fetch;
    globalThis.fetch = (async (url: unknown, init?: RequestInit) => {
      forwardedPath = (url as URL | string).toString();
      if (init?.body) forwardedBody = JSON.parse(init.body as string);
      forwardedHeaders = init?.headers as Record<string, string> | undefined;
      return new Response(
        JSON.stringify({
          slot: 0,
          partial_hex: [h32("a"), h32("b"), h32("c"), h32("d")],
          signature: h32("e"),
          transcript_domain: "EUNOMA_M10B_BALANCE_DECRYPT_PARTIAL_V1",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }) as typeof fetch;
    try {
      const { server } = buildDeoperatorNodeServer({
        slot: 0,
        nodeId: "node-0",
        caDkgV2Roster,
        cryptoWorker: worker(0),
        cryptoWorkerUrl: "http://localhost:9000",
        bearerToken: "secret",
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/balance/decrypt_partial",
        headers: { authorization: "Bearer secret" },
        payload: decryptPartialBody(0),
      });
      expect(res.statusCode).toBe(200);
      expect(forwardedPath).toContain("/v2/balance/decrypt_partial");
      expect(forwardedBody?.slot).toBe(0);
      expect(forwardedBody?.requestId).toBe("m10-e-fix-test");
      // Forward must not leak the deop-node's own bearer to the worker.
      expect(forwardedHeaders?.authorization).toBeUndefined();
      const body = res.json();
      expect(body.slot).toBe(0);
      expect(body.partial_hex).toHaveLength(4);
      expect(body.signature).toBe(h32("e"));
    } finally {
      globalThis.fetch = oldFetch;
    }
  });

  it("bad bearer: 401 before any forwarding", async () => {
    const caDkgV2Roster = testDkgRoster();
    let workerCalled = false;
    const oldFetch = globalThis.fetch;
    globalThis.fetch = (async () => {
      workerCalled = true;
      return new Response("{}", { status: 200 });
    }) as typeof fetch;
    try {
      const { server } = buildDeoperatorNodeServer({
        slot: 0,
        nodeId: "node-0",
        caDkgV2Roster,
        cryptoWorker: worker(0),
        cryptoWorkerUrl: "http://localhost:9000",
        bearerToken: "secret",
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/balance/decrypt_partial",
        // no authorization header
        payload: decryptPartialBody(0),
      });
      expect(res.statusCode).toBe(401);
      expect(workerCalled).toBe(false);
    } finally {
      globalThis.fetch = oldFetch;
    }
  });

  it("forbidden plaintext field (amount): 400 before forwarding", async () => {
    // The route applies the recursive forbidden-field guard BEFORE forwarding;
    // any wire body carrying `amount`, `blind`, `secret`, `vaultDk`, etc. fails
    // closed at this hop — the worker never sees it. This mirrors the existing
    // FROST signing passthrough posture.
    const caDkgV2Roster = testDkgRoster();
    let workerCalled = false;
    const oldFetch = globalThis.fetch;
    globalThis.fetch = (async () => {
      workerCalled = true;
      return new Response("{}", { status: 200 });
    }) as typeof fetch;
    try {
      const { server } = buildDeoperatorNodeServer({
        slot: 0,
        nodeId: "node-0",
        caDkgV2Roster,
        cryptoWorker: worker(0),
        cryptoWorkerUrl: "http://localhost:9000",
        bearerToken: "secret",
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/balance/decrypt_partial",
        headers: { authorization: "Bearer secret" },
        payload: decryptPartialBody(0, { amount: "100" }),
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("forbidden_plaintext_field");
      expect(workerCalled).toBe(false);
    } finally {
      globalThis.fetch = oldFetch;
    }
  });

  it("wrong slot: 400 before forwarding", async () => {
    // The deop-node is configured for slot=0; a request with slot=4 must fail
    // closed at this boundary so a stale or misrouted request can't reach the
    // worker bound to a different slot.
    const caDkgV2Roster = testDkgRoster();
    let workerCalled = false;
    const oldFetch = globalThis.fetch;
    globalThis.fetch = (async () => {
      workerCalled = true;
      return new Response("{}", { status: 200 });
    }) as typeof fetch;
    try {
      const { server } = buildDeoperatorNodeServer({
        slot: 0,
        nodeId: "node-0",
        caDkgV2Roster,
        cryptoWorker: worker(0),
        cryptoWorkerUrl: "http://localhost:9000",
        bearerToken: "secret",
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/balance/decrypt_partial",
        headers: { authorization: "Bearer secret" },
        payload: decryptPartialBody(4), // node is slot 0
      });
      expect(res.statusCode).toBe(400);
      expect(workerCalled).toBe(false);
    } finally {
      globalThis.fetch = oldFetch;
    }
  });

  it("worker 502: status propagated verbatim to the coordinator", async () => {
    const caDkgV2Roster = testDkgRoster();
    const oldFetch = globalThis.fetch;
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ error: "worker_internal" }), {
        status: 502,
        headers: { "content-type": "application/json" },
      })) as typeof fetch;
    try {
      const { server } = buildDeoperatorNodeServer({
        slot: 0,
        nodeId: "node-0",
        caDkgV2Roster,
        cryptoWorker: worker(0),
        cryptoWorkerUrl: "http://localhost:9000",
        bearerToken: "secret",
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/balance/decrypt_partial",
        headers: { authorization: "Bearer secret" },
        payload: decryptPartialBody(0),
      });
      expect(res.statusCode).toBe(502);
      expect(res.json().error).toBe("worker_internal");
    } finally {
      globalThis.fetch = oldFetch;
    }
  });
});

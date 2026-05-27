/**
 * Tests for POST /v2/normalize/sigma/s0.
 *
 * The route handler is exported by `coordinator/src/routes/normalize_sigma_s0.ts`
 * and Agent D wires it into `buildCoordinatorServer`. These tests build a
 * bare Fastify instance with ONLY this route registered, so they're decoupled
 * from the rest of the coordinator while Agent D's wiring lands.
 *
 * Required tests:
 *   1. happy: 5-of-7 quorum fan-out — workers return correct partial; coordinator
 *      Lagrange-aggregates and `sigmaResponseS0Hex` equals reference
 *      `α[0] + e · dk_REAL`.
 *   2. wrong_dkg_epoch → 400 stale_dkg_epoch
 *   3. worker_slot_mismatch → 502
 *   4. worker timeout / failure → 502
 *   5. missing auth (bearer not configured at registrar level — we test via
 *      a Fastify onRequest hook in the test harness).
 *   + bridge vault/asset mismatch + forbidden field
 *
 * Reference math (mirrors the route's docstring):
 *   Worker i returns `partial_i = alpha_share_i + e · λ_i · dk_share_i`.
 *   Σ_i partial_i = (Σ_i alpha_share_i) + e · (Σ_i λ_i · dk_share_i)
 *                 = α[0] + e · dk_REAL.
 *
 * The test fabricates a 5-of-7 Shamir polynomial in pure-bigint arithmetic,
 * derives the per-slot `dk_share_i` by polynomial evaluation at x = slot + 1,
 * and verifies coordinator-aggregated `s[0]` against the closed-form reference.
 */

import Fastify, { type FastifyInstance } from "fastify";
import { describe, expect, it } from "vitest";
import {
  type CaDkgV2Roster,
  ED25519_SCALAR_Q,
  caDkgV2RosterHash,
  lagrangeCoefficientsAtZero,
  scalarHexFromBigint,
} from "@eunoma/deop-protocol";
import {
  registerNormalizeSigmaS0Route,
  type NormalizeSigmaS0Forwarder,
  type RegisterNormalizeSigmaS0Options,
} from "../src/routes/normalize_sigma_s0.js";

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

const h32 = (byte: string) => byte.repeat(64);

const TEST_BRIDGE_VAULT_ADDRESS = "0x" + "a".repeat(64);
const TEST_BRIDGE_ASSET_TYPE = "0x1::aptos_coin::AptosCoin";
const TEST_BEARER_TOKEN = "test-bearer-normalize";

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

const q = ED25519_SCALAR_Q;
function modN(v: bigint): bigint {
  let r = v % q;
  if (r < 0n) r += q;
  return r;
}

/** Build a deterministic 5-of-7 polynomial. dk_REAL = coeffs[0]. */
function buildShamir(seed: bigint): { coeffs: bigint[]; dkReal: bigint } {
  const coeffs: bigint[] = [];
  for (let i = 0; i < 5; i += 1) {
    coeffs.push(modN(seed + BigInt(i + 1) * 0xdeadbeefn));
  }
  return { coeffs, dkReal: coeffs[0] };
}

/** Evaluate the polynomial at x = slot + 1 to get `dk_share_i`. */
function evalShare(coeffs: bigint[], slot: number): bigint {
  const x = BigInt(slot + 1);
  let v = coeffs[coeffs.length - 1];
  for (let i = coeffs.length - 2; i >= 0; i -= 1) {
    v = modN(v * x + coeffs[i]);
  }
  return v;
}

/** Encode a positive bigint < q as the 32-byte LE hex curve25519-dalek expects. */
function scalarHex(v: bigint): string {
  return scalarHexFromBigint(modN(v));
}

const SELECTED_SLOTS = [0, 1, 2, 3, 4];

function alphaSharesFor(alphaZero: bigint): bigint[] {
  const shares = [11n, 22n, 33n, 44n].map(modN);
  const sum = shares.reduce((acc, item) => modN(acc + item), 0n);
  shares.push(modN(alphaZero - sum));
  return shares;
}

function dummyHpkeEnvelope(seed: number) {
  const byte = seed.toString(16).padStart(2, "0").slice(-2);
  return {
    kem: "DHKEM_X25519_HKDF_SHA256",
    kdf: "HKDF_SHA256",
    aead: "AES_256_GCM",
    enc: byte.repeat(32),
    ciphertext: (seed + 16).toString(16).padStart(2, "0").slice(-2).repeat(48),
    aadHash: (seed + 32).toString(16).padStart(2, "0").slice(-2).repeat(32),
  };
}

/**
 * Mock single-node forwarder. For each slot, returns the correctly computed
 * `partial_i = alpha_share_i + e · λ_i · dk_share_i` (so the coordinator should
 * aggregate to the closed-form reference). Test variants override per-slot behavior to
 * inject failures / slot mismatches / timeouts.
 */
function makeForwarder(opts: {
  coeffs: bigint[];
  alphaZero: bigint;
  challenge: bigint;
  recordCalls?: Array<{ path: string; slot: number; body: unknown }>;
  perSlot?: Record<
    number,
    (
      slot: number,
      defaultBody: { slot: number; partialS0Hex: string },
    ) => Promise<{
      slot: number;
      ok: boolean;
      statusCode?: number;
      body?: unknown;
      error?: string;
    }>
  >;
}): NormalizeSigmaS0Forwarder {
  return async (
    path: string,
    body: unknown,
    _roster: unknown,
    slot: number,
  ) => {
    opts.recordCalls?.push({ path, slot, body });
    const dkShare = evalShare(opts.coeffs, slot);
    const selectedSlots =
      Array.isArray((body as Record<string, unknown>).selectedSlots)
        ? ((body as Record<string, unknown>).selectedSlots as number[])
        : SELECTED_SLOTS;
    const lambdas = lagrangeCoefficientsAtZero(selectedSlots);
    const idx = selectedSlots.indexOf(slot);
    const alphaShare = alphaSharesFor(opts.alphaZero)[idx];
    // partial = α_share_i + e · λ_i · dk_share_i   (mod q)
    const partial = modN(alphaShare + opts.challenge * modN(lambdas[idx] * dkShare));
    const defaultBody = { slot, partialS0Hex: scalarHex(partial) };
    if (opts.perSlot && opts.perSlot[slot]) {
      return opts.perSlot[slot](slot, defaultBody);
    }
    return { slot, ok: true, statusCode: 200, body: defaultBody };
  };
}

/** Spin up a bare Fastify instance with ONLY the normalize route + a bearer guard. */
function buildTestServer(
  partial: Partial<RegisterNormalizeSigmaS0Options> & {
    forwarder: NormalizeSigmaS0Forwarder;
    caDkgV2Roster: CaDkgV2Roster;
  },
): FastifyInstance {
  const app = Fastify({ logger: false });
  app.addHook("onRequest", async (req, reply) => {
    const auth = req.headers.authorization;
    if (auth !== `Bearer ${TEST_BEARER_TOKEN}`) {
      reply.code(401).send({ error: "unauthorized" });
    }
  });
  registerNormalizeSigmaS0Route(app, {
    getDefaultRoster: () => partial.caDkgV2Roster,
    getBridgeVaultAddress: () =>
      partial.getBridgeVaultAddress?.() ?? TEST_BRIDGE_VAULT_ADDRESS,
    getBridgeAssetType: () =>
      partial.getBridgeAssetType?.() ?? TEST_BRIDGE_ASSET_TYPE,
    forwarder: partial.forwarder,
    workerTimeoutMs: partial.workerTimeoutMs,
  });
  return app;
}

interface BodyShape {
  dkgEpoch: string;
  vaultAddress: string;
  assetType: string;
  fiatShamirChallengeHex: string;
  rosterHash: string;
  selectedSlots: number[];
  alphaShareEnvelopes: Array<{ slot: number; hpke: ReturnType<typeof dummyHpkeEnvelope> }>;
  requestId: string;
}

function baseBody(overrides: Partial<BodyShape> = {}): BodyShape {
  const roster = dkgRoster();
  return {
    dkgEpoch: "1",
    vaultAddress: TEST_BRIDGE_VAULT_ADDRESS,
    assetType: TEST_BRIDGE_ASSET_TYPE,
    // Realistic-shape 32-byte LE hex; specific value picked deterministically
    // for the reference math below.
    fiatShamirChallengeHex: scalarHex(0x42_42_42_42_42_42_42_42n),
    rosterHash: caDkgV2RosterHash(roster),
    selectedSlots: SELECTED_SLOTS,
    alphaShareEnvelopes: SELECTED_SLOTS.map((slot) => ({
      slot,
      hpke: dummyHpkeEnvelope(slot + 1),
    })),
    requestId: "normalize-test-1",
    ...overrides,
  };
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

describe("POST /v2/normalize/sigma/s0", () => {
  it("happy: 5-of-7 quorum fan-out aggregates to α[0] + e · dk_REAL", async () => {
    const calls: Array<{ path: string; slot: number; body: unknown }> = [];
    const caDkgV2Roster = dkgRoster();
    const { coeffs, dkReal } = buildShamir(0xc0ffee0001n);
    const alphaZero = modN(0xfeed_face_cafe_babe_0000_0000_0000_0001n);
    const challenge = modN(0x42_42_42_42_42_42_42_42n);
    const server = buildTestServer({
      caDkgV2Roster,
      forwarder: makeForwarder({
        coeffs,
        alphaZero,
        challenge,
        recordCalls: calls,
      }),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/normalize/sigma/s0",
      headers: { authorization: `Bearer ${TEST_BEARER_TOKEN}` },
      payload: baseBody({
        fiatShamirChallengeHex: scalarHex(challenge),
      }),
    });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { sigmaResponseS0Hex: string; slots: number[] };
    expect(body.slots).toEqual([0, 1, 2, 3, 4]);
    expect(body.sigmaResponseS0Hex).toMatch(/^[0-9a-f]{64}$/);

    // Reference: s[0]_threshold = α[0] + e · dk_REAL (mod q).
    const expectedS0 = modN(alphaZero + challenge * dkReal);
    expect(body.sigmaResponseS0Hex).toBe(scalarHex(expectedS0));

    // The route hit exactly the 5 selected slots.
    expect(calls.map((c) => c.slot).sort((a, b) => a - b)).toEqual([
      0, 1, 2, 3, 4,
    ]);
    expect(new Set(calls.map((c) => c.path))).toEqual(
      new Set(["/worker/v2/normalize/sigma/s0_partial"]),
    );

    // Worker body shape sanity-check + no forbidden keys.
    for (const call of calls) {
      const cb = call.body as Record<string, unknown>;
      expect(cb).toMatchObject({
        dkgEpoch: "1",
        slot: call.slot,
        requestId: "normalize-test-1",
      });
      expect(typeof cb.fiatShamirChallengeHex).toBe("string");
      expect(typeof cb.alphaShareHpke).toBe("object");
      expect(cb.selectedSlots).toEqual(SELECTED_SLOTS);
      expect(Object.keys(cb)).not.toContain("amount");
      expect(Object.keys(cb)).not.toContain("merklePath");
      expect(Object.keys(cb)).not.toContain("alphaZeroFromUserHex");
    }
  });

  it("wrong dkgEpoch → 400 stale_dkg_epoch", async () => {
    const caDkgV2Roster = dkgRoster();
    const { coeffs } = buildShamir(0xc0ffee0002n);
    const server = buildTestServer({
      caDkgV2Roster,
      forwarder: makeForwarder({
        coeffs,
        alphaZero: 1n,
        challenge: 1n,
      }),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/normalize/sigma/s0",
      headers: { authorization: `Bearer ${TEST_BEARER_TOKEN}` },
      payload: baseBody({ dkgEpoch: "999" }),
    });
    expect(res.statusCode).toBe(400);
    const body = res.json();
    expect(body.error).toBe("stale_dkg_epoch");
    expect(body.message).toContain("request.dkgEpoch=999");
  });

  it("worker slot mismatch → 502", async () => {
    const caDkgV2Roster = dkgRoster();
    const { coeffs } = buildShamir(0xc0ffee0003n);
    const server = buildTestServer({
      caDkgV2Roster,
      forwarder: makeForwarder({
        coeffs,
        alphaZero: 7n,
        challenge: 11n,
        perSlot: {
          // Slot 2 lies and returns slot=99 in the response body.
          2: async (_slot, defaultBody) => ({
            slot: 2, // forwarder still reports the queried slot
            ok: true,
            statusCode: 200,
            body: { ...defaultBody, slot: 99 },
          }),
        },
      }),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/normalize/sigma/s0",
      headers: { authorization: `Bearer ${TEST_BEARER_TOKEN}` },
      payload: baseBody(),
    });
    expect(res.statusCode).toBe(502);
    const body = res.json();
    expect(body.error).toBe("worker_slot_mismatch");
    expect(body.slot).toBe(2);
    expect(body.requestId).toBe("normalize-test-1");
  });

  it("quorum fail (one worker returns 503) → 502 worker_unexpected_status", async () => {
    const caDkgV2Roster = dkgRoster();
    const { coeffs } = buildShamir(0xc0ffee0004n);
    const server = buildTestServer({
      caDkgV2Roster,
      forwarder: makeForwarder({
        coeffs,
        alphaZero: 3n,
        challenge: 5n,
        perSlot: {
          3: async () => ({
            slot: 3,
            ok: false,
            statusCode: 503,
            error: "worker_down",
            body: { error: "service_unavailable" },
          }),
        },
      }),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/normalize/sigma/s0",
      headers: { authorization: `Bearer ${TEST_BEARER_TOKEN}` },
      payload: baseBody(),
    });
    expect(res.statusCode).toBe(502);
    const body = res.json();
    expect(body.error).toBe("worker_unexpected_status");
    expect(body.slot).toBe(3);
  });

  it("auth missing → 401", async () => {
    const caDkgV2Roster = dkgRoster();
    const { coeffs } = buildShamir(0xc0ffee0005n);
    const server = buildTestServer({
      caDkgV2Roster,
      forwarder: makeForwarder({
        coeffs,
        alphaZero: 1n,
        challenge: 1n,
      }),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/normalize/sigma/s0",
      // NO authorization header.
      payload: baseBody(),
    });
    expect(res.statusCode).toBe(401);
  });

  it("forbidden-field guard rejects amount", async () => {
    const caDkgV2Roster = dkgRoster();
    const { coeffs } = buildShamir(0xc0ffee0006n);
    const server = buildTestServer({
      caDkgV2Roster,
      // Forwarder MUST NOT be reached.
      forwarder: async () => {
        throw new Error("should_not_be_called");
      },
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/normalize/sigma/s0",
      headers: { authorization: `Bearer ${TEST_BEARER_TOKEN}` },
      payload: { ...baseBody(), amount: 1_000_000 },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("forbidden_field");
    expect(res.json().field).toContain("amount");
    // Sanity: the helper var is unused (we only use coeffs in some tests);
    // this keeps the file's structure parallel to the other suites.
    expect(coeffs.length).toBe(5);
  });

  it("rejects body with aptosNodeUrl (M10-l mirror)", async () => {
    const caDkgV2Roster = dkgRoster();
    const { coeffs } = buildShamir(0xc0ffee0007n);
    const server = buildTestServer({
      caDkgV2Roster,
      forwarder: async () => {
        throw new Error("should_not_be_called");
      },
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/normalize/sigma/s0",
      headers: { authorization: `Bearer ${TEST_BEARER_TOKEN}` },
      payload: { ...baseBody(), aptosNodeUrl: "http://evil.example" },
    });
    expect(res.statusCode).toBe(400);
    const body = res.json();
    expect(body.error).toBe("invalid_request");
    expect(body.message).toContain("aptosNodeUrl");
    expect(coeffs.length).toBe(5);
  });

  it("rejects body with caDkgV2Roster (M10-l mirror)", async () => {
    const caDkgV2Roster = dkgRoster();
    const { coeffs } = buildShamir(0xc0ffee0008n);
    const server = buildTestServer({
      caDkgV2Roster,
      forwarder: async () => {
        throw new Error("should_not_be_called");
      },
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/normalize/sigma/s0",
      headers: { authorization: `Bearer ${TEST_BEARER_TOKEN}` },
      payload: { ...baseBody(), caDkgV2Roster: { nodes: [] } },
    });
    expect(res.statusCode).toBe(400);
    const body = res.json();
    expect(body.error).toBe("invalid_request");
    expect(body.message).toContain("caDkgV2Roster");
    expect(coeffs.length).toBe(5);
  });

  it("rejects request when vaultAddress doesn't match configured bridge", async () => {
    const caDkgV2Roster = dkgRoster();
    const { coeffs } = buildShamir(0xc0ffee0009n);
    const server = buildTestServer({
      caDkgV2Roster,
      forwarder: async () => {
        throw new Error("should_not_be_called");
      },
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/normalize/sigma/s0",
      headers: { authorization: `Bearer ${TEST_BEARER_TOKEN}` },
      payload: baseBody({ vaultAddress: "0x" + "b".repeat(64) }),
    });
    expect(res.statusCode).toBe(400);
    const body = res.json();
    expect(body.error).toBe("invalid_request");
    expect(body.message).toContain("vaultAddress");
    expect(coeffs.length).toBe(5);
  });

  it("worker-applied Lagrange coefficients match selectedSlots order (math sanity)", async () => {
    // Compare the route's aggregated result against a hand-computed
    // Σ_i λ_i · partial_i to confirm we used the right coefficients
    // in the right order.
    const caDkgV2Roster = dkgRoster();
    const { coeffs, dkReal } = buildShamir(0xc0ffee0010n);
    const alphaZero = 0x123456789abcdef0n;
    const challenge = 0xfedcba9876543210n;
    const server = buildTestServer({
      caDkgV2Roster,
      forwarder: makeForwarder({ coeffs, alphaZero, challenge }),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/normalize/sigma/s0",
      headers: { authorization: `Bearer ${TEST_BEARER_TOKEN}` },
      payload: baseBody({
        fiatShamirChallengeHex: scalarHex(challenge),
      }),
    });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { sigmaResponseS0Hex: string; slots: number[] };
    const slots = body.slots;

    // Hand-computed Σ partial_i, where each worker applies λ_i locally.
    const lambdas = lagrangeCoefficientsAtZero(slots);
    const alphaShares = alphaSharesFor(alphaZero);
    let acc = 0n;
    for (let i = 0; i < slots.length; i += 1) {
      const dkShare = evalShare(coeffs, slots[i]);
      const partial = modN(alphaShares[i] + challenge * modN(lambdas[i] * dkShare));
      acc = modN(acc + partial);
    }
    expect(body.sigmaResponseS0Hex).toBe(scalarHex(acc));

    // And the closed form must also equal the route's output (a stronger
    // assertion that we got both halves right: Shamir reconstruction of
    // dk_REAL AND the α[0] · Σ λ = α[0] identity).
    const closedForm = modN(alphaZero + challenge * dkReal);
    expect(body.sigmaResponseS0Hex).toBe(scalarHex(closedForm));
  });
});

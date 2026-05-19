/**
 * M10-c — tests for POST /v2/balance/decrypt.
 *
 * 5 required tests:
 *   1. happy: 5-of-7 quorum fan-out
 *   2. missing slot fails closed
 *   3. forbidden-field guard rejects amount/leafIndex/commitmentHex
 *   4. signature verification rejects forged partial
 *   5. LagrangeCoeffs match selectedSlots order
 *
 * The route is wired in coordinator/src/server.ts via
 * `registerBalanceDecryptRoute(server, { getDefaultRoster, forwarder })`.
 * Tests inject a `singleNodeForwarder` mock that simulates the M10-b
 * `/v2/balance/decrypt_partial` endpoint — fabricating realistic per-slot
 * `partial_hex` arrays and recomputing the same SHA-256 transcript the route
 * verifies against.
 */

import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  caDkgV2RosterHash,
  lagrangeCoefficientsAtZero,
  scalarHexFromBigint,
  type CaDkgV2Roster,
} from "@eunoma/deop-protocol";
import { BALANCE_DECRYPT_TRANSCRIPT_DOMAIN } from "@eunoma/shared";
import { buildCoordinatorServer } from "../src/index.js";

// ----------------------------------------------------------------------------
// Test helpers — keep self-contained; do not share state with server.test.ts.
// ----------------------------------------------------------------------------

const h32 = (byte: string) => byte.repeat(64);

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

/**
 * Construct a deterministic per-slot `partial_hex` array. We use values that
 * are valid 64-hex strings — the route only verifies hex-length + SHA-256
 * transcript, not that the bytes decompress to a valid Ristretto point.
 */
function fakePartialHex(slot: number, k: number): string {
  const seed = ((slot * 37 + k * 5 + 1) & 0xff).toString(16).padStart(2, "0");
  return seed.repeat(32);
}

/**
 * Recompute the M10-b SHA-256 canonical transcript hash that the worker
 * would have produced. Mirrors `canonical_transcript_bytes` in Rust.
 */
function signPartial(args: {
  dkgEpoch: string;
  vaultAddress: string;
  assetType: string;
  slot: number;
  requestId: string;
  partialHex: string[];
}): string {
  const parts = [
    BALANCE_DECRYPT_TRANSCRIPT_DOMAIN,
    args.dkgEpoch,
    args.vaultAddress,
    args.assetType,
    String(args.slot),
    args.requestId,
    String(args.partialHex.length),
    ...args.partialHex,
  ];
  const bytes = new TextEncoder().encode(parts.join(":"));
  return createHash("sha256").update(bytes).digest("hex");
}

interface BodyShape {
  dkgEpoch: string;
  vaultAddress: string;
  assetType: string;
  oldBalanceDHex: string[];
  requestId: string;
}

const baseBody = (overrides: Partial<BodyShape> = {}): BodyShape => ({
  dkgEpoch: "1",
  vaultAddress: "0xv".padEnd(66, "a"),
  assetType: "0x1::aptos_coin::AptosCoin",
  oldBalanceDHex: Array.from({ length: 8 }, (_, k) =>
    ((k * 11 + 1) & 0xff).toString(16).padStart(2, "0").repeat(32),
  ),
  requestId: "m10c-test",
  ...overrides,
});

/**
 * Mock forwarder that fabricates a "valid" worker response for each slot:
 *   - `partial_hex` is deterministic via `fakePartialHex(slot, k)`
 *   - `signature` is the SHA-256 transcript hash the route will verify
 * `overrides` lets each test tamper with one slot's response (e.g., to flip
 * a byte in `partial_hex`, to return a 503, or to inject a forbidden key).
 */
function makeForwarder(opts: {
  recordCalls?: Array<{ path: string; slot: number; body: unknown }>;
  perSlot?: Record<
    number,
    (
      slot: number,
      bodyAsObject: Record<string, unknown>,
      defaultResponse: Record<string, unknown>,
    ) => Promise<{ slot: number; ok: boolean; statusCode?: number; body?: unknown; error?: string }>
  >;
} = {}) {
  return async (
    path: string,
    body: unknown,
    _roster: unknown,
    slot: number,
  ): Promise<{ slot: number; ok: boolean; statusCode?: number; body?: unknown; error?: string }> => {
    opts.recordCalls?.push({ path, slot, body });
    const b = body as Record<string, unknown>;
    const ell = (b.oldBalanceDHex as string[]).length;
    const partialHex = Array.from({ length: ell }, (_, k) => fakePartialHex(slot, k));
    const signature = signPartial({
      dkgEpoch: b.dkgEpoch as string,
      vaultAddress: b.vaultAddress as string,
      assetType: b.assetType as string,
      slot,
      requestId: b.requestId as string,
      partialHex,
    });
    // M10-c-fix: Rust worker emits camelCase JSON (#[serde(rename_all =
    // "camelCase")]), so the test mock must produce camelCase to match the
    // real wire format the coordinator now expects.
    const defaultResponse = {
      slot,
      partialHex,
      signature,
      transcriptDomain: BALANCE_DECRYPT_TRANSCRIPT_DOMAIN,
    };
    if (opts.perSlot && opts.perSlot[slot]) {
      return opts.perSlot[slot](slot, b, defaultResponse);
    }
    return { slot, ok: true, statusCode: 200, body: defaultResponse };
  };
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

describe("M10-c — POST /v2/balance/decrypt", () => {
  it("happy: 5-of-7 quorum fan-out", async () => {
    const calls: Array<{ path: string; slot: number; body: unknown }> = [];
    const caDkgV2Roster = dkgRoster();
    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: makeForwarder({ recordCalls: calls }),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/balance/decrypt",
      payload: baseBody(),
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.slots).toHaveLength(5);
    expect(body.lagrangeCoeffs).toHaveLength(5);
    // Slot order is lowest-5 of {0..6} → [0,1,2,3,4].
    expect(body.slots.map((s: { slot: number }) => s.slot)).toEqual([0, 1, 2, 3, 4]);
    // Each slot's signature must round-trip the worker's transcript domain.
    for (const s of body.slots) {
      expect(s.transcript_domain).toBe(BALANCE_DECRYPT_TRANSCRIPT_DOMAIN);
      expect(s.partial_hex).toHaveLength(8);
      expect(s.signature).toMatch(/^[0-9a-f]{64}$/);
    }
    // The route hit exactly the 5 selected slots via the worker path.
    expect(calls.map((c) => c.slot).sort((a, b) => a - b)).toEqual([0, 1, 2, 3, 4]);
    expect(new Set(calls.map((c) => c.path))).toEqual(
      new Set(["/v2/balance/decrypt_partial"]),
    );
    // Each worker received the correct body shape (no forbidden keys).
    for (const call of calls) {
      const cb = call.body as Record<string, unknown>;
      expect(cb).toMatchObject({
        dkgEpoch: "1",
        slot: call.slot,
        requestId: "m10c-test",
      });
      expect((cb.oldBalanceDHex as string[]).length).toBe(8);
      // Sanity: there must be no forbidden key in the outbound worker body.
      expect(Object.keys(cb)).not.toContain("amount");
      expect(Object.keys(cb)).not.toContain("merklePath");
    }
  });

  it("missing slot fails closed", async () => {
    const caDkgV2Roster = dkgRoster();
    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: makeForwarder({
        perSlot: {
          2: async (slot) => ({
            slot,
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
      url: "/v2/balance/decrypt",
      payload: baseBody(),
    });
    // Per route contract: any failing slot collapses the request to 5xx.
    expect(res.statusCode).toBeGreaterThanOrEqual(500);
    expect(res.statusCode).toBeLessThan(600);
    const body = res.json();
    expect(body.error).toBe("worker_unexpected_status");
    expect(body.slot).toBe(2);
    expect(body.requestId).toBe("m10c-test");
  });

  it("forbidden-field guard rejects amount/leafIndex/commitmentHex", async () => {
    const caDkgV2Roster = dkgRoster();
    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      // Forwarder MUST NOT be reached — the inbound guard fires first.
      singleNodeForwarder: async () => ({
        slot: -1,
        ok: false,
        statusCode: 500,
        error: "should_not_be_called",
      }),
    });

    // (a) `amount` in top-level body.
    {
      const res = await server.inject({
        method: "POST",
        url: "/v2/balance/decrypt",
        payload: { ...baseBody(), amount: 1_000_000 },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("forbidden_field");
      expect(res.json().field).toContain("amount");
    }

    // (b) `leafIndex` nested in an extra object.
    {
      const res = await server.inject({
        method: "POST",
        url: "/v2/balance/decrypt",
        payload: { ...baseBody(), meta: { leafIndex: 42 } },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("forbidden_field");
      expect(res.json().field).toContain("leafIndex");
    }

    // (c) `commitmentHex` in array element.
    {
      const res = await server.inject({
        method: "POST",
        url: "/v2/balance/decrypt",
        payload: { ...baseBody(), extras: [{ commitmentHex: h32("a") }] },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("forbidden_field");
      expect(res.json().field).toContain("commitmentHex");
    }

    // (d) merklePath via .*Path pattern.
    {
      const res = await server.inject({
        method: "POST",
        url: "/v2/balance/decrypt",
        payload: { ...baseBody(), merklePath: ["aa".repeat(32)] },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("forbidden_field");
    }
  });

  it("signature verification rejects forged partial", async () => {
    const caDkgV2Roster = dkgRoster();
    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: makeForwarder({
        perSlot: {
          // Slot 3 returns a valid-looking response, but we flip a byte in
          // partialHex[0] without updating the signature. The route must
          // recompute SHA-256 and reject the mismatch.
          3: async (slot, _b, defaultResponse) => {
            const tampered = { ...defaultResponse };
            const flipped = [...(defaultResponse.partialHex as string[])];
            const first = flipped[0];
            // Flip the first hex char (00 → 01, 01 → 00, etc.) — produces a
            // valid 64-hex string that no longer matches the worker's signature.
            const swap = (c: string) => (c === "0" ? "1" : "0");
            flipped[0] = swap(first[0]) + first.slice(1);
            tampered.partialHex = flipped;
            return { slot, ok: true, statusCode: 200, body: tampered };
          },
        },
      }),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/balance/decrypt",
      payload: baseBody(),
    });
    expect(res.statusCode).toBe(502);
    const body = res.json();
    expect(body.error).toBe("signature_verification_failed");
    expect(body.slot).toBe(3);
  });

  it("LagrangeCoeffs match selectedSlots order", async () => {
    const caDkgV2Roster = dkgRoster();
    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: makeForwarder(),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/balance/decrypt",
      payload: baseBody(),
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    const slotIds: number[] = body.slots.map((s: { slot: number }) => s.slot);
    expect(slotIds).toEqual([0, 1, 2, 3, 4]);

    // Recompute what the i-th coefficient should be for the selected slots,
    // using the SAME helper the route uses. The i-th lagrange MUST correspond
    // to the i-th slot in the returned `slots[]` array.
    const expected = lagrangeCoefficientsAtZero(slotIds).map(scalarHexFromBigint);
    expect(body.lagrangeCoeffs).toEqual(expected);
    expect(body.lagrangeCoeffs).toHaveLength(slotIds.length);

    // Sanity: a different slot subset would yield different coefficients.
    const otherSlots = [0, 2, 4, 5, 6];
    const otherCoeffs = lagrangeCoefficientsAtZero(otherSlots).map(scalarHexFromBigint);
    expect(otherCoeffs).not.toEqual(body.lagrangeCoeffs);

    // The roster's hash is still computable (just smoke-check it didn't drift).
    expect(caDkgV2RosterHash(caDkgV2Roster)).toMatch(/^[0-9a-f]{64}$/);
  });

  // M10-l (codex P1): body MUST NOT supply `aptosNodeUrl` or `caDkgV2Roster`.
  // Both come from coordinator config only. Request-controlled URL = chosen-D
  // threshold decryption oracle. Request-controlled roster = SSRF + breaks
  // 5-of-7 quorum invariant.

  it("M10-l: rejects body with aptosNodeUrl (chosen-D oracle defense)", async () => {
    const caDkgV2Roster = dkgRoster();
    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      // Forwarder MUST NOT be reached — parseRequest fails before fan-out.
      singleNodeForwarder: async () => ({
        slot: -1,
        ok: false,
        statusCode: 500,
        error: "should_not_be_called",
      }),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/balance/decrypt",
      payload: {
        ...baseBody(),
        aptosNodeUrl: "http://evil.example",
      },
    });
    expect(res.statusCode).toBe(400);
    const body = res.json();
    expect(body.error).toBe("invalid_request");
    expect(body.message).toContain("aptosNodeUrl_not_allowed_in_body");
  });

  it("M10-l: rejects body with caDkgV2Roster (SSRF + 5-of-7 invariant defense)", async () => {
    const caDkgV2Roster = dkgRoster();
    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: async () => ({
        slot: -1,
        ok: false,
        statusCode: 500,
        error: "should_not_be_called",
      }),
    });
    // Attacker-supplied roster — would have re-routed fan-out to attacker
    // endpoints if accepted.
    const attackerRoster = {
      operatorSetVersion: "1",
      dkgEpoch: "1",
      caDkgScheme: "ca_dkg_v2",
      threshold: 5,
      nodes: Array.from({ length: 7 }, (_, slot) => ({
        slot,
        nodeId: `evil-${slot}`,
        endpoint: `http://attacker.example/node-${slot}`,
        hpkePublicKey: h32(String(slot + 1)),
        transcriptPublicKey: h32("d"),
      })),
    };
    const res = await server.inject({
      method: "POST",
      url: "/v2/balance/decrypt",
      payload: {
        ...baseBody(),
        caDkgV2Roster: attackerRoster,
      },
    });
    expect(res.statusCode).toBe(400);
    const body = res.json();
    expect(body.error).toBe("invalid_request");
    expect(body.message).toContain("caDkgV2Roster_not_allowed_in_body");
  });
});

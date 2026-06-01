import { describe, expect, it } from "vitest";
import { WITHDRAW_V2_CALL_ARGS_ORDER } from "@eunoma/deop-protocol";
import { buildRelayerServer } from "../src/index.js";

/**
 * Deterministic 27-field WithdrawV2CallArgs body that matches the Move
 * signature (move/sources/eunoma_bridge.move:515-543, excluding `_relayer`).
 *
 * Chunk counts mirror Aptos CA SDK conventions captured in the existing
 * aptos_ca_transfer_v1_fixture.json:
 *   - ell = 8 for new_balance_* vectors
 *   - n   = 4 for amount_* vectors
 *   - sigma proof: 30 commitments, 25 responses
 */
function validWithdrawV2Body(): Record<string, unknown> {
  const hex32 = (seed: number): string =>
    Array.from({ length: 32 }, (_, i) => ((i + seed) & 0xff).toString(16).padStart(2, "0")).join(
      "",
    );
  const hexN = (n: number, seed: number): string =>
    Array.from({ length: n }, (_, i) => ((i + seed) & 0xff).toString(16).padStart(2, "0")).join("");
  return {
    root: hex32(0x10),
    nullifierHash: hex32(0x11),
    recipient: hex32(0x12),
    recipientHash: hex32(0x13),
    amountTag: hex32(0x14),
    caPayloadHash: hex32(0x15),
    requestHash: hex32(0x16),
    aspRoot: hex32(0x17),
    stateTreeDepth: "4",
    aspTreeDepth: "3",
    vaultSequence: "42",
    withdrawProof: hexN(192, 0x20),
    expirySecs: "1800000000",
    groupSignature: hexN(64, 0x30),
    fallbackBitmap: 0,
    fallbackSignatures: [],
    newBalanceP: Array.from({ length: 8 }, (_, i) => hex32(0x40 + i)),
    newBalanceR: Array.from({ length: 8 }, (_, i) => hex32(0x50 + i)),
    newBalanceREffAud: [],
    amountP: Array.from({ length: 4 }, (_, i) => hex32(0x60 + i)),
    amountRSender: Array.from({ length: 4 }, (_, i) => hex32(0x70 + i)),
    amountRRecip: Array.from({ length: 4 }, (_, i) => hex32(0x80 + i)),
    amountREffAud: [],
    ekVolunAuds: [],
    amountRVolunAuds: [],
    zkrpNewBalance: hexN(672, 0x90),
    zkrpAmount: hexN(672, 0xa0),
    sigmaProtoComm: Array.from({ length: 30 }, (_, i) => hex32(0xb0 + i)),
    sigmaProtoResp: Array.from({ length: 25 }, (_, i) => hex32(0xc0 + i)),
    memo: "",
  };
}

describe("relayer /v2/relayer/health", () => {
  it("is reachable without a bearer token", async () => {
    const server = buildRelayerServer({ bearerToken: "secret" });
    const res = await server.inject({ method: "GET", url: "/v2/relayer/health" });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ ok: true });
  });
});

describe("relayer /v2/relayer/submit/withdraw — killer tests", () => {
  it("withdraw_v2_route_rejects_forbidden_amount_field", async () => {
    const server = buildRelayerServer({
      submitter: async () => ({ accepted: true, txHash: "x", simulated: true }),
    });
    const body = validWithdrawV2Body();
    body.amount = "1000"; // forbidden plaintext witness field
    const res = await server.inject({
      method: "POST",
      url: "/v2/relayer/submit/withdraw",
      payload: body,
    });
    expect(res.statusCode).toBe(400);
    const json = res.json();
    expect(json.error).toBe("forbidden_plaintext_field");
    expect(json.field).toBe("amount");
  });

  it("withdraw_v2_route_invokes_submitter_with_canonical_call_args", async () => {
    let received: Record<string, unknown> | undefined;
    const server = buildRelayerServer({
      submitter: async (args) => {
        received = args as unknown as Record<string, unknown>;
        return { accepted: true, txHash: "0x" + "aa".repeat(32), simulated: true };
      },
    });
    const body = validWithdrawV2Body();
    const res = await server.inject({
      method: "POST",
      url: "/v2/relayer/submit/withdraw",
      payload: body,
    });
    expect(res.statusCode).toBe(202);
    expect(received).toBeDefined();
    // LOAD-BEARING: assert the submitter's argument has the 27 fields in EXACT
    // Move-signature order. If the parser or the manifest ever reorder, this
    // test fails — which is the whole point of locking the order in.
    expect(Object.keys(received!)).toEqual([...WITHDRAW_V2_CALL_ARGS_ORDER]);
    expect(Object.keys(received!).length).toBe(30);
    // Spot-check a few fields end-to-end.
    expect(received!.vaultSequence).toBe("42");
    expect(received!.expirySecs).toBe("1800000000");
    expect(received!.fallbackBitmap).toBe(0);
    expect(Array.isArray(received!.amountRVolunAuds)).toBe(true);
    expect((received!.sigmaProtoComm as string[]).length).toBe(30);
    expect((received!.sigmaProtoResp as string[]).length).toBe(25);
  });

  it("withdraw_v2_route_returns_tx_hash_from_submitter", async () => {
    const expectedHash = "0x" + "ab".repeat(32);
    const server = buildRelayerServer({
      submitter: async () => ({ accepted: true, txHash: expectedHash, simulated: true }),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/relayer/submit/withdraw",
      payload: validWithdrawV2Body(),
    });
    expect(res.statusCode).toBe(202);
    const json = res.json();
    expect(json.accepted).toBe(true);
    expect(json.txHash).toBe(expectedHash);
    expect(json.simulated).toBe(true);
  });

  it("withdraw_v2_route_propagates_submit_disabled_error", async () => {
    const server = buildRelayerServer({
      submitter: async () => {
        throw new Error("submit_disabled: RELAYER_SUBMIT_ENABLED=0");
      },
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/relayer/submit/withdraw",
      payload: validWithdrawV2Body(),
    });
    expect(res.statusCode).toBe(502);
    const json = res.json();
    expect(json.error).toBe("submit_failed");
    expect(json.message).toMatch(/submit_disabled/);
  });

  it("rejects shape-invalid payloads with invalid_request (not forbidden_plaintext_field)", async () => {
    const server = buildRelayerServer({
      submitter: async () => ({ accepted: true, txHash: "x", simulated: true }),
    });
    const body = validWithdrawV2Body();
    body.caPayloadHash = "deadbeef"; // 4 bytes, expected 32
    const res = await server.inject({
      method: "POST",
      url: "/v2/relayer/submit/withdraw",
      payload: body,
    });
    expect(res.statusCode).toBe(400);
    const json = res.json();
    expect(json.error).toBe("invalid_request");
    expect(json.message).toMatch(/caPayloadHash/);
  });

  it("fails closed when no submitter is configured", async () => {
    const server = buildRelayerServer();
    const res = await server.inject({
      method: "POST",
      url: "/v2/relayer/submit/withdraw",
      payload: validWithdrawV2Body(),
    });
    expect(res.statusCode).toBe(502);
    expect(res.json().error).toBe("submit_failed");
  });

  it("requires bearer token when configured", async () => {
    const server = buildRelayerServer({
      bearerToken: "secret",
      submitter: async () => ({ accepted: true, txHash: "x", simulated: true }),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/relayer/submit/withdraw",
      payload: validWithdrawV2Body(),
      // no Authorization header
    });
    expect(res.statusCode).toBe(401);
    expect(res.json().error).toBe("unauthorized");
  });

  it("accepts bearer token when configured", async () => {
    const server = buildRelayerServer({
      bearerToken: "secret",
      submitter: async () => ({ accepted: true, txHash: "x", simulated: true }),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/relayer/submit/withdraw",
      payload: validWithdrawV2Body(),
      headers: { authorization: "Bearer secret" },
    });
    expect(res.statusCode).toBe(202);
  });
});

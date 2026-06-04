import { describe, expect, it } from "vitest";
import { ForbiddenPlaintextFieldError } from "@eunoma/deop-protocol";
import { RelayerSubmitterError, buildRelayerServer } from "../src/server.js";
import { DepositV3ArgsError, parseDepositV3DelegateArgs } from "../src/deposit_v3_args.js";
import type { GasGuard } from "../src/gas_guard.js";

function validDepositBody(): Record<string, unknown> {
  const h = (b: string, n = 32) => b.repeat(n);
  return {
    assetAddr: h("00"),
    userAddr: h("01"),
    commitment: h("aa"),
    amountTag: h("a1"),
    amountP: [h("b0"), h("b1"), h("b2"), h("b3")],
    depositBindingProof: h("cc", 192),
    caPayloadHash: h("dd"),
    depositNonce: h("ee"),
    expirySecs: "1800000000",
    groupSignature: h("0f", 64),
    fallbackBitmap: 0,
    fallbackSignatures: [],
    newBalanceP: Array.from({ length: 8 }, (_, i) => h(((0x40 + i) & 0xff).toString(16).padStart(2, "0"))),
    newBalanceR: Array.from({ length: 8 }, (_, i) => h(((0x50 + i) & 0xff).toString(16).padStart(2, "0"))),
    newBalanceREffAud: [],
    amountRSender: Array.from({ length: 4 }, (_, i) => h(((0x70 + i) & 0xff).toString(16).padStart(2, "0"))),
    amountRRecip: Array.from({ length: 4 }, (_, i) => h(((0x80 + i) & 0xff).toString(16).padStart(2, "0"))),
    amountREffAud: [],
    ekVolunAuds: [],
    amountRVolunAuds: [],
    zkrpNewBalance: h("90", 672),
    zkrpAmount: h("a0", 672),
    sigmaProtoComm: Array.from({ length: 30 }, (_, i) => h(((0xb0 + i) & 0xff).toString(16).padStart(2, "0"))),
    sigmaProtoResp: Array.from({ length: 25 }, (_, i) => h(((0xc0 + i) & 0xff).toString(16).padStart(2, "0"))),
    memo: "",
  };
}

describe("parseDepositV3DelegateArgs", () => {
  it("accepts a valid body and normalizes hex (strips 0x, lowercases)", () => {
    const parsed = parseDepositV3DelegateArgs(validDepositBody());
    expect(parsed.assetAddr).toBe("00".repeat(32));
    expect(parsed.userAddr).toBe("01".repeat(32));
    expect(parsed.amountP.length).toBe(4);
    expect(parsed.sigmaProtoComm.length).toBe(30);
  });

  it("runs the forbidden-plaintext-field guard FIRST", () => {
    const body = validDepositBody();
    body.amount = "1000";
    expect(() => parseDepositV3DelegateArgs(body)).toThrow(ForbiddenPlaintextFieldError);
  });

  it("rejects a wrong-length userAddr", () => {
    const body = validDepositBody();
    body.userAddr = "dead"; // 2 bytes, not 32
    expect(() => parseDepositV3DelegateArgs(body)).toThrow(DepositV3ArgsError);
  });

  it("rejects a non-decimal expirySecs", () => {
    const body = validDepositBody();
    body.expirySecs = "soon";
    expect(() => parseDepositV3DelegateArgs(body)).toThrow(DepositV3ArgsError);
  });
});

const allowGuard: GasGuard = { check: async () => ({ allow: true }) };
const openGuard: GasGuard = { check: async () => ({ allow: false, reason: "reserve_low" }) };
const okSubmitter = async () => ({ accepted: true as const, simulated: true, txHashes: ["0xh0", "0xh1"] });

describe("relayer /v3/relayer/submit/deposit", () => {
  it("returns 501 when no deposit submitter is configured", async () => {
    const server = buildRelayerServer({});
    const res = await server.inject({
      method: "POST",
      url: "/v3/relayer/submit/deposit",
      payload: validDepositBody(),
    });
    expect(res.statusCode).toBe(501);
  });

  it("submits prepare + step2a and returns 2 tx hashes (202)", async () => {
    let called = false;
    const server = buildRelayerServer({
      depositV3Submitter: async (args) => {
        called = true;
        expect(args.assetAddr).toBe("00".repeat(32));
        expect(args.userAddr).toBe("01".repeat(32));
        return okSubmitter();
      },
      gasGuard: allowGuard,
    });
    const res = await server.inject({
      method: "POST",
      url: "/v3/relayer/submit/deposit",
      payload: validDepositBody(),
    });
    expect(res.statusCode).toBe(202);
    expect(res.json().txHashes.length).toBe(2);
    expect(called).toBe(true);
  });

  it("self_submit (200) when the gas/reserve guard refuses, without calling the submitter", async () => {
    let called = false;
    const server = buildRelayerServer({
      depositV3Submitter: async () => {
        called = true;
        return okSubmitter();
      },
      gasGuard: openGuard,
    });
    const res = await server.inject({
      method: "POST",
      url: "/v3/relayer/submit/deposit",
      payload: validDepositBody(),
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ action: "self_submit", reason: "reserve_low" });
    expect(called).toBe(false);
  });

  it("rejects a forbidden plaintext field with 400", async () => {
    const server = buildRelayerServer({ depositV3Submitter: okSubmitter });
    const body = validDepositBody();
    body.blind = "secret";
    const res = await server.inject({
      method: "POST",
      url: "/v3/relayer/submit/deposit",
      payload: body,
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("forbidden_plaintext_field");
  });

  it("surfaces a RelayerSubmitterError as 502", async () => {
    const server = buildRelayerServer({
      gasGuard: allowGuard,
      depositV3Submitter: async () => {
        throw new RelayerSubmitterError("aptos_cli_error", "generic; check logs");
      },
    });
    const res = await server.inject({
      method: "POST",
      url: "/v3/relayer/submit/deposit",
      payload: validDepositBody(),
    });
    expect(res.statusCode).toBe(502);
    expect(res.json().code).toBe("aptos_cli_error");
  });
});

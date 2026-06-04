import { describe, expect, it } from "vitest";
import {
  EMERGENCY_EXIT_CALL_ARGS_ORDER,
  EmergencyExitCallArgsError,
  classifyEmergencyExitAbort,
  encodeEmergencyExitArgs,
  parseEmergencyExitCallArgs,
  type EmergencyExitCallArgs,
} from "../src/emergency_exit_submitter.js";

function validBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const hex32 = (seed: number): string =>
    Array.from({ length: 32 }, (_, i) => ((i + seed) & 0xff).toString(16).padStart(2, "0")).join("");
  const hexN = (n: number, seed: number): string =>
    Array.from({ length: n }, (_, i) => ((i + seed) & 0xff).toString(16).padStart(2, "0")).join("");
  return {
    assetAddr: hex32(0x01),
    recipient: hex32(0x02),
    amount: "1000000", // PLAINTEXT residual — the intentional de-list disclosure (allowed here).
    expirySecs: "1800000000",
    groupSignature: hexN(64, 0x30),
    fallbackBitmap: 0,
    fallbackSignatures: [],
    newBalanceP: Array.from({ length: 8 }, (_, i) => hex32(0x40 + i)),
    newBalanceR: Array.from({ length: 8 }, (_, i) => hex32(0x50 + i)),
    newBalanceRAud: [],
    zkrpNewBalance: hexN(672, 0x90),
    sigmaProtoComm: Array.from({ length: 30 }, (_, i) => hex32(0xb0 + i)),
    sigmaProtoResp: Array.from({ length: 25 }, (_, i) => hex32(0xc0 + i)),
    ...overrides,
  };
}

describe("EMERGENCY_EXIT_CALL_ARGS_ORDER — mirrors the Move signature positionally", () => {
  it("matches eunoma_bridge::emergency_exit_to_raw_v4 field order (13 args, no _relayer)", () => {
    expect([...EMERGENCY_EXIT_CALL_ARGS_ORDER]).toEqual([
      "assetAddr",
      "recipient",
      "amount",
      "expirySecs",
      "groupSignature",
      "fallbackBitmap",
      "fallbackSignatures",
      "newBalanceP",
      "newBalanceR",
      "newBalanceRAud",
      "zkrpNewBalance",
      "sigmaProtoComm",
      "sigmaProtoResp",
    ]);
  });
});

describe("parseEmergencyExitCallArgs", () => {
  it("accepts a fully-populated body and preserves Move-order keys", () => {
    const parsed = parseEmergencyExitCallArgs(validBody());
    expect(Object.keys(parsed)).toEqual([...EMERGENCY_EXIT_CALL_ARGS_ORDER]);
    expect(parsed.amount).toBe("1000000");
  });

  it("ALLOWS a plaintext `amount` (the signed de-list disclosure) — not forbidden here", () => {
    // The confidential withdraw path forbids any plaintext amount; emergency-exit signs it.
    expect(() => parseEmergencyExitCallArgs(validBody({ amount: "42" }))).not.toThrow();
  });

  it("rejects a body with no FROST attestation (no group sig AND empty fallback set)", () => {
    const body = validBody({ groupSignature: "", fallbackSignatures: [] });
    expect(() => parseEmergencyExitCallArgs(body)).toThrow(EmergencyExitCallArgsError);
    try {
      parseEmergencyExitCallArgs(body);
    } catch (e) {
      expect((e as EmergencyExitCallArgsError).code).toBe("missing_frost_attestation");
    }
  });

  it("accepts the fallback-bitmap form (group sig empty, fallback sigs present)", () => {
    const body = validBody({
      groupSignature: "",
      fallbackBitmap: 0b0011111, // 5-of-7 bits set
      fallbackSignatures: Array.from({ length: 5 }, (_, i) =>
        Array.from({ length: 64 }, (_, j) => ((i + j) & 0xff).toString(16).padStart(2, "0")).join(""),
      ),
    });
    expect(() => parseEmergencyExitCallArgs(body)).not.toThrow();
  });

  it("rejects a non-empty auditor vector (M5a no-auditor invariant)", () => {
    const body = validBody({ newBalanceRAud: ["00".repeat(32)] });
    expect(() => parseEmergencyExitCallArgs(body)).toThrow(/auditor/);
  });

  it("rejects a non-decimal amount", () => {
    expect(() => parseEmergencyExitCallArgs(validBody({ amount: "0x2a" }))).toThrow(
      EmergencyExitCallArgsError,
    );
  });
});

describe("encodeEmergencyExitArgs — aptos-CLI positional encoding", () => {
  it("encodes address/u64/u8/hex/vector forms in Move order", () => {
    const parsed: EmergencyExitCallArgs = parseEmergencyExitCallArgs(validBody());
    const positional = encodeEmergencyExitArgs(parsed);
    expect(positional.length).toBe(EMERGENCY_EXIT_CALL_ARGS_ORDER.length);
    expect(positional[0]).toMatch(/^address:0x[0-9a-f]{64}$/); // assetAddr
    expect(positional[1]).toMatch(/^address:0x[0-9a-f]{64}$/); // recipient
    expect(positional[2]).toBe("u64:1000000"); // amount (plaintext disclosure)
    expect(positional[3]).toMatch(/^u64:/); // expirySecs
    expect(positional[4]).toMatch(/^hex:0x/); // groupSignature
    expect(positional[5]).toMatch(/^u8:/); // fallbackBitmap
    expect(positional[7]).toMatch(/^hex:\[/); // newBalanceP (vector)
    expect(positional[9]).toMatch(/^hex:\[/); // newBalanceRAud (empty vector ok)
  });
});

describe("classifyEmergencyExitAbort — structured framework_paused signal (RC6(B))", () => {
  it("classifies the framework is_emergency_paused() abort as framework_paused", () => {
    // confidential_asset::E_EMERGENCY_PAUSED = 20 -> error::invalid_state(20) = 196628 / 0x30014.
    const stderr =
      "Transaction failed: MoveAbort { location: 0x7::confidential_asset, code: 196628 }";
    const c = classifyEmergencyExitAbort(stderr);
    expect(c.signal).toBe("framework_paused");
    expect(c.detail).toMatch(/halted/);
  });

  it("classifies the hex-rendered framework abort (0x30014) as framework_paused", () => {
    const stderr = "MoveAbort in 0x7::confidential_asset: 0x30014";
    expect(classifyEmergencyExitAbort(stderr).signal).toBe("framework_paused");
  });

  it("does NOT mis-classify a bare 196628 in some unrelated module as framework_paused", () => {
    const stderr = "MoveAbort { location: 0x1::some_other_module, code: 196628 }";
    expect(classifyEmergencyExitAbort(stderr).signal).not.toBe("framework_paused");
  });

  it("classifies E_NOT_DELISTED (bridge code 44) as not_delisted", () => {
    const stderr = "MoveAbort { location: 0xeunoma::eunoma_bridge, code: 44 }";
    expect(classifyEmergencyExitAbort(stderr).signal).toBe("not_delisted");
  });

  it("classifies E_ASSET_NOT_ACTIVE (bridge code 40) as asset_not_active", () => {
    const stderr = "MoveAbort { location: 0xeunoma::eunoma_bridge, code: 40 }";
    expect(classifyEmergencyExitAbort(stderr).signal).toBe("asset_not_active");
  });

  it("falls back to submit_error for an unrecognized failure (and leaks no raw stderr)", () => {
    const stderr = "INSUFFICIENT_BALANCE_FOR_TRANSACTION_FEE: ...secret-looking-bytes...";
    const c = classifyEmergencyExitAbort(stderr);
    expect(c.signal).toBe("submit_error");
    expect(c.detail).not.toContain("secret-looking-bytes");
  });
});

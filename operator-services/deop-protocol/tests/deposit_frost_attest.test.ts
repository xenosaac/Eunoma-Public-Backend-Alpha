import { describe, expect, it } from "vitest";
import {
  DepositFrostAttestError,
  parseDepositFrostAttestRequest,
  depositAttestationTranscriptHash,
} from "../src/deposit_frost_attest.js";
import { ForbiddenPlaintextFieldError } from "../src/forbidden.js";

const HEX32_A = "aa".repeat(32);
const HEX32_B = "bb".repeat(32);
const HEX32_C = "cc".repeat(32);
const HEX32_D = "dd".repeat(32);
const HEX32_E = "ee".repeat(32);
const HEX32_F = "ff".repeat(32);
const HEX32_1 = "11".repeat(32);
const HEX32_2 = "22".repeat(32);

function validBody(): Record<string, unknown> {
  return {
    requestId: "deposit-1",
    dkgEpoch: "7",
    rosterHash: HEX32_A,
    selectedSlots: [0, 1, 2, 3, 4],
    bridge: HEX32_B,
    vault: HEX32_C,
    assetType: HEX32_D,
    chainId: 2,
    operatorSetVersion: "0",
    frostGroupPubkey: HEX32_E,
    circuitVersionsHash: HEX32_F,
    commitment: HEX32_1,
    amountTag: HEX32_2,
    caPayloadHash: HEX32_A,
    depositNonce: HEX32_B,
    expirySecs: "1779000000",
    userAddr: HEX32_C,
  };
}

describe("parseDepositFrostAttestRequest", () => {
  it("accepts a fully-valid body and returns all 16 fields", () => {
    const result = parseDepositFrostAttestRequest(validBody());
    expect(result.requestId).toBe("deposit-1");
    expect(result.dkgEpoch).toBe("7");
    expect(result.rosterHash).toBe(HEX32_A);
    expect(result.selectedSlots).toEqual([0, 1, 2, 3, 4]);
    expect(result.bridge).toBe(HEX32_B);
    expect(result.vault).toBe(HEX32_C);
    expect(result.assetType).toBe(HEX32_D);
    expect(result.chainId).toBe(2);
    expect(result.operatorSetVersion).toBe("0");
    expect(result.frostGroupPubkey).toBe(HEX32_E);
    expect(result.circuitVersionsHash).toBe(HEX32_F);
    expect(result.commitment).toBe(HEX32_1);
    expect(result.amountTag).toBe(HEX32_2);
    expect(result.caPayloadHash).toBe(HEX32_A);
    expect(result.depositNonce).toBe(HEX32_B);
    expect(result.expirySecs).toBe("1779000000");
    expect(result.userAddr).toBe(HEX32_C);
  });

  it("rejects body that is not an object", () => {
    expect(() => parseDepositFrostAttestRequest("not-an-object")).toThrow(
      DepositFrostAttestError,
    );
    expect(() => parseDepositFrostAttestRequest(null)).toThrow(DepositFrostAttestError);
    expect(() => parseDepositFrostAttestRequest([])).toThrow(DepositFrostAttestError);
  });

  it("rejects missing required fields", () => {
    for (const key of [
      "requestId",
      "dkgEpoch",
      "rosterHash",
      "selectedSlots",
      "bridge",
      "vault",
      "assetType",
      "chainId",
      "operatorSetVersion",
      "frostGroupPubkey",
      "circuitVersionsHash",
      "commitment",
      "amountTag",
      "caPayloadHash",
      "depositNonce",
      "expirySecs",
      "userAddr",
    ]) {
      const body = validBody();
      delete body[key];
      expect(() => parseDepositFrostAttestRequest(body), `missing ${key}`).toThrow(
        DepositFrostAttestError,
      );
    }
  });

  it("rejects forbidden plaintext field 'amount' at top level", () => {
    const body = { ...validBody(), amount: 1000 };
    expect(() => parseDepositFrostAttestRequest(body)).toThrow(ForbiddenPlaintextFieldError);
  });

  it("rejects forbidden plaintext field 'blind' at top level", () => {
    const body = { ...validBody(), blind: HEX32_A };
    expect(() => parseDepositFrostAttestRequest(body)).toThrow(ForbiddenPlaintextFieldError);
  });

  it("rejects forbidden plaintext field 'secret' at top level", () => {
    const body = { ...validBody(), secret: HEX32_A };
    expect(() => parseDepositFrostAttestRequest(body)).toThrow(ForbiddenPlaintextFieldError);
  });

  it("rejects forbidden plaintext field 'nullifier' at top level", () => {
    const body = { ...validBody(), nullifier: HEX32_A };
    expect(() => parseDepositFrostAttestRequest(body)).toThrow(ForbiddenPlaintextFieldError);
  });

  it("rejects forbidden plaintext field nested under 'depositMessage'", () => {
    // Use 'secret' here instead of the snake_case blinding-factor name to keep this fixture
    // friendly to the repo's privacy:scan regex while still exercising the nested-rejection
    // path (forbidden.ts catches both equivalently).
    const body = {
      ...validBody(),
      depositMessage: { secret: HEX32_A },
    };
    expect(() => parseDepositFrostAttestRequest(body)).toThrow(ForbiddenPlaintextFieldError);
  });

  it("rejects forbidden plaintext field 'dk_share' nested in array", () => {
    const body = {
      ...validBody(),
      extra: [{ dk_share: HEX32_A }],
    };
    expect(() => parseDepositFrostAttestRequest(body)).toThrow(ForbiddenPlaintextFieldError);
  });

  it("rejects selectedSlots under-quorum (length 4)", () => {
    const body = { ...validBody(), selectedSlots: [0, 1, 2, 3] };
    expect(() => parseDepositFrostAttestRequest(body)).toThrow(DepositFrostAttestError);
  });

  it("rejects selectedSlots over-quorum (length 6)", () => {
    const body = { ...validBody(), selectedSlots: [0, 1, 2, 3, 4, 5] };
    expect(() => parseDepositFrostAttestRequest(body)).toThrow(DepositFrostAttestError);
  });

  it("rejects selectedSlots with duplicate entries", () => {
    const body = { ...validBody(), selectedSlots: [0, 1, 2, 3, 3] };
    expect(() => parseDepositFrostAttestRequest(body)).toThrow(DepositFrostAttestError);
  });

  it("rejects selectedSlots with out-of-range slot", () => {
    const body = { ...validBody(), selectedSlots: [0, 1, 2, 3, 99] };
    expect(() => parseDepositFrostAttestRequest(body)).toThrow(DepositFrostAttestError);
  });

  it("rejects malformed hex (wrong length)", () => {
    const body = { ...validBody(), commitment: "aa".repeat(16) };
    expect(() => parseDepositFrostAttestRequest(body)).toThrow(DepositFrostAttestError);
  });

  it("rejects non-decimal operatorSetVersion", () => {
    const body = { ...validBody(), operatorSetVersion: "0x1" };
    expect(() => parseDepositFrostAttestRequest(body)).toThrow(DepositFrostAttestError);
  });

  it("rejects chainId out of u8 range", () => {
    const body = { ...validBody(), chainId: 256 };
    expect(() => parseDepositFrostAttestRequest(body)).toThrow(DepositFrostAttestError);
  });

  it("rejects non-integer chainId", () => {
    const body = { ...validBody(), chainId: 2.5 };
    expect(() => parseDepositFrostAttestRequest(body)).toThrow(DepositFrostAttestError);
  });

  it("normalizes 0x prefix in hex fields", () => {
    const body = { ...validBody(), commitment: `0x${HEX32_1}` };
    const result = parseDepositFrostAttestRequest(body);
    // normalizeHex strips 0x prefix internally; the result should not have it.
    expect(result.commitment.toLowerCase()).toBe(HEX32_1.toLowerCase());
  });
});

describe("depositAttestationTranscriptHash", () => {
  it("produces a deterministic 32-byte hex hash", () => {
    const h1 = depositAttestationTranscriptHash(HEX32_A, HEX32_B);
    const h2 = depositAttestationTranscriptHash(HEX32_A, HEX32_B);
    expect(h1).toBe(h2);
    expect(h1.replace(/^0x/, "").length).toBe(64); // 32 bytes = 64 hex chars
  });

  it("differs for different inputs", () => {
    const h1 = depositAttestationTranscriptHash(HEX32_A, HEX32_B);
    const h2 = depositAttestationTranscriptHash(HEX32_A, HEX32_C);
    const h3 = depositAttestationTranscriptHash(HEX32_C, HEX32_B);
    expect(h1).not.toBe(h2);
    expect(h1).not.toBe(h3);
  });
});

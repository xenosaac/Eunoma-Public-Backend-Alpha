import { describe, expect, it } from "vitest";
import {
  EUNOMA_WITHDRAW_V2_DOMAIN,
  ForbiddenPlaintextFieldError,
  WITHDRAW_V2_CALL_ARGS_ORDER,
  WithdrawV2CallArgsError,
  parseWithdrawV2CallArgs,
} from "../src/index.js";

// 27 entries — matches the Move signature at
// move/sources/eunoma_bridge.move:515-543 (excluding `_relayer: &signer`).
const EXPECTED_FIELD_COUNT = 27;
const EXPECTED_MOVE_ORDER = [
  "root",
  "nullifierHash",
  "recipient",
  "recipientHash",
  "amountTag",
  "caPayloadHash",
  "requestHash",
  "vaultSequence",
  "withdrawProof",
  "expirySecs",
  "groupSignature",
  "fallbackBitmap",
  "fallbackSignatures",
  "newBalanceP",
  "newBalanceR",
  "newBalanceREffAud",
  "amountP",
  "amountRSender",
  "amountRRecip",
  "amountREffAud",
  "ekVolunAuds",
  "amountRVolunAuds",
  "zkrpNewBalance",
  "zkrpAmount",
  "sigmaProtoComm",
  "sigmaProtoResp",
  "memo",
];

/**
 * Deterministic 27-field fixture matching the Move signature.
 *
 * Chunk counts mirror the Aptos CA SDK in the existing
 * aptos_ca_transfer_v1_fixture.json:
 *   - ell = 8 (new_balance_* arrays)
 *   - n   = 4 (amount_* arrays)
 *   - sigma proof: 30 commitment points / 25 response scalars
 * Hex blobs themselves are deterministic but otherwise opaque — this fixture
 * is for shape validation, not cryptographic verification.
 */
function buildValidFixture(): Record<string, unknown> {
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
    vaultSequence: "42",
    withdrawProof: hexN(192, 0x20), // Groth16 BN254 proof = 192 bytes (3 G1 + 1 G2 in compressed form)
    expirySecs: "1800000000",
    groupSignature: hexN(64, 0x30), // FROST ed25519 signature
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
    amountRVolunAuds: [], // depth-3, empty top-level is legal
    zkrpNewBalance: hexN(672, 0x90), // bulletproofs range proof, opaque blob
    zkrpAmount: hexN(672, 0xa0),
    sigmaProtoComm: Array.from({ length: 30 }, (_, i) => hex32(0xb0 + i)),
    sigmaProtoResp: Array.from({ length: 25 }, (_, i) => hex32(0xc0 + i)),
    memo: "",
  };
}

describe("WithdrawV2CallArgs domain constant", () => {
  it("exposes the versioned domain string", () => {
    expect(EUNOMA_WITHDRAW_V2_DOMAIN).toBe("EUNOMA_WITHDRAW_V2_CALL_ARGS_V1");
  });

  it("WITHDRAW_V2_CALL_ARGS_ORDER matches Move signature byte-for-byte", () => {
    expect(WITHDRAW_V2_CALL_ARGS_ORDER.length).toBe(EXPECTED_FIELD_COUNT);
    expect([...WITHDRAW_V2_CALL_ARGS_ORDER]).toEqual(EXPECTED_MOVE_ORDER);
  });
});

describe("parseWithdrawV2CallArgs — happy path", () => {
  it("accepts a fully-populated fixture and preserves field order in returned object", () => {
    const fixture = buildValidFixture();
    const parsed = parseWithdrawV2CallArgs(fixture);
    // Object.keys preserves insertion order in JS; the parser writes fields in
    // Move-signature order, so this assertion locks the order in.
    expect(Object.keys(parsed)).toEqual(EXPECTED_MOVE_ORDER);
    expect(parsed.vaultSequence).toBe("42");
    expect(parsed.fallbackBitmap).toBe(0);
    expect(parsed.amountRVolunAuds).toEqual([]);
    expect(parsed.sigmaProtoComm).toHaveLength(30);
    expect(parsed.sigmaProtoResp).toHaveLength(25);
  });

  it("parser_rejects_nonempty_auditor_fields_until_milestone_4d", () => {
    // M5a is no-auditor: any non-empty auditor vector MUST be rejected with
    // a stable error code. Milestone 4d will relax this once auditor support
    // ships on the Move side. Each of the four auditor vectors is exercised
    // INDEPENDENTLY so a regression on any single field fails the test.
    const baseFixture = buildValidFixture();
    const oneHash = "ff".repeat(32);

    const cases: Array<[string, (f: Record<string, unknown>) => void]> = [
      [
        "newBalanceREffAud non-empty",
        (f) => {
          f.newBalanceREffAud = [oneHash];
        },
      ],
      [
        "amountREffAud non-empty",
        (f) => {
          f.amountREffAud = [oneHash];
        },
      ],
      [
        "ekVolunAuds non-empty",
        (f) => {
          f.ekVolunAuds = [oneHash];
        },
      ],
      [
        "amountRVolunAuds non-empty",
        (f) => {
          f.amountRVolunAuds = [[oneHash]];
        },
      ],
    ];

    for (const [label, mutate] of cases) {
      const fixture = { ...baseFixture };
      mutate(fixture);
      try {
        parseWithdrawV2CallArgs(fixture);
        throw new Error(`expected rejection for ${label}`);
      } catch (err) {
        expect(err, label).toBeInstanceOf(WithdrawV2CallArgsError);
        expect((err as WithdrawV2CallArgsError).code, label).toBe(
          "auditor_branch_not_supported_in_milestone_5a",
        );
        expect((err as WithdrawV2CallArgsError).message, label).toMatch(
          /no-auditor today.*Milestone 4d/,
        );
      }
    }
  });
});

describe("parseWithdrawV2CallArgs — rejection paths", () => {
  it("rejects a body containing a forbidden plaintext field name (top-level)", () => {
    const fixture = buildValidFixture();
    (fixture as Record<string, unknown>).amount = "1000";
    expect(() => parseWithdrawV2CallArgs(fixture)).toThrow(ForbiddenPlaintextFieldError);
  });

  it("rejects a body containing a forbidden plaintext field name nested under a sub-object", () => {
    const fixture = buildValidFixture();
    (fixture as Record<string, unknown>).meta = { user: { dk_share: "00".repeat(32) } };
    expect(() => parseWithdrawV2CallArgs(fixture)).toThrow(ForbiddenPlaintextFieldError);
  });

  it("rejects a body missing a required field (recipientHash)", () => {
    const fixture = buildValidFixture();
    delete (fixture as Record<string, unknown>).recipientHash;
    expect(() => parseWithdrawV2CallArgs(fixture)).toThrow(/recipientHash/);
  });

  it("rejects a body with the wrong hex length on a 32-byte hash (caPayloadHash short)", () => {
    const fixture = buildValidFixture();
    fixture.caPayloadHash = "deadbeef";
    expect(() => parseWithdrawV2CallArgs(fixture)).toThrow(/caPayloadHash must be 32 bytes/);
  });

  it("rejects a body where fallbackBitmap is out of u8 range", () => {
    const fixture = buildValidFixture();
    fixture.fallbackBitmap = 256;
    expect(() => parseWithdrawV2CallArgs(fixture)).toThrow(/fallbackBitmap/);
  });

  it("rejects a body where fallbackBitmap is negative", () => {
    const fixture = buildValidFixture();
    fixture.fallbackBitmap = -1;
    expect(() => parseWithdrawV2CallArgs(fixture)).toThrow(/fallbackBitmap/);
  });

  it("rejects a body where amountRVolunAuds is depth-2 (string[]) instead of depth-3 (string[][])", () => {
    const fixture = buildValidFixture();
    // depth-2 with one outer entry that is a string instead of a string[]
    fixture.amountRVolunAuds = ["00".repeat(32)] as unknown as string[][];
    expect(() => parseWithdrawV2CallArgs(fixture)).toThrow(/amountRVolunAuds\[0\]/);
  });

  it("rejects a body where vaultSequence is not a decimal string", () => {
    const fixture = buildValidFixture();
    fixture.vaultSequence = "0x2a"; // hex, not decimal
    expect(() => parseWithdrawV2CallArgs(fixture)).toThrow(/vaultSequence/);
  });

  it("rejects a body where vaultSequence overflows u64", () => {
    const fixture = buildValidFixture();
    fixture.vaultSequence = "18446744073709551616"; // u64 max + 1
    expect(() => parseWithdrawV2CallArgs(fixture)).toThrow(/u64/);
  });

  it("rejects a body where expirySecs is not a decimal string", () => {
    const fixture = buildValidFixture();
    fixture.expirySecs = "not-a-number";
    expect(() => parseWithdrawV2CallArgs(fixture)).toThrow(/expirySecs/);
  });

  it("rejects a body where withdrawProof contains non-hex characters", () => {
    const fixture = buildValidFixture();
    fixture.withdrawProof = "GG".repeat(96);
    expect(() => parseWithdrawV2CallArgs(fixture)).toThrow();
  });

  it("rejects a body where newBalanceP is empty (required vector)", () => {
    const fixture = buildValidFixture();
    fixture.newBalanceP = [];
    expect(() => parseWithdrawV2CallArgs(fixture)).toThrow(/newBalanceP must be a non-empty array/);
  });
});

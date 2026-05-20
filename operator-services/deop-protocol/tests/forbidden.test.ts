import { describe, expect, it } from "vitest";
import {
  ForbiddenPlaintextFieldError,
  assertNoForbiddenPlaintextFields,
} from "../src/index.js";

describe("forbidden plaintext field gate", () => {
  it("rejects plaintext user witness field names recursively", () => {
    expect(() =>
      assertNoForbiddenPlaintextFields({
        requestId: "r",
        nested: [{ amountOctas: "1000" }],
      }),
    ).toThrow(ForbiddenPlaintextFieldError);
  });

  it("allows public commitment/tag/hash names", () => {
    expect(() =>
      assertNoForbiddenPlaintextFields({
        commitment: "00",
        amountTag: "11",
        nullifierHash: "22",
        shareCommitments: ["33"],
        hpke: { ciphertext: "44" },
      }),
    ).not.toThrow();
  });

  it("rejects complete vault decryption key names", () => {
    expect(() =>
      assertNoForbiddenPlaintextFields({
        vaultDecryptionKey: "00",
      }),
    ).toThrow(ForbiddenPlaintextFieldError);
  });

  it("rejects CA DKG Shamir share field names (dk_share class)", () => {
    for (const fieldName of ["dkShare", "dk_share", "caDkShare", "ca_dk_share", "shamirShare", "shamir_share"]) {
      expect(() =>
        assertNoForbiddenPlaintextFields({
          [fieldName]: "00",
        }),
      ).toThrow(ForbiddenPlaintextFieldError);
    }
  });
});

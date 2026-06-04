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

  // HARD INVARIANT (V4 partial-withdraw): the change-note LINEAGE block is FRONTEND-ONLY metadata and
  // must NEVER cross a Move arg / circuit-input boundary — a parent identifier on the spend boundary
  // re-links deposit↔withdraw (the exact correlation WithdrawConfirmedV4's minimal fields avoid).
  it("rejects V4 change-note lineage fields (lineage / parentCommitment / parentNullifierHash)", () => {
    for (const fieldName of [
      "lineage",
      "parentCommitment",
      "parent_commitment",
      "parentNullifier",
      "parent_nullifier",
      "parentNullifierHash",
      "parent_nullifier_hash",
    ]) {
      expect(() =>
        assertNoForbiddenPlaintextFields({ [fieldName]: "00" }),
      ).toThrow(ForbiddenPlaintextFieldError);
    }
  });

  it("rejects a nested lineage block (as it would appear on a v4 change note) reaching a Move arg", () => {
    expect(() =>
      assertNoForbiddenPlaintextFields({
        requestId: "r",
        moveArgs: [
          {
            lineage: { kind: "remainder", parentNullifierHash: "ab", parentCommitment: "cd", createdAtTx: "0x1" },
          },
        ],
      }),
    ).toThrow(ForbiddenPlaintextFieldError);
  });

  // The PUBLIC nullifier_hash / commitment of the SPENT note stay allowed — only the PARENT-scoped
  // lineage identifiers are banned. This guards against the ban over-matching public fields.
  it("still allows the public nullifierHash + commitment (only PARENT lineage ids are banned)", () => {
    expect(() =>
      assertNoForbiddenPlaintextFields({
        commitment: "00",
        nullifierHash: "11",
        changeCommitment: "22",
      }),
    ).not.toThrow();
  });
});

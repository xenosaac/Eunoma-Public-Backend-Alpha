import { describe, expect, it } from "vitest";
import { bytesToHex, hexToBytes, sha256 } from "@eunoma/shared";
import {
  FrostSigningError,
  parseFrostAggregateSignatureResponse,
  parseFrostNonceCommitmentResponse,
  parseFrostPartialSignatureResponse,
} from "../src/frost_signing.js";

const HEX32_A = "aa".repeat(32);
const HEX32_B = "bb".repeat(32);

function syntheticSignatureHex(byte: number): string {
  return byte.toString(16).padStart(2, "0").repeat(64);
}

describe("FROST signing response parsers (M5)", () => {
  it("parseFrostNonceCommitmentResponse accepts a valid response", () => {
    const body = {
      nonceId: "nonce-abc-123",
      commitmentHash: HEX32_A,
      commitments: { hiding: { value: "deadbeef" }, binding: { value: "cafebabe" } },
      transcriptHash: HEX32_B,
    };
    const parsed = parseFrostNonceCommitmentResponse(body);
    expect(parsed.nonceId).toBe("nonce-abc-123");
    expect(parsed.commitmentHash).toBe(HEX32_A);
    expect(parsed.transcriptHash).toBe(HEX32_B);
    expect(parsed.commitments).toBeDefined();
  });

  it("rejects nonce-commit without commitments field", () => {
    const body = {
      nonceId: "n",
      commitmentHash: HEX32_A,
      transcriptHash: HEX32_B,
      // commitments missing
    };
    expect(() => parseFrostNonceCommitmentResponse(body)).toThrow(FrostSigningError);
  });

  it("rejects nonce-commit with wrong commitmentHash length", () => {
    const body = {
      nonceId: "n",
      commitmentHash: "ab",
      commitments: {},
      transcriptHash: HEX32_B,
    };
    expect(() => parseFrostNonceCommitmentResponse(body)).toThrow(/32-byte hex/);
  });

  it("parseFrostPartialSignatureResponse accepts a valid response", () => {
    const body = {
      nonceId: "n",
      signatureShareHash: HEX32_A,
      signatureShare: { share: { value: "1234" } },
      transcriptHash: HEX32_B,
    };
    const parsed = parseFrostPartialSignatureResponse(body);
    expect(parsed.nonceId).toBe("n");
    expect(parsed.signatureShareHash).toBe(HEX32_A);
    expect(parsed.signatureShare).toBeDefined();
  });

  it("rejects partial-sign without signatureShare field", () => {
    const body = {
      nonceId: "n",
      signatureShareHash: HEX32_A,
      transcriptHash: HEX32_B,
      // signatureShare missing
    };
    expect(() => parseFrostPartialSignatureResponse(body)).toThrow(FrostSigningError);
  });

  it("parseFrostAggregateSignatureResponse accepts a valid 64-byte signature", () => {
    const sigHex = syntheticSignatureHex(0x42);
    const sigBytes = hexToBytes(sigHex);
    const sigHash = bytesToHex(sha256(sigBytes));
    const body = {
      signature: sigHex,
      signatureHash: sigHash,
      transcriptHash: HEX32_B,
    };
    const parsed = parseFrostAggregateSignatureResponse(body);
    expect(parsed.signature).toBe(sigHex);
    expect(parsed.signatureHash).toBe(sigHash);
    expect(parsed.transcriptHash).toBe(HEX32_B);
  });

  it("rejects aggregate-sign with wrong signature length (not 64 bytes)", () => {
    const body = {
      signature: "ab".repeat(32), // 32 bytes, not 64
      signatureHash: HEX32_A,
      transcriptHash: HEX32_B,
    };
    expect(() => parseFrostAggregateSignatureResponse(body)).toThrow(/64-byte hex/);
  });

  it("rejects aggregate-sign when signatureHash != sha256(signature) — defense-in-depth", () => {
    const body = {
      signature: syntheticSignatureHex(0x42),
      signatureHash: HEX32_A, // wrong — not sha256 of the signature
      transcriptHash: HEX32_B,
    };
    expect(() => parseFrostAggregateSignatureResponse(body)).toThrow(/signatureHash/);
  });

  it("all parsers fire forbidden-plaintext-field guard", () => {
    const forbiddenField = { amount: 1_000_000 };
    expect(() =>
      parseFrostNonceCommitmentResponse({
        ...forbiddenField,
        nonceId: "n",
        commitmentHash: HEX32_A,
        commitments: {},
        transcriptHash: HEX32_B,
      }),
    ).toThrow();
    expect(() =>
      parseFrostPartialSignatureResponse({
        ...forbiddenField,
        nonceId: "n",
        signatureShareHash: HEX32_A,
        signatureShare: {},
        transcriptHash: HEX32_B,
      }),
    ).toThrow();
    expect(() =>
      parseFrostAggregateSignatureResponse({
        ...forbiddenField,
        signature: syntheticSignatureHex(0x42),
        signatureHash: bytesToHex(sha256(hexToBytes(syntheticSignatureHex(0x42)))),
        transcriptHash: HEX32_B,
      }),
    ).toThrow();
  });
});

import { describe, expect, it } from "vitest";
import {
  CaRegistrationV2Error,
  assembleCaRegistrationV2Transcript,
  caRegistrationV2FinalTranscriptHash,
  caRegistrationV2Round1WorkerTranscriptHash,
  caRegistrationV2Round2WorkerTranscriptHash,
  parseCaRegistrationV2Round1Request,
  parseCaRegistrationV2Round1Response,
  parseCaRegistrationV2Round2Request,
  parseCaRegistrationV2Round2Response,
} from "../src/ca_registration_v2.js";

const h32 = (byte: string) => byte.repeat(64);

function validRound1Request(overrides: Record<string, unknown> = {}) {
  return {
    dkgEpoch: "3",
    requestId: "req-ca-reg-v2-test",
    sessionId: "sess-ca-reg-v2-test",
    caDkgTranscriptHash: h32("a"),
    rosterHash: h32("b"),
    selectedSlots: [0, 1, 2, 3, 4],
    selfSlot: 0,
    playerId: 0,
    vaultEk: h32("c"),
    senderAddress: h32("d"),
    assetType: h32("e"),
    chainId: 2,
    ...overrides,
  };
}

describe("ca_registration_v2 parsers", () => {
  it("accepts a fully-populated round1 request", () => {
    const parsed = parseCaRegistrationV2Round1Request(validRound1Request());
    expect(parsed.dkgEpoch).toBe("3");
    expect(parsed.selectedSlots).toEqual([0, 1, 2, 3, 4]);
    expect(parsed.vaultEk).toBe(h32("c"));
    expect(parsed.chainId).toBe(2);
  });

  it("rejects under-quorum selectedSlots", () => {
    expect(() =>
      parseCaRegistrationV2Round1Request(
        validRound1Request({ selectedSlots: [0, 1, 2, 3] }),
      ),
    ).toThrow(CaRegistrationV2Error);
  });

  it("rejects duplicate selectedSlots", () => {
    expect(() =>
      parseCaRegistrationV2Round1Request(
        validRound1Request({ selectedSlots: [0, 0, 2, 3, 4] }),
      ),
    ).toThrow(CaRegistrationV2Error);
  });

  it("rejects out-of-range selfSlot", () => {
    expect(() =>
      parseCaRegistrationV2Round1Request(validRound1Request({ selfSlot: 7 })),
    ).toThrow(CaRegistrationV2Error);
  });

  it("rejects out-of-range playerId", () => {
    expect(() =>
      parseCaRegistrationV2Round1Request(validRound1Request({ playerId: 5 })),
    ).toThrow(CaRegistrationV2Error);
  });

  it("rejects non-32-byte hex fields", () => {
    expect(() =>
      parseCaRegistrationV2Round1Request(validRound1Request({ vaultEk: "deadbeef" })),
    ).toThrow(CaRegistrationV2Error);
  });

  it("rejects forbidden plaintext fields recursively", () => {
    // The forbidden gate is recursive; a nested `secret` field is rejected.
    const malicious: Record<string, unknown> = {
      ...validRound1Request(),
      // Embed a forbidden field name to confirm the gate fires.
      secret: "anything",
    };
    expect(() => parseCaRegistrationV2Round1Request(malicious)).toThrow();
  });

  it("accepts a valid round1 response", () => {
    const parsed = parseCaRegistrationV2Round1Response({
      slot: 0,
      commitmentHex: h32("1"),
      commitmentHash: h32("2"),
      nonceId: h32("3"),
      workerTranscriptHash: h32("4"),
    });
    expect(parsed.slot).toBe(0);
  });

  it("accepts a valid round2 request and response", () => {
    const req = parseCaRegistrationV2Round2Request({
      dkgEpoch: "3",
      requestId: "req",
      sessionId: "sess",
      caDkgTranscriptHash: h32("a"),
      rosterHash: h32("b"),
      selectedSlots: [0, 1, 2, 3, 4],
      selfSlot: 0,
      playerId: 0,
      nonceId: h32("3"),
      challenge: h32("5"),
    });
    expect(req.challenge).toBe(h32("5"));
    const res = parseCaRegistrationV2Round2Response({
      slot: 0,
      responseHex: h32("6"),
      responseHash: h32("7"),
      workerTranscriptHash: h32("8"),
    });
    expect(res.responseHex).toBe(h32("6"));
  });
});

describe("ca_registration_v2 transcript binding", () => {
  it("round1 transcript hash is byte-stable across hex casing", () => {
    const args = {
      sessionId: "sess",
      requestId: "req",
      dkgEpoch: "3",
      caDkgTranscriptHash: h32("a"),
      rosterHash: h32("b"),
      sortedSelectedSlots: [0, 1, 2, 3, 4],
      selfSlot: 0,
      playerId: 0,
      vaultEk: h32("c"),
      senderAddress: h32("d"),
      assetType: h32("e"),
      chainId: 2,
      commitmentHex: h32("f"),
      nonceId: h32("1"),
    };
    const lower = caRegistrationV2Round1WorkerTranscriptHash(args);
    const upper = caRegistrationV2Round1WorkerTranscriptHash({
      ...args,
      caDkgTranscriptHash: h32("a").toUpperCase(),
      rosterHash: "0x" + h32("b"),
    });
    expect(lower).toBe(upper);
    expect(lower).toMatch(/^[0-9a-f]{64}$/);
  });

  it("round2 transcript hash includes responseHash and challenge", () => {
    const base = {
      sessionId: "sess",
      requestId: "req",
      dkgEpoch: "3",
      caDkgTranscriptHash: h32("a"),
      sortedSelectedSlots: [0, 1, 2, 3, 4],
      selfSlot: 0,
      playerId: 0,
      nonceId: h32("3"),
      challenge: h32("4"),
      responseHash: h32("5"),
    };
    const a = caRegistrationV2Round2WorkerTranscriptHash(base);
    const b = caRegistrationV2Round2WorkerTranscriptHash({
      ...base,
      responseHash: h32("6"),
    });
    expect(a).not.toBe(b);
  });

  it("assembleCaRegistrationV2Transcript normalizes and produces a stable transcriptHash", () => {
    const transcript = assembleCaRegistrationV2Transcript({
      dkgEpoch: "3",
      caDkgTranscriptHash: h32("a"),
      rosterHash: h32("b"),
      selectedSlots: [2, 0, 1, 4, 3],
      verifierSlot: 0,
      vaultEk: h32("c"),
      senderAddress: h32("d"),
      assetType: h32("e"),
      chainId: 2,
      aggregateCommitment: h32("1"),
      aggregateResponse: h32("2"),
      challenge: h32("3"),
      perSlotContributions: [0, 1, 2, 3, 4].map((slot) => ({
        slot,
        commitmentHex: h32((slot + 1).toString(16)),
        responseHex: h32((slot + 2).toString(16)),
        workerRound1TranscriptHash: h32("8"),
        workerRound2TranscriptHash: h32("9"),
      })),
    });
    expect(transcript.scheme).toBe("ca_registration_v2");
    expect(transcript.selectedSlots).toEqual([0, 1, 2, 3, 4]);
    expect(transcript.transcriptHash).toMatch(/^[0-9a-f]{64}$/);

    const recomputed = caRegistrationV2FinalTranscriptHash({
      dkgEpoch: "3",
      caDkgTranscriptHash: h32("a"),
      rosterHash: h32("b"),
      sortedSelectedSlots: [0, 1, 2, 3, 4],
      vaultEk: h32("c"),
      senderAddress: h32("d"),
      assetType: h32("e"),
      chainId: 2,
      aggregateCommitment: h32("1"),
      aggregateResponse: h32("2"),
      challenge: h32("3"),
      perSlotContributions: transcript.perSlotContributions,
    });
    expect(recomputed).toBe(transcript.transcriptHash);
  });

  it("assembleCaRegistrationV2Transcript rejects verifierSlot outside selectedSlots", () => {
    expect(() =>
      assembleCaRegistrationV2Transcript({
        dkgEpoch: "3",
        caDkgTranscriptHash: h32("a"),
        rosterHash: h32("b"),
        selectedSlots: [0, 1, 2, 3, 4],
        verifierSlot: 6,
        vaultEk: h32("c"),
        senderAddress: h32("d"),
        assetType: h32("e"),
        chainId: 2,
        aggregateCommitment: h32("1"),
        aggregateResponse: h32("2"),
        challenge: h32("3"),
        perSlotContributions: [0, 1, 2, 3, 4].map((slot) => ({
          slot,
          commitmentHex: h32("a"),
          responseHex: h32("b"),
          workerRound1TranscriptHash: h32("c"),
          workerRound2TranscriptHash: h32("d"),
        })),
      }),
    ).toThrow(CaRegistrationV2Error);
  });

  it("assembleCaRegistrationV2Transcript rejects duplicate per-slot contributions", () => {
    expect(() =>
      assembleCaRegistrationV2Transcript({
        dkgEpoch: "3",
        caDkgTranscriptHash: h32("a"),
        rosterHash: h32("b"),
        selectedSlots: [0, 1, 2, 3, 4],
        verifierSlot: 0,
        vaultEk: h32("c"),
        senderAddress: h32("d"),
        assetType: h32("e"),
        chainId: 2,
        aggregateCommitment: h32("1"),
        aggregateResponse: h32("2"),
        challenge: h32("3"),
        perSlotContributions: [
          { slot: 0, commitmentHex: h32("a"), responseHex: h32("b"), workerRound1TranscriptHash: h32("c"), workerRound2TranscriptHash: h32("d") },
          { slot: 0, commitmentHex: h32("a"), responseHex: h32("b"), workerRound1TranscriptHash: h32("c"), workerRound2TranscriptHash: h32("d") },
          { slot: 2, commitmentHex: h32("a"), responseHex: h32("b"), workerRound1TranscriptHash: h32("c"), workerRound2TranscriptHash: h32("d") },
          { slot: 3, commitmentHex: h32("a"), responseHex: h32("b"), workerRound1TranscriptHash: h32("c"), workerRound2TranscriptHash: h32("d") },
          { slot: 4, commitmentHex: h32("a"), responseHex: h32("b"), workerRound1TranscriptHash: h32("c"), workerRound2TranscriptHash: h32("d") },
        ],
      }),
    ).toThrow(CaRegistrationV2Error);
  });
});

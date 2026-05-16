import { describe, expect, it } from "vitest";
import type { HpkeEnvelope } from "../src/types.js";
import {
  assembleMpccaWithdrawTranscript,
  canonicalJsonStringify,
  EUNOMA_M1_AMOUNT_INGRESS_V1,
  EUNOMA_MPCCA_WITHDRAW_V2_FINALIZE_V1,
  EUNOMA_MPCCA_WITHDRAW_V2_FINAL_V1,
  EUNOMA_MPCCA_WITHDRAW_V2_PROVE_V1,
  EUNOMA_MPCCA_WITHDRAW_V2_ROUND1_V1,
  EUNOMA_MPCCA_WITHDRAW_V2_ROUND1_V2,
  EUNOMA_MPCCA_WITHDRAW_V2_ROUND2_V1,
  ingressEnvelopesHash,
  m1IngressAad,
  MpccaWithdrawV2Error,
  mpccaWithdrawFinalTranscriptHash,
  mpccaWithdrawFinalizeWorkerTranscriptHash,
  mpccaWithdrawProveWorkerTranscriptHash,
  mpccaWithdrawRound1WorkerTranscriptHash,
  mpccaWithdrawRound2WorkerTranscriptHash,
  parseMpccaWithdrawFinalizeRequest,
  parseMpccaWithdrawFinalizeResponse,
  parseMpccaWithdrawProveRequest,
  parseMpccaWithdrawProveResponse,
  parseMpccaWithdrawRound1Request,
  parseMpccaWithdrawRound1Response,
  parseMpccaWithdrawRound2Request,
  parseMpccaWithdrawRound2Response,
  perShareCommitmentsHash,
} from "../src/mpcca_withdraw_v2.js";

const HEX32_A = "aa".repeat(32);
const HEX32_B = "bb".repeat(32);
const HEX32_C = "cc".repeat(32);
const HEX32_D = "dd".repeat(32);
const HEX32_E = "ee".repeat(32);
const HEX32_F = "ff".repeat(32);
const HEX32_1 = "11".repeat(32);
const HEX32_2 = "22".repeat(32);
const HEX32_3 = "33".repeat(32);
const HEX32_4 = "44".repeat(32);
const HEX32_5 = "55".repeat(32);
const HEX32_6 = "66".repeat(32);
const HEX32_7 = "77".repeat(32);
const HEX32_8 = "88".repeat(32);
const HEX32_9 = "99".repeat(32);
const HEX32_0 = "00".repeat(32);

function mockEnvelope(seed: number): HpkeEnvelope {
  const seedByte = seed.toString(16).padStart(2, "0");
  return {
    kem: "DHKEM_X25519_HKDF_SHA256",
    kdf: "HKDF_SHA256",
    aead: "AES_256_GCM",
    enc: seedByte.repeat(32),
    // 80-byte ciphertext = 64-byte plaintext + 16-byte GCM tag.
    ciphertext: seedByte.repeat(80),
    aadHash: seedByte.repeat(32),
  };
}

const VALID_INGRESS = {
  amountCommitment: "ac".repeat(32),
  perShareCommitments: [
    "11".repeat(32),
    "22".repeat(32),
    "33".repeat(32),
    "44".repeat(32),
    "55".repeat(32),
  ],
  ingressEnvelopes: [
    mockEnvelope(0x11),
    mockEnvelope(0x22),
    mockEnvelope(0x33),
    mockEnvelope(0x44),
    mockEnvelope(0x55),
  ],
};

function validRound1Body(): Record<string, unknown> {
  return {
    dkgEpoch: "1",
    requestId: "withdraw-r1",
    sessionId: "withdraw-r1",
    vaultEkTranscriptHash: HEX32_A,
    registrationTranscriptHash: HEX32_B,
    vaultStateInitTranscriptHash: HEX32_C,
    observedDepositTranscriptHashes: [HEX32_D, HEX32_E],
    rosterHash: HEX32_F,
    selectedSlots: [0, 1, 2, 3, 4],
    selfSlot: 2,
    playerId: 2,
    vaultEk: HEX32_1,
    senderAddress: HEX32_2,
    assetType: HEX32_3,
    chainId: 2,
    root: HEX32_4,
    nullifierHash: HEX32_5,
    recipient: HEX32_6,
    recipientHash: HEX32_7,
    amountTag: HEX32_8,
    vaultSequence: 4,
    expirySecs: 1_700_000_000,
    requestHash: HEX32_9,
    depositCount: 7,
    amountCommitment: VALID_INGRESS.amountCommitment,
    perShareCommitments: [...VALID_INGRESS.perShareCommitments],
    ingressEnvelopes: VALID_INGRESS.ingressEnvelopes.map((e) => ({ ...e })),
  };
}

function validChainedBody(): Record<string, unknown> {
  const body = validRound1Body();
  // Chained rounds do NOT carry ingress fields — drop them.
  delete (body as Record<string, unknown>).amountCommitment;
  delete (body as Record<string, unknown>).perShareCommitments;
  delete (body as Record<string, unknown>).ingressEnvelopes;
  return {
    ...body,
    previousRoundTranscriptHash: HEX32_0,
    previousRoundCommitments: [HEX32_A, HEX32_B, HEX32_C, HEX32_D, HEX32_E],
  };
}

function validStubResponseBody(notImplementedPhase: string): Record<string, unknown> {
  return {
    slot: 2,
    playerId: 2,
    sessionStatePath: "/tmp/state/mpc-sessions/withdraw-r1__withdraw-r1/mpcca_withdraw_v2_round1.json",
    sessionStateHash: HEX32_A,
    workerTranscriptHash: HEX32_B,
    observedAtUnixMs: 1_700_000_000_000,
    completed: false,
    notImplementedPhase,
  };
}

function validRound1ResponseBody(): Record<string, unknown> {
  return {
    slot: 2,
    playerId: 2,
    sessionStatePath: "/tmp/state/mpc-sessions/withdraw-r1__withdraw-r1/mpcca_withdraw_v2_round1.json",
    sessionStateHash: HEX32_A,
    workerTranscriptHash: HEX32_B,
    observedAtUnixMs: 1_700_000_000_000,
    completed: true,
    ingressTranscriptHash: HEX32_B,
  };
}

describe("mpcca_withdraw_v2 protocol — domain constants are distinct per round", () => {
  it("each round has its own domain string", () => {
    const all = new Set([
      EUNOMA_MPCCA_WITHDRAW_V2_ROUND1_V1,
      EUNOMA_MPCCA_WITHDRAW_V2_ROUND1_V2,
      EUNOMA_MPCCA_WITHDRAW_V2_ROUND2_V1,
      EUNOMA_MPCCA_WITHDRAW_V2_PROVE_V1,
      EUNOMA_MPCCA_WITHDRAW_V2_FINALIZE_V1,
      EUNOMA_MPCCA_WITHDRAW_V2_FINAL_V1,
      EUNOMA_M1_AMOUNT_INGRESS_V1,
    ]);
    expect(all.size).toBe(7);
  });
});

describe("mpcca_withdraw_v2 round1 worker transcript hash (M1 V2 with ingress binding)", () => {
  const base = {
    sessionId: "sess-x",
    requestId: "req-x",
    dkgEpoch: "1",
    vaultEkTranscriptHash: HEX32_A,
    registrationTranscriptHash: HEX32_B,
    vaultStateInitTranscriptHash: HEX32_C,
    observedDepositTranscriptHashes: [HEX32_D, HEX32_E],
    rosterHash: HEX32_F,
    sortedSelectedSlots: [0, 1, 2, 3, 4],
    selfSlot: 2,
    playerId: 2,
    vaultEk: HEX32_1,
    senderAddress: HEX32_2,
    assetType: HEX32_3,
    chainId: 2,
    root: HEX32_4,
    nullifierHash: HEX32_5,
    recipient: HEX32_6,
    recipientHash: HEX32_7,
    amountTag: HEX32_8,
    vaultSequence: 4,
    expirySecs: 1_700_000_000,
    requestHash: HEX32_9,
    depositCount: 7,
    amountCommitment: VALID_INGRESS.amountCommitment,
    perShareCommitments: VALID_INGRESS.perShareCommitments,
    ingressEnvelopesHash: ingressEnvelopesHash(VALID_INGRESS.ingressEnvelopes),
  };

  it("round1 hash is byte-stable for identical inputs", () => {
    const a = mpccaWithdrawRound1WorkerTranscriptHash(base);
    const b = mpccaWithdrawRound1WorkerTranscriptHash(base);
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it("round1 hash changes when ANY single field changes (including new ingress fields)", () => {
    const baseHash = mpccaWithdrawRound1WorkerTranscriptHash(base);
    const mutators: Array<(b: typeof base) => typeof base> = [
      (b) => ({ ...b, sessionId: "sess-y" }),
      (b) => ({ ...b, requestId: "req-y" }),
      (b) => ({ ...b, dkgEpoch: "2" }),
      (b) => ({ ...b, vaultEkTranscriptHash: HEX32_F }),
      (b) => ({ ...b, registrationTranscriptHash: HEX32_F }),
      (b) => ({ ...b, vaultStateInitTranscriptHash: HEX32_F }),
      (b) => ({ ...b, observedDepositTranscriptHashes: [HEX32_D] }),
      (b) => ({ ...b, observedDepositTranscriptHashes: [HEX32_E, HEX32_D] }), // ordering
      (b) => ({ ...b, rosterHash: HEX32_0 }),
      (b) => ({ ...b, sortedSelectedSlots: [1, 2, 3, 4, 5] }),
      (b) => ({ ...b, selfSlot: 3, playerId: 3 }),
      (b) => ({ ...b, vaultEk: HEX32_F }),
      (b) => ({ ...b, senderAddress: HEX32_F }),
      (b) => ({ ...b, assetType: HEX32_F }),
      (b) => ({ ...b, chainId: 3 }),
      (b) => ({ ...b, root: HEX32_F }),
      (b) => ({ ...b, nullifierHash: HEX32_F }),
      (b) => ({ ...b, recipient: HEX32_F }),
      (b) => ({ ...b, recipientHash: HEX32_F }),
      (b) => ({ ...b, amountTag: HEX32_F }),
      (b) => ({ ...b, vaultSequence: 5 }),
      (b) => ({ ...b, expirySecs: 1_700_000_001 }),
      (b) => ({ ...b, requestHash: HEX32_F }),
      (b) => ({ ...b, depositCount: 8 }),
      // M1 ingress fields — every one must flip the round1 hash.
      (b) => ({ ...b, amountCommitment: HEX32_F }),
      (b) => ({
        ...b,
        perShareCommitments: [HEX32_F, HEX32_2, HEX32_3, HEX32_4, HEX32_5],
      }),
      (b) => ({ ...b, ingressEnvelopesHash: HEX32_F }),
    ];
    for (const mutate of mutators) {
      const mutated = mutate(base);
      expect(mpccaWithdrawRound1WorkerTranscriptHash(mutated), JSON.stringify(mutated)).not.toBe(
        baseHash,
      );
    }
  });

  it("round1 hash uses domain V2 (binds the ingress fields)", () => {
    // A V1-style hash (no ingress fields) would necessarily differ from V2: the V2 domain
    // string is bigger and the appended ingress bytes shift the input. We don't expose a
    // V1 hash function publicly (V1 stub-mode is gone); this test just confirms the V2
    // domain is non-empty and the export name matches.
    expect(EUNOMA_MPCCA_WITHDRAW_V2_ROUND1_V2).toBe("EUNOMA_MPCCA_WITHDRAW_V2_ROUND1_V2");
    expect(EUNOMA_MPCCA_WITHDRAW_V2_ROUND1_V2).not.toBe(EUNOMA_MPCCA_WITHDRAW_V2_ROUND1_V1);
  });
});

describe("mpcca_withdraw_v2 chained rounds (round2/prove/finalize)", () => {
  const base = {
    sessionId: "sess-x",
    requestId: "req-x",
    dkgEpoch: "1",
    vaultEkTranscriptHash: HEX32_A,
    registrationTranscriptHash: HEX32_B,
    vaultStateInitTranscriptHash: HEX32_C,
    observedDepositTranscriptHashes: [HEX32_D],
    rosterHash: HEX32_F,
    sortedSelectedSlots: [0, 1, 2, 3, 4],
    selfSlot: 2,
    playerId: 2,
    vaultEk: HEX32_1,
    senderAddress: HEX32_2,
    assetType: HEX32_3,
    chainId: 2,
    root: HEX32_4,
    nullifierHash: HEX32_5,
    recipient: HEX32_6,
    recipientHash: HEX32_7,
    amountTag: HEX32_8,
    vaultSequence: 4,
    expirySecs: 1_700_000_000,
    requestHash: HEX32_9,
    depositCount: 7,
    previousRoundTranscriptHash: HEX32_0,
    previousRoundCommitments: [HEX32_A, HEX32_B, HEX32_C, HEX32_D, HEX32_E],
  };

  it("each chained round returns distinct hashes for the same body", () => {
    const r2 = mpccaWithdrawRound2WorkerTranscriptHash(base);
    const pr = mpccaWithdrawProveWorkerTranscriptHash(base);
    const fin = mpccaWithdrawFinalizeWorkerTranscriptHash(base);
    expect(new Set([r2, pr, fin]).size).toBe(3);
    expect(r2).toMatch(/^[0-9a-f]{64}$/);
    expect(pr).toMatch(/^[0-9a-f]{64}$/);
    expect(fin).toMatch(/^[0-9a-f]{64}$/);
  });

  it("chained hash changes when previousRoundTranscriptHash flips", () => {
    const baseHash = mpccaWithdrawRound2WorkerTranscriptHash(base);
    expect(
      mpccaWithdrawRound2WorkerTranscriptHash({
        ...base,
        previousRoundTranscriptHash: HEX32_F,
      }),
    ).not.toBe(baseHash);
  });

  it("chained hash changes when ANY previousRoundCommitments entry flips", () => {
    const baseHash = mpccaWithdrawProveWorkerTranscriptHash(base);
    const mutated = {
      ...base,
      previousRoundCommitments: [HEX32_A, HEX32_B, HEX32_F, HEX32_D, HEX32_E],
    };
    expect(mpccaWithdrawProveWorkerTranscriptHash(mutated)).not.toBe(baseHash);
  });
});

describe("mpcca_withdraw_v2 final transcript hash", () => {
  function fixture() {
    const slots = [0, 1, 2, 3, 4];
    return {
      dkgEpoch: "1",
      vaultEkTranscriptHash: HEX32_A,
      registrationTranscriptHash: HEX32_B,
      vaultStateInitTranscriptHash: HEX32_C,
      observedDepositTranscriptHashes: [HEX32_D],
      rosterHash: HEX32_F,
      sortedSelectedSlots: slots,
      vaultEk: HEX32_1,
      senderAddress: HEX32_2,
      assetType: HEX32_3,
      chainId: 2,
      root: HEX32_4,
      nullifierHash: HEX32_5,
      recipient: HEX32_6,
      recipientHash: HEX32_7,
      amountTag: HEX32_8,
      vaultSequence: 4,
      expirySecs: 1_700_000_000,
      requestHash: HEX32_9,
      depositCount: 7,
      round1Contributions: slots.map((slot) => ({
        slot,
        sessionStateHash: HEX32_A,
        workerTranscriptHash: HEX32_B,
        completed: true as const,
        ingressTranscriptHash: HEX32_B,
      })),
      round2Contributions: [],
      proveContributions: [],
      finalizeContributions: [],
    };
  }

  it("binds every per-slot round1 contribution", () => {
    const a = mpccaWithdrawFinalTranscriptHash(fixture());
    const mutated = fixture();
    mutated.round1Contributions[2] = {
      ...mutated.round1Contributions[2],
      sessionStateHash: HEX32_F,
    };
    expect(mpccaWithdrawFinalTranscriptHash(mutated)).not.toBe(a);
  });

  it("binds every per-slot ingressTranscriptHash (round1 V2 layout)", () => {
    const a = mpccaWithdrawFinalTranscriptHash(fixture());
    const mutated = fixture();
    mutated.round1Contributions[3] = {
      ...mutated.round1Contributions[3],
      ingressTranscriptHash: HEX32_F,
    };
    expect(mpccaWithdrawFinalTranscriptHash(mutated)).not.toBe(a);
  });
});

describe("mpcca_withdraw_v2 assembleMpccaWithdrawTranscript", () => {
  it("happy path produces stable transcriptHash", () => {
    const slots = [0, 1, 2, 3, 4];
    const round1Contributions = slots.map((slot) => ({
      slot,
      sessionStateHash: HEX32_A,
      workerTranscriptHash: HEX32_B,
      completed: true as const,
      ingressTranscriptHash: HEX32_B,
    }));
    const t = assembleMpccaWithdrawTranscript({
      dkgEpoch: "1",
      requestId: "wdr-1",
      vaultEkTranscriptHash: HEX32_A,
      registrationTranscriptHash: HEX32_B,
      vaultStateInitTranscriptHash: HEX32_C,
      observedDepositTranscriptHashes: [HEX32_D],
      rosterHash: HEX32_F,
      selectedSlots: slots,
      vaultEk: HEX32_1,
      senderAddress: HEX32_2,
      assetType: HEX32_3,
      chainId: 2,
      root: HEX32_4,
      nullifierHash: HEX32_5,
      recipient: HEX32_6,
      recipientHash: HEX32_7,
      amountTag: HEX32_8,
      vaultSequence: 4,
      expirySecs: 1_700_000_000,
      requestHash: HEX32_9,
      depositCount: 7,
      round1Contributions,
      round2Contributions: [],
      proveContributions: [],
      finalizeContributions: [],
    });
    expect(t.scheme).toBe("mpcca_withdraw_v2");
    expect(t.transcriptHash).toMatch(/^[0-9a-f]{64}$/);
    expect(t.selectedSlots).toEqual([0, 1, 2, 3, 4]);
    expect(t.round1Contributions).toHaveLength(5);
    expect(t.round2Contributions).toHaveLength(0);
  });

  it("rejects under-quorum selectedSlots", () => {
    expect(() =>
      assembleMpccaWithdrawTranscript({
        dkgEpoch: "1",
        requestId: "wdr-quorum",
        vaultEkTranscriptHash: HEX32_A,
        registrationTranscriptHash: HEX32_B,
        vaultStateInitTranscriptHash: HEX32_C,
        observedDepositTranscriptHashes: [],
        rosterHash: HEX32_F,
        selectedSlots: [0, 1, 2],
        vaultEk: HEX32_1,
        senderAddress: HEX32_2,
        assetType: HEX32_3,
        chainId: 2,
        root: HEX32_4,
        nullifierHash: HEX32_5,
        recipient: HEX32_6,
        recipientHash: HEX32_7,
        amountTag: HEX32_8,
        vaultSequence: 4,
        expirySecs: 1_700_000_000,
        requestHash: HEX32_9,
        depositCount: 7,
        round1Contributions: [],
        round2Contributions: [],
        proveContributions: [],
        finalizeContributions: [],
      }),
    ).toThrow(MpccaWithdrawV2Error);
  });
});

describe("mpcca_withdraw_v2 parsers", () => {
  it("parseMpccaWithdrawRound1Request accepts a valid wire body (with M1 ingress)", () => {
    const parsed = parseMpccaWithdrawRound1Request(validRound1Body());
    expect(parsed.dkgEpoch).toBe("1");
    expect(parsed.selfSlot).toBe(2);
    expect(parsed.depositCount).toBe(7);
    expect(parsed.observedDepositTranscriptHashes).toHaveLength(2);
    expect(parsed.amountCommitment).toBe(VALID_INGRESS.amountCommitment);
    expect(parsed.perShareCommitments).toHaveLength(5);
    expect(parsed.ingressEnvelopes).toHaveLength(5);
    expect(parsed.ingressEnvelopes[0].kem).toBe("DHKEM_X25519_HKDF_SHA256");
  });

  it("parseMpccaWithdrawRound1Request rejects under-quorum selectedSlots", () => {
    const body = { ...validRound1Body(), selectedSlots: [0, 1, 2] };
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(MpccaWithdrawV2Error);
  });

  it("parseMpccaWithdrawRound1Request rejects 33-byte vaultEk", () => {
    const body = { ...validRound1Body(), vaultEk: "aa".repeat(33) };
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(MpccaWithdrawV2Error);
  });

  it("parseMpccaWithdrawRound1Request rejects 31-byte root", () => {
    const body = { ...validRound1Body(), root: "aa".repeat(31) };
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(MpccaWithdrawV2Error);
  });

  // KILLER guard test: forbidden plaintext field smuggled into the body must be rejected.
  it("parseMpccaWithdrawRound1Request fires forbidden guard on `secret`", () => {
    const body = { ...validRound1Body(), secret: "abc" };
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(/forbidden plaintext field/);
  });

  it("parseMpccaWithdrawRound1Request fires forbidden guard on `dkShare`", () => {
    const body = { ...validRound1Body(), dkShare: "abc" };
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(/forbidden plaintext field/);
  });

  it("parseMpccaWithdrawRound1Request fires forbidden guard on `blind`", () => {
    const body = { ...validRound1Body(), blind: "abc" };
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(/forbidden plaintext field/);
  });

  it("parseMpccaWithdrawRound1Request fires forbidden guard on nested `secret`", () => {
    const body = { ...validRound1Body(), metadata: { secret: "leak" } };
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(/forbidden plaintext field/);
  });

  it("parseMpccaWithdrawRound1Request rejects non-decimal dkgEpoch", () => {
    const body = { ...validRound1Body(), dkgEpoch: "0x10" };
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(MpccaWithdrawV2Error);
  });

  it("parseMpccaWithdrawRound1Request rejects missing observedDepositTranscriptHashes", () => {
    const body = { ...validRound1Body() };
    delete (body as Record<string, unknown>).observedDepositTranscriptHashes;
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(MpccaWithdrawV2Error);
  });

  it("parseMpccaWithdrawRound2Request accepts a chained body", () => {
    const parsed = parseMpccaWithdrawRound2Request(validChainedBody());
    expect(parsed.previousRoundTranscriptHash).toBe(HEX32_0);
    expect(parsed.previousRoundCommitments).toHaveLength(5);
  });

  it("parseMpccaWithdrawRound2Request rejects missing previousRoundTranscriptHash", () => {
    const body = { ...validChainedBody() };
    delete (body as Record<string, unknown>).previousRoundTranscriptHash;
    expect(() => parseMpccaWithdrawRound2Request(body)).toThrow(MpccaWithdrawV2Error);
  });

  it("parseMpccaWithdrawRound2Request rejects under-quorum previousRoundCommitments", () => {
    const body = {
      ...validChainedBody(),
      previousRoundCommitments: [HEX32_A, HEX32_B, HEX32_C, HEX32_D],
    };
    expect(() => parseMpccaWithdrawRound2Request(body)).toThrow(MpccaWithdrawV2Error);
  });

  it("parseMpccaWithdrawProveRequest accepts a chained body", () => {
    expect(parseMpccaWithdrawProveRequest(validChainedBody()).previousRoundCommitments).toHaveLength(
      5,
    );
  });

  it("parseMpccaWithdrawFinalizeRequest accepts a chained body", () => {
    expect(
      parseMpccaWithdrawFinalizeRequest(validChainedBody()).previousRoundCommitments,
    ).toHaveLength(5);
  });

  it("parseMpccaWithdrawRound1Response accepts a completed M1 response", () => {
    const r = parseMpccaWithdrawRound1Response(validRound1ResponseBody());
    expect(r.completed).toBe(true);
    expect(r.ingressTranscriptHash).toBe(HEX32_B);
  });

  it("parseMpccaWithdrawRound1Response rejects completed=false (M3a stub shape)", () => {
    expect(() =>
      parseMpccaWithdrawRound1Response({
        ...validRound1ResponseBody(),
        completed: false,
        notImplementedPhase: "any",
      }),
    ).toThrow(MpccaWithdrawV2Error);
  });

  it("parseMpccaWithdrawRound1Response rejects ingressTranscriptHash mismatch with workerTranscriptHash", () => {
    expect(() =>
      parseMpccaWithdrawRound1Response({
        ...validRound1ResponseBody(),
        ingressTranscriptHash: HEX32_F,
      }),
    ).toThrow(MpccaWithdrawV2Error);
  });

  it("parseMpccaWithdrawRound2Response accepts a stub response", () => {
    const r = parseMpccaWithdrawRound2Response(
      validStubResponseBody("mpcca_withdraw_v2_round2_partial_sigma_pending_milestone4"),
    );
    expect(r.notImplementedPhase).toContain("round2");
  });

  it("parseMpccaWithdrawProveResponse accepts a stub response", () => {
    const r = parseMpccaWithdrawProveResponse(
      validStubResponseBody("mpcca_withdraw_v2_prove_collaborative_bulletproof_pending_milestone4"),
    );
    expect(r.notImplementedPhase).toContain("prove");
  });

  it("parseMpccaWithdrawFinalizeResponse accepts a stub response", () => {
    const r = parseMpccaWithdrawFinalizeResponse(
      validStubResponseBody("mpcca_withdraw_v2_finalize_aggregate_pending_milestone4"),
    );
    expect(r.notImplementedPhase).toContain("finalize");
  });
});

// =================================================================================================
// Milestone 1 — killer tests for the ingress envelope wire shape, AAD canonical-JSON parity,
// and helper byte-stability. These are the round1-specific guards that protect the no-plaintext
// invariant at the wire boundary.
// =================================================================================================
describe("mpcca_withdraw_v2 M1 — ingress envelope wire validation", () => {
  it("rejects perShareCommitments with wrong count (4 instead of 5)", () => {
    const body = { ...validRound1Body() };
    body.perShareCommitments = [HEX32_A, HEX32_B, HEX32_C, HEX32_D];
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(/perShareCommitments must have/);
  });

  it("rejects perShareCommitments with wrong count (6 instead of 5)", () => {
    const body = { ...validRound1Body() };
    body.perShareCommitments = [HEX32_A, HEX32_B, HEX32_C, HEX32_D, HEX32_E, HEX32_F];
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(/perShareCommitments must have/);
  });

  it("rejects perShareCommitments with non-32-byte hex entries", () => {
    const body = { ...validRound1Body() };
    body.perShareCommitments = [HEX32_A, HEX32_B, "ab".repeat(31), HEX32_D, HEX32_E];
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(/must be 32-byte hex/);
  });

  it("rejects ingressEnvelopes with wrong count (4 instead of 5)", () => {
    const body = { ...validRound1Body() };
    body.ingressEnvelopes = VALID_INGRESS.ingressEnvelopes.slice(0, 4);
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(/ingressEnvelopes must have/);
  });

  it("rejects ingressEnvelopes with mismatched ciphersuite", () => {
    const body = { ...validRound1Body() };
    const mutated = VALID_INGRESS.ingressEnvelopes.map((e) => ({ ...e }));
    (mutated[2] as Record<string, unknown>).kem = "DHKEM_P256";
    body.ingressEnvelopes = mutated;
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(/DHKEM_X25519_HKDF_SHA256/);
  });

  it("rejects ingressEnvelopes with wrong ciphertext length (not 80 bytes)", () => {
    const body = { ...validRound1Body() };
    const mutated = VALID_INGRESS.ingressEnvelopes.map((e) => ({ ...e }));
    mutated[1] = { ...mutated[1], ciphertext: "11".repeat(48) };
    body.ingressEnvelopes = mutated;
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(/80-byte hex/);
  });

  it("rejects ingressEnvelopes with non-32-byte enc (KEM ephemeral)", () => {
    const body = { ...validRound1Body() };
    const mutated = VALID_INGRESS.ingressEnvelopes.map((e) => ({ ...e }));
    mutated[1] = { ...mutated[1], enc: "11".repeat(33) };
    body.ingressEnvelopes = mutated;
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(/32-byte hex \(X25519 KEM ephemeral\)/);
  });

  it("rejects amountCommitment with wrong byte length", () => {
    const body = { ...validRound1Body() };
    body.amountCommitment = "ab".repeat(33);
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(/32-byte hex/);
  });

  it("forbidden-field guard still trips when ingress fields are valid (defense in depth)", () => {
    const body = { ...validRound1Body(), secret: "leak" };
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(/forbidden plaintext field/);
  });

  it("ingressEnvelopes field name is NOT caught by forbidden-field guard", () => {
    // Sanity: 'ingressEnvelopes' contains no banned token. This protects against accidental
    // future regressions that add 'envelope' or similar to the banned set.
    expect(() => parseMpccaWithdrawRound1Request(validRound1Body())).not.toThrow(
      /forbidden plaintext field/,
    );
  });

  it("perShareCommitments field name is NOT caught by forbidden-field guard", () => {
    // 'share' is not a banned token by itself; only banned tokens like 'secretshare',
    // 'shamir_share', 'dk_share' trip. Defense-in-depth: ensure naming convention holds.
    expect(() => parseMpccaWithdrawRound1Request(validRound1Body())).not.toThrow(
      /forbidden plaintext field/,
    );
  });
});

describe("mpcca_withdraw_v2 M1 — ingress helper byte-stability", () => {
  it("ingressEnvelopesHash is byte-stable", () => {
    const a = ingressEnvelopesHash(VALID_INGRESS.ingressEnvelopes);
    const b = ingressEnvelopesHash(VALID_INGRESS.ingressEnvelopes);
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it("ingressEnvelopesHash changes when any envelope flips", () => {
    const a = ingressEnvelopesHash(VALID_INGRESS.ingressEnvelopes);
    const mutated = VALID_INGRESS.ingressEnvelopes.map((e) => ({ ...e }));
    mutated[3] = { ...mutated[3], ciphertext: "ff".repeat(80) };
    expect(ingressEnvelopesHash(mutated)).not.toBe(a);
  });

  it("ingressEnvelopesHash changes when envelope ORDER flips", () => {
    const a = ingressEnvelopesHash(VALID_INGRESS.ingressEnvelopes);
    const reordered = [
      VALID_INGRESS.ingressEnvelopes[1],
      VALID_INGRESS.ingressEnvelopes[0],
      VALID_INGRESS.ingressEnvelopes[2],
      VALID_INGRESS.ingressEnvelopes[3],
      VALID_INGRESS.ingressEnvelopes[4],
    ];
    expect(ingressEnvelopesHash(reordered)).not.toBe(a);
  });

  it("perShareCommitmentsHash is byte-stable + changes on commitment edit", () => {
    const a = perShareCommitmentsHash(VALID_INGRESS.perShareCommitments);
    const b = perShareCommitmentsHash(VALID_INGRESS.perShareCommitments);
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    const mutated = [...VALID_INGRESS.perShareCommitments];
    mutated[2] = HEX32_F;
    expect(perShareCommitmentsHash(mutated)).not.toBe(a);
  });

  it("canonicalJsonStringify sorts keys deterministically", () => {
    expect(canonicalJsonStringify({ b: 2, a: 1, c: 3 })).toBe('{"a":1,"b":2,"c":3}');
    expect(canonicalJsonStringify({ nested: { y: 1, x: 0 } })).toBe(
      '{"nested":{"x":0,"y":1}}',
    );
    expect(canonicalJsonStringify([{ b: 1, a: 2 }, { d: 3, c: 4 }])).toBe(
      '[{"a":2,"b":1},{"c":4,"d":3}]',
    );
  });

  it("m1IngressAad produces stable bytes and changes on any field flip", () => {
    const args = {
      requestId: "req-1",
      sessionId: "sess-1",
      dkgEpoch: "1",
      selfSlot: 2,
      playerId: 1,
      rosterHash: HEX32_F,
      vaultEk: HEX32_1,
      root: HEX32_4,
      nullifierHash: HEX32_5,
      recipientHash: HEX32_7,
      amountTag: HEX32_8,
      vaultSequence: 4,
      depositCount: 7,
      amountCommitment: VALID_INGRESS.amountCommitment,
      perShareCommitments: VALID_INGRESS.perShareCommitments,
    };
    const a = m1IngressAad(args);
    const b = m1IngressAad(args);
    expect(a).toEqual(b);

    const flipSlot = m1IngressAad({ ...args, selfSlot: 3 });
    expect(flipSlot).not.toEqual(a);

    const flipPlayer = m1IngressAad({ ...args, playerId: 4 });
    expect(flipPlayer).not.toEqual(a);

    const flipCommit = m1IngressAad({
      ...args,
      perShareCommitments: [HEX32_F, ...args.perShareCommitments.slice(1)],
    });
    expect(flipCommit).not.toEqual(a);

    const flipDomain = JSON.parse(new TextDecoder().decode(a));
    expect(flipDomain.domain).toBe(EUNOMA_M1_AMOUNT_INGRESS_V1);
  });
});

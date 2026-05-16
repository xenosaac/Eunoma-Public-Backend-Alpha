import { describe, expect, it } from "vitest";
import {
  assembleMpccaWithdrawTranscript,
  EUNOMA_MPCCA_WITHDRAW_V2_FINALIZE_V1,
  EUNOMA_MPCCA_WITHDRAW_V2_FINAL_V1,
  EUNOMA_MPCCA_WITHDRAW_V2_PROVE_V1,
  EUNOMA_MPCCA_WITHDRAW_V2_ROUND1_V1,
  EUNOMA_MPCCA_WITHDRAW_V2_ROUND2_V1,
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
  };
}

function validChainedBody(): Record<string, unknown> {
  return {
    ...validRound1Body(),
    previousRoundTranscriptHash: HEX32_0,
    previousRoundCommitments: [HEX32_A, HEX32_B, HEX32_C, HEX32_D, HEX32_E],
  };
}

function validResponseBody(notImplementedPhase: string): Record<string, unknown> {
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

describe("mpcca_withdraw_v2 protocol — domain constants are distinct per round", () => {
  it("each round has its own domain string", () => {
    const all = new Set([
      EUNOMA_MPCCA_WITHDRAW_V2_ROUND1_V1,
      EUNOMA_MPCCA_WITHDRAW_V2_ROUND2_V1,
      EUNOMA_MPCCA_WITHDRAW_V2_PROVE_V1,
      EUNOMA_MPCCA_WITHDRAW_V2_FINALIZE_V1,
      EUNOMA_MPCCA_WITHDRAW_V2_FINAL_V1,
    ]);
    expect(all.size).toBe(5);
  });
});

describe("mpcca_withdraw_v2 round1 worker transcript hash", () => {
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
  };

  it("round1 hash is byte-stable for identical inputs", () => {
    const a = mpccaWithdrawRound1WorkerTranscriptHash(base);
    const b = mpccaWithdrawRound1WorkerTranscriptHash(base);
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it("round1 hash changes when ANY single field changes", () => {
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
    ];
    for (const mutate of mutators) {
      const mutated = mutate(base);
      expect(mpccaWithdrawRound1WorkerTranscriptHash(mutated), JSON.stringify(mutated)).not.toBe(
        baseHash,
      );
    }
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
        completed: false as const,
        notImplementedPhase: "mpcca_withdraw_v2_round1_nonce_generation_pending_milestone4",
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
});

describe("mpcca_withdraw_v2 assembleMpccaWithdrawTranscript", () => {
  it("happy path produces stable transcriptHash", () => {
    const slots = [0, 1, 2, 3, 4];
    const round1Contributions = slots.map((slot) => ({
      slot,
      sessionStateHash: HEX32_A,
      workerTranscriptHash: HEX32_B,
      completed: false as const,
      notImplementedPhase: "mpcca_withdraw_v2_round1_nonce_generation_pending_milestone4",
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
  it("parseMpccaWithdrawRound1Request accepts a valid wire body", () => {
    const parsed = parseMpccaWithdrawRound1Request(validRound1Body());
    expect(parsed.dkgEpoch).toBe("1");
    expect(parsed.selfSlot).toBe(2);
    expect(parsed.depositCount).toBe(7);
    expect(parsed.observedDepositTranscriptHashes).toHaveLength(2);
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

  it("parseMpccaWithdrawRound1Response accepts a stub response", () => {
    const r = parseMpccaWithdrawRound1Response(
      validResponseBody("mpcca_withdraw_v2_round1_nonce_generation_pending_milestone4"),
    );
    expect(r.completed).toBe(false);
    expect(r.notImplementedPhase).toContain("round1");
  });

  it("parseMpccaWithdrawRound1Response rejects completed=true", () => {
    expect(() =>
      parseMpccaWithdrawRound1Response({
        ...validResponseBody("nope"),
        completed: true,
      }),
    ).toThrow(MpccaWithdrawV2Error);
  });

  it("parseMpccaWithdrawRound2Response accepts a stub response", () => {
    const r = parseMpccaWithdrawRound2Response(
      validResponseBody("mpcca_withdraw_v2_round2_partial_sigma_pending_milestone4"),
    );
    expect(r.notImplementedPhase).toContain("round2");
  });

  it("parseMpccaWithdrawProveResponse accepts a stub response", () => {
    const r = parseMpccaWithdrawProveResponse(
      validResponseBody("mpcca_withdraw_v2_prove_collaborative_bulletproof_pending_milestone4"),
    );
    expect(r.notImplementedPhase).toContain("prove");
  });

  it("parseMpccaWithdrawFinalizeResponse accepts a stub response", () => {
    const r = parseMpccaWithdrawFinalizeResponse(
      validResponseBody("mpcca_withdraw_v2_finalize_aggregate_pending_milestone4"),
    );
    expect(r.notImplementedPhase).toContain("finalize");
  });
});
